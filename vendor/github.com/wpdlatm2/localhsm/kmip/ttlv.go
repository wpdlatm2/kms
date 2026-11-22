// Package kmip is a KMIP (OASIS Key Management Interoperability Protocol) client for fetching keys
// by name over mutual TLS and storing them in a localhsm keystore.
//
// It speaks KMIP 1.0-1.4, 2.0/2.1 and 3.0: the wire encoding (TTLV) is the same in all of them; what
// differs is how attributes are expressed (1.x: Attribute name/value structures; 2.x and later: one
// "Attributes" structure with typed attribute items). The version is negotiated with Discover
// Versions or pinned in the configuration. The 3.x wire format is assumed to follow 2.x.
package kmip

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// Type is a TTLV item type.
type Type byte

const (
	TypeStructure        Type = 0x01
	TypeInteger          Type = 0x02
	TypeLongInteger      Type = 0x03
	TypeBigInteger       Type = 0x04
	TypeEnumeration      Type = 0x05
	TypeBoolean          Type = 0x06
	TypeTextString       Type = 0x07
	TypeByteString       Type = 0x08
	TypeDateTime         Type = 0x09
	TypeInterval         Type = 0x0A
	TypeDateTimeExtended Type = 0x0B
)

const (
	maxDepth   = 16
	maxMessage = 16 << 20 // refuse messages larger than 16 MiB
)

// Item is one TTLV item: a tag, a type and a value (children for structures).
type Item struct {
	Tag      Tag
	Type     Type
	Num      int64   // Integer, LongInteger, Enumeration, Boolean, DateTime, Interval, DateTimeExtended
	Bytes    []byte  // TextString, ByteString, BigInteger
	Children []*Item // Structure
}

// ---- constructors

func Struct(tag Tag, children ...*Item) *Item {
	return &Item{Tag: tag, Type: TypeStructure, Children: children}
}
func Int(tag Tag, v int32) *Item    { return &Item{Tag: tag, Type: TypeInteger, Num: int64(v)} }
func Enum(tag Tag, v uint32) *Item  { return &Item{Tag: tag, Type: TypeEnumeration, Num: int64(v)} }
func Text(tag Tag, s string) *Item  { return &Item{Tag: tag, Type: TypeTextString, Bytes: []byte(s)} }
func Bytes(tag Tag, b []byte) *Item { return &Item{Tag: tag, Type: TypeByteString, Bytes: b} }
func DateTime(tag Tag, t time.Time) *Item {
	return &Item{Tag: tag, Type: TypeDateTime, Num: t.Unix()}
}
func Bool(tag Tag, v bool) *Item {
	n := int64(0)
	if v {
		n = 1
	}
	return &Item{Tag: tag, Type: TypeBoolean, Num: n}
}

// ---- accessors

// Child returns the first child with the given tag (nil if absent).
func (i *Item) Child(tag Tag) *Item {
	for _, c := range i.Children {
		if c.Tag == tag {
			return c
		}
	}
	return nil
}

// All returns every child with the given tag.
func (i *Item) All(tag Tag) []*Item {
	var out []*Item
	for _, c := range i.Children {
		if c.Tag == tag {
			out = append(out, c)
		}
	}
	return out
}

func (i *Item) Str() string     { return string(i.Bytes) }
func (i *Item) Uint() uint32    { return uint32(i.Num) }
func (i *Item) Time() time.Time { return time.Unix(i.Num, 0).UTC() }

// ---- encoding

func pad8(n int) int { return (n + 7) &^ 7 }

func (i *Item) valueLen() (int, error) {
	switch i.Type {
	case TypeStructure:
		n := 0
		for _, c := range i.Children {
			l, err := c.encodedLen()
			if err != nil {
				return 0, err
			}
			n += l
		}
		return n, nil
	case TypeInteger, TypeEnumeration, TypeInterval:
		return 4, nil
	case TypeLongInteger, TypeBoolean, TypeDateTime, TypeDateTimeExtended:
		return 8, nil
	case TypeTextString, TypeByteString, TypeBigInteger:
		return len(i.Bytes), nil
	}
	return 0, fmt.Errorf("kmip: cannot encode item type 0x%02X", byte(i.Type))
}

func (i *Item) encodedLen() (int, error) {
	n, err := i.valueLen()
	if err != nil {
		return 0, err
	}
	if i.Type == TypeStructure {
		return 8 + n, nil
	}
	return 8 + pad8(n), nil
}

// Encode serializes the item (and its children).
func (i *Item) Encode() ([]byte, error) {
	total, err := i.encodedLen()
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, total)
	return i.appendTo(out)
}

func (i *Item) appendTo(out []byte) ([]byte, error) {
	vl, err := i.valueLen()
	if err != nil {
		return nil, err
	}
	out = append(out, byte(i.Tag>>16), byte(i.Tag>>8), byte(i.Tag), byte(i.Type))
	out = binary.BigEndian.AppendUint32(out, uint32(vl))
	switch i.Type {
	case TypeStructure:
		for _, c := range i.Children {
			if out, err = c.appendTo(out); err != nil {
				return nil, err
			}
		}
	case TypeInteger, TypeEnumeration, TypeInterval:
		out = binary.BigEndian.AppendUint32(out, uint32(int32(i.Num)))
		out = append(out, 0, 0, 0, 0)
	case TypeLongInteger, TypeBoolean, TypeDateTime, TypeDateTimeExtended:
		out = binary.BigEndian.AppendUint64(out, uint64(i.Num))
	default: // text, byte string, big integer
		out = append(out, i.Bytes...)
		for p := pad8(len(i.Bytes)) - len(i.Bytes); p > 0; p-- {
			out = append(out, 0)
		}
	}
	return out, nil
}

// ---- decoding

var errTruncated = errors.New("kmip: truncated TTLV message")

// Decode parses one item from the start of b and returns it with the number of bytes consumed.
func Decode(b []byte) (*Item, int, error) { return decode(b, 0) }

func decode(b []byte, depth int) (*Item, int, error) {
	if depth > maxDepth {
		return nil, 0, errors.New("kmip: TTLV nesting too deep")
	}
	if len(b) < 8 {
		return nil, 0, errTruncated
	}
	it := &Item{Tag: Tag(uint32(b[0])<<16 | uint32(b[1])<<8 | uint32(b[2])), Type: Type(b[3])}
	l := int(binary.BigEndian.Uint32(b[4:8]))
	if l < 0 || l > maxMessage {
		return nil, 0, fmt.Errorf("kmip: item length %d out of range", l)
	}
	body := b[8:]
	switch it.Type {
	case TypeStructure:
		if l > len(body) {
			return nil, 0, errTruncated
		}
		rest := body[:l]
		for len(rest) > 0 {
			c, n, err := decode(rest, depth+1)
			if err != nil {
				return nil, 0, err
			}
			it.Children = append(it.Children, c)
			rest = rest[n:]
		}
		return it, 8 + l, nil
	case TypeInteger, TypeEnumeration, TypeInterval:
		if l != 4 {
			return nil, 0, fmt.Errorf("kmip: bad length %d for a 32-bit item", l)
		}
		if len(body) < 8 {
			return nil, 0, errTruncated
		}
		if it.Type == TypeInteger {
			it.Num = int64(int32(binary.BigEndian.Uint32(body)))
		} else {
			it.Num = int64(binary.BigEndian.Uint32(body))
		}
		return it, 16, nil
	case TypeLongInteger, TypeBoolean, TypeDateTime, TypeDateTimeExtended:
		if l != 8 {
			return nil, 0, fmt.Errorf("kmip: bad length %d for a 64-bit item", l)
		}
		if len(body) < 8 {
			return nil, 0, errTruncated
		}
		it.Num = int64(binary.BigEndian.Uint64(body))
		return it, 16, nil
	case TypeTextString, TypeByteString, TypeBigInteger:
		pl := pad8(l)
		if pl > len(body) {
			return nil, 0, errTruncated
		}
		it.Bytes = append([]byte(nil), body[:l]...)
		return it, 8 + pl, nil
	}
	return nil, 0, fmt.Errorf("kmip: unknown item type 0x%02X (tag 0x%06X)", byte(it.Type), uint32(it.Tag))
}
