package kmip

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"sync"
	"time"
)

// Version is a KMIP protocol version.
type Version struct{ Major, Minor int }

func (v Version) String() string { return fmt.Sprintf("%d.%d", v.Major, v.Minor) }
func (v Version) less(o Version) bool {
	return v.Major < o.Major || (v.Major == o.Major && v.Minor < o.Minor)
}

// modern reports whether attributes use the 2.x "Attributes" structure (KMIP 2.0 and later).
func (v Version) modern() bool { return v.Major >= 2 }

// Supported lists the versions this client can speak, newest first.
var Supported = []Version{{3, 0}, {2, 1}, {2, 0}, {1, 4}, {1, 3}, {1, 2}, {1, 1}, {1, 0}}

func supported(v Version) bool {
	for _, s := range Supported {
		if s == v {
			return true
		}
	}
	return false
}

// Config configures a Client.
type Config struct {
	Addr    string      // host:port (KMIP default port 5696)
	TLS     *tls.Config // mutual TLS; build it with localhsm.NewKMSTLSConfig so the client key stays in the TPM
	Version Version     // zero = negotiate with Discover Versions (falls back to 1.4)
	Timeout time.Duration
	// Optional KMIP-level credential (in addition to the certificate); most servers identify the
	// client from the certificate alone.
	Username, Password string
}

// Client is a KMIP session over one TLS connection. Safe for sequential use; calls are serialized.
type Client struct {
	mu      sync.Mutex
	conn    net.Conn
	cfg     Config
	version Version
	timeout time.Duration
}

// Dial connects (mutual TLS) and settles the protocol version.
func Dial(ctx context.Context, cfg Config) (*Client, error) {
	if cfg.TLS == nil {
		return nil, errors.New("kmip: TLS config is required (KMIP must run over mutual TLS)")
	}
	if cfg.Addr == "" {
		return nil, errors.New("kmip: address is required")
	}
	if cfg.Version != (Version{}) && !supported(cfg.Version) {
		return nil, fmt.Errorf("kmip: unsupported protocol version %s", cfg.Version)
	}
	to := cfg.Timeout
	if to == 0 {
		to = 30 * time.Second
	}
	d := &tls.Dialer{NetDialer: &net.Dialer{Timeout: to}, Config: cfg.TLS}
	conn, err := d.DialContext(ctx, "tcp", cfg.Addr)
	if err != nil {
		return nil, fmt.Errorf("kmip: connect %s: %w", cfg.Addr, err)
	}
	c := &Client{conn: conn, cfg: cfg, timeout: to}
	if cfg.Version != (Version{}) {
		c.version = cfg.Version
		return c, nil
	}
	if err := c.negotiate(); err != nil {
		conn.Close()
		return nil, err
	}
	return c, nil
}

// Version returns the protocol version in use.
func (c *Client) Version() Version { return c.version }

// Close ends the session.
func (c *Client) Close() error { return c.conn.Close() }

// negotiate asks the server which versions it supports and picks the newest common one.
func (c *Client) negotiate() error {
	c.version = Version{1, 2} // Discover Versions exists since 1.1; servers answer any version they know
	payload := Struct(TagRequestPayload)
	for _, v := range Supported {
		payload.Children = append(payload.Children, Struct(TagProtocolVersion,
			Int(TagProtocolVersionMajor, int32(v.Major)), Int(TagProtocolVersionMinor, int32(v.Minor))))
	}
	resp, err := c.roundTrip(OpDiscoverVersions, payload)
	if err != nil {
		// Servers older than 1.1, or ones that reject the operation: assume the widely deployed 1.4... but
		// only if the failure was a protocol-level refusal, not a transport error.
		var pe *ProtocolError
		if errors.As(err, &pe) {
			c.version = Version{1, 4}
			return nil
		}
		return err
	}
	var best Version
	for _, pv := range resp.All(TagProtocolVersion) {
		maj, mn := pv.Child(TagProtocolVersionMajor), pv.Child(TagProtocolVersionMinor)
		if maj == nil || mn == nil {
			continue
		}
		v := Version{int(maj.Num), int(mn.Num)}
		if supported(v) && best.less(v) {
			best = v
		}
	}
	if best == (Version{}) {
		return errors.New("kmip: the server supports none of KMIP 1.0-1.4, 2.0, 2.1, 3.0")
	}
	c.version = best
	return nil
}

// ProtocolError is a KMIP result with status != Success.
type ProtocolError struct {
	Op      uint32
	Status  uint32
	Reason  uint32
	Message string
}

func (e *ProtocolError) Error() string {
	r := reasonNames[e.Reason]
	if r == "" {
		r = fmt.Sprintf("0x%X", e.Reason)
	}
	op := operationNames[e.Op]
	if op == "" {
		op = fmt.Sprintf("0x%X", e.Op)
	}
	if e.Message != "" {
		return fmt.Sprintf("kmip: %s failed: %s: %s", op, r, e.Message)
	}
	return fmt.Sprintf("kmip: %s failed: %s", op, r)
}

// roundTrip sends one single-item batch and returns the Response Payload (possibly empty).
func (c *Client) roundTrip(op uint32, payload *Item) (*Item, error) {
	hdr := Struct(TagRequestHeader,
		Struct(TagProtocolVersion, Int(TagProtocolVersionMajor, int32(c.version.Major)), Int(TagProtocolVersionMinor, int32(c.version.Minor))))
	if c.cfg.Username != "" {
		hdr.Children = append(hdr.Children, Struct(TagAuthentication, Struct(TagCredential,
			Enum(TagCredentialType, 1), // Username and Password
			Struct(TagCredentialValue, Text(TagUsername, c.cfg.Username), Text(TagPassword, c.cfg.Password)))))
	}
	hdr.Children = append(hdr.Children, Int(TagBatchCount, 1))
	if payload == nil {
		payload = Struct(TagRequestPayload)
	}
	req := Struct(TagRequestMessage, hdr, Struct(TagBatchItem, Enum(TagOperation, op), payload))
	b, err := req.Encode()
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	_ = c.conn.SetDeadline(time.Now().Add(c.timeout))
	if _, err := c.conn.Write(b); err != nil {
		return nil, fmt.Errorf("kmip: send: %w", err)
	}
	raw, err := readMessage(c.conn)
	if err != nil {
		return nil, err
	}
	msg, _, err := Decode(raw)
	if err != nil {
		return nil, err
	}
	if msg.Tag != TagResponseMessage {
		return nil, fmt.Errorf("kmip: unexpected message tag 0x%06X", uint32(msg.Tag))
	}
	items := msg.All(TagBatchItem)
	if len(items) != 1 {
		return nil, fmt.Errorf("kmip: expected 1 batch item, got %d", len(items))
	}
	bi := items[0]
	st := bi.Child(TagResultStatus)
	if st == nil {
		return nil, errors.New("kmip: response without Result Status")
	}
	if st.Uint() != StatusSuccess {
		pe := &ProtocolError{Op: op, Status: st.Uint()}
		if r := bi.Child(TagResultReason); r != nil {
			pe.Reason = r.Uint()
		}
		if m := bi.Child(TagResultMessage); m != nil {
			pe.Message = m.Str()
		}
		return nil, pe
	}
	if p := bi.Child(TagResponsePayload); p != nil {
		return p, nil
	}
	return Struct(TagResponsePayload), nil
}

// readMessage reads exactly one TTLV message (an 8-byte header plus the declared length).
func readMessage(r io.Reader) ([]byte, error) {
	var h [8]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return nil, fmt.Errorf("kmip: receive: %w", err)
	}
	if h[3] != byte(TypeStructure) {
		return nil, errors.New("kmip: response is not a TTLV structure")
	}
	n := binary.BigEndian.Uint32(h[4:])
	if n > maxMessage {
		return nil, fmt.Errorf("kmip: response of %d bytes exceeds the limit", n)
	}
	buf := make([]byte, 8+int(n))
	copy(buf, h[:])
	if _, err := io.ReadFull(r, buf[8:]); err != nil {
		return nil, fmt.Errorf("kmip: receive: %w", err)
	}
	return buf, nil
}

// ---- operations

// Locate finds the unique identifiers of managed objects whose Name equals name.
func (c *Client) Locate(name string) ([]string, error) {
	nameItem := Struct(TagName, Text(TagNameValue, name), Enum(TagNameType, NameTypeUninterpretedTextString))
	var payload *Item
	if c.version.modern() {
		payload = Struct(TagRequestPayload, Struct(TagAttributes, nameItem))
	} else {
		payload = Struct(TagRequestPayload, Struct(TagAttribute, Text(TagAttributeName, "Name"), nameItem2(nameItem)))
	}
	payload.Children = append(payload.Children, Int(TagMaximumItems, 64))
	resp, err := c.roundTrip(OpLocate, payload)
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, u := range resp.All(TagUniqueIdentifier) {
		ids = append(ids, u.Str())
	}
	return ids, nil
}

// nameItem2 re-tags the Name structure as an Attribute Value (same tag/children; the 1.x value of the
// "Name" attribute is the Name structure itself, tagged Attribute Value).
func nameItem2(n *Item) *Item {
	return &Item{Tag: TagAttributeValue, Type: TypeStructure, Children: n.Children}
}

// Object is a fetched key object.
type Object struct {
	ID        string
	Type      uint32 // Obj… constant
	Format    uint32 // Fmt… constant
	Material  []byte // raw bytes; the caller must clear it
	Algorithm uint32 // from the key block (0 if absent)
	Length    int    // bits, from the key block (0 if absent)
	Wrapped   bool
}

// Get retrieves the object with the given identifier (no wrapping requested: the KMIP server must be
// willing to return the key in the clear over the mutual-TLS channel).
func (c *Client) Get(id string) (*Object, error) {
	resp, err := c.roundTrip(OpGet, Struct(TagRequestPayload, Text(TagUniqueIdentifier, id)))
	if err != nil {
		return nil, err
	}
	o := &Object{ID: id}
	if t := resp.Child(TagObjectType); t != nil {
		o.Type = t.Uint()
	}
	var holder *Item
	for _, t := range []Tag{TagSymmetricKey, TagPrivateKey, TagPublicKey, TagSecretData} {
		if h := resp.Child(t); h != nil {
			holder = h
			break
		}
	}
	if holder == nil {
		return nil, fmt.Errorf("kmip: object %s is of an unsupported kind (need a Symmetric, Private or Public Key, or Secret Data)", id)
	}
	kb := holder.Child(TagKeyBlock)
	if kb == nil {
		return nil, fmt.Errorf("kmip: object %s has no key block", id)
	}
	if f := kb.Child(TagKeyFormatType); f != nil {
		o.Format = f.Uint()
	}
	if a := kb.Child(TagCryptographicAlgorithm); a != nil {
		o.Algorithm = a.Uint()
	}
	if l := kb.Child(TagCryptographicLength); l != nil {
		o.Length = int(l.Num)
	}
	o.Wrapped = kb.Child(TagKeyWrappingData) != nil
	kv := kb.Child(TagKeyValue)
	if kv == nil {
		return nil, fmt.Errorf("kmip: object %s has no key value", id)
	}
	switch kv.Type {
	case TypeByteString: // key value delivered as an opaque byte string
		o.Material = append([]byte(nil), kv.Bytes...)
	case TypeStructure:
		km := kv.Child(TagKeyMaterial)
		if km == nil {
			return nil, fmt.Errorf("kmip: object %s has no key material", id)
		}
		switch km.Type {
		case TypeByteString:
			o.Material = append([]byte(nil), km.Bytes...)
		case TypeStructure: // Transparent Symmetric Key
			k := km.Child(TagKey)
			if k == nil {
				return nil, fmt.Errorf("kmip: object %s: transparent key material of an unsupported kind", id)
			}
			o.Material = append([]byte(nil), k.Bytes...)
		default:
			return nil, fmt.Errorf("kmip: object %s: unexpected key material type", id)
		}
	default:
		return nil, fmt.Errorf("kmip: object %s: unexpected key value type", id)
	}
	// the decoded copy in the response tree is not zeroized by the GC; clear what we can reach
	wipe(resp)
	return o, nil
}

func wipe(i *Item) {
	clear(i.Bytes)
	for _, c := range i.Children {
		wipe(c)
	}
}

// Attrs are the lifecycle attributes of an object.
type Attrs struct {
	State       uint32
	HasState    bool
	Activation  time.Time
	Deactivated time.Time
	Initial     time.Time
	Algorithm   uint32
	Length      int
	Names       []string
	ObjectType  uint32
	UsageMask   int32
	LastChange  time.Time
	Destroyed   time.Time
	Compromised time.Time
}

// GetAttributes reads the attributes the sync needs. No attribute list is sent, so the server returns
// all of them in the form of the negotiated version (1.x Attribute structures / 2.x Attributes).
func (c *Client) GetAttributes(id string) (*Attrs, error) {
	resp, err := c.roundTrip(OpGetAttributes, Struct(TagRequestPayload, Text(TagUniqueIdentifier, id)))
	if err != nil {
		return nil, err
	}
	a := &Attrs{}
	set := func(name string, tag Tag, v *Item) {
		switch {
		case tag == TagState || name == "State":
			a.State, a.HasState = v.Uint(), true
		case tag == TagActivationDate || name == "Activation Date":
			a.Activation = v.Time()
		case tag == TagDeactivationDate || name == "Deactivation Date":
			a.Deactivated = v.Time()
		case tag == TagInitialDate || name == "Initial Date":
			a.Initial = v.Time()
		case tag == TagCryptographicAlgorithm || name == "Cryptographic Algorithm":
			a.Algorithm = v.Uint()
		case tag == TagCryptographicLength || name == "Cryptographic Length":
			a.Length = int(v.Num)
		case tag == TagObjectType || name == "Object Type":
			a.ObjectType = v.Uint()
		case tag == TagCryptographicUsageMask || name == "Cryptographic Usage Mask":
			a.UsageMask = int32(v.Num)
		case tag == TagLastChangeDate || name == "Last Change Date":
			a.LastChange = v.Time()
		case tag == TagDestroyDate || name == "Destroy Date":
			a.Destroyed = v.Time()
		case tag == TagCompromiseOccurrenceDate || name == "Compromise Occurrence Date":
			a.Compromised = v.Time()
		case tag == TagName || name == "Name":
			if nv := v.Child(TagNameValue); nv != nil {
				a.Names = append(a.Names, nv.Str())
			}
		}
	}
	if as := resp.Child(TagAttributes); as != nil { // 2.x and later
		for _, v := range as.Children {
			set("", v.Tag, v)
		}
	}
	for _, at := range resp.All(TagAttribute) { // 1.x
		n, v := at.Child(TagAttributeName), at.Child(TagAttributeValue)
		if n != nil && v != nil {
			set(n.Str(), 0, v)
		}
	}
	return a, nil
}

// Sorted returns ids ordered by creation: oldest first (used by the adapter for version numbering).
func sortedByInitial(ids []string, attrs map[string]*Attrs) []string {
	out := append([]string(nil), ids...)
	sort.SliceStable(out, func(i, j int) bool {
		a, b := attrs[out[i]], attrs[out[j]]
		if a == nil || b == nil {
			return false
		}
		return a.Initial.Before(b.Initial)
	})
	return out
}
