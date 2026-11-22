package kmip

import (
	"errors"
	"fmt"
	"time"
)

// Lifecycle operations (Create, Create Key Pair, Activate, Revoke, Destroy, Re-key, Locate with
// filters, Query). Attribute encoding follows the negotiated version: KMIP 1.x sends Attribute
// name/value structures inside a Template-Attribute, 2.x and later send one Attributes structure.

// Attr is one attribute to send. Value carries the attribute's own tag (used verbatim by 2.x); for 1.x
// it is re-tagged as Attribute Value under the given Name.
type Attr struct {
	Name  string
	Value *Item
}

func (c *Client) attrItems(attrs []Attr) []*Item {
	out := make([]*Item, 0, len(attrs))
	for _, a := range attrs {
		if c.version.modern() {
			out = append(out, a.Value)
			continue
		}
		if a.Name == "" {
			continue // a 2.x-only attribute
		}
		v := *a.Value
		v.Tag = TagAttributeValue
		out = append(out, Struct(TagAttribute, Text(TagAttributeName, a.Name), &v))
	}
	return out
}

// attrContainer wraps attribute items the way the negotiated version expects. legacy is the 1.x
// container tag; modern the 2.x one.
func (c *Client) attrContainer(legacy, modern Tag, attrs []Attr) *Item {
	if c.version.modern() {
		return Struct(modern, c.attrItems(attrs)...)
	}
	return Struct(legacy, c.attrItems(attrs)...)
}

// NameAttr builds the Name attribute (uninterpreted text string).
func NameAttr(name string) Attr {
	return Attr{"Name", Struct(TagName, Text(TagNameValue, name), Enum(TagNameType, NameTypeUninterpretedTextString))}
}

// AlgorithmAttrs are the Cryptographic Algorithm / Length / Usage Mask attributes (bits 0 = no length,
// e.g. for post-quantum algorithms whose size is implied; usageMask 0 = leave it to the server).
func AlgorithmAttrs(alg uint32, bits int, usageMask int32) []Attr {
	a := []Attr{{"Cryptographic Algorithm", Enum(TagCryptographicAlgorithm, alg)}}
	if bits > 0 {
		a = append(a, Attr{"Cryptographic Length", Int(TagCryptographicLength, int32(bits))})
	}
	if usageMask != 0 {
		a = append(a, Attr{"Cryptographic Usage Mask", Int(TagCryptographicUsageMask, usageMask)})
	}
	return a
}

// Create generates a symmetric key on the server and returns its unique identifier.
func (c *Client) Create(attrs []Attr) (string, error) {
	pl := Struct(TagRequestPayload, Enum(TagObjectType, ObjSymmetricKey))
	pl.Children = append(pl.Children, c.attrContainer(TagTemplateAttribute, TagAttributes, attrs))
	resp, err := c.roundTrip(OpCreate, pl)
	if err != nil {
		return "", err
	}
	u := resp.Child(TagUniqueIdentifier)
	if u == nil {
		return "", errors.New("kmip: Create returned no unique identifier")
	}
	return u.Str(), nil
}

// CreateKeyPair generates an asymmetric key pair; common applies to both halves.
func (c *Client) CreateKeyPair(common []Attr) (privID, pubID string, err error) {
	return c.CreateKeyPairEx(common, nil, nil)
}

// CreateKeyPairEx is CreateKeyPair with separate attributes for the private and the public key.
func (c *Client) CreateKeyPairEx(common, private, public []Attr) (privID, pubID string, err error) {
	pl := Struct(TagRequestPayload)
	if c.version.modern() {
		pl.Children = append(pl.Children, Struct(TagCommonAttributes, c.attrItems(common)...))
		if len(private) > 0 {
			pl.Children = append(pl.Children, Struct(TagPrivateKeyAttributes, c.attrItems(private)...))
		}
		if len(public) > 0 {
			pl.Children = append(pl.Children, Struct(TagPublicKeyAttributes, c.attrItems(public)...))
		}
	} else {
		pl.Children = append(pl.Children, Struct(TagCommonTemplateAttribute, c.attrItems(common)...))
		if len(private) > 0 {
			pl.Children = append(pl.Children, Struct(TagPrivateKeyTemplateAttribute, c.attrItems(private)...))
		}
		if len(public) > 0 {
			pl.Children = append(pl.Children, Struct(TagPublicKeyTemplateAttribute, c.attrItems(public)...))
		}
	}
	resp, err := c.roundTrip(OpCreateKeyPair, pl)
	if err != nil {
		return "", "", err
	}
	priv, pub := resp.Child(TagPrivateKeyUniqueIdentifier), resp.Child(TagPublicKeyUniqueIdentifier)
	if priv == nil || pub == nil {
		return "", "", errors.New("kmip: Create Key Pair returned no identifiers")
	}
	return priv.Str(), pub.Str(), nil
}

// CurveAttr selects the elliptic curve (Cryptographic Domain Parameters / Recommended Curve).
func CurveAttr(curve uint32) Attr {
	return Attr{"Cryptographic Domain Parameters", Struct(TagCryptographicDomainParameters, Enum(TagRecommendedCurve, curve))}
}

// KeyFormatAttr / ObjectTypeAttr exist as attributes in KMIP 2.x only; they are ignored for 1.x.
func KeyFormatAttr(f uint32) Attr  { return Attr{"", Enum(TagKeyFormatType, f)} }
func ObjectTypeAttr(o uint32) Attr { return Attr{"", Enum(TagObjectType, o)} }

func (c *Client) simple(op uint32, id string, extra ...*Item) (*Item, error) {
	pl := Struct(TagRequestPayload, Text(TagUniqueIdentifier, id))
	pl.Children = append(pl.Children, extra...)
	return c.roundTrip(op, pl)
}

// Activate moves a Pre-Active object to Active.
func (c *Client) Activate(id string) error {
	_, err := c.simple(OpActivate, id)
	return err
}

// Revoke deactivates (reason != key compromise: state Deactivated) or marks an object compromised
// (state Compromised). message is free text kept by the server.
func (c *Client) Revoke(id string, reason uint32, message string) error {
	rr := Struct(TagRevocationReason, Enum(TagRevocationReasonCode, reason))
	if message != "" {
		rr.Children = append(rr.Children, Text(TagRevocationMessage, message))
	}
	extra := []*Item{rr}
	if reason == RevokeKeyCompromise || reason == RevokeCACompromise {
		extra = append(extra, DateTime(TagCompromiseOccurrenceDate, time.Now()))
	}
	_, err := c.simple(OpRevoke, id, extra...)
	return err
}

// Destroy destroys the key material (irreversible); the object stays as Destroyed metadata.
func (c *Client) Destroy(id string) error {
	_, err := c.simple(OpDestroy, id)
	return err
}

// ReKey creates a replacement for a symmetric key and returns the new object's identifier.
func (c *Client) ReKey(id string) (string, error) {
	resp, err := c.simple(OpReKey, id)
	if err != nil {
		return "", err
	}
	u := resp.Child(TagUniqueIdentifier)
	if u == nil {
		return "", errors.New("kmip: Re-key returned no unique identifier")
	}
	return u.Str(), nil
}

// LocateAll lists identifiers of objects matching every filter attribute (nil = all objects the
// client may see). max 0 = server default.
func (c *Client) LocateAll(filter []Attr, max int) ([]string, error) {
	pl := Struct(TagRequestPayload)
	if max > 0 {
		pl.Children = append(pl.Children, Int(TagMaximumItems, int32(max)))
	}
	if c.version.modern() {
		// 2.x: the Attributes structure is mandatory even when no filter is given (Eviden KMS rejects its absence)
		pl.Children = append(pl.Children, Struct(TagAttributes, c.attrItems(filter)...))
	} else {
		pl.Children = append(pl.Children, c.attrItems(filter)...)
	}
	resp, err := c.roundTrip(OpLocate, pl)
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, u := range resp.All(TagUniqueIdentifier) {
		ids = append(ids, u.Str())
	}
	return ids, nil
}

// StateAttr filters by lifecycle state.
func StateAttr(state uint32) Attr { return Attr{"State", Enum(TagState, state)} }

// ServerInfo is the result of Query.
type ServerInfo struct {
	Operations  []string
	ObjectTypes []string
	Vendor      string
}

// Query asks the server for its capabilities.
func (c *Client) Query() (*ServerInfo, error) {
	pl := Struct(TagRequestPayload,
		Enum(TagQueryFunction, QueryFnQueryOperations),
		Enum(TagQueryFunction, QueryFnQueryObjects),
		Enum(TagQueryFunction, QueryFnQueryServerInformation))
	resp, err := c.roundTrip(OpQuery, pl)
	if err != nil {
		return nil, err
	}
	si := &ServerInfo{}
	for _, o := range resp.All(TagOperation) {
		if n, ok := operationNames[o.Uint()]; ok {
			si.Operations = append(si.Operations, n)
		} else {
			si.Operations = append(si.Operations, fmt.Sprintf("0x%X", o.Uint()))
		}
	}
	for _, o := range resp.All(TagObjectType) {
		if n, ok := objectNames[o.Uint()]; ok {
			si.ObjectTypes = append(si.ObjectTypes, n)
		}
	}
	if v := resp.Child(TagVendorIdentification); v != nil {
		si.Vendor = v.Str()
	}
	return si, nil
}

// StateName returns the KMIP name of a lifecycle state.
func StateName(s uint32) string {
	if n, ok := stateNames[s]; ok {
		return n
	}
	return fmt.Sprintf("0x%X", s)
}

// AlgorithmName returns the KMIP name of a cryptographic algorithm.
func AlgorithmName(a uint32) string { return algName(a) }

// ObjectName returns the KMIP name of an object type.
func ObjectName(o uint32) string {
	if n, ok := objectNames[o]; ok {
		return n
	}
	return fmt.Sprintf("0x%X", o)
}

// AddAttribute adds one attribute (e.g. an additional Name) to an object.
func (c *Client) AddAttribute(id string, a Attr) error {
	var attr *Item
	if c.version.modern() {
		attr = Struct(TagNewAttribute, a.Value)
	} else {
		v := *a.Value
		v.Tag = TagAttributeValue
		attr = Struct(TagAttribute, Text(TagAttributeName, a.Name), &v)
	}
	_, err := c.simple(OpAddAttribute, id, attr)
	return err
}

// OperationName returns the KMIP name of an operation code.
func OperationName(op uint32) string {
	if n, ok := operationNames[op]; ok {
		return n
	}
	return fmt.Sprintf("0x%X", op)
}

// ObjectGroupAttr sets the Object Group attribute (the pqc-kms server uses it to name the permission group).
func ObjectGroupAttr(group string) Attr {
	return Attr{"Object Group", Text(TagObjectGroup, group)}
}
