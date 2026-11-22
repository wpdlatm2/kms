package kmipsrv

import (
	"time"

	"github.com/wpdlatm2/localhsm/kmip"
	"github.com/wpdlatm2/kms/internal/kms"
)

// ---- attribute vocabulary (name of the 1.x Attribute <-> tag of the 2.x typed attribute)

var attrNames = map[kmip.Tag]string{
	kmip.TagUniqueIdentifier:              "Unique Identifier",
	kmip.TagObjectType:                    "Object Type",
	kmip.TagName:                          "Name",
	kmip.TagState:                         "State",
	kmip.TagCryptographicAlgorithm:        "Cryptographic Algorithm",
	kmip.TagCryptographicLength:           "Cryptographic Length",
	kmip.TagCryptographicUsageMask:        "Cryptographic Usage Mask",
	kmip.TagCryptographicDomainParameters: "Cryptographic Domain Parameters",
	kmip.TagInitialDate:                   "Initial Date",
	kmip.TagActivationDate:                "Activation Date",
	kmip.TagDeactivationDate:              "Deactivation Date",
	kmip.TagDestroyDate:                   "Destroy Date",
	kmip.TagLastChangeDate:                "Last Change Date",
	kmip.TagCompromiseOccurrenceDate:      "Compromise Occurrence Date",
	kmip.TagKeyFormatType:                 "Key Format Type",
	kmip.TagObjectGroup:                   "Object Group",
}

func tagOfName(name string) kmip.Tag {
	for t, n := range attrNames {
		if n == name {
			return t
		}
	}
	return 0
}

// bag holds the attributes of a request, keyed by attribute name (a name can repeat).
type bag map[string][]*kmip.Item

func (b bag) one(name string) *kmip.Item {
	if l := b[name]; len(l) > 0 {
		return l[0]
	}
	return nil
}

// parseAttrs reads the attribute container of a request in the encoding of its protocol version.
// For 1.x the container's children are Attribute structures; for 2.x they are the typed attributes.
func parseAttrs(v kmip.Version, container *kmip.Item) bag {
	b := bag{}
	if container == nil {
		return b
	}
	for _, c := range container.Children {
		if v.Major >= 2 {
			if n := attrNames[c.Tag]; n != "" {
				b[n] = append(b[n], c)
			}
			continue
		}
		if c.Tag != kmip.TagAttribute {
			continue
		}
		n, val := c.Child(kmip.TagAttributeName), c.Child(kmip.TagAttributeValue)
		if n != nil && val != nil {
			b[n.Str()] = append(b[n.Str()], val)
		}
	}
	return b
}

func (b bag) names() []string {
	var out []string
	for _, it := range b["Name"] {
		if nv := it.Child(kmip.TagNameValue); nv != nil {
			out = append(out, nv.Str())
		}
	}
	return out
}

func (b bag) curve() uint32 {
	if d := b.one("Cryptographic Domain Parameters"); d != nil {
		if c := d.Child(kmip.TagRecommendedCurve); c != nil {
			return c.Uint()
		}
	}
	return 0
}

func (b bag) group() string {
	if it := b.one("Object Group"); it != nil {
		return it.Str()
	}
	return ""
}

func (b bag) algorithm() uint32 {
	if it := b.one("Cryptographic Algorithm"); it != nil {
		return it.Uint()
	}
	return 0
}

func (b bag) length() int {
	if it := b.one("Cryptographic Length"); it != nil {
		return int(it.Num)
	}
	return 0
}

func (b bag) usage() int32 {
	if it := b.one("Cryptographic Usage Mask"); it != nil {
		return int32(max(min(it.Num, 1<<31-1), -1<<31))
	}
	return 0
}

// attrContainer finds the creation attributes: 1.x Template-Attribute, 2.x Attributes.
func attrContainer(v kmip.Version, pl *kmip.Item, legacy, modern kmip.Tag) *kmip.Item {
	if v.Major >= 2 {
		return pl.Child(modern)
	}
	return pl.Child(legacy)
}

func merge(bags ...bag) bag {
	out := bag{}
	for _, b := range bags {
		for k, l := range b {
			if k == "Name" {
				out[k] = append(out[k], l...)
			} else {
				out[k] = l
			}
		}
	}
	return out
}

// ---- Create / Create Key Pair

func (s *Server) create(p kms.Principal, v kmip.Version, pl *kmip.Item) (*kmip.Item, *opError) {
	if t := pl.Child(kmip.TagObjectType); t == nil || t.Uint() != kmip.ObjSymmetricKey {
		return nil, &opError{kmip.ReasonOperationNotSupported, "Create supports symmetric keys; use Create Key Pair for asymmetric keys"}
	}
	b := parseAttrs(v, attrContainer(v, pl, kmip.TagTemplateAttribute, kmip.TagAttributes))
	a := kms.FindAlgo(b.algorithm(), b.length(), 0, false)
	if a == nil {
		return nil, bad("unsupported cryptographic algorithm / length")
	}
	out, err := s.Svc.Create(p, kms.CreateReq{Algo: a.ID, Group: b.group(), Names: b.names(), Usage: b.usage()})
	if err != nil {
		return nil, fromErr(err)
	}
	// the Create response carries the Object Type before the Unique Identifier (KMIP section 4.1)
	return kmip.Struct(kmip.TagResponsePayload, kmip.Enum(kmip.TagObjectType, kmip.ObjSymmetricKey), kmip.Text(kmip.TagUniqueIdentifier, out[0].ID)), nil
}

func (s *Server) createPair(p kms.Principal, v kmip.Version, pl *kmip.Item) (*kmip.Item, *opError) {
	ct, pt, ut := kmip.TagCommonTemplateAttribute, kmip.TagPrivateKeyTemplateAttribute, kmip.TagPublicKeyTemplateAttribute
	if v.Major >= 2 {
		ct, pt, ut = kmip.TagCommonAttributes, kmip.TagPrivateKeyAttributes, kmip.TagPublicKeyAttributes
	}
	common, priv, pub := parseAttrs(v, pl.Child(ct)), parseAttrs(v, pl.Child(pt)), parseAttrs(v, pl.Child(ut))
	all := merge(common, priv)
	a := kms.FindAlgo(all.algorithm(), all.length(), all.curve(), true)
	if a == nil {
		return nil, bad("unsupported cryptographic algorithm / length / curve")
	}
	names := append(append(all.names(), pub.names()...), []string(nil)...)
	out, err := s.Svc.Create(p, kms.CreateReq{Algo: a.ID, Group: all.group(), Names: names, Usage: all.usage()})
	if err != nil {
		return nil, fromErr(err)
	}
	return kmip.Struct(kmip.TagResponsePayload,
		kmip.Text(kmip.TagPrivateKeyUniqueIdentifier, out[0].ID), kmip.Text(kmip.TagPublicKeyUniqueIdentifier, out[1].ID)), nil
}

// ---- Locate

func (s *Server) locate(p kms.Principal, v kmip.Version, pl *kmip.Item) (*kmip.Item, *opError) {
	var b bag
	if v.Major >= 2 {
		b = parseAttrs(v, pl.Child(kmip.TagAttributes))
	} else {
		b = parseAttrs(v, pl) // 1.x: Attribute structures sit directly in the payload
	}
	f := kms.Filter{Alg: b.algorithm(), Bits: b.length(), Group: b.group()}
	if n := b.names(); len(n) > 0 {
		f.Name = n[0]
	}
	if it := b.one("State"); it != nil {
		f.State, f.HasState = kms.State(it.Uint()), true
	}
	if it := b.one("Object Type"); it != nil {
		f.Kind = it.Uint()
	}
	max, offset := 0, 0
	if m := pl.Child(kmip.TagMaximumItems); m != nil {
		max = int(m.Num)
	}
	if o := pl.Child(kmip.TagOffsetItems); o != nil {
		offset = int(o.Num)
	}
	ids := s.Svc.Locate(p, f)
	if offset > 0 {
		if offset >= len(ids) {
			ids = nil
		} else {
			ids = ids[offset:]
		}
	}
	if max > 0 && len(ids) > max {
		ids = ids[:max]
	}
	out := kmip.Struct(kmip.TagResponsePayload, kmip.Int(kmip.TagLocatedItems, i32(len(ids))))
	for _, id := range ids {
		out.Children = append(out.Children, kmip.Text(kmip.TagUniqueIdentifier, id))
	}
	return out, nil
}

// ---- Get Attributes

type namedAttr struct {
	name string
	item *kmip.Item
}

func attrList(o kms.View, v kmip.Version) []namedAttr {
	d := func(tag kmip.Tag, ts int64) *kmip.Item { return kmip.DateTime(tag, time.Unix(ts, 0)) }
	l := []namedAttr{
		{"Unique Identifier", kmip.Text(kmip.TagUniqueIdentifier, o.ID)},
		{"Object Type", kmip.Enum(kmip.TagObjectType, o.Kind)},
		{"State", kmip.Enum(kmip.TagState, uint32(o.State))},
		{"Cryptographic Algorithm", kmip.Enum(kmip.TagCryptographicAlgorithm, o.Alg)},
		{"Cryptographic Usage Mask", kmip.Int(kmip.TagCryptographicUsageMask, o.Usage)},
		{"Initial Date", d(kmip.TagInitialDate, o.Created)},
		{"Last Change Date", d(kmip.TagLastChangeDate, o.Changed)},
		{"Object Group", kmip.Text(kmip.TagObjectGroup, o.Group)},
	}
	if o.Bits > 0 {
		l = append(l, namedAttr{"Cryptographic Length", kmip.Int(kmip.TagCryptographicLength, i32(o.Bits))})
	}
	if o.Curve != 0 {
		l = append(l, namedAttr{"Cryptographic Domain Parameters", kmip.Struct(kmip.TagCryptographicDomainParameters, kmip.Enum(kmip.TagRecommendedCurve, o.Curve))})
	}
	for _, n := range o.Names {
		l = append(l, namedAttr{"Name", kmip.Struct(kmip.TagName, kmip.Text(kmip.TagNameValue, n), kmip.Enum(kmip.TagNameType, kmip.NameTypeUninterpretedTextString))})
	}
	if o.Activated != 0 {
		l = append(l, namedAttr{"Activation Date", d(kmip.TagActivationDate, o.Activated)})
	}
	if o.Deactivated != 0 {
		l = append(l, namedAttr{"Deactivation Date", d(kmip.TagDeactivationDate, o.Deactivated)})
	}
	if o.Compromised != 0 {
		l = append(l, namedAttr{"Compromise Occurrence Date", d(kmip.TagCompromiseOccurrenceDate, o.Compromised)})
	}
	if o.Destroyed != 0 {
		l = append(l, namedAttr{"Destroy Date", d(kmip.TagDestroyDate, o.Destroyed)})
	}
	if v.Major >= 2 {
		l = append(l, namedAttr{"Key Format Type", kmip.Enum(kmip.TagKeyFormatType, o.Format)})
	}
	return l
}

func (s *Server) getAttributes(p kms.Principal, v kmip.Version, pl *kmip.Item) (*kmip.Item, *opError) {
	id := pl.Child(kmip.TagUniqueIdentifier)
	if id == nil {
		return nil, bad("missing unique identifier")
	}
	o, err := s.Svc.Attributes(p, id.Str())
	if err != nil {
		return nil, fromErr(err)
	}
	// optional selection: 1.x Attribute Name items, 2.x Attribute Reference items (an enumeration holding the tag)
	want := map[string]bool{}
	for _, n := range pl.All(kmip.TagAttributeName) {
		want[n.Str()] = true
	}
	for _, r := range pl.All(kmip.TagAttributeReference) {
		if r.Type == kmip.TypeEnumeration {
			if n := attrNames[kmip.Tag(r.Uint())]; n != "" {
				want[n] = true
			}
		}
	}
	out := kmip.Struct(kmip.TagResponsePayload, kmip.Text(kmip.TagUniqueIdentifier, o.ID))
	var typed *kmip.Item
	if v.Major >= 2 {
		typed = kmip.Struct(kmip.TagAttributes)
		out.Children = append(out.Children, typed)
	}
	for _, a := range attrList(o, v) {
		if len(want) > 0 && !want[a.name] {
			continue
		}
		if v.Major >= 2 {
			if a.name != "Unique Identifier" {
				typed.Children = append(typed.Children, a.item)
			}
			continue
		}
		val := *a.item
		val.Tag = kmip.TagAttributeValue
		out.Children = append(out.Children, kmip.Struct(kmip.TagAttribute, kmip.Text(kmip.TagAttributeName, a.name), &val))
	}
	return out, nil
}

// ---- Get

func (s *Server) get(p kms.Principal, pl *kmip.Item) (*kmip.Item, *opError) {
	id := pl.Child(kmip.TagUniqueIdentifier)
	if id == nil {
		return nil, bad("missing unique identifier")
	}
	if pl.Child(kmip.TagKeyWrappingSpecification) != nil {
		return nil, &opError{kmip.ReasonOperationNotSupported, "key wrapping on Get is not supported"}
	}
	m, err := s.Svc.GetMaterial(p, id.Str())
	if err != nil {
		return nil, fromErr(err)
	}
	defer clear(m.Bytes)
	o := m.Info
	kb := kmip.Struct(kmip.TagKeyBlock,
		kmip.Enum(kmip.TagKeyFormatType, o.Format),
		kmip.Struct(kmip.TagKeyValue, kmip.Bytes(kmip.TagKeyMaterial, append([]byte(nil), m.Bytes...))),
		kmip.Enum(kmip.TagCryptographicAlgorithm, o.Alg))
	if o.Bits > 0 {
		kb.Children = append(kb.Children, kmip.Int(kmip.TagCryptographicLength, i32(o.Bits)))
	}
	holder := kmip.TagSymmetricKey
	switch o.Kind {
	case kms.KindPrivate:
		holder = kmip.TagPrivateKey
	case kms.KindPublic:
		holder = kmip.TagPublicKey
	case kms.KindSecret:
		holder = kmip.TagSecretData
	}
	return kmip.Struct(kmip.TagResponsePayload, kmip.Enum(kmip.TagObjectType, o.Kind), kmip.Text(kmip.TagUniqueIdentifier, o.ID), kmip.Struct(holder, kb)), nil
}

// ---- Activate / Revoke / Destroy / Re-key

func (s *Server) lifecycle(p kms.Principal, op uint32, pl *kmip.Item) (*kmip.Item, *opError) {
	id := pl.Child(kmip.TagUniqueIdentifier)
	if id == nil {
		return nil, bad("missing unique identifier")
	}
	var err error
	switch op {
	case kmip.OpActivate:
		_, err = s.Svc.Activate(p, id.Str())
	case kmip.OpDestroy:
		_, err = s.Svc.Destroy(p, id.Str())
	case kmip.OpRevoke:
		rr := pl.Child(kmip.TagRevocationReason)
		if rr == nil || rr.Child(kmip.TagRevocationReasonCode) == nil {
			return nil, bad("missing revocation reason")
		}
		switch rr.Child(kmip.TagRevocationReasonCode).Uint() {
		case kmip.RevokeKeyCompromise, kmip.RevokeCACompromise:
			_, err = s.Svc.MarkCompromised(p, id.Str())
		default:
			_, err = s.Svc.Deactivate(p, id.Str())
		}
	case kmip.OpReKey:
		nv, e := s.Svc.ReKey(p, id.Str())
		if e != nil {
			return nil, fromErr(e)
		}
		return uidResponse(nv.ID), nil
	}
	if err != nil {
		return nil, fromErr(err)
	}
	return uidResponse(id.Str()), nil
}

// ---- Add / Delete Attribute (names only)

func (s *Server) names(p kms.Principal, v kmip.Version, op uint32, pl *kmip.Item) (*kmip.Item, *opError) {
	id := pl.Child(kmip.TagUniqueIdentifier)
	if id == nil {
		return nil, bad("missing unique identifier")
	}
	if op == kmip.OpAddAttribute {
		var name *kmip.Item
		if v.Major >= 2 {
			if na := pl.Child(kmip.TagNewAttribute); na != nil {
				name = na.Child(kmip.TagName)
			}
		} else if at := pl.Child(kmip.TagAttribute); at != nil && at.Child(kmip.TagAttributeName) != nil && at.Child(kmip.TagAttributeName).Str() == "Name" {
			name = at.Child(kmip.TagAttributeValue)
		}
		if name == nil || name.Child(kmip.TagNameValue) == nil {
			return nil, &opError{kmip.ReasonOperationNotSupported, "only the Name attribute can be added"}
		}
		if err := s.Svc.SetName(p, id.Str(), name.Child(kmip.TagNameValue).Str(), true); err != nil {
			return nil, fromErr(err)
		}
		return uidResponse(id.Str()), nil
	}
	// Delete Attribute: 1.x Attribute Name "Name" with an optional index
	an := pl.Child(kmip.TagAttributeName)
	if an == nil || an.Str() != "Name" {
		return nil, &opError{kmip.ReasonOperationNotSupported, "only the Name attribute can be deleted"}
	}
	idx := 0
	if ix := pl.Child(kmip.TagAttributeIndex); ix != nil {
		idx = int(ix.Num)
	}
	o, err := s.Svc.Attributes(p, id.Str())
	if err != nil {
		return nil, fromErr(err)
	}
	if idx < 0 || idx >= len(o.Names) {
		return nil, &opError{kmip.ReasonItemNotFound, "no such attribute instance"}
	}
	if err := s.Svc.SetName(p, id.Str(), o.Names[idx], false); err != nil {
		return nil, fromErr(err)
	}
	return uidResponse(id.Str()), nil
}
