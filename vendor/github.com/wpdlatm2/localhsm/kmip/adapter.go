package kmip

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/wpdlatm2/localhsm"
)

// ErrNotFound is returned when no object carries the requested key name.
var ErrNotFound = errors.New("kmip: no object with that key name")

// Adapter implements localhsm.KMS on top of a KMIP server: a key reference is a KMIP key *name*; every
// managed object carrying that name becomes one version of the key (a rotated key is a new object with
// the same name). The values are fetched over mutual TLS and handed to HSM.SyncFromKMS, which stores
// them under the TPM-protected master key.
type Adapter struct {
	Config Config
	// Exportable: may applications read the key values back out of the HSM (custody)? The KMS policy
	// decides in Enterprise mode; KMIP has no such attribute, so it is set here.
	Exportable bool
	// Types overrides the key type per name where it cannot be derived (e.g. a Secret Data object, or
	// AES256GCM instead of the custody type AES256).
	Types map[string]localhsm.KeyType
}

var _ localhsm.KMS = (*Adapter)(nil)

// Fetch implements localhsm.KMS.
func (a *Adapter) Fetch(ctx context.Context, refs []string) ([]localhsm.KMSKey, error) {
	c, err := Dial(ctx, a.Config)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	var out []localhsm.KMSKey
	fail := func(err error) ([]localhsm.KMSKey, error) {
		for _, k := range out {
			for _, v := range k.Versions {
				clear(v.Material)
			}
		}
		return nil, err
	}
	for _, name := range refs {
		if err := ctx.Err(); err != nil {
			return fail(err)
		}
		k, err := a.fetchOne(c, name)
		if err != nil {
			return fail(fmt.Errorf("%s: %w", name, err))
		}
		out = append(out, *k)
	}
	return out, nil
}

func (a *Adapter) fetchOne(c *Client, name string) (*localhsm.KMSKey, error) {
	ids, err := c.Locate(name)
	if err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return nil, ErrNotFound
	}
	attrs := map[string]*Attrs{}
	for _, id := range ids {
		at, err := c.GetAttributes(id)
		if err != nil {
			return nil, err
		}
		attrs[id] = at
	}
	k := &localhsm.KMSKey{Ref: name, Exportable: a.Exportable}
	fail := func(err error) (*localhsm.KMSKey, error) {
		for _, v := range k.Versions {
			clear(v.Material)
		}
		return nil, err
	}
	for _, id := range sortedByInitial(ids, attrs) {
		at := attrs[id]
		st, ok := mapState(at)
		v := localhsm.KMSKeyVersion{ID: id, Status: st}
		if ok { // usable states carry material
			o, err := c.Get(id)
			var pe *ProtocolError
			if err != nil && st == localhsm.StatusDecryptOnly && errors.As(err, &pe) {
				// Some servers (Eviden KMS) refuse Get on a Deactivated object. Report the state without a value:
				// the keystore updates versions it already holds and skips (reports) ones it never saw.
				typ, terr := a.typeFromAttrs(name, at)
				if terr != nil {
					return fail(fmt.Errorf("object %s: %w (and the server refuses to return it)", id, err))
				}
				if k.Type != "" && k.Type != typ {
					return fail(fmt.Errorf("object %s is a %s but earlier versions are %s", id, typ, k.Type))
				}
				k.Type = typ
				k.Versions = append(k.Versions, versionMeta(id, st, at))
				continue
			}
			if err != nil {
				return fail(err)
			}
			if o.Wrapped {
				clear(o.Material)
				return fail(fmt.Errorf("object %s is returned wrapped; unwrapping is not supported", id))
			}
			typ, mat, err := a.convert(name, o, at)
			if err != nil {
				clear(o.Material)
				return fail(fmt.Errorf("object %s: %w", id, err))
			}
			if k.Type != "" && k.Type != typ {
				clear(mat)
				return fail(fmt.Errorf("object %s is a %s but earlier versions are %s", id, typ, k.Type))
			}
			k.Type = typ
			v.Material = mat
		}
		meta := versionMeta(id, st, at)
		v.IssuedAt, v.ExpiresAt = meta.IssuedAt, meta.ExpiresAt
		k.Versions = append(k.Versions, v)
	}
	if k.Type == "" { // every object was unusable: the key has nothing to hand out
		return fail(fmt.Errorf("no object named %q is usable (all pre-active, compromised or destroyed)", name))
	}
	return k, nil
}

// mapState converts the KMIP lifecycle state. The bool reports whether key material is needed.
func mapState(a *Attrs) (localhsm.KeyStatus, bool) {
	if !a.HasState {
		// 1.x servers must report State for managed cryptographic objects; absence is a server quirk.
		// Treat it as unusable rather than guessing "active".
		return localhsm.StatusDisabled, false
	}
	switch a.State {
	case StateActive:
		return localhsm.StatusActive, true
	case StateDeactivated:
		return localhsm.StatusDecryptOnly, true
	default: // Pre-Active, Compromised, Destroyed, Destroyed Compromised
		return localhsm.StatusDisabled, false
	}
}

// convert derives the localhsm key type and the stored material.
func (a *Adapter) convert(name string, o *Object, at *Attrs) (localhsm.KeyType, []byte, error) {
	override := a.Types[name]
	switch o.Type {
	case ObjPrivateKey:
		return convertPrivate(o.Material, override)
	case ObjSymmetricKey, ObjSecretData:
		if o.Format != FmtRaw && o.Format != FmtOpaque && o.Format != FmtTransparentSymmetricKey {
			return "", nil, fmt.Errorf("key format 0x%X is not supported for secret keys (need Raw)", o.Format)
		}
		if override != "" {
			return override, o.Material, nil
		}
		alg := o.Algorithm
		if alg == 0 {
			alg = at.Algorithm
		}
		bits := len(o.Material) * 8
		if o.Length != 0 && o.Length != bits {
			return "", nil, fmt.Errorf("declared length %d bits does not match the %d-bit value", o.Length, bits)
		}
		t, ok := symType(alg, bits)
		if !ok {
			return "", nil, fmt.Errorf("cannot map algorithm %s / %d bits to a key type (set an explicit type)", algName(alg), bits)
		}
		return t, o.Material, nil
	}
	return "", nil, fmt.Errorf("object type %s is not supported", objectNames[o.Type])
}

func algName(a uint32) string {
	if n := algorithmNames[a]; n != "" {
		return n
	}
	if n := extAlgorithmNames[a]; n != "" {
		return n
	}
	return fmt.Sprintf("0x%X", a)
}

func symType(alg uint32, bits int) (localhsm.KeyType, bool) {
	switch alg {
	case AlgAES:
		switch bits {
		case 128:
			return localhsm.AES128, true
		case 192:
			return localhsm.AES192, true
		case 256:
			return localhsm.AES256, true
		}
	case AlgARIA:
		switch bits {
		case 128:
			return localhsm.ARIA128, true
		case 192:
			return localhsm.ARIA192, true
		case 256:
			return localhsm.ARIA256, true
		}
	case AlgSEED:
		if bits == 128 {
			return localhsm.SEED128, true
		}
	}
	return "", false
}

// convertPrivate accepts PKCS#8, PKCS#1 (RSA) or SEC1 (EC) DER and returns PKCS#8.
func convertPrivate(der []byte, override localhsm.KeyType) (localhsm.KeyType, []byte, error) {
	var key any
	var err error
	if key, err = x509.ParsePKCS8PrivateKey(der); err != nil {
		if k, e2 := x509.ParsePKCS1PrivateKey(der); e2 == nil {
			key, err = k, nil
		} else if k, e3 := x509.ParseECPrivateKey(der); e3 == nil {
			key, err = k, nil
		}
	}
	if err != nil {
		return "", nil, errors.New("private key is not PKCS#8, PKCS#1 or SEC1 DER")
	}
	var t localhsm.KeyType
	switch k := key.(type) {
	case *rsa.PrivateKey:
		switch k.N.BitLen() {
		case 2048:
			t = localhsm.RSA2048
		case 3072:
			t = localhsm.RSA3072
		case 4096:
			t = localhsm.RSA4096
		default:
			return "", nil, fmt.Errorf("RSA-%d is not supported (need 2048, 3072 or 4096)", k.N.BitLen())
		}
	case *ecdsa.PrivateKey:
		switch k.Curve {
		case elliptic.P256():
			t = localhsm.ECDSAP256
		case elliptic.P384():
			t = localhsm.ECDSAP384
		case elliptic.P521():
			t = localhsm.ECDSAP521
		default:
			return "", nil, errors.New("unsupported EC curve")
		}
	default:
		return "", nil, fmt.Errorf("unsupported private key type %T", key)
	}
	if override != "" && override != t {
		return "", nil, fmt.Errorf("configured type %s does not match the key (%s)", override, t)
	}
	p8, err := x509.MarshalPKCS8PrivateKey(key)
	clear(der)
	return t, p8, err
}

// versionMeta builds a version entry without material (state and dates only).
func versionMeta(id string, st localhsm.KeyStatus, at *Attrs) localhsm.KMSKeyVersion {
	v := localhsm.KMSKeyVersion{ID: id, Status: st}
	switch {
	case !at.Activation.IsZero():
		v.IssuedAt = at.Activation
	case !at.Initial.IsZero():
		v.IssuedAt = at.Initial
	}
	if st == localhsm.StatusActive && !at.Deactivated.IsZero() {
		v.ExpiresAt = at.Deactivated
	}
	return v
}

// typeFromAttrs derives the key type from attributes only (used when the value cannot be fetched).
func (a *Adapter) typeFromAttrs(name string, at *Attrs) (localhsm.KeyType, error) {
	if t := a.Types[name]; t != "" {
		return t, nil
	}
	switch at.ObjectType {
	case ObjSymmetricKey, 0: // servers may omit the Object Type attribute; the algorithm still tells
		if t, ok := symType(at.Algorithm, at.Length); ok {
			return t, nil
		}
	case ObjPrivateKey:
		if at.Algorithm == AlgRSA {
			switch at.Length {
			case 2048:
				return localhsm.RSA2048, nil
			case 3072:
				return localhsm.RSA3072, nil
			case 4096:
				return localhsm.RSA4096, nil
			}
		}
	}
	return "", errors.New("the key type cannot be derived from its attributes (set an explicit type)")
}
