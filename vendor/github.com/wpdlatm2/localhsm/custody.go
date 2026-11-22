package localhsm

// Key custody mode: the HSM stores key VALUES (protected by the master key / TPM) and hands them
// to the application, which performs the cryptographic operations itself. The HSM therefore needs
// no implementation of the algorithm (SEED, ARIA, AES-XTS, ML-DSA ...): it only records the
// algorithm, validates the key format/length and guards access.
//
// Material formats (what ExportKey returns / ImportKey accepts):
//
//	symmetric (aes-*, seed-128, aria-*)  raw key bytes
//	rsa-*, ecdsa-*                       PKCS#8 DER private key
//	ed25519                              32-byte seed
//	ml-kem-768/1024                      64-byte seed (FIPS 203 d||z)
//	ml-dsa-44/65/87                      32-byte seed or the FIPS 204 encoded private key (import-only)
//
// SECURITY: an exported key lives in the application's memory. If the application is compromised
// the key is compromised. Mark keys non-exportable (WithExportable(false)) and use the HSM-side
// operations (Encrypt/Sign) where the algorithm is supported; use Zeroize() on exported keys.

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"strconv"
	"time"
)

// Algorithms stored by value. Names are stable identifiers written into the keystore.
const (
	AES128      KeyType = "aes-128"
	AES192      KeyType = "aes-192"
	AES256      KeyType = "aes-256"
	AESXTS128   KeyType = "aes-xts-128" // 32 bytes = two AES-128 keys
	AESXTS256   KeyType = "aes-xts-256" // 64 bytes = two AES-256 keys (the "512-bit AES key")
	SEED128     KeyType = "seed-128"    // KISA SEED, 16 bytes
	ARIA128     KeyType = "aria-128"
	ARIA192     KeyType = "aria-192"
	ARIA256     KeyType = "aria-256"
	RSA2048     KeyType = "rsa-2048"
	RSA3072     KeyType = "rsa-3072"
	RSA4096     KeyType = "rsa-4096"
	ECDSAP256   KeyType = "ecdsa-p256"
	ECDSAP384   KeyType = "ecdsa-p384"
	ECDSAP521   KeyType = "ecdsa-p521"
	MLKEM768    KeyType = "ml-kem-768"
	MLKEM1024   KeyType = "ml-kem-1024"
	MLDSA44     KeyType = "ml-dsa-44" // import-only
	MLDSA65     KeyType = "ml-dsa-65" // import-only
	MLDSA87     KeyType = "ml-dsa-87" // import-only
	custodyHint         = "custody"
)

var (
	// ErrNotExportable: the key was created non-exportable.
	ErrNotExportable = errors.New("localhsm: key is not exportable")
	// ErrImportOnly: the HSM cannot generate this algorithm; generate it elsewhere and ImportKey.
	ErrImportOnly = errors.New("localhsm: algorithm is import-only")
	// ErrNoPublicKey: no public key derivation for this algorithm.
	ErrNoPublicKey = errors.New("localhsm: no public key derivation for this algorithm")
)

type spec struct {
	custody  bool // exportable by default (custody algorithm)
	generate func() ([]byte, error)
	validate func([]byte) error
	public   func([]byte) ([]byte, error)
}

func randBytes(n int) func() ([]byte, error) {
	return func() ([]byte, error) {
		b := make([]byte, n)
		_, err := rand.Read(b)
		return b, err
	}
}

func lenIs(n int) func([]byte) error {
	return func(b []byte) error {
		if len(b) != n {
			return fmt.Errorf("localhsm: key must be %d bytes, got %d", n, len(b))
		}
		return nil
	}
}

func symSpec(n int) *spec { return &spec{custody: true, generate: randBytes(n), validate: lenIs(n)} }

func rsaSpec(bits int) *spec {
	parse := func(b []byte) (*rsa.PrivateKey, error) {
		k, err := x509.ParsePKCS8PrivateKey(b)
		if err != nil {
			return nil, fmt.Errorf("localhsm: bad PKCS#8: %w", err)
		}
		rk, ok := k.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("localhsm: not an RSA key")
		}
		if rk.N.BitLen() != bits {
			return nil, fmt.Errorf("localhsm: RSA key is %d bits, expected %d", rk.N.BitLen(), bits)
		}
		return rk, rk.Validate()
	}
	return &spec{custody: true,
		generate: func() ([]byte, error) {
			k, err := rsa.GenerateKey(rand.Reader, bits)
			if err != nil {
				return nil, err
			}
			return x509.MarshalPKCS8PrivateKey(k)
		},
		validate: func(b []byte) error { _, err := parse(b); return err },
		public: func(b []byte) ([]byte, error) {
			k, err := parse(b)
			if err != nil {
				return nil, err
			}
			return x509.MarshalPKIXPublicKey(&k.PublicKey)
		}}
}

func ecdsaSpec(curve elliptic.Curve) *spec {
	name := curve.Params().Name
	parse := func(b []byte) (*ecdsa.PrivateKey, error) {
		k, err := x509.ParsePKCS8PrivateKey(b)
		if err != nil {
			return nil, fmt.Errorf("localhsm: bad PKCS#8: %w", err)
		}
		ek, ok := k.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("localhsm: not an ECDSA key")
		}
		if ek.Curve.Params().Name != name {
			return nil, fmt.Errorf("localhsm: curve is %s, expected %s", ek.Curve.Params().Name, name)
		}
		return ek, nil
	}
	return &spec{custody: true,
		generate: func() ([]byte, error) {
			k, err := ecdsa.GenerateKey(curve, rand.Reader)
			if err != nil {
				return nil, err
			}
			return x509.MarshalPKCS8PrivateKey(k)
		},
		validate: func(b []byte) error { _, err := parse(b); return err },
		public: func(b []byte) ([]byte, error) {
			k, err := parse(b)
			if err != nil {
				return nil, err
			}
			return x509.MarshalPKIXPublicKey(&k.PublicKey)
		}}
}

func mlkemSpec(large bool) *spec {
	enc := func(seed []byte) ([]byte, error) {
		if len(seed) != mlkem.SeedSize {
			return nil, fmt.Errorf("localhsm: ML-KEM seed must be %d bytes, got %d", mlkem.SeedSize, len(seed))
		}
		if large {
			dk, err := mlkem.NewDecapsulationKey1024(seed)
			if err != nil {
				return nil, err
			}
			return dk.EncapsulationKey().Bytes(), nil
		}
		dk, err := mlkem.NewDecapsulationKey768(seed)
		if err != nil {
			return nil, err
		}
		return dk.EncapsulationKey().Bytes(), nil
	}
	return &spec{custody: true,
		generate: func() ([]byte, error) {
			if large {
				dk, err := mlkem.GenerateKey1024()
				if err != nil {
					return nil, err
				}
				return dk.Bytes(), nil
			}
			dk, err := mlkem.GenerateKey768()
			if err != nil {
				return nil, err
			}
			return dk.Bytes(), nil
		},
		validate: func(b []byte) error { _, err := enc(b); return err },
		public:   enc}
}

// mldsaSpec validates size only (seed or encoded private key); no ML-DSA implementation is bundled.
func mldsaSpec(skLen int) *spec {
	return &spec{custody: true, // generate == nil -> import-only
		validate: func(b []byte) error {
			if len(b) != 32 && len(b) != skLen {
				return fmt.Errorf("localhsm: ML-DSA key must be a 32-byte seed or %d-byte private key, got %d", skLen, len(b))
			}
			return nil
		}}
}

var specs = map[KeyType]*spec{
	// HSM-side operation types (Encrypt / Sign / Verify) - not exportable by default
	AES256GCM: {generate: randBytes(32), validate: lenIs(32)},
	HMACSHA256: {generate: randBytes(32), validate: func(b []byte) error {
		if len(b) < 16 {
			return errors.New("localhsm: HMAC key must be at least 16 bytes")
		}
		return nil
	}},
	Ed25519: {generate: randBytes(32), validate: lenIs(32), public: func(b []byte) ([]byte, error) {
		return ed25519.NewKeyFromSeed(b).Public().(ed25519.PublicKey), nil
	}},
	// custody types
	AES128: symSpec(16), AES192: symSpec(24), AES256: symSpec(32),
	AESXTS128: symSpec(32), AESXTS256: symSpec(64),
	SEED128: symSpec(16), ARIA128: symSpec(16), ARIA192: symSpec(24), ARIA256: symSpec(32),
	RSA2048: rsaSpec(2048), RSA3072: rsaSpec(3072), RSA4096: rsaSpec(4096),
	ECDSAP256: ecdsaSpec(elliptic.P256()), ECDSAP384: ecdsaSpec(elliptic.P384()), ECDSAP521: ecdsaSpec(elliptic.P521()),
	MLKEM768: mlkemSpec(false), MLKEM1024: mlkemSpec(true),
	MLDSA44: mldsaSpec(2560), MLDSA65: mldsaSpec(4032), MLDSA87: mldsaSpec(4896),
}

func newMaterial(t KeyType) ([]byte, error) {
	sp, ok := specs[t]
	if !ok {
		return nil, fmt.Errorf("localhsm: unknown key type %q", t)
	}
	if sp.generate == nil {
		return nil, fmt.Errorf("%w: %s", ErrImportOnly, t)
	}
	return sp.generate()
}

// KeyTypes lists all supported algorithm identifiers.
func KeyTypes() []KeyType {
	out := make([]KeyType, 0, len(specs))
	for t := range specs {
		out = append(out, t)
	}
	return out
}

// KeyOptions tunes key creation. Zero value = default policy for the algorithm.
type KeyOptions struct {
	Exportable *bool
	// IV selects the IV policy of a symmetric key (nil = random per message). See iv.go.
	IV *IVOptions
}

// WithExportable overrides the default export policy (custody types: true, HSM-side types: false).
func WithExportable(b bool) KeyOptions { return KeyOptions{Exportable: &b} }

func (o KeyOptions) resolve(sp *spec) bool {
	if o.Exportable != nil {
		return *o.Exportable
	}
	return sp.custody
}

// ExportedKey is key material handed to the application. Call Zeroize when done.
type ExportedKey struct {
	ID       string
	Type     KeyType
	Version  uint32
	State    string // "active" (use for new operations) or "decrypt-only" (existing data only)
	Material []byte
	// IV is the fixed IV delivered with the key (IV policy "static"); nil otherwise. Use NextIV for the others.
	IV []byte
}

// Zeroize overwrites the key bytes.
func (k *ExportedKey) Zeroize() { clear(k.Material) }

// AuditEvent describes a key custody operation. The hook runs while the HSM lock is held:
// it must be fast and must not call back into the HSM.
type AuditEvent struct {
	Time    time.Time
	Op      string // "generate" | "import" | "export" | "import-version"
	KeyID   string
	Version uint32
	Err     error
}

// SetAuditHook registers a callback for generate/import/export operations (nil disables).
func (h *HSM) SetAuditHook(f func(AuditEvent)) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.audit = f
}

func (h *HSM) emit(op, id string, ver uint32, err error) {
	if h.audit != nil {
		h.audit(AuditEvent{Time: time.Now(), Op: op, KeyID: id, Version: ver, Err: err})
	}
}

// GenerateKey creates version 1 of a new key with the algorithm's default export policy.
func (h *HSM) GenerateKey(id string, t KeyType) error { return h.GenerateKeyWith(id, t, KeyOptions{}) }

// GenerateKeyWith generates a key inside the HSM. Import-only algorithms return ErrImportOnly.
func (h *HSM) GenerateKeyWith(id string, t KeyType, o KeyOptions) error {
	sp, ok := specs[t]
	if !ok {
		return fmt.Errorf("localhsm: unknown key type %q", t)
	}
	mat, err := newMaterial(t)
	if err != nil {
		return err
	}
	defer clear(mat)
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.doc.Mode == modeEnterprise {
		return ErrEnterpriseMode
	}
	ivs, err := resolveIV(t, o.IV, false)
	if err != nil {
		return err
	}
	err = h.addKey(id, t, mat, o.resolve(sp), ivs)
	h.emit("generate", id, 1, err)
	return err
}

// ImportKey stores externally generated key material after validating its format and length.
func (h *HSM) ImportKey(id string, t KeyType, material []byte, o KeyOptions) error {
	sp, ok := specs[t]
	if !ok {
		return fmt.Errorf("localhsm: unknown key type %q", t)
	}
	if err := sp.validate(material); err != nil {
		return err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.doc.Mode == modeEnterprise {
		return ErrEnterpriseMode
	}
	ivs, err := resolveIV(t, o.IV, false)
	if err != nil {
		return err
	}
	err = h.addKey(id, t, material, o.resolve(sp), ivs)
	h.emit("import", id, 1, err)
	return err
}

func (h *HSM) addKey(id string, t KeyType, mat []byte, exportable bool, ivs ivSetup) error {
	if h.mk == nil {
		return ErrClosed
	}
	if id == "" {
		return errors.New("localhsm: empty key id")
	}
	if h.doc.Keys[id] != nil {
		return fmt.Errorf("localhsm: key exists: %s", id)
	}
	kv, err := h.wrapMaterial(id, t, 1, mat)
	if err != nil {
		return err
	}
	kv.StaticIV = ivs.static
	h.doc.Keys[id] = &keyEntry{Type: t, Current: 1, Exportable: exportable, IVPolicy: ivs.policy, IVSize: ivs.size,
		Versions: map[string]*keyVersion{"1": kv}}
	if err := h.save(); err != nil {
		delete(h.doc.Keys, id)
		return err
	}
	return nil
}

// ImportKeyVersion adds externally generated material as the new current version (rotation for
// import-only algorithms such as ML-DSA). The previous version becomes decrypt-only.
func (h *HSM) ImportKeyVersion(id string, material []byte) (uint32, error) {
	return h.importKeyVersion(id, material, nil)
}

// ImportKeyVersionWithIV is ImportKeyVersion for keys with a static IV policy: the new version
// carries its own fixed IV.
func (h *HSM) ImportKeyVersionWithIV(id string, material, iv []byte) (uint32, error) {
	return h.importKeyVersion(id, material, iv)
}

func (h *HSM) importKeyVersion(id string, material, staticIV []byte) (uint32, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.mk == nil {
		return 0, ErrClosed
	}
	if h.doc.Mode == modeEnterprise {
		return 0, ErrEnterpriseMode
	}
	e := h.doc.Keys[id]
	if e == nil {
		return 0, fmt.Errorf("localhsm: no such key: %s", id)
	}
	if err := specs[e.Type].validate(material); err != nil {
		return 0, err
	}
	if e.IVPolicy == string(IVStatic) {
		if len(staticIV) != e.IVSize {
			return 0, ErrStaticIVNeeded
		}
	} else if staticIV != nil {
		return 0, errors.New("localhsm: this key does not use a static IV")
	}
	prev, next := e.Current, e.Current+1
	prevKey, nextKey := strconv.FormatUint(uint64(prev), 10), strconv.FormatUint(uint64(next), 10)
	kv, err := h.wrapMaterial(id, e.Type, next, material)
	if err != nil {
		return 0, err
	}
	kv.StaticIV = append([]byte(nil), staticIV...)
	oldState := e.Versions[prevKey].State
	e.Versions[prevKey].State = stateDecryptOnly
	e.Versions[nextKey] = kv
	e.Current = next
	if err := h.save(); err != nil {
		e.Versions[prevKey].State = oldState
		delete(e.Versions, nextKey)
		e.Current = prev
		h.emit("import-version", id, next, err)
		return 0, err
	}
	h.emit("import-version", id, next, nil)
	return next, nil
}

// ExportKey returns the key value to the application (version 0 = current). Disabled versions and
// non-exportable keys are refused. The caller must Zeroize the result.
func (h *HSM) ExportKey(id string, ver uint32) (*ExportedKey, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	m, v, t, err := h.material(id, ver, false)
	if err != nil {
		h.emit("export", id, ver, err)
		return nil, err
	}
	e := h.doc.Keys[id]
	if !e.Exportable {
		clear(m)
		h.emit("export", id, v, ErrNotExportable)
		return nil, ErrNotExportable
	}
	h.emit("export", id, v, nil)
	rec := e.Versions[strconv.FormatUint(uint64(v), 10)]
	var iv []byte
	if e.IVPolicy == string(IVStatic) {
		iv = append([]byte(nil), rec.StaticIV...)
	}
	return &ExportedKey{ID: id, Type: t, Version: v, State: effectiveState(rec, time.Now()), Material: m, IV: iv}, nil
}

// PublicKeyBytes derives the public key (version 0 = current): PKIX DER for RSA/ECDSA, the raw
// 32-byte key for Ed25519, the encapsulation key for ML-KEM. Works for non-exportable keys too.
func (h *HSM) PublicKeyBytes(id string, ver uint32) ([]byte, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	m, _, t, err := h.material(id, ver, false)
	if err != nil {
		return nil, err
	}
	defer clear(m)
	sp := specs[t]
	if sp == nil || sp.public == nil {
		return nil, fmt.Errorf("%w: %s", ErrNoPublicKey, t)
	}
	return sp.public(m)
}
