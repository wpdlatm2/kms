package localhsm

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"sync"
	"time"
)

type KeyType string

const (
	AES256GCM  KeyType = "aes256-gcm"
	HMACSHA256 KeyType = "hmac-sha256"
	Ed25519    KeyType = "ed25519"
)

const (
	formatVersion = 1
	magic         = "LHSM"
	hdrLen        = 4 + 1 + 4 // magic, format, key version
	nonceLen      = 12
	tagLen        = 16

	stateActive      = "active"
	stateDecryptOnly = "decrypt-only"
	stateDisabled    = "disabled"
)

var ErrClosed = errors.New("localhsm: closed")

type keyVersion struct {
	Wrapped []byte       `json:"wrapped"`
	Created int64        `json:"created"`
	State   string       `json:"state"`
	Meta    *versionMeta `json:"meta,omitempty"` // KMS provenance (enterprise mode)
	// StaticIV is the fixed IV of this version (IV policy "static" only). Not secret; covered by the file MAC.
	StaticIV []byte `json:"static_iv,omitempty"`
}

type keyEntry struct {
	Type       KeyType                `json:"type"`
	Current    uint32                 `json:"current"`
	Versions   map[string]*keyVersion `json:"versions"`
	Exportable bool                   `json:"exportable,omitempty"`
	KMSRef     string                 `json:"kms_ref,omitempty"`
	IVPolicy   string                 `json:"iv_policy,omitempty"` // "", "counter", "static" (see iv.go)
	IVSize     int                    `json:"iv_size,omitempty"`
}

// recipient is one node (or offline recovery key) able to unseal the shared master key.
type recipient struct {
	ID        string `json:"id"` // fingerprint of the public key, or "dpapi:<name>"
	Kind      string `json:"kind"`
	Label     string `json:"label"`
	PublicKey []byte `json:"public_key,omitempty"` // DER PKIX; lets any node re-wrap the master key for it
	WrappedMK []byte `json:"wrapped_mk"`
	Added     int64  `json:"added"`
}

type document struct {
	Version        int                  `json:"version"`
	Serial         uint64               `json:"serial"`         // bumped on every write; detects conflicts and rollback
	Mode           string               `json:"mode,omitempty"` // "" = stand-alone, "enterprise" = keys issued by a KMS
	MaxSyncSeconds int64                `json:"max_sync_seconds,omitempty"`
	LastSync       int64                `json:"last_sync,omitempty"`
	Recipients     []*recipient         `json:"recipients"`
	Keys           map[string]*keyEntry `json:"keys"`
	MAC            []byte               `json:"mac,omitempty"`
}

// KeyInfo is the public view of a key (never contains key material).
type KeyInfo struct {
	Type       KeyType
	Current    uint32
	Versions   map[uint32]string
	Exportable bool
	IVPolicy   IVPolicy // "" for random
}

// HSM is safe for concurrent use within a process. Across nodes, use ONE writer
// (see README) and call Reload on the others.
type HSM struct {
	mu    sync.Mutex
	path  string
	prot  Protector
	id    string // this node's recipient ID
	mk    []byte
	doc   document
	audit func(AuditEvent)

	ivPath  string   // node-local IV counter state file (see iv.go)
	ivs     *ivState // loaded lazily
	ivBlock uint64   // counter reservation block size (0 = default)
}

var (
	// ErrConflict: the keystore file changed on disk since it was loaded; Reload and retry.
	ErrConflict = errors.New("localhsm: keystore changed on disk (Reload and retry)")
	// ErrNotRecipient: this node's protector is not listed in the keystore.
	ErrNotRecipient = errors.New("localhsm: this node is not an authorized recipient of the keystore")
)

// CreateWith makes a new keystore at path, with a fresh master key sealed by p as the first recipient.
func CreateWith(path string, p Protector, opts CreateOptions) (*HSM, error) {
	if err := opts.validate(); err != nil {
		return nil, err
	}
	if _, err := os.Stat(path); err == nil {
		return nil, fmt.Errorf("localhsm: keystore already exists: %s", path)
	}
	id, pub, err := p.Recipient()
	if err != nil {
		return nil, err
	}
	mk := make([]byte, 32)
	if _, err := rand.Read(mk); err != nil {
		return nil, err
	}
	wrapped, err := p.Wrap(mk)
	if err != nil {
		clear(mk)
		return nil, err
	}
	rec := &recipient{ID: id, Kind: p.Name(), Label: id, WrappedMK: wrapped, Added: time.Now().Unix()}
	if pub != nil {
		if rec.PublicKey, err = x509.MarshalPKIXPublicKey(pub); err != nil {
			clear(mk)
			return nil, err
		}
	}
	h := &HSM{path: path, prot: p, id: id, mk: mk, doc: document{
		Version: formatVersion, Mode: opts.mode(), MaxSyncSeconds: int64(opts.MaxSyncAge / time.Second),
		Recipients: []*recipient{rec}, Keys: map[string]*keyEntry{}}}
	if err := h.save(); err != nil {
		h.Close()
		return nil, err
	}
	return h, nil
}

// Open loads a keystore, unseals the master key through p and verifies file integrity.
func Open(path string, p Protector) (*HSM, error) {
	id, _, err := p.Recipient()
	if err != nil {
		return nil, err
	}
	h := &HSM{path: path, prot: p, id: id}
	if err := h.load(); err != nil {
		return nil, err
	}
	return h, nil
}

// Reload re-reads the keystore file (picks up new keys, rotations, a rotated master key, revocation).
// On error the previous in-memory state is kept.
func (h *HSM) Reload() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.mk == nil {
		return ErrClosed
	}
	return h.load()
}

func (h *HSM) load() error {
	raw, err := os.ReadFile(h.path)
	if err != nil {
		return err
	}
	var d document
	if err := json.Unmarshal(raw, &d); err != nil {
		return fmt.Errorf("localhsm: corrupt keystore: %w", err)
	}
	if d.Version != formatVersion {
		return errors.New("localhsm: unsupported keystore version")
	}
	var rec *recipient
	for _, r := range d.Recipients {
		if r.ID == h.id {
			rec = r
		}
	}
	if rec == nil {
		return ErrNotRecipient
	}
	mk, err := h.prot.Unwrap(rec.WrappedMK)
	if err != nil {
		return err
	}
	want, err := macWith(mk, &d)
	if err != nil || subtle.ConstantTimeCompare(want, d.MAC) != 1 {
		clear(mk)
		return errors.New("localhsm: keystore integrity check failed (tampered or wrong master key)")
	}
	if d.Serial < h.doc.Serial {
		clear(mk)
		return errors.New("localhsm: keystore rollback detected (older serial than loaded)")
	}
	if d.Keys == nil {
		d.Keys = map[string]*keyEntry{}
	}
	clear(h.mk)
	h.mk, h.doc = mk, d
	return nil
}

// Close zeroizes the master key held in memory.
func (h *HSM) Close() {
	h.mu.Lock()
	defer h.mu.Unlock()
	clear(h.mk)
	h.mk = nil
}

// Destroy irreversibly deletes THIS node's protecting key and the keystore file (crypto-erase).
// In a cluster, other nodes' copies of the file stay usable by them; to wipe the cluster, destroy every node.
func (h *HSM) Destroy() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	err := h.prot.Destroy()
	clear(h.mk)
	h.mk = nil
	if e := os.Remove(h.path); e != nil && !os.IsNotExist(e) && err == nil {
		err = e
	}
	return err
}

func (h *HSM) HardwareBacked() bool { return h.prot.HardwareBacked() }

// ------------------------------------------------------------- internals

func macWith(mk []byte, d *document) ([]byte, error) {
	if mk == nil {
		return nil, ErrClosed
	}
	k, err := hkdf.Key(sha256.New, mk, nil, "localhsm-keystore-mac", 32)
	if err != nil {
		return nil, err
	}
	cp := *d
	cp.MAC = nil
	body, err := json.Marshal(&cp) // struct order + sorted map keys => deterministic
	if err != nil {
		return nil, err
	}
	m := hmac.New(sha256.New, k)
	m.Write(body)
	return m.Sum(nil), nil
}

func diskSerial(path string) (serial uint64, exists bool, err error) {
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	var s struct {
		Serial uint64 `json:"serial"`
	}
	if err := json.Unmarshal(raw, &s); err != nil {
		return 0, true, err
	}
	return s.Serial, true, nil
}

// save is an optimistic-concurrency write: it fails with ErrConflict if another writer got in first.
func (h *HSM) save() error {
	if s, ok, err := diskSerial(h.path); err != nil {
		return err
	} else if ok && s != h.doc.Serial {
		return ErrConflict
	}
	h.doc.Serial++
	m, err := macWith(h.mk, &h.doc)
	if err != nil {
		h.doc.Serial--
		return err
	}
	h.doc.MAC = m
	b, err := json.MarshalIndent(&h.doc, "", " ")
	if err != nil {
		h.doc.Serial--
		return err
	}
	tmp := h.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		h.doc.Serial--
		return err
	}
	if err := os.Rename(tmp, h.path); err != nil {
		h.doc.Serial--
		return err
	}
	return nil
}

func keyAAD(id string, ver uint32, t KeyType) []byte {
	return []byte(id + "|" + strconv.FormatUint(uint64(ver), 10) + "|" + string(t))
}

func newGCM(key []byte) (cipher.AEAD, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

func (h *HSM) wrapMaterial(id string, t KeyType, ver uint32, mat []byte) (*keyVersion, error) {
	g, err := newGCM(h.mk)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return &keyVersion{Wrapped: g.Seal(nonce, nonce, mat, keyAAD(id, ver, t)),
		Created: time.Now().Unix(), State: stateActive}, nil
}

// material returns a copy of the key bytes; the caller must clear() it.
func (h *HSM) material(id string, ver uint32, forNewOps bool) ([]byte, uint32, KeyType, error) {
	if h.mk == nil {
		return nil, 0, "", ErrClosed
	}
	e := h.doc.Keys[id]
	if e == nil {
		return nil, 0, "", fmt.Errorf("localhsm: no such key: %s", id)
	}
	if ver == 0 {
		ver = e.Current
	}
	rec := e.Versions[strconv.FormatUint(uint64(ver), 10)]
	if rec == nil {
		return nil, 0, "", fmt.Errorf("localhsm: no such key version: %s v%d", id, ver)
	}
	if rec.State == stateDisabled || (forNewOps && (ver != e.Current || rec.State != stateActive)) {
		return nil, 0, "", fmt.Errorf("localhsm: key version not usable: %s v%d (%s)", id, ver, rec.State)
	}
	if err := h.enterprisePolicy(id, ver, rec, forNewOps); err != nil {
		return nil, 0, "", err
	}
	g, err := newGCM(h.mk)
	if err != nil {
		return nil, 0, "", err
	}
	if len(rec.Wrapped) < nonceLen+tagLen {
		return nil, 0, "", errors.New("localhsm: corrupted key entry")
	}
	m, err := g.Open(nil, rec.Wrapped[:nonceLen], rec.Wrapped[nonceLen:], keyAAD(id, ver, e.Type))
	if err != nil {
		return nil, 0, "", errors.New("localhsm: key unwrap failed (corrupted entry)")
	}
	return m, ver, e.Type, nil
}

// ------------------------------------------------------------ key mgmt

// RotateKey makes a new version current; older versions stay decrypt/verify-only.
func (h *HSM) rotateKeyLocal(id string, staticIV []byte) (uint32, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.mk == nil {
		return 0, ErrClosed
	}
	e := h.doc.Keys[id]
	if e == nil {
		return 0, fmt.Errorf("localhsm: no such key: %s", id)
	}
	if e.IVPolicy == string(IVStatic) {
		if len(staticIV) != e.IVSize {
			return 0, ErrStaticIVNeeded
		}
	} else if staticIV != nil {
		return 0, errors.New("localhsm: this key does not use a static IV")
	}
	mat, err := newMaterial(e.Type)
	if err != nil {
		return 0, err
	}
	defer clear(mat)
	next := e.Current + 1
	kv, err := h.wrapMaterial(id, e.Type, next, mat)
	if err != nil {
		return 0, err
	}
	kv.StaticIV = append([]byte(nil), staticIV...)
	e.Versions[strconv.FormatUint(uint64(e.Current), 10)].State = stateDecryptOnly
	e.Versions[strconv.FormatUint(uint64(next), 10)] = kv
	e.Current = next
	err = h.save()
	h.emit("rotate", id, next, err)
	return next, err
}

// DisableKeyVersion blocks all use of an old version (e.g. after re-encrypting its data).
func (h *HSM) DisableKeyVersion(id string, ver uint32) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.mk == nil {
		return ErrClosed
	}
	e := h.doc.Keys[id]
	if e == nil {
		return fmt.Errorf("localhsm: no such key: %s", id)
	}
	if ver == e.Current {
		return errors.New("localhsm: cannot disable the current version; rotate first")
	}
	rec := e.Versions[strconv.FormatUint(uint64(ver), 10)]
	if rec == nil {
		return fmt.Errorf("localhsm: no such key version: %s v%d", id, ver)
	}
	rec.State = stateDisabled
	err := h.save()
	h.emit("disable-version", id, ver, err)
	return err
}

func (h *HSM) DeleteKey(id string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.mk == nil {
		return ErrClosed
	}
	if h.doc.Keys[id] == nil {
		return fmt.Errorf("localhsm: no such key: %s", id)
	}
	delete(h.doc.Keys, id)
	err := h.save()
	h.emit("delete-key", id, 0, err)
	return err
}

func (h *HSM) ListKeys() map[string]KeyInfo {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make(map[string]KeyInfo, len(h.doc.Keys))
	for id, e := range h.doc.Keys {
		vs := map[uint32]string{}
		for n, r := range e.Versions {
			v, _ := strconv.ParseUint(n, 10, 32)
			vs[uint32(v)] = r.State
		}
		out[id] = KeyInfo{e.Type, e.Current, vs, e.Exportable, IVPolicy(e.IVPolicy)}
	}
	return out
}

// ------------------------------------------------------------ AES-256-GCM

func encAAD(hdr []byte, id string, aad []byte) []byte {
	return append(append(append([]byte{}, hdr...), id+"|"...), aad...)
}

// Encrypt returns magic|fmt|keyver|nonce|ciphertext+tag. aad is authenticated, not encrypted.
func (h *HSM) Encrypt(id string, plaintext, aad []byte) ([]byte, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	m, ver, t, err := h.material(id, 0, true)
	if err != nil {
		return nil, err
	}
	defer clear(m)
	if t != AES256GCM {
		return nil, errors.New("localhsm: not an AES key")
	}
	g, err := newGCM(m)
	if err != nil {
		return nil, err
	}
	hdr := make([]byte, hdrLen)
	copy(hdr, magic)
	hdr[4] = formatVersion
	binary.BigEndian.PutUint32(hdr[5:], ver)
	out := make([]byte, hdrLen+nonceLen, hdrLen+nonceLen+len(plaintext)+tagLen)
	copy(out, hdr)
	// 96-bit nonce: random, or counter-based if the key's IV policy says so (see iv.go). With random
	// nonces rotate keys well before 2^32 messages per key version.
	nonce, err := h.encNonceLocked(id, ver)
	if err != nil {
		return nil, err
	}
	copy(out[hdrLen:], nonce)
	return g.Seal(out, out[hdrLen:hdrLen+nonceLen], plaintext, encAAD(hdr, id, aad)), nil
}

func (h *HSM) Decrypt(id string, blob, aad []byte) ([]byte, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(blob) < hdrLen+nonceLen+tagLen || string(blob[:4]) != magic || blob[4] != formatVersion {
		return nil, errors.New("localhsm: bad ciphertext")
	}
	ver := binary.BigEndian.Uint32(blob[5:9])
	m, _, t, err := h.material(id, ver, false)
	if err != nil {
		return nil, err
	}
	defer clear(m)
	if t != AES256GCM {
		return nil, errors.New("localhsm: not an AES key")
	}
	g, err := newGCM(m)
	if err != nil {
		return nil, err
	}
	pt, err := g.Open(nil, blob[hdrLen:hdrLen+nonceLen], blob[hdrLen+nonceLen:], encAAD(blob[:hdrLen], id, aad))
	if err != nil {
		return nil, errors.New("localhsm: decryption failed (wrong key/aad or tampered data)")
	}
	return pt, nil
}

// ---------------------------------------------------- MAC / signatures

// Sign produces HMAC-SHA256 or Ed25519 depending on key type; output = keyver(4B) || sig.
func (h *HSM) Sign(id string, data []byte) ([]byte, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	m, ver, t, err := h.material(id, 0, true)
	if err != nil {
		return nil, err
	}
	defer clear(m)
	var sig []byte
	switch t {
	case HMACSHA256:
		x := hmac.New(sha256.New, m)
		x.Write(data)
		sig = x.Sum(nil)
	case Ed25519:
		pk := ed25519.NewKeyFromSeed(m)
		defer clear(pk)
		sig = ed25519.Sign(pk, data)
	default:
		return nil, errors.New("localhsm: key type cannot sign")
	}
	out := make([]byte, 4, 4+len(sig))
	binary.BigEndian.PutUint32(out, ver)
	return append(out, sig...), nil
}

func (h *HSM) Verify(id string, data, signature []byte) (bool, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(signature) < 5 {
		return false, nil
	}
	m, _, t, err := h.material(id, binary.BigEndian.Uint32(signature[:4]), false)
	if err != nil {
		return false, err
	}
	defer clear(m)
	sig := signature[4:]
	switch t {
	case HMACSHA256:
		x := hmac.New(sha256.New, m)
		x.Write(data)
		return hmac.Equal(sig, x.Sum(nil)), nil
	case Ed25519:
		pk := ed25519.NewKeyFromSeed(m)
		defer clear(pk)
		return ed25519.Verify(pk.Public().(ed25519.PublicKey), data, sig), nil
	}
	return false, errors.New("localhsm: key type cannot verify")
}

// PublicKey returns the Ed25519 public key (version 0 = current). Private bytes never leave the HSM.
func (h *HSM) PublicKey(id string, ver uint32) (ed25519.PublicKey, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	m, _, t, err := h.material(id, ver, false)
	if err != nil {
		return nil, err
	}
	defer clear(m)
	if t != Ed25519 {
		return nil, errors.New("localhsm: not an asymmetric key")
	}
	pk := ed25519.NewKeyFromSeed(m)
	defer clear(pk)
	return append(ed25519.PublicKey{}, pk.Public().(ed25519.PublicKey)...), nil
}

// VerifyWithPublicKey checks a Sign() output from an Ed25519 key without needing the HSM.
func VerifyWithPublicKey(pub ed25519.PublicKey, data, signature []byte) bool {
	return len(signature) > 4 && len(pub) == ed25519.PublicKeySize && ed25519.Verify(pub, data, signature[4:])
}
