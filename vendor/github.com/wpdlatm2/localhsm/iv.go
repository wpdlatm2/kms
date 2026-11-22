package localhsm

// IV (nonce) management, the same in stand-alone and enterprise mode.
//
// An IV is not secret, but for most modes it must be UNIQUE per key (AES-GCM, CTR, ChaCha20-Poly1305:
// a repeated IV destroys confidentiality and, for GCM, authenticity). Each symmetric key has an IV
// policy, stored with the key (and covered by the keystore MAC):
//
//	random   (default)  a fresh random IV per message; nothing to store. For 96-bit IVs stay below
//	                    about 2^32 messages per key version, then rotate the key.
//	counter             node-tag(4 bytes) || counter, issued by NextIV. The counter is reserved in blocks
//	                    and persisted in a NODE-LOCAL state file BEFORE any IV of the block is handed out,
//	                    so a crash or restart never reissues an IV. Different nodes use different tags.
//	static              one fixed IV stored with the key version (what some KMS / legacy systems issue as a
//	                    key+IV pair). Cryptographically weak: refused for AES-GCM (HSM-side encryption),
//	                    needs an explicit opt-in, and every NextIV is audited. Prefer random or counter.
//
// The HSM's own Encrypt (aes256-gcm) follows the key's policy (random or counter). For keys you use
// yourself (custody / kernel AEAD) call NextIV and put the IV next to the ciphertext.
//
// Counter caveat: the state file must not be rolled back (restored from an old backup) or reused by
// two nodes, otherwise IVs can repeat. A TPM NV counter would remove that risk; it has not been
// verified on the target TPMs (the server TPM reports 0 NV counters), so it is not used.

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
)

// IVPolicy selects how IVs are produced for a symmetric key.
type IVPolicy string

const (
	IVRandom  IVPolicy = "random"
	IVCounter IVPolicy = "counter"
	IVStatic  IVPolicy = "static"
)

// IVOptions are given at key creation (KeyOptions.IV).
type IVOptions struct {
	Policy IVPolicy // "" = random
	Size   int      // IV length in bytes (8..16); 0 = default: 12 for aes256-gcm, else 16
	// Static is the fixed IV for version 1 (IVStatic only).
	Static []byte
	// AllowInsecureStatic must be set to use IVStatic: a fixed IV is a known weakness.
	AllowInsecureStatic bool
}

var (
	// ErrStaticIVNeeded: a static-IV key needs the new IV when it is rotated (RotateKeyWithIV).
	ErrStaticIVNeeded = errors.New("localhsm: this key uses a static IV: provide the new IV (RotateKeyWithIV / ImportKeyVersionWithIV)")
	// ErrInsecureStaticIV: a static IV was requested without the explicit opt-in, or for a key type that forbids it.
	ErrInsecureStaticIV = errors.New("localhsm: static IV refused (needs AllowInsecureStatic and a non-AEAD key type)")
)

type ivSetup struct {
	policy string // "" = random
	size   int    // 0 = type default
	static []byte
}

func isSymmetricType(t KeyType) bool {
	switch t {
	case AES256GCM, AES128, AES192, AES256, AESXTS128, AESXTS256, SEED128, ARIA128, ARIA192, ARIA256:
		return true
	}
	return false
}

func defaultIVSize(t KeyType) int {
	if t == AES256GCM {
		return nonceLen
	}
	return 16
}

func validIVSize(t KeyType, size int) error {
	if size < 8 || size > 16 {
		return fmt.Errorf("localhsm: IV size must be 8..16 bytes, got %d", size)
	}
	if t == AES256GCM && size != nonceLen {
		return fmt.Errorf("localhsm: aes256-gcm uses 12-byte IVs, got %d", size)
	}
	return nil
}

// resolveIV validates IV options for a key type. kmsStatic=true is used for KMS-issued keys, where the
// KMS (not the local caller) decides on a static IV and the value arrives per version.
func resolveIV(t KeyType, o *IVOptions, kmsStatic bool) (ivSetup, error) {
	if o == nil {
		return ivSetup{}, nil
	}
	if !isSymmetricType(t) {
		return ivSetup{}, fmt.Errorf("localhsm: IV options apply to symmetric keys only, not %s", t)
	}
	switch o.Policy {
	case "", IVRandom:
		if len(o.Static) > 0 {
			return ivSetup{}, errors.New("localhsm: a static IV was given for a non-static policy")
		}
		if o.Size != 0 {
			if err := validIVSize(t, o.Size); err != nil {
				return ivSetup{}, err
			}
		}
		return ivSetup{size: o.Size}, nil
	case IVCounter:
		size := o.Size
		if size == 0 {
			size = defaultIVSize(t)
		}
		if err := validIVSize(t, size); err != nil {
			return ivSetup{}, err
		}
		if size < 12 {
			return ivSetup{}, errors.New("localhsm: counter IVs need at least 12 bytes (4-byte node tag + 8-byte counter)")
		}
		return ivSetup{policy: string(IVCounter), size: size}, nil
	case IVStatic:
		if t == AES256GCM {
			return ivSetup{}, ErrInsecureStaticIV
		}
		if !kmsStatic && !o.AllowInsecureStatic {
			return ivSetup{}, ErrInsecureStaticIV
		}
		size := o.Size
		if kmsStatic {
			if err := validIVSize(t, size); err != nil {
				return ivSetup{}, err
			}
			return ivSetup{policy: string(IVStatic), size: size}, nil
		}
		if size == 0 {
			size = len(o.Static)
		}
		if len(o.Static) != size {
			return ivSetup{}, fmt.Errorf("localhsm: static IV is %d bytes, expected %d", len(o.Static), size)
		}
		if err := validIVSize(t, size); err != nil {
			return ivSetup{}, err
		}
		return ivSetup{policy: string(IVStatic), size: size, static: append([]byte(nil), o.Static...)}, nil
	}
	return ivSetup{}, fmt.Errorf("localhsm: unknown IV policy %q", o.Policy)
}

// ------------------------------------------------------------- counter state

type ivStateFile struct {
	Version  int               `json:"version"`
	Node     string            `json:"node"`
	Reserved map[string]uint64 `json:"reserved"` // "keyID|version" -> highest reserved counter value + 1
}

type ivState struct {
	path     string
	node     string
	tag      [4]byte
	reserved map[string]uint64
	next     map[string]uint64
	limit    map[string]uint64
}

const defaultIVBlock = 1 << 20

// SetIVStatePath sets the node-local file holding counter reservations. The default is
// "<keystore>.iv-<node>.json" next to the keystore: when the keystore directory is shared between
// nodes, point this at node-local storage.
func (h *HSM) SetIVStatePath(path string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.ivPath, h.ivs = path, nil
}

func (h *HSM) ivStateLocked() (*ivState, error) {
	if h.ivs != nil {
		return h.ivs, nil
	}
	sum := sha256.Sum256([]byte("localhsm-iv-node|" + h.id))
	st := &ivState{node: hex.EncodeToString(sum[:4]), reserved: map[string]uint64{},
		next: map[string]uint64{}, limit: map[string]uint64{}}
	copy(st.tag[:], sum[:4])
	st.path = h.ivPath
	if st.path == "" {
		st.path = h.path + ".iv-" + st.node + ".json"
	}
	raw, err := os.ReadFile(st.path)
	switch {
	case err == nil:
		var f ivStateFile
		if err := json.Unmarshal(raw, &f); err != nil {
			return nil, fmt.Errorf("localhsm: corrupt IV state %s: %w", st.path, err)
		}
		if f.Node != st.node {
			return nil, fmt.Errorf("localhsm: IV state %s belongs to another node", st.path)
		}
		if f.Reserved != nil {
			st.reserved = f.Reserved
		}
	case os.IsNotExist(err):
	default:
		return nil, err
	}
	h.ivs = st
	return st, nil
}

func (st *ivState) save() error {
	b, err := json.Marshal(&ivStateFile{Version: 1, Node: st.node, Reserved: st.reserved})
	if err != nil {
		return err
	}
	tmp := st.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, st.path)
}

// counterIVLocked returns the next IV of a counter-policy key version.
func (h *HSM) counterIVLocked(id string, ver uint32, size int) ([]byte, error) {
	st, err := h.ivStateLocked()
	if err != nil {
		return nil, err
	}
	key := id + "|" + strconv.FormatUint(uint64(ver), 10)
	n, ok := st.next[key]
	if !ok || n >= st.limit[key] {
		base := st.reserved[key] // after a restart: skip everything that may have been issued before
		if ok {
			base = st.limit[key]
		}
		block := h.ivBlock
		if block == 0 {
			block = defaultIVBlock
		}
		if base+block < base {
			return nil, errors.New("localhsm: IV counter exhausted: rotate the key")
		}
		st.reserved[key] = base + block
		if err := st.save(); err != nil { // persist BEFORE issuing from the new block
			st.reserved[key] = base
			return nil, fmt.Errorf("localhsm: cannot persist IV counter reservation: %w", err)
		}
		st.next[key], st.limit[key], n = base, base+block, base
		h.emit("iv-reserve", id, ver, nil)
	}
	st.next[key] = n + 1
	iv := make([]byte, size)
	copy(iv, st.tag[:])
	binary.BigEndian.PutUint64(iv[size-8:], n)
	return iv, nil
}

// encNonceLocked is the nonce for the HSM's own AES-GCM Encrypt: counter-based if the key's policy
// says so, else random.
func (h *HSM) encNonceLocked(id string, ver uint32) ([]byte, error) {
	if e := h.doc.Keys[id]; e != nil && e.IVPolicy == string(IVCounter) {
		return h.counterIVLocked(id, ver, nonceLen)
	}
	n := make([]byte, nonceLen)
	_, err := rand.Read(n)
	return n, err
}

// NextIV returns the IV to use for the next encryption with the key's current version, following the
// key's policy (random, counter or static). It refuses keys whose current version may not encrypt
// (retired, expired, stale enterprise keystore).
func (h *HSM) NextIV(keyID string) ([]byte, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.mk == nil {
		return nil, ErrClosed
	}
	e := h.doc.Keys[keyID]
	if e == nil {
		return nil, fmt.Errorf("localhsm: no such key: %s", keyID)
	}
	if !isSymmetricType(e.Type) {
		return nil, fmt.Errorf("localhsm: %s is not a symmetric key", e.Type)
	}
	ver := e.Current
	rec := e.Versions[strconv.FormatUint(uint64(ver), 10)]
	if rec == nil || rec.State != stateActive {
		return nil, ErrNotCurrent
	}
	if err := h.enterprisePolicy(keyID, ver, rec, true); err != nil {
		return nil, err
	}
	size := e.IVSize
	if size == 0 {
		size = defaultIVSize(e.Type)
	}
	switch IVPolicy(e.IVPolicy) {
	case IVCounter:
		return h.counterIVLocked(keyID, ver, size)
	case IVStatic:
		h.emit("static-iv", keyID, ver, nil) // every use of a fixed IV is recorded
		return append([]byte(nil), rec.StaticIV...), nil
	}
	iv := make([]byte, size)
	_, err := rand.Read(iv)
	return iv, err
}

// IVPolicyOf reports a key's IV policy and IV size.
func (h *HSM) IVPolicyOf(keyID string) (IVPolicy, int, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	e := h.doc.Keys[keyID]
	if e == nil {
		return "", 0, fmt.Errorf("localhsm: no such key: %s", keyID)
	}
	size := e.IVSize
	if size == 0 {
		size = defaultIVSize(e.Type)
	}
	if e.IVPolicy == "" {
		return IVRandom, size, nil
	}
	return IVPolicy(e.IVPolicy), size, nil
}

// resolveKMSIV validates the IV policy of a KMS-issued key (the static IV values arrive per version).
func resolveKMSIV(k KMSKey) (ivSetup, error) {
	if k.IVPolicy == "" && k.IVSize == 0 {
		return ivSetup{}, nil
	}
	return resolveIV(k.Type, &IVOptions{Policy: k.IVPolicy, Size: k.IVSize}, true)
}
