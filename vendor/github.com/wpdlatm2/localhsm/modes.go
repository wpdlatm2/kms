package localhsm

// Operating modes.
//
//	Stand-alone: no external KMS. localhsm itself generates, rotates and (optionally) uses the keys:
//	             GenerateKey / RotateKey / Encrypt / Sign, plus custody export. (Default.)
//	Enterprise:  an external KMS is the authority. KMS-issued keys are imported into localhsm, which
//	             stores them protected by the TPM-sealed master key. Local key creation, rotation and
//	             free-form import are DISABLED; the keystore is refreshed from the KMS with
//	             SyncFromKMS, which carries versions, status (active / decrypt-only / disabled) and
//	             expiry. An optional maximum sync age forces key use to stop when the KMS has not been
//	             reachable for too long, which bounds revocation latency.
//
// localhsm does not speak a KMS wire protocol (KMIP, REST, cloud APIs ...). Implement the small KMS
// interface for your KMS, or load an exported bundle with ApplyKMSKeys.

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"time"
)

// Mode selects who owns the keys.
type Mode string

const (
	ModeStandalone Mode = "standalone"
	ModeEnterprise Mode = "enterprise"

	modeEnterprise = "enterprise" // value stored in the keystore ("" = stand-alone)
)

var (
	// ErrEnterpriseMode: the operation creates keys locally, which enterprise mode forbids.
	ErrEnterpriseMode = errors.New("localhsm: enterprise mode: keys must be issued by the KMS (use SyncFromKMS)")
	// ErrNotEnterprise: KMS operations need a keystore created in enterprise mode.
	ErrNotEnterprise = errors.New("localhsm: keystore is not in enterprise mode")
	// ErrStaleKeystore: the keystore has not been synchronized with the KMS within MaxSyncAge.
	ErrStaleKeystore = errors.New("localhsm: keystore not synchronized with the KMS within the allowed age")
	// ErrKeyExpired: the key version's validity period (set by the KMS) has ended; decrypt/verify only.
	ErrKeyExpired = errors.New("localhsm: key version expired")
)

// CreateOptions configure a new keystore.
type CreateOptions struct {
	Mode Mode // "" = stand-alone
	// MaxSyncAge (enterprise only): key use is refused when the last successful KMS sync is older.
	// 0 disables the check (keys stay usable while the KMS is unreachable).
	MaxSyncAge time.Duration
}

func (o CreateOptions) validate() error {
	switch o.Mode {
	case "", ModeStandalone:
		if o.MaxSyncAge != 0 {
			return errors.New("localhsm: MaxSyncAge only applies to enterprise mode")
		}
	case ModeEnterprise:
		if o.MaxSyncAge < 0 {
			return errors.New("localhsm: negative MaxSyncAge")
		}
	default:
		return fmt.Errorf("localhsm: unknown mode %q", o.Mode)
	}
	return nil
}

func (o CreateOptions) mode() string {
	if o.Mode == ModeEnterprise {
		return modeEnterprise
	}
	return ""
}

// Create makes a new stand-alone keystore (see CreateWith for enterprise mode).
func Create(path string, p Protector) (*HSM, error) { return CreateWith(path, p, CreateOptions{}) }

// Mode reports the keystore's operating mode.
func (h *HSM) Mode() Mode {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.doc.Mode == modeEnterprise {
		return ModeEnterprise
	}
	return ModeStandalone
}

// LastSync is the time of the last successful KMS synchronization (zero if never).
func (h *HSM) LastSync() time.Time {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.doc.LastSync == 0 {
		return time.Time{}
	}
	return time.Unix(h.doc.LastSync, 0)
}

// Serial is the keystore write counter this node has loaded. After a change on the writer node, compare
// the value across nodes to confirm that every node has reloaded (hsmctl info prints it).
func (h *HSM) Serial() uint64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.doc.Serial
}

// RotateKey makes a new version current. Not available in enterprise mode: the KMS rotates keys.
func (h *HSM) RotateKey(id string) (uint32, error) {
	h.mu.Lock()
	ent := h.doc.Mode == modeEnterprise
	h.mu.Unlock()
	if ent {
		return 0, ErrEnterpriseMode
	}
	return h.rotateKeyLocal(id, nil)
}

// RotateKeyWithIV rotates a key whose IV policy is "static": the new version carries its own fixed IV.
// Not available in enterprise mode (the KMS delivers key and IV together).
func (h *HSM) RotateKeyWithIV(id string, iv []byte) (uint32, error) {
	h.mu.Lock()
	ent := h.doc.Mode == modeEnterprise
	h.mu.Unlock()
	if ent {
		return 0, ErrEnterpriseMode
	}
	return h.rotateKeyLocal(id, iv)
}

// ---------------------------------------------------------------- policy

// versionMeta records where a key version came from.
type versionMeta struct {
	KMSVersion string `json:"kms_version"`
	IssuedAt   int64  `json:"issued_at,omitempty"`
	ExpiresAt  int64  `json:"expires_at,omitempty"`
	SyncedAt   int64  `json:"synced_at,omitempty"`
}

const stateExpired = "expired"

// effectiveState folds the validity period into the state shown to callers.
func effectiveState(rec *keyVersion, now time.Time) string {
	if rec.State == stateActive && rec.Meta != nil && rec.Meta.ExpiresAt > 0 && now.Unix() > rec.Meta.ExpiresAt {
		return stateExpired
	}
	return rec.State
}

// enterprisePolicy is called for every use of key material.
func (h *HSM) enterprisePolicy(id string, ver uint32, rec *keyVersion, forNewOps bool) error {
	if h.doc.Mode != modeEnterprise {
		return nil
	}
	if h.doc.MaxSyncSeconds > 0 {
		max := time.Duration(h.doc.MaxSyncSeconds) * time.Second
		if h.doc.LastSync == 0 || time.Since(time.Unix(h.doc.LastSync, 0)) > max {
			return fmt.Errorf("%w (max %s)", ErrStaleKeystore, max)
		}
	}
	if forNewOps && effectiveState(rec, time.Now()) == stateExpired {
		return fmt.Errorf("%w: %s v%d", ErrKeyExpired, id, ver)
	}
	return nil
}

// ------------------------------------------------------------------- KMS

// KeyStatus is the lifecycle status reported by the KMS for one key version.
type KeyStatus string

const (
	StatusActive      KeyStatus = "active"       // may be used for new operations (the newest active is current)
	StatusDecryptOnly KeyStatus = "decrypt-only" // retired: existing data only
	StatusDisabled    KeyStatus = "disabled"     // revoked / compromised: no use at all
)

func (s KeyStatus) state() (string, bool) {
	switch s {
	case StatusActive:
		return stateActive, true
	case StatusDecryptOnly:
		return stateDecryptOnly, true
	case StatusDisabled:
		return stateDisabled, true
	}
	return "", false
}

// KMSKeyVersion is one version of a KMS-issued key. Versions are listed oldest first.
type KMSKeyVersion struct {
	ID        string    `json:"id"`                 // the KMS's version identifier (stable)
	Material  []byte    `json:"material,omitempty"` // required for versions localhsm has not seen yet
	Status    KeyStatus `json:"status"`
	IssuedAt  time.Time `json:"issued_at,omitempty"`
	ExpiresAt time.Time `json:"expires_at,omitempty"` // zero = no expiry
	// IV is the fixed IV issued with this key version (key.IVPolicy "static" only).
	IV []byte `json:"iv,omitempty"`
}

// KMSKey is a KMS-issued key. Ref is the KMS key name and is also the local key ID.
type KMSKey struct {
	Ref        string          `json:"ref"`
	Type       KeyType         `json:"type"`
	Exportable bool            `json:"exportable"` // KMS policy: may the application receive the key value?
	Versions   []KMSKeyVersion `json:"versions"`
	// IVPolicy / IVSize: how IVs are produced for this key ("" = random; "counter"; "static" with a
	// per-version IV). Fixed for the life of the key.
	IVPolicy IVPolicy `json:"iv_policy,omitempty"`
	IVSize   int      `json:"iv_size,omitempty"`
}

// KMS is what an adapter for your key management system implements. Fetch must return the current
// state of the requested keys (version material only needs to be included for versions that are new
// to the caller, but may always be included).
type KMS interface {
	Fetch(ctx context.Context, refs []string) ([]KMSKey, error)
}

// SyncReport summarizes one synchronization.
type SyncReport struct {
	Created       []string
	Updated       []string
	NewVersions   int
	StatusChanges int
	// Skipped lists versions that were not stored because the KMS no longer releases their value
	// (retired, never seen before): "key/version: reason". Data encrypted with them cannot be read here.
	Skipped []string
	At      time.Time
}

// SyncFromKMS pulls the given keys (all stored keys if refs is empty) from the KMS and applies them.
// The KMS call happens outside the HSM lock; the result is applied atomically. Run it on the
// writer node of a cluster (see the multi-node notes).
func (h *HSM) SyncFromKMS(ctx context.Context, kms KMS, refs []string) (*SyncReport, error) {
	h.mu.Lock()
	closed, ent := h.mk == nil, h.doc.Mode == modeEnterprise
	if len(refs) == 0 {
		for r := range h.doc.Keys {
			refs = append(refs, r)
		}
		sort.Strings(refs)
	}
	h.mu.Unlock()
	if closed {
		return nil, ErrClosed
	}
	if !ent {
		return nil, ErrNotEnterprise
	}
	keys, err := kms.Fetch(ctx, refs)
	if err != nil {
		return nil, fmt.Errorf("localhsm: KMS fetch: %w", err)
	}
	return h.ApplyKMSKeys(keys)
}

func rank(state string) int {
	switch state {
	case stateDisabled:
		return 2
	case stateDecryptOnly:
		return 1
	}
	return 0
}

func cloneKeys(in map[string]*keyEntry) map[string]*keyEntry {
	out := make(map[string]*keyEntry, len(in))
	for id, e := range in {
		ne := *e
		ne.Versions = make(map[string]*keyVersion, len(e.Versions))
		for n, v := range e.Versions {
			nv := *v
			if v.Meta != nil {
				m := *v.Meta
				nv.Meta = &m
			}
			ne.Versions[n] = &nv
		}
		out[id] = &ne
	}
	return out
}

func unixOrZero(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

// ApplyKMSKeys applies KMS key state to the keystore (enterprise mode only). The whole batch is
// validated first and applied atomically; the Material slices are zeroized before returning.
//
// Rules: unknown versions are added (the newest active one becomes current); known versions only
// get their status/expiry updated, and re-delivered material must match what is stored; a status
// is never loosened locally (the more restrictive of local and KMS wins), so a local emergency
// disable survives a sync.
func (h *HSM) ApplyKMSKeys(keys []KMSKey) (*SyncReport, error) {
	defer func() {
		for _, k := range keys {
			for _, v := range k.Versions {
				clear(v.Material)
			}
		}
	}()
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.mk == nil {
		return nil, ErrClosed
	}
	if h.doc.Mode != modeEnterprise {
		return nil, ErrNotEnterprise
	}
	// ---- validate everything before touching state
	refs := map[string]bool{}
	for _, k := range keys {
		if k.Ref == "" {
			return nil, errors.New("localhsm: KMS key without Ref")
		}
		if refs[k.Ref] {
			return nil, fmt.Errorf("localhsm: duplicate KMS key %q", k.Ref)
		}
		refs[k.Ref] = true
		sp := specs[k.Type]
		if sp == nil {
			return nil, fmt.Errorf("localhsm: %s: unknown key type %q", k.Ref, k.Type)
		}
		ivs, err := resolveKMSIV(k)
		if err != nil {
			return nil, fmt.Errorf("localhsm: %s: %w", k.Ref, err)
		}
		ids := map[string]bool{}
		for _, v := range k.Versions {
			if ivs.policy == string(IVStatic) {
				if len(v.IV) != 0 && len(v.IV) != ivs.size {
					return nil, fmt.Errorf("localhsm: %s/%s: IV is %d bytes, expected %d", k.Ref, v.ID, len(v.IV), ivs.size)
				}
			} else if len(v.IV) != 0 {
				return nil, fmt.Errorf("localhsm: %s/%s: an IV was delivered but the key's IV policy is not static", k.Ref, v.ID)
			}
			if v.ID == "" || ids[v.ID] {
				return nil, fmt.Errorf("localhsm: %s: missing or duplicate version id %q", k.Ref, v.ID)
			}
			ids[v.ID] = true
			if _, ok := v.Status.state(); !ok {
				return nil, fmt.Errorf("localhsm: %s/%s: bad status %q", k.Ref, v.ID, v.Status)
			}
			if len(v.Material) > 0 {
				if err := sp.validate(v.Material); err != nil {
					return nil, fmt.Errorf("localhsm: %s/%s: %w", k.Ref, v.ID, err)
				}
			}
		}
	}
	// ---- apply on a copy
	now := time.Now()
	newKeys := cloneKeys(h.doc.Keys)
	gcm, err := newGCM(h.mk)
	if err != nil {
		return nil, err
	}
	rep := &SyncReport{At: now}
	touched := map[string]bool{}
	for _, k := range keys {
		e := newKeys[k.Ref]
		if e == nil {
			ivs, _ := resolveKMSIV(k)
			e = &keyEntry{Type: k.Type, KMSRef: k.Ref, IVPolicy: ivs.policy, IVSize: ivs.size, Versions: map[string]*keyVersion{}}
			newKeys[k.Ref] = e
			rep.Created = append(rep.Created, k.Ref)
		} else if e.Type != k.Type || e.KMSRef != k.Ref {
			return nil, fmt.Errorf("localhsm: %s: KMS key type/identity changed", k.Ref)
		} else if ivs, _ := resolveKMSIV(k); e.IVPolicy != ivs.policy || e.IVSize != ivs.size {
			return nil, fmt.Errorf("localhsm: %s: KMS changed the key's IV policy", k.Ref)
		}
		e.Exportable = k.Exportable
		for _, kv := range k.Versions {
			st, _ := kv.Status.state()
			var lv *keyVersion
			var lnum uint32
			maxv := uint32(0)
			for n, v := range e.Versions {
				num, _ := strconv.ParseUint(n, 10, 32)
				if uint32(num) > maxv {
					maxv = uint32(num)
				}
				if v.Meta != nil && v.Meta.KMSVersion == kv.ID {
					lv, lnum = v, uint32(num)
				}
			}
			if lv != nil {
				if len(kv.Material) > 0 {
					m, err := gcm.Open(nil, lv.Wrapped[:nonceLen], lv.Wrapped[nonceLen:], keyAAD(k.Ref, lnum, e.Type))
					if err != nil || subtle.ConstantTimeCompare(m, kv.Material) != 1 {
						clear(m)
						return nil, fmt.Errorf("localhsm: %s/%s: KMS delivered different material for an existing version", k.Ref, kv.ID)
					}
					clear(m)
				}
				if len(kv.IV) > 0 && string(kv.IV) != string(lv.StaticIV) {
					return nil, fmt.Errorf("localhsm: %s/%s: KMS delivered a different IV for an existing version", k.Ref, kv.ID)
				}
				if rank(st) > rank(lv.State) {
					lv.State = st
					rep.StatusChanges++
					touched[k.Ref] = true
				}
				if exp := unixOrZero(kv.ExpiresAt); lv.Meta.ExpiresAt != exp {
					lv.Meta.ExpiresAt = exp
					touched[k.Ref] = true
				}
				lv.Meta.SyncedAt = now.Unix()
				continue
			}
			if len(kv.Material) == 0 && kv.Status == StatusDisabled {
				continue // never seen and already revoked: nothing worth storing
			}
			if len(kv.Material) == 0 && kv.Status == StatusDecryptOnly {
				rep.Skipped = append(rep.Skipped, k.Ref+"/"+kv.ID+": retired and the KMS does not release its value")
				continue
			}
			if len(kv.Material) == 0 {
				return nil, fmt.Errorf("localhsm: %s/%s: new version delivered without material", k.Ref, kv.ID)
			}
			if e.IVPolicy == string(IVStatic) && len(kv.IV) != e.IVSize {
				return nil, fmt.Errorf("localhsm: %s/%s: new version of a static-IV key delivered without its IV", k.Ref, kv.ID)
			}
			next := maxv + 1
			nonce := make([]byte, nonceLen)
			if _, err := randRead(nonce); err != nil {
				return nil, err
			}
			e.Versions[strconv.FormatUint(uint64(next), 10)] = &keyVersion{
				Wrapped: gcm.Seal(nonce, nonce, kv.Material, keyAAD(k.Ref, next, e.Type)),
				Created: now.Unix(), State: st, StaticIV: append([]byte(nil), kv.IV...),
				Meta: &versionMeta{KMSVersion: kv.ID, IssuedAt: unixOrZero(kv.IssuedAt), ExpiresAt: unixOrZero(kv.ExpiresAt), SyncedAt: now.Unix()},
			}
			rep.NewVersions++
			touched[k.Ref] = true
		}
		// current = newest active version, else the newest version overall
		var bestActive, bestAny uint32
		for n, v := range e.Versions {
			num64, _ := strconv.ParseUint(n, 10, 32)
			num := uint32(num64)
			if num > bestAny {
				bestAny = num
			}
			if v.State == stateActive && num > bestActive {
				bestActive = num
			}
		}
		e.Current = bestActive
		if e.Current == 0 {
			e.Current = bestAny
		}
	}
	for r := range touched {
		if !contains(rep.Created, r) {
			rep.Updated = append(rep.Updated, r)
		}
	}
	sort.Strings(rep.Updated)
	// ---- commit atomically
	oldKeys, oldSync := h.doc.Keys, h.doc.LastSync
	h.doc.Keys, h.doc.LastSync = newKeys, now.Unix()
	if err := h.save(); err != nil {
		h.doc.Keys, h.doc.LastSync = oldKeys, oldSync
		return nil, err
	}
	for _, k := range keys {
		h.emit("kms-sync", k.Ref, newKeys[k.Ref].Current, nil)
	}
	return rep, nil
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func randRead(b []byte) (int, error) { return rand.Read(b) }
