package localhsm

// Multi-node sharing of ONE master key.
//
// TPM keys are non-exportable, so the master key is never copied between machines in the clear.
// Instead the keystore lists several "recipients": the same master key, wrapped separately to each
// node's own TPM public key (RSA-OAEP). Any listed node can open the same keystore file.
//
// Enrollment (no secret ever crosses the wire, only a public key):
//  1. new node:      req := NewJoinRequest(protector, "node-b")      -> send req (JSON) to an admin
//  2. admin verifies req.ID out-of-band, then on an already-enrolled node: hsm.AddRecipient(req)
//  3. distribute the updated keystore file; the new node calls Open().
//
// Revocation re-keys: RevokeRecipient removes the node AND rotates the master key.

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"time"
)

// JoinRequest is what a new node sends to an admin. It contains only public data.
//
// NOTE: it does not prove the key lives in a TPM (that needs TPM attestation); the admin must
// trust the channel/node it came from and compare ID out-of-band.
type JoinRequest struct {
	ID        string `json:"id"`
	Kind      string `json:"kind"`
	Label     string `json:"label"`
	PublicKey []byte `json:"public_key"` // DER PKIX RSA
}

// RecipientInfo is the public view of a recipient.
type RecipientInfo struct {
	ID, Kind, Label string
	Added           time.Time
	Self            bool
}

func fingerprint(pub *rsa.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	s := sha256.Sum256(der)
	return hex.EncodeToString(s[:16]), nil
}

// WrapForPublicKey seals secret to an RSA public key; the output is accepted by Protector.Unwrap
// of the TPM protector that owns the matching private key.
func WrapForPublicKey(pub *rsa.PublicKey, secret []byte) ([]byte, error) {
	if pub.N.BitLen() < 2048 {
		return nil, errors.New("localhsm: recipient RSA key must be >= 2048 bits")
	}
	ct, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, secret, nil)
	if err != nil {
		return nil, err
	}
	return append([]byte{1, 1}, ct...), nil // [format 1][hash 1 = SHA256]
}

// NewJoinRequest is run on the node that wants to join (creates its TPM key if needed).
func NewJoinRequest(p Protector, label string) (JoinRequest, error) {
	id, pub, err := p.Recipient()
	if err != nil {
		return JoinRequest{}, err
	}
	if pub == nil {
		return JoinRequest{}, errors.New("localhsm: this protector cannot be shared (no public key); use a TPM or recovery key")
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return JoinRequest{}, err
	}
	return JoinRequest{ID: id, Kind: p.Name(), Label: label, PublicKey: der}, nil
}

// AddRecipient authorizes another node/recovery key. Call on an enrolled node, then distribute the file.
func (h *HSM) AddRecipient(req JoinRequest) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.mk == nil {
		return ErrClosed
	}
	pk, err := x509.ParsePKIXPublicKey(req.PublicKey)
	if err != nil {
		return fmt.Errorf("localhsm: bad join request key: %w", err)
	}
	pub, ok := pk.(*rsa.PublicKey)
	if !ok {
		return errors.New("localhsm: join request key is not RSA")
	}
	if fp, _ := fingerprint(pub); fp != req.ID {
		return errors.New("localhsm: join request ID does not match its public key")
	}
	for _, r := range h.doc.Recipients {
		if r.ID == req.ID {
			return fmt.Errorf("localhsm: recipient already present: %s", req.ID)
		}
	}
	w, err := WrapForPublicKey(pub, h.mk)
	if err != nil {
		return err
	}
	h.doc.Recipients = append(h.doc.Recipients,
		&recipient{ID: req.ID, Kind: req.Kind, Label: req.Label, PublicKey: req.PublicKey, WrappedMK: w, Added: time.Now().Unix()})
	if err := h.save(); err != nil {
		h.doc.Recipients = h.doc.Recipients[:len(h.doc.Recipients)-1]
		h.emit("add-recipient", req.ID, 0, err)
		return err
	}
	h.emit("add-recipient", req.ID, 0, nil)
	return nil
}

func (h *HSM) Recipients() []RecipientInfo {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]RecipientInfo, 0, len(h.doc.Recipients))
	for _, r := range h.doc.Recipients {
		out = append(out, RecipientInfo{r.ID, r.Kind, r.Label, time.Unix(r.Added, 0), r.ID == h.id})
	}
	return out
}

// RotateMasterKey generates a new master key, re-wraps every stored key under it and re-seals it
// for every recipient. Other nodes pick it up with Reload().
func (h *HSM) RotateMasterKey() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	err := h.rotateMK(h.doc.Recipients)
	h.emit("rotate-master", "*", 0, err)
	return err
}

// RevokeRecipient removes a node and rotates the master key so the removed node's copy of the
// keystore file can no longer be reached by future changes.
//
// It does NOT un-leak anything the node already saw: a node that held the old master key plus an
// old keystore copy can still read data protected by keys in that copy. After revoking a possibly
// compromised node, also RotateKey() every data key and re-encrypt the data.
func (h *HSM) RevokeRecipient(id string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if id == h.id {
		return errors.New("localhsm: refusing to revoke self")
	}
	var keep []*recipient
	for _, r := range h.doc.Recipients {
		if r.ID != id {
			keep = append(keep, r)
		}
	}
	if len(keep) == len(h.doc.Recipients) {
		return fmt.Errorf("localhsm: no such recipient: %s", id)
	}
	err := h.rotateMK(keep)
	h.emit("revoke-recipient", id, 0, err)
	return err
}

func (h *HSM) rotateMK(recips []*recipient) error {
	if h.mk == nil {
		return ErrClosed
	}
	newMK := make([]byte, 32)
	if _, err := rand.Read(newMK); err != nil {
		return err
	}
	oldGCM, err := newGCM(h.mk)
	if err != nil {
		return err
	}
	newGCMc, err := newGCM(newMK)
	if err != nil {
		return err
	}
	// re-wrap all key versions
	newKeys := make(map[string]*keyEntry, len(h.doc.Keys))
	for id, e := range h.doc.Keys {
		ne := &keyEntry{Type: e.Type, Current: e.Current, Exportable: e.Exportable, KMSRef: e.KMSRef, IVPolicy: e.IVPolicy, IVSize: e.IVSize, Versions: map[string]*keyVersion{}}
		for vs, v := range e.Versions {
			ver, _ := strconv.ParseUint(vs, 10, 32)
			aad := keyAAD(id, uint32(ver), e.Type)
			if len(v.Wrapped) < nonceLen+tagLen {
				clear(newMK)
				return errors.New("localhsm: corrupted key entry")
			}
			mat, err := oldGCM.Open(nil, v.Wrapped[:nonceLen], v.Wrapped[nonceLen:], aad)
			if err != nil {
				clear(newMK)
				return errors.New("localhsm: key unwrap failed during master key rotation")
			}
			nonce := make([]byte, nonceLen)
			rand.Read(nonce)
			nw := newGCMc.Seal(nonce, nonce, mat, aad)
			clear(mat)
			ne.Versions[vs] = &keyVersion{Wrapped: nw, Created: v.Created, State: v.State, Meta: v.Meta, StaticIV: v.StaticIV}
		}
		newKeys[id] = ne
	}
	// re-seal the new master key for every recipient
	newRecips := make([]*recipient, 0, len(recips))
	for _, r := range recips {
		nr := *r
		switch {
		case r.ID == h.id:
			if nr.WrappedMK, err = h.prot.Wrap(newMK); err != nil {
				clear(newMK)
				return err
			}
		case len(r.PublicKey) > 0:
			pk, err := x509.ParsePKIXPublicKey(r.PublicKey)
			if err == nil {
				if pub, ok := pk.(*rsa.PublicKey); ok {
					nr.WrappedMK, err = WrapForPublicKey(pub, newMK)
				} else {
					err = errors.New("not RSA")
				}
			}
			if err != nil {
				clear(newMK)
				return fmt.Errorf("localhsm: cannot re-seal for %s: %w", r.ID, err)
			}
		default:
			clear(newMK)
			return fmt.Errorf("localhsm: recipient %s has no public key; cannot re-seal", r.ID)
		}
		newRecips = append(newRecips, &nr)
	}
	// commit (roll back in memory if the write fails)
	oldMK, oldDoc := h.mk, h.doc
	h.mk = newMK
	h.doc.Keys, h.doc.Recipients = newKeys, newRecips
	if err := h.save(); err != nil {
		h.mk, h.doc = oldMK, oldDoc
		clear(newMK)
		return err
	}
	clear(oldMK)
	return nil
}

// ------------------------------------------------- offline recovery key

type recoveryProtector struct{ priv *rsa.PrivateKey }

// GenerateRecoveryKey creates an RSA-3072 key. Store the private half OFFLINE (printed/safe/other HSM)
// and enroll it with NewJoinRequest(NewRecoveryProtector(k), "recovery") + AddRecipient.
// It is the only way back in if every TPM is lost or cleared.
func GenerateRecoveryKey() (*rsa.PrivateKey, error) { return rsa.GenerateKey(rand.Reader, 3072) }

// NewRecoveryProtector is a software protector over an RSA key (portable across OSes).
func NewRecoveryProtector(priv *rsa.PrivateKey) Protector { return &recoveryProtector{priv} }

func (r *recoveryProtector) Name() string         { return "recovery-rsa" }
func (r *recoveryProtector) HardwareBacked() bool { return false }
func (r *recoveryProtector) Destroy() error       { return nil }
func (r *recoveryProtector) Recipient() (string, *rsa.PublicKey, error) {
	fp, err := fingerprint(&r.priv.PublicKey)
	return fp, &r.priv.PublicKey, err
}
func (r *recoveryProtector) Wrap(s []byte) ([]byte, error) {
	return WrapForPublicKey(&r.priv.PublicKey, s)
}
func (r *recoveryProtector) Unwrap(b []byte) ([]byte, error) {
	if len(b) < 3 || b[0] != 1 || b[1] != 1 {
		return nil, errors.New("localhsm: bad recovery blob header")
	}
	return rsa.DecryptOAEP(sha256.New(), nil, r.priv, b[2:], nil)
}
