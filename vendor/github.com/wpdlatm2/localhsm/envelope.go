package localhsm

// Envelope encryption: the application encrypts data with a per-object (or per-batch) data key
// (DEK) using the CPU's accelerated AES-GCM, and only the DEK is wrapped by a key-encryption key
// (KEK) that stays inside the HSM (an "aes256-gcm" key, normally non-exportable). Unlike calling
// Encrypt on the data itself, the HSM is involved once per DEK instead of once per byte, and a
// KEK rotation only needs the (tiny) wrapped DEKs to be re-wrapped.
//
// The KEK can be a locally generated key (stand-alone mode) or a KMS-issued one (enterprise mode).
//
//	// one DEK per object (SealEnvelope / OpenEnvelope)
//	blob, _ := h.SealEnvelope("kek", plaintext, objectID)
//	pt, _ := h.OpenEnvelope("kek", blob, objectID)
//
//	// one DEK for many objects: GenerateDataKey once, keep the wrapped key next to the data
//	dek, wrapped, _ := h.GenerateDataKey("kek", batchID)
//	defer clear(dek)                                   // ... encrypt objects with dek yourself ...
//	dek, _ = h.DecryptDataKey("kek", wrapped, batchID) // later, to decrypt
//
// SECURITY: the plaintext DEK exists in application memory while you hold it. Hold it as briefly
// as possible and clear() it. The AAD binds a wrapped DEK to its object, so wrapped keys cannot be
// swapped between objects.

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
)

const (
	envMagic     = "LHEV"
	envFormat    = 1
	envHdrLen    = 4 + 1 + 2 // magic, format, wrapped-DEK length
	dekAADPrefix = "localhsm/dek|"
	// DEKSize is the size of the data keys produced by GenerateDataKey (AES-256).
	DEKSize = 32
)

func dekAAD(aad []byte) []byte { return append([]byte(dekAADPrefix), aad...) }

// GenerateDataKey returns a fresh random DEK and the same key wrapped by the KEK. The caller must
// clear() the plaintext DEK. aad (e.g. an object ID) is authenticated and must be supplied again
// to DecryptDataKey.
func (h *HSM) GenerateDataKey(kekID string, aad []byte) (dek, wrapped []byte, err error) {
	dek = make([]byte, DEKSize)
	if _, err = rand.Read(dek); err != nil {
		return nil, nil, err
	}
	if wrapped, err = h.Encrypt(kekID, dek, dekAAD(aad)); err != nil {
		clear(dek)
		return nil, nil, err
	}
	h.emitLocked("datakey-generate", kekID, wrappedKeyVersion(wrapped), nil)
	return dek, wrapped, nil
}

// DecryptDataKey unwraps a DEK produced by GenerateDataKey (any non-disabled KEK version works,
// so data stays readable across KEK rotations). The caller must clear() the result.
func (h *HSM) DecryptDataKey(kekID string, wrapped, aad []byte) ([]byte, error) {
	dek, err := h.Decrypt(kekID, wrapped, dekAAD(aad))
	h.emitLocked("datakey-decrypt", kekID, wrappedKeyVersion(wrapped), err)
	return dek, err
}

// RewrapDataKey re-wraps a DEK under the KEK's current version without exposing it to the caller.
// Use it after a KEK rotation to retire an old KEK version.
func (h *HSM) RewrapDataKey(kekID string, wrapped, aad []byte) ([]byte, error) {
	dek, err := h.Decrypt(kekID, wrapped, dekAAD(aad))
	if err != nil {
		h.emitLocked("datakey-rewrap", kekID, wrappedKeyVersion(wrapped), err)
		return nil, err
	}
	defer clear(dek)
	nw, err := h.Encrypt(kekID, dek, dekAAD(aad))
	h.emitLocked("datakey-rewrap", kekID, wrappedKeyVersion(nw), err)
	return nw, err
}

// SealEnvelope encrypts plaintext with a new DEK and returns
// magic|fmt|len(wrapped)|wrapped DEK|nonce|ciphertext+tag. aad is authenticated, not stored.
func (h *HSM) SealEnvelope(kekID string, plaintext, aad []byte) ([]byte, error) {
	dek, wrapped, err := h.GenerateDataKey(kekID, aad)
	if err != nil {
		return nil, err
	}
	defer clear(dek)
	if len(wrapped) > 0xFFFF {
		return nil, errors.New("localhsm: wrapped key too large")
	}
	g, err := newGCM(dek)
	if err != nil {
		return nil, err
	}
	out := make([]byte, envHdrLen+len(wrapped)+nonceLen, envHdrLen+len(wrapped)+nonceLen+len(plaintext)+tagLen)
	copy(out, envMagic)
	out[4] = envFormat
	binary.BigEndian.PutUint16(out[5:], uint16(len(wrapped)))
	copy(out[envHdrLen:], wrapped)
	nonce := out[envHdrLen+len(wrapped):]
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	// the data layer authenticates the header and the wrapped DEK as well
	ad := append(append([]byte{}, out[:envHdrLen+len(wrapped)]...), aad...)
	return g.Seal(out, nonce, plaintext, ad), nil
}

// OpenEnvelope reverses SealEnvelope.
func (h *HSM) OpenEnvelope(kekID string, blob, aad []byte) ([]byte, error) {
	if len(blob) < envHdrLen || string(blob[:4]) != envMagic || blob[4] != envFormat {
		return nil, errors.New("localhsm: bad envelope")
	}
	wl := int(binary.BigEndian.Uint16(blob[5:]))
	if len(blob) < envHdrLen+wl+nonceLen+tagLen {
		return nil, errors.New("localhsm: envelope too short")
	}
	wrapped := blob[envHdrLen : envHdrLen+wl]
	dek, err := h.DecryptDataKey(kekID, wrapped, aad)
	if err != nil {
		return nil, err
	}
	defer clear(dek)
	g, err := newGCM(dek)
	if err != nil {
		return nil, err
	}
	nonce := blob[envHdrLen+wl : envHdrLen+wl+nonceLen]
	ad := append(append([]byte{}, blob[:envHdrLen+wl]...), aad...)
	pt, err := g.Open(nil, nonce, blob[envHdrLen+wl+nonceLen:], ad)
	if err != nil {
		return nil, errors.New("localhsm: envelope decryption failed (wrong key/aad or tampered data)")
	}
	return pt, nil
}

// wrappedKeyVersion reads the KEK version from a wrapped key's header (0 if malformed).
func wrappedKeyVersion(blob []byte) uint32 {
	if len(blob) < hdrLen {
		return 0
	}
	return binary.BigEndian.Uint32(blob[5:9])
}

// emitLocked delivers an audit event from code that does not already hold the HSM lock.
func (h *HSM) emitLocked(op, id string, ver uint32, err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.emit(op, id, ver, err)
}
