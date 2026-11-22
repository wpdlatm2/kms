package localhsm

// Kernel-held keys (Linux): the HSM hands a key to the kernel crypto API (AF_ALG "gcm(aes)") and
// from then on the application only sends the data of each request and receives the result. The
// application never receives the key bytes, and after setup only the kernel transform holds them.
//
//	k, _ := h.OpenKernelAEAD("db-key", 0)          // key goes into the kernel, the copy here is zeroized
//	defer k.Close()
//	ct, _ := k.Seal(nonce, aad, plaintext)         // plaintext in, ciphertext||tag out
//	pt, _ := k.Open(nonce, aad, ct)
//
//	f, _ := k.DupFile()                            // hand a keyed handle to another process
//	other, _ := localhsm.NewKernelAEADFromFile(f, true)   // that process never sees the key
//
// Limits (measured on Linux 7.0): per-operation cost is a few microseconds (about 3x slower than
// in-process AES-GCM at 64 KiB and 28x at 64 bytes), and AAD+payload must stay below
// MaxKernelMessage because a larger AF_ALG request blocks in the kernel. Only algorithms the
// kernel provides are possible (AES-GCM here; SEED and post-quantum algorithms are not).
// Linux only; other platforms return ErrUnsupported.

import (
	"errors"
	"strconv"
	"time"
)

// MaxKernelMessage is the largest AAD+payload accepted by one kernel AEAD operation.
// 128 KiB was verified; 256 KiB made the kernel call block indefinitely.
const MaxKernelMessage = 128 << 10

var (
	// ErrTooLarge: the request exceeds MaxKernelMessage; split the data into records.
	ErrTooLarge = errors.New("localhsm: message too large for one kernel AEAD operation (split into records)")
	// ErrNotCurrent: this handle was opened for a key version that may no longer encrypt
	// (an old, expired or retired version); it can only Open.
	ErrNotCurrent = errors.New("localhsm: kernel handle is decrypt-only (not the current active key version)")
	// ErrAuthFailed: the ciphertext, AAD or nonce did not authenticate.
	ErrAuthFailed = errors.New("localhsm: kernel AEAD authentication failed")
)

// loadForKernel applies the keystore policy (disabled versions, enterprise staleness) and returns a
// copy of the key material to be loaded into the kernel. The caller must clear() it. canSeal is true
// only for the current, active, unexpired version. Export policy is NOT required: the application
// never receives the key.
func (h *HSM) loadForKernel(keyID string, ver uint32) (mat []byte, canSeal bool, err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	m, v, t, err := h.material(keyID, ver, false)
	if err != nil {
		h.emit("kernel-load", keyID, ver, err)
		return nil, false, err
	}
	switch t {
	case AES256GCM, AES128, AES192, AES256:
	default:
		clear(m)
		err = errors.New("localhsm: kernel AEAD supports AES keys only, not " + string(t))
		h.emit("kernel-load", keyID, v, err)
		return nil, false, err
	}
	e := h.doc.Keys[keyID]
	rec := e.Versions[strconv.FormatUint(uint64(v), 10)]
	canSeal = v == e.Current && effectiveState(rec, time.Now()) == stateActive
	h.emit("kernel-load", keyID, v, nil)
	return m, canSeal, nil
}
