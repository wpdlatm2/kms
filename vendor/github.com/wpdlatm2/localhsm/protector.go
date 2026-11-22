// Package localhsm is a single-application local HSM.
//
// Trust chain:
//
//	TPM (non-exportable RSA key) --wraps--> master key (32B)
//	master key --AES-GCM--> per-key material stored in the keystore file
//	master key --HKDF--> keystore MAC key (integrity of the whole file)
//
// Bulk crypto uses the Go standard library (AES-NI accelerated on amd64).
package localhsm

import (
	"crypto/rsa"
	"errors"
)

// ErrUnsupported is returned by protectors not available on this platform.
var ErrUnsupported = errors.New("localhsm: protector not supported on this platform")

// Protector wraps/unwraps a small secret (the HSM master key).
type Protector interface {
	Name() string
	// Recipient returns this protector's ID in a keystore and, if it is an RSA key that
	// other nodes can wrap the master key to, its public key (nil for DPAPI).
	// For a TPM protector this creates the TPM key if it does not exist yet.
	Recipient() (id string, pub *rsa.PublicKey, err error)
	HardwareBacked() bool
	Wrap(secret []byte) ([]byte, error)
	Unwrap(blob []byte) ([]byte, error)
	// Destroy irreversibly removes the protecting key (crypto-erase).
	Destroy() error
}

// AvailableProtector returns a TPM protector if a platform TPM exists.
// The software fallback is only used when allowSoftware is true.
func AvailableProtector(name string, allowSoftware bool) (Protector, error) {
	if TPMAvailable() {
		return NewTPMProtector(name)
	}
	if allowSoftware {
		return NewDPAPIProtector(name)
	}
	return nil, errors.New("localhsm: no TPM available and software fallback not allowed")
}
