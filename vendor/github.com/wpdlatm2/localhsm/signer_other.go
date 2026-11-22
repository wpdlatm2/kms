//go:build !windows && !linux

package localhsm

import (
	"crypto"
	"io"
)

// TPMSigner is not available on this platform.
type TPMSigner struct{}

func NewTPMSigner(name string) (*TPMSigner, error) { return nil, ErrUnsupported }
func (s *TPMSigner) Public() crypto.PublicKey      { return nil }
func (s *TPMSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, ErrUnsupported
}
func (s *TPMSigner) Destroy() error { return ErrUnsupported }
