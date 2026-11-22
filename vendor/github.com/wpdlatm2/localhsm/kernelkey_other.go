//go:build !linux

package localhsm

import "os"

// KernelAEAD is only available on Linux.
type KernelAEAD struct{}

func (h *HSM) OpenKernelAEAD(keyID string, ver uint32) (*KernelAEAD, error) {
	return nil, ErrUnsupported
}

func NewKernelAEADFromFile(f *os.File, canSeal bool) (*KernelAEAD, error) {
	return nil, ErrUnsupported
}

func (k *KernelAEAD) Seal(nonce, aad, plaintext []byte) ([]byte, error) { return nil, ErrUnsupported }
func (k *KernelAEAD) Open(nonce, aad, ciphertext []byte) ([]byte, error) {
	return nil, ErrUnsupported
}
func (k *KernelAEAD) DupFile() (*os.File, error) { return nil, ErrUnsupported }
func (k *KernelAEAD) KeyViaKeyring() bool        { return false }
func (k *KernelAEAD) Close()                     {}

// KernelAEADSupported is always false off Linux.
func KernelAEADSupported() bool { return false }
