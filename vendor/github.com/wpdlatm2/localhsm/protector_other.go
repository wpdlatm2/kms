//go:build !windows && !linux

package localhsm

// TPMAvailable: no TPM backend on this platform.
func TPMAvailable() bool { return false }

func NewTPMProtector(keyName string) (Protector, error)   { return nil, ErrUnsupported }
func NewDPAPIProtector(keyName string) (Protector, error) { return nil, ErrUnsupported }
