//go:build linux

package localhsm

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	algSetKeyBySerial = 7 // ALG_SET_KEY_BY_KEY_SERIAL (include/uapi/linux/if_alg.h)
	kernelTagLen      = 16
	kernelNonceLen    = 12
	opPoolSize        = 8
)

// KEY_SPEC_PROCESS_KEYRING (-2): freed automatically when the process exits. A variable, because a
// negative constant cannot be converted to uintptr.
var keySpecProcess = -2

// KernelAEAD is an AES-GCM transform whose key lives only inside the kernel. It is safe for
// concurrent use.
type KernelAEAD struct {
	tfm        int
	canSeal    bool
	viaKeyring bool
	ops        chan int // idle operation sockets

	mu     sync.Mutex
	closed bool
}

// OpenKernelAEAD loads a key version (0 = current) into the kernel and returns the handle. The
// key must be an AES key (aes256-gcm, aes-128/192/256). The copy in this process is zeroized.
func (h *HSM) OpenKernelAEAD(keyID string, ver uint32) (*KernelAEAD, error) {
	mat, canSeal, err := h.loadForKernel(keyID, ver)
	if err != nil {
		return nil, err
	}
	defer clear(mat)
	return newKernelAEAD(mat, canSeal)
}

// NewKernelAEADFromFile wraps a keyed AF_ALG socket received from another process (see DupFile).
// The caller keeps ownership of f; canSeal says whether this holder may encrypt.
func NewKernelAEADFromFile(f *os.File, canSeal bool) (*KernelAEAD, error) {
	fd, err := unix.Dup(int(f.Fd()))
	if err != nil {
		return nil, err
	}
	unix.CloseOnExec(fd)
	return &KernelAEAD{tfm: fd, canSeal: canSeal, ops: make(chan int, opPoolSize)}, nil
}

func newKernelAEAD(key []byte, canSeal bool) (*KernelAEAD, error) {
	switch len(key) {
	case 16, 24, 32:
	default:
		return nil, fmt.Errorf("localhsm: bad AES key length %d", len(key))
	}
	tfm, err := unix.Socket(unix.AF_ALG, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("localhsm: AF_ALG unavailable: %w", err)
	}
	if err := unix.Bind(tfm, &unix.SockaddrALG{Type: "aead", Name: "gcm(aes)"}); err != nil {
		unix.Close(tfm)
		return nil, fmt.Errorf("localhsm: kernel gcm(aes) unavailable: %w", err)
	}
	via := setKeyViaKeyring(tfm, key)
	if !via { // older kernels: pass the bytes directly (no Go string copy, so they can be zeroized)
		_, _, e := unix.Syscall6(unix.SYS_SETSOCKOPT, uintptr(tfm), unix.SOL_ALG, unix.ALG_SET_KEY,
			uintptr(unsafe.Pointer(&key[0])), uintptr(len(key)), 0)
		if e != 0 {
			unix.Close(tfm)
			return nil, fmt.Errorf("localhsm: set kernel key: %w", e)
		}
	}
	if _, _, e := unix.Syscall6(unix.SYS_SETSOCKOPT, uintptr(tfm), unix.SOL_ALG, unix.ALG_SET_AEAD_AUTHSIZE, 0, kernelTagLen, 0); e != 0 {
		unix.Close(tfm)
		return nil, fmt.Errorf("localhsm: set tag size: %w", e)
	}
	return &KernelAEAD{tfm: tfm, canSeal: canSeal, viaKeyring: via, ops: make(chan int, opPoolSize)}, nil
}

// setKeyViaKeyring puts the key into a process-keyring "logon" key (unreadable from user space),
// points the transform at it by serial number, and removes the keyring key again.
func setKeyViaKeyring(tfm int, key []byte) bool {
	var rnd [8]byte
	rand.Read(rnd[:])
	desc := append([]byte("localhsm:kk:"+hex.EncodeToString(rnd[:])), 0)
	typ := append([]byte("logon"), 0)
	r, _, e := unix.Syscall6(unix.SYS_ADD_KEY, uintptr(unsafe.Pointer(&typ[0])), uintptr(unsafe.Pointer(&desc[0])),
		uintptr(unsafe.Pointer(&key[0])), uintptr(len(key)), uintptr(keySpecProcess), 0)
	if e != 0 {
		return false
	}
	serial := int(r)
	defer func() { // the kernel transform has its own copy now
		unix.Syscall6(unix.SYS_KEYCTL, unix.KEYCTL_REVOKE, uintptr(serial), 0, 0, 0, 0)
		unix.Syscall6(unix.SYS_KEYCTL, unix.KEYCTL_UNLINK, uintptr(serial), uintptr(keySpecProcess), 0, 0, 0)
	}()
	return unix.SetsockoptInt(tfm, unix.SOL_ALG, algSetKeyBySerial, serial) == nil
}

// KeyViaKeyring reports whether the key reached the kernel through the keyring (it never sat in a
// user-space socket option) or, on older kernels, directly.
func (k *KernelAEAD) KeyViaKeyring() bool { return k.viaKeyring }

// DupFile returns a duplicate of the keyed transform that can be passed to another process
// (exec.Cmd.ExtraFiles or SCM_RIGHTS). The receiver can encrypt/decrypt but cannot read the key.
func (k *KernelAEAD) DupFile() (*os.File, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.closed {
		return nil, errors.New("localhsm: kernel handle closed")
	}
	fd, err := unix.Dup(k.tfm)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), "localhsm-kernel-aead"), nil
}

// Close releases the kernel transform (and with it the key).
func (k *KernelAEAD) Close() {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.closed {
		return
	}
	k.closed = true
	for {
		select {
		case fd := <-k.ops:
			unix.Close(fd)
		default:
			unix.Close(k.tfm)
			return
		}
	}
}

func (k *KernelAEAD) getOp() (int, error) {
	k.mu.Lock()
	closed := k.closed
	k.mu.Unlock()
	if closed {
		return -1, errors.New("localhsm: kernel handle closed")
	}
	select {
	case fd := <-k.ops:
		return fd, nil
	default:
	}
	r, _, e := unix.Syscall6(unix.SYS_ACCEPT4, uintptr(k.tfm), 0, 0, unix.SOCK_CLOEXEC, 0, 0)
	if e != 0 {
		return -1, fmt.Errorf("localhsm: kernel operation socket: %w", e)
	}
	return int(r), nil
}

func (k *KernelAEAD) putOp(fd int, ok bool) {
	if !ok {
		unix.Close(fd)
		return
	}
	select {
	case k.ops <- fd:
	default:
		unix.Close(fd)
	}
}

func cmsgALG(typ int32, data []byte) []byte {
	b := make([]byte, unix.CmsgSpace(len(data)))
	h := (*unix.Cmsghdr)(unsafe.Pointer(&b[0]))
	h.Level, h.Type = unix.SOL_ALG, typ
	h.SetLen(unix.CmsgLen(len(data)))
	copy(b[unix.CmsgLen(0):], data)
	return b
}

func le32(v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return b
}

// run executes one operation. in = AAD||data, returns the raw kernel output (AAD||result).
func (k *KernelAEAD) run(op uint32, nonce, aad, data []byte, outLen int) ([]byte, error) {
	if len(nonce) != kernelNonceLen {
		return nil, fmt.Errorf("localhsm: nonce must be %d bytes", kernelNonceLen)
	}
	if len(aad)+len(data) == 0 { // an empty request would leave the kernel waiting for data forever
		return nil, errors.New("localhsm: empty kernel AEAD request is not supported (use at least 1 byte of AAD or data)")
	}
	fd, err := k.getOp()
	if err != nil {
		return nil, err
	}
	in := make([]byte, 0, len(aad)+len(data))
	in = append(append(in, aad...), data...)
	oob := append(append(cmsgALG(unix.ALG_SET_OP, le32(op)),
		cmsgALG(unix.ALG_SET_IV, append(le32(uint32(len(nonce))), nonce...))...),
		cmsgALG(unix.ALG_SET_AEAD_ASSOCLEN, le32(uint32(len(aad))))...)
	if _, err := unix.SendmsgN(fd, in, oob, nil, 0); err != nil {
		k.putOp(fd, false)
		return nil, fmt.Errorf("localhsm: kernel send: %w", err)
	}
	out := make([]byte, outLen)
	n, err := unix.Read(fd, out)
	if err != nil {
		k.putOp(fd, false)
		if errors.Is(err, unix.EBADMSG) {
			return nil, ErrAuthFailed
		}
		return nil, fmt.Errorf("localhsm: kernel receive: %w", err)
	}
	k.putOp(fd, true)
	return out[:n], nil
}

// Seal encrypts plaintext and returns ciphertext||tag (16-byte tag). nonce must be 12 bytes and
// unique per key; aad is authenticated.
func (k *KernelAEAD) Seal(nonce, aad, plaintext []byte) ([]byte, error) {
	if !k.canSeal {
		return nil, ErrNotCurrent
	}
	if len(aad)+len(plaintext) > MaxKernelMessage {
		return nil, ErrTooLarge
	}
	out, err := k.run(unix.ALG_OP_ENCRYPT, nonce, aad, plaintext, len(aad)+len(plaintext)+kernelTagLen)
	if err != nil {
		return nil, err
	}
	return out[len(aad):], nil
}

// Open verifies and decrypts ciphertext||tag.
func (k *KernelAEAD) Open(nonce, aad, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < kernelTagLen {
		return nil, ErrAuthFailed
	}
	if len(aad)+len(ciphertext)-kernelTagLen > MaxKernelMessage {
		return nil, ErrTooLarge
	}
	out, err := k.run(unix.ALG_OP_DECRYPT, nonce, aad, ciphertext, len(aad)+len(ciphertext)-kernelTagLen)
	if err != nil {
		return nil, err
	}
	return out[len(aad):], nil
}

// KernelAEADSupported reports whether this system can host kernel-held AES-GCM keys (AF_ALG
// gcm(aes) available to this process).
func KernelAEADSupported() bool {
	k, err := newKernelAEAD(make([]byte, 32), true)
	if err != nil {
		return false
	}
	k.Close()
	return true
}
