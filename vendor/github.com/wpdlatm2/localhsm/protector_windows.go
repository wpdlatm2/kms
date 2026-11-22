//go:build windows

package localhsm

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"unsafe"
)

func sysDLL(name string) *syscall.LazyDLL {
	// Load from System32 only (avoid DLL search-order hijack).
	return syscall.NewLazyDLL(filepath.Join(os.Getenv("SystemRoot"), "System32", name))
}

var (
	ncrypt   = sysDLL("ncrypt.dll")
	crypt32  = sysDLL("crypt32.dll")
	kernel32 = sysDLL("kernel32.dll")

	pOpenProvider = ncrypt.NewProc("NCryptOpenStorageProvider")
	pCreateKey    = ncrypt.NewProc("NCryptCreatePersistedKey")
	pSetProperty  = ncrypt.NewProc("NCryptSetProperty")
	pFinalizeKey  = ncrypt.NewProc("NCryptFinalizeKey")
	pOpenKey      = ncrypt.NewProc("NCryptOpenKey")
	pDeleteKey    = ncrypt.NewProc("NCryptDeleteKey")
	pFreeObject   = ncrypt.NewProc("NCryptFreeObject")
	pEncrypt      = ncrypt.NewProc("NCryptEncrypt")
	pDecrypt      = ncrypt.NewProc("NCryptDecrypt")

	pProtect   = crypt32.NewProc("CryptProtectData")
	pUnprotect = crypt32.NewProc("CryptUnprotectData")
	pLocalFree = kernel32.NewProc("LocalFree")
)

const (
	platformProvider = "Microsoft Platform Crypto Provider"
	padOAEPFlag      = 0x4
	allowDecrypt     = 0x1
)

var oaepHashes = map[byte]string{1: "SHA256", 2: "SHA1"}

type oaepPadding struct {
	algID   *uint16
	label   uintptr
	cbLabel uint32
}

func u16(s string) *uint16 {
	p, _ := syscall.UTF16PtrFromString(s)
	return p
}

func chk(r uintptr, what string) error {
	if r != 0 {
		return fmt.Errorf("localhsm: %s failed: 0x%08X", what, uint32(r))
	}
	return nil
}

func free(h uintptr) {
	if h != 0 {
		pFreeObject.Call(h)
	}
}

// ------------------------------------------------------------------ TPM

type tpmProtector struct{ keyName string }

// TPMAvailable reports whether the platform TPM crypto provider can be opened.
func TPMAvailable() bool {
	var h uintptr
	r, _, _ := pOpenProvider.Call(uintptr(unsafe.Pointer(&h)), uintptr(unsafe.Pointer(u16(platformProvider))), 0)
	if r != 0 {
		return false
	}
	free(h)
	return true
}

// NewTPMProtector returns a protector backed by a non-exportable RSA-2048 key
// stored in the platform TPM (AMD fTPM / Intel PTT / discrete TPM).
func NewTPMProtector(keyName string) (Protector, error) {
	if keyName == "" {
		return nil, errors.New("localhsm: empty TPM key name")
	}
	return &tpmProtector{keyName}, nil
}

func (t *tpmProtector) Name() string         { return "tpm-ncrypt" }
func (t *tpmProtector) HardwareBacked() bool { return true }

func (t *tpmProtector) provider() (uintptr, error) {
	var h uintptr
	r, _, _ := pOpenProvider.Call(uintptr(unsafe.Pointer(&h)), uintptr(unsafe.Pointer(u16(platformProvider))), 0)
	return h, chk(r, "NCryptOpenStorageProvider")
}

func (t *tpmProtector) openKey(prov uintptr) uintptr {
	var k uintptr
	r, _, _ := pOpenKey.Call(prov, uintptr(unsafe.Pointer(&k)), uintptr(unsafe.Pointer(u16(t.keyName))), 0, 0)
	if r != 0 {
		return 0
	}
	return k
}

func (t *tpmProtector) ensureKey(prov uintptr) (uintptr, error) {
	if k := t.openKey(prov); k != 0 {
		return k, nil
	}
	var k uintptr
	r, _, _ := pCreateKey.Call(prov, uintptr(unsafe.Pointer(&k)), uintptr(unsafe.Pointer(u16("RSA"))),
		uintptr(unsafe.Pointer(u16(t.keyName))), 0, 0)
	if err := chk(r, "NCryptCreatePersistedKey"); err != nil {
		return 0, err
	}
	length, usage := uint32(2048), uint32(allowDecrypt)
	steps := []struct {
		prop string
		val  *uint32
	}{{"Length", &length}, {"Key Usage", &usage}}
	for _, s := range steps {
		r, _, _ = pSetProperty.Call(k, uintptr(unsafe.Pointer(u16(s.prop))), uintptr(unsafe.Pointer(s.val)), 4, 0)
		if err := chk(r, "NCryptSetProperty("+s.prop+")"); err != nil {
			free(k)
			return 0, err
		}
	}
	r, _, _ = pFinalizeKey.Call(k, 0)
	if err := chk(r, "NCryptFinalizeKey"); err != nil {
		free(k)
		return 0, err
	}
	return k, nil
}

func oaep(proc *syscall.LazyProc, key uintptr, data []byte, hash string) ([]byte, error) {
	pad := oaepPadding{algID: u16(hash)}
	var n uint32
	in := uintptr(unsafe.Pointer(&data[0]))
	r, _, _ := proc.Call(key, in, uintptr(len(data)), uintptr(unsafe.Pointer(&pad)), 0, 0,
		uintptr(unsafe.Pointer(&n)), padOAEPFlag)
	if err := chk(r, "size query"); err != nil {
		return nil, err
	}
	out := make([]byte, n)
	r, _, _ = proc.Call(key, in, uintptr(len(data)), uintptr(unsafe.Pointer(&pad)),
		uintptr(unsafe.Pointer(&out[0])), uintptr(n), uintptr(unsafe.Pointer(&n)), padOAEPFlag)
	runtime.KeepAlive(pad)
	runtime.KeepAlive(data)
	if err := chk(r, "crypt"); err != nil {
		return nil, err
	}
	return out[:n], nil
}

func (t *tpmProtector) Wrap(secret []byte) ([]byte, error) {
	if len(secret) == 0 {
		return nil, errors.New("localhsm: empty secret")
	}
	prov, err := t.provider()
	if err != nil {
		return nil, err
	}
	defer free(prov)
	key, err := t.ensureKey(prov)
	if err != nil {
		return nil, err
	}
	defer free(key)
	var last error
	for _, id := range []byte{1, 2} { // prefer OAEP-SHA256, fall back to SHA1
		ct, err := oaep(pEncrypt, key, secret, oaepHashes[id])
		if err == nil {
			return append([]byte{1, id}, ct...), nil
		}
		last = err
	}
	return nil, last
}

func (t *tpmProtector) Unwrap(blob []byte) ([]byte, error) {
	if len(blob) < 3 || blob[0] != 1 || oaepHashes[blob[1]] == "" {
		return nil, errors.New("localhsm: bad TPM blob header")
	}
	prov, err := t.provider()
	if err != nil {
		return nil, err
	}
	defer free(prov)
	key := t.openKey(prov)
	if key == 0 {
		return nil, fmt.Errorf("localhsm: TPM key %q not found (different machine / TPM cleared?)", t.keyName)
	}
	defer free(key)
	return oaep(pDecrypt, key, blob[2:], oaepHashes[blob[1]])
}

func (t *tpmProtector) Destroy() error {
	prov, err := t.provider()
	if err != nil {
		return err
	}
	defer free(prov)
	key := t.openKey(prov)
	if key == 0 {
		return nil
	}
	r, _, _ := pDeleteKey.Call(key, 0) // releases the handle on success
	return chk(r, "NCryptDeleteKey")
}

// ---------------------------------------------------------------- DPAPI

type dataBlob struct {
	cb uint32
	pb *byte
}

type dpapiProtector struct{ entropy []byte }

// NewDPAPIProtector is a SOFTWARE fallback bound to the Windows user; it is not hardware-backed.
func NewDPAPIProtector(keyName string) (Protector, error) {
	e := []byte(keyName)
	if len(e) == 0 {
		e = []byte("localhsm")
	}
	return &dpapiProtector{e}, nil
}

func (d *dpapiProtector) Name() string         { return "dpapi" }
func (d *dpapiProtector) HardwareBacked() bool { return false }
func (d *dpapiProtector) Destroy() error       { return nil }

func (d *dpapiProtector) run(p *syscall.LazyProc, data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("localhsm: empty input")
	}
	in := dataBlob{uint32(len(data)), &data[0]}
	ent := dataBlob{uint32(len(d.entropy)), &d.entropy[0]}
	var out dataBlob
	r, _, e := p.Call(uintptr(unsafe.Pointer(&in)), 0, uintptr(unsafe.Pointer(&ent)), 0, 0, 0, uintptr(unsafe.Pointer(&out)))
	if r == 0 {
		return nil, fmt.Errorf("localhsm: DPAPI failed: %v", e)
	}
	defer pLocalFree.Call(uintptr(unsafe.Pointer(out.pb)))
	res := make([]byte, out.cb)
	copy(res, unsafe.Slice(out.pb, out.cb))
	runtime.KeepAlive(data)
	return res, nil
}

func (d *dpapiProtector) Wrap(secret []byte) ([]byte, error) { return d.run(pProtect, secret) }
func (d *dpapiProtector) Unwrap(blob []byte) ([]byte, error) { return d.run(pUnprotect, blob) }
