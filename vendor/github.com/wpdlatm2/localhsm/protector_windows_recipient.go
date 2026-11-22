//go:build windows

package localhsm

import (
	"crypto/rsa"
	"encoding/binary"
	"errors"
	"math/big"
	"runtime"
	"unsafe"
)

var pExportKey = ncrypt.NewProc("NCryptExportKey")

const rsaPublicMagic = 0x31415352 // "RSA1"

// exportPublic reads the public half of a (non-exportable) TPM RSA key.
func exportPublic(key uintptr) (*rsa.PublicKey, error) {
	blobType := u16("RSAPUBLICBLOB")
	var n uint32
	r, _, _ := pExportKey.Call(key, 0, uintptr(unsafe.Pointer(blobType)), 0, 0, 0, uintptr(unsafe.Pointer(&n)), 0)
	if err := chk(r, "NCryptExportKey(size)"); err != nil {
		return nil, err
	}
	buf := make([]byte, n)
	r, _, _ = pExportKey.Call(key, 0, uintptr(unsafe.Pointer(blobType)), 0,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(n), uintptr(unsafe.Pointer(&n)), 0)
	runtime.KeepAlive(blobType)
	if err := chk(r, "NCryptExportKey"); err != nil {
		return nil, err
	}
	buf = buf[:n]
	// BCRYPT_RSAKEY_BLOB: Magic, BitLength, cbPublicExp, cbModulus, cbPrime1, cbPrime2 (LE u32), exp, modulus (BE)
	if len(buf) < 24 || binary.LittleEndian.Uint32(buf) != rsaPublicMagic {
		return nil, errors.New("localhsm: unexpected RSA public blob")
	}
	e, m := int(binary.LittleEndian.Uint32(buf[8:])), int(binary.LittleEndian.Uint32(buf[12:]))
	if len(buf) < 24+e+m {
		return nil, errors.New("localhsm: truncated RSA public blob")
	}
	exp := new(big.Int).SetBytes(buf[24 : 24+e])
	return &rsa.PublicKey{N: new(big.Int).SetBytes(buf[24+e : 24+e+m]), E: int(exp.Int64())}, nil
}

func (t *tpmProtector) Recipient() (string, *rsa.PublicKey, error) {
	prov, err := t.provider()
	if err != nil {
		return "", nil, err
	}
	defer free(prov)
	key, err := t.ensureKey(prov)
	if err != nil {
		return "", nil, err
	}
	defer free(key)
	pub, err := exportPublic(key)
	if err != nil {
		return "", nil, err
	}
	id, err := fingerprint(pub)
	return id, pub, err
}

func (d *dpapiProtector) Recipient() (string, *rsa.PublicKey, error) {
	return "dpapi:" + string(d.entropy), nil, nil
}
