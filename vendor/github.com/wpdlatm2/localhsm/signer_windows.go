//go:build windows

package localhsm

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"unsafe"
)

var pSignHash = ncrypt.NewProc("NCryptSignHash")

const (
	allowSigning   = 0x2        // NCRYPT_ALLOW_SIGNING_FLAG
	eccPublicP256  = 0x31534345 // BCRYPT_ECDSA_PUBLIC_P256_MAGIC "ECS1"
	sigKeyNamePref = "LocalHSM-sig-"
)

// TPMSigner is a crypto.Signer whose ECDSA P-256 private key lives in the TPM (Windows CNG
// Microsoft Platform Crypto Provider) and cannot be exported. Use it as the private key of a TLS
// client certificate (see NewKMSTLSConfig) or to create a CSR (CreateCSR).
type TPMSigner struct {
	keyName string
	pub     *ecdsa.PublicKey
}

func openSigKey(prov uintptr, keyName string) uintptr {
	var k uintptr
	if r, _, _ := pOpenKey.Call(prov, uintptr(unsafe.Pointer(&k)), uintptr(unsafe.Pointer(u16(keyName))), 0, 0); r != 0 {
		return 0
	}
	return k
}

// NewTPMSigner opens the TPM signing key called name, creating it on first use.
func NewTPMSigner(name string) (*TPMSigner, error) {
	if name == "" {
		return nil, errors.New("localhsm: empty signer name")
	}
	keyName := sigKeyNamePref + name
	var prov uintptr
	r, _, _ := pOpenProvider.Call(uintptr(unsafe.Pointer(&prov)), uintptr(unsafe.Pointer(u16(platformProvider))), 0)
	if err := chk(r, "NCryptOpenStorageProvider"); err != nil {
		return nil, err
	}
	defer free(prov)
	key := openSigKey(prov, keyName)
	if key == 0 {
		var k uintptr
		r, _, _ = pCreateKey.Call(prov, uintptr(unsafe.Pointer(&k)), uintptr(unsafe.Pointer(u16("ECDSA_P256"))),
			uintptr(unsafe.Pointer(u16(keyName))), 0, 0)
		if err := chk(r, "NCryptCreatePersistedKey(ECDSA_P256)"); err != nil {
			return nil, err
		}
		usage := uint32(allowSigning)
		r, _, _ = pSetProperty.Call(k, uintptr(unsafe.Pointer(u16("Key Usage"))), uintptr(unsafe.Pointer(&usage)), 4, 0)
		if err := chk(r, "NCryptSetProperty(Key Usage)"); err != nil {
			free(k)
			return nil, err
		}
		r, _, _ = pFinalizeKey.Call(k, 0)
		if err := chk(r, "NCryptFinalizeKey"); err != nil {
			free(k)
			return nil, err
		}
		key = k
	}
	defer free(key)
	pub, err := exportECDSAP256(key)
	if err != nil {
		return nil, err
	}
	return &TPMSigner{keyName: keyName, pub: pub}, nil
}

func exportECDSAP256(key uintptr) (*ecdsa.PublicKey, error) {
	blobType := u16("ECCPUBLICBLOB")
	var n uint32
	r, _, _ := pExportKey.Call(key, 0, uintptr(unsafe.Pointer(blobType)), 0, 0, 0, uintptr(unsafe.Pointer(&n)), 0)
	if err := chk(r, "NCryptExportKey(size)"); err != nil {
		return nil, err
	}
	buf := make([]byte, n)
	r, _, _ = pExportKey.Call(key, 0, uintptr(unsafe.Pointer(blobType)), 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(n), uintptr(unsafe.Pointer(&n)), 0)
	if err := chk(r, "NCryptExportKey"); err != nil {
		return nil, err
	}
	buf = buf[:n]
	// BCRYPT_ECCKEY_BLOB: magic (LE u32), cbKey (LE u32), X (cbKey, BE), Y (cbKey, BE)
	if len(buf) < 8 || binary.LittleEndian.Uint32(buf) != eccPublicP256 {
		return nil, errors.New("localhsm: unexpected ECC public blob (not P-256?)")
	}
	cb := int(binary.LittleEndian.Uint32(buf[4:]))
	if cb != 32 || len(buf) < 8+2*cb {
		return nil, errors.New("localhsm: truncated ECC public blob")
	}
	return &ecdsa.PublicKey{Curve: elliptic.P256(),
		X: new(big.Int).SetBytes(buf[8 : 8+cb]), Y: new(big.Int).SetBytes(buf[8+cb : 8+2*cb])}, nil
}

// Public returns the public key (*ecdsa.PublicKey).
func (s *TPMSigner) Public() crypto.PublicKey { return s.pub }

// Sign signs digest with the TPM key and returns an ASN.1 DER ECDSA signature.
func (s *TPMSigner) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	if len(digest) == 0 {
		return nil, errors.New("localhsm: empty digest")
	}
	var prov uintptr
	r, _, _ := pOpenProvider.Call(uintptr(unsafe.Pointer(&prov)), uintptr(unsafe.Pointer(u16(platformProvider))), 0)
	if err := chk(r, "NCryptOpenStorageProvider"); err != nil {
		return nil, err
	}
	defer free(prov)
	key := openSigKey(prov, s.keyName)
	if key == 0 {
		return nil, fmt.Errorf("localhsm: TPM signing key %q not found", s.keyName)
	}
	defer free(key)
	sig := make([]byte, 64)
	var n uint32
	r, _, _ = pSignHash.Call(key, 0, uintptr(unsafe.Pointer(&digest[0])), uintptr(len(digest)),
		uintptr(unsafe.Pointer(&sig[0])), uintptr(len(sig)), uintptr(unsafe.Pointer(&n)), 0)
	if err := chk(r, "NCryptSignHash"); err != nil {
		return nil, err
	}
	if n != 64 { // IEEE P1363: r || s
		return nil, fmt.Errorf("localhsm: unexpected signature length %d", n)
	}
	return ecdsaDER(new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:]))
}

// Destroy deletes the TPM key (the certificate issued for it becomes useless).
func (s *TPMSigner) Destroy() error {
	var prov uintptr
	r, _, _ := pOpenProvider.Call(uintptr(unsafe.Pointer(&prov)), uintptr(unsafe.Pointer(u16(platformProvider))), 0)
	if err := chk(r, "NCryptOpenStorageProvider"); err != nil {
		return err
	}
	defer free(prov)
	key := openSigKey(prov, s.keyName)
	if key == 0 {
		return nil
	}
	r, _, _ = pDeleteKey.Call(key, 0)
	return chk(r, "NCryptDeleteKey")
}
