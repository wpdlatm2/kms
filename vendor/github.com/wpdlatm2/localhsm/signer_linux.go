//go:build linux

package localhsm

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

const sigHandleBase = 0x810A0000 // LocalHSM signing keys: 0x810A0000-0x810AFFFF

// TPMSigner is a crypto.Signer whose ECDSA P-256 private key lives in the TPM (persistent object
// under the owner SRK, fixedTPM/fixedParent: it cannot be exported). Use it as the private key of a
// TLS client certificate (see NewKMSTLSConfig) or to create a CSR (CreateCSR). The same ownership
// rule as the wrapping key applies: a handle holding a foreign object is never touched.
type TPMSigner struct {
	name   string
	handle tpm2.TPMHandle
	tag    []byte
	pub    *ecdsa.PublicKey
}

func (s *TPMSigner) template() tpm2.TPMTPublic {
	return tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM: true, FixedParent: true, SensitiveDataOrigin: true,
			UserWithAuth: true, NoDA: true, SignEncrypt: true,
		},
		AuthPolicy: tpm2.TPM2BDigest{Buffer: s.tag},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
			Symmetric: tpm2.TPMTSymDefObject{Algorithm: tpm2.TPMAlgNull},
			Scheme:    tpm2.TPMTECCScheme{Scheme: tpm2.TPMAlgNull},
			CurveID:   tpm2.TPMECCNistP256,
			KDF:       tpm2.TPMTKDFScheme{Scheme: tpm2.TPMAlgNull},
		}),
		Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{}),
	}
}

// lookup reads the persistent signing key; found=false if the handle is empty.
func (s *TPMSigner) lookup(rwc transport.TPM) (name tpm2.TPM2BName, found bool, err error) {
	rp, err := tpm2.ReadPublic{ObjectHandle: s.handle}.Execute(rwc)
	if err != nil {
		return tpm2.TPM2BName{}, false, nil
	}
	pub, err := rp.OutPublic.Contents()
	if err != nil {
		return tpm2.TPM2BName{}, false, err
	}
	if string(pub.AuthPolicy.Buffer) != string(s.tag) || pub.Type != tpm2.TPMAlgECC {
		return tpm2.TPM2BName{}, false, fmt.Errorf("localhsm: persistent handle 0x%08X is in use by another object (choose a different signer name)", uint32(s.handle))
	}
	pt, err := pub.Unique.ECC()
	if err != nil {
		return tpm2.TPM2BName{}, false, err
	}
	s.pub = &ecdsa.PublicKey{Curve: elliptic.P256(),
		X: new(big.Int).SetBytes(pt.X.Buffer), Y: new(big.Int).SetBytes(pt.Y.Buffer)}
	return rp.Name, true, nil
}

func (s *TPMSigner) create(rwc transport.TPM) error {
	srk, err := tpm2.CreatePrimary{PrimaryHandle: tpm2.TPMRHOwner, InPublic: tpm2.New2B(tpm2.RSASRKTemplate)}.Execute(rwc)
	if err != nil {
		return fmt.Errorf("localhsm: CreatePrimary: %w", err)
	}
	defer flush(rwc, srk.ObjectHandle)
	parent := tpm2.NamedHandle{Handle: srk.ObjectHandle, Name: srk.Name}
	c, err := tpm2.Create{ParentHandle: parent, InPublic: tpm2.New2B(s.template())}.Execute(rwc)
	if err != nil {
		return fmt.Errorf("localhsm: Create: %w", err)
	}
	l, err := tpm2.Load{ParentHandle: parent, InPrivate: c.OutPrivate, InPublic: c.OutPublic}.Execute(rwc)
	if err != nil {
		return fmt.Errorf("localhsm: Load: %w", err)
	}
	defer flush(rwc, l.ObjectHandle)
	if _, err := (tpm2.EvictControl{Auth: tpm2.TPMRHOwner,
		ObjectHandle:     tpm2.NamedHandle{Handle: l.ObjectHandle, Name: l.Name},
		PersistentHandle: s.handle}).Execute(rwc); err != nil {
		return fmt.Errorf("localhsm: EvictControl (persist): %w", err)
	}
	return nil
}

// NewTPMSigner opens the TPM signing key called name, creating it on first use.
func NewTPMSigner(name string) (*TPMSigner, error) {
	if name == "" {
		return nil, errors.New("localhsm: empty signer name")
	}
	h := sha256.Sum256([]byte("sig-handle:" + name))
	tag := sha256.Sum256([]byte("localhsm-sig:" + name))
	s := &TPMSigner{name: name, tag: tag[:],
		handle: tpm2.TPMHandle(sigHandleBase | uint32(h[0])<<8 | uint32(h[1]))}
	rwc, err := openTPM()
	if err != nil {
		return nil, fmt.Errorf("localhsm: open TPM %s: %w (is the user in the 'tss' group?)", tpmDevice(), err)
	}
	defer rwc.Close()
	if _, ok, err := s.lookup(rwc); err != nil || ok {
		return s, err
	}
	if err := s.create(rwc); err != nil {
		return nil, err
	}
	if _, ok, err := s.lookup(rwc); err != nil || !ok {
		if err == nil {
			err = errors.New("localhsm: signing key not found after creation")
		}
		return nil, err
	}
	return s, nil
}

// Public returns the public key (*ecdsa.PublicKey).
func (s *TPMSigner) Public() crypto.PublicKey { return s.pub }

// Sign signs digest (32 or 48 bytes) with the TPM key and returns an ASN.1 DER ECDSA signature.
func (s *TPMSigner) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	var alg tpm2.TPMIAlgHash
	switch len(digest) {
	case 32:
		alg = tpm2.TPMAlgSHA256
	case 48:
		alg = tpm2.TPMAlgSHA384
	default:
		return nil, fmt.Errorf("localhsm: unsupported digest length %d (want 32 or 48)", len(digest))
	}
	rwc, err := openTPM()
	if err != nil {
		return nil, fmt.Errorf("localhsm: open TPM %s: %w", tpmDevice(), err)
	}
	defer rwc.Close()
	name, ok, err := s.lookup(rwc)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("localhsm: TPM signing key %q not found", s.name)
	}
	rsp, err := tpm2.Sign{
		KeyHandle: tpm2.NamedHandle{Handle: s.handle, Name: name},
		Digest:    tpm2.TPM2BDigest{Buffer: digest},
		InScheme: tpm2.TPMTSigScheme{Scheme: tpm2.TPMAlgECDSA,
			Details: tpm2.NewTPMUSigScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSchemeHash{HashAlg: alg})},
		Validation: tpm2.TPMTTKHashCheck{Tag: tpm2.TPMSTHashCheck, Hierarchy: tpm2.TPMRHNull},
	}.Execute(rwc)
	if err != nil {
		return nil, fmt.Errorf("localhsm: TPM Sign: %w", err)
	}
	sig, err := rsp.Signature.Signature.ECDSA()
	if err != nil {
		return nil, err
	}
	return ecdsaDER(new(big.Int).SetBytes(sig.SignatureR.Buffer), new(big.Int).SetBytes(sig.SignatureS.Buffer))
}

// Destroy deletes the TPM key (the certificate issued for it becomes useless).
func (s *TPMSigner) Destroy() error {
	rwc, err := openTPM()
	if err != nil {
		return err
	}
	defer rwc.Close()
	name, ok, err := s.lookup(rwc)
	if err != nil || !ok {
		return err // never evict a foreign object; nothing to do if absent
	}
	_, err = tpm2.EvictControl{Auth: tpm2.TPMRHOwner,
		ObjectHandle:     tpm2.NamedHandle{Handle: s.handle, Name: name},
		PersistentHandle: s.handle}.Execute(rwc)
	if err != nil {
		return fmt.Errorf("localhsm: EvictControl (delete): %w", err)
	}
	return nil
}
