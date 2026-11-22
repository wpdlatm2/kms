//go:build linux

package localhsm

// Linux TPM 2.0 backend (kernel resource manager /dev/tpmrm0).
//
// The wrapping key is an RSA-2048 decrypt-only key created under the owner-hierarchy SRK and made
// persistent at a handle derived from the key name (range 0x8109xxxx). It is fixedTPM/fixedParent, so
// it cannot be exported or duplicated. Ownership is tagged in the key's AuthPolicy field
// (sha256("localhsm:"+name)); a persistent handle holding anything else is never touched.
//
// Wrapping is done in software with the public key (OAEP-SHA256); only unwrap needs the TPM.
// The process user needs access to the device (group "tss" or root). Override the device with
// LOCALHSM_TPM_DEVICE.

import (
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
)

const handleBase = 0x81090000 // LocalHSM persistent range 0x81090000-0x8109FFFF

func tpmDevice() string {
	if d := os.Getenv("LOCALHSM_TPM_DEVICE"); d != "" {
		return d
	}
	return "/dev/tpmrm0"
}

func openTPM() (transport.TPMCloser, error) { return linuxtpm.Open(tpmDevice()) }

// TPMAvailable reports whether the TPM resource-manager device can be opened by this process.
func TPMAvailable() bool {
	t, err := openTPM()
	if err != nil {
		return false
	}
	t.Close()
	return true
}

type tpmProtector struct {
	keyName string
	handle  tpm2.TPMHandle
	tag     []byte
}

// NewTPMProtector returns a protector backed by a non-exportable RSA-2048 key in the TPM.
func NewTPMProtector(keyName string) (Protector, error) {
	if keyName == "" {
		return nil, errors.New("localhsm: empty TPM key name")
	}
	h := sha256.Sum256([]byte("handle:" + keyName))
	tag := sha256.Sum256([]byte("localhsm:" + keyName))
	return &tpmProtector{keyName, tpm2.TPMHandle(handleBase | uint32(h[0])<<8 | uint32(h[1])), tag[:]}, nil
}

func (t *tpmProtector) Name() string         { return "tpm-ncrypt" } // same name as Windows: keystores are portable
func (t *tpmProtector) HardwareBacked() bool { return true }

func (t *tpmProtector) template() tpm2.TPMTPublic {
	return tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM: true, FixedParent: true, SensitiveDataOrigin: true,
			UserWithAuth: true, NoDA: true, Decrypt: true,
		},
		AuthPolicy: tpm2.TPM2BDigest{Buffer: t.tag},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgRSA, &tpm2.TPMSRSAParms{
			Symmetric: tpm2.TPMTSymDefObject{Algorithm: tpm2.TPMAlgNull},
			Scheme:    tpm2.TPMTRSAScheme{Scheme: tpm2.TPMAlgNull},
			KeyBits:   2048,
		}),
		Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgRSA, &tpm2.TPM2BPublicKeyRSA{Buffer: make([]byte, 256)}),
	}
}

type loadedKey struct {
	pub  *rsa.PublicKey
	name tpm2.TPM2BName
}

// lookup reads the persistent key. found=false if the handle is empty; error if it holds a foreign object.
func (t *tpmProtector) lookup(rwc transport.TPM) (k loadedKey, found bool, err error) {
	rp, err := tpm2.ReadPublic{ObjectHandle: t.handle}.Execute(rwc)
	if err != nil {
		return loadedKey{}, false, nil // empty handle (a real TPM fault surfaces on the next command)
	}
	pub, err := rp.OutPublic.Contents()
	if err != nil {
		return loadedKey{}, false, err
	}
	if string(pub.AuthPolicy.Buffer) != string(t.tag) || pub.Type != tpm2.TPMAlgRSA {
		return loadedKey{}, false, fmt.Errorf("localhsm: persistent handle 0x%08X is in use by another object "+
			"(choose a different key name)", uint32(t.handle))
	}
	parms, err := pub.Parameters.RSADetail()
	if err != nil {
		return loadedKey{}, false, err
	}
	n, err := pub.Unique.RSA()
	if err != nil {
		return loadedKey{}, false, err
	}
	rk, err := tpm2.RSAPub(parms, n)
	if err != nil {
		return loadedKey{}, false, err
	}
	return loadedKey{rk, rp.Name}, true, nil
}

func flush(rwc transport.TPM, h tpm2.TPMHandle) {
	tpm2.FlushContext{FlushHandle: h}.Execute(rwc)
}

func (t *tpmProtector) create(rwc transport.TPM) error {
	srk, err := tpm2.CreatePrimary{PrimaryHandle: tpm2.TPMRHOwner,
		InPublic: tpm2.New2B(tpm2.RSASRKTemplate)}.Execute(rwc)
	if err != nil {
		return fmt.Errorf("localhsm: CreatePrimary: %w", err)
	}
	defer flush(rwc, srk.ObjectHandle)
	parent := tpm2.NamedHandle{Handle: srk.ObjectHandle, Name: srk.Name}

	c, err := tpm2.Create{ParentHandle: parent, InPublic: tpm2.New2B(t.template())}.Execute(rwc)
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
		PersistentHandle: t.handle}).Execute(rwc); err != nil {
		return fmt.Errorf("localhsm: EvictControl (persist): %w", err)
	}
	return nil
}

func (t *tpmProtector) ensure(rwc transport.TPM) (loadedKey, error) {
	if k, ok, err := t.lookup(rwc); err != nil || ok {
		return k, err
	}
	if err := t.create(rwc); err != nil {
		return loadedKey{}, err
	}
	k, ok, err := t.lookup(rwc)
	if err == nil && !ok {
		err = errors.New("localhsm: key not found after creation")
	}
	return k, err
}

func (t *tpmProtector) Recipient() (string, *rsa.PublicKey, error) {
	rwc, err := openTPM()
	if err != nil {
		return "", nil, fmt.Errorf("localhsm: open TPM %s: %w (is the user in the 'tss' group?)", tpmDevice(), err)
	}
	defer rwc.Close()
	k, err := t.ensure(rwc)
	if err != nil {
		return "", nil, err
	}
	id, err := fingerprint(k.pub)
	return id, k.pub, err
}

func (t *tpmProtector) Wrap(secret []byte) ([]byte, error) {
	if len(secret) == 0 {
		return nil, errors.New("localhsm: empty secret")
	}
	_, pub, err := t.Recipient()
	if err != nil {
		return nil, err
	}
	return WrapForPublicKey(pub, secret)
}

func (t *tpmProtector) Unwrap(blob []byte) ([]byte, error) {
	if len(blob) < 3 || blob[0] != 1 || blob[1] != 1 {
		return nil, errors.New("localhsm: bad TPM blob header (only OAEP-SHA256 supported on Linux)")
	}
	rwc, err := openTPM()
	if err != nil {
		return nil, fmt.Errorf("localhsm: open TPM %s: %w (is the user in the 'tss' group?)", tpmDevice(), err)
	}
	defer rwc.Close()
	k, ok, err := t.lookup(rwc)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("localhsm: TPM key %q not found (different machine / TPM cleared?)", t.keyName)
	}
	dec, err := tpm2.RSADecrypt{
		KeyHandle:  tpm2.NamedHandle{Handle: t.handle, Name: k.name},
		CipherText: tpm2.TPM2BPublicKeyRSA{Buffer: blob[2:]},
		InScheme: tpm2.TPMTRSADecrypt{Scheme: tpm2.TPMAlgOAEP,
			Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgOAEP, &tpm2.TPMSEncSchemeOAEP{HashAlg: tpm2.TPMAlgSHA256})},
	}.Execute(rwc)
	if err != nil {
		return nil, fmt.Errorf("localhsm: TPM RSADecrypt: %w", err)
	}
	return dec.Message.Buffer, nil
}

func (t *tpmProtector) Destroy() error {
	rwc, err := openTPM()
	if err != nil {
		return err
	}
	defer rwc.Close()
	k, ok, err := t.lookup(rwc)
	if err != nil || !ok {
		return err // never evict a foreign object; nothing to do if absent
	}
	_, err = tpm2.EvictControl{Auth: tpm2.TPMRHOwner,
		ObjectHandle:     tpm2.NamedHandle{Handle: t.handle, Name: k.name},
		PersistentHandle: t.handle}.Execute(rwc)
	if err != nil {
		return fmt.Errorf("localhsm: EvictControl (delete): %w", err)
	}
	return nil
}

// NewDPAPIProtector: Windows only. On Linux use a TPM or a recovery-key protector.
func NewDPAPIProtector(keyName string) (Protector, error) { return nil, ErrUnsupported }
