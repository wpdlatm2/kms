package localhsm

// Credentials a node uses to authenticate to an external KMS (enterprise mode).
//
//   - PKI client certificate (mTLS): the private key is a TPM-resident, non-exportable ECDSA P-256
//     key (TPMSigner). It never leaves the TPM; the TLS stack asks the TPM to sign each handshake.
//     NewKMSTLSConfig builds the tls.Config; CreateCSR makes the certificate request.
//   - API key / token / password: these must be presented to the KMS in clear, so the TPM can only
//     protect them at rest. SecretStore keeps them in a node-local file wrapped by a TPM-bound key.
//
// Keep these credentials on the node that talks to the KMS (the cluster's writer node), not in the
// shared keystore: reader nodes never contact the KMS and need none.

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
)

// ecdsaDER encodes an ECDSA signature as ASN.1 DER (what crypto.Signer implementations return).
func ecdsaDER(r, s *big.Int) ([]byte, error) {
	return asn1.Marshal(struct{ R, S *big.Int }{r, s})
}

// CreateCSR builds a PKCS#10 certificate request signed by signer (e.g. a TPMSigner), as PEM.
func CreateCSR(signer crypto.Signer, subject pkix.Name, dnsNames []string) ([]byte, error) {
	der, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: subject, DNSNames: dnsNames}, signer)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

// KMSTLSOptions describes the TLS client identity and the KMS server to trust.
type KMSTLSOptions struct {
	Signer       crypto.Signer // TPM-backed key (TPMSigner)
	CertChainPEM []byte        // client certificate (leaf first) issued for Signer's public key
	ServerCAPEM  []byte        // CA(s) that issued the KMS server certificate (empty = system roots)
	ServerName   string        // expected KMS host name
	PinSHA256    []byte        // optional: SHA-256 of the KMS leaf SubjectPublicKeyInfo (public key pin)
}

// NewKMSTLSConfig returns a tls.Config for mutual TLS to the KMS. It refuses a certificate that does
// not belong to the signer's key, and (if PinSHA256 is set) a KMS whose public key does not match
// in addition to the normal chain verification.
func NewKMSTLSConfig(o KMSTLSOptions) (*tls.Config, error) {
	if o.Signer == nil {
		return nil, errors.New("localhsm: no signer")
	}
	var chain [][]byte
	rest := o.CertChainPEM
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type == "CERTIFICATE" {
			chain = append(chain, b.Bytes)
		}
	}
	if len(chain) == 0 {
		return nil, errors.New("localhsm: no certificate in CertChainPEM")
	}
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		return nil, fmt.Errorf("localhsm: bad client certificate: %w", err)
	}
	want, _ := x509.MarshalPKIXPublicKey(o.Signer.Public())
	have, _ := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if string(want) != string(have) {
		return nil, errors.New("localhsm: the client certificate was not issued for the signer's key")
	}
	cfg := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		ServerName:   o.ServerName,
		Certificates: []tls.Certificate{{Certificate: chain, PrivateKey: o.Signer, Leaf: leaf}},
	}
	if len(o.ServerCAPEM) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(o.ServerCAPEM) {
			return nil, errors.New("localhsm: no certificate in ServerCAPEM")
		}
		cfg.RootCAs = pool
	}
	if len(o.PinSHA256) > 0 {
		pin := append([]byte(nil), o.PinSHA256...)
		cfg.VerifyPeerCertificate = func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return errors.New("localhsm: KMS sent no certificate")
			}
			c, err := x509.ParseCertificate(raw[0])
			if err != nil {
				return err
			}
			sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
			if string(sum[:]) != string(pin) {
				return errors.New("localhsm: KMS public key does not match the pin")
			}
			return nil
		}
	}
	return cfg, nil
}
