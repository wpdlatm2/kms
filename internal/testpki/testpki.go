// Package testpki builds throw-away PKIs for tests: a CA, a server certificate and client certificates.
package testpki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"
)

type PKI struct {
	t      testing.TB
	ca     *x509.Certificate
	caKey  *ecdsa.PrivateKey
	Pool   *x509.CertPool
	CAPEM  []byte
	Server tls.Certificate
	serial int64
}

func New(t testing.TB) *PKI {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test ca"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(der)
	p := &PKI{t: t, ca: ca, caKey: k, Pool: x509.NewCertPool(), serial: 1, CAPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
	p.Pool.AddCert(ca)
	p.Server = p.leaf("localhost", x509.ExtKeyUsageServerAuth)
	return p
}

func (p *PKI) leaf(cn string, eku x509.ExtKeyUsage) tls.Certificate {
	p.serial++
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(p.serial), Subject: pkix.Name{CommonName: cn}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(24 * time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{eku}, KeyUsage: x509.KeyUsageDigitalSignature,
		DNSNames: []string{"localhost", "kms"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, p.ca, &k.PublicKey, p.caKey)
	if err != nil {
		p.t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
}

// ServerTLS requires and verifies client certificates issued by this PKI.
func (p *PKI) ServerTLS() *tls.Config {
	return &tls.Config{Certificates: []tls.Certificate{p.Server}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: p.Pool, MinVersion: tls.VersionTLS12}
}

// ClientTLS returns a client configuration presenting a fresh certificate whose CN is cn.
func (p *PKI) ClientTLS(cn string) *tls.Config {
	return &tls.Config{Certificates: []tls.Certificate{p.leaf(cn, x509.ExtKeyUsageClientAuth)}, RootCAs: p.Pool, ServerName: "localhost", MinVersion: tls.VersionTLS12}
}

// NoCertTLS is a client configuration without a client certificate.
func (p *PKI) NoCertTLS() *tls.Config {
	return &tls.Config{RootCAs: p.Pool, ServerName: "localhost", MinVersion: tls.VersionTLS12}
}
