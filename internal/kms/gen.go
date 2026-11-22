// Package kms is the key management core of the pqc-kms backend: an encrypted object store, the KMIP
// lifecycle state machine, per-object access control and key generation for classical and post-quantum
// algorithms. The KMIP and REST servers are thin front ends over this package.
//
// The server manages keys; it does not perform encryption, decryption or signing for clients. That is why
// key types without a bulk-cryptography use here (post-quantum signatures, KEMs, Edwards/Montgomery curves)
// can be created, stored, rotated and destroyed like any other key.
package kms

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"sort"
	"strings"

	"github.com/cloudflare/circl/dh/x448"
	kems "github.com/cloudflare/circl/kem/schemes"
	signs "github.com/cloudflare/circl/sign/schemes"
	"github.com/wpdlatm2/localhsm/kmip"
)

// KMIP Cryptographic Usage Mask bits.
const (
	UseSign        int32 = kmip.UsageSign
	UseVerify      int32 = kmip.UsageVerify
	UseEncrypt     int32 = kmip.UsageEncrypt
	UseDecrypt     int32 = kmip.UsageDecrypt
	UseWrap        int32 = kmip.UsageWrapKey
	UseUnwrap      int32 = kmip.UsageUnwrapKey
	UseExport      int32 = kmip.UsageExport
	UseMACGenerate int32 = kmip.UsageMACGenerate
	UseMACVerify   int32 = kmip.UsageMACVerify
	UseDerive      int32 = kmip.UsageDeriveKey
	UseAgreement   int32 = kmip.UsageKeyAgreement
	UseAuth        int32 = kmip.UsageAuthenticate
)

// Algo is one entry of the creation catalog.
type Algo struct {
	ID        string `json:"id"`
	Name      string `json:"name"`               // standard name, e.g. ML-DSA-65
	Family    string `json:"family"`             // AES, RSA, EC, EdDSA, ML-DSA, ...
	Category  string `json:"category"`           // symmetric, rsa, ec, pq-signature, pq-kem
	Type      string `json:"type"`               // symmetric | asymmetric
	Standard  string `json:"standard,omitempty"` // defining specification
	CurveName string `json:"curve,omitempty"`    // P-256, Ed25519, ...
	Label     string `json:"label"`              // display name
	Group     string `json:"group"`              // display group
	Pair      bool   `json:"pair"`               // creates a private/public key pair
	Bits      int    `json:"bits"`               // KMIP Cryptographic Length (0 = not applicable)
	Usage     int32  `json:"usage"`              // default usage mask
	Alg       uint32 `json:"-"`                  // KMIP Cryptographic Algorithm
	Curve     uint32 `json:"-"`                  // KMIP Recommended Curve (0 = none)
	PrivFmt   uint32 `json:"-"`                  // KMIP key format of the private / secret value
	PubFmt    uint32 `json:"-"`                  // KMIP key format of the public value
	gen       func() (priv, pub []byte, err error)
}

var catalog = map[string]*Algo{}

func reg(a *Algo) { catalog[a.ID] = a }

func randBytes(n int) func() ([]byte, []byte, error) {
	return func() ([]byte, []byte, error) {
		b := make([]byte, n)
		_, err := rand.Read(b)
		return b, nil, err
	}
}

func init() {
	// ---- symmetric
	for _, n := range []int{128, 192, 256} {
		reg(&Algo{ID: fmt.Sprintf("aes-%d", n), Label: fmt.Sprintf("AES-%d", n), Group: "대칭키", Bits: n, Usage: UseEncrypt | UseDecrypt,
			Alg: kmip.AlgAES, PrivFmt: kmip.FmtRaw, gen: randBytes(n / 8)})
		reg(&Algo{ID: fmt.Sprintf("aria-%d", n), Label: fmt.Sprintf("ARIA-%d", n), Group: "대칭키", Bits: n, Usage: UseEncrypt | UseDecrypt,
			Alg: kmip.AlgARIA, PrivFmt: kmip.FmtRaw, gen: randBytes(n / 8)})
	}
	reg(&Algo{ID: "seed-128", Label: "SEED-128", Group: "대칭키", Bits: 128, Usage: UseEncrypt | UseDecrypt, Alg: kmip.AlgSEED, PrivFmt: kmip.FmtRaw, gen: randBytes(16)})
	reg(&Algo{ID: "chacha20-256", Label: "ChaCha20-256", Group: "대칭키", Bits: 256, Usage: UseEncrypt | UseDecrypt, Alg: kmip.AlgChaCha20, PrivFmt: kmip.FmtRaw, gen: randBytes(32)})
	for _, h := range []struct {
		id    string
		alg   uint32
		bits  int
		label string
	}{{"hmac-sha256", kmip.AlgHMACSHA256, 256, "HMAC-SHA256"}, {"hmac-sha384", kmip.AlgHMACSHA384, 384, "HMAC-SHA384"}, {"hmac-sha512", kmip.AlgHMACSHA512, 512, "HMAC-SHA512"}} {
		reg(&Algo{ID: h.id, Label: h.label, Group: "대칭키", Bits: h.bits, Usage: UseMACGenerate | UseMACVerify, Alg: h.alg, PrivFmt: kmip.FmtRaw, gen: randBytes(h.bits / 8)})
	}

	// ---- RSA
	for _, n := range []int{2048, 3072, 4096} {
		n := n
		reg(&Algo{ID: fmt.Sprintf("rsa-%d", n), Label: fmt.Sprintf("RSA-%d", n), Group: "RSA", Pair: true, Bits: n,
			Usage: UseSign | UseVerify | UseEncrypt | UseDecrypt | UseWrap | UseUnwrap, Alg: kmip.AlgRSA, PrivFmt: kmip.FmtPKCS8, PubFmt: kmip.FmtX509,
			gen: func() ([]byte, []byte, error) {
				k, err := rsa.GenerateKey(rand.Reader, n)
				if err != nil {
					return nil, nil, err
				}
				return pkcs8(k, &k.PublicKey)
			}})
	}

	// ---- elliptic curves
	for _, c := range []struct {
		id, label string
		curve     elliptic.Curve
		kc        uint32
		bits      int
	}{{"ec-p224", "EC P-224", elliptic.P224(), kmip.CurveP224, 224}, {"ec-p256", "EC P-256", elliptic.P256(), kmip.CurveP256, 256},
		{"ec-p384", "EC P-384", elliptic.P384(), kmip.CurveP384, 384}, {"ec-p521", "EC P-521", elliptic.P521(), kmip.CurveP521, 521}} {
		c := c
		reg(&Algo{ID: c.id, Label: c.label, Group: "타원곡선", Pair: true, Bits: c.bits, Usage: UseSign | UseVerify | UseDerive | UseAgreement,
			Alg: kmip.AlgEC, Curve: c.kc, PrivFmt: kmip.FmtPKCS8, PubFmt: kmip.FmtX509,
			gen: func() ([]byte, []byte, error) {
				k, err := ecdsa.GenerateKey(c.curve, rand.Reader)
				if err != nil {
					return nil, nil, err
				}
				return pkcs8(k, &k.PublicKey)
			}})
	}
	reg(&Algo{ID: "ed25519", Label: "Ed25519", Group: "타원곡선", Pair: true, Bits: 256, Usage: UseSign | UseVerify, Alg: kmip.AlgEd25519, Curve: kmip.CurveEd25519,
		PrivFmt: kmip.FmtPKCS8, PubFmt: kmip.FmtX509, gen: func() ([]byte, []byte, error) {
			pub, priv, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				return nil, nil, err
			}
			return pkcs8(priv, pub)
		}})
	reg(&Algo{ID: "x25519", Label: "X25519", Group: "타원곡선", Pair: true, Bits: 256, Usage: UseDerive | UseAgreement, Alg: kmip.AlgEC, Curve: kmip.CurveX25519,
		PrivFmt: kmip.FmtPKCS8, PubFmt: kmip.FmtX509, gen: func() ([]byte, []byte, error) {
			k, err := ecdh.X25519().GenerateKey(rand.Reader)
			if err != nil {
				return nil, nil, err
			}
			return pkcs8(k, k.PublicKey())
		}})
	reg(&Algo{ID: "ed448", Label: "Ed448", Group: "타원곡선", Pair: true, Bits: 448, Usage: UseSign | UseVerify, Alg: kmip.AlgEd448, Curve: kmip.CurveEd448,
		PrivFmt: kmip.FmtRaw, PubFmt: kmip.FmtRaw, gen: signGen("Ed448")})
	reg(&Algo{ID: "x448", Label: "X448", Group: "타원곡선", Pair: true, Bits: 448, Usage: UseDerive | UseAgreement, Alg: kmip.AlgEC, Curve: kmip.CurveX448,
		PrivFmt: kmip.FmtRaw, PubFmt: kmip.FmtRaw, gen: func() ([]byte, []byte, error) {
			var priv, pub x448.Key
			if _, err := rand.Read(priv[:]); err != nil {
				return nil, nil, err
			}
			x448.KeyGen(&pub, &priv)
			return append([]byte(nil), priv[:]...), append([]byte(nil), pub[:]...), nil
		}})

	// ---- post-quantum signatures
	for i, p := range []string{"44", "65", "87"} {
		reg(&Algo{ID: "ml-dsa-" + p, Label: "ML-DSA-" + p + " (FIPS 204)", Group: "PQC 서명", Pair: true, Usage: UseSign | UseVerify,
			Alg: kmip.AlgMLDSA44 + uint32(i), PrivFmt: kmip.FmtRaw, PubFmt: kmip.FmtRaw, gen: signGen("ML-DSA-" + p)})
	}
	slh := []string{"sha2-128s", "sha2-128f", "sha2-192s", "sha2-192f", "sha2-256s", "sha2-256f", "shake-128s", "shake-128f", "shake-192s", "shake-192f", "shake-256s", "shake-256f"}
	for i, v := range slh {
		reg(&Algo{ID: "slh-dsa-" + v, Label: "SLH-DSA-" + strings.ToUpper(v[:strings.Index(v, "-")]) + v[strings.Index(v, "-"):] + " (FIPS 205)", Group: "PQC 서명", Pair: true, Usage: UseSign | UseVerify,
			Alg: kmip.AlgSLHDSASHA2128s + uint32(i), PrivFmt: kmip.FmtRaw, PubFmt: kmip.FmtRaw, gen: signGen("SLH-DSA-" + strings.ToUpper(v))})
	}

	// ---- post-quantum / hybrid key encapsulation
	for i, p := range []string{"512", "768", "1024"} {
		reg(&Algo{ID: "ml-kem-" + p, Label: "ML-KEM-" + p + " (FIPS 203)", Group: "PQC KEM", Pair: true, Usage: UseEncrypt | UseDecrypt,
			Alg: kmip.AlgMLKEM512 + uint32(i), PrivFmt: kmip.FmtRaw, PubFmt: kmip.FmtRaw, gen: kemGen("ML-KEM-" + p)})
	}
	reg(&Algo{ID: "x25519-ml-kem-768", Label: "X25519MLKEM768 (하이브리드)", Group: "PQC KEM", Pair: true, Usage: UseEncrypt | UseDecrypt,
		Alg: kmip.AlgX25519MLKEM768, PrivFmt: kmip.FmtRaw, PubFmt: kmip.FmtRaw, gen: kemGen("X25519MLKEM768")})
	reg(&Algo{ID: "x-wing", Label: "X-Wing (X25519+ML-KEM-768 하이브리드)", Group: "PQC KEM", Pair: true, Usage: UseEncrypt | UseDecrypt,
		Alg: kmip.AlgXWing, PrivFmt: kmip.FmtRaw, PubFmt: kmip.FmtRaw, gen: kemGen("X-Wing")})
}

// enrich fills the descriptive fields (names as the standards write them, not KMIP enumerations).
func enrich() {
	for id, a := range catalog {
		a.Name = strings.TrimSpace(strings.SplitN(a.Label, "(", 2)[0])
		if a.Pair {
			a.Type = "asymmetric"
		} else {
			a.Type = "symmetric"
		}
		switch {
		case strings.HasPrefix(id, "aes-"):
			a.Family, a.Category, a.Standard = "AES", "symmetric", "FIPS 197"
		case strings.HasPrefix(id, "aria-"):
			a.Family, a.Category, a.Standard = "ARIA", "symmetric", "RFC 5794"
		case id == "seed-128":
			a.Family, a.Category, a.Standard = "SEED", "symmetric", "RFC 4269"
		case id == "chacha20-256":
			a.Family, a.Category, a.Standard = "ChaCha20", "symmetric", "RFC 8439"
		case strings.HasPrefix(id, "hmac-"):
			a.Family, a.Category, a.Standard = "HMAC", "symmetric", "FIPS 198-1"
		case strings.HasPrefix(id, "rsa-"):
			a.Family, a.Category, a.Standard = "RSA", "rsa", "RFC 8017"
		case strings.HasPrefix(id, "ec-p"):
			a.Family, a.Category, a.Standard, a.CurveName = "EC", "ec", "FIPS 186-5", "P-"+strings.TrimPrefix(id, "ec-p")
			a.Name = "EC " + a.CurveName
		case id == "ed25519":
			a.Family, a.Category, a.Standard, a.CurveName = "EdDSA", "ec", "RFC 8032", "Ed25519"
		case id == "ed448":
			a.Family, a.Category, a.Standard, a.CurveName = "EdDSA", "ec", "RFC 8032", "Ed448"
		case id == "x25519":
			a.Family, a.Category, a.Standard, a.CurveName = "XDH", "ec", "RFC 7748", "X25519"
		case id == "x448":
			a.Family, a.Category, a.Standard, a.CurveName = "XDH", "ec", "RFC 7748", "X448"
		case strings.HasPrefix(id, "ml-dsa-"):
			a.Family, a.Category, a.Standard = "ML-DSA", "pq-signature", "FIPS 204"
		case strings.HasPrefix(id, "slh-dsa-"):
			a.Family, a.Category, a.Standard = "SLH-DSA", "pq-signature", "FIPS 205"
		case strings.HasPrefix(id, "ml-kem-"):
			a.Family, a.Category, a.Standard = "ML-KEM", "pq-kem", "FIPS 203"
		case id == "x25519-ml-kem-768":
			a.Family, a.Category, a.Standard, a.Name = "X25519MLKEM768", "pq-kem", "IETF draft-ietf-tls-ecdhe-mlkem", "X25519MLKEM768"
		case id == "x-wing":
			a.Family, a.Category, a.Standard, a.Name = "X-Wing", "pq-kem", "IETF draft-connolly-cfrg-xwing-kem", "X-Wing"
		}
	}
}

func init() { enrich() }

func pkcs8(priv any, pub any) ([]byte, []byte, error) {
	p, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	q, err := x509.MarshalPKIXPublicKey(pub)
	return p, q, err
}

func signGen(name string) func() ([]byte, []byte, error) {
	return func() ([]byte, []byte, error) {
		s := signs.ByName(name)
		if s == nil {
			return nil, nil, fmt.Errorf("signature scheme %s is not available", name)
		}
		pub, priv, err := s.GenerateKey()
		if err != nil {
			return nil, nil, err
		}
		pb, err := priv.MarshalBinary()
		if err != nil {
			return nil, nil, err
		}
		qb, err := pub.MarshalBinary()
		return pb, qb, err
	}
}

func kemGen(name string) func() ([]byte, []byte, error) {
	return func() ([]byte, []byte, error) {
		s := kems.ByName(name)
		if s == nil {
			return nil, nil, fmt.Errorf("KEM %s is not available", name)
		}
		pub, priv, err := s.GenerateKeyPair()
		if err != nil {
			return nil, nil, err
		}
		pb, err := priv.MarshalBinary()
		if err != nil {
			return nil, nil, err
		}
		qb, err := pub.MarshalBinary()
		return pb, qb, err
	}
}

// Catalog lists the algorithms a client may create, grouped and sorted for display.
func Catalog() []*Algo {
	out := make([]*Algo, 0, len(catalog))
	for _, a := range catalog {
		out = append(out, a)
	}
	order := map[string]int{"대칭키": 0, "RSA": 1, "타원곡선": 2, "PQC 서명": 3, "PQC KEM": 4}
	sort.Slice(out, func(i, j int) bool {
		if order[out[i].Group] != order[out[j].Group] {
			return order[out[i].Group] < order[out[j].Group]
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// LookupAlgo returns a catalog entry by id.
func LookupAlgo(id string) *Algo { return catalog[id] }

// FindAlgo maps KMIP creation attributes (algorithm, length, curve) to a catalog entry.
func FindAlgo(alg uint32, bits int, curve uint32, pair bool) *Algo {
	if alg == kmip.AlgECDSA || alg == kmip.AlgECDH || alg == kmip.AlgECMQV {
		alg = kmip.AlgEC // the curve, not the algorithm name, selects the key type
	}
	for _, a := range catalog {
		if a.Pair != pair || a.Alg != alg {
			continue
		}
		switch {
		case a.Curve != 0: // elliptic curves: the curve decides (Ed25519/Ed448 are implied by the algorithm)
			if curve != a.Curve && !(curve == 0 && (a.Alg == kmip.AlgEd25519 || a.Alg == kmip.AlgEd448)) {
				continue
			}
		case curve != 0:
			continue
		case a.Bits != 0 && a.Bits != bits: // symmetric and RSA need the exact length
			continue
		}
		return a
	}
	return nil
}

var usageNames = []struct {
	name string
	bit  int32
}{
	{"encrypt", UseEncrypt}, {"decrypt", UseDecrypt}, {"sign", UseSign}, {"verify", UseVerify}, {"wrap", UseWrap}, {"unwrap", UseUnwrap},
	{"mac-generate", UseMACGenerate}, {"mac-verify", UseMACVerify}, {"derive", UseDerive}, {"key-agreement", UseAgreement},
	{"authenticate", UseAuth}, {"export", UseExport},
}

// UsageNames lists the names of the bits set in a usage mask.
func UsageNames(mask int32) []string {
	out := []string{}
	for _, u := range usageNames {
		if mask&u.bit != 0 {
			out = append(out, u.name)
		}
	}
	return out
}

// UsageList lists every usage name (for forms).
func UsageList() []string {
	out := make([]string, 0, len(usageNames))
	for _, u := range usageNames {
		out = append(out, u.name)
	}
	return out
}

// ParseUsage converts usage names to a mask.
func ParseUsage(names []string) (int32, error) {
	var m int32
	for _, n := range names {
		found := false
		for _, u := range usageNames {
			if u.name == n {
				m |= u.bit
				found = true
			}
		}
		if !found {
			return 0, fmt.Errorf("unknown usage %q", n)
		}
	}
	return m, nil
}
