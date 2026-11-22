package admin

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" // #nosec G505 -- HMAC-SHA1 is the RFC 6238 default that every authenticator app supports; HMAC does not need collision resistance
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"time"

	qrcode "github.com/skip2/go-qrcode"
)

// Time-based one-time passwords (RFC 6238) with the parameters every authenticator app understands:
// HMAC-SHA1, 6 digits, 30 second steps. Google Authenticator, Microsoft Authenticator, 2FAS, Aegis, FreeOTP,
// Authy and password managers (Bitwarden, 1Password, ...) on Android and iOS all accept the QR code.
const (
	otpDigits = 6
	otpPeriod = 30
	otpSkew   = 1 // accept the previous and the next step (clock drift)
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// newOTPSecret returns a random 160-bit secret in base32.
func newOTPSecret() (string, error) {
	raw := make([]byte, 20)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return b32.EncodeToString(raw), nil
}

// hotp is RFC 4226 with SHA-1.
func hotp(secret []byte, counter uint64, digits int) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	m := hmac.New(sha1.New, secret)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	code := (uint32(sum[off]&0x7f) << 24) | uint32(sum[off+1])<<16 | uint32(sum[off+2])<<8 | uint32(sum[off+3])
	mod := uint32(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, code%mod)
}

func decodeSecret(b32secret string) ([]byte, error) {
	return b32.DecodeString(strings.ToUpper(strings.ReplaceAll(b32secret, " ", "")))
}

// totpStep is the time step of t.
func totpStep(t time.Time) int64 { return t.Unix() / otpPeriod }

// matchTOTP checks a code against the steps around now. It returns the matched step (0 if none). The code
// comparison is constant time for every candidate step.
func matchTOTP(secret []byte, code string, now time.Time) int64 {
	code = strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	if len(code) != otpDigits {
		return 0
	}
	var hit int64
	cur := totpStep(now)
	for d := int64(-otpSkew); d <= otpSkew; d++ {
		step := cur + d
		if step <= 0 {
			continue
		}
		want := hotp(secret, uint64(step), otpDigits)
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			hit = step
		}
	}
	return hit
}

// otpauthURI is the provisioning URI encoded in the QR code (the "Key URI Format" of Google Authenticator).
func otpauthURI(issuer, account, secret string) string {
	v := url.Values{}
	v.Set("secret", secret)
	v.Set("issuer", issuer)
	v.Set("algorithm", "SHA1")
	v.Set("digits", fmt.Sprint(otpDigits))
	v.Set("period", fmt.Sprint(otpPeriod))
	return "otpauth://totp/" + url.PathEscape(issuer) + ":" + url.PathEscape(account) + "?" + v.Encode()
}

// qrPNG renders the URI as a PNG QR code.
func qrPNG(uri string) ([]byte, error) { return qrcode.Encode(uri, qrcode.Medium, 280) }

// groupSecret formats a secret in blocks of four for manual entry.
func groupSecret(s string) string {
	var out []string
	for i := 0; i < len(s); i += 4 {
		j := i + 4
		if j > len(s) {
			j = len(s)
		}
		out = append(out, s[i:j])
	}
	return strings.Join(out, " ")
}

// ---- recovery codes (single use, for a lost phone)

const recoveryAlphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789" // no 0/O/1/I/L

func newRecoveryCodes(n int) (plain, hashed []string, err error) {
	for i := 0; i < n; i++ {
		b := make([]byte, 10)
		if _, err := rand.Read(b); err != nil {
			return nil, nil, err
		}
		var sb strings.Builder
		for j, x := range b {
			if j == 5 {
				sb.WriteByte('-')
			}
			sb.WriteByte(recoveryAlphabet[int(x)%len(recoveryAlphabet)])
		}
		plain = append(plain, sb.String())
		hashed = append(hashed, hashRecovery(sb.String()))
	}
	return plain, hashed, nil
}

func normRecovery(s string) string {
	return strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(strings.TrimSpace(s)))
}

func hashRecovery(code string) string {
	sum := sha256.Sum256([]byte("pqc-kms recovery:" + normRecovery(code)))
	return hex.EncodeToString(sum[:])
}
