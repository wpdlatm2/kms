package admin

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// RFC 6238 appendix B, SHA-1, secret "12345678901234567890" (8-digit reference values; we use the last 6).
func TestTOTPReferenceVectors(t *testing.T) {
	secret := []byte("12345678901234567890")
	for _, v := range []struct {
		unix int64
		full string
	}{{59, "94287082"}, {1111111109, "07081804"}, {1111111111, "14050471"}, {1234567890, "89005924"}, {2000000000, "69279037"}, {20000000000, "65353130"}} {
		if got := hotp(secret, uint64(v.unix/30), 8); got != v.full {
			t.Fatalf("T=%d: %s, want %s", v.unix, got, v.full)
		}
		six := v.full[2:]
		if got := hotp(secret, uint64(v.unix/30), 6); got != six {
			t.Fatalf("T=%d: 6 digits %s, want %s", v.unix, got, six)
		}
		if matchTOTP(secret, six, time.Unix(v.unix, 0)) != v.unix/30 {
			t.Fatalf("T=%d: the code was not accepted at its own time", v.unix)
		}
	}
	// RFC 4226 appendix D (HOTP counters 0..3)
	for i, want := range []string{"755224", "287082", "359152", "969429"} {
		if got := hotp(secret, uint64(i), 6); got != want {
			t.Fatalf("HOTP %d: %s, want %s", i, got, want)
		}
	}
}

func TestTOTPWindowAndFormat(t *testing.T) {
	secret := []byte("12345678901234567890")
	now := time.Unix(1111111109, 0)
	code := hotp(secret, uint64(totpStep(now)), 6)
	if matchTOTP(secret, code[:3]+" "+code[3:], now) == 0 {
		t.Fatal("a code typed with a space was refused")
	}
	if matchTOTP(secret, code, now.Add(-30*time.Second)) == 0 || matchTOTP(secret, code, now.Add(30*time.Second)) == 0 {
		t.Fatal("one step of clock drift must be tolerated")
	}
	if matchTOTP(secret, code, now.Add(90*time.Second)) != 0 || matchTOTP(secret, code, now.Add(-90*time.Second)) != 0 {
		t.Fatal("a code outside the window was accepted")
	}
	for _, bad := range []string{"", "12345", "1234567", "abcdef", "000000"} {
		if bad != "000000" && matchTOTP(secret, bad, now) != 0 {
			t.Fatalf("%q accepted", bad)
		}
	}
}

func TestProvisioningURIAndQR(t *testing.T) {
	uri := otpauthURI("pqc-kms", "alice@example.com", "JBSWY3DPEHPK3PXP")
	u, err := url.Parse(uri)
	if err != nil || u.Scheme != "otpauth" || u.Host != "totp" {
		t.Fatalf("uri %q: %v", uri, err)
	}
	q := u.Query()
	if q.Get("secret") != "JBSWY3DPEHPK3PXP" || q.Get("issuer") != "pqc-kms" || q.Get("algorithm") != "SHA1" || q.Get("digits") != "6" || q.Get("period") != "30" {
		t.Fatalf("parameters %v", q)
	}
	if !strings.Contains(u.Path, "pqc-kms:alice@example.com") {
		t.Fatalf("label %q", u.Path)
	}
	png, err := qrPNG(uri)
	if err != nil || !bytes.HasPrefix(png, []byte("\x89PNG\r\n\x1a\n")) || len(png) < 500 {
		t.Fatalf("QR png: %d bytes %v", len(png), err)
	}
	if groupSecret("ABCDEFGHIJ") != "ABCD EFGH IJ" {
		t.Fatal("secret grouping")
	}
	sec, _ := newOTPSecret()
	if raw, err := decodeSecret(sec); err != nil || len(raw) != 20 {
		t.Fatalf("secret %q: %v", sec, err)
	}
	// a secret typed with spaces and lower case (manual entry) decodes to the same key
	if a, _ := decodeSecret(groupSecret(sec)); !bytes.Equal(a, mustDecode(t, sec)) {
		t.Fatal("grouped secret decodes differently")
	}
}

func mustDecode(t *testing.T, s string) []byte {
	b, err := decodeSecret(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestUserOTPReplayAndRecoveryCodes(t *testing.T) {
	u, _ := LoadUsers(filepath.Join(t.TempDir(), "u.json"))
	if err := u.Set("ann", pw); err != nil {
		t.Fatal(err)
	}
	sec, _ := newOTPSecret()
	raw := mustDecode(t, sec)
	plain, hashed, _ := newRecoveryCodes(10)
	now := time.Now()
	step := totpStep(now)
	if err := u.EnableOTP("ann", sec, step, hashed); err != nil {
		t.Fatal(err)
	}
	if !u.HasOTP("ann") || u.RecoveryLeft("ann") != 10 {
		t.Fatal("state")
	}
	// the code used to confirm the enrollment cannot be replayed
	if ok, _ := u.VerifyOTP("ann", hotp(raw, uint64(step), 6), now); ok {
		t.Fatal("the enrollment code was accepted again")
	}
	next := now.Add(30 * time.Second)
	code := hotp(raw, uint64(totpStep(next)), 6)
	if ok, rec := u.VerifyOTP("ann", code, next); !ok || rec {
		t.Fatal("a fresh code was refused")
	}
	if ok, _ := u.VerifyOTP("ann", code, next); ok {
		t.Fatal("a code was accepted twice")
	}
	// recovery codes: each works once, in any spelling
	c := plain[0]
	if len(c) != 11 || c[5] != '-' {
		t.Fatalf("recovery code format %q", c)
	}
	if ok, rec := u.VerifyOTP("ann", strings.ToLower(strings.ReplaceAll(c, "-", " ")), next); !ok || !rec {
		t.Fatal("recovery code refused")
	}
	if ok, _ := u.VerifyOTP("ann", c, next); ok {
		t.Fatal("recovery code accepted twice")
	}
	if u.RecoveryLeft("ann") != 9 {
		t.Fatal("recovery code not consumed")
	}
	if ok, _ := u.VerifyOTP("ann", "ZZZZZ-ZZZZZ", next); ok {
		t.Fatal("a made-up recovery code was accepted")
	}
	// the state survives a reload, and a password change keeps the second factor
	u2, _ := LoadUsers(u.path)
	if !u2.HasOTP("ann") || u2.RecoveryLeft("ann") != 9 {
		t.Fatal("not persisted")
	}
	if err := u2.Set("ann", "another-long-password"); err != nil || !u2.HasOTP("ann") {
		t.Fatal("password change dropped the OTP")
	}
	// the file never contains the recovery codes themselves
	b, _ := os.ReadFile(u.path)
	if strings.Contains(string(b), strings.ReplaceAll(plain[1], "-", "")) {
		t.Fatal("recovery codes stored in clear")
	}
	if err := u2.ResetOTP("ann"); err != nil || u2.HasOTP("ann") {
		t.Fatal("reset")
	}
}

func TestOTPEnrollmentAndLoginFlow(t *testing.T) {
	s := newStackOpts(t, map[string]string{"alice": pw, "bob": pw}, Options{OTP: "required", Issuer: "pqc-kms-test"})
	c := s.web()

	// 1. password only: the session may do nothing but enroll
	code, raw := c.call("POST", "/api/login", map[string]string{"user": "alice", "password": pw}, false)
	var lr map[string]any
	json.Unmarshal(raw, &lr)
	if code != 200 || lr["enrollRequired"] != true {
		t.Fatalf("first login: %d %s", code, raw)
	}
	c.csrf = lr["csrf"].(string)
	c.must(403, "GET", "/api/keys", nil)
	c.must(403, "GET", "/api/catalog", nil)
	c.must(403, "POST", "/api/groups", map[string]any{"name": "x", "kind": "super", "owner": "tester"})
	var me map[string]any
	json.Unmarshal(c.must(200, "GET", "/api/me", nil), &me)
	if me["enrollRequired"] != true {
		t.Fatalf("me during enrollment: %v", me)
	}

	// 2. setup: QR code, URI and the secret for manual entry
	var setup struct {
		Issuer, Account, Secret, URI, QR, Algorithm string
		Digits, Period                              int
	}
	json.Unmarshal(c.must(200, "GET", "/api/otp/setup", nil), &setup)
	if setup.Issuer != "pqc-kms-test" || setup.Account != "alice" || setup.Digits != 6 || setup.Period != 30 || setup.Algorithm != "SHA1" ||
		!strings.HasPrefix(setup.URI, "otpauth://totp/") || !strings.HasPrefix(setup.QR, "data:image/png;base64,") {
		t.Fatalf("setup %+v", setup)
	}
	if png, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(setup.QR, "data:image/png;base64,")); err != nil || !bytes.HasPrefix(png, []byte("\x89PNG")) {
		t.Fatal("the QR image is not a PNG")
	}
	var again struct{ Secret string }
	json.Unmarshal(c.must(200, "GET", "/api/otp/setup", nil), &again)
	if again.Secret != setup.Secret {
		t.Fatal("the secret changed between two setup calls of one session (the app would be scanned with a stale code)")
	}
	secret := mustDecode(t, setup.Secret)
	now := time.Now()
	codeNow := func(d time.Duration) string { return hotp(secret, uint64(totpStep(now.Add(d))), 6) }

	// 3. a wrong code does not enroll; the right one does and yields recovery codes once
	c.must(400, "POST", "/api/otp/confirm", map[string]string{"code": "000000"})
	var done struct {
		Enrolled      bool
		RecoveryCodes []string
	}
	json.Unmarshal(c.must(200, "POST", "/api/otp/confirm", map[string]string{"code": codeNow(0)}), &done)
	if !done.Enrolled || len(done.RecoveryCodes) != 10 {
		t.Fatalf("confirm %+v", done)
	}
	c.must(409, "POST", "/api/otp/confirm", map[string]string{"code": codeNow(0)}) // nothing pending any more
	c.must(409, "GET", "/api/otp/setup", nil)                                      // cannot be replaced from a session
	c.must(200, "GET", "/api/catalog", nil)                                        // full access after enrolling

	// 4. next login: password alone is not enough
	c2 := s.web()
	code, raw = c2.call("POST", "/api/login", map[string]string{"user": "alice", "password": pw}, false)
	if code != 401 || !strings.Contains(string(raw), `"otpRequired":true`) {
		t.Fatalf("login without code: %d %s", code, raw)
	}
	// the code from the enrollment was consumed; the code of the next step works
	if c2.login3("alice", pw, codeNow(0)) == 200 {
		t.Fatal("the enrollment code was accepted for login (replay)")
	}
	if got := c2.login3("alice", pw, codeNow(30*time.Second)); got != 200 {
		t.Fatalf("login with a valid code = %d", got)
	}
	c2.must(200, "GET", "/api/catalog", nil)
	if code, _ := c2.call("POST", "/api/login", map[string]string{"user": "alice", "password": "wrong-password-xx", "otp": codeNow(30 * time.Second)}, false); code != 401 {
		t.Fatalf("right code but wrong password = %d", code)
	}

	// 5. a recovery code logs in once
	c3 := s.web()
	if got := c3.login3("alice", pw, done.RecoveryCodes[0]); got != 200 {
		t.Fatalf("recovery code login = %d", got)
	}
	if got := s.web().login3("alice", pw, done.RecoveryCodes[0]); got == 200 {
		t.Fatal("a recovery code worked twice")
	}
	var meOTP struct {
		OTP struct {
			Enrolled          bool
			RecoveryCodesLeft int
			Policy            string
		}
	}
	json.Unmarshal(c3.must(200, "GET", "/api/me", nil), &meOTP)
	if !meOTP.OTP.Enrolled || meOTP.OTP.RecoveryCodesLeft != 9 || meOTP.OTP.Policy != "required" {
		t.Fatalf("me.otp %+v", meOTP.OTP)
	}

	// 6. guessing codes is throttled
	c4 := s.web()
	for i := 0; i < maxFails; i++ {
		c4.login3("alice", pw, "111111")
	}
	if got := c4.login3("alice", pw, codeNow(60*time.Second)); got != 429 {
		t.Fatalf("after %d wrong codes even a good attempt gave %d, want 429", maxFails, got)
	}

	// 7. the console log tells what happened, without any secret
	var sawEnroll, sawBad, sawRecovery bool
	for _, e := range s.srv.log.Last(500) {
		sawEnroll = sawEnroll || (e.Op == "otp-enroll" && e.Result == "ok")
		sawBad = sawBad || strings.Contains(e.Result, "bad one-time password")
		sawRecovery = sawRecovery || e.Op == "otp-recovery-code-used"
		if strings.Contains(e.Detail+e.Result, setup.Secret) {
			t.Fatal("secret in the log")
		}
	}
	if !sawEnroll || !sawBad || !sawRecovery {
		t.Fatalf("log: enroll=%v bad=%v recovery=%v", sawEnroll, sawBad, sawRecovery)
	}
}

func TestOTPPolicies(t *testing.T) {
	// optional: users without a second factor log in normally, but an enrolled user can never skip it
	s := newStackOpts(t, map[string]string{"carol": pw}, Options{OTP: "optional"})
	c := s.web()
	code, raw := c.call("POST", "/api/login", map[string]string{"user": "carol", "password": pw}, false)
	var lr map[string]any
	json.Unmarshal(raw, &lr)
	if code != 200 || lr["enrollRequired"] != false {
		t.Fatalf("optional policy: %d %s", code, raw)
	}
	c.csrf = lr["csrf"].(string)
	var setup struct{ Secret string }
	json.Unmarshal(c.must(200, "GET", "/api/otp/setup", nil), &setup)
	sec := mustDecode(t, setup.Secret)
	c.must(200, "POST", "/api/otp/confirm", map[string]string{"code": hotp(sec, uint64(totpStep(time.Now())), 6)})

	for _, policy := range []string{"optional", "off"} {
		s.srv.opts.OTP = policy
		if code, _ := s.web().call("POST", "/api/login", map[string]string{"user": "carol", "password": pw}, false); code != 401 {
			t.Fatalf("policy %q let an enrolled user in without the code (%d)", policy, code)
		}
	}
	if _, err := New(s.srv.Backend, s.srv.Users, "", false, Options{OTP: "sometimes"}); err == nil {
		t.Fatal("an invalid policy was accepted")
	}
}

func (c *web) login3(user, pw, otp string) int {
	code, raw := c.call("POST", "/api/login", map[string]string{"user": user, "password": pw, "otp": otp}, false)
	if code == 200 {
		var m map[string]any
		json.Unmarshal(raw, &m)
		c.csrf, _ = m["csrf"].(string)
	}
	return code
}
