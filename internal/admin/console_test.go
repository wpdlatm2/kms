package admin

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wpdlatm2/kms/internal/kms"
	"github.com/wpdlatm2/kms/internal/logs"
	"github.com/wpdlatm2/kms/internal/restsrv"
	"github.com/wpdlatm2/kms/internal/testpki"
)

type stack struct {
	t         *testing.T
	console   *httptest.Server
	srv       *Server
	adminLog  *logs.Log
	clientLog *logs.Log
}

func newStack(t *testing.T, users map[string]string) *stack {
	return newStackOpts(t, users, Options{OTP: "off"})
}

func newStackOpts(t *testing.T, users map[string]string, opts Options) *stack {
	t.Helper()
	dir := t.TempDir()
	sl, _ := kms.LoadFileSealer(filepath.Join(dir, "m.key"))
	st, err := kms.OpenStore(filepath.Join(dir, "kms.db"), sl)
	if err != nil {
		t.Fatal(err)
	}
	svc := kms.NewService(st, []string{"root"})
	al, _ := logs.Open("", "admin")
	cl, _ := logs.Open("", "client")
	svc.Audit = func(ev kms.AuditEvent) {
		e := logs.Entry{Plane: string(ev.Plane), Kind: "event", Who: ev.Who, Op: ev.Op, Target: ev.Target, Detail: ev.Detail, Result: ev.Result, Approval: ev.Approval, Owner: ev.Owner}
		if ev.Plane == kms.PlaneAdmin {
			al.Add(e)
		} else {
			cl.Add(e)
		}
	}
	pki := testpki.New(t)
	adminAPI := restsrv.NewAdmin(&restsrv.Admin{Svc: svc, Log: al, ClientLog: cl, TrustedProxies: []string{"console"}})
	hs, ln, err := restsrv.Serve("127.0.0.1:0", pki.ServerTLS(), adminAPI)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { hs.Close() })
	b := &Backend{Base: "https://" + ln.Addr().String(), Client: &http.Client{Transport: &http.Transport{TLSClientConfig: pki.ClientTLS("console")}}}

	ul, _ := LoadUsers(filepath.Join(dir, "users.json"))
	for n, pw := range users {
		if err := ul.Set(n, pw); err != nil {
			t.Fatal(err)
		}
	}
	srv, err := New(b, ul, filepath.Join(dir, "console.log"), false, opts)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv)
	t.Cleanup(func() { ts.Close(); srv.Close() })
	_ = tls.VersionTLS12
	return &stack{t: t, console: ts, srv: srv, adminLog: al, clientLog: cl}
}

type web struct {
	t    *testing.T
	h    *http.Client
	base string
	csrf string
}

func (s *stack) web() *web {
	jar, _ := cookiejar.New(nil)
	return &web{t: s.t, h: &http.Client{Jar: jar}, base: s.console.URL}
}

func (c *web) call(method, path string, body any, csrf bool) (int, []byte) {
	c.t.Helper()
	var rd *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req, _ := http.NewRequest(method, c.base+path, rd)
	req.Header.Set("Content-Type", "application/json")
	if csrf && c.csrf != "" {
		req.Header.Set("X-CSRF-Token", c.csrf)
	}
	resp, err := c.h.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	var buf bytes.Buffer
	buf.ReadFrom(resp.Body)
	return resp.StatusCode, buf.Bytes()
}

func (c *web) login(user, pw string) int {
	code, raw := c.call("POST", "/api/login", map[string]string{"user": user, "password": pw}, false)
	if code == 200 {
		var m map[string]any
		json.Unmarshal(raw, &m)
		c.csrf, _ = m["csrf"].(string)
	}
	return code
}

func (c *web) must(want int, method, path string, body any) []byte {
	c.t.Helper()
	code, raw := c.call(method, path, body, true)
	if code != want {
		c.t.Fatalf("%s %s = %d, want %d: %s", method, path, code, want, raw)
	}
	return raw
}

const pw = "correct-horse-battery"

func TestConsoleSessionAndForwarding(t *testing.T) {
	s := newStack(t, map[string]string{"root": pw, "dora": pw, "ava": pw, "nobody": pw})
	anon := s.web()
	if code, _ := anon.call("GET", "/api/keys", nil, false); code != 401 {
		t.Fatalf("anonymous = %d", code)
	}
	if code, _ := anon.call("GET", "/", nil, false); code != 200 {
		t.Fatalf("page = %d", code)
	}
	if anon.login("root", "wrong-password-xx") != 401 {
		t.Fatal("bad password accepted")
	}

	root, dora, ava, nobody := s.web(), s.web(), s.web(), s.web()
	for c, u := range map[*web]string{root: "root", dora: "dora", ava: "ava", nobody: "nobody"} {
		if c.login(u, pw) != 200 {
			t.Fatalf("login %s", u)
		}
	}
	// CSRF
	if code, _ := root.call("POST", "/api/groups", map[string]any{"name": "x", "kind": "super", "owner": "tester"}, false); code != 403 {
		t.Fatalf("no CSRF token = %d", code)
	}
	// only the allow-listed API is reachable
	root.must(404, "GET", "/api/health", nil)
	root.must(404, "GET", "/api/..%2f..%2fconfig", nil)

	// root sets up the structure through the console; the backend sees the real user
	root.must(201, "POST", "/api/groups", map[string]any{"name": "division", "kind": "super", "owner": "tester"})
	root.must(201, "POST", "/api/groups", map[string]any{"name": "pay", "kind": "service", "owner": "tester", "parent": "division"})
	root.must(201, "POST", "/api/groups", map[string]any{"name": "mail", "kind": "service", "owner": "tester"})
	root.must(200, "PUT", "/api/managers", map[string]any{"identity": "dora", "scope": "division", "role": "admin", "approvalCode": "APR-T1", "owner": "tester"})
	root.must(200, "PUT", "/api/managers", map[string]any{"identity": "ava", "scope": "ALL", "role": "audit", "approvalCode": "APR-T1", "owner": "tester"})

	var me map[string]any
	json.Unmarshal(dora.must(200, "GET", "/api/me", nil), &me)
	if me["user"] != "dora" || me["global"] != false || me["writer"] != true || me["csrf"] == "" {
		t.Fatalf("dora me: %v", me)
	}
	json.Unmarshal(nobody.must(200, "GET", "/api/me", nil), &me)
	if len(me["scopes"].([]any)) != 0 {
		t.Fatalf("nobody has scopes: %v", me)
	}
	nobody.must(403, "GET", "/api/groups", nil)

	// scoped administration through the console
	dora.must(201, "POST", "/api/keys", map[string]any{"algorithm": "ml-dsa-65", "group": "pay", "names": []string{"sig"}, "activate": true})
	dora.must(403, "POST", "/api/keys", map[string]any{"algorithm": "aes-256", "group": "mail"})
	var kl struct {
		Count int              `json:"count"`
		Keys  []map[string]any `json:"keys"`
	}
	json.Unmarshal(dora.must(200, "GET", "/api/keys", nil), &kl)
	if kl.Count != 2 || len(kl.Keys) != 2 || kl.Keys[0]["group"] != "pay" || kl.Keys[0]["state"] != "active" {
		t.Fatalf("dora keys: %v", kl)
	}
	var cat struct {
		Algorithms []map[string]any `json:"algorithms"`
	}
	json.Unmarshal(dora.must(200, "GET", "/api/catalog", nil), &cat)
	if len(cat.Algorithms) < 40 {
		t.Fatalf("catalog has %d algorithms", len(cat.Algorithms))
	}
	dora.must(403, "POST", "/api/templates", map[string]any{"name": "t", "approvalCode": "APR-T1", "operations": []string{"get"}})
	dora.must(403, "GET", "/api/logs/admin", nil)
	dora.must(403, "GET", "/api/logs/console", nil)

	// audit: global read-only
	ava.must(200, "GET", "/api/keys", nil)
	ava.must(403, "POST", "/api/keys", map[string]any{"algorithm": "aes-256", "group": "pay"})
	ava.must(200, "GET", "/api/logs/admin", nil)
	ava.must(200, "GET", "/api/logs/client", nil)
	var cl []logs.Entry
	json.Unmarshal(ava.must(200, "GET", "/api/logs/console", nil), &cl)
	if len(cl) == 0 {
		t.Fatal("console log is empty")
	}
	sawFail, sawLogin := false, false
	for _, e := range cl {
		sawFail = sawFail || (e.Op == "login-failed" && e.Outcome == logs.OutcomeFailure && strings.HasPrefix(e.Result, "error: bad password"))
		sawLogin = sawLogin || (e.Op == "login" && e.Who == "dora" && e.Result == "ok")
	}
	if !sawFail || !sawLogin {
		t.Fatalf("console log lacks the failed login (%v) or a login (%v)", sawFail, sawLogin)
	}

	// the three logs are different things
	for _, e := range s.adminLog.Last(1000) {
		if e.Plane != "admin" {
			t.Fatalf("non-admin entry in the admin log: %+v", e)
		}
	}
	found := false
	for _, e := range s.adminLog.Last(1000) {
		found = found || (e.Kind == "request" && e.Who == "dora" && e.Via == "console")
	}
	if !found {
		t.Fatal("admin log does not show dora acting via the console")
	}
	if len(s.clientLog.Last(10)) != 0 {
		t.Fatal("console traffic leaked into the client log")
	}

	// logout kills the session
	dora.must(200, "POST", "/api/logout", map[string]string{})
	if code, _ := dora.call("GET", "/api/keys", nil, true); code != 401 {
		t.Fatalf("after logout = %d", code)
	}
}

func TestLoginThrottleAndHeaders(t *testing.T) {
	s := newStack(t, map[string]string{"adam": pw})
	c := s.web()
	for i := 0; i < maxFails; i++ {
		if c.login("adam", "bad-password-1234") != 401 {
			t.Fatal("bad login accepted")
		}
	}
	if code := c.login("adam", pw); code != 429 {
		t.Fatalf("right password after %d failures = %d, want 429", maxFails, code)
	}
	resp, _ := http.Get(s.console.URL + "/")
	if resp.Header.Get("Content-Security-Policy") == "" || resp.Header.Get("X-Frame-Options") != "DENY" {
		t.Fatal("security headers missing")
	}
	if err := ListenAndServe("0.0.0.0:0", "", "", s.srv); err == nil {
		t.Fatal("plain HTTP on a public address allowed")
	}
}

func TestUserFile(t *testing.T) {
	u, _ := LoadUsers(filepath.Join(t.TempDir(), "u.json"))
	if u.Set("a", "short") == nil {
		t.Fatal("short password accepted")
	}
	if u.Set("bad:name", pw) == nil {
		t.Fatal("name with ':' accepted")
	}
	if err := u.Set("ok", pw); err != nil {
		t.Fatal(err)
	}
	if _, ok := u.Verify("ok", pw); !ok {
		t.Fatal("verify")
	}
	if _, ok := u.Verify("ok", pw+"x"); ok {
		t.Fatal("wrong password verified")
	}
}
