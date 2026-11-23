package admin

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"sync"
	"testing"
	"time"
)

func setCookie(resp *http.Response) *http.Cookie {
	for _, c := range resp.Cookies() {
		if c.Name == cookieName {
			return c
		}
	}
	return nil
}

func postJSON(t *testing.T, base, path string, body []byte, hdr map[string]string) (*http.Response, []byte) {
	t.Helper()
	req, _ := http.NewRequest("POST", base+path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var buf bytes.Buffer
	buf.ReadFrom(resp.Body)
	return resp, buf.Bytes()
}

// GS: session management.
func TestGS_SessionManagement(t *testing.T) {
	s := newStack(t, map[string]string{"alice": pw})
	login := func() (*http.Response, string) {
		b, _ := json.Marshal(map[string]string{"user": "alice", "password": pw})
		resp, body := postJSON(t, s.console.URL, "/api/login", b, nil)
		var m map[string]any
		json.Unmarshal(body, &m)
		csrf, _ := m["csrf"].(string)
		return resp, csrf
	}
	r1, csrf1 := login()
	r2, csrf2 := login()
	c1, c2 := setCookie(r1), setCookie(r2)
	if c1 == nil || c2 == nil || c1.Value == c2.Value || csrf1 == csrf2 {
		t.Fatal("every login must create a new, different session identifier and CSRF token")
	}
	if len(c1.Value) < 40 {
		t.Fatalf("session identifier of %d characters is too short", len(c1.Value))
	}
	if !c1.HttpOnly || c1.SameSite != http.SameSiteStrictMode || c1.Path != "/" || c1.MaxAge <= 0 {
		t.Fatalf("cookie attributes: %+v", c1)
	}
	// the session identifier is not derivable from the CSRF token or the user name
	if strings.Contains(c1.Value, "alice") || c1.Value == csrf1 {
		t.Fatal("weak session identifier")
	}

	get := func(cookie string) int {
		req, _ := http.NewRequest("GET", s.console.URL+"/api/me", nil)
		if cookie != "" {
			req.AddCookie(&http.Cookie{Name: cookieName, Value: cookie})
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if get(c1.Value) != 200 || get(c2.Value) != 200 {
		t.Fatal("valid sessions refused")
	}
	for name, v := range map[string]string{"none": "", "random": "AAAA", "tampered": c1.Value[:len(c1.Value)-2] + "xx", "long": strings.Repeat("A", 100000), "other user": c1.Value + c2.Value, "NUL": "a\x00b"} {
		if code := get(v); code != 401 {
			t.Fatalf("%s cookie accepted: %d", name, code)
		}
	}
	// logout invalidates the identifier for good (replay)
	req, _ := http.NewRequest("POST", s.console.URL+"/api/logout", nil)
	req.AddCookie(&http.Cookie{Name: cookieName, Value: c1.Value})
	req.Header.Set("X-CSRF-Token", csrf1)
	resp, _ := http.DefaultClient.Do(req)
	resp.Body.Close()
	if get(c1.Value) != 401 {
		t.Fatal("a logged-out session is still valid")
	}
	if get(c2.Value) != 200 {
		t.Fatal("logging out one session ended another")
	}

	// idle and absolute lifetime
	s.srv.sess.idle = 150 * time.Millisecond
	r3, _ := login()
	c3 := setCookie(r3)
	if get(c3.Value) != 200 {
		t.Fatal("fresh session refused")
	}
	time.Sleep(300 * time.Millisecond)
	if get(c3.Value) != 401 {
		t.Fatal("an idle session did not expire")
	}
	s.srv.sess.idle = 20 * time.Minute
	s.srv.sess.ttl = 200 * time.Millisecond
	r4, _ := login()
	c4 := setCookie(r4)
	time.Sleep(300 * time.Millisecond)
	if get(c4.Value) != 401 {
		t.Fatal("a session outlived its absolute lifetime")
	}
}

func TestGS_SecureCookieOverTLS(t *testing.T) {
	s := newStack(t, map[string]string{"alice": pw})
	s.srv.Secure = true
	b, _ := json.Marshal(map[string]string{"user": "alice", "password": pw})
	resp, _ := postJSON(t, s.console.URL, "/api/login", b, nil)
	if c := setCookie(resp); c == nil || !c.Secure {
		t.Fatalf("the session cookie must carry the Secure flag when served over TLS: %+v", c)
	}
	if resp.Header.Get("Strict-Transport-Security") == "" {
		t.Fatal("no HSTS header over TLS")
	}
}

// GS: input validation of the login and of the forwarded API.
func TestGS_ConsoleInputValidation(t *testing.T) {
	s := newStack(t, map[string]string{"alice": pw})
	forbidden := []string{"goroutine", ".go:", "panic", "runtime.", "json:", "unexpected EOF", "github.com"}
	bodies := map[string][]byte{
		"empty": {}, "not json": []byte("{"), "null": []byte("null"), "array": []byte("[]"), "number": []byte("1"),
		"huge":  append([]byte(`{"user":"`), append(bytes.Repeat([]byte("a"), 1<<20), []byte(`","password":"x"}`)...)...),
		"sql":   []byte(`{"user":"alice' OR '1'='1","password":"' OR '1'='1"}`),
		"html":  []byte(`{"user":"<script>alert(1)</script>","password":"x"}`),
		"nul":   []byte("{\"user\":\"alice\\u0000\",\"password\":\"x\"}"),
		"types": []byte(`{"user":123,"password":["x"]}`), "badutf8": []byte("{\"user\":\"a\xff\",\"password\":\"x\"}"),
		"missing": []byte(`{}`), "extra": []byte(`{"user":"alice","password":"x","role":"admin", "approvalCode": "APR-T1", "owner": "tester"}`),
	}
	for name, body := range bodies {
		resp, out := postJSON(t, s.console.URL, "/api/login", body, nil)
		if resp.StatusCode == 200 || resp.StatusCode >= 500 {
			t.Fatalf("%s: HTTP %d", name, resp.StatusCode)
		}
		for _, f := range forbidden {
			if strings.Contains(string(out), f) {
				t.Fatalf("%s: the answer leaks %q: %s", name, f, out)
			}
		}
		if strings.Contains(string(out), "<script>") || strings.Contains(string(out), "OR '1'") {
			t.Fatalf("%s: the answer echoes the input: %s", name, out)
		}
		if resp.Header.Get("Content-Security-Policy") == "" || resp.Header.Get("X-Content-Type-Options") != "nosniff" || resp.Header.Get("Cache-Control") != "no-store" {
			t.Fatalf("%s: security headers missing on an error answer", name)
		}
	}
	// unknown user and wrong password are indistinguishable
	_, a := postJSON(t, s.console.URL, "/api/login", []byte(`{"user":"nobody","password":"wrong-password-xx"}`), nil)
	_, b := postJSON(t, s.console.URL, "/api/login", []byte(`{"user":"alice","password":"wrong-password-xx"}`), nil)
	if string(a) != string(b) {
		t.Fatalf("login errors differ: %s vs %s", a, b)
	}
	// wrong method
	resp, _ := http.Get(s.console.URL + "/api/login")
	if resp.StatusCode < 400 || resp.StatusCode >= 500 {
		t.Fatalf("GET /api/login = %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestGS_ConsoleForwardingBoundaries(t *testing.T) {
	s := newStack(t, map[string]string{"root": pw, "dora": pw})
	root, dora := s.web(), s.web()
	root.login("root", pw)
	root.must(201, "POST", "/api/groups", map[string]any{"name": "pay", "kind": "service", "owner": "tester"})
	root.must(200, "PUT", "/api/managers", map[string]any{"identity": "dora", "scope": "pay", "role": "admin", "approvalCode": "APR-T1", "owner": "tester"})
	dora.login("dora", pw)

	// a client-supplied identity header never reaches the backend: dora stays dora
	req, _ := http.NewRequest("GET", s.console.URL+"/api/me", nil)
	req.Header.Set("X-Acting-User", "root")
	jar, _ := cookiejar.New(nil)
	cl := &http.Client{Jar: jar}
	b, _ := json.Marshal(map[string]string{"user": "dora", "password": pw})
	lr, _ := cl.Post(s.console.URL+"/api/login", "application/json", bytes.NewReader(b))
	lr.Body.Close()
	resp, err := cl.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var me map[string]any
	json.NewDecoder(resp.Body).Decode(&me)
	resp.Body.Close()
	if me["user"] != "dora" || me["global"] == true {
		t.Fatalf("a spoofed X-Acting-User changed the identity: %v", me)
	}

	for _, p := range []string{"/api/health", "/api/../groups", "/api/%2e%2e/groups", "/api/keys/../../me", "/api/otp", "/api/unknown", "/api/logs/../keys"} {
		code, _ := dora.call("GET", p, nil, true)
		if code >= 500 {
			t.Fatalf("GET %s = %d", p, code)
		}
	}
	for _, m := range []string{"PATCH", "OPTIONS", "TRACE", "HEAD"} {
		req, _ := http.NewRequest(m, s.console.URL+"/api/keys", nil)
		req.Header.Set("X-CSRF-Token", dora.csrf)
		resp, err := dora.h.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode == 200 && m != "HEAD" {
			t.Fatalf("%s /api/keys accepted", m)
		}
		if resp.StatusCode >= 500 {
			t.Fatalf("%s /api/keys = %d", m, resp.StatusCode)
		}
	}
	// body limit and CSRF/Origin
	big := map[string]any{"name": "x", "kind": "service", "owner": "tester", "description": strings.Repeat("d", 100000)}
	if code, _ := dora.call("POST", "/api/groups", big, true); code < 400 || code >= 500 {
		t.Fatalf("an oversized body gave %d", code)
	}
	if code, _ := dora.call("POST", "/api/keys", map[string]any{"algorithm": "aes-256", "group": "pay"}, false); code != 403 {
		t.Fatalf("no CSRF token: %d", code)
	}
	req, _ = http.NewRequest("POST", s.console.URL+"/api/keys", strings.NewReader(`{"algorithm":"aes-256","group":"pay"}`))
	req.Header.Set("X-CSRF-Token", dora.csrf)
	req.Header.Set("Origin", "https://evil.example")
	resp, _ = dora.h.Do(req)
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("a cross-origin request with a valid token gave %d", resp.StatusCode)
	}
	req, _ = http.NewRequest("POST", s.console.URL+"/api/keys", strings.NewReader(`{"algorithm":"aes-256","group":"pay"}`))
	req.Header.Set("X-CSRF-Token", dora.csrf+"x")
	resp, _ = dora.h.Do(req)
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("a wrong CSRF token gave %d", resp.StatusCode)
	}
}

// GS: stability under concurrent logins and requests.
func TestGS_ConsoleConcurrency(t *testing.T) {
	users := map[string]string{}
	for _, n := range []string{"u0", "u1", "u2", "u3", "u4", "u5", "u6", "u7"} {
		users[n] = pw
	}
	s := newStack(t, users)
	var wg sync.WaitGroup
	errs := make(chan string, 400)
	for i := 0; i < 48; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c := s.web()
			user := []string{"u0", "u1", "u2", "u3", "u4", "u5", "u6", "u7"}[i%8]
			if code := c.login(user, pw); code != 200 {
				errs <- "login " + user
				return
			}
			for j := 0; j < 5; j++ {
				if code, _ := c.call("GET", "/api/me", nil, true); code != 200 {
					errs <- "me"
				}
				if code, _ := c.call("GET", "/api/groups", nil, true); code != 403 { // no management role: refused by the backend
					errs <- "groups"
				}
			}
			c.call("POST", "/api/logout", map[string]string{}, true)
		}(i)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
}
