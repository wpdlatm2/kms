package restsrv

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"

	"github.com/wpdlatm2/kms/internal/kms"
)

// rawDo sends an arbitrary body (not necessarily valid JSON).
func (c *caller) rawDo(method, path string, body []byte, ctype string) (int, http.Header, []byte) {
	c.t.Helper()
	req, _ := http.NewRequest(method, c.base+path, bytes.NewReader(body))
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	if c.user != "" {
		req.Header.Set("X-Acting-User", c.user)
	}
	resp, err := c.h.Do(req)
	if err != nil {
		c.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	var buf bytes.Buffer
	buf.ReadFrom(resp.Body)
	return resp.StatusCode, resp.Header, buf.Bytes()
}

func keyCount(r *rig) int {
	return len(r.svc.List(r.svc.AdminPrincipal("root"), kms.Filter{}))
}

// gsRig has a service, an owner client and a guest client.
func gsRig(t *testing.T) (*rig, *caller, *caller) {
	r := newRig(t)
	root := r.caller(r.adminAddr, "root", "")
	root.must(201, "POST", "/admin/v1/groups", map[string]any{"name": "pay", "kind": "service"})
	root.must(200, "PUT", "/admin/v1/bindings", map[string]any{"client": "app", "group": "pay", "template": "owner"})
	return r, root, r.caller(r.clientAddr, "app", "")
}

func mustBeStructuredError(t *testing.T, what string, code int, body []byte) {
	t.Helper()
	if code >= 500 {
		t.Fatalf("%s: HTTP %d (a bad request must never cause a server error): %s", what, code, body)
	}
	var eb ErrorBody
	if err := json.Unmarshal(body, &eb); err != nil || eb.Error.Code == "" || eb.Error.Status != code || eb.RequestID == "" {
		t.Fatalf("%s: HTTP %d without a structured error body: %s", what, code, body)
	}
}

// GS: input validation. Every malformed request is rejected with a 4xx and a structured error, and changes nothing.
func TestGS_RESTInputValidation(t *testing.T) {
	r, root, app := gsRig(t)
	long := strings.Repeat("a", 129)
	manyNames, _ := json.Marshal(map[string]any{"algorithm": "aes-256", "group": "pay", "names": func() []string {
		n := make([]string, 1000)
		for i := range n {
			n[i] = fmt.Sprintf("n%d", i)
		}
		return n
	}()})
	cases := []struct {
		name string
		body string
		want int // 0 = any 4xx
	}{
		{"not JSON", `{`, 400}, {"array", `[]`, 400}, {"null", `null`, 400}, {"string", `"x"`, 400}, {"number", `123`, 400},
		{"trailing value", `{"algorithm":"aes-256","group":"pay"}{"x":1}`, 400},
		{"trailing garbage", `{"algorithm":"aes-256","group":"pay"} xyz`, 400},
		{"unknown field", `{"algorithm":"aes-256","group":"pay","admin":true}`, 400},
		{"algorithm is a number", `{"algorithm":123,"group":"pay"}`, 400},
		{"activate is a string", `{"algorithm":"aes-256","group":"pay","activate":"yes"}`, 400},
		{"names is a string", `{"algorithm":"aes-256","group":"pay","names":"a"}`, 400},
		{"usage holds a number", `{"algorithm":"aes-256","group":"pay","usage":[1]}`, 400},
		{"missing algorithm", `{"group":"pay"}`, 400},
		{"empty algorithm", `{"algorithm":"","group":"pay"}`, 400},
		{"blank algorithm", `{"algorithm":"   ","group":"pay"}`, 400},
		{"unknown algorithm", `{"algorithm":"rot13","group":"pay"}`, 400},
		{"algorithm with NUL", "{\"algorithm\":\"aes-256\\u0000\",\"group\":\"pay\"}", 400},
		{"algorithm in capitals", `{"algorithm":"AES-256","group":"pay"}`, 400},
		{"unknown usage", `{"algorithm":"aes-256","group":"pay","usage":["fly"]}`, 400},
		{"unknown group", `{"algorithm":"aes-256","group":"nope"}`, 400},
		{"group is ALL", `{"algorithm":"aes-256","group":"ALL"}`, 400},
		{"name with NUL", "{\"algorithm\":\"aes-256\",\"group\":\"pay\",\"name\":\"a\\u0000b\"}", 400},
		{"name with newline", `{"algorithm":"aes-256","group":"pay","name":"a\nb"}`, 400},
		{"name with line separator", "{\"algorithm\":\"aes-256\",\"group\":\"pay\",\"name\":\"a\\u2028b\"}", 400},
		{"name with BOM", "{\"algorithm\":\"aes-256\",\"group\":\"pay\",\"name\":\"\\ufeffa\"}", 400},
		{"name too long", `{"algorithm":"aes-256","group":"pay","name":"` + long + `"}`, 400},
		{"1000 names", string(manyNames), 400},
		{"huge body", `{"algorithm":"aes-256","group":"pay","name":"` + strings.Repeat("x", 200_000) + `"}`, 400},
	}
	before := keyCount(r)
	for _, c := range cases {
		for _, who := range []struct {
			label string
			cl    *caller
			path  string
		}{{"client", app, "/v1/keys"}, {"admin", root, "/admin/v1/keys"}} {
			code, _, body := who.cl.rawDo("POST", who.path, []byte(c.body), "application/json")
			mustBeStructuredError(t, who.label+": "+c.name, code, body)
			if c.want != 0 && code != c.want {
				t.Fatalf("%s: %s: HTTP %d, want %d: %s", who.label, c.name, code, c.want, body)
			}
		}
	}
	// invalid UTF-8 inside a string
	for _, who := range []struct {
		cl   *caller
		path string
	}{{app, "/v1/keys"}, {root, "/admin/v1/keys"}} {
		code, _, body := who.cl.rawDo("POST", who.path, []byte("{\"algorithm\":\"aes-256\",\"group\":\"pay\",\"name\":\"a\xff\xfeb\"}"), "application/json")
		mustBeStructuredError(t, "invalid UTF-8 name", code, body)
	}
	if after := keyCount(r); after != before {
		t.Fatalf("rejected requests created %d keys", after-before)
	}

	// the same discipline on the administration endpoints
	adminBad := []struct {
		method, path, body string
	}{
		{"POST", "/admin/v1/groups", `{"name":"../etc","kind":"service"}`},
		{"POST", "/admin/v1/groups", `{"name":"a b","kind":"service"}`},
		{"POST", "/admin/v1/groups", `{"name":"` + long + `","kind":"service"}`},
		{"POST", "/admin/v1/groups", `{"name":"ok-name","kind":"galaxy"}`},
		{"POST", "/admin/v1/groups", `{"name":"ok-name","kind":"service","parent":"nope"}`},
		{"POST", "/admin/v1/groups", `{"name":"ok-name","kind":"service","description":"` + strings.Repeat("d", 300) + `"}`},
		{"POST", "/admin/v1/groups", "{\"name\":\"ok-name\",\"kind\":\"service\",\"description\":\"x\\ny\"}"},
		{"POST", "/admin/v1/groups", `{"name":"ALL","kind":"super"}`},
		{"POST", "/admin/v1/templates", `{"name":"t","operations":[]}`},
		{"POST", "/admin/v1/templates", `{"name":"t","operations":["fly"]}`},
		{"POST", "/admin/v1/templates", `{"name":"t t","operations":["get"]}`},
		{"POST", "/admin/v1/templates", `{"name":"t","operations":"get"}`},
		{"PUT", "/admin/v1/bindings", `{"client":"*","group":"pay","template":"owner"}`},
		{"PUT", "/admin/v1/bindings", `{"client":"","group":"pay","template":"owner"}`},
		{"PUT", "/admin/v1/bindings", "{\"client\":\"a\\u0000b\",\"group\":\"pay\",\"template\":\"owner\"}"},
		{"PUT", "/admin/v1/bindings", `{"client":"` + long + `","group":"pay","template":"owner"}`},
		{"PUT", "/admin/v1/bindings", `{"client":"x","group":"nope","template":"owner"}`},
		{"PUT", "/admin/v1/bindings", `{"client":"x","group":"pay","template":"nope"}`},
		{"PUT", "/admin/v1/managers", `{"identity":"x","scope":"pay","role":"root"}`},
		{"PUT", "/admin/v1/managers", `{"identity":"*","scope":"pay","role":"admin"}`},
		{"PUT", "/admin/v1/managers", `{"identity":"x","scope":"ghost","role":"admin"}`},
	}
	for _, c := range adminBad {
		code, _, body := root.rawDo(c.method, c.path, []byte(c.body), "application/json")
		mustBeStructuredError(t, c.method+" "+c.path+" "+c.body, code, body)
	}
	// query parameters
	for _, q := range []string{"limit=-1", "limit=abc", "limit=99999999999999999999", "state=%00", "state=" + strings.Repeat("x", 5000), "type=%ff", "name=" + url.QueryEscape(long), "group=%27%20OR%201%3D1--"} {
		code, _, body := app.rawDo("GET", "/v1/keys?"+q, nil, "")
		if code >= 500 {
			t.Fatalf("query %q: HTTP %d: %s", q, code, body)
		}
	}
}

// GS: identifiers in the path never reach the store and never produce a server error or a 200.
func TestGS_RESTIdentifiers(t *testing.T) {
	_, root, app := gsRig(t)
	ids := []string{
		"..%2f..%2fetc%2fpasswd", "%2e%2e%2f", "%00", "..", "a%2Fb", "' OR '1'='1", "%3Cscript%3Ealert(1)%3C%2Fscript%3E", strings.Repeat("a", 10000),
		"%e2%80%ae", "%ff%fe", "0", "-1", "null", "undefined", "*", "%25s%25n", "${jndi:ldap:%2f%2fx}", "..%5c..%5cwindows",
	}
	for _, id := range ids {
		for _, c := range []struct {
			cl     *caller
			method string
			path   string
		}{
			{app, "GET", "/v1/keys/" + id}, {app, "GET", "/v1/keys/" + id + "/value"}, {app, "POST", "/v1/keys/" + id + "/destroy"},
			{root, "GET", "/admin/v1/keys/" + id}, {root, "POST", "/admin/v1/keys/" + id + "/deactivate"},
		} {
			code, _, body := c.cl.rawDo(c.method, c.path, nil, "")
			if code == 200 || code >= 500 {
				t.Fatalf("%s %s: HTTP %d: %.120s", c.method, c.path, code, body)
			}
		}
	}
	// an unknown lifecycle action
	code, _, body := root.rawDo("POST", "/admin/v1/keys/"+strings.Repeat("a", 36)+"/explode", nil, "")
	if code >= 500 {
		t.Fatalf("unknown action: %d %s", code, body)
	}
}

// GS: hostile text is stored as data and returned escaped; it can neither break out of JSON nor of the log.
func TestGS_RESTHostileTextIsInert(t *testing.T) {
	r, root, app := gsRig(t)
	names := []string{`<script>alert(1)</script>`, `"><img src=x onerror=alert(1)>`, `'; DROP TABLE keys;--`, `{{7*7}}`, `${jndi:ldap://x/a}`, `%s%s%s%n`, `</title><b>`, `日本語 키 이름 🔑`}
	for _, n := range names {
		b, _ := json.Marshal(map[string]any{"algorithm": "aes-128", "group": "pay", "name": n})
		code, hdr, body := app.rawDo("POST", "/v1/keys", b, "application/json")
		if code != 201 {
			t.Fatalf("name %q: HTTP %d %s", n, code, body)
		}
		if strings.Contains(string(body), "<script>") || strings.Contains(string(body), "<img") || strings.Contains(string(body), "</title>") {
			t.Fatalf("an HTML name is returned unescaped: %.200s", body)
		}
		if ct := hdr.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") || hdr.Get("X-Content-Type-Options") != "nosniff" {
			t.Fatalf("headers %v", hdr)
		}
		var kl KeyList
		if err := json.Unmarshal(body, &kl); err != nil || kl.Keys[0].Names[0] != n || !utf8.ValidString(kl.Keys[0].Names[0]) {
			t.Fatalf("the name did not survive unchanged: %v", err)
		}
	}
	// log lines stay one JSON object per entry even for hostile names
	for _, e := range r.clientLog.Last(500) {
		b, _ := json.Marshal(e)
		if bytes.ContainsAny(b, "\n\r") {
			t.Fatal("a log entry contains a line break")
		}
	}
	_ = root
}

// GS: error handling. Failures never reveal stack traces, source paths, store details or type names.
func TestGS_RESTNoInformationLeak(t *testing.T) {
	_, root, app := gsRig(t)
	forbidden := []string{"goroutine", ".go:", "panic", "runtime.", "kms.db", "/data", "C:\\", "/home/", "/src/", "*kms.", "github.com", "json: ", "unexpected EOF"}
	reqs := []struct {
		cl           *caller
		method, path string
		body         string
	}{
		{app, "POST", "/v1/keys", `{`}, {app, "POST", "/v1/keys", `{"algorithm":1}`}, {app, "GET", "/v1/keys/zzz", ""},
		{app, "POST", "/v1/keys/zzz/destroy", ""}, {app, "POST", "/v1/keys", `{"algorithm":"nope"}`},
		{root, "POST", "/admin/v1/groups", `{"name":"a b"}`}, {root, "PUT", "/admin/v1/bindings", `{`}, {root, "DELETE", "/admin/v1/bindings?client=x&group=y", ""},
		{root, "GET", "/admin/v1/logs/nope", ""},
	}
	for _, q := range reqs {
		code, _, body := q.cl.rawDo(q.method, q.path, []byte(q.body), "application/json")
		for _, f := range forbidden {
			if strings.Contains(string(body), f) {
				t.Fatalf("%s %s (HTTP %d) leaks %q: %s", q.method, q.path, code, f, body)
			}
		}
	}
}

// GS: stability. Many clients changing the same data at once leave a consistent, loadable state.
func TestGS_ConcurrentLifecycleKeepsInvariants(t *testing.T) {
	r, root, app := gsRig(t)
	root.must(200, "PUT", "/admin/v1/bindings", map[string]any{"client": "reader", "group": "pay", "template": "guest"})
	reader := r.caller(r.clientAddr, "reader", "")

	const workers, rounds = 24, 12
	var wg sync.WaitGroup
	fail := make(chan string, workers*rounds*8)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < rounds; i++ {
				name := fmt.Sprintf("w%d-%d", w, i)
				algo := []string{"aes-256", "ml-kem-768", "ed25519", "hmac-sha256"}[(w+i)%4]
				code, _, body := app.rawDo("POST", "/v1/keys", []byte(fmt.Sprintf(`{"algorithm":%q,"name":%q,"activate":true}`, algo, name)), "application/json")
				if code != 201 {
					fail <- fmt.Sprintf("create %s: %d %s", name, code, body)
					continue
				}
				var kl KeyList
				json.Unmarshal(body, &kl)
				id := kl.Keys[0].ID
				reader.rawDo("GET", "/v1/keys?name="+name, nil, "")
				reader.rawDo("GET", "/v1/keys/"+id+"/value", nil, "")
				rekeyed := false
				if algo == "aes-256" || algo == "hmac-sha256" {
					c, _, b := app.rawDo("POST", "/v1/keys/"+id+"/rekey", nil, "")
					if c != 200 {
						fail <- fmt.Sprintf("rekey: %d %s", c, b)
					}
					rekeyed = c == 200 // a re-keyed key is already deactivated by the server
				}
				// two racing lifecycle requests for the same key: exactly one may win, the other must be refused cleanly
				var inner sync.WaitGroup
				codes := make([]int, 2)
				for j := 0; j < 2; j++ {
					inner.Add(1)
					go func(j int) {
						defer inner.Done()
						codes[j], _, _ = app.rawDo("POST", "/v1/keys/"+id+"/deactivate", nil, "")
					}(j)
				}
				inner.Wait()
				ok := 0
				for _, c := range codes {
					if c == 200 {
						ok++
					} else if c != 409 {
						fail <- fmt.Sprintf("racing deactivate: %d", c)
					}
				}
				if rekeyed {
					if ok != 0 {
						fail <- fmt.Sprintf("deactivating the already replaced key %s succeeded", id)
					}
				} else if ok != 1 {
					fail <- fmt.Sprintf("racing deactivate of %s: %d winners (%v)", id, ok, codes)
				}
				root.rawDo("GET", "/admin/v1/keys", nil, "")
				root.rawDo("GET", "/admin/v1/groups", nil, "")
			}
		}(w)
	}
	wg.Wait()
	close(fail)
	for f := range fail {
		t.Error(f)
	}
	if t.Failed() {
		return
	}
	// invariants of the final state
	all := r.svc.List(r.svc.AdminPrincipal("root"), kms.Filter{})
	byID := map[string]kms.View{}
	for _, k := range all {
		byID[k.ID] = k
	}
	for _, k := range all {
		if k.PairID != "" {
			if p, ok := byID[k.PairID]; !ok || p.PairID != k.ID {
				t.Fatalf("pair of %s is inconsistent", k.ID)
			}
		}
		if k.ReplacedByID != "" {
			if n, ok := byID[k.ReplacedByID]; !ok || n.ReplacesID != k.ID || k.State != kms.Deactivated {
				t.Fatalf("replacement chain of %s is inconsistent", k.ID)
			}
		}
		if k.State < kms.PreActive || k.State > kms.DestroyedCompromised {
			t.Fatalf("invalid state %d", k.State)
		}
	}
	if want := 0; len(all) <= want {
		t.Fatal("no keys survived")
	}
}
