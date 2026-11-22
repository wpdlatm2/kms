package restsrv

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wpdlatm2/kms/internal/kms"
	"github.com/wpdlatm2/kms/internal/logs"
	"github.com/wpdlatm2/kms/internal/testpki"
)

type rig struct {
	t                     *testing.T
	pki                   *testpki.PKI
	svc                   *kms.Service
	clientLog, adminLog   *logs.Log
	clientAddr, adminAddr string
}

func newRig(t *testing.T) *rig {
	t.Helper()
	dir := t.TempDir()
	sl, err := kms.LoadFileSealer(filepath.Join(dir, "m.key"))
	if err != nil {
		t.Fatal(err)
	}
	st, err := kms.OpenStore(filepath.Join(dir, "kms.db"), sl)
	if err != nil {
		t.Fatal(err)
	}
	svc := kms.NewService(st, []string{"root"})
	cl, _ := logs.Open("", "client")
	al, _ := logs.Open("", "admin")
	svc.Audit = func(ev kms.AuditEvent) {
		e := logs.Entry{Plane: string(ev.Plane), Kind: "event", Who: ev.Who, Op: ev.Op, Target: ev.Target, Detail: ev.Detail, Result: ev.Result}
		if ev.Plane == kms.PlaneAdmin {
			al.Add(e)
		} else {
			cl.Add(e)
		}
	}
	pki := testpki.New(t)
	r := &rig{t: t, pki: pki, svc: svc, clientLog: cl, adminLog: al}
	srvC, lnC, err := Serve("127.0.0.1:0", pki.ServerTLS(), NewClient(svc, cl))
	if err != nil {
		t.Fatal(err)
	}
	admin := NewAdmin(&Admin{Svc: svc, Log: al, ClientLog: cl, TrustedProxies: []string{"console"}})
	srvA, lnA, err := Serve("127.0.0.1:0", pki.ServerTLS(), admin)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srvC.Close(); srvA.Close() })
	r.clientAddr, r.adminAddr = addr(lnC), addr(lnA)
	return r
}

func addr(ln net.Listener) string { return ln.Addr().String() }

type caller struct {
	t    *testing.T
	h    *http.Client
	base string
	user string // X-Acting-User
}

func (r *rig) caller(base, cn, acting string) *caller {
	cfg := r.pki.ClientTLS(cn)
	return &caller{t: r.t, h: &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}}, base: "https://" + base, user: acting}
}

func (c *caller) do(method, path string, body any) (int, []byte) {
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
	return resp.StatusCode, buf.Bytes()
}

func (c *caller) must(want int, method, path string, body any) []byte {
	c.t.Helper()
	code, raw := c.do(method, path, body)
	if code != want {
		c.t.Fatalf("%s %s = %d, want %d: %s", method, path, code, want, raw)
	}
	return raw
}

func TestSeparatePortsAndLogs(t *testing.T) {
	r := newRig(t)
	root := r.caller(r.adminAddr, "root", "")
	root.must(201, "POST", "/admin/v1/groups", map[string]any{"name": "pay", "kind": "service"})
	root.must(200, "PUT", "/admin/v1/bindings", map[string]any{"client": "app", "group": "pay", "template": "owner"})
	root.must(200, "PUT", "/admin/v1/bindings", map[string]any{"client": "viewer", "group": "pay", "template": "guest"})

	app := r.caller(r.clientAddr, "app", "")
	viewer := r.caller(r.clientAddr, "viewer", "")
	var created KeyList
	json.Unmarshal(app.must(201, "POST", "/v1/keys", map[string]any{"algorithm": "ml-kem-768", "group": "pay", "name": "kem", "activate": true}), &created)
	if created.Count != 2 || created.Keys[0].Group != "pay" || created.Keys[0].State != "active" || created.Keys[0].Algorithm.Name != "ML-KEM-768" ||
		created.Keys[0].Algorithm.Standard != "FIPS 203" || created.Keys[0].Type != "private" || created.Keys[1].Type != "public" ||
		created.Keys[0].PairID != created.Keys[1].ID || created.Keys[0].PairRole != "public" {
		t.Fatalf("created %+v", created)
	}
	if v := created.Keys[0].Value; !v.Present || v.Format != "raw" || v.SizeBytes != 2400 || v.FingerprintSHA256 != "" {
		t.Fatalf("private value info %+v (a private key must not carry a fingerprint)", v)
	}
	if v := created.Keys[1].Value; !v.Present || v.SizeBytes != 1184 || len(v.FingerprintSHA256) != 64 {
		t.Fatalf("public value info %+v", v)
	}
	if created.Keys[0].CreatedAt == "" || created.Keys[0].ActivatedAt == "" || len(created.Keys[0].Permissions) != 9 {
		t.Fatalf("times or permissions missing: %+v", created.Keys[0])
	}
	priv := created.Keys[0].ID

	// guest: reads (including the value), cannot change
	var list KeyList
	json.Unmarshal(viewer.must(200, "GET", "/v1/keys?name=kem&state=ACTIVE", nil), &list)
	if list.Count != 2 {
		t.Fatalf("guest list %d", list.Count)
	}
	for _, k := range list.Keys {
		if len(k.Actions) != 0 || !contains(k.Permissions, "get") || contains(k.Permissions, "destroy") {
			t.Fatalf("a guest is offered actions or has wrong permissions: %v %v", k.Actions, k.Permissions)
		}
	}
	var onlyPub KeyList
	json.Unmarshal(viewer.must(200, "GET", "/v1/keys?type=public", nil), &onlyPub)
	if onlyPub.Count != 1 || onlyPub.Keys[0].Type != "public" {
		t.Fatalf("type filter: %+v", onlyPub)
	}
	var mat ValueResponse
	json.Unmarshal(viewer.must(200, "GET", "/v1/keys/"+priv+"/value", nil), &mat)
	if mat.Value.Format != "raw" || mat.Value.Encoding != "base64" || len(mat.Value.Data) < 3000 || mat.Value.SizeBytes != 2400 || mat.Key.ID != priv {
		t.Fatalf("value %+v", mat.Value)
	}
	json.Unmarshal(viewer.must(200, "GET", "/v1/keys/"+priv+"/value?encoding=hex", nil), &mat)
	if mat.Value.Encoding != "hex" || len(mat.Value.Data) != 4800 {
		t.Fatalf("hex value %d chars", len(mat.Value.Data))
	}
	viewer.must(400, "GET", "/v1/keys/"+priv+"/value?encoding=pem", nil) // a raw value has no PEM form
	viewer.must(400, "GET", "/v1/keys/"+priv+"/value?encoding=rot13", nil)
	viewer.must(403, "POST", "/v1/keys", map[string]any{"algorithm": "aes-256", "group": "pay"})
	viewer.must(404, "POST", "/v1/keys/"+priv+"/deactivate", nil)
	app.must(200, "POST", "/v1/keys/"+priv+"/deactivate", nil)
	app.must(409, "POST", "/v1/keys/"+priv+"/activate", nil) // Deactivated -> Active is not a transition
	app.must(400, "POST", "/v1/keys", map[string]any{"algorithm": "nope", "group": "pay"})
	app.must(400, "POST", "/v1/keys", map[string]any{"algorithm": "aes-256", "group": "pay", "usage": []string{"fly"}})

	// the client port has no administration endpoints, and a client certificate holds no admin role
	app.must(404, "GET", "/admin/v1/groups", nil)
	appOnAdmin := r.caller(r.adminAddr, "app", "")
	appOnAdmin.must(403, "GET", "/admin/v1/groups", nil)
	appOnAdmin.must(403, "GET", "/admin/v1/logs/client", nil)

	// the administration API never returns key values
	code, _ := root.do("GET", "/admin/v1/keys/"+priv+"/value", nil)
	if code == 200 {
		t.Fatal("the admin API released a key value")
	}

	// logs are separate: client requests only in the client log, admin requests only in the admin log
	for _, e := range r.clientLog.Last(1000) {
		if e.Plane != "client" || strings.HasPrefix(e.Op, "GET /admin") || strings.Contains(e.Op, "/admin/") {
			t.Fatalf("admin traffic in the client log: %+v", e)
		}
	}
	for _, e := range r.adminLog.Last(1000) {
		if e.Plane != "admin" || strings.HasPrefix(e.Op, "REST ") {
			t.Fatalf("client traffic in the admin log: %+v", e)
		}
	}
	var cl, ad struct {
		Count   int          `json:"count"`
		Entries []logs.Entry `json:"entries"`
	}
	json.Unmarshal(root.must(200, "GET", "/admin/v1/logs/client?limit=50", nil), &cl)
	json.Unmarshal(root.must(200, "GET", "/admin/v1/logs/admin?limit=50", nil), &ad)
	clients, admins := cl.Entries, ad.Entries
	if len(clients) == 0 || len(admins) == 0 || cl.Count != len(clients) {
		t.Fatalf("log API: %d client, %d admin entries", len(clients), len(admins))
	}
	sawDenied, sawEvent := false, false
	for _, e := range clients {
		sawDenied = sawDenied || (e.Who == "viewer" && strings.HasPrefix(e.Result, "error"))
		sawEvent = sawEvent || (e.Kind == "event" && e.Op == "create" && e.Who == "app")
	}
	if !sawDenied || !sawEvent {
		t.Fatalf("client log lacks the refusal (%v) or the create event (%v)", sawDenied, sawEvent)
	}
	sawGroup := false
	for _, e := range admins {
		sawGroup = sawGroup || (e.Kind == "event" && e.Op == "group-put" && e.Who == "root")
	}
	if !sawGroup {
		t.Fatal("admin log lacks the group creation event")
	}
	// without a certificate nothing is served on either port
	for _, base := range []string{r.clientAddr, r.adminAddr} {
		c := &http.Client{Transport: &http.Transport{TLSClientConfig: r.pki.NoCertTLS()}}
		if resp, err := c.Get("https://" + base + "/v1/keys"); err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				t.Fatalf("%s served a client without certificate", base)
			}
		}
	}
	_ = tls.VersionTLS12
}

func TestDelegatedAdministrationThroughTheConsoleProxy(t *testing.T) {
	r := newRig(t)
	root := r.caller(r.adminAddr, "root", "")
	root.must(201, "POST", "/admin/v1/groups", map[string]any{"name": "division", "kind": "super"})
	root.must(201, "POST", "/admin/v1/groups", map[string]any{"name": "other", "kind": "super"})
	root.must(201, "POST", "/admin/v1/groups", map[string]any{"name": "pay", "kind": "service", "parent": "division"})
	root.must(201, "POST", "/admin/v1/groups", map[string]any{"name": "mail", "kind": "service", "parent": "other"})
	root.must(200, "PUT", "/admin/v1/managers", map[string]any{"identity": "dora", "scope": "division", "role": "admin"})
	root.must(200, "PUT", "/admin/v1/managers", map[string]any{"identity": "ava", "scope": "ALL", "role": "audit"})
	root.must(200, "PUT", "/admin/v1/managers", map[string]any{"identity": "sam", "scope": "pay", "role": "audit"})

	// the console speaks for users; a plain certificate cannot claim a user
	console := func(user string) *caller { return r.caller(r.adminAddr, "console", user) }
	impostor := r.caller(r.adminAddr, "mallory", "root")
	impostor.must(403, "GET", "/admin/v1/groups", nil)
	r.caller(r.adminAddr, "console", "").must(403, "GET", "/admin/v1/groups", nil) // a proxy naming no user has no rights

	var me kms.Me
	json.Unmarshal(console("dora").must(200, "GET", "/admin/v1/me", nil), &me)
	if me.Global || !me.Writer || len(me.Scopes) != 1 || me.Scopes[0].Group != "division" {
		t.Fatalf("dora: %+v", me)
	}
	json.Unmarshal(console("ava").must(200, "GET", "/admin/v1/me", nil), &me)
	if !me.Global || me.Writer {
		t.Fatalf("ava: %+v", me)
	}

	dora := console("dora")
	var groups struct {
		Groups []GroupJSON `json:"groups"`
	}
	json.Unmarshal(dora.must(200, "GET", "/admin/v1/groups", nil), &groups)
	names := []string{}
	for _, g := range groups.Groups {
		names = append(names, g.Name)
	}
	if strings.Join(names, ",") != "division,pay" {
		t.Fatalf("dora sees %v", names)
	}
	dora.must(201, "POST", "/admin/v1/groups", map[string]any{"name": "ledger", "kind": "service", "parent": "division"})
	dora.must(403, "POST", "/admin/v1/groups", map[string]any{"name": "evil", "kind": "service", "parent": "other"})
	dora.must(403, "POST", "/admin/v1/groups", map[string]any{"name": "sup", "kind": "super"})
	dora.must(200, "PUT", "/admin/v1/bindings", map[string]any{"client": "app", "group": "division", "template": "owner"})
	dora.must(403, "PUT", "/admin/v1/bindings", map[string]any{"client": "app", "group": "mail", "template": "owner"})
	dora.must(403, "PUT", "/admin/v1/bindings", map[string]any{"client": "app", "group": "ALL", "template": "owner"})
	dora.must(403, "POST", "/admin/v1/templates", map[string]any{"name": "t1", "operations": []string{"get"}})
	dora.must(403, "GET", "/admin/v1/logs/client", nil)
	dora.must(200, "PUT", "/admin/v1/managers", map[string]any{"identity": "pavel", "scope": "ledger", "role": "admin"})
	dora.must(403, "PUT", "/admin/v1/managers", map[string]any{"identity": "pavel", "scope": "other", "role": "admin"})

	// keys: created and managed inside the scope only
	var vs KeyList
	json.Unmarshal(dora.must(201, "POST", "/admin/v1/keys", map[string]any{"algorithm": "aes-256", "group": "pay"}), &vs)
	dora.must(400, "POST", "/admin/v1/keys", map[string]any{"algorithm": "aes-256"}) // an administrator names the service
	dora.must(403, "POST", "/admin/v1/keys", map[string]any{"algorithm": "aes-256", "group": "mail"})
	dora.must(200, "POST", "/admin/v1/keys/"+vs.Keys[0].ID+"/activate", nil)
	var k KeyJSON
	json.Unmarshal(dora.must(200, "GET", "/admin/v1/keys/"+vs.Keys[0].ID, nil), &k)
	if k.State != "active" || !contains(k.Actions, "rekey") || k.ParentGroup != "division" || k.Value.Format != "raw" || k.Value.FingerprintSHA256 != "" {
		t.Fatalf("key %+v", k)
	}
	console("olaf").must(404, "GET", "/admin/v1/keys/"+vs.Keys[0].ID, nil) // outside any scope the key does not exist for him
	// a read-only auditor sees everything but is offered no actions and cannot write
	ava, sam := console("ava"), console("sam")
	json.Unmarshal(ava.must(200, "GET", "/admin/v1/keys/"+vs.Keys[0].ID, nil), &k)
	if len(k.Actions) != 0 {
		t.Fatalf("auditor is offered actions %v", k.Actions)
	}
	ava.must(403, "POST", "/admin/v1/keys/"+vs.Keys[0].ID+"/deactivate", nil)
	ava.must(403, "POST", "/admin/v1/keys", map[string]any{"algorithm": "aes-256", "group": "pay"})
	ava.must(200, "GET", "/admin/v1/logs/client", nil)
	ava.must(200, "GET", "/admin/v1/logs/admin", nil)
	sam.must(403, "POST", "/admin/v1/keys/"+vs.Keys[0].ID+"/deactivate", nil)
	sam.must(403, "GET", "/admin/v1/logs/admin", nil) // a scoped auditor may not read the global logs

	// the admin log names the acting user and the proxy that asserted it
	found := false
	for _, e := range r.adminLog.Last(1000) {
		found = found || (e.Who == "dora" && e.Via == "console")
	}
	if !found {
		t.Fatal("the admin log does not record the acting user and the proxy")
	}
	// the catalog lists post-quantum algorithms for the console form
	var cat struct {
		Algorithms []catalogEntry `json:"algorithms"`
	}
	json.Unmarshal(ava.must(200, "GET", "/admin/v1/catalog", nil), &cat)
	have := map[string]bool{}
	for _, a := range cat.Algorithms {
		have[a.ID] = true
	}
	for _, want := range []string{"ml-kem-768", "ml-dsa-65", "slh-dsa-sha2-128s", "ed448", "rsa-4096", "aes-128", "x-wing"} {
		if !have[want] {
			t.Fatalf("catalog lacks %s", want)
		}
	}
}

func TestTemplatesEditableThroughTheAPI(t *testing.T) {
	r := newRig(t)
	root := r.caller(r.adminAddr, "root", "")
	root.must(201, "POST", "/admin/v1/groups", map[string]any{"name": "pay", "kind": "service"})
	root.must(201, "POST", "/admin/v1/templates", map[string]any{"name": "rotator", "description": "can rotate", "operations": []string{"locate", "getattributes", "rekey", "get"}})
	root.must(409, "POST", "/admin/v1/templates", map[string]any{"name": "rotator", "operations": []string{"get"}})
	root.must(400, "POST", "/admin/v1/templates", map[string]any{"name": "bad", "operations": []string{"fly"}})
	root.must(200, "PUT", "/admin/v1/bindings", map[string]any{"client": "bot", "group": "pay", "template": "rotator"})
	root.must(409, "DELETE", "/admin/v1/templates/rotator", nil)
	var ts struct {
		Templates []TemplateJSON `json:"templates"`
	}
	json.Unmarshal(root.must(200, "GET", "/admin/v1/templates", nil), &ts)
	if len(ts.Templates) != 3 {
		t.Fatalf("templates %v", ts)
	}
	for _, x := range ts.Templates {
		if x.Name == "owner" && x.CRUD != "CRUD" || x.Name == "guest" && x.CRUD != "R" || x.Name == "rotator" && x.CRUD != "RU" {
			t.Fatalf("crud summary of %s is %q", x.Name, x.CRUD)
		}
	}
	root.must(200, "PUT", "/admin/v1/templates/rotator", map[string]any{"description": "now without get", "operations": []string{"locate", "getattributes", "rekey"}})
	var vs KeyList
	json.Unmarshal(root.must(201, "POST", "/admin/v1/keys", map[string]any{"algorithm": "aes-128", "group": "pay", "activate": true}), &vs)
	bot := r.caller(r.clientAddr, "bot", "")
	bot.must(404, "GET", "/v1/keys/"+vs.Keys[0].ID+"/value", nil) // 'get' was removed from the template
	var rk ActionResponse
	json.Unmarshal(bot.must(200, "POST", "/v1/keys/"+vs.Keys[0].ID+"/rekey", nil), &rk)
	if rk.Action != "rekey" || rk.Key.State != "active" || rk.Replaced == nil || rk.Replaced.State != "deactivated" || rk.Key.ReplacesID != rk.Replaced.ID {
		t.Fatalf("rekey answer %+v", rk)
	}
	root.must(200, "PUT", "/admin/v1/templates/guest", map[string]any{"description": "edited built-in", "operations": []string{"locate"}})
	root.must(400, "DELETE", "/admin/v1/templates/owner", nil)
	root.must(200, "DELETE", "/admin/v1/bindings?client=bot&group=pay", nil)
	root.must(200, "DELETE", "/admin/v1/templates/rotator", nil)
	root.must(404, "DELETE", "/admin/v1/bindings?client=bot&group=pay", nil)
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func TestErrorsAreStructuredAndMinimalRequestsWork(t *testing.T) {
	r := newRig(t)
	root := r.caller(r.adminAddr, "root", "")
	root.must(201, "POST", "/admin/v1/groups", map[string]any{"name": "pay", "kind": "service"})
	root.must(200, "PUT", "/admin/v1/bindings", map[string]any{"client": "app", "group": "pay", "template": "owner"})
	app := r.caller(r.clientAddr, "app", "")

	// the minimal create: one field. The only service of the client is used; defaults fill the rest.
	var made KeyList
	json.Unmarshal(app.must(201, "POST", "/v1/keys", map[string]any{"algorithm": "aes-256"}), &made)
	k := made.Keys[0]
	if k.Group != "pay" || k.State != "pre-active" || !contains(k.Usage, "encrypt") || k.Algorithm.Family != "AES" || k.Algorithm.Bits != 256 || k.Algorithm.Category != "symmetric" {
		t.Fatalf("minimal create: %+v", k)
	}
	// errors: code + message + status + request id (also as a header)
	code, raw := app.do("POST", "/v1/keys/"+k.ID+"/deactivate", nil)
	var eb ErrorBody
	json.Unmarshal(raw, &eb)
	if code != 409 || eb.Error.Code != "invalid_state" || eb.Error.Status != 409 || eb.Error.Message == "" || len(eb.RequestID) != 16 {
		t.Fatalf("error body %s", raw)
	}
	code, raw = app.do("GET", "/v1/keys/nope", nil)
	json.Unmarshal(raw, &eb)
	if code != 404 || eb.Error.Code != "not_found" {
		t.Fatalf("not found body %s", raw)
	}
	code, raw = app.do("POST", "/v1/keys", map[string]any{"algorithm": "aes-256", "colour": "red"}) // unknown fields are refused
	json.Unmarshal(raw, &eb)
	if code != 400 || eb.Error.Code != "invalid_request" {
		t.Fatalf("unknown field: %d %s", code, raw)
	}
	stranger := r.caller(r.clientAddr, "stranger", "")
	code, raw = stranger.do("POST", "/v1/keys", map[string]any{"algorithm": "aes-256", "group": "pay"})
	json.Unmarshal(raw, &eb)
	if code != 403 || eb.Error.Code != "permission_denied" {
		t.Fatalf("denied body %s", raw)
	}
	// catalog: algorithms by the names standards use, with their specification
	var cat struct {
		Algorithms []catalogEntry `json:"algorithms"`
	}
	json.Unmarshal(app.must(200, "GET", "/v1/catalog", nil), &cat)
	seen := map[string]catalogEntry{}
	for _, a := range cat.Algorithms {
		seen[a.ID] = a
	}
	for id, want := range map[string][3]string{"ec-p256": {"EC", "ec", "P-256"}, "ed25519": {"EdDSA", "ec", "Ed25519"}, "slh-dsa-shake-256f": {"SLH-DSA", "pq-signature", ""}, "x-wing": {"X-Wing", "pq-kem", ""}} {
		a := seen[id]
		if a.Family != want[0] || a.Category != want[1] || a.Curve != want[2] || a.Standard == "" {
			t.Fatalf("%s: %+v", id, a)
		}
	}
	if !contains(seen["ml-kem-512"].Produces, "private") || !contains(seen["aes-128"].Produces, "symmetric") {
		t.Fatal("catalog does not say what a create produces")
	}
	// PEM output for asymmetric keys with a standard encoding
	var pair KeyList
	json.Unmarshal(app.must(201, "POST", "/v1/keys", map[string]any{"algorithm": "ec-p256", "name": "e", "activate": true}), &pair)
	var pv ValueResponse
	json.Unmarshal(app.must(200, "GET", "/v1/keys/"+pair.Keys[0].ID+"/value?encoding=pem", nil), &pv)
	if !strings.HasPrefix(pv.Value.Data, "-----BEGIN PRIVATE KEY-----") || pv.Value.Format != "pkcs8" || pv.Key.Algorithm.Curve != "P-256" {
		t.Fatalf("pem value %+v", pv)
	}
	json.Unmarshal(app.must(200, "GET", "/v1/keys/"+pair.Keys[1].ID+"/value?encoding=pem", nil), &pv)
	if !strings.HasPrefix(pv.Value.Data, "-----BEGIN PUBLIC KEY-----") || pv.Value.Format != "x509-spki" {
		t.Fatalf("public pem %+v", pv)
	}
	// admin status
	var st map[string]any
	json.Unmarshal(root.must(200, "GET", "/admin/v1/status", nil), &st)
	if st["totalKeys"].(float64) != 3 || st["time"] == "" {
		t.Fatalf("status %v", st)
	}
}
