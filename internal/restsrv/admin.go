package restsrv

import (
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/wpdlatm2/kms/internal/kms"
	"github.com/wpdlatm2/kms/internal/logs"
)

// Admin is the administration API.
type Admin struct {
	Svc *kms.Service
	// Log is the administration log; ClientLog is only read (the audit view of client activity).
	Log       *logs.Log
	ClientLog *logs.Log
	// TrustedProxies are certificate names (such as the web console) allowed to act on behalf of a user:
	// they send the user in the X-Acting-User header. Without the header a proxy holds no rights.
	TrustedProxies []string
	mux            *http.ServeMux
	Info           func() map[string]any
}

// ---- wire forms

type GroupJSON struct {
	Name         string         `json:"name"`
	Kind         string         `json:"kind"` // service | super | all
	Parent       string         `json:"parent,omitempty"`
	Description  string         `json:"description"`
	Builtin      bool           `json:"builtin"`
	CreatedAt    string         `json:"createdAt,omitempty"`
	KeyCount     int            `json:"keyCount"`
	KeysByState  map[string]int `json:"keysByState"`
	Services     []string       `json:"services,omitempty"`
	ClientCount  int            `json:"clientCount"`
	ManagerCount int            `json:"managerCount"`
}

type TemplateJSON struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Builtin     bool     `json:"builtin"`
	Operations  []string `json:"operations"`
	CRUD        string   `json:"crud"` // letters of the classes the operations belong to, e.g. "CRUD"
}

type BindingJSON struct {
	Client     string   `json:"client"`
	Group      string   `json:"group"`
	GroupKind  string   `json:"groupKind"`
	Template   string   `json:"template"`
	Operations []string `json:"operations"`
}

type ManagerJSON struct {
	Identity  string `json:"identity"`
	Scope     string `json:"scope"`
	ScopeKind string `json:"scopeKind"`
	Role      string `json:"role"` // admin | audit
	Root      bool   `json:"root"` // configured at start-up, not revocable here
}

type MeJSON struct {
	Name   string      `json:"name"`
	Global bool        `json:"global"`
	Writer bool        `json:"writer"`
	Scopes []kms.Scope `json:"scopes"`
}

func crud(ops []string) string {
	s := ""
	for _, c := range []string{"C", "R", "U", "D"} {
		for _, o := range ops {
			if kms.OpClass[o] == c {
				s += c
				break
			}
		}
	}
	return s
}

func NewAdmin(a *Admin) *Admin {
	a.mux = http.NewServeMux()
	h := a.wrap
	a.mux.HandleFunc("GET /admin/v1/me", h(func(w http.ResponseWriter, r *http.Request, p kms.Principal) {
		m := a.Svc.Me(p)
		writeJSON(w, 200, MeJSON{Name: m.Name, Global: m.Global, Writer: m.Writer, Scopes: m.Scopes})
	}))
	a.mux.HandleFunc("GET /admin/v1/status", h(a.status))
	a.mux.HandleFunc("GET /admin/v1/catalog", h(func(w http.ResponseWriter, r *http.Request, p kms.Principal) {
		writeJSON(w, 200, map[string]any{"algorithms": catalog(), "usages": kms.UsageList(), "operations": kms.Operations, "operationClasses": kms.OpClass})
	}))

	a.mux.HandleFunc("GET /admin/v1/groups", h(a.groups))
	a.mux.HandleFunc("POST /admin/v1/groups", h(a.putGroup(true)))
	a.mux.HandleFunc("PUT /admin/v1/groups/{name}", h(a.putGroup(false)))
	a.mux.HandleFunc("DELETE /admin/v1/groups/{name}", h(func(w http.ResponseWriter, r *http.Request, p kms.Principal) {
		done(w, a.Svc.DeleteGroup(p, r.PathValue("name")), "deleted")
	}))

	a.mux.HandleFunc("GET /admin/v1/templates", h(a.templates))
	a.mux.HandleFunc("POST /admin/v1/templates", h(a.putTemplate(true)))
	a.mux.HandleFunc("PUT /admin/v1/templates/{name}", h(a.putTemplate(false)))
	a.mux.HandleFunc("DELETE /admin/v1/templates/{name}", h(func(w http.ResponseWriter, r *http.Request, p kms.Principal) {
		done(w, a.Svc.DeleteTemplate(p, r.PathValue("name")), "deleted")
	}))

	a.mux.HandleFunc("GET /admin/v1/bindings", h(a.bindings))
	a.mux.HandleFunc("PUT /admin/v1/bindings", h(func(w http.ResponseWriter, r *http.Request, p kms.Principal) {
		var b kms.Binding
		if err := decode(r, &b); err != nil {
			fail(w, err)
			return
		}
		done(w, a.Svc.PutBinding(p, b.Client, b.Group, b.Template), "saved")
	}))
	a.mux.HandleFunc("DELETE /admin/v1/bindings", h(func(w http.ResponseWriter, r *http.Request, p kms.Principal) {
		done(w, a.Svc.DeleteBinding(p, r.URL.Query().Get("client"), r.URL.Query().Get("group")), "deleted")
	}))

	a.mux.HandleFunc("GET /admin/v1/managers", h(a.managers))
	a.mux.HandleFunc("PUT /admin/v1/managers", h(func(w http.ResponseWriter, r *http.Request, p kms.Principal) {
		var m kms.Manager
		if err := decode(r, &m); err != nil {
			fail(w, err)
			return
		}
		done(w, a.Svc.PutManager(p, m.Identity, m.Scope, m.Role), "saved")
	}))
	a.mux.HandleFunc("DELETE /admin/v1/managers", h(func(w http.ResponseWriter, r *http.Request, p kms.Principal) {
		done(w, a.Svc.DeleteManager(p, r.URL.Query().Get("identity"), r.URL.Query().Get("scope")), "deleted")
	}))

	a.mux.HandleFunc("GET /admin/v1/keys", h(func(w http.ResponseWriter, r *http.Request, p kms.Principal) {
		writeJSON(w, 200, keyList(a.Svc, p, a.Svc.List(p, filterFrom(r))))
	}))
	a.mux.HandleFunc("GET /admin/v1/keys/{id}", h(func(w http.ResponseWriter, r *http.Request, p kms.Principal) {
		v, err := a.Svc.Attributes(p, r.PathValue("id"))
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, 200, keyJSON(a.Svc, p, v))
	}))
	a.mux.HandleFunc("POST /admin/v1/keys", h(func(w http.ResponseWriter, r *http.Request, p kms.Principal) {
		var b createBody
		if err := decode(r, &b); err != nil {
			fail(w, err)
			return
		}
		req, err := b.req()
		if err != nil {
			fail(w, err)
			return
		}
		vs, err := a.Svc.Create(p, req)
		if err != nil {
			fail(w, err)
			return
		}
		w.Header().Set("Location", "/admin/v1/keys/"+vs[0].ID)
		writeJSON(w, 201, keyList(a.Svc, p, vs))
	}))
	a.mux.HandleFunc("POST /admin/v1/keys/{id}/{action}", h(func(w http.ResponseWriter, r *http.Request, p kms.Principal) {
		out, err := doAction(a.Svc, p, r.PathValue("id"), r.PathValue("action"))
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, 200, out)
	}))

	a.mux.HandleFunc("GET /admin/v1/logs/{which}", h(a.logs))
	return a
}

func (a *Admin) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	requestID(w)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	a.mux.ServeHTTP(w, r)
}

// done answers a mutation without a resource to return.
func done(w http.ResponseWriter, err error, result string) {
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"result": result})
}

// wrap authenticates (certificate, or a trusted proxy acting for a user), resolves the management scopes and
// writes the administration log line.
func (a *Admin) wrap(h func(http.ResponseWriter, *http.Request, kms.Principal)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cn := peerCN(r)
		if cn == "" {
			failWith(w, http.StatusUnauthorized, "unauthorized", "a client certificate is required")
			return
		}
		who, via := cn, ""
		if slices.Contains(a.TrustedProxies, cn) {
			via = cn
			if u := r.Header.Get("X-Acting-User"); u != "" && len(u) <= 128 {
				who = u
			} else {
				who = "proxy:" + cn // a proxy that names no user holds no rights
			}
		}
		p := a.Svc.AdminPrincipal(who)
		sw := &statusWriter{ResponseWriter: w, code: 200}
		h(sw, r, p)
		res := "ok"
		if sw.code >= 400 {
			res = "error: HTTP " + strconv.Itoa(sw.code)
		}
		a.Log.Add(logs.Entry{Plane: "admin", Kind: "request", Who: who, Via: via, Op: r.Method + " " + r.URL.Path, Detail: "request " + w.Header().Get("X-Request-Id"), Result: res, Remote: remoteIP(r)})
	}
}

func (a *Admin) status(w http.ResponseWriter, r *http.Request, p kms.Principal) {
	if len(p.Scopes) == 0 {
		fail(w, &kms.Error{Code: kms.ErrDenied, Msg: "this identity holds no administration role"})
		return
	}
	keys := a.Svc.Stats()
	total := 0
	for _, n := range keys {
		total += n
	}
	out := map[string]any{"time": time.Now().UTC().Format(time.RFC3339), "keys": keys, "totalKeys": total}
	if a.Info != nil {
		for k, v := range a.Info() {
			out[k] = v
		}
	}
	writeJSON(w, 200, out)
}

func (a *Admin) groups(w http.ResponseWriter, r *http.Request, p kms.Principal) {
	gs, err := a.Svc.Groups(p)
	if err != nil {
		fail(w, err)
		return
	}
	out := []GroupJSON{}
	for _, g := range gs {
		out = append(out, GroupJSON{Name: g.Name, Kind: g.Kind, Parent: g.Parent, Description: g.Description, Builtin: g.Builtin, CreatedAt: ts(g.Created),
			KeyCount: g.Keys, KeysByState: g.KeysByState, Services: g.Services, ClientCount: g.Clients, ManagerCount: g.Managers})
	}
	writeJSON(w, 200, map[string]any{"count": len(out), "groups": out})
}

func (a *Admin) putGroup(create bool) func(http.ResponseWriter, *http.Request, kms.Principal) {
	return func(w http.ResponseWriter, r *http.Request, p kms.Principal) {
		var b struct {
			Name        string `json:"name"`
			Kind        string `json:"kind"`
			Parent      string `json:"parent"`
			Description string `json:"description"`
		}
		if err := decode(r, &b); err != nil {
			fail(w, err)
			return
		}
		if !create {
			b.Name = r.PathValue("name")
		}
		err := a.Svc.PutGroup(p, kms.GroupReq{Name: b.Name, Kind: b.Kind, Parent: b.Parent, Description: b.Description}, create)
		if err != nil {
			fail(w, err)
			return
		}
		status := 200
		if create {
			status = 201
			w.Header().Set("Location", "/admin/v1/groups/"+b.Name)
		}
		writeJSON(w, status, map[string]any{"result": "saved", "name": b.Name})
	}
}

func (a *Admin) templates(w http.ResponseWriter, r *http.Request, p kms.Principal) {
	ts, err := a.Svc.Templates(p)
	if err != nil {
		fail(w, err)
		return
	}
	out := []TemplateJSON{}
	for _, t := range ts {
		out = append(out, TemplateJSON{Name: t.Name, Description: t.Description, Builtin: t.Builtin, Operations: t.Operations, CRUD: crud(t.Operations)})
	}
	writeJSON(w, 200, map[string]any{"count": len(out), "templates": out})
}

func (a *Admin) putTemplate(create bool) func(http.ResponseWriter, *http.Request, kms.Principal) {
	return func(w http.ResponseWriter, r *http.Request, p kms.Principal) {
		var b struct {
			Name        string   `json:"name"`
			Description string   `json:"description"`
			Operations  []string `json:"operations"`
		}
		if err := decode(r, &b); err != nil {
			fail(w, err)
			return
		}
		if !create {
			b.Name = r.PathValue("name")
		}
		if err := a.Svc.PutTemplate(p, b.Name, b.Description, b.Operations, create); err != nil {
			fail(w, err)
			return
		}
		status := 200
		if create {
			status = 201
			w.Header().Set("Location", "/admin/v1/templates/"+b.Name)
		}
		writeJSON(w, status, map[string]any{"result": "saved", "name": b.Name})
	}
}

func (a *Admin) bindings(w http.ResponseWriter, r *http.Request, p kms.Principal) {
	bs, err := a.Svc.Bindings(p)
	if err != nil {
		fail(w, err)
		return
	}
	ts, _ := a.Svc.Templates(p)
	ops := map[string][]string{}
	for _, t := range ts {
		ops[t.Name] = t.Operations
	}
	gs, _ := a.Svc.Groups(p)
	kind := map[string]string{}
	for _, g := range gs {
		kind[g.Name] = g.Kind
	}
	out := []BindingJSON{}
	for _, b := range bs {
		out = append(out, BindingJSON{Client: b.Client, Group: b.Group, GroupKind: kind[b.Group], Template: b.Template, Operations: ops[b.Template]})
	}
	writeJSON(w, 200, map[string]any{"count": len(out), "bindings": out})
}

func (a *Admin) managers(w http.ResponseWriter, r *http.Request, p kms.Principal) {
	ms, err := a.Svc.Managers(p)
	if err != nil {
		fail(w, err)
		return
	}
	gs, _ := a.Svc.Groups(p)
	kind := map[string]string{}
	for _, g := range gs {
		kind[g.Name] = g.Kind
	}
	out := []ManagerJSON{}
	for _, m := range ms {
		root := strings.HasSuffix(m.Role, "(root)")
		out = append(out, ManagerJSON{Identity: m.Identity, Scope: m.Scope, ScopeKind: kind[m.Scope], Role: strings.TrimSuffix(strings.TrimSuffix(m.Role, " (root)"), "(root)"), Root: root})
	}
	writeJSON(w, 200, map[string]any{"count": len(out), "managers": out})
}

// logs serves the client log or the administration log. Both span every group, so only identities with a
// global role (admin or audit) may read them.
func (a *Admin) logs(w http.ResponseWriter, r *http.Request, p kms.Principal) {
	if !a.Svc.Me(p).Global {
		fail(w, &kms.Error{Code: kms.ErrDenied, Msg: "logs are readable by global administrators and auditors only"})
		return
	}
	n := 500
	if v, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && v > 0 && v <= 2000 {
		n = v
	}
	var entries []logs.Entry
	switch r.PathValue("which") {
	case "client":
		entries = a.ClientLog.Last(n)
	case "admin":
		entries = a.Log.Last(n)
	default:
		fail(w, &kms.Error{Code: kms.ErrNotFound, Msg: "unknown log"})
		return
	}
	writeJSON(w, 200, map[string]any{"log": r.PathValue("which"), "count": len(entries), "entries": entries})
}
