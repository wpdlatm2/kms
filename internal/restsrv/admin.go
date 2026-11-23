package restsrv

import (
	"bytes"
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
	// MACKey verifies the MAC of audit entries (the key the logs were opened with).
	MACKey []byte
}

// ---- wire forms

type GroupJSON struct {
	Name         string         `json:"name"`
	Kind         string         `json:"kind"` // service | super | all
	Parent       string         `json:"parent,omitempty"`
	Description  string         `json:"description"`
	Owner        string         `json:"owner,omitempty"` // person responsible (담당자)
	Builtin      bool           `json:"builtin"`
	CreatedAt    string         `json:"createdAt,omitempty"`
	KeyCount     int            `json:"keyCount"`
	KeysByState  map[string]int `json:"keysByState"`
	Services     []string       `json:"services,omitempty"`
	ClientCount  int            `json:"clientCount"`
	ManagerCount int            `json:"managerCount"`
}

type TemplateJSON struct {
	Name         string   `json:"name"`
	Description  string   `json:"description"`
	Builtin      bool     `json:"builtin"`
	Operations   []string `json:"operations"`
	CRUD         string   `json:"crud"`                   // letters of the classes the operations belong to, e.g. "CRUD"
	ApprovalCode string   `json:"approvalCode,omitempty"` // approval number of the latest change (승인번호)
	ChangedBy    string   `json:"changedBy,omitempty"`
	ChangedAt    string   `json:"changedAt,omitempty"`
}

type BindingJSON struct {
	Client     string   `json:"client"`
	Group      string   `json:"group"`
	GroupKind  string   `json:"groupKind"`
	Template   string   `json:"template"`
	Operations []string `json:"operations"`
	// evidence of the approved grant
	ApprovalCode    string `json:"approvalCode,omitempty"` // 승인번호
	Owner           string `json:"owner,omitempty"`        // 담당자
	GrantedBy       string `json:"grantedBy,omitempty"`
	GrantedAt       string `json:"grantedAt,omitempty"`
	MissingEvidence bool   `json:"missingEvidence"` // granted before approval numbers were required
}

type ManagerJSON struct {
	Identity  string `json:"identity"`
	Scope     string `json:"scope"`
	ScopeKind string `json:"scopeKind"`
	Role      string `json:"role"` // admin | audit
	Root      bool   `json:"root"` // configured at start-up, not revocable here
	// evidence of the approved grant
	ApprovalCode    string `json:"approvalCode,omitempty"` // 승인번호
	Owner           string `json:"owner,omitempty"`        // 담당자
	GrantedBy       string `json:"grantedBy,omitempty"`
	GrantedAt       string `json:"grantedAt,omitempty"`
	MissingEvidence bool   `json:"missingEvidence"`
}

// grantFromQuery reads the optional evidence of a removal (?approvalCode=..&owner=..).
func grantFromQuery(r *http.Request) kms.GrantInfo {
	return kms.GrantInfo{Approval: r.URL.Query().Get("approvalCode"), Owner: r.URL.Query().Get("owner")}
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
		done(w, a.Svc.DeleteGroup(p, r.PathValue("name"), grantFromQuery(r)), "deleted")
	}))

	a.mux.HandleFunc("GET /admin/v1/templates", h(a.templates))
	a.mux.HandleFunc("POST /admin/v1/templates", h(a.putTemplate(true)))
	a.mux.HandleFunc("PUT /admin/v1/templates/{name}", h(a.putTemplate(false)))
	a.mux.HandleFunc("DELETE /admin/v1/templates/{name}", h(func(w http.ResponseWriter, r *http.Request, p kms.Principal) {
		done(w, a.Svc.DeleteTemplate(p, r.PathValue("name"), grantFromQuery(r)), "deleted")
	}))

	a.mux.HandleFunc("GET /admin/v1/bindings", h(a.bindings))
	a.mux.HandleFunc("PUT /admin/v1/bindings", h(func(w http.ResponseWriter, r *http.Request, p kms.Principal) {
		var b struct {
			Client       string `json:"client"`
			Group        string `json:"group"`
			Template     string `json:"template"`
			ApprovalCode string `json:"approvalCode"`
			Owner        string `json:"owner"`
		}
		if err := decode(r, &b); err != nil {
			fail(w, err)
			return
		}
		done(w, a.Svc.PutBinding(p, b.Client, b.Group, b.Template, kms.GrantInfo{Approval: b.ApprovalCode, Owner: b.Owner}), "saved")
	}))
	a.mux.HandleFunc("DELETE /admin/v1/bindings", h(func(w http.ResponseWriter, r *http.Request, p kms.Principal) {
		done(w, a.Svc.DeleteBinding(p, r.URL.Query().Get("client"), r.URL.Query().Get("group"), grantFromQuery(r)), "deleted")
	}))

	a.mux.HandleFunc("GET /admin/v1/managers", h(a.managers))
	a.mux.HandleFunc("PUT /admin/v1/managers", h(func(w http.ResponseWriter, r *http.Request, p kms.Principal) {
		var m struct {
			Identity     string `json:"identity"`
			Scope        string `json:"scope"`
			Role         string `json:"role"`
			ApprovalCode string `json:"approvalCode"`
			Owner        string `json:"owner"`
		}
		if err := decode(r, &m); err != nil {
			fail(w, err)
			return
		}
		done(w, a.Svc.PutManager(p, m.Identity, m.Scope, m.Role, kms.GrantInfo{Approval: m.ApprovalCode, Owner: m.Owner}), "saved")
	}))
	a.mux.HandleFunc("DELETE /admin/v1/managers", h(func(w http.ResponseWriter, r *http.Request, p kms.Principal) {
		done(w, a.Svc.DeleteManager(p, r.URL.Query().Get("identity"), r.URL.Query().Get("scope"), grantFromQuery(r)), "deleted")
	}))

	a.mux.HandleFunc("GET /admin/v1/keys", h(func(w http.ResponseWriter, r *http.Request, p kms.Principal) {
		writeJSON(w, 200, keyList(a.Svc, p, a.Svc.List(p, filterFrom(r))))
	}))
	a.mux.HandleFunc("GET /admin/v1/keys/{id}", h(func(w http.ResponseWriter, r *http.Request, p kms.Principal) {
		if !validID(r.PathValue("id")) {
			failWith(w, http.StatusNotFound, "not_found", "no such object")
			return
		}
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
		if !validID(r.PathValue("id")) {
			failWith(w, http.StatusNotFound, "not_found", "no such object")
			return
		}
		out, err := doAction(a.Svc, p, r.PathValue("id"), r.PathValue("action"))
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, 200, out)
	}))

	a.mux.HandleFunc("GET /admin/v1/logs/{which}", h(a.logs))
	a.mux.HandleFunc("GET /admin/v1/audit/verify", h(a.auditVerify))
	a.mux.HandleFunc("GET /admin/v1/audit/export", h(a.auditExport))
	a.mux.HandleFunc("GET /admin/v1/audit/reviews", h(a.auditReviews))
	a.mux.HandleFunc("POST /admin/v1/audit/reviews", h(a.auditReview))
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
		a.Log.Add(logs.Entry{Plane: "admin", Kind: "request", Who: who, Via: via, Op: r.Method + " " + r.URL.Path, Detail: "request " + w.Header().Get("X-Request-Id"), Result: res, Remote: remoteIP(r), RequestID: w.Header().Get("X-Request-Id")})
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
		out = append(out, GroupJSON{Name: g.Name, Kind: g.Kind, Parent: g.Parent, Description: g.Description, Owner: g.Owner, Builtin: g.Builtin, CreatedAt: ts(g.Created),
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
			Owner       string `json:"owner"`
		}
		if err := decode(r, &b); err != nil {
			fail(w, err)
			return
		}
		if !create {
			b.Name = r.PathValue("name")
		}
		err := a.Svc.PutGroup(p, kms.GroupReq{Name: b.Name, Kind: b.Kind, Parent: b.Parent, Description: b.Description, Owner: b.Owner}, create)
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
	tpls, err := a.Svc.Templates(p)
	if err != nil {
		fail(w, err)
		return
	}
	out := []TemplateJSON{}
	for _, t := range tpls {
		out = append(out, TemplateJSON{Name: t.Name, Description: t.Description, Builtin: t.Builtin, Operations: t.Operations, CRUD: crud(t.Operations),
			ApprovalCode: t.Approval, ChangedBy: t.ChangedBy, ChangedAt: ts(t.ChangedAt)})
	}
	writeJSON(w, 200, map[string]any{"count": len(out), "templates": out})
}

func (a *Admin) putTemplate(create bool) func(http.ResponseWriter, *http.Request, kms.Principal) {
	return func(w http.ResponseWriter, r *http.Request, p kms.Principal) {
		var b struct {
			Name         string   `json:"name"`
			Description  string   `json:"description"`
			Operations   []string `json:"operations"`
			ApprovalCode string   `json:"approvalCode"`
			Owner        string   `json:"owner"`
		}
		if err := decode(r, &b); err != nil {
			fail(w, err)
			return
		}
		if !create {
			b.Name = r.PathValue("name")
		}
		if err := a.Svc.PutTemplate(p, b.Name, b.Description, b.Operations, create, kms.GrantInfo{Approval: b.ApprovalCode, Owner: b.Owner}); err != nil {
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
	tpls, _ := a.Svc.Templates(p)
	ops := map[string][]string{}
	for _, t := range tpls {
		ops[t.Name] = t.Operations
	}
	gs, _ := a.Svc.Groups(p)
	kind := map[string]string{}
	for _, g := range gs {
		kind[g.Name] = g.Kind
	}
	out := []BindingJSON{}
	for _, b := range bs {
		out = append(out, BindingJSON{Client: b.Client, Group: b.Group, GroupKind: kind[b.Group], Template: b.Template, Operations: ops[b.Template],
			ApprovalCode: b.Approval, Owner: b.Owner, GrantedBy: b.GrantedBy, GrantedAt: ts(b.GrantedAt), MissingEvidence: b.Approval == "" || b.Owner == ""})
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
		out = append(out, ManagerJSON{Identity: m.Identity, Scope: m.Scope, ScopeKind: kind[m.Scope], Role: strings.TrimSuffix(strings.TrimSuffix(m.Role, " (root)"), "(root)"), Root: root,
			ApprovalCode: m.Approval, Owner: m.Owner, GrantedBy: m.GrantedBy, GrantedAt: ts(m.GrantedAt), MissingEvidence: !root && (m.Approval == "" || m.Owner == "")})
	}
	writeJSON(w, 200, map[string]any{"count": len(out), "managers": out})
}

func (a *Admin) pick(w http.ResponseWriter, name string) *logs.Log {
	switch name {
	case "client":
		return a.ClientLog
	case "admin":
		return a.Log
	}
	fail(w, &kms.Error{Code: kms.ErrNotFound, Msg: "unknown log"})
	return nil
}

// auditor admits identities with a global role (admin or audit): the logs span every group.
func (a *Admin) auditor(w http.ResponseWriter, p kms.Principal) bool {
	if !a.Svc.Me(p).Global {
		fail(w, &kms.Error{Code: kms.ErrDenied, Msg: "audit data is available to global administrators and auditors only"})
		return false
	}
	return true
}

// FilterFromQuery reads the common audit filter parameters (from/to as RFC 3339 or YYYY-MM-DD).
func FilterFromQuery(q map[string][]string) (logs.Filter, error) {
	get := func(k string) string {
		if v := q[k]; len(v) > 0 {
			return strings.TrimSpace(v[0])
		}
		return ""
	}
	f := logs.Filter{Category: get("category"), Outcome: get("outcome"), Who: get("who"), Op: get("op"), Text: get("q")}
	for k, dst := range map[string]*time.Time{"from": &f.From, "to": &f.To} {
		if v := get(k); v != "" {
			t, err := time.Parse(time.RFC3339, v)
			if err != nil {
				if t, err = time.Parse("2006-01-02", v); err != nil {
					return f, &kms.Error{Code: kms.ErrInvalid, Msg: k + " must be RFC 3339 or YYYY-MM-DD"}
				}
				if k == "to" {
					t = t.AddDate(0, 0, 1) // a date means the whole day
				}
			}
			*dst = t
		}
	}
	if v, err := strconv.Atoi(get("limit")); err == nil && v > 0 && v <= 20000 {
		f.Limit = v
	}
	return f, nil
}

func filterText(r *http.Request) string {
	q := r.URL.Query()
	q.Del("limit")
	return q.Encode()
}

// logs serves the client log or the administration log. Reading them is itself recorded.
func (a *Admin) logs(w http.ResponseWriter, r *http.Request, p kms.Principal) {
	if !a.auditor(w, p) {
		return
	}
	lg := a.pick(w, r.PathValue("which"))
	if lg == nil {
		return
	}
	f, err := FilterFromQuery(r.URL.Query())
	if err != nil {
		fail(w, err)
		return
	}
	if f.Limit == 0 {
		f.Limit = 500
	}
	if f.Limit > 2000 {
		f.Limit = 2000
	}
	entries, err := lg.Query(f)
	if err != nil {
		fail(w, err)
		return
	}
	a.Log.Add(logs.Entry{Plane: "admin", Kind: "event", Who: p.Name, Op: "audit-view", Target: r.PathValue("which"), Result: "ok",
		Detail: "filter: " + filterText(r), Remote: remoteIP(r), RequestID: w.Header().Get("X-Request-Id")})
	writeJSON(w, 200, map[string]any{"log": r.PathValue("which"), "count": len(entries), "entries": entries})
}

// auditVerify checks the hash chain and MACs of a log.
func (a *Admin) auditVerify(w http.ResponseWriter, r *http.Request, p kms.Principal) {
	if !a.auditor(w, p) {
		return
	}
	lg := a.pick(w, r.URL.Query().Get("log"))
	if lg == nil {
		return
	}
	rep, err := lg.Verify(a.MACKey)
	if err != nil {
		fail(w, err)
		return
	}
	res := "ok"
	if !rep.OK {
		res = "error: integrity violation: " + rep.Problem
	}
	a.Log.Add(logs.Entry{Plane: "admin", Kind: "event", Who: p.Name, Op: "audit-verify", Target: lg.Name(), Result: res, Remote: remoteIP(r),
		Detail: "entries=" + strconv.Itoa(rep.Entries) + " " + rep.Where, RequestID: w.Header().Get("X-Request-Id")})
	writeJSON(w, 200, rep)
}

// auditExport streams a zip with the matching entries and a manifest (evidence for an inspection).
func (a *Admin) auditExport(w http.ResponseWriter, r *http.Request, p kms.Principal) {
	if !a.auditor(w, p) {
		return
	}
	lg := a.pick(w, r.URL.Query().Get("log"))
	if lg == nil {
		return
	}
	f, err := FilterFromQuery(r.URL.Query())
	if err != nil {
		fail(w, err)
		return
	}
	var buf bytes.Buffer
	m, err := lg.Export(&buf, f, p.Name, a.MACKey)
	if err != nil {
		fail(w, err)
		return
	}
	a.Log.Add(logs.Entry{Plane: "admin", Kind: "event", Who: p.Name, Op: "audit-export", Target: lg.Name(), Result: "ok", Remote: remoteIP(r),
		Detail: "entries=" + strconv.Itoa(m.Entries) + " sha256=" + m.DataSHA256 + " filter: " + filterText(r), RequestID: w.Header().Get("X-Request-Id")})
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="audit-`+lg.Name()+"-"+time.Now().UTC().Format("20060102-150405")+`.zip"`)
	_, _ = w.Write(buf.Bytes())
}

type reviewReq struct {
	Log          string `json:"log"`
	From         string `json:"from"`
	To           string `json:"to"`
	Finding      string `json:"finding"` // none | anomaly
	Note         string `json:"note"`
	ApprovalCode string `json:"approvalCode"`
}

// auditReview records that a reviewer examined a period of a log (periodic log review evidence).
func (a *Admin) auditReview(w http.ResponseWriter, r *http.Request, p kms.Principal) {
	if !a.auditor(w, p) {
		return
	}
	var in reviewReq
	if err := decode(r, &in); err != nil {
		fail(w, err)
		return
	}
	lg := a.pick(w, in.Log)
	if lg == nil {
		return
	}
	if in.Finding != "none" && in.Finding != "anomaly" {
		failWith(w, http.StatusBadRequest, "invalid_request", "finding must be none or anomaly")
		return
	}
	if len(in.Note) > 1000 || len(in.From) > 40 || len(in.To) > 40 || in.From == "" || in.To == "" {
		failWith(w, http.StatusBadRequest, "invalid_request", "from, to and a note of at most 1000 characters are required")
		return
	}
	if in.Finding == "anomaly" && strings.TrimSpace(in.Note) == "" {
		failWith(w, http.StatusBadRequest, "invalid_request", "describe the anomaly in the note")
		return
	}
	for _, v := range []string{in.Note, in.From, in.To} {
		if strings.ContainsAny(v, "\x00\r\n") {
			failWith(w, http.StatusBadRequest, "invalid_request", "control characters are not allowed")
			return
		}
	}
	if in.ApprovalCode != "" && !kms.ValidApproval(in.ApprovalCode) {
		failWith(w, http.StatusBadRequest, "invalid_request", "invalid approval number")
		return
	}
	a.Log.Add(logs.Entry{Plane: "admin", Kind: "event", Who: p.Name, Op: "audit-review", Target: lg.Name(), Result: "ok", Remote: remoteIP(r),
		Category: "audit-access", Approval: in.ApprovalCode, RequestID: w.Header().Get("X-Request-Id"),
		Detail: "period " + in.From + " .. " + in.To + "; finding=" + in.Finding + "; " + in.Note})
	writeJSON(w, 201, map[string]any{"result": "recorded", "reviewer": p.Name})
}

// auditReviews lists the recorded reviews.
func (a *Admin) auditReviews(w http.ResponseWriter, r *http.Request, p kms.Principal) {
	if !a.auditor(w, p) {
		return
	}
	ents, err := a.Log.Query(logs.Filter{Op: "audit-review", Limit: 500})
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"count": len(ents), "reviews": ents})
}
