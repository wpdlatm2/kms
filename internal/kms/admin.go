package kms

import (
	"regexp"
	"slices"
	"sort"
	"strings"
)

// ---- scopes: who may do what (the evaluation rules)

// parentOf returns the super group of a service ("" if none). The caller holds the store lock.
func (s *Service) parentOf(service string) string {
	if g := s.st.groups[service]; g != nil {
		return g.Parent
	}
	return ""
}

// covers reports whether a management scope includes a service. The caller holds the store lock.
func (s *Service) covers(scope, service string) bool {
	return scope == GroupAll || scope == service || (scope != "" && scope == s.parentOf(service))
}

// adminCan reports whether the administration identity holds a role (admin, or audit for reads) over a service.
func (s *Service) adminCan(p Principal, service string, write bool) bool {
	for _, sc := range p.Scopes {
		if s.covers(sc.Group, service) && (sc.Role == RoleAdmin || !write) {
			return true
		}
	}
	return false
}

// isGlobal reports a global administrator (write) or any global role (read).
func isGlobal(p Principal, write bool) bool {
	for _, sc := range p.Scopes {
		if sc.Group == GroupAll && (sc.Role == RoleAdmin || !write) {
			return true
		}
	}
	return false
}

// manages reports whether the identity holds the admin role over a group itself (a service, a super group or
// ALL): the right to change that group's mappings and management grants. An administrator of a super group
// also manages the services inside it.
func (s *Service) manages(p Principal, scope string, write bool) bool {
	for _, sc := range p.Scopes {
		if sc.Role != RoleAdmin && write {
			continue
		}
		if sc.Group == GroupAll || sc.Group == scope {
			return true
		}
		if g := s.st.groups[scope]; g != nil && g.Kind == KindService && g.Parent != "" && g.Parent == sc.Group {
			return true
		}
	}
	return false
}

// can reports whether the principal may perform op on keys of the service. The caller holds the store lock.
// Client bindings count when they name the service, its super group or ALL.
func (s *Service) can(p Principal, service, op string) bool {
	if p.Plane == PlaneAdmin {
		if op == "get" {
			return false // administrators manage keys but are never handed key values
		}
		write := op != "locate" && op != "getattributes"
		return s.adminCan(p, service, write)
	}
	parent := s.parentOf(service)
	for _, b := range s.st.bindings {
		if b.Client != p.Name || (b.Group != service && b.Group != GroupAll && (parent == "" || b.Group != parent)) {
			continue
		}
		if t := s.st.templates[b.Template]; t != nil && slices.Contains(t.Operations, op) {
			return true
		}
	}
	return false
}

// writeOK rejects an administration identity that holds no write role at all.
func writeOK(p Principal) *Error {
	if p.Plane == PlaneAdmin {
		for _, sc := range p.Scopes {
			if sc.Role == RoleAdmin {
				return nil
			}
		}
		return errf(ErrDenied, "this administration identity is read-only")
	}
	return nil
}

// ---- permission model: services, super groups, templates, bindings, managers (administration plane)

var nameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

func adminOnly(p Principal) *Error {
	if p.Plane != PlaneAdmin {
		return errf(ErrDenied, "administration only")
	}
	if len(p.Scopes) == 0 {
		return errf(ErrDenied, "this identity holds no administration role")
	}
	return nil
}

// persist saves the database; on failure it undoes the in-memory change. It returns a plain error so a
// nil result is a nil interface.
func (s *Service) persist(restore func()) error {
	if err := s.st.save(); err != nil {
		restore()
		return persistErr(err)
	}
	return nil
}

func badIdent(x string) bool {
	return x == "" || len(x) > 128 || x == "*" || badText(x)
}

// Me describes the management rights of an administration identity.
type Me struct {
	Name   string  `json:"name"`
	Scopes []Scope `json:"scopes"`
	Global bool    `json:"global"`
	Writer bool    `json:"writer"`
}

func (s *Service) Me(p Principal) Me {
	return Me{Name: p.Name, Scopes: append([]Scope{}, p.Scopes...), Global: isGlobal(p, false), Writer: writeOK(p) == nil}
}

// GroupInfo is a group with its key count and members.
type GroupInfo struct {
	Group
	Keys        int            `json:"keys"`
	KeysByState map[string]int `json:"keysByState"`
	Services    []string       `json:"services,omitempty"` // for a super group
	Clients     int            `json:"clients"`            // mappings of this group
	Managers    int            `json:"managers"`
}

// visibleGroup reports whether the identity may see the group (a read role over it or over a service inside).
func (s *Service) visibleGroup(p Principal, g *Group) bool {
	switch g.Kind {
	case KindAll:
		return isGlobal(p, false)
	case KindService:
		return s.adminCan(p, g.Name, false)
	}
	for _, sc := range p.Scopes {
		if sc.Group == GroupAll || sc.Group == g.Name {
			return true
		}
	}
	for _, m := range s.st.groups {
		if m.Kind == KindService && m.Parent == g.Name && s.adminCan(p, m.Name, false) {
			return true
		}
	}
	return false
}

// Groups lists the groups the identity can see.
func (s *Service) Groups(p Principal) ([]GroupInfo, error) {
	if e := adminOnly(p); e != nil {
		return nil, e
	}
	s.st.mu.RLock()
	defer s.st.mu.RUnlock()
	count := map[string]int{}
	byState := map[string]map[string]int{}
	for _, o := range s.st.objs {
		count[o.Group]++
		if byState[o.Group] == nil {
			byState[o.Group] = map[string]int{}
		}
		byState[o.Group][StateID(o.State)]++
	}
	clients, mgrs := map[string]int{}, map[string]int{}
	for _, b := range s.st.bindings {
		clients[b.Group]++
	}
	for _, m := range s.st.managers {
		mgrs[m.Scope]++
	}
	members := map[string][]string{}
	for _, g := range s.st.groups {
		if g.Kind == KindService && g.Parent != "" {
			members[g.Parent] = append(members[g.Parent], g.Name)
		}
	}
	rank := map[string]int{KindAll: 0, KindSuper: 1, KindService: 2}
	out := []GroupInfo{}
	for _, g := range s.st.groups {
		if !s.visibleGroup(p, g) {
			continue
		}
		gi := GroupInfo{Group: *g, Keys: count[g.Name], KeysByState: byState[g.Name], Services: members[g.Name], Clients: clients[g.Name], Managers: mgrs[g.Name]}
		if gi.KeysByState == nil {
			gi.KeysByState = map[string]int{}
		}
		sort.Strings(gi.Services)
		out = append(out, gi)
	}
	sort.Slice(out, func(i, j int) bool {
		if rank[out[i].Kind] != rank[out[j].Kind] {
			return rank[out[i].Kind] < rank[out[j].Kind]
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
}

// GrantInfo is the evidence that accompanies every permission change: the approval number the change was
// authorised under (승인번호) and the person responsible (담당자).
type GrantInfo struct {
	Approval string `json:"approvalCode"`
	Owner    string `json:"owner"`
}

// ValidApproval reports whether s is an acceptable approval number.
func ValidApproval(s string) bool { return approvalRe.MatchString(s) }

var approvalRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/#-]{0,63}$`)

// ValidOwner reports whether o is an acceptable responsible-person field.
func ValidOwner(o string) bool { return validOwner(o) }

func validOwner(o string) bool {
	return o != "" && len(o) <= 64 && !badText(o)
}

// validate checks the evidence fields. A grant needs both; a template change only the approval number.
func (g *GrantInfo) validate(needOwner bool) *Error {
	g.Approval, g.Owner = strings.TrimSpace(g.Approval), strings.TrimSpace(g.Owner)
	if !approvalRe.MatchString(g.Approval) {
		return errf(ErrInvalid, "approval number (승인번호) is required: 1-64 letters, digits, dot, underscore, slash, hash or hyphen")
	}
	if needOwner && !validOwner(g.Owner) {
		return errf(ErrInvalid, "owner (담당자) is required: the person responsible, at most 64 characters")
	}
	if !needOwner && g.Owner != "" && !validOwner(g.Owner) {
		return errf(ErrInvalid, "invalid owner (담당자)")
	}
	return nil
}

func optGrant(gi []GrantInfo) GrantInfo {
	if len(gi) > 0 {
		return gi[0]
	}
	return GrantInfo{}
}

// GroupReq creates or updates a group.
type GroupReq struct {
	Owner       string // the person responsible for the service / super group (required when created)
	Name        string
	Kind        string // service | super (create only)
	Parent      string // for a service: its super group ("" = none)
	Description string
}

// PutGroup creates (create=true) or updates a service or super group.
//   - creating or deleting a super group needs a global administrator;
//   - a service is created, changed or deleted by the administrator of its super group (or a global one);
//   - a service without a super group is managed by a global administrator;
//   - moving a service needs authority over both the old and the new super group.
func (s *Service) PutGroup(p Principal, r GroupReq, create bool) (err error) {
	defer func() {
		s.emitG(p, "group-put", r.Name, r.Kind+" parent="+r.Parent+" "+r.Description, GrantInfo{Owner: r.Owner}, err)
	}()
	if e := adminOnly(p); e != nil {
		return e
	}
	if e := writeOK(p); e != nil {
		return e
	}
	if !nameRe.MatchString(r.Name) {
		return errf(ErrInvalid, "name: 1-64 letters, digits, dot, underscore or hyphen")
	}
	if len(r.Description) > 256 || badText(r.Description) {
		return errf(ErrInvalid, "description is too long")
	}
	owner := strings.TrimSpace(r.Owner)
	if (create && owner == "") || (owner != "" && !validOwner(owner)) {
		return errf(ErrInvalid, "owner (담당자) is required: the person responsible for the group, at most 64 characters")
	}
	r.Owner = owner
	s.st.mu.Lock()
	defer s.st.mu.Unlock()
	g := s.st.groups[r.Name]
	if create {
		if g != nil {
			return errf(ErrConflict, "%q exists", r.Name)
		}
		switch r.Kind {
		case KindSuper:
			if !isGlobal(p, true) {
				return errf(ErrDenied, "only a global administrator creates super groups")
			}
			s.st.groups[r.Name] = &Group{Name: r.Name, Kind: KindSuper, Description: r.Description, Owner: owner, Created: now()}
		case KindService:
			if e := s.checkParent(p, "", r.Parent, false); e != nil {
				return e
			}
			s.st.groups[r.Name] = &Group{Name: r.Name, Kind: KindService, Parent: r.Parent, Description: r.Description, Owner: owner, Created: now()}
		default:
			return errf(ErrInvalid, "kind must be service or super")
		}
		return s.persist(func() { delete(s.st.groups, r.Name) })
	}
	if g == nil || g.Builtin {
		return errf(ErrNotFound, "no such group")
	}
	old := *g
	switch g.Kind {
	case KindSuper:
		if !s.manages(p, g.Name, true) {
			return errf(ErrDenied, "no management right over %q", g.Name)
		}
		g.Description = r.Description
		if owner != "" {
			g.Owner = owner
		}
	case KindService:
		if e := s.checkParent(p, g.Parent, r.Parent, true); e != nil {
			return e
		}
		g.Description, g.Parent = r.Description, r.Parent
		if owner != "" {
			g.Owner = owner
		}
	}
	return s.persist(func() { *g = old })
}

// checkParent verifies the authority to place a service under newParent (and, when moving, to take it out of
// oldParent). A service without a super group is a global administrator's business.
func (s *Service) checkParent(p Principal, oldParent, newParent string, existing bool) *Error {
	pars := []string{newParent}
	if existing {
		pars = append(pars, oldParent)
	}
	for _, par := range pars {
		if par == "" {
			if !isGlobal(p, true) {
				return errf(ErrDenied, "a service without a super group is managed by a global administrator")
			}
			continue
		}
		pg := s.st.groups[par]
		if pg == nil || pg.Kind != KindSuper {
			return errf(ErrInvalid, "unknown super group %q", par)
		}
		if !s.manages(p, par, true) {
			return errf(ErrDenied, "no management right over super group %q", par)
		}
	}
	return nil
}

func (s *Service) DeleteGroup(p Principal, name string, gi ...GrantInfo) (err error) {
	defer func() { s.emitG(p, "group-delete", name, "", optGrant(gi), err) }()
	if e := adminOnly(p); e != nil {
		return e
	}
	if e := writeOK(p); e != nil {
		return e
	}
	s.st.mu.Lock()
	defer s.st.mu.Unlock()
	g := s.st.groups[name]
	if g == nil {
		return errf(ErrNotFound, "no such group")
	}
	if g.Builtin {
		return errf(ErrInvalid, "the %s group cannot be deleted", name)
	}
	if g.Kind == KindSuper {
		if !isGlobal(p, true) {
			return errf(ErrDenied, "only a global administrator deletes super groups")
		}
		for _, m := range s.st.groups {
			if m.Parent == name {
				return errf(ErrConflict, "super group %q still contains service %q", name, m.Name)
			}
		}
	} else {
		if !s.manages(p, name, true) {
			return errf(ErrDenied, "no management right over %q", name)
		}
		for _, o := range s.st.objs {
			if o.Group == name {
				return errf(ErrConflict, "service %q still contains keys", name)
			}
		}
	}
	oldB, oldM := slices.Clone(s.st.bindings), slices.Clone(s.st.managers)
	delete(s.st.groups, name)
	s.st.bindings = slices.DeleteFunc(s.st.bindings, func(b Binding) bool { return b.Group == name })
	s.st.managers = slices.DeleteFunc(s.st.managers, func(m Manager) bool { return m.Scope == name })
	return s.persist(func() { s.st.groups[name] = g; s.st.bindings = oldB; s.st.managers = oldM })
}

// Templates lists permission templates (every administration identity may read them).
func (s *Service) Templates(p Principal) ([]Template, error) {
	if e := adminOnly(p); e != nil {
		return nil, e
	}
	s.st.mu.RLock()
	defer s.st.mu.RUnlock()
	out := make([]Template, 0, len(s.st.templates))
	for _, t := range s.st.templates {
		c := *t
		c.Operations = slices.Clone(t.Operations)
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Builtin != out[j].Builtin {
			return out[i].Builtin
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
}

// PutTemplate creates (create=true) or updates a template (global administrators only: templates are shared
// by every group). Built-in templates (owner, guest) may be edited but not deleted.
func (s *Service) PutTemplate(p Principal, name, description string, ops []string, create bool, gi GrantInfo) (err error) {
	detail := strings.Join(ops, ",")
	defer func() { s.emitG(p, "template-put", name, detail, gi, err) }()
	if e := adminOnly(p); e != nil {
		return e
	}
	if !isGlobal(p, true) {
		return errf(ErrDenied, "templates are shared by all groups: only a global administrator edits them")
	}
	if e := gi.validate(false); e != nil {
		return e
	}
	if !nameRe.MatchString(name) {
		return errf(ErrInvalid, "template name: 1-64 letters, digits, dot, underscore or hyphen")
	}
	if len(description) > 256 || badText(description) {
		return errf(ErrInvalid, "description is too long")
	}
	if len(ops) == 0 {
		return errf(ErrInvalid, "choose at least one operation")
	}
	for _, o := range ops {
		if !slices.Contains(Operations, o) {
			return errf(ErrInvalid, "unknown operation %q", o)
		}
	}
	var clean []string
	for _, o := range Operations { // canonical order, no duplicates
		if slices.Contains(ops, o) {
			clean = append(clean, o)
		}
	}
	s.st.mu.Lock()
	defer s.st.mu.Unlock()
	t := s.st.templates[name]
	if create {
		if t != nil {
			return errf(ErrConflict, "template %q exists", name)
		}
		s.st.templates[name] = &Template{Name: name, Description: description, Operations: clean, Approval: gi.Approval, ChangedBy: p.Name, ChangedAt: now()}
		return s.persist(func() { delete(s.st.templates, name) })
	}
	if t == nil {
		return errf(ErrNotFound, "no such template")
	}
	old := *t
	detail = "before=" + strings.Join(old.Operations, ",") + " (approval " + old.Approval + ") after=" + strings.Join(clean, ",")
	t.Description, t.Operations = description, clean
	t.Approval, t.ChangedBy, t.ChangedAt = gi.Approval, p.Name, now()
	return s.persist(func() { *t = old })
}

func (s *Service) DeleteTemplate(p Principal, name string, gi ...GrantInfo) (err error) {
	defer func() { s.emitG(p, "template-delete", name, "", optGrant(gi), err) }()
	if e := adminOnly(p); e != nil {
		return e
	}
	if !isGlobal(p, true) {
		return errf(ErrDenied, "only a global administrator deletes templates")
	}
	s.st.mu.Lock()
	defer s.st.mu.Unlock()
	t := s.st.templates[name]
	if t == nil {
		return errf(ErrNotFound, "no such template")
	}
	if t.Builtin {
		return errf(ErrInvalid, "the built-in template %q cannot be deleted (it can be edited)", name)
	}
	for _, b := range s.st.bindings {
		if b.Template == name {
			return errf(ErrConflict, "template %q is used by client %q", name, b.Client)
		}
	}
	delete(s.st.templates, name)
	return s.persist(func() { s.st.templates[name] = t })
}

// Bindings lists the client mappings of groups the identity can see.
func (s *Service) Bindings(p Principal) ([]Binding, error) {
	if e := adminOnly(p); e != nil {
		return nil, e
	}
	s.st.mu.RLock()
	defer s.st.mu.RUnlock()
	out := []Binding{}
	for _, b := range s.st.bindings {
		if g := s.st.groups[b.Group]; g != nil && s.visibleGroup(p, g) {
			out = append(out, b)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Client != out[j].Client {
			return out[i].Client < out[j].Client
		}
		return out[i].Group < out[j].Group
	})
	return out, nil
}

// PutBinding maps a client to a template in a group (replacing the client's earlier mapping for that group).
// The group may be a service, a super group (all its services) or ALL (everything). It needs management
// authority over that group.
func (s *Service) PutBinding(p Principal, client, group, template string, gi GrantInfo) (err error) {
	detail := group + " -> " + template
	defer func() { s.emitG(p, "binding-put", client, detail, gi, err) }()
	if e := adminOnly(p); e != nil {
		return e
	}
	if e := writeOK(p); e != nil {
		return e
	}
	client = strings.TrimSpace(client)
	if badIdent(client) {
		return errf(ErrInvalid, "client must be a certificate common name (no wildcard)")
	}
	if e := gi.validate(true); e != nil {
		return e
	}
	s.st.mu.Lock()
	defer s.st.mu.Unlock()
	if s.st.groups[group] == nil {
		return errf(ErrInvalid, "unknown group %q", group)
	}
	if s.st.templates[template] == nil {
		return errf(ErrInvalid, "unknown template %q", template)
	}
	if !s.manages(p, group, true) {
		return errf(ErrDenied, "no management right over %q", group)
	}
	old := slices.Clone(s.st.bindings)
	replaced := false
	for i := range s.st.bindings {
		if b := &s.st.bindings[i]; b.Client == client && b.Group == group {
			detail = group + ": " + b.Template + " (approval " + b.Approval + ", owner " + b.Owner + ") -> " + template
			b.Template, b.Approval, b.Owner, b.GrantedBy, b.GrantedAt = template, gi.Approval, gi.Owner, p.Name, now()
			replaced = true
		}
	}
	if !replaced {
		s.st.bindings = append(s.st.bindings, Binding{Client: client, Group: group, Template: template, Approval: gi.Approval, Owner: gi.Owner, GrantedBy: p.Name, GrantedAt: now()})
	}
	return s.persist(func() { s.st.bindings = old })
}

func (s *Service) DeleteBinding(p Principal, client, group string, gi ...GrantInfo) (err error) {
	detail := group
	defer func() { s.emitG(p, "binding-delete", client, detail, optGrant(gi), err) }()
	if e := adminOnly(p); e != nil {
		return e
	}
	if e := writeOK(p); e != nil {
		return e
	}
	s.st.mu.Lock()
	defer s.st.mu.Unlock()
	if !s.manages(p, group, true) {
		return errf(ErrDenied, "no management right over %q", group)
	}
	old := slices.Clone(s.st.bindings)
	n := len(s.st.bindings)
	for _, b := range s.st.bindings {
		if b.Client == client && b.Group == group {
			detail = group + ": removed " + b.Template + " (approval " + b.Approval + ", owner " + b.Owner + ")"
		}
	}
	s.st.bindings = slices.DeleteFunc(s.st.bindings, func(b Binding) bool { return b.Client == client && b.Group == group })
	if len(s.st.bindings) == n {
		return errf(ErrNotFound, "no such mapping")
	}
	return s.persist(func() { s.st.bindings = old })
}

// ---- delegated management

// Managers lists the management grants inside the identity's visible scope (root administrators included
// for global identities).
func (s *Service) Managers(p Principal) ([]Manager, error) {
	if e := adminOnly(p); e != nil {
		return nil, e
	}
	s.st.mu.RLock()
	defer s.st.mu.RUnlock()
	out := []Manager{}
	if isGlobal(p, false) {
		for _, r := range s.rootAdmins {
			out = append(out, Manager{Identity: r, Scope: GroupAll, Role: RoleAdmin + " (root)"})
		}
	}
	for _, m := range s.st.managers {
		if g := s.st.groups[m.Scope]; g != nil && s.visibleGroup(p, g) {
			out = append(out, m)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Identity != out[j].Identity {
			return out[i].Identity < out[j].Identity
		}
		return out[i].Scope < out[j].Scope
	})
	return out, nil
}

// PutManager grants an identity the admin or audit role over a scope. The grantor needs the admin role over
// that scope: a super-group administrator may delegate inside the super group; only a global administrator
// grants rights over ALL.
func (s *Service) PutManager(p Principal, identity, scope, role string, gi GrantInfo) (err error) {
	detail := scope + " " + role
	defer func() { s.emitG(p, "manager-put", identity, detail, gi, err) }()
	if e := adminOnly(p); e != nil {
		return e
	}
	if e := writeOK(p); e != nil {
		return e
	}
	identity = strings.TrimSpace(identity)
	if badIdent(identity) {
		return errf(ErrInvalid, "identity must be a user or certificate name (no wildcard)")
	}
	if e := gi.validate(true); e != nil {
		return e
	}
	if role != RoleAdmin && role != RoleAudit {
		return errf(ErrInvalid, "role must be admin or audit")
	}
	s.st.mu.Lock()
	defer s.st.mu.Unlock()
	if s.st.groups[scope] == nil {
		return errf(ErrInvalid, "unknown scope %q", scope)
	}
	if !s.manages(p, scope, true) {
		return errf(ErrDenied, "no management right over %q", scope)
	}
	old := slices.Clone(s.st.managers)
	replaced := false
	for i := range s.st.managers {
		if m := &s.st.managers[i]; m.Identity == identity && m.Scope == scope {
			detail = scope + ": " + m.Role + " (approval " + m.Approval + ", owner " + m.Owner + ") -> " + role
			m.Role, m.Approval, m.Owner, m.GrantedBy, m.GrantedAt = role, gi.Approval, gi.Owner, p.Name, now()
			replaced = true
		}
	}
	if !replaced {
		s.st.managers = append(s.st.managers, Manager{Identity: identity, Scope: scope, Role: role, Approval: gi.Approval, Owner: gi.Owner, GrantedBy: p.Name, GrantedAt: now()})
	}
	return s.persist(func() { s.st.managers = old })
}

func (s *Service) DeleteManager(p Principal, identity, scope string, gi ...GrantInfo) (err error) {
	detail := scope
	defer func() { s.emitG(p, "manager-delete", identity, detail, optGrant(gi), err) }()
	if e := adminOnly(p); e != nil {
		return e
	}
	if e := writeOK(p); e != nil {
		return e
	}
	s.st.mu.Lock()
	defer s.st.mu.Unlock()
	if !s.manages(p, scope, true) {
		return errf(ErrDenied, "no management right over %q", scope)
	}
	old := slices.Clone(s.st.managers)
	n := len(s.st.managers)
	for _, m := range s.st.managers {
		if m.Identity == identity && m.Scope == scope {
			detail = scope + ": removed " + m.Role + " (approval " + m.Approval + ", owner " + m.Owner + ")"
		}
	}
	s.st.managers = slices.DeleteFunc(s.st.managers, func(m Manager) bool { return m.Identity == identity && m.Scope == scope })
	if len(s.st.managers) == n {
		return errf(ErrNotFound, "no such management grant")
	}
	return s.persist(func() { s.st.managers = old })
}
