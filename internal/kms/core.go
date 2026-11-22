package kms

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"sort"
	"strings"
)

// State is the KMIP lifecycle state (values as in the KMIP specification).
type State uint32

const (
	PreActive            State = 1
	Active               State = 2
	Deactivated          State = 3
	Compromised          State = 4
	Destroyed            State = 5
	DestroyedCompromised State = 6
)

// StateID returns the REST name of a state: pre-active, active, deactivated, compromised, destroyed,
// destroyed-compromised.
func StateID(s State) string {
	switch s {
	case PreActive:
		return "pre-active"
	case Active:
		return "active"
	case Deactivated:
		return "deactivated"
	case Compromised:
		return "compromised"
	case Destroyed:
		return "destroyed"
	case DestroyedCompromised:
		return "destroyed-compromised"
	}
	return "unknown"
}

// ParseState parses a state name (any case; space or hyphen separated).
func ParseState(q string) (State, bool) {
	q = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(q), " ", "-"))
	for st := PreActive; st <= DestroyedCompromised; st++ {
		if StateID(st) == q {
			return st, true
		}
	}
	return 0, false
}

func (s State) String() string {
	switch s {
	case PreActive:
		return "Pre-Active"
	case Active:
		return "Active"
	case Deactivated:
		return "Deactivated"
	case Compromised:
		return "Compromised"
	case Destroyed:
		return "Destroyed"
	case DestroyedCompromised:
		return "Destroyed Compromised"
	}
	return fmt.Sprintf("state-%d", uint32(s))
}

// Object kinds (KMIP Object Type values).
const (
	KindSymmetric uint32 = 2
	KindPublic    uint32 = 3
	KindPrivate   uint32 = 4
	KindSecret    uint32 = 7
)

// GroupAll is the special permission group: a client bound to it with a template holds that template's
// operations on the keys of every group.
const GroupAll = "ALL"

// Operations are the individual rights a permission template is made of.
var Operations = []string{"create", "locate", "getattributes", "get", "activate", "revoke", "rekey", "setattribute", "destroy"}

// OpClass tells which CRUD letter an operation belongs to (for display).
var OpClass = map[string]string{
	"create": "C", "locate": "R", "getattributes": "R", "get": "R",
	"activate": "U", "revoke": "U", "rekey": "U", "setattribute": "U", "destroy": "D",
}

// Object is a managed key. It belongs to exactly one permission group.
type Object struct {
	ID       string   `json:"id"`
	Group    string   `json:"group"`
	Kind     uint32   `json:"kind"`
	Algo     string   `json:"algo"`
	Alg      uint32   `json:"alg"`
	Bits     int      `json:"bits"`
	Curve    uint32   `json:"curve,omitempty"`
	Format   uint32   `json:"format"`
	Usage    int32    `json:"usage"`
	Names    []string `json:"names"`
	State    State    `json:"state"`
	Creator  string   `json:"creator"`
	Material []byte   `json:"material,omitempty"`

	Created     int64 `json:"created"`
	Activated   int64 `json:"activated,omitempty"`
	Deactivated int64 `json:"deactivated,omitempty"`
	Compromised int64 `json:"compromised,omitempty"`
	Destroyed   int64 `json:"destroyed,omitempty"`
	Changed     int64 `json:"changed"`

	PairID       string `json:"pair,omitempty"`
	ReplacesID   string `json:"replaces,omitempty"`
	ReplacedByID string `json:"replacedBy,omitempty"`

	// derived when a View is made (not stored)
	ValueSize   int    `json:"-"`
	Fingerprint string `json:"-"` // SHA-256 of a public key (public values are not secret)
}

// View is an Object without its value (Material is nil).
type View = Object

func view(o *Object) View {
	c := *o
	c.ValueSize = len(o.Material)
	if o.Kind == KindPublic && len(o.Material) > 0 {
		sum := sha256.Sum256(o.Material)
		c.Fingerprint = hex.EncodeToString(sum[:])
	}
	c.Material = nil
	c.Names = append([]string{}, o.Names...)
	return c
}

// Group kinds. A service is the permission group keys belong to; a super group bundles services so that
// permissions and management rights can be given to all of them at once; ALL covers everything.
const (
	KindService = "service"
	KindSuper   = "super"
	KindAll     = "all"
)

// Group is a service (kind "service"; every key belongs to exactly one), a super group (kind "super") or
// the built-in ALL group. A service belongs to at most one super group (Parent).
type Group struct {
	Name        string `json:"name"`
	Kind        string `json:"kind"`
	Parent      string `json:"parent,omitempty"`
	Description string `json:"description"`
	Builtin     bool   `json:"builtin,omitempty"`
	Created     int64  `json:"created"`
}

// Manager gives an administration identity management rights over a scope: a service, a super group (all of
// its services) or ALL. Role admin manages, role audit only reads.
type Manager struct {
	Identity string `json:"identity"`
	Scope    string `json:"scope"`
	Role     string `json:"role"`
}

const (
	RoleAdmin = "admin"
	RoleAudit = "audit"
)

// Template is a named set of operations (a role such as owner or guest).
type Template struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Operations  []string `json:"operations"`
	Builtin     bool     `json:"builtin,omitempty"`
}

// Binding gives a client (certificate CN) a template's operations in a group.
type Binding struct {
	Client   string `json:"client"`
	Group    string `json:"group"`
	Template string `json:"template"`
}

// ErrCode classifies service errors for the front ends.
type ErrCode int

const (
	ErrNotFound ErrCode = iota + 1
	ErrDenied
	ErrState
	ErrInvalid
	ErrUnsupported
	ErrInternal
	ErrConflict
)

// Error is returned by every Service method.
type Error struct {
	Code ErrCode
	Msg  string
}

func (e *Error) Error() string { return e.Msg }

func errf(c ErrCode, format string, a ...any) *Error { return &Error{c, fmt.Sprintf(format, a...)} }

// Plane distinguishes the two ways the service is reached.
type Plane string

const (
	PlaneClient Plane = "client" // KMIP and the client REST API: rights come from group bindings
	PlaneAdmin  Plane = "admin"  // the administration API: manages everything, but is never handed key values
)

// Scope is one management right of an administration identity.
type Scope struct {
	Group string `json:"group"`
	Role  string `json:"role"`
}

// Principal is the authenticated caller. For the client plane Name is the certificate common name and the
// rights come from bindings; for the administration plane Scopes lists the management rights.
type Principal struct {
	Name   string
	Plane  Plane
	Scopes []Scope
}

// AuditEvent is reported for every state-changing call, every key release and every refusal.
type AuditEvent struct {
	Plane                           Plane
	Who, Op, Target, Detail, Result string
}

// Service implements the key management operations.
type Service struct {
	st         *Store
	rootAdmins []string
	Audit      func(AuditEvent)
}

// NewService creates the service. rootAdmins are administration identities that are always global
// administrators (they bootstrap the system; everyone else is configured through Managers).
func NewService(st *Store, rootAdmins []string) *Service {
	return &Service{st: st, rootAdmins: rootAdmins}
}

// ClientPrincipal is a data-plane caller; its rights come from bindings.
func ClientPrincipal(cn string) Principal { return Principal{Name: cn, Plane: PlaneClient} }

// AdminPrincipal resolves the management rights of an administration identity.
func (s *Service) AdminPrincipal(identity string) Principal {
	p := Principal{Name: identity, Plane: PlaneAdmin}
	if slices.Contains(s.rootAdmins, identity) {
		p.Scopes = append(p.Scopes, Scope{GroupAll, RoleAdmin})
	}
	s.st.mu.RLock()
	defer s.st.mu.RUnlock()
	for _, m := range s.st.managers {
		if m.Identity == identity {
			p.Scopes = append(p.Scopes, Scope{m.Scope, m.Role})
		}
	}
	return p
}

func (s *Service) emit(p Principal, op, target, detail string, err error) {
	if s.Audit == nil {
		return
	}
	res := "ok"
	if err != nil {
		res = "error: " + err.Error()
	}
	s.Audit(AuditEvent{Plane: p.Plane, Who: p.Name, Op: op, Target: target, Detail: detail, Result: res})
}

func newID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

// get returns the live object when the caller holds the right; the lock must be held.
// A caller without the right cannot tell an object exists (not found, not denied).
func (s *Service) get(p Principal, id, op string) (*Object, *Error) {
	o := s.st.objs[id]
	if o == nil || !s.can(p, o.Group, op) {
		return nil, errf(ErrNotFound, "no such object")
	}
	return o, nil
}

// ---- create

// CreateReq describes a key to generate.
type CreateReq struct {
	Algo     string
	Group    string // empty = the caller's only group in which it may create
	Names    []string
	Usage    int32 // 0 = the algorithm's default
	Activate bool
}

func cleanNames(in []string) ([]string, *Error) {
	var out []string
	for _, n := range in {
		n = strings.TrimSpace(n)
		if n == "" {
			continue
		}
		if len(n) > 128 || strings.ContainsAny(n, "\r\n\t\x00") {
			return nil, errf(ErrInvalid, "invalid key name")
		}
		if !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	return out, nil
}

// defaultGroup finds the single group a client may create keys in (bound to ALL counts as "no single group").
func (s *Service) defaultGroup(p Principal) (string, *Error) {
	var found []string
	for _, b := range s.st.bindings {
		if b.Client != p.Name {
			continue
		}
		g := s.st.groups[b.Group]
		if g == nil || g.Kind != KindService {
			continue
		}
		if t := s.st.templates[b.Template]; t != nil && slices.Contains(t.Operations, "create") && !slices.Contains(found, b.Group) {
			found = append(found, b.Group)
		}
	}
	switch {
	case len(found) == 1:
		return found[0], nil
	case len(found) == 0:
		// no service of its own to create in: either it may not create at all, or its right comes from a super group / ALL
		for _, b := range s.st.bindings {
			if t := s.st.templates[b.Template]; b.Client == p.Name && t != nil && slices.Contains(t.Operations, "create") {
				return "", errf(ErrInvalid, "a service (permission group) is required (KMIP attribute Object Group)")
			}
		}
		return "", errf(ErrDenied, "this client holds no permission to create keys")
	}
	return "", errf(ErrInvalid, "a service (permission group) is required (KMIP attribute Object Group)")
}

// Create generates a key (two objects for an asymmetric pair: private first) and returns their views.
func (s *Service) Create(p Principal, r CreateReq) (out []View, err error) {
	defer func() { s.emit(p, "create", idsOf(out), r.Group+" "+r.Algo+" "+strings.Join(r.Names, ","), err) }()
	if e := writeOK(p); e != nil {
		return nil, e
	}
	a := LookupAlgo(r.Algo)
	if a == nil {
		return nil, errf(ErrInvalid, "unknown algorithm %q", r.Algo)
	}
	names, e := cleanNames(r.Names)
	if e != nil {
		return nil, e
	}
	s.st.mu.Lock()
	defer s.st.mu.Unlock()
	group := r.Group
	if group == "" && p.Plane == PlaneAdmin {
		return nil, errf(ErrInvalid, "name the service (group) the key belongs to")
	}
	if group == "" {
		g, e := s.defaultGroup(p)
		if e != nil {
			return nil, e
		}
		group = g
	}
	g := s.st.groups[group]
	if g == nil {
		return nil, errf(ErrInvalid, "unknown service %q", group)
	}
	if g.Kind != KindService {
		return nil, errf(ErrInvalid, "keys belong to a service; %q is a %s group, a permission scope rather than a place for keys", group, g.Kind)
	}
	if !s.can(p, group, "create") {
		return nil, errf(ErrDenied, "no permission to create keys in group %q", group)
	}
	priv, pub, gerr := a.gen()
	if gerr != nil {
		return nil, errf(ErrInternal, "key generation failed: %v", gerr)
	}
	defer clear(priv)
	usage := r.Usage
	if usage == 0 {
		usage = a.Usage
	}
	t := now()
	mk := func(kind uint32, format uint32, material []byte) *Object {
		o := &Object{ID: newID(), Group: group, Kind: kind, Algo: a.ID, Alg: a.Alg, Bits: a.Bits, Curve: a.Curve, Format: format, Usage: usage,
			Names: slices.Clone(names), State: PreActive, Creator: p.Name, Material: slices.Clone(material), Created: t, Changed: t}
		if r.Activate {
			o.State, o.Activated = Active, t
		}
		return o
	}
	var objs []*Object
	if a.Pair {
		pr, pu := mk(KindPrivate, a.PrivFmt, priv), mk(KindPublic, a.PubFmt, pub)
		pr.PairID, pu.PairID = pu.ID, pr.ID
		objs = []*Object{pr, pu}
	} else {
		objs = []*Object{mk(KindSymmetric, a.PrivFmt, priv)}
	}
	for _, o := range objs {
		s.st.objs[o.ID] = o
	}
	if serr := s.st.save(); serr != nil {
		for _, o := range objs {
			delete(s.st.objs, o.ID)
		}
		return nil, errf(ErrInternal, "could not persist: %v", serr)
	}
	for _, o := range objs {
		out = append(out, view(o))
	}
	return out, nil
}

func idsOf(v []View) string {
	var s []string
	for _, x := range v {
		s = append(s, x.ID)
	}
	return strings.Join(s, ",")
}

// ---- read

// Filter selects objects for Locate; zero fields do not filter.
type Filter struct {
	Name     string
	Group    string
	State    State
	HasState bool
	Kind     uint32
	Alg      uint32
	Bits     int
	Max      int
}

// Locate returns the identifiers (oldest first) of visible objects matching the filter.
func (s *Service) Locate(p Principal, f Filter) []string {
	vs := s.List(p, f)
	out := make([]string, 0, len(vs))
	for _, v := range vs {
		out = append(out, v.ID)
	}
	return out
}

// List returns views of visible objects matching the filter (oldest first).
func (s *Service) List(p Principal, f Filter) []View {
	s.st.mu.RLock()
	defer s.st.mu.RUnlock()
	var out []View
	for _, o := range s.st.objs {
		if !s.can(p, o.Group, "locate") {
			continue
		}
		if f.Name != "" && !slices.Contains(o.Names, f.Name) {
			continue
		}
		if f.Group != "" && o.Group != f.Group {
			continue
		}
		if f.HasState && o.State != f.State {
			continue
		}
		if f.Kind != 0 && o.Kind != f.Kind {
			continue
		}
		if f.Alg != 0 && o.Alg != f.Alg {
			continue
		}
		if f.Bits != 0 && o.Bits != f.Bits {
			continue
		}
		out = append(out, view(o))
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Created != out[j].Created {
			return out[i].Created < out[j].Created
		}
		return out[i].ID < out[j].ID
	})
	if f.Max > 0 && len(out) > f.Max {
		out = out[:f.Max]
	}
	return out
}

// Attributes returns the metadata of one object.
func (s *Service) Attributes(p Principal, id string) (View, error) {
	s.st.mu.RLock()
	defer s.st.mu.RUnlock()
	o, e := s.get(p, id, "getattributes")
	if e != nil {
		return View{}, e
	}
	return view(o), nil
}

// Material is a key value released to a caller. The caller must clear Bytes.
type Material struct {
	Info  View
	Bytes []byte
}

// GetMaterial releases the key value to a client holding "get" in the key's group. Only Active and
// Deactivated keys can be retrieved (a deactivated key is still needed to decrypt old data).
func (s *Service) GetMaterial(p Principal, id string) (m *Material, err error) {
	defer func() { s.emit(p, "get", id, "", err) }()
	s.st.mu.RLock()
	defer s.st.mu.RUnlock()
	o, e := s.get(p, id, "get")
	if e != nil {
		return nil, e
	}
	if o.State != Active && o.State != Deactivated {
		return nil, errf(ErrState, "the key value cannot be retrieved in state %s", o.State)
	}
	return &Material{Info: view(o), Bytes: slices.Clone(o.Material)}, nil
}

// ---- lifecycle

// ActionsFor lists the lifecycle actions the state machine allows (rights are checked separately).
func ActionsFor(o View) []string {
	switch o.State {
	case PreActive:
		return []string{"activate", "compromise", "destroy"}
	case Active:
		a := []string{"deactivate", "compromise"}
		if o.Kind == KindSymmetric {
			a = append([]string{"rekey"}, a...)
		}
		return a
	case Deactivated:
		return []string{"compromise", "destroy"}
	case Compromised:
		return []string{"destroy"}
	}
	return []string{}
}

func (s *Service) transition(p Principal, id, op, right string, apply func(o *Object, t int64) *Error) (v View, err error) {
	defer func() { s.emit(p, op, id, "", err) }()
	if e := writeOK(p); e != nil {
		return View{}, e
	}
	s.st.mu.Lock()
	defer s.st.mu.Unlock()
	o, e := s.get(p, id, right)
	if e != nil {
		return View{}, e
	}
	old := *o
	old.Names = slices.Clone(o.Names)
	t := now()
	if e := apply(o, t); e != nil {
		return View{}, e
	}
	o.Changed = t
	if serr := s.st.save(); serr != nil {
		*o = old
		return View{}, errf(ErrInternal, "could not persist: %v", serr)
	}
	return view(o), nil
}

// Activate moves a Pre-Active key to Active.
func (s *Service) Activate(p Principal, id string) (View, error) {
	return s.transition(p, id, "activate", "activate", func(o *Object, t int64) *Error {
		if o.State != PreActive {
			return errf(ErrState, "activate is not allowed in state %s", o.State)
		}
		o.State, o.Activated = Active, t
		return nil
	})
}

// Deactivate moves an Active key to Deactivated (no new use; existing data can still be processed).
func (s *Service) Deactivate(p Principal, id string) (View, error) {
	return s.transition(p, id, "deactivate", "revoke", func(o *Object, t int64) *Error {
		if o.State != Active {
			return errf(ErrState, "deactivate is not allowed in state %s", o.State)
		}
		o.State, o.Deactivated = Deactivated, t
		return nil
	})
}

// MarkCompromised flags a key as compromised (irreversible).
func (s *Service) MarkCompromised(p Principal, id string) (View, error) {
	return s.transition(p, id, "compromise", "revoke", func(o *Object, t int64) *Error {
		switch o.State {
		case PreActive, Active, Deactivated:
			o.State, o.Compromised = Compromised, t
			return nil
		case Destroyed:
			o.State, o.Compromised = DestroyedCompromised, t
			return nil
		}
		return errf(ErrState, "compromise is not allowed in state %s", o.State)
	})
}

// Destroy erases the key value. The object stays as a record in state Destroyed.
func (s *Service) Destroy(p Principal, id string) (View, error) {
	return s.transition(p, id, "destroy", "destroy", func(o *Object, t int64) *Error {
		switch o.State {
		case PreActive, Deactivated:
			o.State = Destroyed
		case Compromised:
			o.State = DestroyedCompromised
		default:
			return errf(ErrState, "destroy is not allowed in state %s (deactivate the key first)", o.State)
		}
		clear(o.Material)
		o.Material, o.Destroyed = nil, t
		return nil
	})
}

// ReKey replaces an active symmetric key: a new key (same algorithm, group and names) becomes Active and the
// old key becomes Deactivated. Both keep their names, so a consumer looking the name up sees the old key as a
// decrypt-only version and the new one as current.
func (s *Service) ReKey(p Principal, id string) (nv View, err error) {
	defer func() { s.emit(p, "rekey", id, "new="+nv.ID, err) }()
	if e := writeOK(p); e != nil {
		return View{}, e
	}
	s.st.mu.Lock()
	defer s.st.mu.Unlock()
	o, e := s.get(p, id, "rekey")
	if e != nil {
		return View{}, e
	}
	if o.Kind != KindSymmetric {
		return View{}, errf(ErrUnsupported, "re-key is available for symmetric keys only")
	}
	if o.State != Active {
		return View{}, errf(ErrState, "re-key is not allowed in state %s", o.State)
	}
	a := LookupAlgo(o.Algo)
	if a == nil {
		return View{}, errf(ErrInternal, "unknown algorithm %q", o.Algo)
	}
	secret, _, gerr := a.gen()
	if gerr != nil {
		return View{}, errf(ErrInternal, "key generation failed: %v", gerr)
	}
	t := now()
	n := *o
	n.ID, n.Material, n.Created, n.Changed, n.Creator = newID(), secret, t, t, p.Name
	n.State, n.Activated, n.Deactivated, n.Compromised, n.Destroyed = Active, t, 0, 0, 0
	n.ReplacesID, n.ReplacedByID = o.ID, ""
	n.Names = slices.Clone(o.Names)
	old := *o
	o.State, o.Deactivated, o.ReplacedByID, o.Changed = Deactivated, t, n.ID, t
	s.st.objs[n.ID] = &n
	if serr := s.st.save(); serr != nil {
		*o = old
		delete(s.st.objs, n.ID)
		return View{}, errf(ErrInternal, "could not persist: %v", serr)
	}
	return view(&n), nil
}

// SetName adds (add=true) or removes a name of an object.
func (s *Service) SetName(p Principal, id, name string, add bool) (err error) {
	defer func() { s.emit(p, "setname", id, name, err) }()
	if e := writeOK(p); e != nil {
		return e
	}
	names, e := cleanNames([]string{name})
	if e != nil || len(names) != 1 {
		return errf(ErrInvalid, "invalid key name")
	}
	s.st.mu.Lock()
	defer s.st.mu.Unlock()
	o, e2 := s.get(p, id, "setattribute")
	if e2 != nil {
		return e2
	}
	old := slices.Clone(o.Names)
	if add {
		if !slices.Contains(o.Names, names[0]) {
			o.Names = append(o.Names, names[0])
		}
	} else {
		o.Names = slices.DeleteFunc(o.Names, func(x string) bool { return x == names[0] })
	}
	o.Changed = now()
	if serr := s.st.save(); serr != nil {
		o.Names = old
		return errf(ErrInternal, "could not persist: %v", serr)
	}
	return nil
}

// Stats counts objects per state.
func (s *Service) Stats() map[string]int {
	s.st.mu.RLock()
	defer s.st.mu.RUnlock()
	m := map[string]int{}
	for _, o := range s.st.objs {
		m[StateID(o.State)]++
	}
	return m
}

// GroupExists is used by front ends to validate input early.
func (s *Service) GroupExists(name string) bool {
	s.st.mu.RLock()
	defer s.st.mu.RUnlock()
	return s.st.groups[name] != nil
}

var actionRight = map[string]string{"activate": "activate", "deactivate": "revoke", "compromise": "revoke", "rekey": "rekey", "destroy": "destroy"}

// ActionsAllowed lists the lifecycle actions the state machine permits AND the principal holds the right for.
func (s *Service) ActionsAllowed(p Principal, o View) []string {
	s.st.mu.RLock()
	defer s.st.mu.RUnlock()
	out := []string{}
	for _, a := range ActionsFor(o) {
		if s.can(p, o.Group, actionRight[a]) {
			out = append(out, a)
		}
	}
	return out
}

// Act runs a lifecycle action by name (activate, deactivate, compromise, rekey, destroy). For rekey the
// returned view is the new key.
func (s *Service) Act(p Principal, id, action string) (View, error) {
	switch action {
	case "activate":
		return s.Activate(p, id)
	case "deactivate":
		return s.Deactivate(p, id)
	case "compromise":
		return s.MarkCompromised(p, id)
	case "destroy":
		return s.Destroy(p, id)
	case "rekey":
		return s.ReKey(p, id)
	}
	return View{}, errf(ErrInvalid, "unknown action %q", action)
}

// Permissions lists the operations the principal holds on keys of the service.
func (s *Service) Permissions(p Principal, service string) []string {
	s.st.mu.RLock()
	defer s.st.mu.RUnlock()
	out := []string{}
	for _, op := range Operations {
		if s.can(p, service, op) {
			out = append(out, op)
		}
	}
	return out
}

// ParentOf returns the super group of a service ("" if none).
func (s *Service) ParentOf(service string) string {
	s.st.mu.RLock()
	defer s.st.mu.RUnlock()
	return s.parentOf(service)
}
