package kms

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func newSvc(t testing.TB) (*Service, string) {
	t.Helper()
	dir := t.TempDir()
	sl, err := LoadFileSealer(filepath.Join(dir, "master.key"))
	if err != nil {
		t.Fatal(err)
	}
	st, err := OpenStore(filepath.Join(dir, "kms.db"), sl)
	if err != nil {
		t.Fatal(err)
	}
	return NewService(st, []string{"root"}), dir
}

func code(err error) ErrCode {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return 0
}

func mustNil(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func wantCode(t *testing.T, err error, c ErrCode, what string) {
	t.Helper()
	if code(err) != c {
		t.Fatalf("%s: got %v, want error code %d", what, err, c)
	}
}

// topology used by most tests:  ALL | division(super) { pay, ledger } | other(super) { mail } | solo (no parent)
func topology(t *testing.T) (*Service, string) {
	s, dir := newSvc(t)
	root := s.AdminPrincipal("root")
	mustNil(t, s.PutGroup(root, GroupReq{Name: "division", Kind: KindSuper}, true))
	mustNil(t, s.PutGroup(root, GroupReq{Name: "other", Kind: KindSuper}, true))
	mustNil(t, s.PutGroup(root, GroupReq{Name: "pay", Kind: KindService, Parent: "division"}, true))
	mustNil(t, s.PutGroup(root, GroupReq{Name: "ledger", Kind: KindService, Parent: "division"}, true))
	mustNil(t, s.PutGroup(root, GroupReq{Name: "mail", Kind: KindService, Parent: "other"}, true))
	mustNil(t, s.PutGroup(root, GroupReq{Name: "solo", Kind: KindService}, true))
	return s, dir
}

func TestDefaults(t *testing.T) {
	s, _ := newSvc(t)
	root := s.AdminPrincipal("root")
	gs, err := s.Groups(root)
	mustNil(t, err)
	if len(gs) != 1 || gs[0].Name != GroupAll || gs[0].Kind != KindAll {
		t.Fatalf("groups %+v", gs)
	}
	ts, _ := s.Templates(root)
	names := []string{}
	for _, x := range ts {
		names = append(names, x.Name)
	}
	if !slices.Equal(names, []string{"guest", "owner"}) && !slices.Equal(names, []string{"owner", "guest"}) {
		t.Fatalf("templates %v", names)
	}
	// the built-ins are editable but not deletable; ALL is not deletable
	mustNil(t, s.PutTemplate(root, "guest", "read", []string{"locate", "getattributes"}, false))
	wantCode(t, s.DeleteTemplate(root, "owner"), ErrInvalid, "delete built-in template")
	wantCode(t, s.DeleteGroup(root, GroupAll), ErrInvalid, "delete ALL")
}

func TestClientRightsFollowBindings(t *testing.T) {
	s, _ := topology(t)
	root := s.AdminPrincipal("root")
	alice, bob := ClientPrincipal("alice"), ClientPrincipal("bob")

	// no binding: nothing, not even existence
	_, err := s.Create(alice, CreateReq{Algo: "aes-256", Group: "pay"})
	wantCode(t, err, ErrDenied, "create without binding")

	mustNil(t, s.PutBinding(root, "alice", "pay", "owner"))
	mustNil(t, s.PutBinding(root, "bob", "pay", "guest"))
	ks, err := s.Create(alice, CreateReq{Algo: "aes-256", Group: "pay", Names: []string{"k1"}, Activate: true})
	mustNil(t, err)
	id := ks[0].ID

	// guest: read only
	if _, err := s.Attributes(bob, id); err != nil {
		t.Fatalf("guest getattributes: %v", err)
	}
	if m, err := s.GetMaterial(bob, id); err != nil || len(m.Bytes) != 32 {
		t.Fatalf("guest get: %v", err)
	}
	_, err = s.Create(bob, CreateReq{Algo: "aes-256", Group: "pay"})
	wantCode(t, err, ErrDenied, "guest create")
	_, err = s.Deactivate(bob, id)
	wantCode(t, err, ErrNotFound, "guest deactivate (indistinguishable from absent)")
	_, err = s.Destroy(bob, id)
	wantCode(t, err, ErrNotFound, "guest destroy")

	// a client of another group cannot even see it
	mustNil(t, s.PutBinding(root, "carol", "ledger", "owner"))
	carol := ClientPrincipal("carol")
	if got := s.Locate(carol, Filter{}); len(got) != 0 {
		t.Fatalf("carol sees keys of another service: %v", got)
	}
	_, err = s.GetMaterial(carol, id)
	wantCode(t, err, ErrNotFound, "get across services")

	// owner: full CRUD
	nv, err := s.ReKey(alice, id)
	mustNil(t, err)
	if nv.Group != "pay" {
		t.Fatalf("re-keyed key left its service: %s", nv.Group)
	}
	_, err = s.Deactivate(alice, nv.ID)
	mustNil(t, err)
	_, err = s.Destroy(alice, nv.ID)
	mustNil(t, err)
}

func TestSuperGroupAndALLBindings(t *testing.T) {
	s, _ := topology(t)
	root := s.AdminPrincipal("root")
	mustNil(t, s.PutBinding(root, "owner-ish", "pay", "owner"))
	mustNil(t, s.PutBinding(root, "owner-ish", "ledger", "owner"))
	mustNil(t, s.PutBinding(root, "owner-ish", "mail", "owner"))
	oi := ClientPrincipal("owner-ish")
	var kp, kl, km string
	for svc, dst := range map[string]*string{"pay": &kp, "ledger": &kl, "mail": &km} {
		v, err := s.Create(oi, CreateReq{Algo: "aes-128", Group: svc, Activate: true})
		mustNil(t, err)
		*dst = v[0].ID
	}

	// guest on the super group "division" reads pay and ledger, not mail
	mustNil(t, s.PutBinding(root, "auditor-app", "division", "guest"))
	ap := ClientPrincipal("auditor-app")
	if _, err := s.GetMaterial(ap, kp); err != nil {
		t.Fatalf("super-group guest cannot read pay: %v", err)
	}
	if _, err := s.GetMaterial(ap, kl); err != nil {
		t.Fatalf("super-group guest cannot read ledger: %v", err)
	}
	if _, err := s.GetMaterial(ap, km); err == nil {
		t.Fatal("super-group guest read a service of another super group")
	}
	// a super-group binding has no create right for a guest, and owners need an explicit service to create in
	_, err := s.Create(ap, CreateReq{Algo: "aes-128", Group: "pay"})
	wantCode(t, err, ErrDenied, "guest of a super group creates")

	// moving a service changes who inherits
	mustNil(t, s.PutGroup(root, GroupReq{Name: "mail", Kind: KindService, Parent: "division"}, false))
	if _, err := s.GetMaterial(ap, km); err != nil {
		t.Fatalf("after moving mail under division the guest should read it: %v", err)
	}

	// ALL: owner everywhere, regardless of group, including a service without any super group
	mustNil(t, s.PutBinding(root, "super-app", GroupAll, "owner"))
	sa := ClientPrincipal("super-app")
	v, err := s.Create(sa, CreateReq{Algo: "ed25519", Group: "solo"})
	mustNil(t, err)
	if len(v) != 2 {
		t.Fatalf("ed25519 pair: %d objects", len(v))
	}
	for _, id := range []string{kp, kl, km} {
		if _, err := s.Attributes(sa, id); err != nil {
			t.Fatalf("ALL owner cannot see %s: %v", id, err)
		}
	}
	// ALL guest: read everything, change nothing
	mustNil(t, s.PutBinding(root, "reader", GroupAll, "guest"))
	rd := ClientPrincipal("reader")
	if _, err := s.GetMaterial(rd, kp); err != nil {
		t.Fatal(err)
	}
	_, err = s.Create(rd, CreateReq{Algo: "aes-128", Group: "pay"})
	wantCode(t, err, ErrDenied, "ALL guest creates")
	// ALL is a scope, not a place for keys
	_, err = s.Create(sa, CreateReq{Algo: "aes-128", Group: GroupAll})
	wantCode(t, err, ErrInvalid, "create in ALL")
	_, err = s.Create(sa, CreateReq{Algo: "aes-128", Group: "division"})
	wantCode(t, err, ErrInvalid, "create in a super group")
}

func TestKeyNeedsExactlyOneService(t *testing.T) {
	s, _ := topology(t)
	root := s.AdminPrincipal("root")
	mustNil(t, s.PutBinding(root, "app", "pay", "owner"))
	app := ClientPrincipal("app")
	// no group given: allowed when the client has exactly one service to create in
	v, err := s.Create(app, CreateReq{Algo: "aes-256"})
	mustNil(t, err)
	if v[0].Group != "pay" {
		t.Fatalf("default group %q", v[0].Group)
	}
	mustNil(t, s.PutBinding(root, "app", "ledger", "owner"))
	_, err = s.Create(app, CreateReq{Algo: "aes-256"})
	wantCode(t, err, ErrInvalid, "ambiguous default group")
	_, err = s.Create(app, CreateReq{Algo: "aes-256", Group: "nope"})
	wantCode(t, err, ErrInvalid, "unknown service")
}

func TestAdministratorsNeverGetKeyValues(t *testing.T) {
	s, _ := topology(t)
	root := s.AdminPrincipal("root")
	v, err := s.Create(root, CreateReq{Algo: "aes-256", Group: "pay", Activate: true})
	mustNil(t, err)
	_, err = s.GetMaterial(root, v[0].ID)
	wantCode(t, err, ErrNotFound, "root admin get")
	// but manages the lifecycle
	_, err = s.Deactivate(root, v[0].ID)
	mustNil(t, err)
	_, err = s.Destroy(root, v[0].ID)
	mustNil(t, err)
}

func TestScopedAdministration(t *testing.T) {
	s, _ := topology(t)
	root := s.AdminPrincipal("root")
	mustNil(t, s.PutManager(root, "dora", "division", RoleAdmin))
	mustNil(t, s.PutManager(root, "olaf", "other", RoleAdmin))
	mustNil(t, s.PutManager(root, "ava", "division", RoleAudit))
	mustNil(t, s.PutManager(root, "pavel", "pay", RoleAdmin))
	dora, olaf, ava, pavel := s.AdminPrincipal("dora"), s.AdminPrincipal("olaf"), s.AdminPrincipal("ava"), s.AdminPrincipal("pavel")

	// dora: services of "division" only
	v, err := s.Create(dora, CreateReq{Algo: "aes-256", Group: "pay"})
	mustNil(t, err)
	_, err = s.Create(dora, CreateReq{Algo: "aes-256", Group: "mail"})
	wantCode(t, err, ErrDenied, "division admin creates in another division")
	mustNil(t, s.PutGroup(dora, GroupReq{Name: "billing", Kind: KindService, Parent: "division"}, true))
	wantCode(t, s.PutGroup(dora, GroupReq{Name: "rogue", Kind: KindService, Parent: "other"}, true), ErrDenied, "create service under another super group")
	wantCode(t, s.PutGroup(dora, GroupReq{Name: "free", Kind: KindService}, true), ErrDenied, "create parentless service")
	wantCode(t, s.PutGroup(dora, GroupReq{Name: "newsuper", Kind: KindSuper}, true), ErrDenied, "create super group")
	wantCode(t, s.PutGroup(dora, GroupReq{Name: "mail", Kind: KindService, Parent: "division"}, false), ErrDenied, "steal a service")
	mustNil(t, s.PutBinding(dora, "app1", "pay", "owner"))
	mustNil(t, s.PutBinding(dora, "app1", "division", "guest"))
	wantCode(t, s.PutBinding(dora, "app1", "mail", "owner"), ErrDenied, "bind outside the scope")
	wantCode(t, s.PutBinding(dora, "app1", GroupAll, "owner"), ErrDenied, "bind to ALL")
	wantCode(t, s.PutTemplate(dora, "mine", "", []string{"get"}, true), ErrDenied, "template edit by a scoped admin")
	wantCode(t, s.PutTemplate(dora, "guest", "", []string{"destroy"}, false), ErrDenied, "edit built-in by a scoped admin")

	// dora sees only her world
	gs, _ := s.Groups(dora)
	for _, g := range gs {
		if g.Name == "mail" || g.Name == "other" || g.Name == "solo" || g.Name == GroupAll {
			t.Fatalf("division admin sees %s", g.Name)
		}
	}
	if len(s.List(dora, Filter{})) != 1 || len(s.List(olaf, Filter{})) != 0 {
		t.Fatal("key visibility is not scoped")
	}
	bs, _ := s.Bindings(dora)
	for _, b := range bs {
		if b.Group == "mail" {
			t.Fatal("division admin sees a binding of another service")
		}
	}
	// delegation inside the scope, not beyond
	mustNil(t, s.PutManager(dora, "ned", "ledger", RoleAdmin))
	wantCode(t, s.PutManager(dora, "ned", "mail", RoleAdmin), ErrDenied, "delegate outside scope")
	wantCode(t, s.PutManager(dora, "ned", GroupAll, RoleAdmin), ErrDenied, "delegate ALL")
	wantCode(t, s.PutManager(pavel, "x", "division", RoleAdmin), ErrDenied, "service admin delegates upwards")
	mustNil(t, s.PutManager(pavel, "y", "pay", RoleAudit))

	// audit: read only
	if _, err := s.Attributes(ava, v[0].ID); err != nil {
		t.Fatalf("audit cannot read: %v", err)
	}
	_, err = s.Create(ava, CreateReq{Algo: "aes-256", Group: "pay"})
	wantCode(t, err, ErrDenied, "audit creates")
	_, err = s.Activate(ava, v[0].ID)
	wantCode(t, err, ErrDenied, "audit activates")
	wantCode(t, s.PutBinding(ava, "z", "pay", "guest"), ErrDenied, "audit binds")
	if _, err := s.Managers(ava); err != nil {
		t.Fatalf("audit lists managers: %v", err)
	}

	// service admin: his service only, and no management of the super group
	if _, err := s.Activate(pavel, v[0].ID); err != nil {
		t.Fatalf("service admin cannot activate: %v", err)
	}
	wantCode(t, s.PutBinding(pavel, "q", "division", "guest"), ErrDenied, "service admin binds the super group")

	// removing the scope removes the right
	mustNil(t, s.DeleteManager(dora, "ned", "ledger"))
	wantCode(t, s.DeleteManager(dora, "olaf", "other"), ErrDenied, "revoke outside scope")
	if p := s.AdminPrincipal("ned"); len(p.Scopes) != 0 {
		t.Fatalf("revoked identity keeps scopes: %+v", p.Scopes)
	}
	// an identity without any role gets nothing
	_, err = s.Groups(s.AdminPrincipal("nobody"))
	wantCode(t, err, ErrDenied, "no role")
	// client-plane principals cannot use admin functions
	_, err = s.Groups(ClientPrincipal("root"))
	wantCode(t, err, ErrDenied, "client plane on admin function")
}

func TestDeletionRules(t *testing.T) {
	s, _ := topology(t)
	root := s.AdminPrincipal("root")
	mustNil(t, s.PutBinding(root, "app", "pay", "owner"))
	v, err := s.Create(root, CreateReq{Algo: "aes-128", Group: "pay"})
	mustNil(t, err)
	wantCode(t, s.DeleteGroup(root, "pay"), ErrConflict, "delete service with keys")
	wantCode(t, s.DeleteGroup(root, "division"), ErrConflict, "delete super group with services")
	wantCode(t, s.PutGroup(root, GroupReq{Name: "pay", Kind: KindService}, true), ErrConflict, "duplicate group")
	mustNil(t, s.PutTemplate(root, "rotator", "", []string{"locate", "getattributes", "rekey"}, true))
	mustNil(t, s.PutBinding(root, "bot", "pay", "rotator"))
	wantCode(t, s.DeleteTemplate(root, "rotator"), ErrConflict, "delete a template in use")
	mustNil(t, s.DeleteBinding(root, "bot", "pay"))
	mustNil(t, s.DeleteTemplate(root, "rotator"))
	wantCode(t, s.PutBinding(root, "x", "pay", "ghost"), ErrInvalid, "unknown template")
	wantCode(t, s.PutBinding(root, "x", "ghost", "owner"), ErrInvalid, "unknown group")
	wantCode(t, s.PutBinding(root, "*", "pay", "owner"), ErrInvalid, "wildcard client")
	wantCode(t, s.PutTemplate(root, "bad", "", []string{"fly"}, true), ErrInvalid, "unknown operation")
	wantCode(t, s.PutTemplate(root, "empty", "", nil, true), ErrInvalid, "empty template")
	_, err = s.Deactivate(root, v[0].ID) // PreActive cannot be deactivated
	wantCode(t, err, ErrState, "deactivate pre-active")
	_, err = s.Destroy(root, v[0].ID)
	mustNil(t, err)
	// destroyed keys remain as records, so their service cannot be deleted; an empty one can, with its mappings
	wantCode(t, s.DeleteGroup(root, "pay"), ErrConflict, "delete service with destroyed records")
	mustNil(t, s.DeleteGroup(root, "solo"))
	mustNil(t, s.PutBinding(root, "tmp", "ledger", "guest"))
	mustNil(t, s.DeleteGroup(root, "ledger"))
	for _, b := range mustBindings(t, s, root) {
		if b.Group == "ledger" {
			t.Fatal("the mapping of a deleted service survived")
		}
	}
}

func mustBindings(t *testing.T, s *Service, p Principal) []Binding {
	b, err := s.Bindings(p)
	mustNil(t, err)
	return b
}

func TestTemplateEditTakesEffectImmediately(t *testing.T) {
	s, _ := topology(t)
	root := s.AdminPrincipal("root")
	mustNil(t, s.PutBinding(root, "app", "pay", "guest"))
	v, err := s.Create(root, CreateReq{Algo: "aes-128", Group: "pay", Activate: true})
	mustNil(t, err)
	app := ClientPrincipal("app")
	if _, err := s.GetMaterial(app, v[0].ID); err != nil {
		t.Fatal(err)
	}
	mustNil(t, s.PutTemplate(root, "guest", "no value release", []string{"locate", "getattributes"}, false))
	if _, err := s.GetMaterial(app, v[0].ID); err == nil {
		t.Fatal("guest still gets the key value after 'get' was removed from the template")
	}
	if _, err := s.Attributes(app, v[0].ID); err != nil {
		t.Fatal("guest lost getattributes it still has")
	}
}

func TestPersistenceAndTamperDetection(t *testing.T) {
	s, dir := topology(t)
	root := s.AdminPrincipal("root")
	mustNil(t, s.PutBinding(root, "app", "pay", "owner"))
	mustNil(t, s.PutManager(root, "dora", "division", RoleAdmin))
	v, err := s.Create(ClientPrincipal("app"), CreateReq{Algo: "ml-dsa-65", Group: "pay", Names: []string{"sig"}, Activate: true})
	mustNil(t, err)
	if len(v) != 2 || v[0].Kind != KindPrivate || v[1].Kind != KindPublic || v[0].PairID != v[1].ID {
		t.Fatalf("pair: %+v", v)
	}

	reopen := func(keyFile string) (*Service, error) {
		sl, err := LoadFileSealer(keyFile)
		if err != nil {
			return nil, err
		}
		st, err := OpenStore(filepath.Join(dir, "kms.db"), sl)
		if err != nil {
			return nil, err
		}
		return NewService(st, []string{"root"}), nil
	}
	s2, err := reopen(filepath.Join(dir, "master.key"))
	mustNil(t, err)
	m, err := s2.GetMaterial(ClientPrincipal("app"), v[0].ID)
	mustNil(t, err)
	if len(m.Bytes) == 0 {
		t.Fatal("private key value lost")
	}
	if p := s2.AdminPrincipal("dora"); len(p.Scopes) != 1 {
		t.Fatal("manager grants were not persisted")
	}

	raw, _ := os.ReadFile(filepath.Join(dir, "kms.db"))
	for _, secret := range [][]byte{m.Bytes[:16], []byte("division"), []byte("sig")} {
		if containsBytes(raw, secret) {
			t.Fatal("the database file shows plaintext (key value or metadata)")
		}
	}
	// flip a bit: authentication must fail
	raw[len(raw)/2] ^= 1
	mustNil(t, os.WriteFile(filepath.Join(dir, "kms.db"), raw, 0o600))
	if _, err := reopen(filepath.Join(dir, "master.key")); err == nil {
		t.Fatal("a modified database was accepted")
	}
	// wrong master key
	raw[len(raw)/2] ^= 1
	mustNil(t, os.WriteFile(filepath.Join(dir, "kms.db"), raw, 0o600))
	other := filepath.Join(dir, "other.key")
	if _, err := reopen(other); err == nil {
		t.Fatal("the database opened with a different master key")
	}
	if _, err := reopen(filepath.Join(dir, "master.key")); err != nil {
		t.Fatalf("restored database no longer opens: %v", err)
	}
}

func containsBytes(hay, needle []byte) bool {
	for i := 0; i+len(needle) <= len(hay); i++ {
		if string(hay[i:i+len(needle)]) == string(needle) {
			return true
		}
	}
	return false
}

func TestEveryCatalogAlgorithmCreates(t *testing.T) {
	s, _ := topology(t)
	root := s.AdminPrincipal("root")
	for _, a := range Catalog() {
		v, err := s.Create(root, CreateReq{Algo: a.ID, Group: "solo", Activate: true})
		if err != nil {
			t.Fatalf("%s: %v", a.ID, err)
		}
		want := 1
		if a.Pair {
			want = 2
		}
		if len(v) != want {
			t.Fatalf("%s: %d objects", a.ID, len(v))
		}
		if got := FindAlgo(a.Alg, a.Bits, a.Curve, a.Pair); got == nil || got.ID != a.ID {
			t.Fatalf("FindAlgo does not map %s back (%v)", a.ID, got)
		}
	}
}

func TestLifecycleStateMachine(t *testing.T) {
	s, _ := topology(t)
	root := s.AdminPrincipal("root")
	v, _ := s.Create(root, CreateReq{Algo: "aes-256", Group: "pay"})
	id := v[0].ID
	_, err := s.Destroy(root, id) // pre-active -> destroyed is allowed
	mustNil(t, err)
	if _, err := s.Activate(root, id); code(err) != ErrState {
		t.Fatalf("activate a destroyed key: %v", err)
	}
	v, _ = s.Create(root, CreateReq{Algo: "aes-256", Group: "pay", Activate: true})
	id = v[0].ID
	if _, err := s.Destroy(root, id); code(err) != ErrState {
		t.Fatalf("destroy an active key: %v", err)
	}
	if _, err := s.Activate(root, id); code(err) != ErrState {
		t.Fatalf("activate an active key: %v", err)
	}
	_, err = s.MarkCompromised(root, id)
	mustNil(t, err)
	d, err := s.Destroy(root, id)
	mustNil(t, err)
	if d.State != DestroyedCompromised || d.Destroyed == 0 {
		t.Fatalf("state %v", d.State)
	}
	// destroyed objects stay listed (as a record) but hold no value
	if got := s.List(root, Filter{HasState: true, State: DestroyedCompromised}); len(got) != 1 {
		t.Fatalf("destroyed record missing: %d", len(got))
	}
}
