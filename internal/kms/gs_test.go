package kms

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
	"unicode/utf8"
)

// GS: reliability. A damaged database is refused with a clear error; it is never silently replaced by an empty one.
func TestGS_DamagedDatabaseIsRefused(t *testing.T) {
	s, dir := topology(t)
	root := s.AdminPrincipal("root")
	if _, err := s.Create(root, CreateReq{Algo: "aes-256", Group: "pay", Activate: true}); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(dir, "kms.db")
	good, _ := os.ReadFile(dbPath)
	open := func() error {
		sl, err := LoadFileSealer(filepath.Join(dir, "master.key"))
		if err != nil {
			return err
		}
		_, err = OpenStore(dbPath, sl)
		return err
	}
	mutations := map[string][]byte{
		"empty":            {},
		"one byte":         good[:1],
		"half":             good[:len(good)/2],
		"minus one":        good[:len(good)-1],
		"zeros":            make([]byte, len(good)),
		"text":             []byte("this is not a database"),
		"appended garbage": append(append([]byte{}, good...), 1, 2, 3),
		"first byte":       append([]byte{good[0] ^ 1}, good[1:]...),
		"last byte":        append(append([]byte{}, good[:len(good)-1]...), good[len(good)-1]^1),
	}
	for name, data := range mutations {
		if err := os.WriteFile(dbPath, data, 0o600); err != nil {
			t.Fatal(err)
		}
		err := open()
		if err == nil {
			t.Fatalf("%s: a damaged database was accepted", name)
		}
		if len(err.Error()) > 400 {
			t.Fatalf("%s: unwieldy error: %s", name, err)
		}
		if after, _ := os.ReadFile(dbPath); string(after) != string(data) {
			t.Fatalf("%s: opening a damaged database modified the file", name)
		}
	}
	// restore: opens again and holds the key
	if err := os.WriteFile(dbPath, good, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := open(); err != nil {
		t.Fatalf("the intact database no longer opens: %v", err)
	}
	// an interrupted write (leftover temp file, or a missing main file with a previous generation) never loads a partial state
	if err := os.WriteFile(dbPath+".tmp", good[:len(good)/3], 0o600); err != nil {
		t.Fatal(err)
	}
	if err := open(); err != nil {
		t.Fatalf("a leftover temp file broke the start: %v", err)
	}
	// a master key of the wrong length is refused too
	bad := filepath.Join(dir, "short.key")
	os.WriteFile(bad, []byte("short"), 0o600)
	if _, err := LoadFileSealer(bad); err == nil {
		t.Fatal("a 5 byte master key was accepted")
	}
}

// GS: stability. Parallel administration and key operations; afterwards the file on disk equals the memory.
func TestGS_ConcurrentOperationsAndReload(t *testing.T) {
	s, dir := topology(t)
	root := s.AdminPrincipal("root")
	for _, b := range [][3]string{{"app1", "pay", "owner"}, {"app2", "ledger", "owner"}, {"app3", "division", "guest"}} {
		if err := s.PutBinding(root, b[0], b[1], b[2]); err != nil {
			t.Fatal(err)
		}
	}
	var wg sync.WaitGroup
	errs := make(chan string, 2000)
	for w := 0; w < 24; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			app := ClientPrincipal([]string{"app1", "app2"}[w%2])
			svc := []string{"pay", "ledger"}[w%2]
			for i := 0; i < 15; i++ {
				v, err := s.Create(app, CreateReq{Algo: []string{"aes-256", "ml-dsa-65", "rsa-2048"}[i%3], Group: svc, Names: []string{fmt.Sprintf("k%d-%d", w, i)}, Activate: true})
				if err != nil {
					errs <- "create: " + err.Error()
					continue
				}
				s.List(ClientPrincipal("app3"), Filter{})
				s.Locate(app, Filter{Name: fmt.Sprintf("k%d-%d", w, i)})
				if v[0].Kind == KindSymmetric {
					if nv, err := s.ReKey(app, v[0].ID); err != nil {
						errs <- "rekey: " + err.Error()
					} else {
						s.Deactivate(app, nv.ID)
						s.Destroy(app, nv.ID)
					}
				}
				// administration churn at the same time
				name := fmt.Sprintf("t%d-%d", w, i)
				if err := s.PutTemplate(root, name, "", []string{"locate", "getattributes"}, true); err == nil {
					s.PutBinding(root, fmt.Sprintf("c%d", w), svc, name)
					s.DeleteBinding(root, fmt.Sprintf("c%d", w), svc)
					s.DeleteTemplate(root, name)
				}
				s.PutManager(root, fmt.Sprintf("m%d", w), svc, RoleAudit)
				s.DeleteManager(root, fmt.Sprintf("m%d", w), svc)
				s.Groups(root)
				s.Bindings(root)
			}
		}(w)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
	if t.Failed() {
		return
	}
	// reload from disk and compare everything with the live state
	sl, _ := LoadFileSealer(filepath.Join(dir, "master.key"))
	st2, err := OpenStore(filepath.Join(dir, "kms.db"), sl)
	if err != nil {
		t.Fatalf("the database written under concurrency does not reopen: %v", err)
	}
	s2 := NewService(st2, []string{"root"})
	live, disk := s.List(root, Filter{}), s2.List(s2.AdminPrincipal("root"), Filter{})
	if len(live) != len(disk) {
		t.Fatalf("memory has %d objects, disk %d", len(live), len(disk))
	}
	dm := map[string]View{}
	for _, v := range disk {
		dm[v.ID] = v
	}
	for _, v := range live {
		d, ok := dm[v.ID]
		if !ok || d.State != v.State || d.Group != v.Group || len(d.Names) != len(v.Names) || d.ReplacedByID != v.ReplacedByID {
			t.Fatalf("object %s differs between memory and disk", v.ID)
		}
	}
	b1, _ := s.Bindings(root)
	b2, _ := s2.Bindings(s2.AdminPrincipal("root"))
	if len(b1) != len(b2) {
		t.Fatalf("bindings: memory %d, disk %d", len(b1), len(b2))
	}
	if s.st.Seq() != st2.Seq() {
		t.Fatalf("sequence: memory %d, disk %d", s.st.Seq(), st2.Seq())
	}
	// destroyed keys keep no value
	for _, o := range s.st.objs {
		if (o.State == Destroyed || o.State == DestroyedCompromised) && len(o.Material) != 0 {
			t.Fatalf("destroyed key %s still holds a value", o.ID)
		}
	}
}

// GS: input validation of the core: text rules and bounds.
func TestGS_TextValidation(t *testing.T) {
	bad := []string{"a\x00b", "a\nb", "a\rb", "a\tb", "a\u2028b", "a\u2029b", "\ufeffa", "a\x7fb", "a\u0085b", string([]byte{0xff, 0xfe}), "a\x1bb"}
	for _, x := range bad {
		if !badText(x) {
			t.Fatalf("%q accepted", x)
		}
	}
	good := []string{"plain", "with space", "日本語", "키-이름_01", "emoji 🔑", "quote\"s", "<tag>", "a/b\\c", "a;b"}
	for _, x := range good {
		if badText(x) {
			t.Fatalf("%q rejected", x)
		}
	}
	if names, err := cleanNames([]string{"  a  ", "a", " b", ""}); err != nil || len(names) != 2 || names[0] != "a" {
		t.Fatalf("normalisation: %v %v", names, err)
	}
	many := make([]string, maxNames+1)
	for i := range many {
		many[i] = fmt.Sprintf("n%d", i)
	}
	if _, err := cleanNames(many); err == nil {
		t.Fatal("too many names accepted")
	}
	if _, err := cleanNames(make([]string, 4*maxNames+1)); err == nil {
		t.Fatal("an absurd number of names accepted")
	}
}

// GS: performance efficiency. Every change rewrites the sealed database, so the cost grows with its size:
// measure it so the limit is known instead of guessed.
func TestGS_LatencyWithGrowingDatabase(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	s, _ := topology(t)
	root := s.AdminPrincipal("root")
	steps := []int{100, 500, 1000, 2000}
	n := 0
	for _, target := range steps {
		start := time.Now()
		count := 0
		for ; n < target; n++ {
			if _, err := s.Create(root, CreateReq{Algo: "aes-256", Group: "pay"}); err != nil {
				t.Fatal(err)
			}
			count++
		}
		per := time.Since(start) / time.Duration(count)
		t.Logf("database with %4d keys: %v per create", target, per)
		if per > 400*time.Millisecond {
			t.Fatalf("a create takes %v with %d keys: too slow", per, target)
		}
	}
	// reads stay fast regardless of the size
	start := time.Now()
	for i := 0; i < 200; i++ {
		s.List(root, Filter{Name: "nope"})
	}
	if per := time.Since(start) / 200; per > 20*time.Millisecond {
		t.Fatalf("a list over %d keys takes %v", n, per)
	}
}

// ---- fuzzing

func FuzzApplyReplicated(f *testing.F) {
	s, _ := newSvc(f)
	f.Add([]byte(`{"version":1,"seq":5,"objects":[],"groups":[],"templates":[],"bindings":[],"managers":[]}`))
	f.Add([]byte(`{"seq":1,"objects":[{"id":"x","group":"g","names":null,"material":"AAAA"}]}`))
	f.Add([]byte(`{`))
	f.Fuzz(func(t *testing.T, data []byte) {
		before := s.st.Seq()
		err := s.st.ApplyReplicated(data, false)
		if err != nil && s.st.Seq() != before {
			t.Fatal("a rejected state changed the sequence")
		}
		// whatever was accepted, the built-ins exist and the service still answers
		if s.st.groups[GroupAll] == nil || s.st.templates["owner"] == nil {
			t.Fatal("built-in group or template lost")
		}
		_ = s.List(s.AdminPrincipal("root"), Filter{})
	})
}

func FuzzBadText(f *testing.F) {
	for _, x := range []string{"", "a", "a\x00", "日本", string([]byte{0xff})} {
		f.Add(x)
	}
	f.Fuzz(func(t *testing.T, x string) {
		if !badText(x) {
			if !utf8.ValidString(x) {
				t.Fatal("invalid UTF-8 accepted")
			}
			for _, r := range x {
				if r < 0x20 || r == 0x7f {
					t.Fatal("control character accepted")
				}
			}
		}
	})
}
