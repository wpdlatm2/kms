package logs

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var key = []byte("0123456789abcdef0123456789abcdef")

func open(t *testing.T, dir string) *Log {
	t.Helper()
	l, err := OpenWith(Options{Path: filepath.Join(dir, "admin.log.jsonl"), Name: "admin", Key: key, Retention: 30 * 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(l.Close)
	return l
}

func fill(l *Log, n int) {
	for i := 0; i < n; i++ {
		l.Add(Entry{Plane: "admin", Kind: "event", Who: "root", Op: "binding-put", Target: "app", Result: "ok", Approval: "APR-1", Owner: "kim"})
	}
}

func TestChainVerifiesAndContinuesAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	l := open(t, dir)
	fill(l, 5)
	l.Close()
	l = open(t, dir)
	fill(l, 3)
	rep, err := l.Verify(key)
	if err != nil || !rep.OK || rep.Entries != 8 || rep.LastSeq != 8 {
		t.Fatalf("%+v %v", rep, err)
	}
	ents, _ := l.Query(Filter{})
	if ents[0].Category != "permission-change" || ents[0].Outcome != OutcomeSuccess || ents[0].MAC == "" {
		t.Fatalf("%+v", ents[0])
	}
}

func rewrite(t *testing.T, dir string, f func(lines []string) []string) {
	t.Helper()
	m, _ := filepath.Glob(filepath.Join(dir, "admin.log-*.jsonl"))
	b, _ := os.ReadFile(m[0])
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	os.WriteFile(m[0], []byte(strings.Join(f(lines), "\n")+"\n"), 0o600)
}

func TestTamperingIsDetected(t *testing.T) {
	cases := map[string]func([]string) []string{
		"modify": func(l []string) []string {
			l[2] = strings.Replace(l[2], `"owner":"kim"`, `"owner":"mallory"`, 1)
			return l
		},
		"delete": func(l []string) []string { return append(l[:2], l[3:]...) },
		"swap":   func(l []string) []string { l[1], l[2] = l[2], l[1]; return l },
		"insert": func(l []string) []string { return append(l[:2], append([]string{l[1]}, l[2:]...)...) },
		"truncate-tail": func(l []string) []string {
			return l[:len(l)-2]
		},
	}
	for name, mut := range cases {
		dir := t.TempDir()
		l := open(t, dir)
		fill(l, 6)
		l.Close()
		rewrite(t, dir, mut)
		l2, err := OpenWith(Options{Path: filepath.Join(dir, "admin.log.jsonl"), Name: "admin", Key: key})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(l2.Close)
		rep, _ := l2.Verify(key)
		if name == "truncate-tail" {
			// a reopened log continues from what is on disk; the cut is visible as a sequence regression against an earlier export
			if !rep.OK || rep.LastSeq != 4 {
				t.Fatalf("%s: %+v", name, rep)
			}
			continue
		}
		if rep.OK || rep.Problem == "" {
			t.Fatalf("%s not detected: %+v", name, rep)
		}
	}
}

func TestRecomputedChainNeedsTheKey(t *testing.T) {
	dir := t.TempDir()
	l := open(t, dir)
	fill(l, 4)
	l.Close()
	// an attacker without the key rewrites the file with a consistent hash chain
	forged, _ := OpenWith(Options{Path: filepath.Join(t.TempDir(), "admin.log.jsonl"), Name: "admin"}) // chain only, no MAC
	fill(forged, 4)
	forged.Close()
	m, _ := filepath.Glob(filepath.Join(forged.dir, "admin.log-*.jsonl"))
	fb, _ := os.ReadFile(m[0])
	t2, _ := filepath.Glob(filepath.Join(dir, "admin.log-*.jsonl"))
	os.WriteFile(t2[0], fb, 0o600)
	l2, _ := OpenWith(Options{Path: filepath.Join(dir, "admin.log.jsonl"), Name: "admin"})
	t.Cleanup(l2.Close)
	if rep, _ := l2.Verify(nil); !rep.OK { // chain alone is consistent ...
		t.Fatalf("%+v", rep)
	}
	if rep, _ := l2.Verify(key); rep.OK { // ... but the MAC exposes the forgery
		t.Fatal("forged chain passed MAC verification")
	}
}

func TestTornLastLineIsRepaired(t *testing.T) {
	dir := t.TempDir()
	l := open(t, dir)
	fill(l, 3)
	l.Close()
	m, _ := filepath.Glob(filepath.Join(dir, "admin.log-*.jsonl"))
	f, _ := os.OpenFile(m[0], os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString(`{"seq":4,"time":"2026`)
	f.Close()
	l = open(t, dir)
	if l.Recovered == "" {
		t.Fatal("torn line not reported")
	}
	fill(l, 1)
	rep, _ := l.Verify(key)
	if !rep.OK || rep.Entries != 5 { // 3 + audit-recovered + 1
		t.Fatalf("%+v", rep)
	}
}

func TestRotationQueryPurgeAndRetention(t *testing.T) {
	dir := t.TempDir()
	l := open(t, dir)
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	for d := 0; d < 3; d++ {
		day := base.AddDate(0, 0, d)
		l.now = func() time.Time { return day }
		fill(l, 2)
	}
	l.now = func() time.Time { return base.AddDate(0, 0, 100) }
	files, _ := filepath.Glob(filepath.Join(dir, "admin.log-*.jsonl"))
	if len(files) != 3 {
		t.Fatalf("%d files", len(files))
	}
	got, _ := l.Query(Filter{From: base.AddDate(0, 0, 1), To: base.AddDate(0, 0, 2)})
	if len(got) != 2 {
		t.Fatalf("range query %d", len(got))
	}
	if got, _ := l.Query(Filter{Text: "APR-1", Who: "root", Category: "permission-change"}); len(got) != 6 {
		t.Fatalf("filter %d", len(got))
	}
	// younger than the retention period -> refused
	if _, err := l.Purge(l.now().AddDate(0, 0, -10), "root"); err == nil {
		t.Fatal("purge inside the retention period was allowed")
	}
	removed, err := l.Purge(base.AddDate(0, 0, 2), "root")
	if err != nil || len(removed) != 2 {
		t.Fatalf("%v %v", removed, err)
	}
	rep, _ := l.Verify(key)
	if !rep.OK || rep.FirstSeq == 1 {
		t.Fatalf("after purge %+v", rep)
	}
	if ents, _ := l.Query(Filter{Op: "audit-purge"}); len(ents) != 1 || !strings.Contains(ents[0].Detail, "2 file") {
		t.Fatalf("purge not recorded: %+v", ents)
	}
}

func TestExportManifestAndRecipientVerification(t *testing.T) {
	l := open(t, t.TempDir())
	fill(l, 5)
	var buf bytes.Buffer
	m, err := l.Export(&buf, Filter{Category: "permission-change"}, "auditor", key)
	if err != nil || !m.ChainOK || m.Entries != 5 || m.ExportedBy != "auditor" {
		t.Fatalf("%+v %v", m, err)
	}
	zr, _ := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	var data []byte
	var man Manifest
	for _, f := range zr.File {
		rc, _ := f.Open()
		b, _ := io.ReadAll(rc)
		rc.Close()
		if f.Name == "manifest.json" {
			json.Unmarshal(b, &man)
		} else {
			data = b
		}
	}
	if man.DataSHA256 != m.DataSHA256 || man.Entries != 5 {
		t.Fatal("manifest mismatch")
	}
	var ents []Entry
	for _, ln := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var e Entry
		json.Unmarshal([]byte(ln), &e)
		ents = append(ents, e)
	}
	if err := VerifyEntries(ents, key); err != nil {
		t.Fatal(err)
	}
	ents[2].Owner = "x"
	if VerifyEntries(ents, key) == nil {
		t.Fatal("tampered export verified")
	}
}

func TestOutcomeAndSinks(t *testing.T) {
	l, _ := Open("", "client")
	var seen []Entry
	l.AddSink(func(e Entry) { seen = append(seen, e) })
	l.Add(Entry{Kind: "request", Op: "Get", Result: "denied: no permission"})
	l.Add(Entry{Kind: "request", Op: "Locate", Result: "ok"})
	l.Add(Entry{Kind: "event", Op: "login", Result: "invalid credentials"})
	if len(seen) != 3 || seen[0].Outcome != OutcomeDenied || seen[1].Outcome != OutcomeSuccess || seen[2].Category != "authentication" || seen[2].Outcome != OutcomeFailure {
		t.Fatalf("%+v", seen)
	}
}
