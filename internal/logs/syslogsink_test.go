package logs

import (
	"strings"
	"testing"

	"github.com/wpdlatm2/kms/internal/syslogx"
)

func TestSysSinkKeepsOperationsNewsOnly(t *testing.T) {
	var sb strings.Builder
	sys := syslogx.Discard()
	sys.SetStderr(&sb)
	l, _ := Open("", "admin")
	l.AddSink(SysSink(sys, "admin"))
	l.Add(Entry{Plane: "admin", Kind: "request", Who: "root", Op: "GET /admin/v1/keys", Result: "ok"}) // routine: not repeated
	l.Add(Entry{Plane: "client", Kind: "event", Who: "app", Op: "get", Result: "ok"})                  // key read: audit only
	l.Add(Entry{Plane: "admin", Kind: "event", Who: "root", Op: "binding-put", Target: "app", Approval: "APR-1", Owner: "kim", Result: "ok"})
	l.Add(Entry{Plane: "admin", Kind: "event", Who: "ev\nil", Op: "key-destroy", Result: "denied: no permission"})
	out := sb.String()
	if strings.Contains(out, "GET /admin/v1/keys") || strings.Contains(out, "op=get ") {
		t.Fatalf("routine entries were repeated:\n%s", out)
	}
	if !strings.Contains(out, `NOTICE discard: admin audit: op=binding-put outcome=success who="root" target="app" approval="APR-1" owner="kim"`) {
		t.Fatalf("grant missing:\n%s", out)
	}
	if !strings.Contains(out, "WARN discard: admin audit: op=key-destroy outcome=denied") || strings.Count(out, "\n") != 2 {
		t.Fatalf("refusal missing or log forged:\n%s", out)
	}
}
