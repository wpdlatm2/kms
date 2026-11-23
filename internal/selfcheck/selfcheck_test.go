package selfcheck

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/wpdlatm2/kms/internal/syslogx"
)

func TestRunLogsAndReportsChanges(t *testing.T) {
	var buf bytes.Buffer
	sys := syslogx.Discard()
	sys.SetStderr(&buf)
	fail := false
	var changes []bool
	r := &Runner{Sys: sys, Checks: []Check{
		{"kmip", func(context.Context) (string, error) { return "v1.4", nil }},
		{"rest", func(context.Context) (string, error) {
			if fail {
				return "", errors.New("connect: refused\nwith newline")
			}
			return "", nil
		}},
		{"boom", func(context.Context) (string, error) { panic("oops") }},
	}, OnChange: func(rep Report, was bool) { changes = append(changes, rep.OK) }}
	rep := r.Run(context.Background())
	if rep.OK || len(rep.Results) != 3 || rep.Results[2].OK || !strings.Contains(rep.Results[2].Error, "panicked") {
		t.Fatalf("%+v", rep)
	}
	if !strings.Contains(buf.String(), "ERR discard: selfcheck FAILED (1 in a row)") || !strings.Contains(buf.String(), "kmip=ok(") || !strings.Contains(buf.String(), "boom=FAIL(") {
		t.Fatalf("%s", buf.String())
	}
	r.Checks = r.Checks[:2]
	fail = true
	r.Run(context.Background())
	fail = false
	buf.Reset()
	rep = r.Run(context.Background())
	if !rep.OK || !strings.Contains(buf.String(), "NOTICE discard: selfcheck RECOVERED") {
		t.Fatalf("%+v %s", rep, buf.String())
	}
	buf.Reset()
	r.Run(context.Background())
	if !strings.Contains(buf.String(), "INFO discard: selfcheck ok:") {
		t.Fatal(buf.String())
	}
	// first run failed -> change reported; second failure -> not again; recovery -> reported
	if len(changes) != 2 || changes[0] != false || changes[1] != true {
		t.Fatalf("changes %v", changes)
	}
	if last, ok := r.Last(); !ok || !last.OK {
		t.Fatal("last")
	}
}
