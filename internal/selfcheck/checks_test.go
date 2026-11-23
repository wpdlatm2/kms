package selfcheck

import (
	"context"
	"crypto/tls"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wpdlatm2/kms/internal/kmipsrv"
	"github.com/wpdlatm2/kms/internal/kms"
	"github.com/wpdlatm2/kms/internal/logs"
	"github.com/wpdlatm2/kms/internal/restsrv"
	"github.com/wpdlatm2/kms/internal/syslogx"
	"github.com/wpdlatm2/kms/internal/testpki"
)

type stack struct {
	t                 *testing.T
	pki               *testpki.PKI
	kmip, rest, admin string
	srv               *kmipsrv.Server
	sealer            kms.Sealer
	dir               string
	svc               *kms.Service
}

func newStack(t *testing.T) *stack {
	dir := t.TempDir()
	sl, _ := kms.LoadFileSealer(filepath.Join(dir, "m.key"))
	st, err := kms.OpenStore(filepath.Join(dir, "kms.db"), sl)
	if err != nil {
		t.Fatal(err)
	}
	svc := kms.NewService(st, []string{"root"})
	pki := testpki.New(t)
	cl, _ := logs.Open("", "client")
	al, _ := logs.Open("", "admin")
	srv := &kmipsrv.Server{Svc: svc, TLS: pki.ServerTLS(), Access: cl}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", srv.TLS)
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	t.Cleanup(srv.Close)
	rs, rln, err := restsrv.Serve("127.0.0.1:0", pki.ServerTLS(), restsrv.NewClient(svc, cl))
	if err != nil {
		t.Fatal(err)
	}
	as, aln, err := restsrv.Serve("127.0.0.1:0", pki.ServerTLS(), restsrv.NewAdmin(&restsrv.Admin{Svc: svc, Log: al, ClientLog: cl}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rs.Close(); as.Close() })
	return &stack{t: t, pki: pki, kmip: ln.Addr().String(), rest: rln.Addr().String(), admin: aln.Addr().String(), srv: srv, sealer: sl, dir: dir, svc: svc}
}

func (s *stack) targets(withCert bool) Targets {
	cc := s.pki.ClientTLS("kms-selfcheck")
	t := Targets{KMIP: s.kmip, REST: s.rest, Admin: s.admin, ServerName: cc.ServerName, CA: cc.RootCAs, Sealer: s.sealer, DataDir: s.dir, Stats: s.svc.Stats}
	if withCert {
		t.Cert = &cc.Certificates[0]
	}
	return t
}

func run(t *testing.T, ts Targets) (Report, string) {
	var sb strings.Builder
	sys := syslogx.Discard()
	sys.SetStderr(&sb)
	r := &Runner{Checks: Standard(ts), Sys: sys}
	return r.Run(context.Background()), sb.String()
}

func TestSelfCheckAgainstRealServices(t *testing.T) {
	s := newStack(t)
	rep, line := run(t, s.targets(true))
	if !rep.OK || len(rep.Results) != 6 {
		t.Fatalf("%+v\n%s", rep, line)
	}
	for _, want := range []string{"kmip=ok(", "KMIP ", "rest=ok(", "admin-api=ok(", "master-key=ok(", "store=ok(", "data-dir=ok("} {
		if !strings.Contains(line, want) {
			t.Fatalf("missing %q in %s", want, line)
		}
	}
	if !strings.Contains(line, "INFO discard: selfcheck ok") {
		t.Fatal(line)
	}
}

func TestSelfCheckSeesOutagesAndBrokenParts(t *testing.T) {
	s := newStack(t)
	ts := s.targets(true)
	s.srv.Close() // the KMIP listener goes away
	rep, line := run(t, ts)
	if rep.OK || !strings.Contains(line, "kmip=FAIL(") || !strings.Contains(line, "rest=ok(") || !strings.Contains(line, "ERR discard: selfcheck FAILED") {
		t.Fatalf("%+v\n%s", rep, line)
	}
	ts = s.targets(true)
	ts.DataDir = filepath.Join(s.dir, "does-not-exist")
	ts.Admin = "127.0.0.1:1"
	rep, line = run(t, ts)
	if rep.OK || !strings.Contains(line, "data-dir=FAIL(") || !strings.Contains(line, "admin-api=FAIL(") {
		t.Fatalf("%+v\n%s", rep, line)
	}
}

func TestHandshakeOnlyModeWithoutIdentity(t *testing.T) {
	s := newStack(t)
	rep, line := run(t, s.targets(false))
	if !rep.OK || !strings.Contains(line, "tls up") {
		t.Fatalf("%+v\n%s", rep, line)
	}
	ts := s.targets(false)
	ts.REST = "127.0.0.1:1"
	if rep, _ := run(t, ts); rep.OK {
		t.Fatal("a closed port passed")
	}
}
