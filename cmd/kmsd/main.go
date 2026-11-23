// kmsd: the pqc-kms backend. It serves
//
//	KMIP (binary TTLV, mutual TLS)        -kmip-listen    default :5696   client plane
//	client REST API (mutual TLS)          -rest-listen    default :9998   client plane
//	administration REST API (mutual TLS)  -admin-listen   default :9999   control plane
//
// Keys live in one encrypted database file. Its master key comes from a file or, preferably, from a
// TPM-protected localhsm keystore (-master-hsm). The client log and the administration log are separate files.
package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/wpdlatm2/kms/internal/kmipsrv"
	"github.com/wpdlatm2/kms/internal/kms"
	"github.com/wpdlatm2/kms/internal/logs"
	"github.com/wpdlatm2/kms/internal/restsrv"
	"github.com/wpdlatm2/kms/internal/selfcheck"
	"github.com/wpdlatm2/kms/internal/syslogx"
)

// sys is the system log (syslog / journald) of the program: start, stop, errors, self test results.
var sys = syslogx.New("kmsd")

func die(err error) {
	sys.Criticalf("fatal: %v", err)
	os.Exit(1)
}

// hostPort turns a listen address (":5696", "0.0.0.0:5696") into one this process can dial.
func hostPort(listen string) string {
	if listen == "" {
		return ""
	}
	h, p, err := net.SplitHostPort(listen)
	if err != nil {
		return ""
	}
	if h == "" || h == "0.0.0.0" || h == "::" {
		h = "127.0.0.1"
	}
	return net.JoinHostPort(h, p)
}

func split(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func main() {
	started := time.Now()
	data := flag.String("data", "/data", "data directory (database, logs)")
	masterFile := flag.String("master-file", "", "file holding the 32-byte database master key (created if missing)")
	masterHSM := flag.String("master-hsm", "", "localhsm keystore file protecting the database master key with the TPM")
	masterTPM := flag.String("master-tpm-name", "pqc-kms", "name of the TPM key for -master-hsm")
	masterSoft := flag.Bool("master-allow-software", false, "with -master-hsm: allow a software protector when no TPM exists (NOT for production)")
	tlsCert := flag.String("tls-cert", "", "server certificate (PEM)")
	tlsKey := flag.String("tls-key", "", "server key (PEM)")
	clientCA := flag.String("client-ca", "", "CA that issues client certificates (PEM)")
	kmipAddr := flag.String("kmip-listen", ":5696", "KMIP listen address ('' = off)")
	restAddr := flag.String("rest-listen", ":9998", "client REST API listen address ('' = off)")
	adminAddr := flag.String("admin-listen", ":9999", "administration API listen address")
	roots := flag.String("root-admin", "", "comma-separated identities that are global administrators (bootstrap)")
	proxies := flag.String("trusted-proxy", "", "comma-separated certificate names allowed to act for a user (the web console)")
	retention := flag.Int("audit-retention-days", 1825, "minimum days audit files are kept; purging younger files is refused (set per your compliance policy; 5 years is a common financial-sector minimum)")
	scInterval := flag.Duration("selfcheck-interval", 5*time.Minute, "self test of the KMIP, REST and administration ports, the master key and the data directory (0 = off); results go to the system log")
	scCert := flag.String("selfcheck-cert", "", "client certificate of the self test identity (it must hold no rights; without it the ports are only tested up to the TLS handshake)")
	scKey := flag.String("selfcheck-key", "", "key of the self test identity")
	syslogAddr := flag.String("audit-syslog", "", "forward audit entries to a syslog collector: tcp://host:514 or tls://host:6514 (RFC 5424)")
	flag.Parse()

	sys.Noticef("starting: pid %d, go %s, data %s", os.Getpid(), runtime.Version(), *data)
	logs.ErrorHook = func(msg string) { sys.Errorf("%s", msg) }
	if *tlsCert == "" || *tlsKey == "" || *clientCA == "" {
		die(fmt.Errorf("-tls-cert, -tls-key and -client-ca are required: every port uses mutual TLS"))
	}
	if *adminAddr == "" {
		die(fmt.Errorf("the administration API cannot be switched off"))
	}
	if err := os.MkdirAll(*data, 0o700); err != nil {
		die(err)
	}

	var sealer kms.Sealer
	var err error
	switch {
	case *masterHSM != "":
		sealer, err = kms.OpenHSMSealer(*masterHSM, *masterTPM, *masterSoft)
	case *masterFile != "":
		sealer, err = kms.LoadFileSealer(*masterFile)
	default:
		err = fmt.Errorf("choose -master-hsm (TPM) or -master-file")
	}
	if err != nil {
		die(err)
	}
	st, err := kms.OpenStore(filepath.Join(*data, "kms.db"), sealer)
	if err != nil {
		die(err)
	}
	macKey, err := loadAuditKey(filepath.Join(*data, "audit.key"), sealer)
	if err != nil {
		die(err)
	}
	ret := time.Duration(*retention) * 24 * time.Hour
	clientLog, err := logs.OpenWith(logs.Options{Path: filepath.Join(*data, "client.log.jsonl"), Name: "client", Key: macKey, Retention: ret})
	if err != nil {
		die(err)
	}
	adminLog, err := logs.OpenWith(logs.Options{Path: filepath.Join(*data, "admin.log.jsonl"), Name: "admin", Key: macKey, Retention: ret})
	if err != nil {
		die(err)
	}
	clientLog.AddSink(logs.SysSink(sys, "client"))
	adminLog.AddSink(logs.SysSink(sys, "admin"))
	if *syslogAddr != "" {
		fw, err := logs.NewSyslogForwarder(*syslogAddr, "kmsd")
		if err != nil {
			die(err)
		}
		clientLog.AddSink(fw.Send)
		adminLog.AddSink(fw.Send)
	}
	handshakeFail := func(remote, reason string) {
		clientLog.Add(logs.Entry{Plane: "client", Kind: "event", Who: "unknown", Op: "tls-handshake", Result: "denied: " + reason, Remote: remote, Category: "authentication"})
	}
	svc := kms.NewService(st, split(*roots))
	svc.Audit = func(ev kms.AuditEvent) {
		e := logs.Entry{Plane: string(ev.Plane), Kind: "event", Who: ev.Who, Op: ev.Op, Target: ev.Target, Detail: ev.Detail, Result: ev.Result, Approval: ev.Approval, Owner: ev.Owner}
		if ev.Plane == kms.PlaneAdmin {
			adminLog.Add(e)
		} else {
			clientLog.Add(e)
		}
	}

	cert, err := tls.LoadX509KeyPair(*tlsCert, *tlsKey)
	if err != nil {
		die(err)
	}
	caPEM, err := os.ReadFile(*clientCA)
	if err != nil {
		die(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		die(fmt.Errorf("-client-ca contains no certificate"))
	}
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, MinVersion: tls.VersionTLS12}

	lg := log.New(sys.Writer(), "", 0) // the KMIP server's own messages (handshake failures, recovered panics) go to the system log
	lg.Printf("database %s sealed by %s", filepath.Join(*data, "kms.db"), sealer.Name())
	for _, l := range []*logs.Log{clientLog, adminLog} { // the audit chains are checked once at start
		if rep, err := l.Verify(macKey); err != nil {
			sys.Errorf("audit log %s cannot be read: %v", l.Name(), err)
		} else if !rep.OK {
			sys.Criticalf("audit log %s FAILED the integrity check at start: %s (%s)", l.Name(), rep.Problem, rep.Where)
		} else {
			sys.Infof("audit log %s verified at start: %d entries", l.Name(), rep.Entries)
		}
		if l.Recovered != "" {
			sys.Warnf("audit log %s: %s", l.Name(), l.Recovered)
		}
	}

	if *kmipAddr != "" {
		ks := &kmipsrv.Server{Svc: svc, TLS: tlsCfg, Log: lg, Access: clientLog}
		go func() { die(ks.ListenAndServe(*kmipAddr)) }()
		lg.Printf("KMIP (client plane) on %s", *kmipAddr)
	}
	if *restAddr != "" {
		if _, _, err := restsrv.ServeAudited(*restAddr, tlsCfg, restsrv.NewClient(svc, clientLog), handshakeFail); err != nil {
			die(err)
		}
		lg.Printf("client REST API on %s", *restAddr)
	}
	admin := restsrv.NewAdmin(&restsrv.Admin{Svc: svc, Log: adminLog, ClientLog: clientLog, TrustedProxies: split(*proxies), MACKey: macKey,
		Info: func() map[string]any {
			head := func(l *logs.Log) map[string]any {
				seq, _ := l.Head()
				m := map[string]any{"seq": seq}
				if e := l.Last(1); len(e) == 1 {
					m["lastTime"] = e[0].Time.Format(time.RFC3339)
				}
				return m
			}
			out := map[string]any{"sealer": sealer.Name(), "kmip": *kmipAddr, "clientRest": *restAddr, "adminApi": *adminAddr,
				"startedAt": started.Format(time.RFC3339), "uptimeSeconds": int64(time.Since(started).Seconds()), "goVersion": runtime.Version(),
				"selfcheck": selfInfo(),
				"audit":     map[string]any{"client": head(clientLog), "admin": head(adminLog), "retentionDays": *retention, "syslog": *syslogAddr != ""}}
			if fi, err := os.Stat(filepath.Join(*data, "kms.db")); err == nil {
				out["dbBytes"] = fi.Size()
			}
			return out
		}})
	if _, _, err := restsrv.ServeAudited(*adminAddr, tlsCfg, admin, func(remote, reason string) {
		adminLog.Add(logs.Entry{Plane: "admin", Kind: "event", Who: "unknown", Op: "tls-handshake", Result: "denied: " + reason, Remote: remote, Category: "authentication"})
	}); err != nil {
		die(err)
	}
	lg.Printf("administration API on %s (separate port, separate log)", *adminAddr)

	var checker *selfcheck.Runner
	if *scInterval > 0 {
		tg := selfcheck.Targets{KMIP: hostPort(*kmipAddr), REST: hostPort(*restAddr), Admin: hostPort(*adminAddr), ServerName: "localhost", CA: pool, Sealer: sealer, DataDir: *data, Stats: svc.Stats}
		if *scCert != "" || *scKey != "" {
			c, err := tls.LoadX509KeyPair(*scCert, *scKey)
			if err != nil {
				die(fmt.Errorf("self test identity: %w", err))
			}
			tg.Cert = &c
		} else {
			sys.Warnf("selfcheck: no -selfcheck-cert; the ports are only tested up to the TLS handshake")
		}
		checker = &selfcheck.Runner{Checks: selfcheck.Standard(tg), Interval: *scInterval, Sys: sys,
			OnChange: func(r selfcheck.Report, was bool) {
				op, res, out := "selfcheck-failed", "error: "+selfcheck.Summary(r), logs.OutcomeFailure
				if r.OK {
					op, res, out = "selfcheck-recovered", "ok", logs.OutcomeSuccess
				}
				adminLog.Add(logs.Entry{Plane: "admin", Kind: "event", Who: "system", Op: op, Category: "system", Outcome: out, Result: res, Detail: selfcheck.Summary(r)})
			}}
		selfCtx, stopSelf := context.WithCancel(context.Background())
		defer stopSelf()
		checker.Start(selfCtx, 2*time.Second)
	}
	selfInfo = func() any {
		if checker == nil {
			return map[string]any{"enabled": false}
		}
		r, ok := checker.Last()
		return map[string]any{"enabled": true, "intervalSeconds": int(checker.Interval.Seconds()), "ran": ok, "report": r}
	}
	sys.Noticef("started: sealer %s; KMIP %q, REST %q, admin API %q; self test every %v", sealer.Name(), *kmipAddr, *restAddr, *adminAddr, *scInterval)
	adminLog.Add(logs.Entry{Plane: "admin", Kind: "event", Who: "system", Op: "startup", Result: "ok", Detail: "sealer " + sealer.Name() + "; audit retention " + strconv.Itoa(*retention) + " days"})
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	got := <-sig
	sys.Noticef("stopping: received %v", got)
	adminLog.Add(logs.Entry{Plane: "admin", Kind: "event", Who: "system", Op: "shutdown", Result: "ok"})
	clientLog.Close()
	adminLog.Close()
	sys.Noticef("stopped")
	sys.Close()
}

// selfInfo is set once the self test is configured; the status endpoint reads it.
var selfInfo = func() any { return map[string]any{"enabled": false} }

// loadAuditKey returns the key that authenticates audit entries (HMAC). It is generated once and kept sealed by
// the same protector as the database (TPM-bound with -master-hsm), so editing the log files is not enough to
// forge a valid chain.
func loadAuditKey(path string, sealer kms.Sealer) ([]byte, error) {
	aad := []byte("pqc-kms audit mac key v1")
	if b, err := os.ReadFile(path); err == nil { // #nosec G304 -- fixed name inside the data directory
		return sealer.Open(aad, b)
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	blob, err := sealer.Seal(aad, k)
	if err != nil {
		return nil, err
	}
	return k, os.WriteFile(path, blob, 0o600)
}
