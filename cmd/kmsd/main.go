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
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/wpdlatm2/kms/internal/kmipsrv"
	"github.com/wpdlatm2/kms/internal/kms"
	"github.com/wpdlatm2/kms/internal/logs"
	"github.com/wpdlatm2/kms/internal/restsrv"
)

func die(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
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
	flag.Parse()

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
	clientLog, err := logs.Open(filepath.Join(*data, "client.log.jsonl"), "client")
	if err != nil {
		die(err)
	}
	adminLog, err := logs.Open(filepath.Join(*data, "admin.log.jsonl"), "admin")
	if err != nil {
		die(err)
	}
	svc := kms.NewService(st, split(*roots))
	svc.Audit = func(ev kms.AuditEvent) {
		e := logs.Entry{Plane: string(ev.Plane), Kind: "event", Who: ev.Who, Op: ev.Op, Target: ev.Target, Detail: ev.Detail, Result: ev.Result}
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

	lg := log.New(os.Stderr, "kmsd: ", log.LstdFlags)
	lg.Printf("database %s sealed by %s", filepath.Join(*data, "kms.db"), sealer.Name())

	if *kmipAddr != "" {
		ks := &kmipsrv.Server{Svc: svc, TLS: tlsCfg, Log: lg, Access: clientLog}
		go func() { die(ks.ListenAndServe(*kmipAddr)) }()
		lg.Printf("KMIP (client plane) on %s", *kmipAddr)
	}
	if *restAddr != "" {
		if _, _, err := restsrv.Serve(*restAddr, tlsCfg, restsrv.NewClient(svc, clientLog)); err != nil {
			die(err)
		}
		lg.Printf("client REST API on %s", *restAddr)
	}
	admin := restsrv.NewAdmin(&restsrv.Admin{Svc: svc, Log: adminLog, ClientLog: clientLog, TrustedProxies: split(*proxies),
		Info: func() map[string]any {
			return map[string]any{"sealer": sealer.Name(), "kmip": *kmipAddr, "clientRest": *restAddr, "adminApi": *adminAddr}
		}})
	if _, _, err := restsrv.Serve(*adminAddr, tlsCfg, admin); err != nil {
		die(err)
	}
	lg.Printf("administration API on %s (separate port, separate log)", *adminAddr)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	lg.Printf("shutting down")
	clientLog.Close()
	adminLog.Close()
}
