// kmsadmin: the web console of the pqc-kms backend.
//
//	kmsadmin -users users.json useradd NAME                         (password: stdin, or KMSADMIN_PASSWORD)
//	kmsadmin -users users.json otp-reset NAME                       (lost phone: the user enrolls again)
//	kmsadmin -users users.json -backend https://kms:9999 -backend-ca ca.crt \
//	         -backend-cert console.crt -backend-key console.key serve
//
// The console logs people in and acts for them on the backend's administration API with its own client
// certificate, which the backend must list as a trusted proxy. Rights are managed in the backend.
package main

import (
	"bufio"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/wpdlatm2/kms/internal/admin"
	"github.com/wpdlatm2/kms/internal/sysctl"
	"github.com/wpdlatm2/kms/internal/syslogx"
)

var (
	sys     = syslogx.New("kmsadmin")
	serving bool
)

func die(err error) {
	if serving { // a failure of the running console is operations news; a mistyped command is not
		sys.Criticalf("fatal: %v", err)
	} else {
		fmt.Fprintln(os.Stderr, "error:", err)
	}
	os.Exit(1)
}

func main() {
	users := flag.String("users", "users.json", "account file")
	listen := flag.String("listen", "127.0.0.1:8443", "web listen address")
	tlsCert := flag.String("tls-cert", "", "web TLS certificate (required for non-loopback addresses)")
	tlsKey := flag.String("tls-key", "", "web TLS key")
	logFile := flag.String("log", "console.log.jsonl", "console log file (logins and logouts)")
	backend := flag.String("backend", "https://127.0.0.1:9999", "administration API of the backend")
	bca := flag.String("backend-ca", "", "CA that issued the backend certificate")
	bcert := flag.String("backend-cert", "", "console client certificate (PEM)")
	bkey := flag.String("backend-key", "", "console client key (PEM)")
	bname := flag.String("backend-server-name", "", "expected backend host name (default: host of -backend)")
	otpPolicy := flag.String("otp", "required", "one-time password policy: required | optional | off (an enrolled user always needs the code)")
	otpIssuer := flag.String("otp-issuer", "pqc-kms", "name shown in the authenticator app")
	retention := flag.Int("audit-retention-days", 1825, "minimum days console audit files are kept")
	syslogAddr := flag.String("audit-syslog", "", "forward console audit entries: tcp://host:514 or tls://host:6514")
	agentSock := flag.String("agent-socket", "", "Unix socket of kmsagent (enables service control in the dashboard)")
	probes := flag.String("probe", "", "ports the dashboard checks: name=host:port,... e.g. kmip=kms:5696,rest=kms:9998,admin=kms:9999")
	flag.Parse()
	if flag.NArg() == 0 {
		flag.Usage()
		os.Exit(2)
	}
	switch flag.Arg(0) {
	case "useradd":
		if flag.NArg() != 2 {
			die(fmt.Errorf("usage: kmsadmin -users FILE useradd NAME"))
		}
		pw := os.Getenv("KMSADMIN_PASSWORD")
		if pw == "" {
			fmt.Fprint(os.Stderr, "password (min 12 chars, read from stdin): ")
			pw, _ = bufio.NewReader(os.Stdin).ReadString('\n')
			pw = strings.TrimRight(pw, "\r\n")
		}
		u, err := admin.LoadUsers(*users)
		if err != nil {
			die(err)
		}
		if err := u.Set(flag.Arg(1), pw); err != nil {
			die(err)
		}
		fmt.Println("user saved:", flag.Arg(1), "(grant it management rights in the backend)")
	case "unlock":
		if flag.NArg() != 2 {
			die(fmt.Errorf("usage: kmsadmin -users FILE unlock NAME"))
		}
		u, err := admin.LoadUsers(*users)
		if err != nil {
			die(err)
		}
		if err := u.Unlock(flag.Arg(1)); err != nil {
			die(err)
		}
		fmt.Println("account unlocked:", flag.Arg(1))
	case "otp-reset":
		if flag.NArg() != 2 {
			die(fmt.Errorf("usage: kmsadmin -users FILE otp-reset NAME"))
		}
		u, err := admin.LoadUsers(*users)
		if err != nil {
			die(err)
		}
		if err := u.ResetOTP(flag.Arg(1)); err != nil {
			die(err)
		}
		fmt.Println("one-time password removed for", flag.Arg(1), "- the user enrolls again at the next login")
	case "serve":
		serving = true
		sys.Noticef("starting: pid %d, listen %s, backend %s", os.Getpid(), *listen, *backend)
		u, err := admin.LoadUsers(*users)
		if err != nil {
			die(err)
		}
		if u.Count() == 0 {
			die(fmt.Errorf("no users in %s: create one with 'useradd'", *users))
		}
		b, err := newBackend(*backend, *bca, *bcert, *bkey, *bname)
		if err != nil {
			die(err)
		}
		var agent sysctl.Client
		if *agentSock != "" {
			agent = sysctl.NewUnixClient(*agentSock)
		}
		var pr []admin.Probe
		for _, p := range strings.Split(*probes, ",") {
			if n, a, ok := strings.Cut(strings.TrimSpace(p), "="); ok && n != "" && a != "" {
				pr = append(pr, admin.Probe{Name: n, Addr: a})
			}
		}
		// the audit MAC key lives beside the log (mode 0600); the backend's own audit key is sealed by the TPM
		key, err := loadKey(*logFile + ".key")
		if err != nil {
			die(err)
		}
		srv, err := admin.New(b, u, *logFile, *tlsCert != "", admin.Options{OTP: *otpPolicy, Issuer: *otpIssuer, AuditKey: key, RetentionDays: *retention, Syslog: *syslogAddr, Agent: agent, Probes: pr})
		if err != nil {
			die(err)
		}
		srv.AttachSyslog(sys)
		sys.Noticef("started: console on %s (otp %s, agent %v)", *listen, *otpPolicy, agent != nil)
		go func() { die(admin.ListenAndServe(*listen, *tlsCert, *tlsKey, srv)) }()
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		got := <-sig
		sys.Noticef("stopping: received %v", got)
		srv.Close()
		sys.Noticef("stopped")
		sys.Close()
	default:
		die(fmt.Errorf("unknown command %q (useradd | unlock | otp-reset | serve)", flag.Arg(0)))
	}
}

func newBackend(base, caFile, certFile, keyFile, serverName string) (*admin.Backend, error) {
	if certFile == "" || keyFile == "" {
		return nil, fmt.Errorf("-backend-cert and -backend-key are required: the backend requires mutual TLS")
	}
	u, err := url.Parse(base)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("-backend must be an https URL")
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if caFile != "" {
		ca, err := os.ReadFile(caFile) // #nosec G304 -- operator-configured path
		if err != nil {
			return nil, err
		}
		if !pool.AppendCertsFromPEM(ca) {
			return nil, fmt.Errorf("-backend-ca contains no certificate")
		}
	} else if pool, err = x509.SystemCertPool(); err != nil {
		return nil, err
	}
	if serverName == "" {
		serverName = u.Hostname()
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: pool, ServerName: serverName, MinVersion: tls.VersionTLS12}
	return &admin.Backend{Base: strings.TrimRight(base, "/"),
		Client: &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: cfg, MaxIdleConns: 4, IdleConnTimeout: 60 * time.Second}}}, nil
}

func loadKey(path string) ([]byte, error) {
	if b, err := os.ReadFile(path); err == nil && len(b) == 32 { // #nosec G304 -- operator-configured path
		return b, nil
	}
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	return k, os.WriteFile(path, k, 0o600)
}
