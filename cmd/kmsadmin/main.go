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
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/wpdlatm2/kms/internal/admin"
)

func die(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
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
		srv, err := admin.New(b, u, *logFile, *tlsCert != "", admin.Options{OTP: *otpPolicy, Issuer: *otpIssuer})
		if err != nil {
			die(err)
		}
		fmt.Printf("kmsadmin: %s  ->  %s\n", *listen, *backend)
		die(admin.ListenAndServe(*listen, *tlsCert, *tlsKey, srv))
	default:
		die(fmt.Errorf("unknown command %q (useradd | otp-reset | serve)", flag.Arg(0)))
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
		ca, err := os.ReadFile(caFile)
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
