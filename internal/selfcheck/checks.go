package selfcheck

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/wpdlatm2/localhsm/kmip"
)

// Sealer is the master key protector of the database (a TPM-bound one in production).
type Sealer interface {
	Seal(aad, plaintext []byte) ([]byte, error)
	Open(aad, blob []byte) ([]byte, error)
}

// Targets describe what the standard checks test.
type Targets struct {
	KMIP, REST, Admin string // host:port as reachable from this process ("" = not served)
	ServerName        string // name in the server certificate (e.g. localhost)
	CA                *x509.CertPool
	// Cert is the identity of the self test (a client certificate that holds no rights at all). Without it the
	// ports are only tested up to the TLS handshake.
	Cert    *tls.Certificate
	Sealer  Sealer
	DataDir string
	Stats   func() map[string]int // reads the object store
}

func (t Targets) tlsConfig() *tls.Config {
	c := &tls.Config{RootCAs: t.CA, ServerName: t.ServerName, MinVersion: tls.VersionTLS12}
	if t.Cert != nil {
		c.Certificates = []tls.Certificate{*t.Cert}
	}
	return c
}

// Standard returns the checks of the key server.
func Standard(t Targets) []Check {
	var cs []Check
	if t.KMIP != "" {
		if t.Cert != nil {
			cs = append(cs, Check{"kmip", t.kmip})
		} else {
			cs = append(cs, Check{"kmip", func(ctx context.Context) (string, error) { return t.handshake(ctx, t.KMIP) }})
		}
	}
	if t.REST != "" {
		if t.Cert != nil {
			cs = append(cs, Check{"rest", t.rest})
		} else {
			cs = append(cs, Check{"rest", func(ctx context.Context) (string, error) { return t.handshake(ctx, t.REST) }})
		}
	}
	if t.Admin != "" {
		if t.Cert != nil {
			cs = append(cs, Check{"admin-api", t.admin})
		} else {
			cs = append(cs, Check{"admin-api", func(ctx context.Context) (string, error) { return t.handshake(ctx, t.Admin) }})
		}
	}
	if t.Sealer != nil {
		cs = append(cs, Check{"master-key", t.sealer})
	}
	if t.Stats != nil {
		cs = append(cs, Check{"store", func(context.Context) (string, error) {
			n := 0
			for _, v := range t.Stats() {
				n += v
			}
			return fmt.Sprintf("%d keys", n), nil
		}})
	}
	if t.DataDir != "" {
		cs = append(cs, Check{"data-dir", t.dataDir})
	}
	return cs
}

// handshake connects and completes TLS without a client certificate. A server that insists on one ends the
// session with an alert right after; that alert proves the TLS layer of the service is alive.
func (t Targets) handshake(ctx context.Context, addr string) (string, error) {
	d := &tls.Dialer{NetDialer: &net.Dialer{Timeout: 5 * time.Second}, Config: t.tlsConfig()}
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		if strings.Contains(err.Error(), "certificate required") || strings.Contains(err.Error(), "bad certificate") {
			return "tls up (client certificate demanded)", nil
		}
		return "", err
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(1 * time.Second))
	_, rerr := c.Read(make([]byte, 1))
	if rerr != nil && (strings.Contains(rerr.Error(), "certificate required") || strings.Contains(rerr.Error(), "bad certificate") || errors.Is(rerr, io.EOF)) {
		return "tls up", nil
	}
	return "tls up", nil
}

// kmip runs a real protocol exchange: version negotiation, Query, and a Locate that goes through the
// permission layer (the self test identity has no rights, so it must come back empty, not with an error).
func (t Targets) kmip(ctx context.Context) (string, error) {
	c, err := kmip.Dial(ctx, kmip.Config{Addr: t.KMIP, TLS: t.tlsConfig(), Timeout: 8 * time.Second})
	if err != nil {
		return "", err
	}
	defer c.Close()
	info, err := c.Query()
	if err != nil {
		return "", fmt.Errorf("query: %w", err)
	}
	if len(info.Operations) == 0 {
		return "", errors.New("query: the server lists no operations")
	}
	ids, err := c.Locate("kms-selfcheck-probe")
	if err != nil {
		return "", fmt.Errorf("locate: %w", err)
	}
	if len(ids) != 0 {
		return "", errors.New("locate: the self test identity sees objects it should not")
	}
	return fmt.Sprintf("KMIP %s, %d operations", c.Version(), len(info.Operations)), nil
}

func (t Targets) httpClient() *http.Client {
	return &http.Client{Timeout: 8 * time.Second, Transport: &http.Transport{TLSClientConfig: t.tlsConfig(), DisableKeepAlives: true}}
}

func (t Targets) get(ctx context.Context, base, path string, v any) error {
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://"+base+path, nil)
	resp, err := t.httpClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != 200 {
		return fmt.Errorf("GET %s: HTTP %d", path, resp.StatusCode)
	}
	if v != nil {
		return json.NewDecoder(bytes.NewReader(b)).Decode(v)
	}
	return nil
}

func (t Targets) rest(ctx context.Context) (string, error) {
	var cat struct {
		Count int `json:"count"`
	}
	if err := t.get(ctx, t.REST, "/v1/catalog", &cat); err != nil {
		return "", err
	}
	if cat.Count == 0 {
		return "", errors.New("the algorithm catalog is empty")
	}
	var list struct {
		Count int `json:"count"`
	}
	if err := t.get(ctx, t.REST, "/v1/keys?name=kms-selfcheck-probe", &list); err != nil {
		return "", err
	}
	if list.Count != 0 {
		return "", errors.New("the self test identity sees keys it should not")
	}
	return fmt.Sprintf("%d algorithms", cat.Count), nil
}

func (t Targets) admin(ctx context.Context) (string, error) {
	var me struct {
		Global bool `json:"global"`
	}
	if err := t.get(ctx, t.Admin, "/admin/v1/me", &me); err != nil {
		return "", err
	}
	if me.Global {
		return "", errors.New("the self test identity holds a management role; it must hold none")
	}
	return "me ok", nil
}

func (t Targets) sealer(context.Context) (string, error) {
	pt := make([]byte, 16)
	if _, err := rand.Read(pt); err != nil {
		return "", err
	}
	aad := []byte("pqc-kms selfcheck")
	blob, err := t.Sealer.Seal(aad, pt)
	if err != nil {
		return "", fmt.Errorf("seal: %w", err)
	}
	back, err := t.Sealer.Open(aad, blob)
	if err != nil {
		return "", fmt.Errorf("open: %w", err)
	}
	if !bytes.Equal(back, pt) {
		return "", errors.New("seal/open round trip returned different data")
	}
	return "seal/open round trip", nil
}

func (t Targets) dataDir(context.Context) (string, error) {
	f, err := os.CreateTemp(t.DataDir, ".selfcheck-*")
	if err != nil {
		return "", fmt.Errorf("the data directory is not writable: %w", err)
	}
	name := f.Name()
	_, werr := f.Write([]byte("ok"))
	_ = f.Close()
	_ = os.Remove(name)
	if werr != nil {
		return "", fmt.Errorf("write: %w", werr)
	}
	return "writable (" + filepath.Base(t.DataDir) + ")", nil
}
