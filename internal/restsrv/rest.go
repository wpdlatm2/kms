// Package restsrv serves the two REST APIs of the backend on separate ports:
//
//   - the client API (/v1): what applications use to find, read and (if their template allows) create and
//     change keys. Rights come from the client's group bindings.
//   - the administration API (/admin/v1): services and super groups, templates, mappings, management grants,
//     key lifecycle and the logs. Rights come from management scopes. It never returns key values.
//
// Both require mutual TLS and write to separate logs. They follow the same key lifecycle as KMIP but use
// common values instead of KMIP data types (see model.go).
package restsrv

import (
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/wpdlatm2/kms/internal/kms"
	"github.com/wpdlatm2/kms/internal/logs"
)

// Serve runs an HTTPS server that requires client certificates.
func Serve(addr string, cfg *tls.Config, h http.Handler) (*http.Server, net.Listener, error) {
	if cfg == nil || cfg.ClientAuth != tls.RequireAndVerifyClientCert {
		return nil, nil, errors.New("restsrv: TLS with required client certificates is mandatory")
	}
	ln, err := tls.Listen("tcp", addr, cfg)
	if err != nil {
		return nil, nil, err
	}
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 2 * time.Minute}
	go srv.Serve(ln)
	return srv, ln, nil
}

// ---- client API

// Client is the data-plane API.
type Client struct {
	Svc *kms.Service
	Log *logs.Log
	mux *http.ServeMux
}

func NewClient(svc *kms.Service, log *logs.Log) *Client {
	c := &Client{Svc: svc, Log: log, mux: http.NewServeMux()}
	c.mux.HandleFunc("GET /v1/catalog", c.wrap(func(w http.ResponseWriter, r *http.Request, p kms.Principal) {
		writeJSON(w, 200, map[string]any{"count": len(catalog()), "algorithms": catalog(), "usages": kms.UsageList()})
	}))
	c.mux.HandleFunc("GET /v1/keys", c.wrap(c.list))
	c.mux.HandleFunc("GET /v1/keys/{id}", c.wrap(c.get))
	c.mux.HandleFunc("GET /v1/keys/{id}/value", c.wrap(c.value))
	c.mux.HandleFunc("POST /v1/keys", c.wrap(c.create))
	c.mux.HandleFunc("POST /v1/keys/{id}/{action}", c.wrap(c.act))
	return c
}

func (c *Client) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	requestID(w)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	c.mux.ServeHTTP(w, r)
}

func (c *Client) wrap(h func(http.ResponseWriter, *http.Request, kms.Principal)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cn := peerCN(r)
		if cn == "" {
			failWith(w, http.StatusUnauthorized, "unauthorized", "a client certificate is required")
			return
		}
		sw := &statusWriter{ResponseWriter: w, code: 200}
		h(sw, r, kms.ClientPrincipal(cn))
		res := "ok"
		if sw.code >= 400 {
			res = "error: HTTP " + strconv.Itoa(sw.code)
		}
		c.Log.Add(logs.Entry{Plane: "client", Kind: "request", Who: cn, Op: "REST " + r.Method + " " + r.URL.Path, Detail: "request " + w.Header().Get("X-Request-Id"), Result: res, Remote: remoteIP(r)})
	}
}

func (c *Client) list(w http.ResponseWriter, r *http.Request, p kms.Principal) {
	writeJSON(w, 200, keyList(c.Svc, p, c.Svc.List(p, filterFrom(r))))
}

func (c *Client) get(w http.ResponseWriter, r *http.Request, p kms.Principal) {
	if !validID(r.PathValue("id")) {
		failWith(w, http.StatusNotFound, "not_found", "no such object")
		return
	}
	v, err := c.Svc.Attributes(p, r.PathValue("id"))
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, 200, keyJSON(c.Svc, p, v))
}

// value releases the key value: GET /v1/keys/{id}/value?encoding=base64|hex|pem
func (c *Client) value(w http.ResponseWriter, r *http.Request, p kms.Principal) {
	if !validID(r.PathValue("id")) {
		failWith(w, http.StatusNotFound, "not_found", "no such object")
		return
	}
	m, err := c.Svc.GetMaterial(p, r.PathValue("id"))
	if err != nil {
		fail(w, err)
		return
	}
	defer clear(m.Bytes)
	format := formatName(m.Info.Format)
	data, enc, err := encodeValue(format, r.URL.Query().Get("encoding"), m.Bytes)
	if err != nil {
		fail(w, err)
		return
	}
	var out ValueResponse
	out.Key = keyJSON(c.Svc, p, m.Info)
	out.Value.Format, out.Value.Encoding, out.Value.Data, out.Value.SizeBytes = format, enc, data, len(m.Bytes)
	writeJSON(w, 200, out)
}

func (c *Client) create(w http.ResponseWriter, r *http.Request, p kms.Principal) {
	var b createBody
	if err := decode(r, &b); err != nil {
		fail(w, err)
		return
	}
	req, err := b.req()
	if err != nil {
		fail(w, err)
		return
	}
	vs, err := c.Svc.Create(p, req)
	if err != nil {
		fail(w, err)
		return
	}
	w.Header().Set("Location", "/v1/keys/"+vs[0].ID)
	writeJSON(w, 201, keyList(c.Svc, p, vs))
}

// ActionResponse is the answer of a lifecycle action. For rekey, Key is the new key and Replaced the old one.
type ActionResponse struct {
	Action   string   `json:"action"`
	Key      KeyJSON  `json:"key"`
	Replaced *KeyJSON `json:"replaced,omitempty"`
}

func doAction(s *kms.Service, p kms.Principal, id, action string) (ActionResponse, error) {
	v, err := s.Act(p, id, action)
	if err != nil {
		return ActionResponse{}, err
	}
	out := ActionResponse{Action: action, Key: keyJSON(s, p, v)}
	if action == "rekey" {
		if old, err := s.Attributes(p, id); err == nil {
			o := keyJSON(s, p, old)
			out.Replaced = &o
		}
	}
	return out, nil
}

func (c *Client) act(w http.ResponseWriter, r *http.Request, p kms.Principal) {
	if !validID(r.PathValue("id")) {
		failWith(w, http.StatusNotFound, "not_found", "no such object")
		return
	}
	out, err := doAction(c.Svc, p, r.PathValue("id"), r.PathValue("action"))
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, 200, out)
}
