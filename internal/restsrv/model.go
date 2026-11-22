package restsrv

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/wpdlatm2/kms/internal/kms"
)

// The REST API speaks in widely used values, not KMIP data types: lower-case state names, RFC 3339 times,
// standard algorithm and curve names, usage names, PEM/hex/base64 encodings. Requests carry only what an
// operation needs; responses carry everything known about the object.

// AlgorithmJSON describes an algorithm by the names the standards use.
type AlgorithmJSON struct {
	ID       string `json:"id"`                 // request value, e.g. ml-dsa-65
	Name     string `json:"name"`               // ML-DSA-65
	Family   string `json:"family"`             // ML-DSA
	Category string `json:"category"`           // symmetric | rsa | ec | pq-signature | pq-kem
	Standard string `json:"standard,omitempty"` // FIPS 204
	Curve    string `json:"curve,omitempty"`    // P-256, Ed25519
	Bits     int    `json:"bits,omitempty"`     // key size where the algorithm has one
}

// ValueJSON describes the stored key value (never the value itself).
type ValueJSON struct {
	Present           bool   `json:"present"`
	Format            string `json:"format,omitempty"` // raw | pkcs8 | x509-spki
	SizeBytes         int    `json:"sizeBytes,omitempty"`
	FingerprintSHA256 string `json:"fingerprintSha256,omitempty"` // public keys only
}

// KeyJSON is the wire form of a key object.
type KeyJSON struct {
	ID            string        `json:"id"`
	Names         []string      `json:"names"`
	Group         string        `json:"group"`
	ParentGroup   string        `json:"parentGroup,omitempty"`
	Type          string        `json:"type"` // symmetric | private | public
	Algorithm     AlgorithmJSON `json:"algorithm"`
	Usage         []string      `json:"usage"`
	State         string        `json:"state"` // pre-active | active | deactivated | compromised | destroyed | destroyed-compromised
	Creator       string        `json:"creator"`
	CreatedAt     string        `json:"createdAt,omitempty"`
	ActivatedAt   string        `json:"activatedAt,omitempty"`
	DeactivatedAt string        `json:"deactivatedAt,omitempty"`
	CompromisedAt string        `json:"compromisedAt,omitempty"`
	DestroyedAt   string        `json:"destroyedAt,omitempty"`
	UpdatedAt     string        `json:"updatedAt,omitempty"`
	PairID        string        `json:"pairId,omitempty"`
	PairRole      string        `json:"pairRole,omitempty"` // role of the paired key
	ReplacesID    string        `json:"replacesId,omitempty"`
	ReplacedByID  string        `json:"replacedById,omitempty"`
	Value         ValueJSON     `json:"value"`
	Actions       []string      `json:"actions"`     // lifecycle actions available now (state machine AND your rights)
	Permissions   []string      `json:"permissions"` // operations you hold on keys of this group
}

func ts(t int64) string {
	if t == 0 {
		return ""
	}
	return time.Unix(t, 0).UTC().Format(time.RFC3339)
}

func keyType(k uint32) string {
	switch k {
	case kms.KindPrivate:
		return "private"
	case kms.KindPublic:
		return "public"
	case kms.KindSecret:
		return "secret"
	}
	return "symmetric"
}

func formatName(f uint32) string {
	switch f {
	case 1:
		return "raw"
	case 4:
		return "pkcs8"
	case 5:
		return "x509-spki"
	}
	return "unknown"
}

func algorithmJSON(id string, bits int) AlgorithmJSON {
	if a := kms.LookupAlgo(id); a != nil {
		return AlgorithmJSON{ID: a.ID, Name: a.Name, Family: a.Family, Category: a.Category, Standard: a.Standard, Curve: a.CurveName, Bits: bits}
	}
	return AlgorithmJSON{ID: id, Name: id, Bits: bits}
}

func keyJSON(s *kms.Service, p kms.Principal, o kms.View) KeyJSON {
	k := KeyJSON{
		ID: o.ID, Names: o.Names, Group: o.Group, ParentGroup: s.ParentOf(o.Group), Type: keyType(o.Kind), Algorithm: algorithmJSON(o.Algo, o.Bits),
		Usage: kms.UsageNames(o.Usage), State: kms.StateID(o.State), Creator: o.Creator,
		CreatedAt: ts(o.Created), ActivatedAt: ts(o.Activated), DeactivatedAt: ts(o.Deactivated), CompromisedAt: ts(o.Compromised),
		DestroyedAt: ts(o.Destroyed), UpdatedAt: ts(o.Changed), PairID: o.PairID, ReplacesID: o.ReplacesID, ReplacedByID: o.ReplacedByID,
		Value:   ValueJSON{Present: o.ValueSize > 0, SizeBytes: o.ValueSize, FingerprintSHA256: o.Fingerprint},
		Actions: s.ActionsAllowed(p, o), Permissions: s.Permissions(p, o.Group),
	}
	if o.ValueSize > 0 {
		k.Value.Format = formatName(o.Format)
	}
	if o.PairID != "" {
		if o.Kind == kms.KindPrivate {
			k.PairRole = "public"
		} else {
			k.PairRole = "private"
		}
	}
	if k.Names == nil {
		k.Names = []string{}
	}
	return k
}

// ---- envelopes

type KeyList struct {
	Count int       `json:"count"`
	Keys  []KeyJSON `json:"keys"`
}

func keyList(s *kms.Service, p kms.Principal, vs []kms.View) KeyList {
	out := KeyList{Keys: []KeyJSON{}}
	for _, v := range vs {
		out.Keys = append(out.Keys, keyJSON(s, p, v))
	}
	out.Count = len(out.Keys)
	return out
}

// ErrorBody is the error answer of every endpoint.
type ErrorBody struct {
	Error     ErrorInfo `json:"error"`
	RequestID string    `json:"requestId"`
}

type ErrorInfo struct {
	Code    string `json:"code"` // invalid_request | unauthorized | permission_denied | not_found | invalid_state | conflict | unsupported | internal
	Message string `json:"message"`
	Status  int    `json:"status"`
}

type statusWriter struct {
	http.ResponseWriter
	code int
}

func (w *statusWriter) WriteHeader(c int) { w.code = c; w.ResponseWriter.WriteHeader(c) }

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func newRequestID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func failWith(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, ErrorBody{Error: ErrorInfo{Code: code, Message: msg, Status: status}, RequestID: w.Header().Get("X-Request-Id")})
}

func fail(w http.ResponseWriter, err error) {
	var ke *kms.Error
	if errors.As(err, &ke) {
		switch ke.Code {
		case kms.ErrNotFound:
			failWith(w, http.StatusNotFound, "not_found", ke.Msg)
		case kms.ErrDenied:
			failWith(w, http.StatusForbidden, "permission_denied", ke.Msg)
		case kms.ErrState:
			failWith(w, http.StatusConflict, "invalid_state", ke.Msg)
		case kms.ErrConflict:
			failWith(w, http.StatusConflict, "conflict", ke.Msg)
		case kms.ErrInvalid:
			failWith(w, http.StatusBadRequest, "invalid_request", ke.Msg)
		case kms.ErrUnsupported:
			failWith(w, http.StatusNotImplemented, "unsupported", ke.Msg)
		default:
			failWith(w, http.StatusInternalServerError, "internal", "internal error")
		}
		return
	}
	failWith(w, http.StatusBadRequest, "invalid_request", err.Error())
}

func decode(r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(nil, r.Body, 1<<16)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

func peerCN(r *http.Request) string {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return ""
	}
	return r.TLS.PeerCertificates[0].Subject.CommonName
}

func remoteIP(r *http.Request) string {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}

// ---- requests (minimal)

// createBody is everything a create request may carry; only "algorithm" is required (admin callers also name
// the group; a client bound to a single service can omit it).
type createBody struct {
	Algorithm string   `json:"algorithm"`
	Group     string   `json:"group,omitempty"`
	Name      string   `json:"name,omitempty"`
	Names     []string `json:"names,omitempty"`
	Usage     []string `json:"usage,omitempty"` // default: the algorithm's usual usages
	Activate  bool     `json:"activate,omitempty"`
}

func (b createBody) req() (kms.CreateReq, error) {
	mask, err := kms.ParseUsage(b.Usage)
	if err != nil {
		return kms.CreateReq{}, err
	}
	names := b.Names
	if b.Name != "" {
		names = append([]string{b.Name}, names...)
	}
	return kms.CreateReq{Algo: b.Algorithm, Group: b.Group, Names: names, Usage: mask, Activate: b.Activate}, nil
}

// ---- catalog

type catalogEntry struct {
	AlgorithmJSON
	Type     string   `json:"type"`
	Pair     bool     `json:"pair"`
	Usage    []string `json:"usage"` // default usages
	Label    string   `json:"label"`
	Group    string   `json:"group"`
	Produces []string `json:"produces"` // objects a create returns
}

func catalog() []catalogEntry {
	out := []catalogEntry{}
	for _, a := range kms.Catalog() {
		e := catalogEntry{AlgorithmJSON: AlgorithmJSON{ID: a.ID, Name: a.Name, Family: a.Family, Category: a.Category, Standard: a.Standard, Curve: a.CurveName, Bits: a.Bits},
			Type: a.Type, Pair: a.Pair, Usage: kms.UsageNames(a.Usage), Label: a.Label, Group: a.Group, Produces: []string{"symmetric"}}
		if a.Pair {
			e.Produces = []string{"private", "public"}
		}
		out = append(out, e)
	}
	return out
}

// ---- material

// ValueResponse is the answer of the key value endpoint.
type ValueResponse struct {
	Key   KeyJSON `json:"key"`
	Value struct {
		Format    string `json:"format"`   // raw | pkcs8 | x509-spki
		Encoding  string `json:"encoding"` // base64 | hex | pem
		Data      string `json:"data"`
		SizeBytes int    `json:"sizeBytes"`
	} `json:"value"`
}

func encodeValue(format, encoding string, b []byte) (data, enc string, err error) {
	switch strings.ToLower(encoding) {
	case "", "base64":
		return base64.StdEncoding.EncodeToString(b), "base64", nil
	case "hex":
		return hex.EncodeToString(b), "hex", nil
	case "pem":
		switch format {
		case "pkcs8":
			return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: b})), "pem", nil
		case "x509-spki":
			return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: b})), "pem", nil
		}
		return "", "", &kms.Error{Code: kms.ErrInvalid, Msg: "pem encoding is available for pkcs8 and x509-spki values only; this value is " + format}
	}
	return "", "", &kms.Error{Code: kms.ErrInvalid, Msg: "encoding must be base64, hex or pem"}
}

// ---- query

func filterFrom(r *http.Request) kms.Filter {
	q := r.URL.Query()
	f := kms.Filter{Name: q.Get("name"), Group: q.Get("group")}
	if st, ok := kms.ParseState(q.Get("state")); ok {
		f.State, f.HasState = st, true
	}
	switch strings.ToLower(q.Get("type")) {
	case "symmetric":
		f.Kind = kms.KindSymmetric
	case "private":
		f.Kind = kms.KindPrivate
	case "public":
		f.Kind = kms.KindPublic
	}
	if n, err := strconv.Atoi(q.Get("limit")); err == nil && n > 0 {
		f.Max = n
	}
	return f
}

// requestID adds an X-Request-Id header to every answer.
func requestID(w http.ResponseWriter) { w.Header().Set("X-Request-Id", newRequestID()) }
