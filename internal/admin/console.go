// Package admin is the web console of pqc-kms. It authenticates people (password, session, CSRF) and passes
// their requests to the backend's administration API, naming the user on whose behalf it acts. What a user
// may do is decided by the backend (management scopes), never by the console.
package admin

import (
	"bytes"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/wpdlatm2/kms/internal/logs"
	"github.com/wpdlatm2/kms/internal/restsrv"
	"github.com/wpdlatm2/kms/internal/sysctl"
	"github.com/wpdlatm2/kms/internal/syslogx"
)

//go:embed web
var webFS embed.FS

// Backend reaches the administration API over mutual TLS with the console's own certificate (which the
// backend lists as a trusted proxy).
type Backend struct {
	Base   string // https://host:9999
	Client *http.Client
}

// forwarded paths of the administration API
var allowed = map[string]bool{"me": true, "status": true, "catalog": true, "groups": true, "templates": true, "bindings": true, "managers": true, "keys": true, "logs": true, "audit": true}

// Options configure the console.
type Options struct {
	// OTP: "required" (every user must enroll an authenticator app; the default), "optional" (users who
	// enrolled must use it) or "off" (an enrolled user still must use it: the factor is never downgraded).
	OTP    string
	Issuer string // name shown in the authenticator app
	// AuditKey authenticates the console log entries (HMAC); RetentionDays is the minimum retention of its files.
	AuditKey      []byte
	RetentionDays int
	// Syslog forwards console audit entries to a collector (tcp://host:514 or tls://host:6514).
	Syslog string
	// Agent controls the services (nil = the dashboard is read-only); Probes are the ports the dashboard checks.
	Agent  sysctl.Client
	Probes []Probe
}

// Server is the HTTP handler of the console.
type Server struct {
	opts     Options
	Users    *Users
	Backend  *Backend
	Secure   bool // served over TLS: cookies get the Secure flag
	sess     *sessions
	thr      *throttle
	log      *logs.Log
	mux      *http.ServeMux
	sys      sysCache
	sysLog   *syslogx.Logger
	tr       sync.Mutex
	trState  map[string]bool
	started  time.Time
	settings *SettingsStore
}

// New builds the server. logPath "" keeps the console log (logins, logouts) in memory.
func New(b *Backend, u *Users, logPath string, secure bool, opts Options) (*Server, error) {
	l, err := logs.OpenWith(logs.Options{Path: logPath, Name: "console", Key: opts.AuditKey, Retention: time.Duration(opts.RetentionDays) * 24 * time.Hour})
	if err != nil {
		return nil, err
	}
	if opts.Syslog != "" {
		fw, err := logs.NewSyslogForwarder(opts.Syslog, "kmsadmin")
		if err != nil {
			return nil, err
		}
		l.AddSink(fw.Send)
	}
	if opts.OTP == "" {
		opts.OTP = "required"
	}
	if opts.OTP != "required" && opts.OTP != "optional" && opts.OTP != "off" {
		return nil, errors.New("otp policy must be required, optional or off")
	}
	if opts.Issuer == "" {
		opts.Issuer = "pqc-kms"
	}
	setPath := ""
	if u.path != "" {
		setPath = u.path + ".settings"
	}
	st, err := LoadSettings(setPath)
	if err != nil {
		return nil, err
	}
	cur := st.Get()
	s := &Server{opts: opts, Users: u, Backend: b, Secure: secure, settings: st, sess: newSessions(time.Duration(cur.Session.TTLHours)*time.Hour, time.Duration(cur.Session.IdleMinutes)*time.Minute), thr: newThrottle(), log: l, mux: http.NewServeMux(), started: time.Now()}
	sub, _ := fs.Sub(webFS, "web")
	s.mux.Handle("GET /", http.FileServerFS(sub))
	s.mux.HandleFunc("POST /api/login", s.login)
	s.mux.HandleFunc("POST /api/logout", s.guardEnroll(s.logout))
	s.mux.HandleFunc("GET /api/me", s.guardEnroll(s.me))
	s.mux.HandleFunc("GET /api/otp/setup", s.guardEnroll(s.otpSetup))
	s.mux.HandleFunc("POST /api/otp/confirm", s.guardEnroll(s.otpConfirm))
	s.mux.HandleFunc("GET /api/logs/console", s.guard(s.consoleLog))
	s.mux.HandleFunc("POST /api/password", s.guardEnroll(s.changePassword))
	s.mux.HandleFunc("GET /api/users", s.guard(s.listUsers))
	s.mux.HandleFunc("POST /api/users", s.guard(s.createUser))
	for _, a := range []string{"unlock", "reset-password", "reset-otp"} {
		s.mux.HandleFunc("POST /api/users/{name}/"+a, s.guard(s.userAction(a)))
	}
	s.mux.HandleFunc("GET /api/settings", s.guard(s.getSettings))
	s.mux.HandleFunc("PUT /api/settings", s.guard(s.putSettings))
	s.mux.HandleFunc("GET /api/system", s.guard(s.system))
	s.mux.HandleFunc("POST /api/system/services/{name}/{action}", s.guard(s.control))
	s.mux.HandleFunc("GET /api/audit/verify", s.guard(s.auditLocalOrForward(s.consoleVerify)))
	s.mux.HandleFunc("GET /api/audit/export", s.guard(s.auditLocalOrForward(s.consoleExport)))
	s.mux.HandleFunc("POST /api/audit/reviews", s.guard(s.consoleReview))
	for _, m := range []string{"GET", "POST", "PUT", "DELETE"} {
		s.mux.HandleFunc(m+" /api/{path...}", s.guard(s.forward))
	}
	return s, nil
}

// Close releases the log file.
func (s *Server) Close() { s.log.Close() }

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
	if s.Secure {
		h.Set("Strict-Transport-Security", "max-age=31536000")
	}
	s.mux.ServeHTTP(w, r)
}

const cookieName = "kmsadmin_sid"

func clientIP(r *http.Request) string {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

// sameOrigin rejects cross-site state-changing requests (defence in depth next to SameSite and the CSRF token).
func sameOrigin(r *http.Request) bool {
	o := r.Header.Get("Origin")
	if o == "" {
		return true
	}
	u, err := url.Parse(o)
	return err == nil && u.Host == r.Host
}

type ctxHandler func(w http.ResponseWriter, r *http.Request, ss *session)

// guard requires a fully authenticated session; a session that still has to enroll its second factor
// reaches only the enrollment endpoints (guardEnroll).
func (s *Server) guard(h ctxHandler) http.HandlerFunc { return s.guardMode(h, false) }

func (s *Server) guardEnroll(h ctxHandler) http.HandlerFunc { return s.guardMode(h, true) }

func (s *Server) guardMode(h ctxHandler, allowEnroll bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(cookieName)
		var ss *session
		if err == nil {
			ss = s.sess.get(c.Value)
		}
		if ss == nil {
			fail(w, http.StatusUnauthorized, "not signed in")
			return
		}
		if (ss.EnrollOnly || ss.ChangeOnly) && !allowEnroll {
			if ss.ChangeOnly {
				fail(w, http.StatusForbidden, "change the password first")
			} else {
				fail(w, http.StatusForbidden, "enroll the one-time password (OTP) first")
			}
			return
		}
		if r.Method != http.MethodGet {
			if !sameOrigin(r) || subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(ss.CSRF)) != 1 {
				s.authEvent(r, ss.User, "csrf-rejected", logs.OutcomeDenied, "CSRF check failed", r.Method+" "+r.URL.Path)
				fail(w, http.StatusForbidden, "CSRF check failed")
				return
			}
		}
		h(w, r, ss)
	}
}

func (s *Server) note(user, op, result, ip string) {
	s.log.Add(logs.Entry{Plane: "console", Kind: "event", Who: user, Op: op, Result: result, Remote: ip})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) {
		fail(w, http.StatusForbidden, "bad origin")
		return
	}
	var req struct{ User, Password, OTP string }
	r.Body = http.MaxBytesReader(w, r.Body, 1<<14)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		fail(w, http.StatusBadRequest, "bad request")
		return
	}
	ip := clientIP(r)
	key := ip + "|" + strings.ToLower(req.User)
	set, now := s.settings.Get(), time.Now()
	deny := func(reason string) {
		time.Sleep(400 * time.Millisecond)
		fail(w, http.StatusUnauthorized, "invalid user or password, or the account is locked")
		_ = reason
	}
	if s.thr.blocked(key) || s.thr.blocked(ip) {
		s.authEvent(r, req.User, "login-failed", logs.OutcomeDenied, "too many failures from this address", "")
		fail(w, http.StatusTooManyRequests, "too many failed attempts, try again later")
		return
	}
	_, known := s.Users.Account(req.User, set, now)
	if known && s.Users.IsLocked(req.User, now) {
		s.thr.fail(key)
		s.authEvent(r, req.User, "login-failed", logs.OutcomeDenied, "account locked", "")
		deny("locked")
		return
	}
	failure := func(reason string) {
		s.thr.fail(key)
		s.thr.fail(ip)
		s.authEvent(r, req.User, "login-failed", logs.OutcomeFailure, reason, "")
		if known && s.Users.RecordFail(req.User, set.Lockout, now) {
			d := itoa(set.Lockout.MaxFails) + " failures within " + itoa(set.Lockout.WindowMinutes) + " minutes"
			if set.Lockout.LockMinutes == 0 {
				d += "; locked until an administrator unlocks"
			} else {
				d += "; locked for " + itoa(set.Lockout.LockMinutes) + " minutes"
			}
			s.authEvent(r, req.User, "account-locked", logs.OutcomeDenied, "too many failures", d)
		}
	}
	u, ok := s.Users.Verify(req.User, req.Password)
	if !ok {
		reason := "bad password"
		if !known {
			reason = "unknown user"
		}
		failure(reason)
		deny(reason)
		return
	}
	enrollOnly, otpNote := false, "otp=none"
	switch {
	case s.Users.HasOTP(u.Name):
		if strings.TrimSpace(req.OTP) == "" {
			// the password is right; ask for the second factor (this is not a failed attempt)
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "enter the one-time password from your authenticator app", "otpRequired": true})
			return
		}
		good, recovery := s.Users.VerifyOTP(u.Name, req.OTP, time.Now())
		if !good {
			failure("bad one-time password")
			time.Sleep(400 * time.Millisecond)
			fail(w, http.StatusUnauthorized, "invalid one-time password")
			return
		}
		otpNote = "otp=used"
		if recovery {
			otpNote = "otp=recovery-code"
			s.authEvent(r, u.Name, "otp-recovery-code-used", logs.OutcomeSuccess, "", itoa(s.Users.RecoveryLeft(u.Name))+" left")
		}
	case s.opts.OTP == "required":
		enrollOnly = true
	}
	s.thr.reset(key)
	s.Users.RecordSuccess(u.Name, ip, now)
	mustChange, why := s.Users.MustChangeNow(u.Name, set, now)
	tok, ss := s.sess.create(u.Name, enrollOnly)
	if mustChange {
		s.sess.mu.Lock()
		ss.ChangeOnly = true
		s.sess.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: tok, // #nosec G124 -- Secure follows the TLS setting: plain HTTP is only allowed on loopback
		Path: "/", HttpOnly: true, Secure: s.Secure, SameSite: http.SameSiteStrictMode, MaxAge: int(s.sess.ttl.Seconds())})
	detail := otpNote + "; session=" + sessionDigest(tok)
	if mustChange {
		detail += "; password change required (" + why + ")"
	}
	s.log.Add(logs.Entry{Plane: "console", Kind: "event", Who: u.Name, Op: "login", Category: "authentication", Outcome: logs.OutcomeSuccess, Result: "ok", Detail: detail + "; ua=" + userAgent(r), Remote: ip, Session: sessionDigest(tok)})
	writeJSON(w, 200, map[string]any{"user": ss.User, "csrf": ss.CSRF, "enrollRequired": enrollOnly, "passwordChangeRequired": mustChange, "passwordChangeReason": why})
}

func itoa(n int) string { return strconv.Itoa(n) }

func (s *Server) logout(w http.ResponseWriter, r *http.Request, ss *session) {
	if c, err := r.Cookie(cookieName); err == nil {
		s.sess.drop(c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", HttpOnly: true, // #nosec G124 -- see the login cookie
		Secure: s.Secure, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	s.log.Add(logs.Entry{Plane: "console", Kind: "event", Who: ss.User, Op: "logout", Category: "authentication", Outcome: logs.OutcomeSuccess, Result: "ok", Remote: clientIP(r), Session: sessionDigest(s.tokenOf(r))})
	writeJSON(w, 200, map[string]string{"ok": "bye"})
}

// call performs a backend request on behalf of a user.
func (b *Backend) call(method, path, rawQuery, user, contentType string, body io.Reader) (int, http.Header, []byte, error) {
	// the path comes from the browser: escape it so that %3F or %23 cannot add a query or a fragment
	u := b.Base + "/admin/v1/" + (&url.URL{Path: path}).EscapedPath()
	if rawQuery != "" {
		u += "?" + rawQuery
	}
	req, err := http.NewRequest(method, u, body) // #nosec G704 -- the host is the configured backend; only an allow-listed, escaped path is appended
	if err != nil {
		return 0, nil, nil, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("X-Acting-User", user)
	resp, err := b.Client.Do(req) // #nosec G704 -- see above
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	return resp.StatusCode, resp.Header, raw, err
}

func (s *Server) me(w http.ResponseWriter, r *http.Request, ss *session) {
	if ss.EnrollOnly || ss.ChangeOnly {
		writeJSON(w, 200, map[string]any{"user": ss.User, "csrf": ss.CSRF, "enrollRequired": ss.EnrollOnly, "passwordChangeRequired": ss.ChangeOnly})
		return
	}
	code, _, raw, err := s.Backend.call("GET", "me", "", ss.User, "", nil)
	if err != nil {
		fail(w, http.StatusBadGateway, "the key management server is not reachable: "+err.Error())
		return
	}
	var me map[string]any
	if code != 200 || json.Unmarshal(raw, &me) != nil {
		fail(w, http.StatusBadGateway, "unexpected answer of the key management server")
		return
	}
	me["user"], me["csrf"] = ss.User, ss.CSRF
	if a, ok := s.Users.Account(ss.User, s.settings.Get(), time.Now()); ok {
		me["password"] = map[string]any{"expiresInDays": a.ExpiresInDays, "warnDays": s.settings.Get().Password.WarnDays}
	}
	me["otp"] = map[string]any{"enrolled": s.Users.HasOTP(ss.User), "recoveryCodesLeft": s.Users.RecoveryLeft(ss.User), "policy": s.opts.OTP}
	writeJSON(w, 200, me)
}

// isAuditor asks the backend whether the user holds a global role (admin or audit).
func (s *Server) isAuditor(ss *session) bool {
	code, _, raw, err := s.Backend.call("GET", "me", "", ss.User, "", nil)
	var me struct {
		Global bool `json:"global"`
	}
	return err == nil && code == 200 && json.Unmarshal(raw, &me) == nil && me.Global
}

func (s *Server) consoleLog(w http.ResponseWriter, r *http.Request, ss *session) {
	if !s.isAuditor(ss) {
		fail(w, http.StatusForbidden, "the console log is readable by global administrators and auditors only")
		return
	}
	f, err := restsrv.FilterFromQuery(r.URL.Query())
	if err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	if f.Limit == 0 || f.Limit > 2000 {
		f.Limit = 500
	}
	ents, err := s.log.Query(f)
	if err != nil {
		fail(w, http.StatusInternalServerError, "cannot read the log")
		return
	}
	s.note(ss.User, "audit-view", "ok", clientIP(r))
	writeJSON(w, 200, ents)
}

// auditLocalOrForward serves the audit functions of the console's own log here and passes the others on.
func (s *Server) auditLocalOrForward(local ctxHandler) ctxHandler {
	return func(w http.ResponseWriter, r *http.Request, ss *session) {
		if r.URL.Query().Get("log") != "console" {
			s.forward(w, r, ss)
			return
		}
		if !s.isAuditor(ss) {
			fail(w, http.StatusForbidden, "audit data is available to global administrators and auditors only")
			return
		}
		local(w, r, ss)
	}
}

func (s *Server) consoleVerify(w http.ResponseWriter, r *http.Request, ss *session) {
	rep, err := s.log.Verify(s.opts.AuditKey)
	if err != nil {
		fail(w, http.StatusInternalServerError, "cannot read the log")
		return
	}
	res := "ok"
	if !rep.OK {
		res = "error: integrity violation: " + rep.Problem
	}
	s.note(ss.User, "audit-verify", res, clientIP(r))
	writeJSON(w, 200, rep)
}

func (s *Server) consoleExport(w http.ResponseWriter, r *http.Request, ss *session) {
	f, err := restsrv.FilterFromQuery(r.URL.Query())
	if err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	var buf bytes.Buffer
	m, err := s.log.Export(&buf, f, ss.User, s.opts.AuditKey)
	if err != nil {
		fail(w, http.StatusInternalServerError, "cannot export")
		return
	}
	s.log.Add(logs.Entry{Plane: "console", Kind: "event", Who: ss.User, Op: "audit-export", Target: "console", Result: "ok", Remote: clientIP(r),
		Detail: "entries=" + itoa(m.Entries) + " sha256=" + m.DataSHA256})
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="audit-console-`+time.Now().UTC().Format("20060102-150405")+`.zip"`)
	_, _ = w.Write(buf.Bytes())
}

// consoleReview records a review of the console log here and passes reviews of the other logs on.
func (s *Server) consoleReview(w http.ResponseWriter, r *http.Request, ss *session) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<16))
	if err != nil {
		fail(w, http.StatusRequestEntityTooLarge, "request too large")
		return
	}
	var in struct {
		Log, From, To, Finding, Note string
	}
	_ = json.Unmarshal(body, &in)
	if in.Log != "console" {
		r.Body = io.NopCloser(bytes.NewReader(body))
		s.forward(w, r, ss)
		return
	}
	if !s.isAuditor(ss) {
		fail(w, http.StatusForbidden, "audit data is available to global administrators and auditors only")
		return
	}
	if (in.Finding != "none" && in.Finding != "anomaly") || in.From == "" || in.To == "" || len(in.Note) > 1000 || len(in.From) > 40 || len(in.To) > 40 ||
		strings.ContainsAny(in.Note+in.From+in.To, "\x00\r\n") || (in.Finding == "anomaly" && strings.TrimSpace(in.Note) == "") {
		fail(w, http.StatusBadRequest, "from, to, finding (none|anomaly) and a note of at most 1000 characters are required")
		return
	}
	s.log.Add(logs.Entry{Plane: "console", Kind: "event", Who: ss.User, Op: "audit-review", Target: "console", Result: "ok", Remote: clientIP(r), Category: "audit-access",
		Detail: "period " + in.From + " .. " + in.To + "; finding=" + in.Finding + "; " + in.Note})
	writeJSON(w, 201, map[string]any{"result": "recorded", "reviewer": ss.User})
}

// forward passes an allowed request to the administration API as the signed-in user.
func (s *Server) forward(w http.ResponseWriter, r *http.Request, ss *session) {
	path := r.PathValue("path")
	if path == "" { // reached through a specific route (audit/...)
		path = strings.TrimPrefix(r.URL.Path, "/api/")
	}
	first, _, _ := strings.Cut(path, "/")
	if !allowed[first] || strings.Contains(path, "..") {
		fail(w, http.StatusNotFound, "unknown endpoint")
		return
	}
	switch r.Method {
	case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete:
	default:
		fail(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	code, hdr, raw, err := s.Backend.call(r.Method, path, r.URL.RawQuery, ss.User, r.Header.Get("Content-Type"), r.Body)
	if err != nil {
		var mb *http.MaxBytesError
		if errors.As(err, &mb) {
			fail(w, http.StatusRequestEntityTooLarge, "request too large")
			return
		}
		s.note(ss.User, r.Method+" "+path, "error: backend unreachable", clientIP(r))
		fail(w, http.StatusBadGateway, "the key management server is not reachable: "+err.Error())
		return
	}
	// the backend answers JSON only (except the evidence export): do not pass its content type on, state it
	if path == "audit/export" && code == 200 {
		w.Header().Set("Content-Type", "application/zip")
		w.Header().Set("Content-Disposition", resp1(hdr.Get("Content-Disposition")))
	} else {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
	}
	w.WriteHeader(code)
	_, _ = w.Write(raw) // #nosec G705 -- JSON from the backend with a fixed content type and nosniff
}

// ListenAndServe starts the HTTP(S) server. Without TLS it refuses non-loopback addresses.
func ListenAndServe(addr, certFile, keyFile string, h http.Handler) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	if certFile == "" {
		ip := net.ParseIP(host)
		if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return errors.New("refusing to serve plain HTTP on a non-loopback address: configure -tls-cert/-tls-key (or put a TLS proxy in front and use 127.0.0.1)")
		}
	}
	srv := &http.Server{Addr: addr, Handler: h, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 2 * time.Minute,
		ErrorLog: log.New(io.Discard, "", 0)}
	if certFile != "" {
		return srv.ListenAndServeTLS(certFile, keyFile)
	}
	return srv.ListenAndServe()
}

// otpSetup starts the enrollment: a fresh secret (kept in the session until confirmed), its QR code and the
// values for manual entry. A user who already has a second factor cannot replace it here.
func (s *Server) otpSetup(w http.ResponseWriter, r *http.Request, ss *session) {
	if s.Users.HasOTP(ss.User) {
		fail(w, http.StatusConflict, "a one-time password is already set up; ask an administrator to reset it")
		return
	}
	if ss.Pending == "" {
		sec, err := newOTPSecret()
		if err != nil {
			fail(w, http.StatusInternalServerError, "could not create a secret")
			return
		}
		s.sess.setPending(ss, sec)
	}
	uri := otpauthURI(s.opts.Issuer, ss.User, ss.Pending)
	png, err := qrPNG(uri)
	if err != nil {
		fail(w, http.StatusInternalServerError, "could not render the QR code")
		return
	}
	writeJSON(w, 200, map[string]any{
		"issuer": s.opts.Issuer, "account": ss.User, "secret": groupSecret(ss.Pending), "uri": uri,
		"qr": "data:image/png;base64," + base64.StdEncoding.EncodeToString(png), "algorithm": "SHA1", "digits": otpDigits, "period": otpPeriod,
	})
}

// otpConfirm completes the enrollment with a code from the app and returns the recovery codes (shown once).
func (s *Server) otpConfirm(w http.ResponseWriter, r *http.Request, ss *session) {
	var req struct{ Code string }
	r.Body = http.MaxBytesReader(w, r.Body, 1<<12)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		fail(w, http.StatusBadRequest, "bad request")
		return
	}
	ip := clientIP(r)
	key := ip + "|" + strings.ToLower(ss.User)
	if s.thr.blocked(key) {
		fail(w, http.StatusTooManyRequests, "too many failed attempts, try again later")
		return
	}
	if ss.Pending == "" || s.Users.HasOTP(ss.User) {
		fail(w, http.StatusConflict, "no enrollment in progress")
		return
	}
	secret, err := decodeSecret(ss.Pending)
	step := int64(0)
	if err == nil {
		step = matchTOTP(secret, req.Code, time.Now())
	}
	if step == 0 {
		s.thr.fail(key)
		s.note(ss.User, "otp-enroll", "error: wrong code", ip)
		time.Sleep(300 * time.Millisecond)
		fail(w, http.StatusBadRequest, "that code does not match: check the time on your phone and try the next code")
		return
	}
	plain, hashed, err := newRecoveryCodes(10)
	if err != nil {
		fail(w, http.StatusInternalServerError, "could not create recovery codes")
		return
	}
	if err := s.Users.EnableOTP(ss.User, ss.Pending, step, hashed); err != nil {
		fail(w, http.StatusInternalServerError, "could not save: "+err.Error())
		return
	}
	s.thr.reset(key)
	s.sess.finishEnroll(ss)
	s.note(ss.User, "otp-enroll", "ok", ip)
	writeJSON(w, 200, map[string]any{"enrolled": true, "recoveryCodes": plain})
}

// resp1 passes on the attachment name of an export only if it has the expected shape.
func resp1(v string) string {
	if strings.HasPrefix(v, `attachment; filename="audit-`) && !strings.ContainsAny(v, "\r\n") && len(v) < 120 {
		return v
	}
	return `attachment; filename="audit.zip"`
}
