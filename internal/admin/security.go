package admin

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/wpdlatm2/kms/internal/kms"
	"github.com/wpdlatm2/kms/internal/logs"
)

// cleanName makes a user name typed at the login form safe to write into a log line.
func cleanName(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	if len([]rune(s)) > 64 {
		s = string([]rune(s)[:64])
	}
	return s
}

func sessionDigest(tok string) string {
	h := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(h[:4])
}

func userAgent(r *http.Request) string {
	ua := cleanName(r.UserAgent())
	if len(ua) > 100 {
		ua = ua[:100]
	}
	return ua
}

// authEvent writes a login-related audit record: who (as typed), what happened, why, from where.
func (s *Server) authEvent(r *http.Request, who, op, outcome, reason, detail string) {
	res := "ok"
	switch outcome {
	case logs.OutcomeFailure:
		res = "error: " + reason
	case logs.OutcomeDenied:
		res = "denied: " + reason
	}
	d := detail
	if ua := userAgent(r); ua != "" {
		if d != "" {
			d += "; "
		}
		d += "ua=" + ua
	}
	s.log.Add(logs.Entry{Plane: "console", Kind: "event", Who: cleanName(who), Op: op, Category: "authentication", Outcome: outcome, Result: res, Detail: d, Remote: clientIP(r)})
}

func (s *Server) evidence(w http.ResponseWriter, approval, owner string) (string, string, bool) {
	approval, owner = strings.TrimSpace(approval), strings.TrimSpace(owner)
	if !kms.ValidApproval(approval) || !kms.ValidOwner(owner) {
		fail(w, http.StatusBadRequest, "approval number (승인번호) and owner (담당자) are required")
		return "", "", false
	}
	return approval, owner, true
}

// requireAdmin lets only a global administrator through and records the refusal.
func (s *Server) requireAdmin(w http.ResponseWriter, r *http.Request, ss *session, op, target string) bool {
	if _, admin := s.roles(ss); admin {
		return true
	}
	s.log.Add(logs.Entry{Plane: "console", Kind: "event", Who: ss.User, Op: op, Target: target, Category: "permission-change", Outcome: logs.OutcomeDenied,
		Result: "denied: global administrator role required", Remote: clientIP(r)})
	fail(w, http.StatusForbidden, "this needs the global administrator role")
	return false
}

func (s *Server) tokenOf(r *http.Request) string {
	if c, err := r.Cookie(cookieName); err == nil {
		return c.Value
	}
	return ""
}

// ---- own password

func (s *Server) changePassword(w http.ResponseWriter, r *http.Request, ss *session) {
	var in struct {
		Current string `json:"current"`
		New     string `json:"new"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<13)).Decode(&in); err != nil {
		fail(w, http.StatusBadRequest, "bad request")
		return
	}
	set, now := s.settings.Get(), time.Now()
	if s.Users.IsLocked(ss.User, now) {
		s.authEvent(r, ss.User, "password-change-failed", logs.OutcomeDenied, "account-locked", "")
		fail(w, http.StatusForbidden, "the account is locked")
		return
	}
	err := s.Users.ChangePassword(ss.User, in.Current, in.New, set, now)
	if err == ErrBadCurrent {
		locked := s.Users.RecordFail(ss.User, set.Lockout, now)
		s.authEvent(r, ss.User, "password-change-failed", logs.OutcomeFailure, "wrong current password", "")
		if locked {
			s.authEvent(r, ss.User, "account-locked", logs.OutcomeDenied, "too many failures", "during password change")
			s.sess.dropUser(ss.User, "")
		}
		time.Sleep(400 * time.Millisecond)
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	if err != nil {
		s.authEvent(r, ss.User, "password-change-failed", logs.OutcomeFailure, "policy: "+err.Error(), "")
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	s.sess.finishChange(ss)
	s.sess.dropUser(ss.User, s.tokenOf(r)) // every other session of the user ends
	s.authEvent(r, ss.User, "password-changed", logs.OutcomeSuccess, "", "other sessions ended")
	writeJSON(w, 200, map[string]any{"ok": "changed"})
}

// ---- accounts (administrators)

type provisionReq struct {
	Name         string `json:"name"`
	Password     string `json:"password"`
	ApprovalCode string `json:"approvalCode"`
	Owner        string `json:"owner"`
}

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request, ss *session) {
	if g, _ := s.roles(ss); !g {
		fail(w, http.StatusForbidden, "account data is available to global administrators and auditors only")
		return
	}
	writeJSON(w, 200, map[string]any{"users": s.Users.Accounts(s.settings.Get(), time.Now())})
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request, ss *session) {
	var in provisionReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<13)).Decode(&in); err != nil {
		fail(w, http.StatusBadRequest, "bad request")
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if !s.requireAdmin(w, r, ss, "user-create", in.Name) {
		return
	}
	ap, ow, ok := s.evidence(w, in.ApprovalCode, in.Owner)
	if !ok {
		return
	}
	ent := logs.Entry{Plane: "console", Kind: "event", Who: ss.User, Op: "user-create", Target: cleanName(in.Name), Category: "permission-change", Approval: ap, Owner: ow, Remote: clientIP(r)}
	if _, exists := s.Users.Account(in.Name, s.settings.Get(), time.Now()); exists {
		ent.Outcome, ent.Result = logs.OutcomeFailure, "error: the user exists"
		s.log.Add(ent)
		fail(w, http.StatusConflict, "the user exists; use the password reset")
		return
	}
	if _, err := s.Users.Provision(in.Name, in.Password, s.settings.Get(), true, time.Now()); err != nil {
		ent.Outcome, ent.Result = logs.OutcomeFailure, "error: "+err.Error()
		s.log.Add(ent)
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	ent.Outcome, ent.Result, ent.Detail = logs.OutcomeSuccess, "ok", "the user must change the password at the first login; grant management rights in the key server separately"
	s.log.Add(ent)
	writeJSON(w, 201, map[string]any{"ok": "created"})
}

func (s *Server) userAction(action string) ctxHandler {
	return func(w http.ResponseWriter, r *http.Request, ss *session) {
		name := r.PathValue("name")
		var in provisionReq
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<13)).Decode(&in); err != nil {
			fail(w, http.StatusBadRequest, "bad request")
			return
		}
		op := "user-" + action
		if !s.requireAdmin(w, r, ss, op, name) {
			return
		}
		ap, ow, ok := s.evidence(w, in.ApprovalCode, in.Owner)
		if !ok {
			return
		}
		ent := logs.Entry{Plane: "console", Kind: "event", Who: ss.User, Op: op, Target: cleanName(name), Category: "authentication", Approval: ap, Owner: ow, Remote: clientIP(r)}
		set, now := s.settings.Get(), time.Now()
		if _, exists := s.Users.Account(name, set, now); !exists {
			ent.Outcome, ent.Result = logs.OutcomeFailure, "error: no such user"
			s.log.Add(ent)
			fail(w, http.StatusNotFound, "no such user")
			return
		}
		var err error
		switch action {
		case "unlock":
			err = s.Users.Unlock(name)
			ent.Op = "account-unlocked"
		case "reset-password":
			if name == ss.User {
				err = errSelf
			} else {
				_, err = s.Users.Provision(name, in.Password, set, true, now)
				if err == nil {
					s.sess.dropUser(name, "")
				}
			}
		case "reset-otp":
			if name == ss.User {
				err = errSelf
			} else if err = s.Users.ResetOTP(name); err == nil {
				s.sess.dropUser(name, "")
			}
		}
		if err != nil {
			ent.Outcome, ent.Result = logs.OutcomeFailure, "error: "+err.Error()
			s.log.Add(ent)
			fail(w, http.StatusBadRequest, err.Error())
			return
		}
		ent.Outcome, ent.Result = logs.OutcomeSuccess, "ok"
		s.log.Add(ent)
		writeJSON(w, 200, map[string]any{"ok": action})
	}
}

type selfErr string

func (e selfErr) Error() string { return string(e) }

const errSelf = selfErr("use the password change for your own account")

// ---- settings

func (s *Server) getSettings(w http.ResponseWriter, r *http.Request, ss *session) {
	if g, admin := s.roles(ss); !g {
		fail(w, http.StatusForbidden, "settings are available to global administrators and auditors only")
		return
	} else {
		writeJSON(w, 200, map[string]any{"settings": s.settings.Get(), "canEdit": admin})
	}
}

func (s *Server) putSettings(w http.ResponseWriter, r *http.Request, ss *session) {
	var in struct {
		Password     PasswordPolicy `json:"password"`
		Lockout      LockoutPolicy  `json:"lockout"`
		Session      SessionPolicy  `json:"session"`
		ApprovalCode string         `json:"approvalCode"`
		Owner        string         `json:"owner"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<13)).Decode(&in); err != nil {
		fail(w, http.StatusBadRequest, "bad request")
		return
	}
	if !s.requireAdmin(w, r, ss, "settings-change", "security-settings") {
		return
	}
	ap, ow, ok := s.evidence(w, in.ApprovalCode, in.Owner)
	if !ok {
		return
	}
	old := s.settings.Get()
	n := Settings{Password: in.Password, Lockout: in.Lockout, Session: in.Session}
	ent := logs.Entry{Plane: "console", Kind: "event", Who: ss.User, Op: "settings-change", Target: "security-settings", Category: "permission-change", Approval: ap, Owner: ow, Remote: clientIP(r)}
	if err := s.settings.Set(n, ss.User, ap, ow); err != nil {
		ent.Outcome, ent.Result = logs.OutcomeFailure, "error: "+err.Error()
		s.log.Add(ent)
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	s.sess.setLimits(time.Duration(n.Session.TTLHours)*time.Hour, time.Duration(n.Session.IdleMinutes)*time.Minute)
	oj, _ := json.Marshal(struct {
		P PasswordPolicy
		L LockoutPolicy
		S SessionPolicy
	}{old.Password, old.Lockout, old.Session})
	nj, _ := json.Marshal(struct {
		P PasswordPolicy
		L LockoutPolicy
		S SessionPolicy
	}{n.Password, n.Lockout, n.Session})
	ent.Outcome, ent.Result, ent.Detail = logs.OutcomeSuccess, "ok", "before="+string(oj)+" after="+string(nj)
	s.log.Add(ent)
	writeJSON(w, 200, map[string]any{"settings": s.settings.Get()})
}
