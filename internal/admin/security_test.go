package admin

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/wpdlatm2/kms/internal/logs"
)

const strong = "Tr1cky-Passphrase!"

func consoleEntries(s *stack, op string) []logs.Entry {
	es, _ := s.srv.log.Query(logs.Filter{Op: op, Limit: 200})
	return es
}

func TestPasswordPolicyRules(t *testing.T) {
	p := DefaultSettings().Password
	for pw, want := range map[string]bool{
		"Short1!":              false, // too short
		"alllowercaseletters":  false, // one class
		"lowercase-and-digits": false, // two classes
		"Tr1cky-Passphrase!":   true,
		"Abcdefgh1!xx":         true,
		"Aaa1111!bbbb":         false, // repeats
		"Bruce-Secure-Pass1":   false, // contains the user name
	} {
		err := p.CheckPassword("bruce", pw)
		if (err == nil) != want {
			t.Errorf("%q: %v", pw, err)
		}
	}
	if p.CheckPassword("u", "Valid-Pass-123\x07") == nil {
		t.Error("control character accepted")
	}
	p.MinLength, p.MinClasses = 8, 1
	if p.CheckPassword("u", "abcdefgh") != nil {
		t.Error("relaxed policy refuses a plain password")
	}
	bad := DefaultSettings()
	bad.Lockout.MaxFails = 1
	if bad.Validate() == nil {
		t.Error("lockout of 1 failure accepted")
	}
	bad = DefaultSettings()
	bad.Password.WarnDays = 90
	if bad.Validate() == nil {
		t.Error("warning longer than the age accepted")
	}
}

func lockSettings(maxFails, lockMinutes int) map[string]any {
	return map[string]any{
		"password": DefaultSettings().Password, "lockout": map[string]int{"maxFails": maxFails, "windowMinutes": 10, "lockMinutes": lockMinutes},
		"session": DefaultSettings().Session, "approvalCode": "APR-SEC-1", "owner": "kim"}
}

func TestLockoutAfterFailuresAndAdminUnlock(t *testing.T) {
	s := newStack(t, map[string]string{"root": pw, "dora": pw})
	root := s.web()
	root.login("root", pw)
	// permanent lock after 3 failures (needs the administrator)
	root.must(200, "PUT", "/api/settings", lockSettings(3, 0))
	for i := 0; i < 3; i++ {
		if code := s.web().login("dora", "wrong-password-1"); code != 401 {
			t.Fatalf("failure %d: %d", i, code)
		}
	}
	// the right password no longer works
	if code := s.web().login("dora", pw); code != 401 {
		t.Fatalf("login of a locked account: %d", code)
	}
	var us struct{ Users []AccountInfo }
	json.Unmarshal(root.must(200, "GET", "/api/users", nil), &us)
	locked := false
	for _, u := range us.Users {
		if u.Name == "dora" {
			locked = u.Locked
		}
	}
	if !locked {
		t.Fatalf("dora is not shown as locked: %+v", us.Users)
	}
	// audit trail of the whole story
	if got := consoleEntries(s, "account-locked"); len(got) != 1 || got[0].Who != "dora" || got[0].Outcome != logs.OutcomeDenied || !strings.Contains(got[0].Detail, "3 failures") {
		t.Fatalf("account-locked: %+v", got)
	}
	reasons := map[string]int{}
	for _, e := range consoleEntries(s, "login-failed") {
		reasons[e.Result]++
		if e.Category != "authentication" || e.Remote == "" {
			t.Fatalf("incomplete failure record: %+v", e)
		}
	}
	if reasons["error: bad password"] != 3 || reasons["denied: account locked"] != 1 {
		t.Fatalf("failure reasons: %v", reasons)
	}
	// unlocking needs the evidence
	root.must(400, "POST", "/api/users/dora/unlock", map[string]any{})
	root.must(200, "POST", "/api/users/dora/unlock", map[string]any{"approvalCode": "APR-SEC-2", "owner": "kim"})
	if code := s.web().login("dora", pw); code != 200 {
		t.Fatalf("login after unlock: %d", code)
	}
	if u := consoleEntries(s, "account-unlocked"); len(u) != 1 || u[0].Approval != "APR-SEC-2" || u[0].Owner != "kim" || u[0].Who != "root" || u[0].Target != "dora" {
		t.Fatalf("unlock record: %+v", u)
	}
	// success is recorded with the session digest and the client
	found := false
	for _, e := range consoleEntries(s, "login") {
		if e.Who == "dora" && e.Outcome == logs.OutcomeSuccess && e.Session != "" && strings.Contains(e.Detail, "otp=none") {
			found = true
		}
	}
	if !found {
		t.Fatal("login success record missing")
	}
}

func TestTemporaryLockExpiresAndUnknownUsersAreRecorded(t *testing.T) {
	s := newStack(t, map[string]string{"root": pw, "dora": pw})
	lock := LockoutPolicy{MaxFails: 3, WindowMinutes: 10, LockMinutes: 1}
	now := time.Now()
	for i := 0; i < 3; i++ {
		s.srv.Users.RecordFail("dora", lock, now)
	}
	if !s.srv.Users.IsLocked("dora", now) || !s.srv.Users.IsLocked("dora", now.Add(59*time.Second)) {
		t.Fatal("not locked")
	}
	if s.srv.Users.IsLocked("dora", now.Add(61*time.Second)) {
		t.Fatal("lock did not expire")
	}
	if code := s.web().login("ghost\nuser", "whatever-1234"); code != 401 {
		t.Fatalf("unknown user: %d", code)
	}
	var found bool
	for _, e := range consoleEntries(s, "login-failed") {
		if e.Who == "ghostuser" && e.Result == "error: unknown user" {
			found = true
		}
	}
	if !found {
		t.Fatal("login attempt of an unknown user (control characters removed) is not recorded")
	}
	// the answer is the same for unknown users and wrong passwords
	_, b1 := s.web().call("POST", "/api/login", map[string]string{"user": "ghost", "password": "x"}, false)
	_, b2 := s.web().call("POST", "/api/login", map[string]string{"user": "dora", "password": "x"}, false)
	if string(b1) != string(b2) {
		t.Fatalf("answers differ: %s / %s", b1, b2)
	}
}

func TestPasswordChangeHistoryExpiryAndForcedChange(t *testing.T) {
	s := newStack(t, map[string]string{"root": pw, "dora": pw})
	dora := s.web()
	dora.login("dora", pw)
	dora2 := s.web() // a second session that must end when the password changes
	dora2.login("dora", pw)
	dora.must(400, "POST", "/api/password", map[string]string{"current": "wrong", "new": strong})
	dora.must(400, "POST", "/api/password", map[string]string{"current": pw, "new": "short"})
	dora.must(400, "POST", "/api/password", map[string]string{"current": pw, "new": pw}) // same as the current one
	dora.must(200, "POST", "/api/password", map[string]string{"current": pw, "new": strong})
	if code, _ := dora2.call("GET", "/api/me", nil, true); code != 401 {
		t.Fatalf("the other session survived: %d", code)
	}
	// the old password is in the history
	dora.must(400, "POST", "/api/password", map[string]string{"current": strong, "new": pw})
	if got := consoleEntries(s, "password-changed"); len(got) != 1 || got[0].Who != "dora" {
		t.Fatalf("%+v", got)
	}
	for _, e := range consoleEntries(s, "password-change-failed") {
		if strings.Contains(e.Result+e.Detail, strong) || strings.Contains(e.Result+e.Detail, pw) {
			t.Fatal("a password reached the log")
		}
	}
	if s.web().login("dora", pw) != 401 || s.web().login("dora", strong) != 200 {
		t.Fatal("old/new password")
	}

	// expiry: the next login must start with a password change
	s.srv.Users.mu.Lock()
	s.srv.Users.find("dora").PwChanged = time.Now().Add(-100 * 24 * time.Hour).Unix()
	s.srv.Users.mu.Unlock()
	c := s.web()
	code, raw := c.call("POST", "/api/login", map[string]string{"user": "dora", "password": strong}, false)
	var lr map[string]any
	json.Unmarshal(raw, &lr)
	if code != 200 || lr["passwordChangeRequired"] != true {
		t.Fatalf("expired password: %d %s", code, raw)
	}
	c.csrf, _ = lr["csrf"].(string)
	c.must(403, "GET", "/api/keys", nil) // nothing else works yet
	c.must(200, "POST", "/api/password", map[string]string{"current": strong, "new": "An0ther-Strong-One"})
	c.must(200, "GET", "/api/keys", nil)
}

func TestAdministratorManagesAccountsWithEvidence(t *testing.T) {
	s := newStack(t, map[string]string{"root": pw, "dora": pw, "ava": pw})
	root := s.web()
	root.login("root", pw)
	root.must(200, "PUT", "/api/managers", map[string]any{"identity": "ava", "scope": "ALL", "role": "audit", "approvalCode": "APR-1", "owner": "kim"})

	// the audit role may look but not change
	ava := s.web()
	ava.login("ava", pw)
	ava.must(200, "GET", "/api/users", nil)
	var gs struct {
		CanEdit bool `json:"canEdit"`
	}
	json.Unmarshal(ava.must(200, "GET", "/api/settings", nil), &gs)
	if gs.CanEdit {
		t.Fatal("an auditor may edit settings")
	}
	ava.must(403, "PUT", "/api/settings", lockSettings(5, 30))
	ava.must(403, "POST", "/api/users", map[string]any{"name": "x", "password": strong, "approvalCode": "A", "owner": "o"})
	ava.must(403, "POST", "/api/users/dora/unlock", map[string]any{"approvalCode": "A", "owner": "o"})
	denied := 0
	for _, e := range s.srv.log.Last(500) {
		if e.Who == "ava" && e.Outcome == logs.OutcomeDenied {
			denied++
		}
	}
	if denied != 3 {
		t.Fatalf("%d denied attempts recorded, want 3", denied)
	}

	// creating an account: evidence, policy, forced change at the first login
	root.must(400, "POST", "/api/users", map[string]any{"name": "newbie", "password": strong})
	root.must(400, "POST", "/api/users", map[string]any{"name": "newbie", "password": "weak", "approvalCode": "APR-3", "owner": "kim"})
	root.must(201, "POST", "/api/users", map[string]any{"name": "newbie", "password": strong, "approvalCode": "APR-3", "owner": "kim"})
	root.must(409, "POST", "/api/users", map[string]any{"name": "newbie", "password": strong, "approvalCode": "APR-3", "owner": "kim"})
	nb := s.web()
	code, raw := nb.call("POST", "/api/login", map[string]string{"user": "newbie", "password": strong}, false)
	var lr map[string]any
	json.Unmarshal(raw, &lr)
	if code != 200 || lr["passwordChangeRequired"] != true {
		t.Fatalf("new account: %d %s", code, raw)
	}
	okc := 0
	for _, e := range consoleEntries(s, "user-create") {
		if e.Outcome == logs.OutcomeSuccess && e.Approval == "APR-3" && e.Owner == "kim" && e.Target == "newbie" {
			okc++
		}
	}
	if okc != 1 {
		t.Fatalf("%d successful user-create records", okc)
	}

	// reset: ends the user's sessions, forces a change; not for oneself
	dora := s.web()
	dora.login("dora", pw)
	root.must(400, "POST", "/api/users/root/reset-password", map[string]any{"password": "Br4nd-New-Passw0rd", "approvalCode": "APR-4", "owner": "kim"})
	root.must(200, "POST", "/api/users/dora/reset-password", map[string]any{"password": "Br4nd-New-Passw0rd", "approvalCode": "APR-4", "owner": "kim"})
	if code, _ := dora.call("GET", "/api/me", nil, true); code != 401 {
		t.Fatalf("session of the reset user survived: %d", code)
	}
	d2 := s.web()
	_, raw = d2.call("POST", "/api/login", map[string]string{"user": "dora", "password": "Br4nd-New-Passw0rd"}, false)
	json.Unmarshal(raw, &lr)
	if lr["passwordChangeRequired"] != true {
		t.Fatal("reset password does not force a change")
	}

	// settings: validated, evidence required, before/after recorded
	bad := lockSettings(5, 30)
	bad["lockout"] = map[string]int{"maxFails": 1, "windowMinutes": 10, "lockMinutes": 30}
	root.must(400, "PUT", "/api/settings", bad)
	noEv := lockSettings(4, 30)
	delete(noEv, "approvalCode")
	root.must(400, "PUT", "/api/settings", noEv)
	root.must(200, "PUT", "/api/settings", lockSettings(4, 30))
	ev := consoleEntries(s, "settings-change")
	if len(ev) < 1 || ev[0].Approval != "APR-SEC-1" || ev[0].Outcome != logs.OutcomeSuccess || !strings.Contains(ev[0].Detail, `"maxFails":5`) || !strings.Contains(ev[0].Detail, `"maxFails":4`) {
		t.Fatalf("settings change record: %+v", ev)
	}
	if got := s.srv.settings.Get(); got.Lockout.MaxFails != 4 || got.ChangedBy != "root" {
		t.Fatalf("%+v", got)
	}
}

func TestSettingsPersist(t *testing.T) {
	path := t.TempDir() + "/s.json"
	st, _ := LoadSettings(path)
	n := DefaultSettings()
	n.Password.MinLength = 16
	if err := st.Set(n, "root", "APR-9", "kim"); err != nil {
		t.Fatal(err)
	}
	st2, err := LoadSettings(path)
	if err != nil || st2.Get().Password.MinLength != 16 || st2.Get().Approval != "APR-9" {
		t.Fatalf("%v %+v", err, st2.Get())
	}
}
