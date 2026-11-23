package admin

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"sort"
	"strings"
	"time"
)

// PwHist is a remembered former password hash.
type PwHist struct {
	Salt string `json:"salt"`
	Hash string `json:"hash"`
	Iter int    `json:"iter"`
}

// AccountInfo is what the console shows about an account. It never contains secrets.
type AccountInfo struct {
	Name          string `json:"name"`
	Locked        bool   `json:"locked"`
	LockedUntil   string `json:"lockedUntil,omitempty"` // empty with Locked = until an administrator unlocks
	FailedRecent  int    `json:"failedRecent"`
	MustChange    bool   `json:"mustChange"`
	PwChangedAt   string `json:"pwChangedAt,omitempty"`
	ExpiresInDays *int   `json:"expiresInDays,omitempty"`
	Expired       bool   `json:"expired"`
	OTP           bool   `json:"otp"`
	LastLogin     string `json:"lastLogin,omitempty"`
	LastIP        string `json:"lastIp,omitempty"`
	Created       string `json:"created,omitempty"`
}

func ts(sec int64) string {
	if sec == 0 {
		return ""
	}
	return time.Unix(sec, 0).UTC().Format(time.RFC3339)
}

func passwordMatches(pw, salt, hash string, iter int) bool {
	s, err := base64.StdEncoding.DecodeString(salt)
	if err != nil {
		return false
	}
	h, err := hashPassword(pw, s, iter)
	return err == nil && subtle.ConstantTimeCompare([]byte(h), []byte(hash)) == 1
}

func expiry(x *User, p PasswordPolicy, now time.Time) (expired bool, daysLeft int, has bool) {
	if p.MaxAgeDays <= 0 || x.PwChanged == 0 {
		return false, 0, false
	}
	end := time.Unix(x.PwChanged, 0).Add(time.Duration(p.MaxAgeDays) * 24 * time.Hour)
	left := end.Sub(now)
	if left <= 0 {
		return true, 0, true
	}
	return false, int(left.Hours()/24) + 1, true
}

func info(x *User, set Settings, now time.Time) AccountInfo {
	a := AccountInfo{Name: x.Name, MustChange: x.MustChange, OTP: x.OTP != nil, PwChangedAt: ts(x.PwChanged), LastLogin: ts(x.LastLogin), LastIP: x.LastIP, Created: ts(x.Created)}
	if x.Locked || x.LockedUntil > now.Unix() {
		a.Locked = true
		if !x.Locked {
			a.LockedUntil = ts(x.LockedUntil)
		}
	}
	cut := now.Add(-time.Duration(set.Lockout.WindowMinutes) * time.Minute).Unix()
	for _, f := range x.Fails {
		if f > cut {
			a.FailedRecent++
		}
	}
	if exp, left, has := expiry(x, set.Password, now); has {
		a.Expired = exp
		if !exp {
			a.ExpiresInDays = &left
		}
	}
	return a
}

// Account describes one account.
func (u *Users) Account(name string, set Settings, now time.Time) (AccountInfo, bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	x := u.find(name)
	if x == nil {
		return AccountInfo{}, false
	}
	return info(x, set, now), true
}

// Accounts lists all accounts by name.
func (u *Users) Accounts(set Settings, now time.Time) []AccountInfo {
	u.mu.Lock()
	defer u.mu.Unlock()
	out := make([]AccountInfo, 0, len(u.List))
	for i := range u.List {
		out = append(out, info(&u.List[i], set, now))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// IsLocked reports whether the account is locked now; an expired lock is cleared.
func (u *Users) IsLocked(name string, now time.Time) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	x := u.find(name)
	if x == nil {
		return false
	}
	if x.Locked {
		return true
	}
	if x.LockedUntil != 0 && x.LockedUntil <= now.Unix() {
		x.LockedUntil, x.Fails = 0, nil
		_ = u.save()
		return false
	}
	return x.LockedUntil > now.Unix()
}

// RecordFail counts a failed attempt and locks the account when the limit is reached (returns true then).
func (u *Users) RecordFail(name string, pol LockoutPolicy, now time.Time) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	x := u.find(name)
	if x == nil {
		return false
	}
	cut := now.Add(-time.Duration(pol.WindowMinutes) * time.Minute).Unix()
	keep := x.Fails[:0]
	for _, f := range x.Fails {
		if f > cut {
			keep = append(keep, f)
		}
	}
	x.Fails = append(keep, now.Unix())
	locked := false
	if len(x.Fails) >= pol.MaxFails {
		locked = true
		if pol.LockMinutes == 0 {
			x.Locked = true
		} else {
			x.LockedUntil = now.Add(time.Duration(pol.LockMinutes) * time.Minute).Unix()
		}
	}
	_ = u.save()
	return locked
}

// RecordSuccess clears the failure counter and notes the login.
func (u *Users) RecordSuccess(name, ip string, now time.Time) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if x := u.find(name); x != nil {
		x.Fails, x.LockedUntil = nil, 0
		x.LastLogin, x.LastIP = now.Unix(), ip
		if x.PwChanged == 0 { // an account from before password ageing: its age starts now
			x.PwChanged = now.Unix()
		}
		_ = u.save()
	}
}

// Unlock clears a lock and the failure counter.
func (u *Users) Unlock(name string) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	x := u.find(name)
	if x == nil {
		return errors.New("no such user")
	}
	x.Locked, x.LockedUntil, x.Fails = false, 0, nil
	return u.save()
}

// MustChangeNow reports whether the next session has to start with a password change.
func (u *Users) MustChangeNow(name string, set Settings, now time.Time) (bool, string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	x := u.find(name)
	if x == nil {
		return false, ""
	}
	if x.MustChange {
		return true, "the password was set by an administrator"
	}
	if exp, _, _ := expiry(x, set.Password, now); exp {
		return true, "the password has expired"
	}
	return false, ""
}

func (u *Users) reused(x *User, pw string, n int) bool {
	if passwordMatches(pw, x.Salt, x.Hash, x.Iter) {
		return true
	}
	for i := len(x.History) - 1; i >= 0 && i >= len(x.History)-n; i-- {
		if passwordMatches(pw, x.History[i].Salt, x.History[i].Hash, x.History[i].Iter) {
			return true
		}
	}
	return false
}

func (u *Users) apply(x *User, pw string, set Settings, must bool, now time.Time) error {
	// remember the password being replaced
	if x.Hash != "" && set.Password.History > 0 {
		x.History = append(x.History, PwHist{Salt: x.Salt, Hash: x.Hash, Iter: x.Iter})
		if len(x.History) > set.Password.History {
			x.History = x.History[len(x.History)-set.Password.History:]
		}
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	h, err := hashPassword(pw, salt, pbkdfIter)
	if err != nil {
		return err
	}
	x.Salt, x.Hash, x.Iter = base64.StdEncoding.EncodeToString(salt), h, pbkdfIter
	x.PwChanged, x.MustChange = now.Unix(), must
	x.Fails, x.LockedUntil, x.Locked = nil, 0, false
	return u.save()
}

// ChangePassword lets a user replace their own password (current one required).
func (u *Users) ChangePassword(name, current, newPw string, set Settings, now time.Time) error {
	u.mu.Lock()
	x := u.find(name)
	if x == nil {
		u.mu.Unlock()
		return errors.New("no such user")
	}
	cp := *x
	u.mu.Unlock()
	if !passwordMatches(current, cp.Salt, cp.Hash, cp.Iter) {
		return ErrBadCurrent
	}
	if err := set.Password.CheckPassword(name, newPw); err != nil {
		return err
	}
	if u.reused(&cp, newPw, set.Password.History) { // PBKDF2 outside the lock
		return errors.New("password was used before: choose one you have not used in the last " + itoa(max(set.Password.History, 1)) + " changes")
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	x = u.find(name)
	if x == nil {
		return errors.New("no such user")
	}
	return u.apply(x, newPw, set, false, now)
}

// ErrBadCurrent means the current password given for a change was wrong.
var ErrBadCurrent = errors.New("the current password is wrong")

// Provision creates an account or sets a new password for an existing one (administrator action). With
// mustChange the user has to choose their own password at the next login.
func (u *Users) Provision(name, pw string, set Settings, mustChange bool, now time.Time) (created bool, err error) {
	if name == "" || len(name) > 64 || strings.ContainsAny(name, "\r\n\t\x00:") {
		return false, errors.New("user name must be 1-64 characters without control characters or ':'")
	}
	if err := set.Password.CheckPassword(name, pw); err != nil {
		return false, err
	}
	u.mu.Lock()
	x := u.find(name)
	var cp *User
	if x != nil {
		c := *x
		cp = &c
	}
	u.mu.Unlock()
	if cp != nil && u.reused(cp, pw, set.Password.History) {
		return false, errors.New("password was used before")
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if x = u.find(name); x == nil {
		u.List = append(u.List, User{Name: name, Created: now.Unix()})
		x, created = &u.List[len(u.List)-1], true
	}
	return created, u.apply(x, pw, set, mustChange && set.Password.ForceChange, now)
}
