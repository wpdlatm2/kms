package admin

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

const pbkdfIter = 600_000

// User is a console login. What the user may do is decided by the backend (management grants), not here.
// UserOTP is the second factor of a user (TOTP).
type UserOTP struct {
	Secret   string   `json:"secret"`             // base32
	LastStep int64    `json:"lastStep"`           // last accepted time step: a code is never accepted twice
	Recovery []string `json:"recovery,omitempty"` // SHA-256 of the unused recovery codes
	Enrolled int64    `json:"enrolled"`
}

type User struct {
	OTP  *UserOTP `json:"otp,omitempty"`
	Name string   `json:"name"`
	Salt string   `json:"salt"`
	Hash string   `json:"hash"`
	Iter int      `json:"iter"`
}

// Users is the account file (PBKDF2-HMAC-SHA256 hashed passwords).
type Users struct {
	path string
	mu   sync.Mutex
	List []User `json:"users"`
}

func LoadUsers(path string) (*Users, error) {
	u := &Users{path: path}
	b, err := os.ReadFile(path) // #nosec G304 -- operator-configured path
	if errors.Is(err, os.ErrNotExist) {
		return u, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, u); err != nil {
		return nil, fmt.Errorf("users file: %w", err)
	}
	return u, nil
}

func hashPassword(pw string, salt []byte, iter int) (string, error) {
	h, err := pbkdf2.Key(sha256.New, pw, salt, iter, 32)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(h), nil
}

// Set creates or replaces a user.
func (u *Users) Set(name, password string) error {
	if name == "" || len(name) > 64 || strings.ContainsAny(name, "\r\n\t\x00:") {
		return errors.New("user name must be 1-64 characters without control characters or ':'")
	}
	if len(password) < 12 {
		return errors.New("password must be at least 12 characters")
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	h, err := hashPassword(password, salt, pbkdfIter)
	if err != nil {
		return err
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	var keepOTP *UserOTP
	if ex := u.find(name); ex != nil {
		keepOTP = ex.OTP
	}
	nu := User{OTP: keepOTP, Name: name, Salt: base64.StdEncoding.EncodeToString(salt), Hash: h, Iter: pbkdfIter}
	replaced := false
	for i := range u.List {
		if u.List[i].Name == name {
			u.List[i], replaced = nu, true
		}
	}
	if !replaced {
		u.List = append(u.List, nu)
	}
	return u.save()
}

// dummy keeps the verification time constant for unknown users.
var dummySalt = make([]byte, 16)

// Verify returns the user when name and password match.
func (u *Users) Verify(name, password string) (*User, bool) {
	u.mu.Lock()
	var found *User
	for i := range u.List {
		if u.List[i].Name == name {
			c := u.List[i]
			found = &c
		}
	}
	u.mu.Unlock()
	if found == nil {
		_, _ = hashPassword(password, dummySalt, pbkdfIter)
		return nil, false
	}
	salt, err := base64.StdEncoding.DecodeString(found.Salt)
	if err != nil {
		return nil, false
	}
	h, err := hashPassword(password, salt, found.Iter)
	if err != nil || subtle.ConstantTimeCompare([]byte(h), []byte(found.Hash)) != 1 {
		return nil, false
	}
	return found, true
}

func (u *Users) Count() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return len(u.List)
}

// ---- sessions

type session struct {
	User       string
	CSRF       string
	EnrollOnly bool   // password accepted, but the second factor must be enrolled before anything else
	Pending    string // secret shown during enrollment, not yet confirmed
	Expires    time.Time
	Idle       time.Time
}

type sessions struct {
	mu   sync.Mutex
	m    map[string]*session
	ttl  time.Duration
	idle time.Duration
}

func newSessions(ttl, idle time.Duration) *sessions {
	return &sessions{m: map[string]*session{}, ttl: ttl, idle: idle}
}

func randToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func (s *sessions) create(user string, enrollOnly bool) (string, *session) {
	tok := randToken(32)
	now := time.Now()
	ss := &session{User: user, EnrollOnly: enrollOnly, CSRF: randToken(24), Expires: now.Add(s.ttl), Idle: now.Add(s.idle)}
	s.mu.Lock()
	s.m[tok] = ss
	s.mu.Unlock()
	return tok, ss
}

func (s *sessions) get(tok string) *session {
	s.mu.Lock()
	defer s.mu.Unlock()
	ss := s.m[tok]
	if ss == nil {
		return nil
	}
	now := time.Now()
	if now.After(ss.Expires) || now.After(ss.Idle) {
		delete(s.m, tok)
		return nil
	}
	ss.Idle = now.Add(s.idle)
	return ss
}

func (s *sessions) drop(tok string) {
	s.mu.Lock()
	delete(s.m, tok)
	s.mu.Unlock()
}

// ---- login throttling

type throttle struct {
	mu    sync.Mutex
	fails map[string][]time.Time
}

func newThrottle() *throttle { return &throttle{fails: map[string][]time.Time{}} }

const (
	maxFails   = 5
	failWindow = 5 * time.Minute
)

func (t *throttle) blocked(key string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	cut := time.Now().Add(-failWindow)
	var keep []time.Time
	for _, f := range t.fails[key] {
		if f.After(cut) {
			keep = append(keep, f)
		}
	}
	t.fails[key] = keep
	return len(keep) >= maxFails
}

func (t *throttle) fail(key string) {
	t.mu.Lock()
	t.fails[key] = append(t.fails[key], time.Now())
	t.mu.Unlock()
}

func (t *throttle) reset(key string) {
	t.mu.Lock()
	delete(t.fails, key)
	t.mu.Unlock()
}

// save writes the account file; the caller holds the lock.
func (u *Users) save() error {
	b, _ := json.MarshalIndent(u, "", "  ")
	tmp := u.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, u.path)
}

func (u *Users) find(name string) *User {
	for i := range u.List {
		if u.List[i].Name == name {
			return &u.List[i]
		}
	}
	return nil
}

// HasOTP reports whether the user enrolled a second factor.
func (u *Users) HasOTP(name string) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	x := u.find(name)
	return x != nil && x.OTP != nil
}

// EnableOTP stores the second factor after the user proved possession of the secret with a valid code.
func (u *Users) EnableOTP(name, secret string, usedStep int64, recoveryHashes []string) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	x := u.find(name)
	if x == nil {
		return errors.New("no such user")
	}
	x.OTP = &UserOTP{Secret: secret, LastStep: usedStep, Recovery: recoveryHashes, Enrolled: time.Now().Unix()}
	return u.save()
}

// ResetOTP removes the second factor (the user enrolls again at the next login).
func (u *Users) ResetOTP(name string) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	x := u.find(name)
	if x == nil {
		return errors.New("no such user")
	}
	x.OTP = nil
	return u.save()
}

// VerifyOTP accepts a TOTP code (each time step only once) or an unused recovery code (consumed).
func (u *Users) VerifyOTP(name, code string, now time.Time) (ok, recovery bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	x := u.find(name)
	if x == nil || x.OTP == nil {
		return false, false
	}
	if secret, err := decodeSecret(x.OTP.Secret); err == nil {
		if step := matchTOTP(secret, code, now); step > x.OTP.LastStep {
			x.OTP.LastStep = step
			return u.save() == nil, false
		}
	}
	h := hashRecovery(code)
	if len(normRecovery(code)) == 10 {
		for i, r := range x.OTP.Recovery {
			if subtle.ConstantTimeCompare([]byte(r), []byte(h)) == 1 {
				x.OTP.Recovery = append(x.OTP.Recovery[:i], x.OTP.Recovery[i+1:]...)
				return u.save() == nil, true
			}
		}
	}
	return false, false
}

// RecoveryLeft counts the unused recovery codes.
func (u *Users) RecoveryLeft(name string) int {
	u.mu.Lock()
	defer u.mu.Unlock()
	if x := u.find(name); x != nil && x.OTP != nil {
		return len(x.OTP.Recovery)
	}
	return 0
}

func (s *sessions) setPending(ss *session, secret string) {
	s.mu.Lock()
	ss.Pending = secret
	s.mu.Unlock()
}

func (s *sessions) finishEnroll(ss *session) {
	s.mu.Lock()
	ss.Pending, ss.EnrollOnly = "", false
	s.mu.Unlock()
}
