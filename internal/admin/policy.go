package admin

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
	"unicode"
)

// PasswordPolicy are the rules for console passwords.
type PasswordPolicy struct {
	MinLength      int  `json:"minLength"`      // 8-64
	MinClasses     int  `json:"minClasses"`     // character classes required: upper, lower, digit, symbol (1-4)
	ForbidUsername bool `json:"forbidUsername"` // the password must not contain the user name
	ForbidRepeat   bool `json:"forbidRepeat"`   // no character three or more times in a row
	History        int  `json:"history"`        // the last N passwords cannot be reused (0-10)
	MaxAgeDays     int  `json:"maxAgeDays"`     // password expires after N days (0 = never, 1-365)
	WarnDays       int  `json:"warnDays"`       // announce the expiry N days ahead (0-60)
	ForceChange    bool `json:"forceChange"`    // a password set by an administrator must be changed at the next login
}

// LockoutPolicy locks an account after repeated failures.
type LockoutPolicy struct {
	MaxFails      int `json:"maxFails"`      // failures that lock the account (3-10)
	WindowMinutes int `json:"windowMinutes"` // failures count within this time (1-60)
	LockMinutes   int `json:"lockMinutes"`   // lock duration; 0 = until an administrator unlocks (0-1440)
}

// SessionPolicy limits web sessions.
type SessionPolicy struct {
	TTLHours    int `json:"ttlHours"`    // absolute lifetime (1-24)
	IdleMinutes int `json:"idleMinutes"` // idle timeout (5-240)
}

// Settings is the security configuration of the console accounts.
type Settings struct {
	Password  PasswordPolicy `json:"password"`
	Lockout   LockoutPolicy  `json:"lockout"`
	Session   SessionPolicy  `json:"session"`
	ChangedBy string         `json:"changedBy,omitempty"`
	ChangedAt string         `json:"changedAt,omitempty"`
	Approval  string         `json:"approval,omitempty"`
	Owner     string         `json:"owner,omitempty"`
}

// DefaultSettings are the values used until an administrator changes them.
func DefaultSettings() Settings {
	return Settings{
		Password: PasswordPolicy{MinLength: 12, MinClasses: 3, ForbidUsername: true, ForbidRepeat: true, History: 5, MaxAgeDays: 90, WarnDays: 14, ForceChange: true},
		Lockout:  LockoutPolicy{MaxFails: 5, WindowMinutes: 15, LockMinutes: 30},
		Session:  SessionPolicy{TTLHours: 8, IdleMinutes: 20},
	}
}

func between(name string, v, lo, hi int) error {
	if v < lo || v > hi {
		return fmt.Errorf("%s must be between %d and %d", name, lo, hi)
	}
	return nil
}

// Validate checks the ranges.
func (s Settings) Validate() error {
	p, l, x := s.Password, s.Lockout, s.Session
	for _, c := range []error{
		between("password minimum length", p.MinLength, 8, 64), between("character classes", p.MinClasses, 1, 4), between("password history", p.History, 0, 10),
		between("password maximum age (days)", p.MaxAgeDays, 0, 365), between("expiry warning (days)", p.WarnDays, 0, 60),
		between("failures before lock", l.MaxFails, 3, 10), between("failure window (minutes)", l.WindowMinutes, 1, 60), between("lock duration (minutes)", l.LockMinutes, 0, 1440),
		between("session lifetime (hours)", x.TTLHours, 1, 24), between("idle timeout (minutes)", x.IdleMinutes, 5, 240),
	} {
		if c != nil {
			return c
		}
	}
	if p.MaxAgeDays > 0 && p.WarnDays >= p.MaxAgeDays {
		return errors.New("the expiry warning must be shorter than the maximum age")
	}
	return nil
}

// CheckPassword applies the password rules. The message never contains the password.
func (p PasswordPolicy) CheckPassword(user, pw string) error {
	if n := len([]rune(pw)); n < p.MinLength {
		return fmt.Errorf("password must be at least %d characters", p.MinLength)
	}
	if len(pw) > 128 {
		return errors.New("password must be at most 128 bytes")
	}
	var up, lo, dg, sy bool
	for _, r := range pw {
		switch {
		case unicode.IsControl(r):
			return errors.New("password must not contain control characters")
		case unicode.IsUpper(r):
			up = true
		case unicode.IsLower(r):
			lo = true
		case unicode.IsDigit(r):
			dg = true
		default:
			sy = true
		}
	}
	classes := 0
	for _, b := range []bool{up, lo, dg, sy} {
		if b {
			classes++
		}
	}
	if classes < p.MinClasses {
		return fmt.Errorf("password must use at least %d of: upper-case, lower-case, digits, symbols", p.MinClasses)
	}
	if p.ForbidUsername && len(user) >= 3 && strings.Contains(strings.ToLower(pw), strings.ToLower(user)) {
		return errors.New("password must not contain the user name")
	}
	if p.ForbidRepeat {
		rs := []rune(pw)
		for i := 2; i < len(rs); i++ {
			if rs[i] == rs[i-1] && rs[i] == rs[i-2] {
				return errors.New("password must not repeat a character three times in a row")
			}
		}
	}
	return nil
}

// Store keeps the settings in memory and in a file (mode 0600). path "" = memory only.
type SettingsStore struct {
	mu   sync.RWMutex
	path string
	s    Settings
}

// LoadSettings reads the file, falling back to the defaults when it does not exist.
func LoadSettings(path string) (*SettingsStore, error) {
	st := &SettingsStore{path: path, s: DefaultSettings()}
	if path == "" {
		return st, nil
	}
	b, err := os.ReadFile(path) // #nosec G304 -- operator-configured path
	if errors.Is(err, os.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &st.s); err != nil {
		return nil, fmt.Errorf("settings file: %w", err)
	}
	if err := st.s.Validate(); err != nil {
		return nil, fmt.Errorf("settings file: %w", err)
	}
	return st, nil
}

// Get returns a copy.
func (t *SettingsStore) Get() Settings {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.s
}

// Set validates, stores and persists new settings.
func (t *SettingsStore) Set(n Settings, by, approval, owner string) error {
	if err := n.Validate(); err != nil {
		return err
	}
	n.ChangedBy, n.ChangedAt, n.Approval, n.Owner = by, time.Now().UTC().Format(time.RFC3339), approval, owner
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.path != "" {
		b, _ := json.MarshalIndent(n, "", "  ")
		tmp := t.path + ".tmp"
		if err := os.WriteFile(tmp, b, 0o600); err != nil {
			return err
		}
		if err := os.Rename(tmp, t.path); err != nil {
			return err
		}
	}
	t.s = n
	return nil
}
