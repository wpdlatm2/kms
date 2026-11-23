// Package logs writes the audit trails of the backend and the console as tamper-evident records.
//
// Every entry carries the fields an auditor needs to answer who did what, when, from where and with what
// result (user, time, source address, operation, target, outcome), the approval number and the responsible
// person of permission changes, and two integrity fields:
//
//   - Hash: SHA-256 over the entry (including the previous entry's hash), forming a chain. Removing, changing,
//     inserting or reordering an entry breaks the chain from that point on; anyone holding the files can check it.
//   - MAC: HMAC-SHA256 of the hash under a secret key that is not stored next to the files (the backend keeps it
//     sealed by the TPM-bound sealer). Without the key an attacker cannot recompute a valid chain after editing.
//
// Files rotate daily (base-YYYYMMDD.jsonl); the chain continues across files. The application never deletes
// audit files by itself: Purge removes files only after the configured retention period and leaves a record.
package logs

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Entry is one audit record (one JSON line).
type Entry struct {
	Seq       uint64    `json:"seq"`
	Time      time.Time `json:"time"`               // UTC, microsecond resolution
	Plane     string    `json:"plane"`              // client | admin | console
	Kind      string    `json:"kind"`               // request (protocol level) | event (what the service did)
	Category  string    `json:"category,omitempty"` // authentication | key-lifecycle | key-access | permission-change | audit-access | api-access | system | audit-maintenance
	Outcome   string    `json:"outcome,omitempty"`  // success | failure | denied
	Who       string    `json:"who"`                // user, certificate CN, or the acting user for the admin plane
	Via       string    `json:"via,omitempty"`      // the proxy that asserted the acting user
	Op        string    `json:"op"`
	Target    string    `json:"target,omitempty"`
	Detail    string    `json:"detail,omitempty"`
	Approval  string    `json:"approval,omitempty"` // approval number of an authorised permission change (승인번호)
	Owner     string    `json:"owner,omitempty"`    // person responsible for it (담당자)
	Result    string    `json:"result"`
	Remote    string    `json:"remote,omitempty"`    // source address
	RequestID string    `json:"requestId,omitempty"` // correlates with the X-Request-Id the caller received
	Session   string    `json:"session,omitempty"`   // short digest of the console session, for correlation
	Prev      string    `json:"prev"`
	Hash      string    `json:"hash"`
	MAC       string    `json:"mac,omitempty"`
}

// ErrorHook receives operational problems of the audit log itself (an entry that could not be written). The
// service points it at the system log.
var ErrorHook func(msg string)

const (
	OutcomeSuccess = "success"
	OutcomeFailure = "failure"
	OutcomeDenied  = "denied"

	ringSize = 2000
)

// Categorize assigns the audit category of an entry from its operation.
func Categorize(e Entry) string {
	op := strings.ToLower(e.Op)
	switch {
	case e.Category != "":
		return e.Category
	case strings.HasPrefix(op, "audit-"):
		return "audit-access"
	case strings.HasPrefix(op, "login") || op == "logout" || strings.HasPrefix(op, "account-") || strings.HasPrefix(op, "password-") || op == "csrf-rejected" || strings.HasPrefix(op, "otp-") || strings.Contains(op, "handshake") || op == "session-expired":
		return "authentication"
	case strings.HasPrefix(op, "binding-") || strings.HasPrefix(op, "manager-") || strings.HasPrefix(op, "template-") || strings.HasPrefix(op, "group-"):
		return "permission-change"
	case op == "get" || op == "get-denied" || op == "kmip get" || strings.HasSuffix(op, "/value"):
		return "key-access"
	case op == "create" || op == "activate" || op == "deactivate" || op == "compromise" || op == "rekey" || op == "destroy" || op == "setname" ||
		strings.HasSuffix(op, "-denied"):
		return "key-lifecycle"
	case op == "startup" || op == "shutdown":
		return "system"
	case e.Kind == "request":
		return "api-access"
	}
	return "event"
}

// OutcomeOf derives success / failure / denied from the result text.
func OutcomeOf(e Entry) string {
	if e.Outcome != "" {
		return e.Outcome
	}
	r := strings.ToLower(e.Result)
	switch {
	case r == "ok" || r == "success":
		return OutcomeSuccess
	case strings.Contains(r, "denied") || strings.Contains(r, "forbidden") || strings.Contains(r, "http 401") || strings.Contains(r, "http 403") ||
		strings.Contains(r, "not signed in") || strings.HasSuffix(strings.ToLower(e.Op), "-denied"):
		return OutcomeDenied
	}
	return OutcomeFailure
}

// Options configure a Log.
type Options struct {
	Path      string        // base path, e.g. /data/client.log.jsonl ("" = memory only)
	Name      string        // human name of the log
	Key       []byte        // MAC key (empty = hash chain only)
	Retention time.Duration // Purge refuses to remove anything younger than this (0 = no minimum)
}

// Log is an append-only, tamper-evident audit log.
type Log struct {
	mu        sync.Mutex
	opt       Options
	dir, base string
	f         *os.File
	day       string
	seq       uint64
	last      string
	ring      []Entry
	sinks     []func(Entry)
	now       func() time.Time
	Recovered string // set when a torn last line was dropped at start
}

// Open opens a log with a hash chain only (no MAC key).
func Open(path, name string) (*Log, error) { return OpenWith(Options{Path: path, Name: name}) }

func baseOf(path string) (dir, base string) {
	dir, base = filepath.Split(path)
	if dir == "" {
		dir = "."
	}
	return dir, strings.TrimSuffix(base, ".jsonl")
}

func (l *Log) files() ([]string, error) {
	if l.dir == "" {
		return nil, nil
	}
	m, err := filepath.Glob(filepath.Join(l.dir, l.base+"-????????.jsonl"))
	if err != nil {
		return nil, err
	}
	sort.Strings(m)
	return m, nil
}

// OpenWith opens the log, continuing the chain of an existing one.
func OpenWith(o Options) (*Log, error) {
	l := &Log{opt: o, now: func() time.Time { return time.Now().UTC() }}
	if o.Path == "" {
		return l, nil
	}
	l.dir, l.base = baseOf(o.Path)
	if err := os.MkdirAll(l.dir, 0o700); err != nil {
		return nil, err
	}
	files, err := l.files()
	if err != nil {
		return nil, err
	}
	var tail []Entry
	for i := len(files) - 1; i >= 0 && len(tail) < ringSize; i-- {
		ents, dropped, err := readFile(files[i], i == len(files)-1)
		if err != nil {
			return nil, err
		}
		if dropped > 0 {
			l.Recovered = fmt.Sprintf("dropped %d bytes of an incomplete last line in %s", dropped, filepath.Base(files[i]))
		}
		tail = append(ents, tail...)
	}
	if len(tail) > ringSize {
		tail = tail[len(tail)-ringSize:]
	}
	l.ring = tail
	if n := len(tail); n > 0 {
		l.seq, l.last = tail[n-1].Seq, tail[n-1].Hash
	}
	if l.Recovered != "" {
		l.Add(Entry{Plane: planeOf(l.opt.Name), Kind: "event", Who: "system", Op: "audit-recovered", Detail: l.Recovered, Result: "ok", Category: "audit-maintenance"})
	}
	return l, nil
}

func planeOf(name string) string {
	if name == "" {
		return "system"
	}
	return name
}

// readFile parses a log file. With repair set, an incomplete last line (a torn write) is cut off the file.
func readFile(path string, repair bool) (ents []Entry, dropped int, err error) {
	b, err := os.ReadFile(path) // #nosec G304 -- operator-configured path
	if err != nil {
		return nil, 0, err
	}
	good := 0
	for good < len(b) {
		nl := strings.IndexByte(string(b[good:]), '\n')
		if nl < 0 {
			break
		}
		var e Entry
		if json.Unmarshal(b[good:good+nl], &e) != nil {
			break
		}
		ents = append(ents, e)
		good += nl + 1
	}
	if rest := len(b) - good; rest > 0 {
		if repair {
			if err := os.Truncate(path, int64(good)); err != nil {
				return nil, 0, err
			}
		}
		return ents, rest, nil
	}
	return ents, 0, nil
}

// AddSink registers a consumer called with every entry after it was written (for example a SIEM forwarder).
func (l *Log) AddSink(f func(Entry)) {
	l.mu.Lock()
	l.sinks = append(l.sinks, f)
	l.mu.Unlock()
}

func hashOf(e Entry) string {
	e.Hash, e.MAC = "", ""
	b, _ := json.Marshal(e)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func macOf(key []byte, hash string) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(hash))
	return hex.EncodeToString(m.Sum(nil))
}

// Add appends an entry (sequence number, time, chain and MAC are set here).
func (l *Log) Add(e Entry) {
	if l == nil {
		return
	}
	l.mu.Lock()
	e.Time = l.now().UTC().Truncate(time.Microsecond)
	e.Seq, e.Prev = l.seq+1, l.last
	e.Category = Categorize(e)
	e.Outcome = OutcomeOf(e)
	e.Hash = hashOf(e)
	if len(l.opt.Key) > 0 {
		e.MAC = macOf(l.opt.Key, e.Hash)
	}
	if l.dir != "" {
		if err := l.write(e); err != nil {
			// an audit record that cannot be written must not vanish silently
			msg := fmt.Sprintf("audit log %s: cannot write entry %d: %v", l.opt.Name, e.Seq, err)
			if ErrorHook != nil {
				ErrorHook(msg)
			} else {
				fmt.Fprintln(os.Stderr, msg)
			}
		}
	}
	l.seq, l.last = e.Seq, e.Hash
	l.ring = append(l.ring, e)
	if len(l.ring) > ringSize {
		l.ring = l.ring[len(l.ring)-ringSize:]
	}
	sinks := l.sinks
	l.mu.Unlock()
	for _, s := range sinks {
		s(e)
	}
}

func (l *Log) write(e Entry) error {
	day := e.Time.Format("20060102")
	if l.f == nil || day != l.day {
		if l.f != nil {
			_ = l.f.Sync()
			_ = l.f.Close()
		}
		path := filepath.Join(l.dir, l.base+"-"+day+".jsonl")
		f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) // #nosec G304 -- operator-configured path
		if err != nil {
			return err
		}
		l.f, l.day = f, day
	}
	b, _ := json.Marshal(e)
	if _, err := l.f.Write(append(b, '\n')); err != nil {
		return err
	}
	if e.Kind == "event" || e.Outcome != OutcomeSuccess { // what changed, and every failure, is durable before we go on
		return l.f.Sync()
	}
	return nil
}

// Last returns up to n entries, newest first.
func (l *Log) Last(n int) []Entry {
	l.mu.Lock()
	defer l.mu.Unlock()
	if n > len(l.ring) {
		n = len(l.ring)
	}
	out := make([]Entry, 0, n)
	for i := len(l.ring) - 1; i >= len(l.ring)-n; i-- {
		out = append(out, l.ring[i])
	}
	return out
}

// Head returns the sequence number and hash of the newest entry.
func (l *Log) Head() (uint64, string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.seq, l.last
}

// Close flushes and closes the current file.
func (l *Log) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f != nil {
		_ = l.f.Sync()
		_ = l.f.Close()
		l.f = nil
	}
}

// Name is the log's name.
func (l *Log) Name() string { return l.opt.Name }

// Retention is the configured retention period.
func (l *Log) Retention() time.Duration { return l.opt.Retention }

// ---- filtering

// Filter selects entries for Query. Zero fields do not filter.
type Filter struct {
	From, To time.Time
	Category string
	Outcome  string
	Who      string // exact match on the user or on the proxy
	Op       string // substring
	Text     string // substring of any text field
	Limit    int    // newest first; 0 = 1000
}

func (f Filter) match(e Entry) bool {
	if !f.From.IsZero() && e.Time.Before(f.From) {
		return false
	}
	if !f.To.IsZero() && !e.Time.Before(f.To) {
		return false
	}
	if f.Category != "" && e.Category != f.Category {
		return false
	}
	if f.Outcome != "" && e.Outcome != f.Outcome {
		return false
	}
	if f.Who != "" && e.Who != f.Who && e.Via != f.Who {
		return false
	}
	if f.Op != "" && !strings.Contains(strings.ToLower(e.Op), strings.ToLower(f.Op)) {
		return false
	}
	if f.Text != "" {
		hay := strings.ToLower(strings.Join([]string{e.Who, e.Via, e.Op, e.Target, e.Detail, e.Approval, e.Owner, e.Result, e.Remote, e.RequestID}, "\n"))
		if !strings.Contains(hay, strings.ToLower(f.Text)) {
			return false
		}
	}
	return true
}

func dayOf(path, base string) string {
	return strings.TrimSuffix(strings.TrimPrefix(filepath.Base(path), base+"-"), ".jsonl")
}

// Query returns matching entries, newest first.
func (l *Log) Query(f Filter) ([]Entry, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = 1000
	}
	if limit > 20000 {
		limit = 20000
	}
	if l.dir == "" {
		l.mu.Lock()
		defer l.mu.Unlock()
		var out []Entry
		for i := len(l.ring) - 1; i >= 0 && len(out) < limit; i-- {
			if f.match(l.ring[i]) {
				out = append(out, l.ring[i])
			}
		}
		return out, nil
	}
	files, err := l.filesSnapshot()
	if err != nil {
		return nil, err
	}
	var out []Entry
	for i := len(files) - 1; i >= 0 && len(out) < limit; i-- {
		day := dayOf(files[i], l.base)
		if !f.From.IsZero() && day < f.From.UTC().Format("20060102") {
			break
		}
		if !f.To.IsZero() && day > f.To.UTC().Format("20060102") {
			continue
		}
		ents, _, err := readFile(files[i], false)
		if err != nil {
			return nil, err
		}
		for j := len(ents) - 1; j >= 0 && len(out) < limit; j-- {
			if f.match(ents[j]) {
				out = append(out, ents[j])
			}
		}
	}
	return out, nil
}

// ---- retention

// Purge removes whole daily files older than before, but never anything younger than the retention period.
// It records what it removes first, so the chain shows where the retained history now starts.
func (l *Log) Purge(before time.Time, by string) ([]string, error) {
	if l.dir == "" {
		return nil, errors.New("a memory-only log has no files to purge")
	}
	if ret := l.opt.Retention; ret > 0 && before.After(l.now().Add(-ret)) {
		return nil, fmt.Errorf("the retention period of %d days has not elapsed for entries before %s", int(ret.Hours()/24), before.UTC().Format("2006-01-02"))
	}
	files, err := l.filesSnapshot()
	if err != nil {
		return nil, err
	}
	cut := before.UTC().Format("20060102")
	l.mu.Lock()
	cur := l.day
	l.mu.Unlock()
	var old, names []string
	for _, f := range files {
		if d := dayOf(f, l.base); d < cut && d != cur {
			old = append(old, f)
			names = append(names, filepath.Base(f))
		}
	}
	if len(old) == 0 {
		return nil, nil
	}
	l.Add(Entry{Plane: planeOf(l.opt.Name), Kind: "event", Who: by, Op: "audit-purge", Category: "audit-maintenance", Result: "ok",
		Detail: fmt.Sprintf("removed %d file(s) after the retention period: %s", len(old), strings.Join(names, ", "))})
	for _, f := range old {
		if err := os.Remove(f); err != nil {
			return names, err
		}
	}
	return names, nil
}

func (l *Log) filesSnapshot() ([]string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f != nil {
		_ = l.f.Sync()
	}
	return l.files()
}

func scanLines(path string, fn func(line []byte) bool) error {
	f, err := os.Open(path) // #nosec G304 -- operator-configured path
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 8<<20)
	for sc.Scan() {
		if !fn(sc.Bytes()) {
			break
		}
	}
	return sc.Err()
}
