// Package logs writes the two audit trails of the backend: the client log (KMIP and client REST requests)
// and the administration API log. They are separate files; a request is recorded in exactly one of them,
// according to the port it arrived on.
package logs

import (
	"bufio"
	"encoding/json"
	"os"
	"sync"
	"time"
)

// Entry is one log line (JSON).
type Entry struct {
	Time   time.Time `json:"time"`
	Plane  string    `json:"plane"`         // "client" or "admin"
	Kind   string    `json:"kind"`          // "request" (protocol level) or "event" (what the service did)
	Who    string    `json:"who"`           // certificate CN, or the acting user for the admin plane
	Via    string    `json:"via,omitempty"` // the proxy that asserted the acting user
	Op     string    `json:"op"`
	Target string    `json:"target,omitempty"`
	Detail string    `json:"detail,omitempty"`
	Result string    `json:"result"`
	Remote string    `json:"remote,omitempty"`
}

const ringSize = 2000

// Log is an append-only JSONL file with an in-memory tail for the API.
type Log struct {
	mu   sync.Mutex
	f    *os.File
	ring []Entry
	name string
}

// Open opens (creating) the file; path "" keeps the log in memory only.
func Open(path, name string) (*Log, error) {
	l := &Log{name: name}
	if path == "" {
		return l, nil
	}
	if f, err := os.Open(path); err == nil { // #nosec G304 -- operator-configured path
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		for sc.Scan() {
			var e Entry
			if json.Unmarshal(sc.Bytes(), &e) == nil {
				l.push(e)
			}
		}
		_ = f.Close()
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) // #nosec G304 -- operator-configured path
	if err != nil {
		return nil, err
	}
	l.f = f
	return l, nil
}

func (l *Log) push(e Entry) {
	l.ring = append(l.ring, e)
	if len(l.ring) > ringSize {
		l.ring = l.ring[len(l.ring)-ringSize:]
	}
}

// Add records an entry (the time is set here).
func (l *Log) Add(e Entry) {
	if l == nil {
		return
	}
	e.Time = time.Now().UTC()
	l.mu.Lock()
	defer l.mu.Unlock()
	l.push(e)
	if l.f != nil {
		b, _ := json.Marshal(e)
		_, _ = l.f.Write(append(b, '\n'))
	}
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

func (l *Log) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f != nil {
		_ = l.f.Close()
		l.f = nil
	}
}
