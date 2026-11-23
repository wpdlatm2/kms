package logs

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// SyslogForwarder sends every audit entry to a central collector (SIEM) as RFC 5424 messages with
// octet-counting framing over TCP or TLS. Sending never blocks the audit path: entries are queued, and when
// the collector is unreachable the oldest queued entries are dropped (the local, chained log is the record
// of truth; the count of dropped entries is reported when the connection returns).
type SyslogForwarder struct {
	addr, tag string
	useTLS    bool
	host      string
	ch        chan Entry
	mu        sync.Mutex
	dropped   int
}

// NewSyslogForwarder parses tcp://host:port or tls://host:port.
func NewSyslogForwarder(target, tag string) (*SyslogForwarder, error) {
	u, err := url.Parse(target)
	if err != nil || (u.Scheme != "tcp" && u.Scheme != "tls") || u.Host == "" {
		return nil, errors.New("syslog target must look like tcp://host:514 or tls://host:6514")
	}
	h, _ := os.Hostname()
	f := &SyslogForwarder{addr: u.Host, tag: tag, useTLS: u.Scheme == "tls", host: h, ch: make(chan Entry, 4096)}
	go f.run()
	return f, nil
}

// Send queues an entry.
func (f *SyslogForwarder) Send(e Entry) {
	select {
	case f.ch <- e:
	default:
		f.mu.Lock()
		f.dropped++
		f.mu.Unlock()
	}
}

func severity(e Entry) int {
	switch e.Outcome {
	case OutcomeDenied:
		return 4 // warning
	case OutcomeFailure:
		return 3 // error
	}
	return 6 // informational
}

// Format renders an entry as an RFC 5424 message (facility 13 = log audit).
func (f *SyslogForwarder) Format(e Entry) string {
	body, _ := json.Marshal(e)
	pri := 13*8 + severity(e)
	return fmt.Sprintf("<%d>1 %s %s %s - %s - %s", pri, e.Time.UTC().Format("2006-01-02T15:04:05.000000Z"), nz(f.host), f.tag, nz(e.Category), body)
}

func nz(s string) string {
	s = strings.Map(func(r rune) rune {
		if r <= 0x20 || r > 0x7e {
			return -1
		}
		return r
	}, s)
	if s == "" {
		return "-"
	}
	if len(s) > 48 {
		s = s[:48]
	}
	return s
}

func (f *SyslogForwarder) dial() (net.Conn, error) {
	d := &net.Dialer{Timeout: 5 * time.Second}
	if f.useTLS {
		return tls.DialWithDialer(d, "tcp", f.addr, &tls.Config{MinVersion: tls.VersionTLS12})
	}
	return d.Dial("tcp", f.addr)
}

func (f *SyslogForwarder) run() {
	var conn net.Conn
	for e := range f.ch {
		msg := f.Format(e)
		framed := fmt.Sprintf("%d %s", len(msg), msg) // RFC 6587 octet counting
		for try := 0; try < 2; try++ {
			if conn == nil {
				c, err := f.dial()
				if err != nil {
					time.Sleep(2 * time.Second)
					break // drop this entry for now; the local log still has it
				}
				conn = c
				f.mu.Lock()
				d := f.dropped
				f.dropped = 0
				f.mu.Unlock()
				if d > 0 {
					note := f.Format(Entry{Time: time.Now().UTC(), Plane: "system", Kind: "event", Op: "forward-gap", Category: "audit-maintenance", Outcome: OutcomeFailure,
						Who: "system", Detail: fmt.Sprintf("%d entries were not forwarded while the collector was unreachable", d)})
					_, _ = fmt.Fprintf(conn, "%d %s", len(note), note)
				}
			}
			_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if _, err := conn.Write([]byte(framed)); err != nil {
				_ = conn.Close()
				conn = nil
				continue
			}
			break
		}
	}
}
