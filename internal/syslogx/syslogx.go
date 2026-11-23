// Package syslogx sends the operational messages of the programs (start, stop, errors, service control,
// integrity findings) to the host's system log (syslog / journald). Audit records are a different thing: they
// stay in the tamper-evident audit files. Every message is also written to standard error, so `docker logs`
// keeps working, and a missing system log socket never stops a program.
package syslogx

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
)

// Level is a syslog severity.
type Level int

const (
	Crit    Level = 2
	Err     Level = 3
	Warning Level = 4
	Notice  Level = 5
	Info    Level = 6
)

func (l Level) String() string {
	switch l {
	case Crit:
		return "CRIT"
	case Err:
		return "ERR"
	case Warning:
		return "WARN"
	case Notice:
		return "NOTICE"
	}
	return "INFO"
}

// sink writes one message to the system log (set by the platform file).
type sink interface {
	send(l Level, msg string) error
	close()
}

// Logger writes to the system log and to standard error.
type Logger struct {
	tag    string
	mu     sync.Mutex
	s      sink
	stderr io.Writer
	warned bool
}

// New opens the system log with the given tag (the program name). When the system log is not reachable the
// logger still works and only writes to standard error.
func New(tag string) *Logger {
	l := &Logger{tag: tag, stderr: os.Stderr}
	l.s, _ = open(tag)
	return l
}

// Discard returns a logger that writes nowhere (tests).
func Discard() *Logger { return &Logger{tag: "discard", stderr: io.Discard} }

// SetStderr redirects the copy that goes to standard error (tests).
func (l *Logger) SetStderr(w io.Writer) { l.stderr = w }

// Available reports whether the system log socket was reached.
func (l *Logger) Available() bool { return l != nil && l.s != nil }

// Close releases the connection.
func (l *Logger) Close() {
	if l != nil && l.s != nil {
		l.s.close()
	}
}

// clean keeps a message on one line and printable: peer-controlled text must not forge log lines.
func clean(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 && r != '\t' || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	if len(s) > 900 {
		s = s[:900] + "…"
	}
	return strings.TrimSpace(s)
}

// Logf writes one message.
func (l *Logger) Logf(lv Level, format string, a ...any) {
	if l == nil {
		return
	}
	msg := clean(fmt.Sprintf(format, a...))
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.s != nil {
		if err := l.s.send(lv, msg); err != nil && !l.warned {
			l.warned = true
			fmt.Fprintf(l.stderr, "%s: system log unavailable: %v\n", l.tag, err)
		}
	}
	fmt.Fprintf(l.stderr, "%s %s: %s\n", lv, l.tag, msg)
}

func (l *Logger) Infof(f string, a ...any)     { l.Logf(Info, f, a...) }
func (l *Logger) Noticef(f string, a ...any)   { l.Logf(Notice, f, a...) }
func (l *Logger) Warnf(f string, a ...any)     { l.Logf(Warning, f, a...) }
func (l *Logger) Errorf(f string, a ...any)    { l.Logf(Err, f, a...) }
func (l *Logger) Criticalf(f string, a ...any) { l.Logf(Crit, f, a...) }

// Classify picks a severity for a free-text line of the standard library logger.
func Classify(line string) Level {
	s := strings.ToLower(line)
	switch {
	case strings.Contains(s, "panic") || strings.Contains(s, "fatal"):
		return Crit
	case strings.Contains(s, "error") || strings.Contains(s, "cannot") || strings.Contains(s, "unavailable"):
		return Err
	case strings.Contains(s, "failed") || strings.Contains(s, "refused") || strings.Contains(s, "denied"):
		return Warning
	}
	return Info
}

// Writer adapts the logger for log.New: each line goes to the system log (severity guessed from the text).
// Nothing is written to standard error by the adapter itself beyond what Logf does.
func (l *Logger) Writer() io.Writer { return writer{l} }

type writer struct{ l *Logger }

func (w writer) Write(b []byte) (int, error) {
	for _, line := range strings.Split(strings.TrimRight(string(b), "\n"), "\n") {
		if strings.TrimSpace(line) != "" {
			w.l.Logf(Classify(line), "%s", line)
		}
	}
	return len(b), nil
}
