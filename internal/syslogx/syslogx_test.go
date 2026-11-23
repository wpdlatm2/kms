package syslogx

import (
	"bytes"
	"log"
	"strings"
	"testing"
)

type memSink struct{ got []string }

func (m *memSink) send(l Level, msg string) error {
	m.got = append(m.got, l.String()+" "+msg)
	return nil
}
func (m *memSink) close() {}

func TestLevelsLinesAndForgeryAreHandled(t *testing.T) {
	m := &memSink{}
	var errBuf bytes.Buffer
	l := &Logger{tag: "kmsd", s: m, stderr: &errBuf}
	l.Warnf("handshake from %s failed", "10.0.0.9\nFAKE kmsd: login ok")
	l.Infof("started")
	if len(m.got) != 2 || strings.Contains(m.got[0], "\n") || !strings.HasPrefix(m.got[0], "WARN ") {
		t.Fatalf("%q", m.got)
	}
	if !strings.Contains(errBuf.String(), "WARN kmsd: ") || strings.Count(errBuf.String(), "\n") != 2 {
		t.Fatalf("stderr copy: %q", errBuf.String())
	}
	long := strings.Repeat("x", 5000)
	l.Infof("%s", long)
	if len(m.got[2]) > 1000 {
		t.Fatalf("long message not cut: %d", len(m.got[2]))
	}
}

func TestStdLoggerAdapterClassifies(t *testing.T) {
	m := &memSink{}
	l := &Logger{tag: "t", s: m, stderr: &bytes.Buffer{}}
	lg := log.New(l.Writer(), "", 0)
	lg.Printf("kmip: recovered from a panic while serving x")
	lg.Printf("kmip: handshake from y failed: bad certificate")
	lg.Printf("KMIP (client plane) on :5696")
	want := []string{"CRIT", "WARN", "INFO"}
	for i, w := range want {
		if !strings.HasPrefix(m.got[i], w+" ") {
			t.Fatalf("%q", m.got)
		}
	}
}

func TestMissingSystemLogDoesNotStopTheProgram(t *testing.T) {
	var buf bytes.Buffer
	l := &Logger{tag: "x", stderr: &buf} // no sink
	l.Errorf("still logged")
	if !strings.Contains(buf.String(), "ERR x: still logged") || l.Available() {
		t.Fatal(buf.String())
	}
	var nilLogger *Logger
	nilLogger.Infof("no panic")
	Discard().Errorf("nothing")
}
