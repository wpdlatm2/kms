//go:build linux || darwin || freebsd

package syslogx

import (
	"log/syslog"
)

type unixSink struct{ w *syslog.Writer }

func open(tag string) (sink, error) {
	w, err := syslog.New(syslog.LOG_DAEMON|syslog.LOG_INFO, tag)
	if err != nil {
		return nil, err
	}
	return &unixSink{w}, nil
}

func (s *unixSink) send(l Level, msg string) error {
	switch l {
	case Crit:
		return s.w.Crit(msg)
	case Err:
		return s.w.Err(msg)
	case Warning:
		return s.w.Warning(msg)
	case Notice:
		return s.w.Notice(msg)
	}
	return s.w.Info(msg)
}

func (s *unixSink) close() { _ = s.w.Close() }
