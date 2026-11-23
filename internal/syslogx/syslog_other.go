//go:build !(linux || darwin || freebsd)

package syslogx

import "errors"

func open(string) (sink, error) { return nil, errors.New("no system log on this platform") }
