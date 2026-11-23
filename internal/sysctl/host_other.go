//go:build !linux

package sysctl

func hostInfo([]string) Host { return Host{} }
