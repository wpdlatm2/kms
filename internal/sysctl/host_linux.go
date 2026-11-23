//go:build linux

package sysctl

import (
	"bufio"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
)

func hostInfo(disks []string) Host {
	h := Host{CPUs: runtime.NumCPU()}
	if b, err := os.ReadFile("/proc/uptime"); err == nil {
		if f := strings.Fields(string(b)); len(f) > 0 {
			if v, err := strconv.ParseFloat(f[0], 64); err == nil {
				h.UptimeSeconds = int64(v)
			}
		}
	}
	if b, err := os.ReadFile("/proc/loadavg"); err == nil {
		if f := strings.Fields(string(b)); len(f) > 0 {
			h.Load1, _ = strconv.ParseFloat(f[0], 64)
		}
	}
	if f, err := os.Open("/proc/meminfo"); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			l := strings.Fields(sc.Text())
			if len(l) < 2 {
				continue
			}
			kb, _ := strconv.ParseInt(l[1], 10, 64)
			switch l[0] {
			case "MemTotal:":
				h.MemTotalMB = kb / 1024
			case "MemAvailable:":
				h.MemAvailMB = kb / 1024
			}
		}
		_ = f.Close()
	}
	for _, p := range disks {
		var s syscall.Statfs_t
		if syscall.Statfs(p, &s) != nil || s.Blocks == 0 {
			continue
		}
		total := int64(s.Blocks) * int64(s.Bsize)
		free := int64(s.Bavail) * int64(s.Bsize)
		h.Disks = append(h.Disks, DiskUse{Path: p, TotalGB: total >> 30, FreeGB: free >> 30, UsedPct: int(100 * (total - free) / total)})
	}
	return h
}
