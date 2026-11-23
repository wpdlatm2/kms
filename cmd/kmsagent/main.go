// kmsagent is the host-side helper of the web console: it reports the state of the pqc-kms containers and
// starts, stops and restarts exactly the services it was told about. It listens on a Unix socket only.
package main

import (
	"flag"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/wpdlatm2/kms/internal/sysctl"
	"github.com/wpdlatm2/kms/internal/syslogx"
)

var sys = syslogx.New("kmsagent")

func fatal(msg string, a ...any) {
	sys.Criticalf("fatal: "+msg, a...)
	os.Exit(1)
}

func main() {
	sys.Noticef("starting: pid %d", os.Getpid())
	sock := flag.String("socket", "/docker/pqc-kms/run/agent.sock", "Unix socket to listen on")
	mode := flag.String("socket-mode", "660", "socket file mode (octal)")
	services := flag.String("services", "kms=pqc-kms-kms-1,console=pqc-kms-console-1", "controllable services: name=container,...")
	disks := flag.String("disks", "/docker,/data", "paths whose file system usage is reported")
	dockerBin := flag.String("docker", "docker", "docker binary")
	flag.Parse()
	svcs, err := sysctl.ParseServices(*services)
	if err != nil {
		fatal("%v", err)
	}
	var dp []string
	for _, d := range strings.Split(*disks, ",") {
		if d = strings.TrimSpace(d); d != "" {
			dp = append(dp, d)
		}
	}
	a, err := sysctl.NewAgent(svcs, sysctl.DockerRunner{Bin: *dockerBin}, dp)
	if err != nil {
		fatal("%v", err)
	}
	// every action taken on a container is operations news
	a.Log = func(format string, args ...any) { sys.Noticef(format, args...) }
	m, err := strconv.ParseUint(*mode, 8, 32)
	if err != nil || m > 0o777 {
		fatal("-socket-mode must be octal, e.g. 660")
	}
	ln, err := sysctl.ListenUnix(*sock, os.FileMode(m), a)
	if err != nil {
		fatal("%v", err)
	}
	sys.Noticef("started: listening on %s (mode %o) for services %s", *sock, m, *services)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	got := <-sig
	sys.Noticef("stopping: received %v", got)
	_ = ln.Close()
	_ = os.Remove(*sock)
	sys.Noticef("stopped")
	sys.Close()
}
