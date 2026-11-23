// Package sysctl lets the web console look at and control the services of the deployment without handing the
// console any rights over the host. A small host-side agent (cmd/kmsagent) owns the Docker access; it listens
// on a Unix socket (file permissions decide who may talk to it) and accepts exactly three actions - start, stop,
// restart - on a fixed list of services given at its start. The console never sends a container name.
package sysctl

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Service is one controllable service: the public name and the Docker container behind it.
type Service struct{ Name, Container string }

// State is what the agent reports about a service.
type State struct {
	Name          string `json:"name"`
	Container     string `json:"container"`
	Status        string `json:"status"` // running | exited | restarting | paused | created | missing | unknown
	Running       bool   `json:"running"`
	Health        string `json:"health,omitempty"` // healthy | unhealthy | starting | "" (no health check)
	StartedAt     string `json:"startedAt,omitempty"`
	UptimeSeconds int64  `json:"uptimeSeconds,omitempty"`
	RestartCount  int    `json:"restartCount"`
	ExitCode      int    `json:"exitCode,omitempty"`
	Image         string `json:"image,omitempty"`
}

// Host holds basic host metrics (Linux only; empty elsewhere).
type Host struct {
	UptimeSeconds int64     `json:"uptimeSeconds,omitempty"`
	Load1         float64   `json:"load1,omitempty"`
	CPUs          int       `json:"cpus,omitempty"`
	MemTotalMB    int64     `json:"memTotalMB,omitempty"`
	MemAvailMB    int64     `json:"memAvailMB,omitempty"`
	Disks         []DiskUse `json:"disks,omitempty"`
}

// DiskUse is the usage of the file system holding Path.
type DiskUse struct {
	Path    string `json:"path"`
	TotalGB int64  `json:"totalGB"`
	FreeGB  int64  `json:"freeGB"`
	UsedPct int    `json:"usedPct"`
}

// Snapshot is the answer of GET /v1/services.
type Snapshot struct {
	Time     string  `json:"time"`
	Services []State `json:"services"`
	Host     Host    `json:"host"`
}

// Runner is the Docker access (replaced in tests).
type Runner interface {
	Inspect(ctx context.Context, container string) (State, error)
	Do(ctx context.Context, container, action string) error
}

var actions = map[string]bool{"start": true, "stop": true, "restart": true}

var (
	nameRe      = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
	containerRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
)

// ValidAction reports whether action is one of start, stop, restart.
func ValidAction(a string) bool { return actions[a] }

// ---- agent

// Agent serves the control API.
type Agent struct {
	Services []Service
	Runner   Runner
	DiskPath []string
	Log      func(format string, a ...any)
	mu       sync.Mutex // one action at a time: a restart must not race a stop
	mux      *http.ServeMux
}

// NewAgent validates the service list and builds the handler.
func NewAgent(svcs []Service, r Runner, disks []string) (*Agent, error) {
	if len(svcs) == 0 {
		return nil, errors.New("at least one service is required")
	}
	seen := map[string]bool{}
	for _, s := range svcs {
		if !nameRe.MatchString(s.Name) || !containerRe.MatchString(s.Container) || seen[s.Name] {
			return nil, fmt.Errorf("invalid or duplicate service %q", s.Name)
		}
		seen[s.Name] = true
	}
	a := &Agent{Services: svcs, Runner: r, DiskPath: disks, mux: http.NewServeMux(), Log: func(string, ...any) {}}
	a.mux.HandleFunc("GET /v1/services", a.list)
	a.mux.HandleFunc("POST /v1/services/{name}/{action}", a.act)
	return a, nil
}

func (a *Agent) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	r.Body = http.MaxBytesReader(w, r.Body, 1<<10)
	a.mux.ServeHTTP(w, r)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func (a *Agent) state(ctx context.Context, s Service) State {
	st, err := a.Runner.Inspect(ctx, s.Container)
	if err != nil {
		st = State{Status: "unknown"}
	}
	st.Name, st.Container = s.Name, s.Container
	return st
}

func (a *Agent) list(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	snap := Snapshot{Time: time.Now().UTC().Format(time.RFC3339), Host: hostInfo(a.DiskPath)}
	for _, s := range a.Services {
		snap.Services = append(snap.Services, a.state(ctx, s))
	}
	writeJSON(w, 200, snap)
}

func (a *Agent) act(w http.ResponseWriter, r *http.Request) {
	name, action := r.PathValue("name"), r.PathValue("action")
	var svc *Service
	for i := range a.Services {
		if a.Services[i].Name == name {
			svc = &a.Services[i]
		}
	}
	if svc == nil || !actions[action] {
		writeJSON(w, 404, map[string]string{"error": "unknown service or action"})
		return
	}
	if !a.mu.TryLock() {
		writeJSON(w, 409, map[string]string{"error": "another action is running"})
		return
	}
	defer a.mu.Unlock()
	// the action must finish even if the caller (possibly the console being restarted) goes away
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	a.Log("%s %s (container %s)", action, name, svc.Container)
	err := a.Runner.Do(ctx, svc.Container, action)
	st := a.state(ctx, *svc)
	if err != nil {
		a.Log("%s %s failed: %v", action, name, err)
		writeJSON(w, 502, map[string]any{"error": "the action failed: " + short(err.Error()), "state": st})
		return
	}
	writeJSON(w, 200, map[string]any{"result": "ok", "state": st})
}

func short(s string) string {
	if len(s) > 200 {
		return s[:200]
	}
	return s
}

// ListenUnix serves the agent on a Unix socket with the given mode (0660: owner and group may connect).
func ListenUnix(path string, mode os.FileMode, h http.Handler) (net.Listener, error) {
	_ = os.Remove(path) // stale socket of a previous run
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, mode); err != nil {
		_ = ln.Close()
		return nil, err
	}
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 120 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	return ln, nil
}

// ---- Docker runner

// DockerRunner drives the docker CLI with fixed arguments (no shell, container names are validated).
type DockerRunner struct{ Bin string }

func (d DockerRunner) bin() string {
	if d.Bin == "" {
		return "docker"
	}
	return d.Bin
}

type inspectDoc struct {
	State struct {
		Status    string
		Running   bool
		StartedAt string
		ExitCode  int
		Health    *struct{ Status string }
	}
	RestartCount int
	Config       struct{ Image string }
}

func (d DockerRunner) Inspect(ctx context.Context, c string) (State, error) {
	if !containerRe.MatchString(c) {
		return State{}, errors.New("bad container name")
	}
	out, err := exec.CommandContext(ctx, d.bin(), "inspect", "--type", "container", c).Output() // #nosec G204 -- fixed arguments, validated name
	if err != nil {
		return State{Status: "missing"}, nil
	}
	var docs []inspectDoc
	if json.Unmarshal(out, &docs) != nil || len(docs) != 1 {
		return State{Status: "unknown"}, nil
	}
	x := docs[0]
	st := State{Status: x.State.Status, Running: x.State.Running, RestartCount: x.RestartCount, ExitCode: x.State.ExitCode, Image: x.Config.Image, StartedAt: x.State.StartedAt}
	if x.State.Health != nil {
		st.Health = x.State.Health.Status
	}
	if t, err := time.Parse(time.RFC3339Nano, x.State.StartedAt); err == nil && x.State.Running {
		st.UptimeSeconds = int64(time.Since(t).Seconds())
	}
	return st, nil
}

func (d DockerRunner) Do(ctx context.Context, c, action string) error {
	if !containerRe.MatchString(c) || !actions[action] {
		return errors.New("bad request")
	}
	out, err := exec.CommandContext(ctx, d.bin(), action, c).CombinedOutput() // #nosec G204 -- fixed arguments, validated name
	if err != nil {
		return fmt.Errorf("docker %s: %v: %s", action, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// ParseServices reads "kms=pqc-kms-kms-1,console=pqc-kms-console-1".
func ParseServices(s string) ([]Service, error) {
	var out []Service
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		n, c, ok := strings.Cut(part, "=")
		if !ok || n == "" || c == "" {
			return nil, fmt.Errorf("service %q must look like name=container", part)
		}
		out = append(out, Service{Name: n, Container: c})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// ---- client (used by the console)

// Client talks to the agent.
type Client interface {
	Snapshot(ctx context.Context) (Snapshot, error)
	Do(ctx context.Context, name, action string) (State, error)
}

type unixClient struct{ h *http.Client }

// NewUnixClient connects to the agent socket.
func NewUnixClient(path string) Client {
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "unix", path)
	}}
	return &unixClient{h: &http.Client{Transport: tr, Timeout: 100 * time.Second}}
}

func (c *unixClient) Snapshot(ctx context.Context) (Snapshot, error) {
	var s Snapshot
	req, _ := http.NewRequestWithContext(ctx, "GET", "http://agent/v1/services", nil)
	resp, err := c.h.Do(req)
	if err != nil {
		return s, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return s, fmt.Errorf("agent answered HTTP %d", resp.StatusCode)
	}
	return s, json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&s)
}

func (c *unixClient) Do(ctx context.Context, name, action string) (State, error) {
	if !nameRe.MatchString(name) || !actions[action] {
		return State{}, errors.New("bad request")
	}
	req, _ := http.NewRequestWithContext(ctx, "POST", "http://agent/v1/services/"+name+"/"+action, nil)
	resp, err := c.h.Do(req)
	if err != nil {
		return State{}, err
	}
	defer resp.Body.Close()
	var out struct {
		Error string `json:"error"`
		State State  `json:"state"`
	}
	_ = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out)
	if resp.StatusCode != 200 {
		if out.Error == "" {
			out.Error = fmt.Sprintf("agent answered HTTP %d", resp.StatusCode)
		}
		return out.State, errors.New(out.Error)
	}
	return out.State, nil
}
