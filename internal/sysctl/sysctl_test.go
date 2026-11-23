package sysctl

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type fake struct {
	mu    sync.Mutex
	state map[string]string
	calls []string
	fail  bool
	block chan struct{}
}

func (f *fake) Inspect(_ context.Context, c string) (State, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := f.state[c]
	if s == "" {
		return State{Status: "missing"}, nil
	}
	return State{Status: s, Running: s == "running", UptimeSeconds: 42}, nil
}

func (f *fake) Do(_ context.Context, c, a string) error {
	if f.block != nil {
		<-f.block
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, a+" "+c)
	if f.fail {
		return errors.New("boom")
	}
	switch a {
	case "stop":
		f.state[c] = "exited"
	default:
		f.state[c] = "running"
	}
	return nil
}

func rig(t *testing.T) (*httptest.Server, *fake) {
	f := &fake{state: map[string]string{"c-kms": "running", "c-console": "running"}}
	a, err := NewAgent([]Service{{"kms", "c-kms"}, {"console", "c-console"}}, f, nil)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(a)
	t.Cleanup(ts.Close)
	return ts, f
}

func do(t *testing.T, method, url string) (int, string) {
	req, _ := http.NewRequest(method, url, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestListAndActions(t *testing.T) {
	ts, f := rig(t)
	code, body := do(t, "GET", ts.URL+"/v1/services")
	var s Snapshot
	json.Unmarshal([]byte(body), &s)
	if code != 200 || len(s.Services) != 2 || s.Services[0].Name != "kms" || !s.Services[0].Running {
		t.Fatalf("%d %s", code, body)
	}
	if code, _ := do(t, "POST", ts.URL+"/v1/services/kms/stop"); code != 200 || f.state["c-kms"] != "exited" {
		t.Fatalf("stop: %d %v", code, f.state)
	}
	if code, _ := do(t, "POST", ts.URL+"/v1/services/kms/start"); code != 200 || f.state["c-kms"] != "running" {
		t.Fatal("start")
	}
	if code, _ := do(t, "POST", ts.URL+"/v1/services/console/restart"); code != 200 {
		t.Fatal("restart")
	}
	if strings.Join(f.calls, ",") != "stop c-kms,start c-kms,restart c-console" {
		t.Fatalf("%v", f.calls)
	}
}

func TestOnlyTheConfiguredServicesAndActions(t *testing.T) {
	ts, f := rig(t)
	for _, p := range []string{"/v1/services/c-kms/stop", "/v1/services/other/stop", "/v1/services/kms/rm", "/v1/services/kms/kill", "/v1/services/kms/exec",
		"/v1/services/..%2Fkms/stop", "/v1/services/kms%20x/stop", "/v1/services/KMS/stop", "/v1/services/kms/"} {
		if code, _ := do(t, "POST", ts.URL+p); code != 404 && code != 400 && code != 301 && code != 307 {
			t.Errorf("%s: HTTP %d", p, code)
		}
	}
	if code, _ := do(t, "GET", ts.URL+"/v1/services/kms/stop"); code == 200 {
		t.Error("an action by GET")
	}
	if code, _ := do(t, "DELETE", ts.URL+"/v1/services/kms/stop"); code == 200 {
		t.Error("an action by DELETE")
	}
	if len(f.calls) != 0 {
		t.Fatalf("unexpected docker calls: %v", f.calls)
	}
}

func TestFailureIsReportedAndOneActionAtATime(t *testing.T) {
	ts, f := rig(t)
	f.fail = true
	code, body := do(t, "POST", ts.URL+"/v1/services/kms/restart")
	if code != 502 || !strings.Contains(body, "the action failed") {
		t.Fatalf("%d %s", code, body)
	}
	f.fail = false
	f.block = make(chan struct{})
	done := make(chan int)
	go func() { c, _ := do(t, "POST", ts.URL+"/v1/services/kms/restart"); done <- c }()
	time.Sleep(100 * time.Millisecond)
	if code, _ := do(t, "POST", ts.URL+"/v1/services/console/restart"); code != 409 {
		t.Fatalf("concurrent action: HTTP %d", code)
	}
	close(f.block)
	if c := <-done; c != 200 {
		t.Fatalf("first action: %d", c)
	}
}

func TestAgentValidation(t *testing.T) {
	f := &fake{}
	for _, svcs := range [][]Service{nil, {{"KMS", "c"}}, {{"kms", "c;rm -rf /"}}, {{"kms", "-v"}}, {{"kms", "a"}, {"kms", "b"}}, {{"kms", ""}}} {
		if _, err := NewAgent(svcs, f, nil); err == nil {
			t.Errorf("accepted %v", svcs)
		}
	}
	if _, err := ParseServices("kms"); err == nil {
		t.Error("parse without container")
	}
	s, err := ParseServices("b=two, a=one")
	if err != nil || len(s) != 2 || s[0].Name != "a" {
		t.Fatalf("%v %v", s, err)
	}
}

func TestDockerRunnerRejectsBadNames(t *testing.T) {
	d := DockerRunner{Bin: "definitely-not-docker"}
	if err := d.Do(context.Background(), "ok", "rm"); err == nil {
		t.Error("action rm accepted")
	}
	if err := d.Do(context.Background(), "--privileged", "stop"); err == nil {
		t.Error("option-like container accepted")
	}
	if _, err := d.Inspect(context.Background(), "a b"); err == nil {
		t.Error("bad name inspected")
	}
}
