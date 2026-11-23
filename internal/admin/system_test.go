package admin

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/wpdlatm2/kms/internal/logs"
	"github.com/wpdlatm2/kms/internal/sysctl"
)

type fakeAgent struct {
	states map[string]sysctl.State
	calls  []string
	fail   bool
	down   bool
}

func (f *fakeAgent) Snapshot(context.Context) (sysctl.Snapshot, error) {
	if f.down {
		return sysctl.Snapshot{}, errors.New("socket missing")
	}
	s := sysctl.Snapshot{Host: sysctl.Host{Disks: []sysctl.DiskUse{{Path: "/data", TotalGB: 100, FreeGB: 50, UsedPct: 50}}}}
	for _, n := range []string{"console", "kms"} {
		s.Services = append(s.Services, f.states[n])
	}
	return s, nil
}

func (f *fakeAgent) Do(_ context.Context, name, action string) (sysctl.State, error) {
	f.calls = append(f.calls, action+" "+name)
	if f.fail {
		return sysctl.State{}, errors.New("docker said no")
	}
	st := f.states[name]
	st.Running, st.Status = action != "stop", map[bool]string{true: "running", false: "exited"}[action != "stop"]
	f.states[name] = st
	return st, nil
}

func newFake() *fakeAgent {
	return &fakeAgent{states: map[string]sysctl.State{
		"kms":     {Name: "kms", Status: "running", Running: true, Health: "healthy"},
		"console": {Name: "console", Status: "running", Running: true},
	}}
}

type dash struct {
	Overall struct {
		Level    string `json:"level"`
		Findings []struct{ Level, Text string }
	} `json:"overall"`
	CanControl bool `json:"canControl"`
	Backend    struct {
		Reachable bool           `json:"reachable"`
		Status    map[string]any `json:"status"`
	} `json:"backend"`
	Audit []auditState `json:"audit"`
	Agent struct {
		Connected bool           `json:"connected"`
		Services  []sysctl.State `json:"services"`
	} `json:"agent"`
}

func TestDashboardReportsHealthAndFindings(t *testing.T) {
	ag := newFake()
	s := newStackOpts(t, map[string]string{"root": pw, "ava": pw, "nobody": pw}, Options{OTP: "off", Agent: ag})
	root := s.web()
	root.login("root", pw)
	var d dash
	raw := root.must(200, "GET", "/api/system", nil)
	if strings.Contains(string(raw), ": null") { // the page reads .length of lists: they must be [] never null
		t.Fatalf("null in the dashboard answer: %s", raw)
	}
	json.Unmarshal(raw, &d)
	if d.Overall.Level != "ok" || !d.CanControl || !d.Backend.Reachable || !d.Agent.Connected || len(d.Agent.Services) != 2 {
		t.Fatalf("%+v", d)
	}
	if len(d.Audit) != 3 {
		t.Fatalf("audit states: %+v", d.Audit)
	}
	// a service that is down and an unreachable agent are findings
	ag.states["kms"] = sysctl.State{Name: "kms", Status: "exited"}
	json.Unmarshal(root.must(200, "GET", "/api/system", nil), &d)
	if d.Overall.Level != "critical" || !strings.Contains(d.Overall.Findings[0].Text, "kms") {
		t.Fatalf("%+v", d.Overall)
	}
	ag.down = true
	json.Unmarshal(root.must(200, "GET", "/api/system", nil), &d)
	found := false
	for _, f := range d.Overall.Findings {
		found = found || strings.Contains(f.Text, "에이전트")
	}
	if !found {
		t.Fatalf("agent outage not reported: %+v", d.Overall)
	}
	// who may look: global roles only
	s.web().must(401, "GET", "/api/system", nil)
	nb := s.web()
	nb.login("nobody", pw)
	nb.must(403, "GET", "/api/system", nil)
}

func TestServiceControlNeedsAdminEvidenceAndConfirmation(t *testing.T) {
	ag := newFake()
	s := newStackOpts(t, map[string]string{"root": pw, "ava": pw}, Options{OTP: "off", Agent: ag})
	root := s.web()
	root.login("root", pw)
	root.must(200, "PUT", "/api/managers", map[string]any{"identity": "ava", "scope": "ALL", "role": "audit", "approvalCode": "APR-1", "owner": "kim"})
	good := map[string]any{"approvalCode": "CHG-2026-77", "owner": "kim", "confirm": "kms"}

	// an auditor sees the dashboard but cannot control
	ava := s.web()
	ava.login("ava", pw)
	var d dash
	json.Unmarshal(ava.must(200, "GET", "/api/system", nil), &d)
	if d.CanControl {
		t.Fatal("an auditor is offered the controls")
	}
	ava.must(403, "POST", "/api/system/services/kms/restart", good)
	if len(ag.calls) != 0 {
		t.Fatal("the agent was called for an auditor")
	}

	root.must(400, "POST", "/api/system/services/kms/restart", map[string]any{"owner": "kim", "confirm": "kms"})                            // no approval
	root.must(400, "POST", "/api/system/services/kms/restart", map[string]any{"approvalCode": "CHG-1", "confirm": "kms"})                   // no owner
	root.must(400, "POST", "/api/system/services/kms/restart", map[string]any{"approvalCode": "CHG-1", "owner": "kim", "confirm": "other"}) // wrong confirmation
	root.must(404, "POST", "/api/system/services/kms/kill", good)
	root.must(404, "POST", "/api/system/services/kms/rm", good)
	if len(ag.calls) != 0 {
		t.Fatalf("calls before a valid request: %v", ag.calls)
	}

	root.must(200, "POST", "/api/system/services/kms/restart", good)
	root.must(200, "POST", "/api/system/services/kms/stop", good)
	root.must(200, "POST", "/api/system/services/kms/start", good)
	if strings.Join(ag.calls, ",") != "restart kms,stop kms,start kms" {
		t.Fatalf("%v", ag.calls)
	}
	ag.fail = true
	root.must(502, "POST", "/api/system/services/kms/restart", good)

	// everything is on the record: request, result, who, evidence
	var ok, bad, denied int
	for _, e := range s.srv.log.Last(500) {
		if e.Op == "service-restart" || e.Op == "service-stop" || e.Op == "service-start" {
			if e.Approval == "" && e.Outcome != logs.OutcomeDenied {
				continue
			}
			switch {
			case e.Outcome == logs.OutcomeDenied:
				denied++
			case e.Result == "ok":
				ok++
				if e.Approval != "CHG-2026-77" || e.Owner != "kim" || e.Who != "root" || e.Target != "kms" || e.Category != "system" {
					t.Fatalf("%+v", e)
				}
			case strings.HasPrefix(e.Result, "error"):
				bad++
			}
		}
	}
	if ok != 3 || bad < 1 || denied != 1 {
		t.Fatalf("ok=%d failed=%d denied=%d", ok, bad, denied)
	}
}

func TestControlWithoutAgentIsRefused(t *testing.T) {
	s := newStack(t, map[string]string{"root": pw})
	root := s.web()
	root.login("root", pw)
	root.must(503, "POST", "/api/system/services/kms/restart", map[string]any{"approvalCode": "A", "owner": "o", "confirm": "kms"})
	var d dash
	json.Unmarshal(root.must(200, "GET", "/api/system", nil), &d)
	if d.CanControl {
		t.Fatal("controls offered without an agent")
	}
}
