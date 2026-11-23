package admin

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/wpdlatm2/kms/internal/kms"
	"github.com/wpdlatm2/kms/internal/logs"
	"github.com/wpdlatm2/kms/internal/sysctl"
	"github.com/wpdlatm2/kms/internal/syslogx"
)

// AttachSyslog mirrors the console's audit events into the system log and reports, as they happen, when the
// key server or the control agent becomes unreachable and when they come back.
func (s *Server) AttachSyslog(sl *syslogx.Logger) {
	s.sysLog = sl
	s.log.AddSink(logs.SysSink(sl, "console"))
}

// transition writes a state change (up/down) of a dependency once, not at every dashboard refresh.
func (s *Server) transition(name string, up bool, why string) {
	if s.sysLog == nil {
		return
	}
	s.tr.Lock()
	defer s.tr.Unlock()
	if s.trState == nil {
		s.trState = map[string]bool{}
	}
	prev, seen := s.trState[name]
	s.trState[name] = up
	switch {
	case !up && (!seen || prev):
		s.sysLog.Errorf("%s is not reachable: %s", name, why)
	case up && seen && !prev:
		s.sysLog.Noticef("%s is reachable again", name)
	}
}

// Probe is a TCP/TLS endpoint of the key server the dashboard checks (KMIP, client REST, administration API).
type Probe struct{ Name, Addr string }

type probeResult struct {
	Name      string `json:"name"`
	Addr      string `json:"addr"`
	Up        bool   `json:"up"`
	LatencyMS int64  `json:"latencyMs"`
	Error     string `json:"error,omitempty"`
	CertCN    string `json:"certCn,omitempty"`
	CertEnds  string `json:"certExpires,omitempty"`
	CertDays  int    `json:"certDays"`
}

type auditState struct {
	Log       string `json:"log"`
	OK        bool   `json:"ok"`
	Entries   int    `json:"entries"`
	LastSeq   uint64 `json:"lastSeq"`
	Problem   string `json:"problem,omitempty"`
	Where     string `json:"where,omitempty"`
	CheckedAt string `json:"checkedAt"`
}

type finding struct {
	Level string `json:"level"` // warn | critical
	Text  string `json:"text"`
}

// system caches the (costly) audit chain verification between dashboard refreshes.
type sysCache struct {
	mu    sync.Mutex
	audit []auditState
	at    time.Time
}

const auditCacheTTL = 3 * time.Minute

func (s *Server) probes(ctx context.Context) []probeResult {
	var base *tls.Config
	if tr, ok := s.Backend.Client.Transport.(*http.Transport); ok && tr.TLSClientConfig != nil {
		base = tr.TLSClientConfig
	}
	out := make([]probeResult, len(s.opts.Probes))
	var wg sync.WaitGroup
	for i, p := range s.opts.Probes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := probeResult{Name: p.Name, Addr: p.Addr}
			if base == nil {
				r.Error = "no TLS configuration"
				out[i] = r
				return
			}
			t0 := time.Now()
			d := &tls.Dialer{NetDialer: &net.Dialer{Timeout: 4 * time.Second}, Config: base.Clone()}
			c, err := d.DialContext(ctx, "tcp", p.Addr)
			if err != nil {
				r.Error = shortErr(err)
				out[i] = r
				return
			}
			defer c.Close()
			r.Up, r.LatencyMS = true, time.Since(t0).Milliseconds()
			if st := c.(*tls.Conn).ConnectionState(); len(st.PeerCertificates) > 0 {
				cert := st.PeerCertificates[0]
				r.CertCN, r.CertEnds = cert.Subject.CommonName, cert.NotAfter.UTC().Format(time.RFC3339)
				r.CertDays = int(time.Until(cert.NotAfter).Hours() / 24)
			}
			out[i] = r
		}()
	}
	wg.Wait()
	return out
}

func shortErr(err error) string {
	m := strings.Join(strings.Fields(err.Error()), " ")
	if len(m) > 160 {
		m = m[:160]
	}
	return m
}

func (s *Server) auditStates(ss *session, force bool) []auditState {
	s.sys.mu.Lock()
	defer s.sys.mu.Unlock()
	if !force && time.Since(s.sys.at) < auditCacheTTL && s.sys.audit != nil {
		return s.sys.audit
	}
	var out []auditState
	for _, name := range []string{"client", "admin"} {
		st := auditState{Log: name, CheckedAt: time.Now().UTC().Format(time.RFC3339)}
		code, _, raw, err := s.Backend.call("GET", "audit/verify", "log="+name, ss.User, "", nil)
		var rep struct {
			OK      bool   `json:"ok"`
			Entries int    `json:"entries"`
			LastSeq uint64 `json:"lastSeq"`
			Problem string `json:"problem"`
			Where   string `json:"where"`
		}
		if err != nil || code != 200 || json.Unmarshal(raw, &rep) != nil {
			st.Problem = "verification not available"
		} else {
			st.OK, st.Entries, st.LastSeq, st.Problem, st.Where = rep.OK, rep.Entries, rep.LastSeq, rep.Problem, rep.Where
		}
		out = append(out, st)
	}
	st := auditState{Log: "console", CheckedAt: time.Now().UTC().Format(time.RFC3339)}
	if rep, err := s.log.Verify(s.opts.AuditKey); err != nil {
		st.Problem = "verification not available"
	} else {
		st.OK, st.Entries, st.LastSeq, st.Problem, st.Where = rep.OK, rep.Entries, rep.LastSeq, rep.Problem, rep.Where
	}
	out = append(out, st)
	s.sys.audit, s.sys.at = out, time.Now()
	return out
}

// roles reads what the backend says about the user: a global role of any kind, and the global admin role.
func (s *Server) roles(ss *session) (global, admin bool) {
	code, _, raw, err := s.Backend.call("GET", "me", "", ss.User, "", nil)
	var me struct {
		Global bool        `json:"global"`
		Scopes []kms.Scope `json:"scopes"`
	}
	if err != nil || code != 200 || json.Unmarshal(raw, &me) != nil {
		return false, false
	}
	for _, sc := range me.Scopes {
		if sc.Group == kms.GroupAll && sc.Role == kms.RoleAdmin {
			admin = true
		}
	}
	return me.Global, admin
}

// system answers the dashboard: key server, ports, certificates, audit integrity, services and host.
func (s *Server) system(w http.ResponseWriter, r *http.Request, ss *session) {
	global, admin := s.roles(ss)
	if !global {
		fail(w, http.StatusForbidden, "the dashboard is available to global administrators and auditors only")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
	defer cancel()
	finds := []finding{}
	add := func(level, text string) { finds = append(finds, finding{level, text}) }

	rep := map[string]any{"time": time.Now().UTC().Format(time.RFC3339), "canControl": admin && s.opts.Agent != nil}

	// key server
	be := map[string]any{"reachable": false}
	if code, _, raw, err := s.Backend.call("GET", "status", "", ss.User, "", nil); err != nil {
		be["error"] = shortErr(err)
		add("critical", "키 서버(관리 API)에 연결할 수 없습니다")
	} else if code != 200 {
		be["error"] = "HTTP " + itoa(code)
		add("critical", "키 서버가 비정상 응답을 반환했습니다 (HTTP "+itoa(code)+")")
	} else {
		var st map[string]any
		_ = json.Unmarshal(raw, &st)
		be["reachable"], be["status"] = true, st
	}
	rep["backend"] = be
	if be["reachable"] == true {
		s.transition("key server administration API", true, "")
	} else {
		e, _ := be["error"].(string)
		s.transition("key server administration API", false, e)
	}

	if be["reachable"] == true {
		if sc, ok := be["status"].(map[string]any)["selfcheck"].(map[string]any); ok && sc["enabled"] == true {
			rep["selfcheck"] = sc
			if r, ok := sc["report"].(map[string]any); ok {
				if r["ok"] == false {
					add("critical", "키 서버 자가점검 실패: "+selfFailures(r))
				} else if sc["ran"] == true {
					if t, err := time.Parse(time.RFC3339, str(r["time"])); err == nil {
						if iv, _ := sc["intervalSeconds"].(float64); iv > 0 && time.Since(t) > time.Duration(3*iv)*time.Second {
							add("warn", "키 서버 자가점검이 "+itoa(int(time.Since(t).Minutes()))+"분째 실행되지 않았습니다")
						}
					}
				}
			}
		}
	}

	// ports and certificates
	pr := s.probes(ctx)
	for _, p := range pr {
		switch {
		case !p.Up:
			add("critical", p.Name+" 포트("+p.Addr+") 응답 없음")
		case p.CertDays < 7:
			add("critical", p.Name+" 서버 인증서가 "+itoa(p.CertDays)+"일 후 만료됩니다")
		case p.CertDays < 30:
			add("warn", p.Name+" 서버 인증서가 "+itoa(p.CertDays)+"일 후 만료됩니다")
		}
	}
	rep["probes"] = pr

	// audit integrity
	if be["reachable"] == true {
		au := s.auditStates(ss, r.URL.Query().Get("refresh") == "1")
		for _, a := range au {
			if !a.OK {
				add("critical", a.Log+" 감사로그 무결성 이상: "+a.Problem+" "+a.Where)
			}
		}
		rep["audit"] = au
	} else {
		rep["audit"] = []auditState{}
	}

	// services and host through the agent
	ag := map[string]any{"configured": s.opts.Agent != nil}
	if s.opts.Agent != nil {
		snap, err := s.opts.Agent.Snapshot(ctx)
		if err != nil {
			ag["error"] = shortErr(err)
			s.transition("service control agent", false, shortErr(err))
			add("warn", "서비스 제어 에이전트에 연결할 수 없어 컨테이너 상태를 알 수 없습니다")
		} else {
			ag["connected"], ag["services"], ag["host"] = true, snap.Services, snap.Host
			s.transition("service control agent", true, "")
			for _, sv := range snap.Services {
				switch {
				case !sv.Running:
					add("critical", "서비스 "+sv.Name+" 가 실행 중이 아닙니다 ("+sv.Status+")")
				case sv.Health == "unhealthy":
					add("critical", "서비스 "+sv.Name+" 의 상태 점검 실패(unhealthy)")
				case sv.RestartCount >= 5:
					add("warn", "서비스 "+sv.Name+" 가 "+itoa(sv.RestartCount)+"회 재시작되었습니다")
				}
			}
			for _, d := range snap.Host.Disks {
				if d.UsedPct >= 90 {
					add("critical", "디스크 "+d.Path+" 사용률 "+itoa(d.UsedPct)+"%")
				} else if d.UsedPct >= 80 {
					add("warn", "디스크 "+d.Path+" 사용률 "+itoa(d.UsedPct)+"%")
				}
			}
			if h := snap.Host; h.MemTotalMB > 0 && h.MemAvailMB*10 < h.MemTotalMB {
				add("warn", "호스트 가용 메모리가 10% 미만입니다")
			}
		}
	}
	rep["agent"] = ag

	since := time.Now().Add(-24 * time.Hour)
	okL, _ := s.log.Query(logs.Filter{Op: "login", Outcome: logs.OutcomeSuccess, From: since, Limit: 20000})
	failL, _ := s.log.Query(logs.Filter{Op: "login-failed", From: since, Limit: 20000})
	lockedN := 0
	for _, a := range s.Users.Accounts(s.settings.Get(), time.Now()) {
		if a.Locked {
			lockedN++
		}
	}
	if lockedN > 0 {
		add("warn", "잠긴 콘솔 계정이 "+itoa(lockedN)+"개 있습니다")
	}
	if len(failL) >= 20 {
		add("warn", "최근 24시간 로그인 실패 "+itoa(len(failL))+"건")
	}
	rep["logins"] = map[string]any{"success24h": len(okL), "failed24h": len(failL), "lockedAccounts": lockedN}
	level := "ok"
	for _, f := range finds {
		if f.Level == "critical" {
			level = "critical"
		} else if level == "ok" {
			level = "warn"
		}
	}
	rep["overall"] = map[string]any{"level": level, "findings": finds}
	rep["console"] = map[string]any{"startedAt": s.started.UTC().Format(time.RFC3339), "uptimeSeconds": int64(time.Since(s.started).Seconds()),
		"otpPolicy": s.opts.OTP, "sessions": s.sess.count(), "users": s.Users.Count(), "goVersion": runtime.Version()}
	writeJSON(w, 200, rep)
}

type controlReq struct {
	ApprovalCode string `json:"approvalCode"`
	Owner        string `json:"owner"`
	Confirm      string `json:"confirm"`
}

// control starts, stops or restarts a service. It needs the global administrator role, the approval number and
// the person responsible (as every change of this system), and the service name typed as confirmation.
func (s *Server) control(w http.ResponseWriter, r *http.Request, ss *session) {
	name, action := r.PathValue("name"), r.PathValue("action")
	ip := clientIP(r)
	if s.opts.Agent == nil {
		fail(w, http.StatusServiceUnavailable, "the service control agent is not configured")
		return
	}
	if !sysctl.ValidAction(action) {
		fail(w, http.StatusNotFound, "unknown action")
		return
	}
	var in controlReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&in); err != nil {
		fail(w, http.StatusBadRequest, "bad request")
		return
	}
	in.ApprovalCode, in.Owner = strings.TrimSpace(in.ApprovalCode), strings.TrimSpace(in.Owner)
	entry := logs.Entry{Plane: "console", Kind: "event", Who: ss.User, Target: name, Op: "service-" + action, Category: "system", Remote: ip, Approval: in.ApprovalCode, Owner: in.Owner}
	if _, admin := s.roles(ss); !admin {
		entry.Result = "denied: global administrator role required"
		s.log.Add(entry)
		fail(w, http.StatusForbidden, "starting, stopping and restarting services needs the global administrator role")
		return
	}
	if !kms.ValidApproval(in.ApprovalCode) || !kms.ValidOwner(in.Owner) {
		entry.Result = "error: approval number and responsible person are required"
		s.log.Add(entry)
		fail(w, http.StatusBadRequest, "approval number (승인번호) and owner (담당자) are required")
		return
	}
	if in.Confirm != name {
		fail(w, http.StatusBadRequest, "type the service name to confirm")
		return
	}
	entry.Result = "requested"
	s.log.Add(entry)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()
	st, err := s.opts.Agent.Do(ctx, name, action)
	if err != nil {
		entry.Result = "error: " + shortErr(err)
		s.log.Add(entry)
		fail(w, http.StatusBadGateway, shortErr(err))
		return
	}
	entry.Result = "ok"
	entry.Detail = "state: " + st.Status
	s.log.Add(entry)
	s.sys.mu.Lock()
	s.sys.at = time.Time{} // force a fresh audit check after a restart
	s.sys.mu.Unlock()
	writeJSON(w, 200, map[string]any{"result": "ok", "state": st})
}

func str(v any) string { s, _ := v.(string); return s }

func selfFailures(r map[string]any) string {
	var out []string
	if rs, ok := r["results"].([]any); ok {
		for _, x := range rs {
			if m, ok := x.(map[string]any); ok && m["ok"] == false {
				out = append(out, str(m["name"])+" ("+str(m["error"])+")")
			}
		}
	}
	return strings.Join(out, ", ")
}
