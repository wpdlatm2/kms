// Package selfcheck runs the periodic self test of the key server: does it still answer on its KMIP, REST and
// administration ports, can it still open and seal with its master key, are its files writable. Every run is
// written to the system log; a failure and the recovery after it also go to the audit record (OnChange).
package selfcheck

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/wpdlatm2/kms/internal/syslogx"
)

// Result is the outcome of one check.
type Result struct {
	Name      string `json:"name"`
	OK        bool   `json:"ok"`
	Detail    string `json:"detail,omitempty"`
	LatencyMS int64  `json:"latencyMs"`
	Error     string `json:"error,omitempty"`
}

// Report is one run.
type Report struct {
	Time       string   `json:"time"`
	OK         bool     `json:"ok"`
	DurationMS int64    `json:"durationMs"`
	Results    []Result `json:"results"`
}

// Check is one named test. It returns a short detail on success.
type Check struct {
	Name string
	Fn   func(ctx context.Context) (string, error)
}

// Runner runs the checks.
type Runner struct {
	Checks   []Check
	Interval time.Duration
	Timeout  time.Duration // per check
	Sys      *syslogx.Logger
	// OnChange is called when the overall result changes (first failure, recovery) with the report.
	OnChange func(r Report, previouslyOK bool)

	mu     sync.Mutex
	last   Report
	has    bool
	failed int
}

// Run executes all checks once, logs the result and returns it.
func (r *Runner) Run(ctx context.Context) Report {
	start := time.Now()
	to := r.Timeout
	if to == 0 {
		to = 10 * time.Second
	}
	rep := Report{Time: start.UTC().Format(time.RFC3339), OK: true}
	for _, c := range r.Checks {
		cctx, cancel := context.WithTimeout(ctx, to)
		t0 := time.Now()
		detail, err := safe(cctx, c)
		cancel()
		res := Result{Name: c.Name, OK: err == nil, Detail: detail, LatencyMS: time.Since(t0).Milliseconds()}
		if err != nil {
			res.Error = oneLine(err.Error())
			rep.OK = false
		}
		rep.Results = append(rep.Results, res)
	}
	rep.DurationMS = time.Since(start).Milliseconds()

	r.mu.Lock()
	prevOK := !r.has || r.last.OK
	hadPrev := r.has
	r.last, r.has = rep, true
	if rep.OK {
		r.failed = 0
	} else {
		r.failed++
	}
	failed := r.failed
	r.mu.Unlock()

	line := Summary(rep)
	switch {
	case !rep.OK:
		r.Sys.Errorf("selfcheck FAILED (%d in a row): %s", failed, line)
	case hadPrev && !prevOK:
		r.Sys.Noticef("selfcheck RECOVERED: %s", line)
	default:
		r.Sys.Infof("selfcheck ok: %s", line)
	}
	if r.OnChange != nil && (rep.OK != prevOK) {
		r.OnChange(rep, prevOK)
	}
	return rep
}

func safe(ctx context.Context, c Check) (detail string, err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("check panicked: %v", p)
		}
	}()
	return c.Fn(ctx)
}

func oneLine(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return s
}

// Summary renders a report as one line: name=ok(12ms) name=FAIL(reason).
func Summary(rep Report) string {
	parts := make([]string, 0, len(rep.Results))
	for _, x := range rep.Results {
		if x.OK {
			p := fmt.Sprintf("%s=ok(%dms", x.Name, x.LatencyMS)
			if x.Detail != "" {
				p += ", " + x.Detail
			}
			parts = append(parts, p+")")
		} else {
			parts = append(parts, fmt.Sprintf("%s=FAIL(%s)", x.Name, x.Error))
		}
	}
	return strings.Join(parts, " ")
}

// Last returns the latest report (zero before the first run).
func (r *Runner) Last() (Report, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.last, r.has
}

// Start runs once after the first delay and then every Interval until ctx ends.
func (r *Runner) Start(ctx context.Context, firstDelay time.Duration) {
	go func() {
		select {
		case <-ctx.Done():
			return
		case <-time.After(firstDelay):
		}
		for {
			r.Run(ctx)
			select {
			case <-ctx.Done():
				return
			case <-time.After(r.Interval):
			}
		}
	}()
}
