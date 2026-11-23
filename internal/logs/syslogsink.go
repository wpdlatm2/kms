package logs

import (
	"strconv"
	"strings"

	"github.com/wpdlatm2/kms/internal/syslogx"
)

// SysSink mirrors the management-relevant audit entries into the system log. The audit file stays the record
// of truth; the system log is where operators and the host's monitoring look first.
//
//   - events that changed something or were refused are written at notice / warning level;
//   - ordinary successful requests are not repeated there (they would drown everything else);
//   - client-plane successes are left out entirely (key reads are audit evidence, not operations news).
func SysSink(sys *syslogx.Logger, name string) func(Entry) {
	return func(e Entry) {
		if e.Kind == "request" && e.Outcome == OutcomeSuccess {
			return
		}
		if e.Plane == "client" && e.Outcome == OutcomeSuccess {
			return
		}
		lv := syslogx.Info
		switch {
		case e.Outcome == OutcomeDenied || e.Outcome == OutcomeFailure:
			lv = syslogx.Warning
		case e.Category == "permission-change" || e.Category == "system" || e.Category == "key-lifecycle" || e.Category == "audit-maintenance" ||
			strings.HasPrefix(e.Op, "account-") || strings.HasPrefix(e.Op, "password-") || strings.HasPrefix(e.Op, "user-") || strings.HasPrefix(e.Op, "service-"):
			lv = syslogx.Notice
		}
		var b strings.Builder
		b.WriteString(name + " audit: op=" + e.Op + " outcome=" + e.Outcome + " who=" + strconv.Quote(e.Who))
		if e.Target != "" {
			b.WriteString(" target=" + strconv.Quote(short(e.Target, 80)))
		}
		if e.Approval != "" {
			b.WriteString(" approval=" + strconv.Quote(e.Approval) + " owner=" + strconv.Quote(e.Owner))
		}
		if e.Remote != "" {
			b.WriteString(" from=" + e.Remote)
		}
		if e.Outcome != OutcomeSuccess && e.Result != "" {
			b.WriteString(" result=" + strconv.Quote(short(e.Result, 160)))
		}
		sys.Logf(lv, "%s seq=%d", b.String(), e.Seq)
	}
}

func short(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
