package restsrv

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/wpdlatm2/kms/internal/logs"
)

func TestAudit_QueryVerifyExportReview(t *testing.T) {
	r := newRig(t)
	root := r.caller(r.adminAddr, "root", "")
	root.must(201, "POST", "/admin/v1/groups", map[string]any{"name": "pay", "kind": "service", "owner": "hong"})
	root.must(200, "PUT", "/admin/v1/bindings", map[string]any{"client": "app", "group": "pay", "template": "owner", "approvalCode": "APR-9", "owner": "kim"})
	root.rawDo("PUT", "/admin/v1/bindings", mustJSON(map[string]any{"client": "app"}), "application/json") // refused

	// structured fields and filters
	var out struct {
		Count   int          `json:"count"`
		Entries []logs.Entry `json:"entries"`
	}
	json.Unmarshal(root.must(200, "GET", "/admin/v1/logs/admin?category=permission-change&outcome=success&q=APR-9", nil), &out)
	if out.Count == 0 {
		t.Fatal("filter found nothing")
	}
	for _, e := range out.Entries {
		if e.Category != "permission-change" || e.Outcome != "success" || e.Seq == 0 || e.Hash == "" || e.MAC == "" || e.RequestID == "" && e.Kind == "request" {
			t.Fatalf("entry %+v", e)
		}
	}
	json.Unmarshal(root.must(200, "GET", "/admin/v1/logs/admin?outcome=failure", nil), &out)
	if out.Count == 0 {
		t.Fatal("the refused grant is not recorded as a failure")
	}
	root.must(400, "GET", "/admin/v1/logs/admin?from=yesterday", nil)
	root.must(200, "GET", "/admin/v1/logs/admin?from=2020-01-01&to=2099-12-31", nil)

	// reading the log is itself logged
	if ev := adminEntries(r, "audit-view"); len(ev) == 0 || !strings.Contains(ev[0].Detail, "outcome=failure") && !strings.Contains(ev[0].Detail, "from=") {
		t.Fatalf("log reads not recorded: %+v", ev)
	}

	// verify
	var rep logs.Report
	json.Unmarshal(root.must(200, "GET", "/admin/v1/audit/verify?log=admin", nil), &rep)
	if !rep.OK || rep.Entries < 5 || !rep.MACChecked {
		t.Fatalf("%+v", rep)
	}
	root.must(404, "GET", "/admin/v1/audit/verify?log=nope", nil)

	// export: a zip whose data re-verifies on the recipient's side
	code, hdr, body := root.rawDo("GET", "/admin/v1/audit/export?log=admin&category=permission-change", nil, "")
	if code != 200 || hdr.Get("Content-Type") != "application/zip" || !strings.Contains(hdr.Get("Content-Disposition"), "audit-admin-") {
		t.Fatalf("%d %v", code, hdr)
	}
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil || len(zr.File) != 2 {
		t.Fatalf("zip: %v", err)
	}
	for _, f := range zr.File {
		rc, _ := f.Open()
		b, _ := io.ReadAll(rc)
		rc.Close()
		if f.Name == "manifest.json" {
			var m logs.Manifest
			json.Unmarshal(b, &m)
			if !m.ChainOK || m.ExportedBy != "root" || m.Entries == 0 || m.DataSHA256 == "" {
				t.Fatalf("manifest %+v", m)
			}
		}
	}
	if ev := adminEntries(r, "audit-export"); len(ev) != 1 || !strings.Contains(ev[0].Detail, "sha256=") {
		t.Fatalf("export not recorded: %+v", ev)
	}

	// periodic review record
	for _, bad := range []map[string]any{
		{"log": "admin", "from": "2026-11-01", "to": "2026-11-07", "finding": "maybe"},
		{"log": "admin", "from": "2026-11-01", "to": "2026-11-07", "finding": "anomaly"},
		{"log": "admin", "from": "", "to": "2026-11-07", "finding": "none"},
		{"log": "admin", "from": "2026-11-01", "to": "2026-11-07", "finding": "none", "note": "a\nb"},
		{"log": "admin", "from": "2026-11-01", "to": "2026-11-07", "finding": "none", "approvalCode": "bad code"},
	} {
		if code, _, _ := root.rawDo("POST", "/admin/v1/audit/reviews", mustJSON(bad), "application/json"); code != 400 {
			t.Fatalf("bad review accepted (%d): %v", code, bad)
		}
	}
	root.must(201, "POST", "/admin/v1/audit/reviews", map[string]any{"log": "admin", "from": "2026-11-01", "to": "2026-11-07", "finding": "none", "note": "weekly review, no anomalies", "approvalCode": "REV-2026-45"})
	var rv struct {
		Count   int          `json:"count"`
		Reviews []logs.Entry `json:"reviews"`
	}
	json.Unmarshal(root.must(200, "GET", "/admin/v1/audit/reviews", nil), &rv)
	if rv.Count != 1 || rv.Reviews[0].Who != "root" || rv.Reviews[0].Approval != "REV-2026-45" || !strings.Contains(rv.Reviews[0].Detail, "finding=none") {
		t.Fatalf("%+v", rv)
	}
}

func TestAudit_OnlyGlobalRolesAndTamperingShows(t *testing.T) {
	r := newRig(t)
	root := r.caller(r.adminAddr, "root", "")
	root.must(201, "POST", "/admin/v1/groups", map[string]any{"name": "pay", "kind": "service", "owner": "hong"})
	root.must(200, "PUT", "/admin/v1/managers", map[string]any{"identity": "svc-admin", "scope": "pay", "role": "admin", "approvalCode": "APR-1", "owner": "kim"})
	root.must(200, "PUT", "/admin/v1/managers", map[string]any{"identity": "ava", "scope": "ALL", "role": "audit", "approvalCode": "APR-2", "owner": "kim"})
	scoped := r.caller(r.adminAddr, "console", "svc-admin")
	for _, p := range []string{"/admin/v1/audit/verify?log=admin", "/admin/v1/audit/export?log=admin", "/admin/v1/audit/reviews", "/admin/v1/logs/admin"} {
		scoped.must(403, "GET", p, nil)
	}
	scoped.must(403, "POST", "/admin/v1/audit/reviews", map[string]any{"log": "admin", "from": "a", "to": "b", "finding": "none"})
	ava := r.caller(r.adminAddr, "console", "ava")
	ava.must(200, "GET", "/admin/v1/audit/verify?log=client", nil)
	ava.must(201, "POST", "/admin/v1/audit/reviews", map[string]any{"log": "client", "from": "2026-11-01", "to": "2026-11-07", "finding": "none"})

	// the denied attempts were recorded
	denied := 0
	for _, e := range r.adminLog.Last(2000) {
		if e.Kind == "request" && e.Who == "svc-admin" && e.Outcome == logs.OutcomeDenied {
			denied++
		}
	}
	if denied < 4 {
		t.Fatalf("only %d denied attempts recorded", denied)
	}
}
