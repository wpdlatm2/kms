package restsrv

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/wpdlatm2/kms/internal/logs"
)

func adminEntries(r *rig, op string) []logs.Entry {
	var out []logs.Entry
	for _, e := range r.adminLog.Last(2000) {
		if e.Kind == "event" && e.Op == op && e.Result == "ok" {
			out = append(out, e)
		}
	}
	return out
}

// Every permission grant carries the approval number (승인번호) and the person responsible (담당자).
func TestEvidence_GrantsNeedApprovalAndOwner(t *testing.T) {
	r := newRig(t)
	root := r.caller(r.adminAddr, "root", "")
	root.must(201, "POST", "/admin/v1/groups", map[string]any{"name": "pay", "kind": "service", "owner": "hong.gildong"})

	long := strings.Repeat("x", 65)
	bad := []map[string]any{
		{"client": "app", "group": "pay", "template": "owner"},                                                          // nothing
		{"client": "app", "group": "pay", "template": "owner", "owner": "kim"},                                          // no approval
		{"client": "app", "group": "pay", "template": "owner", "approvalCode": "APR-1"},                                 // no owner
		{"client": "app", "group": "pay", "template": "owner", "approvalCode": "APR-1", "owner": "   "},                 // blank owner
		{"client": "app", "group": "pay", "template": "owner", "approvalCode": "bad code!", "owner": "kim"},             // characters
		{"client": "app", "group": "pay", "template": "owner", "approvalCode": strings.Repeat("A", 65), "owner": "kim"}, // length
		{"client": "app", "group": "pay", "template": "owner", "approvalCode": "APR-1", "owner": long},
		{"client": "app", "group": "pay", "template": "owner", "approvalCode": "APR-1", "owner": "k\nim"},
		{"client": "app", "group": "pay", "template": "owner", "approvalCode": "../etc", "owner": "kim"},
		{"client": "app", "group": "pay", "template": "owner", "approvalCode": "-APR", "owner": "kim"},
	}
	for i, b := range bad {
		code, _, body := root.rawDo("PUT", "/admin/v1/bindings", mustJSON(b), "application/json")
		mustBeStructuredError(t, "binding case "+string(rune('0'+i)), code, body)
		if code != 400 {
			t.Fatalf("case %d: HTTP %d", i, code)
		}
	}
	// the refused attempts are evidence too: who tried to grant what, under which approval number
	failed := 0
	for _, e := range r.adminLog.Last(2000) {
		if e.Kind == "event" && e.Op == "binding-put" && strings.HasPrefix(e.Result, "error") {
			failed++
		}
	}
	if failed != len(bad) {
		t.Fatalf("%d refused grants, %d logged", len(bad), failed)
	}
	// the same for management grants
	for _, b := range []map[string]any{
		{"identity": "dora", "scope": "pay", "role": "admin"},
		{"identity": "dora", "scope": "pay", "role": "admin", "approvalCode": "APR-2"},
		{"identity": "dora", "scope": "pay", "role": "admin", "owner": "kim"},
	} {
		if code, _, _ := root.rawDo("PUT", "/admin/v1/managers", mustJSON(b), "application/json"); code != 400 {
			t.Fatalf("manager grant without evidence: HTTP %d", code)
		}
	}
	// nothing was granted by the rejected requests
	var bl struct {
		Bindings []BindingJSON `json:"bindings"`
	}
	json.Unmarshal(root.must(200, "GET", "/admin/v1/bindings", nil), &bl)
	if len(bl.Bindings) != 0 {
		t.Fatalf("rejected grants left %d bindings", len(bl.Bindings))
	}

	// a complete grant is stored with its evidence and who made it
	root.must(200, "PUT", "/admin/v1/bindings", map[string]any{"client": "app", "group": "pay", "template": "owner", "approvalCode": "APR-2026-0042", "owner": "kim.cheolsu"})
	json.Unmarshal(root.must(200, "GET", "/admin/v1/bindings", nil), &bl)
	b := bl.Bindings[0]
	if b.ApprovalCode != "APR-2026-0042" || b.Owner != "kim.cheolsu" || b.GrantedBy != "root" || b.GrantedAt == "" || b.MissingEvidence {
		t.Fatalf("binding evidence %+v", b)
	}
	// ... and appears in the administration log as structured fields, not only in free text
	ev := adminEntries(r, "binding-put")
	if len(ev) != 1 || ev[0].Approval != "APR-2026-0042" || ev[0].Owner != "kim.cheolsu" || ev[0].Who != "root" || ev[0].Target != "app" || !strings.Contains(ev[0].Detail, "pay -> owner") {
		t.Fatalf("audit event %+v", ev)
	}
	// replacing the grant records the new evidence and what it replaced
	root.must(200, "PUT", "/admin/v1/bindings", map[string]any{"client": "app", "group": "pay", "template": "guest", "approvalCode": "APR-2026-0099", "owner": "park.minsu"})
	json.Unmarshal(root.must(200, "GET", "/admin/v1/bindings", nil), &bl)
	if len(bl.Bindings) != 1 || bl.Bindings[0].ApprovalCode != "APR-2026-0099" || bl.Bindings[0].Owner != "park.minsu" || bl.Bindings[0].Template != "guest" {
		t.Fatalf("replaced binding %+v", bl.Bindings)
	}
	ev = adminEntries(r, "binding-put")
	last := ev[0] // newest first
	if last.Approval != "APR-2026-0099" || !strings.Contains(last.Detail, "pay: owner (approval APR-2026-0042, owner kim.cheolsu) -> guest") {
		t.Fatalf("the replacement does not record what it replaced: %+v", last)
	}

	// management grants
	root.must(200, "PUT", "/admin/v1/managers", map[string]any{"identity": "dora", "scope": "pay", "role": "audit", "approvalCode": "APR-2026-0100", "owner": "lee.younghee"})
	var ml struct {
		Managers []ManagerJSON `json:"managers"`
	}
	json.Unmarshal(root.must(200, "GET", "/admin/v1/managers", nil), &ml)
	found := false
	for _, m := range ml.Managers {
		if m.Identity == "dora" {
			found = true
			if m.ApprovalCode != "APR-2026-0100" || m.Owner != "lee.younghee" || m.GrantedBy != "root" || m.MissingEvidence {
				t.Fatalf("manager evidence %+v", m)
			}
		}
		if m.Root && m.MissingEvidence {
			t.Fatal("a root administrator is flagged as missing evidence")
		}
	}
	if !found {
		t.Fatal("manager not listed")
	}
	if ev := adminEntries(r, "manager-put"); len(ev) != 1 || ev[0].Approval != "APR-2026-0100" || ev[0].Owner != "lee.younghee" {
		t.Fatalf("manager audit event %+v", ev)
	}

	// removals may carry the approval too; it lands in the log
	root.must(200, "DELETE", "/admin/v1/managers?identity=dora&scope=pay&approvalCode=APR-2026-0101&owner=lee.younghee", nil)
	root.must(200, "DELETE", "/admin/v1/bindings?client=app&group=pay&approvalCode=APR-2026-0102", nil)
	if ev := adminEntries(r, "manager-delete"); len(ev) != 1 || ev[0].Approval != "APR-2026-0101" || !strings.Contains(ev[0].Detail, "APR-2026-0100") {
		t.Fatalf("manager removal event %+v", ev)
	}
	if ev := adminEntries(r, "binding-delete"); len(ev) != 1 || ev[0].Approval != "APR-2026-0102" || !strings.Contains(ev[0].Detail, "APR-2026-0099") {
		t.Fatalf("binding removal event %+v", ev)
	}
}

// Services and super groups name a person responsible; templates need the approval of every change.
func TestEvidence_GroupOwnerAndTemplateApproval(t *testing.T) {
	r := newRig(t)
	root := r.caller(r.adminAddr, "root", "")
	for _, b := range []map[string]any{
		{"name": "pay", "kind": "service"},
		{"name": "pay", "kind": "service", "owner": ""},
		{"name": "pay", "kind": "service", "owner": strings.Repeat("o", 65)},
		{"name": "div", "kind": "super"},
	} {
		if code, _, _ := root.rawDo("POST", "/admin/v1/groups", mustJSON(b), "application/json"); code != 400 {
			t.Fatalf("a group without a valid owner (담당자) gave HTTP %d: %v", code, b)
		}
	}
	root.must(201, "POST", "/admin/v1/groups", map[string]any{"name": "div", "kind": "super", "owner": "choi.jisoo"})
	root.must(201, "POST", "/admin/v1/groups", map[string]any{"name": "pay", "kind": "service", "parent": "div", "owner": "hong.gildong"})
	var gl struct {
		Groups []GroupJSON `json:"groups"`
	}
	json.Unmarshal(root.must(200, "GET", "/admin/v1/groups", nil), &gl)
	owners := map[string]string{}
	for _, g := range gl.Groups {
		owners[g.Name] = g.Owner
	}
	if owners["pay"] != "hong.gildong" || owners["div"] != "choi.jisoo" {
		t.Fatalf("owners %v", owners)
	}
	// the owner can be changed later (the change is logged with the new owner)
	root.must(200, "PUT", "/admin/v1/groups/pay", map[string]any{"description": "pay", "parent": "div", "owner": "lee.minho"})
	json.Unmarshal(root.must(200, "GET", "/admin/v1/groups", nil), &gl)
	for _, g := range gl.Groups {
		if g.Name == "pay" && g.Owner != "lee.minho" {
			t.Fatalf("owner after change %q", g.Owner)
		}
	}
	if ev := adminEntries(r, "group-put"); len(ev) != 3 || ev[0].Owner != "lee.minho" {
		t.Fatalf("group audit events %+v", ev)
	}

	// templates: approval required for create and edit
	for _, b := range []map[string]any{{"name": "t1", "operations": []string{"get"}}, {"name": "t1", "operations": []string{"get"}, "approvalCode": "no good"}} {
		if code, _, _ := root.rawDo("POST", "/admin/v1/templates", mustJSON(b), "application/json"); code != 400 {
			t.Fatalf("template without approval: %d", code)
		}
	}
	root.must(201, "POST", "/admin/v1/templates", map[string]any{"name": "t1", "operations": []string{"locate", "get"}, "approvalCode": "APR-T-1", "owner": "kim"})
	if code, _, _ := root.rawDo("PUT", "/admin/v1/templates/t1", mustJSON(map[string]any{"operations": []string{"locate"}}), "application/json"); code != 400 {
		t.Fatalf("template edit without approval: %d", code)
	}
	root.must(200, "PUT", "/admin/v1/templates/t1", map[string]any{"operations": []string{"locate"}, "approvalCode": "APR-T-2"})
	var tl struct {
		Templates []TemplateJSON `json:"templates"`
	}
	json.Unmarshal(root.must(200, "GET", "/admin/v1/templates", nil), &tl)
	for _, x := range tl.Templates {
		if x.Name == "t1" && (x.ApprovalCode != "APR-T-2" || x.ChangedBy != "root" || x.ChangedAt == "") {
			t.Fatalf("template evidence %+v", x)
		}
	}
	ev := adminEntries(r, "template-put")
	if len(ev) != 2 || ev[0].Approval != "APR-T-2" || !strings.Contains(ev[0].Detail, "before=locate,get") || !strings.Contains(ev[0].Detail, "APR-T-1") || !strings.Contains(ev[0].Detail, "after=locate") {
		t.Fatalf("template change event does not show before/after: %+v", ev)
	}
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}
