"use strict";
(function () {
  const $ = (s, r = document) => r.querySelector(s);
  const STATES = ["pre-active", "active", "deactivated", "compromised", "destroyed", "destroyed-compromised"];
  const STATE_LABEL = { "pre-active": "Pre-Active", active: "Active", deactivated: "Deactivated", compromised: "Compromised", destroyed: "Destroyed", "destroyed-compromised": "Destroyed Compromised" };
  const TYPE_LABEL = { symmetric: "Symmetric Key", private: "Private Key", public: "Public Key", secret: "Secret Data" };
  const ACTION_LABEL = { activate: "활성화", deactivate: "비활성화", rekey: "키 회전", compromise: "침해 표시", destroy: "파기" };
  const OP_LABEL = {
    create: ["생성", "새 키를 만든다"], locate: ["검색", "키 목록을 찾는다"], getattributes: ["속성 조회", "키의 상태·알고리즘 등 메타데이터"],
    get: ["키 값 조회", "키 값을 가져간다 (KMIP Get / REST material)"], activate: ["활성화", "Pre-Active → Active"],
    revoke: ["비활성화·침해 표시", "KMIP Revoke"], rekey: ["키 회전", "새 키로 교체"], setattribute: ["이름 변경", "이름 추가·삭제"], destroy: ["파기", "키 값 삭제"]
  };
  const OP_CLASS = { create: "C", locate: "R", getattributes: "R", get: "R", activate: "U", revoke: "U", rekey: "U", setattribute: "U", destroy: "D" };
  const ROLE_LABEL = { admin: "관리(admin)", audit: "조회(audit)" };

  let me = null, keys = [], groups = [], templates = [], bindings = [], managers = [], catalog = null;
  let filterState = "", curLog = "client", timer = null, currentTab = "keys";

  function el(tag, props, ...kids) {
    const e = document.createElement(tag);
    if (props) for (const [k, v] of Object.entries(props)) {
      if (k === "class") e.className = v; else if (k === "text") e.textContent = v; else if (k.startsWith("on")) e.addEventListener(k.slice(2), v); else if (v === true) e.setAttribute(k, ""); else if (v !== false && v != null) e.setAttribute(k, v);
    }
    const add = (c) => { if (c == null || c === false) return; if (Array.isArray(c)) c.forEach(add); else e.append(c.nodeType ? c : document.createTextNode(c)); };
    kids.forEach(add);
    return e;
  }
  const fmt = (t) => { if (!t || String(t).startsWith("0001")) return ""; const d = new Date(t); return isNaN(d) ? "" : d.toLocaleString(); };
  const short = (id) => id && id.length > 14 ? id.slice(0, 8) + "…" + id.slice(-4) : id;
  const writer = () => me && me.writer;
  const global = () => me && me.global;

  async function api(method, path, body) {
    const opt = { method, headers: {}, credentials: "same-origin" };
    if (me) opt.headers["X-CSRF-Token"] = me.csrf;
    if (body !== undefined) { opt.headers["Content-Type"] = "application/json"; opt.body = JSON.stringify(body); }
    const r = await fetch(path, opt);
    let data = null;
    try { data = await r.json(); } catch (_) { /* empty */ }
    if (r.status === 401 && path !== "/api/login" && path !== "/api/me") { showLogin(); throw new Error("세션이 만료되었습니다"); }
    if (!r.ok) { const e = data && data.error; throw new Error((e && (e.message || e)) || ("HTTP " + r.status)); }
    return data;
  }
  const q = encodeURIComponent;

  function toast(msg, bad) {
    const t = $("#toast"); t.textContent = msg; t.className = "toast" + (bad ? " bad" : "");
    clearTimeout(toast.h); toast.h = setTimeout(() => t.classList.add("hidden"), bad ? 6000 : 3000);
  }
  function fill(sel, items, keep) {
    const cur = keep ? sel.value : null; sel.replaceChildren(...items);
    if (cur != null && [...sel.options].some(o => o.value === cur)) sel.value = cur;
  }
  const opt = (v, t) => el("option", { value: v, text: t || v });

  // ---------- login / session
  function showLogin() {
    me = null; clearInterval(timer);
    $("#app").classList.add("hidden"); $("#enroll").classList.add("hidden"); $("#pwForce").classList.add("hidden"); $("#login").classList.remove("hidden");
    $("#loginForm").password.value = ""; $("#loginForm").otp.value = ""; $("#otpRow").classList.add("hidden");
  }
  async function showApp() {
    $("#login").classList.add("hidden"); $("#app").classList.remove("hidden");
    const scopes = me.scopes.map(s => (s.group === "ALL" ? "전체" : s.group) + ":" + s.role).join(", ");
    $("#whoami").textContent = me.user + (scopes ? " (" + scopes + ")" : " (권한 없음)");
    $("#newKey").classList.toggle("hidden", !writer());
    $("#newSuper").classList.toggle("hidden", !global());
    $("#newService").classList.toggle("hidden", !writer());
    $("#newTemplate").classList.toggle("hidden", !global());
    $("#bindForm").classList.toggle("hidden", !writer());
    $("#mgrForm").classList.toggle("hidden", !writer());
    document.querySelector('[data-tab=logs]').classList.toggle("hidden", !global());
    document.querySelector('[data-tab=dashboard]').classList.toggle("hidden", !global());
    document.querySelector('[data-tab=security]').classList.toggle("hidden", !global());
    if (me.password && me.password.expiresInDays != null && me.password.warnDays > 0 && me.password.expiresInDays <= me.password.warnDays) toast("비밀번호가 " + me.password.expiresInDays + "일 후 만료됩니다. 상단의 「비밀번호 변경」에서 바꾸세요.", true);
    try { catalog = await api("GET", "/api/catalog"); } catch (e) { toast(e.message, true); }
    try { const s = await api("GET", "/api/status"); $("#kmsInfo").textContent = "· " + (s.sealer || ""); } catch (_) { $("#kmsInfo").textContent = ""; }
    await Promise.all([loadGroups(), loadTemplates()]);
    await loadKeys();
    clearInterval(timer); timer = setInterval(() => { if (!document.hidden && !document.querySelector("dialog[open]") && currentTab === "keys") loadKeys(true); }, 20000);
  }
  async function afterLogin() {
    me = await api("GET", "/api/me");
    if (me.passwordChangeRequired) { await showPwForce(); return; }
    if (me.enrollRequired) { await showEnroll(); return; }
    await showApp();
  }
  $("#loginForm").addEventListener("submit", async (e) => {
    e.preventDefault(); $("#loginErr").textContent = "";
    const f = e.target;
    const body = { user: f.user.value, password: f.password.value };
    if (!$("#otpRow").classList.contains("hidden")) body.otp = f.otp.value.trim();
    try {
      const r = await fetch("/api/login", { method: "POST", headers: { "Content-Type": "application/json" }, credentials: "same-origin", body: JSON.stringify(body) });
      const d = await r.json().catch(() => ({}));
      if (d.otpRequired) { $("#otpRow").classList.remove("hidden"); f.otp.value = ""; f.otp.focus(); $("#loginErr").textContent = "인증 앱의 코드를 입력하세요."; return; }
      if (!r.ok) throw new Error((d.error && (d.error.message || d.error)) || ("HTTP " + r.status));
      await afterLogin();
    } catch (err) { $("#loginErr").textContent = err.message; }
  });

  // ---------- OTP enrollment
  async function showEnroll() {
    $("#login").classList.add("hidden"); $("#app").classList.add("hidden"); $("#enroll").classList.remove("hidden");
    $("#enrollStep1").classList.remove("hidden"); $("#enrollStep2").classList.add("hidden"); $("#enrollErr").textContent = "";
    const s = await api("GET", "/api/otp/setup");
    $("#qrImg").src = s.qr; $("#otpSecret").textContent = s.secret;
  }
  $("#enrollForm").addEventListener("submit", async (e) => {
    e.preventDefault(); $("#enrollErr").textContent = "";
    try {
      const r = await api("POST", "/api/otp/confirm", { code: e.target.code.value });
      $("#recoveryCodes").textContent = r.recoveryCodes.join("\n");
      $("#enrollStep1").classList.add("hidden"); $("#enrollStep2").classList.remove("hidden");
    } catch (err) { $("#enrollErr").textContent = err.message; }
  });
  $("#savedCodes").addEventListener("change", (e) => { $("#enrollDone").disabled = !e.target.checked; });
  $("#copyCodes").addEventListener("click", async () => { try { await navigator.clipboard.writeText($("#recoveryCodes").textContent); toast("복사했습니다"); } catch (_) { toast("복사할 수 없습니다. 직접 선택해 복사하세요.", true); } });
  $("#saveCodes").addEventListener("click", () => {
    const blob = new Blob(["KMS 관리 콘솔 복구 코드 (각 코드는 한 번만 사용)\n\n" + $("#recoveryCodes").textContent + "\n"], { type: "text/plain" });
    const a = el("a", { href: URL.createObjectURL(blob), download: "kms-recovery-codes.txt" }); document.body.append(a); a.click(); a.remove();
  });
  $("#enrollDone").addEventListener("click", async () => { $("#enroll").classList.add("hidden"); $("#recoveryCodes").textContent = ""; me = await api("GET", "/api/me"); await showApp(); });
  $("#enrollLogout").addEventListener("click", async () => { try { await api("POST", "/api/logout"); } catch (_) {} $("#enroll").classList.add("hidden"); showLogin(); });
  $("#logout").addEventListener("click", async () => { try { await api("POST", "/api/logout"); } catch (_) {} showLogin(); });

  // ---------- tabs
  document.querySelectorAll(".tab").forEach(b => b.addEventListener("click", () => {
    currentTab = b.dataset.tab;
    document.querySelectorAll(".tab").forEach(x => x.classList.toggle("active", x === b));
    ["dashboard", "keys", "groups", "templates", "clients", "managers", "logs", "security", "lifecycle"].forEach(t => $("#tab-" + t).classList.toggle("hidden", t !== currentTab));
    ({ keys: loadKeys, groups: loadGroups, templates: loadTemplates, clients: loadBindings, managers: loadManagers, logs: loadLogs, dashboard: loadDash, security: loadSecurity })[currentTab]?.();
  }));

  // ---------- keys
  async function loadKeys(quiet) {
    try { keys = (await api("GET", "/api/keys")).keys; renderKeys(); }
    catch (e) { if (!quiet) toast(e.message, true); }
  }
  function renderKeys() {
    const counts = {}; keys.forEach(k => counts[k.state] = (counts[k.state] || 0) + 1);
    const cards = $("#cards"); cards.replaceChildren();
    cards.append(card("전체", keys.length, ""));
    STATES.forEach(s => { if (counts[s] || s === "active" || s === "pre-active") cards.append(card(STATE_LABEL[s], counts[s] || 0, s)); });
    const sf = $("#stateFilter");
    if (sf.options.length === 1) STATES.forEach(s => sf.append(opt(s, STATE_LABEL[s])));
    sf.value = filterState;
    const gf = $("#groupFilter"), gv = gf.value;
    fill(gf, [opt("", "모든 서비스"), ...groups.filter(g => g.kind === "service").map(g => opt(g.name))]); gf.value = gv;
    const qv = $("#search").value.trim().toLowerCase();
    const rows = keys.filter(k => (!filterState || k.state === filterState) && (!gf.value || k.group === gf.value) &&
      (!qv || k.id.toLowerCase().includes(qv) || k.names.some(n => n.toLowerCase().includes(qv))));
    const tb = $("#keys tbody"); tb.replaceChildren();
    rows.forEach(k => tb.append(el("tr", { class: "click", tabindex: "0", onclick: () => openDetail(k.id), onkeydown: (e) => { if (e.key === "Enter") openDetail(k.id); } },
      el("td", { text: k.names.join(", ") || "—" }), el("td", { text: k.group }), el("td", { text: TYPE_LABEL[k.type] || k.type }),
      el("td", { text: k.algorithm.name }),
      el("td", null, badge(k.state)), el("td", { class: "created", text: fmt(k.createdAt) }))));
    $("#empty").classList.toggle("hidden", rows.length > 0);
  }
  function card(label, n, state) {
    return el("button", { class: state === filterState ? "sel" : "", onclick: () => { filterState = state; renderKeys(); } }, el("span", { class: "muted", text: label }), el("b", { text: String(n) }));
  }
  function badge(s) { return el("span", { class: "badge s-" + (STATE_LABEL[s] || "").replace(/ /g, "-"), text: STATE_LABEL[s] || s || "?" }); }
  $("#search").addEventListener("input", renderKeys);
  $("#stateFilter").addEventListener("change", (e) => { filterState = e.target.value; renderKeys(); });
  $("#groupFilter").addEventListener("change", renderKeys);
  $("#refresh").addEventListener("click", () => { loadKeys(); loadGroups(); });

  // ---------- create key
  function usageBox(defaults) {
    const box = $("#usageBox"); box.replaceChildren();
    (catalog?.usages || []).forEach(u => box.append(el("label", null, el("input", { type: "checkbox", value: u, checked: defaults.includes(u) }), u)));
  }
  function algoChanged() {
    const f = $("#createForm"), a = catalog.algorithms.find(x => x.id === f.algo.value);
    if (!a) return;
    usageBox(a.usage);
    $("#algoNote").textContent = (a.pair ? "개인키·공개키 한 쌍이 생성됩니다. " : "") +
      (/PQC/.test(a.group) ? "양자내성 알고리즘 — 서버는 이 키의 보관·수명주기 관리만 제공하며 암호 연산은 하지 않습니다." : "서버는 키 보관·수명주기 관리를 제공합니다.");
  }
  $("#newKey").addEventListener("click", () => {
    const f = $("#createForm"); f.reset(); $("#createErr").textContent = "";
    const svc = groups.filter(g => g.kind === "service");
    if (!svc.length) { toast("먼저 서비스(권한그룹)를 만드세요", true); return; }
    fill(f.group, svc.map(g => opt(g.name, g.name + (g.parent ? "  (" + g.parent + ")" : ""))));
    const sel = f.algo; sel.replaceChildren();
    const byGroup = {};
    catalog.algorithms.forEach(a => (byGroup[a.group] = byGroup[a.group] || []).push(a));
    Object.entries(byGroup).forEach(([g, list]) => sel.append(el("optgroup", { label: g }, ...list.map(a => opt(a.id, a.label)))));
    sel.value = "aes-256"; algoChanged(); $("#createDlg").showModal();
  });
  $("#createForm").algo.addEventListener("change", algoChanged);
  $("#createForm").addEventListener("submit", async (e) => {
    if (e.submitter && e.submitter.value === "cancel") return;
    e.preventDefault(); const f = e.target; $("#createErr").textContent = "";
    const usage = [...$("#usageBox").querySelectorAll("input:checked")].map(i => i.value);
    $("#createGo").disabled = true;
    try {
      const body = { algorithm: f.algo.value, group: f.group.value };
      if (f.name.value.trim()) body.name = f.name.value.trim();
      const a = catalog.algorithms.find(x => x.id === f.algo.value);
      if (a && JSON.stringify([...usage].sort()) !== JSON.stringify([...a.usage].sort())) body.usage = usage; // only when changed from the default
      if (f.activate.checked) body.activate = true;
      const r = await api("POST", "/api/keys", body);
      $("#createDlg").close(); toast("생성됨: " + r.keys.map(k => short(k.id)).join(", ")); await Promise.all([loadKeys(), loadGroups()]);
    } catch (err) { $("#createErr").textContent = err.message; }
    finally { $("#createGo").disabled = false; }
  });

  // ---------- key detail
  async function openDetail(id) {
    $("#dErr").textContent = "";
    let k;
    try { k = await api("GET", "/api/keys/" + q(id)); } catch (e) { toast(e.message, true); return; }
    $("#dTitle").textContent = k.names[0] || "이름 없음";
    const body = $("#dBody"); body.replaceChildren();
    const row = (t, v) => { body.append(el("dt", { text: t }), el("dd", null, v)); };
    row("ID", el("span", { class: "mono", text: k.id }));
    row("상태", badge(k.state));
    row("서비스", k.group);
    row("종류", TYPE_LABEL[k.type] || k.type);
    row("알고리즘", k.algorithm.name + (k.algorithm.standard ? " · " + k.algorithm.standard : "") + (k.algorithm.bits ? " · " + k.algorithm.bits + " bit" : ""));
    if (k.value) row("키 값", k.value.present ? (k.value.format + " · " + k.value.sizeBytes + " bytes (관리 화면에는 표시되지 않음)") : "삭제됨 / 없음");
    if (k.value && k.value.fingerprintSha256) row("공개키 지문", el("span", { class: "mono", text: k.value.fingerprintSha256 }));
    row("용도", k.usage.join(", ") || "—");
    row("이름", k.names.join(", ") || "—");
    row("생성자", k.creator || "—");
    if (k.parentGroup) row("상위그룹", k.parentGroup);
    if (k.pairId) row("짝 키 (" + k.pairRole + ")", el("span", { class: "mono", text: k.pairId }));
    if (k.replacesId) row("이전 키", el("span", { class: "mono", text: k.replacesId }));
    if (k.replacedById) row("교체된 키", el("span", { class: "mono", text: k.replacedById }));
    const tl = $("#dTimeline"); tl.replaceChildren();
    [["생성", k.createdAt], ["활성화", k.activatedAt], ["비활성화", k.deactivatedAt], ["침해 표시", k.compromisedAt], ["파기", k.destroyedAt], ["마지막 변경", k.updatedAt]]
      .forEach(([n, t]) => { if (fmt(t)) tl.append(el("li", { text: n + " — " + fmt(t) })); });
    const act = $("#dActions"); act.replaceChildren();
    k.actions.forEach(a => act.append(el("button", { class: a === "destroy" || a === "compromise" ? "danger" : (a === "activate" ? "primary" : ""), text: ACTION_LABEL[a], onclick: () => askAction(k, a) })));
    if (!k.actions.length) act.append(el("span", { class: "muted", text: writer() ? "이 상태에서 가능한 동작이 없습니다." : "조회 전용 권한입니다." }));
    $("#detailDlg").showModal();
  }
  $("#dClose").addEventListener("click", () => $("#detailDlg").close());

  // ---------- evidence of grants: approval number (승인번호) and the responsible person (담당자)
  function evidenceCells(x) {
    const missing = x.missingEvidence;
    return [
      el("td", { class: missing ? "err-cell" : "mono small", text: x.approvalCode || (x.root ? "(설정 파일)" : "⚠ 증적 없음"), title: missing ? "승인번호·담당자 기록 도입 이전에 부여됨 — 재승인 후 다시 부여하세요" : "" }),
      el("td", { class: missing ? "err-cell" : "", text: x.owner || (x.root ? "—" : "⚠") }),
      el("td", { class: "small muted", text: x.grantedBy ? x.grantedBy + " · " + fmt(x.grantedAt) : "" })];
  }
  const GRANT_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._/#-]{0,63}$/;
  function grantBody(form) {
    const approvalCode = form.approvalCode.value.trim(), owner = form.owner.value.trim();
    if (!GRANT_PATTERN.test(approvalCode)) throw new Error("승인번호 형식이 올바르지 않습니다 (영문·숫자·. _ / # - , 최대 64자)");
    if (!owner) throw new Error("담당자를 입력하세요");
    return { approvalCode, owner };
  }
  function askRemove(title, text, url, done) {
    confirmBox({ title, text, approval: true, run: async (apr) => { await api("DELETE", url + (apr ? "&approvalCode=" + q(apr) : "")); toast("삭제됨"); await done(); } });
  }

  // ---------- confirm helper
  function confirmBox({ title, text, expect, danger, approval, run }) {
    const dlg = $("#confirmDlg"); $("#cTitle").textContent = title; $("#cText").textContent = text; $("#cErr").textContent = ""; $("#cType").value = "";
    $("#cTypeWrap").classList.toggle("hidden", !expect); $("#cApprovalWrap").classList.toggle("hidden", !approval); $("#cApproval").value = ""; $("#cExpect").textContent = expect || "";
    $("#cGo").className = danger ? "danger" : "primary";
    $("#confirmForm").onsubmit = async (e) => {
      if (e.submitter && e.submitter.value === "cancel") return;
      e.preventDefault(); $("#cErr").textContent = "";
      if (expect && $("#cType").value !== expect) { $("#cErr").textContent = "입력값이 일치하지 않습니다."; return; }
      $("#cGo").disabled = true;
      try { await run($("#cApproval").value.trim()); dlg.close(); } catch (err) { $("#cErr").textContent = err.message; } finally { $("#cGo").disabled = false; }
    };
    dlg.showModal();
  }
  const WARN = {
    activate: "키를 활성화합니다. 이후 클라이언트가 이 키를 사용할 수 있습니다.",
    deactivate: "키를 비활성화합니다. 새로 사용할 수 없고 기존 데이터 처리에만 쓰입니다.",
    rekey: "새 대칭키를 발급합니다. 이전 키는 자동으로 비활성화(복호화 전용)되고 이름은 두 키에 모두 남습니다.",
    compromise: "키를 '침해됨'으로 표시합니다. 되돌릴 수 없습니다.",
    destroy: "키 값을 영구 삭제합니다. 되돌릴 수 없으며, 이 키로 암호화된 데이터는 복구할 수 없습니다."
  };
  function askAction(k, action) {
    const irreversible = action === "destroy" || action === "compromise";
    confirmBox({
      title: ACTION_LABEL[action] + " — " + (k.names[0] || short(k.id)), text: WARN[action], expect: irreversible ? k.id : "", danger: irreversible,
      run: async () => {
        const r = await api("POST", "/api/keys/" + q(k.id) + "/" + action);
        $("#detailDlg").close(); toast(ACTION_LABEL[action] + " 완료" + (action === "rekey" ? " · 새 키 " + short(r.key.id) : "")); await loadKeys();
      }
    });
  }

  // ---------- groups (services and super groups)
  async function loadGroups() {
    try { groups = (await api("GET", "/api/groups")).groups; renderGroups(); } catch (e) { toast(e.message, true); }
  }
  function renderGroups() {
    const tree = $("#groupTree"); tree.replaceChildren();
    const supers = groups.filter(g => g.kind === "super"), svcs = groups.filter(g => g.kind === "service");
    const all = groups.find(g => g.kind === "all");
    if (all) tree.append(el("div", { class: "card gcard" }, el("h3", null, el("span", { text: "ALL" }), el("span", { class: "badge kind", text: "전체 범위" }),
      scopeBtn(all)), el("p", { class: "muted", text: all.description })));
    const svcRow = (g) => el("div", { class: "gsvc" },
      el("div", null, el("b", { text: g.name }), el("span", { class: "muted", text: "  " + (g.description || "") }), el("br"), el("span", { class: "muted small", text: "담당자 " + (g.owner || "⚠ 미지정") + " · 키 " + g.keyCount + "개 · 매핑 " + g.clientCount + " · 관리자 " + g.managerCount })),
      el("div", { class: "actions" }, scopeBtn(g),
        writer() ? el("button", { class: "ghost", text: "수정", onclick: () => groupDialog(g) }) : null,
        writer() ? el("button", { class: "ghost", text: "삭제", onclick: () => deleteGroup(g) }) : null));
    supers.forEach(sg => {
      const members = svcs.filter(s => s.parent === sg.name);
      tree.append(el("div", { class: "card gcard" },
        el("h3", null, el("span", { text: sg.name }), el("span", { class: "badge kind", text: "상위그룹" }), el("span", { class: "muted small", text: sg.description }),
          scopeBtn(sg), writer() ? el("button", { class: "ghost", text: "서비스 추가", onclick: () => groupDialog(null, "service", sg.name) }) : null,
          global() ? el("button", { class: "ghost", text: "수정", onclick: () => groupDialog(sg) }) : null,
          global() ? el("button", { class: "ghost", text: "삭제", onclick: () => deleteGroup(sg) }) : null),
        members.length ? members.map(svcRow) : el("p", { class: "muted small", text: "소속 서비스가 없습니다." })));
    });
    const loose = svcs.filter(s => !s.parent || !supers.some(x => x.name === s.parent));
    if (loose.length) tree.append(el("div", { class: "card gcard" }, el("h3", null, el("span", { text: "상위그룹 없는 서비스" })), loose.map(svcRow)));
    if (!groups.length) tree.append(el("p", { class: "muted", text: "보이는 그룹이 없습니다." }));
  }
  function scopeBtn(g) { return el("button", { class: "ghost", text: "매핑·관리자", onclick: () => scopeDialog(g) }); }

  function groupDialog(g, kind, parent) {
    const dlg = $("#groupDlg"), f = $("#groupForm"); f.reset(); $("#gErr").textContent = "";
    const editing = !!g, k = g ? g.kind : kind;
    $("#gTitle").textContent = (editing ? "수정 — " : "새 ") + (k === "super" ? "상위그룹" : "서비스");
    f.name.value = g ? g.name : ""; f.name.readOnly = editing; f.description.value = g ? g.description : ""; f.owner.value = g ? (g.owner || "") : "";
    $("#gParentWrap").classList.toggle("hidden", k !== "service");
    const supers = groups.filter(x => x.kind === "super");
    fill(f.parent, [opt("", "(없음)"), ...supers.map(x => opt(x.name))]); f.parent.value = g ? (g.parent || "") : (parent || "");
    f.onsubmit = async (e) => {
      if (e.submitter && e.submitter.value === "cancel") return;
      e.preventDefault(); $("#gErr").textContent = "";
      const body = { name: f.name.value, kind: k, parent: k === "service" ? f.parent.value : "", description: f.description.value, owner: f.owner.value.trim() };
      try {
        if (editing) await api("PUT", "/api/groups/" + q(g.name), body); else await api("POST", "/api/groups", body);
        dlg.close(); toast("저장됨"); await loadGroups();
      } catch (err) { $("#gErr").textContent = err.message; }
    };
    dlg.showModal();
  }
  $("#newSuper").addEventListener("click", () => groupDialog(null, "super"));
  $("#newService").addEventListener("click", () => groupDialog(null, "service"));
  function deleteGroup(g) {
    confirmBox({ title: "삭제 — " + g.name, text: "그룹과 이 그룹의 클라이언트 매핑·관리자 지정이 삭제됩니다. 키가 있거나 하위 서비스가 있으면 삭제되지 않습니다.", expect: g.name, danger: true,
      run: async () => { await api("DELETE", "/api/groups/" + q(g.name)); toast("삭제됨"); await loadGroups(); } });
  }

  // dialog: bindings and managers of one group
  async function scopeDialog(g) {
    $("#sTitle").textContent = g.name + (g.kind === "super" ? " (상위그룹)" : g.kind === "all" ? " (전체)" : " (서비스)");
    $("#sErr").textContent = "";
    await loadTemplates(); await Promise.all([loadBindings(), loadManagers()]);
    const draw = () => {
      const bs = bindings.filter(b => b.group === g.name), ms = managers.filter(m => m.scope === g.name);
      const bt = el("table", null, el("thead", null, el("tr", null, el("th", { text: "클라이언트" }), el("th", { text: "템플릿" }), el("th", { text: "승인번호" }), el("th", { text: "담당자" }), el("th", { text: "부여" }), el("th"))),
        el("tbody", null, bs.map(b => el("tr", null, el("td", { text: b.client }), el("td", null, tplChips(b.template)), ...evidenceCells(b),
          el("td", null, writer() ? el("button", { class: "ghost", text: "삭제", onclick: () => askRemove("매핑 삭제 — " + b.client, b.group + " 그룹의 " + b.template + " 권한을 회수합니다.", "/api/bindings?client=" + q(b.client) + "&group=" + q(b.group), async () => { await loadBindings(); draw(); }) }) : null)))));
      $("#sBind").replaceChildren(bs.length ? bt : el("p", { class: "muted small", text: "매핑된 클라이언트가 없습니다." }));
      const mt = el("table", null, el("thead", null, el("tr", null, el("th", { text: "사용자" }), el("th", { text: "역할" }), el("th", { text: "승인번호" }), el("th", { text: "담당자" }), el("th", { text: "부여" }), el("th"))),
        el("tbody", null, ms.map(m => el("tr", null, el("td", { text: m.identity }), el("td", { text: ROLE_LABEL[m.role] || m.role }), ...evidenceCells(m),
          el("td", null, writer() && !m.root ? el("button", { class: "ghost", text: "삭제", onclick: () => askRemove("관리 권한 회수 — " + m.identity, m.scope + " 범위의 " + m.role + " 권한을 회수합니다.", "/api/managers?identity=" + q(m.identity) + "&scope=" + q(m.scope), async () => { await loadManagers(); draw(); }) }) : null)))));
      $("#sMgr").replaceChildren(ms.length ? mt : el("p", { class: "muted small", text: "이 그룹에 직접 지정된 관리자가 없습니다 (상위·전체 관리자는 포함되지 않음)." }));
    };
    const bf = $("#sBindForm"), mf = $("#sMgrForm");
    fill(bf.template, templates.map(t => opt(t.name)));
    bf.classList.toggle("hidden", !writer()); mf.classList.toggle("hidden", !writer());
    bf.onsubmit = async (e) => { e.preventDefault(); try { await api("PUT", "/api/bindings", { client: bf.client.value.trim(), group: g.name, template: bf.template.value, ...grantBody(bf) }); bf.client.value = ""; bf.approvalCode.value = ""; $("#sErr").textContent = ""; await loadBindings(); draw(); } catch (err) { $("#sErr").textContent = err.message; } };
    mf.onsubmit = async (e) => { e.preventDefault(); try { await api("PUT", "/api/managers", { identity: mf.identity.value.trim(), scope: g.name, role: mf.role.value, ...grantBody(mf) }); mf.identity.value = ""; mf.approvalCode.value = ""; $("#sErr").textContent = ""; await loadManagers(); draw(); } catch (err) { $("#sErr").textContent = err.message; } };
    draw(); $("#scopeDlg").showModal();
  }
  $("#sClose").addEventListener("click", () => $("#scopeDlg").close());

  // ---------- templates
  async function loadTemplates() {
    try { templates = (await api("GET", "/api/templates")).templates; renderTemplates(); } catch (e) { toast(e.message, true); }
  }
  function opChip(op) { return el("span", { class: "chip " + (OP_CLASS[op] || ""), title: (OP_LABEL[op] || [op])[1], text: op }); }
  function tplChips(name) { const t = templates.find(x => x.name === name); return t ? t.operations.map(opChip) : el("span", { class: "muted", text: name }); }
  function renderTemplates() {
    const box = $("#templateList"); box.replaceChildren();
    templates.forEach(t => {
      const letters = t.crud;
      box.append(el("div", { class: "card tpl" },
        el("h3", null, el("span", { text: t.name }), t.builtin ? el("span", { class: "badge kind", text: "기본" }) : null, el("span", { class: "badge kind", text: letters })),
        el("p", { class: "muted", text: t.description || "" }), el("div", null, t.operations.map(opChip)),
        t.approvalCode ? el("p", { class: "muted small", text: "최근 변경: 승인번호 " + t.approvalCode + " · " + (t.changedBy || "") + " · " + fmt(t.changedAt) }) : null,
        global() ? el("div", { class: "actions" }, el("button", { class: "ghost", text: "수정", onclick: () => templateDialog(t) }),
          t.builtin ? null : el("button", { class: "ghost", text: "삭제", onclick: () => deleteTemplate(t) })) : null));
    });
  }
  function templateDialog(t) {
    const dlg = $("#tplDlg"), f = $("#tplForm"); f.reset(); $("#tErr").textContent = "";
    $("#tTitle").textContent = t ? "템플릿 수정 — " + t.name : "새 권한 템플릿";
    f.name.value = t ? t.name : ""; f.name.readOnly = !!t; f.description.value = t ? t.description : ""; f.approvalCode.value = "";
    const box = $("#opBox"); box.replaceChildren();
    (catalog?.operations || Object.keys(OP_LABEL)).forEach(op => box.append(el("label", null,
      el("input", { type: "checkbox", value: op, checked: !!t && t.operations.includes(op) }),
      el("span", null, el("span", { class: "chip " + OP_CLASS[op], text: OP_CLASS[op] }), " " + (OP_LABEL[op] || [op])[0], el("small", { text: op + " — " + (OP_LABEL[op] || ["", ""])[1] })))));
    const setAll = (pred) => box.querySelectorAll("input").forEach(i => i.checked = pred(i.value));
    $("#tplCrud").onclick = () => setAll(() => true);
    $("#tplRead").onclick = () => setAll(o => OP_CLASS[o] === "R");
    $("#tplNone").onclick = () => setAll(() => false);
    f.onsubmit = async (e) => {
      if (e.submitter && e.submitter.value === "cancel") return;
      e.preventDefault(); $("#tErr").textContent = "";
      const ops = [...box.querySelectorAll("input:checked")].map(i => i.value);
      const body = { name: f.name.value, description: f.description.value, operations: ops, approvalCode: f.approvalCode.value.trim() };
      try {
        if (t) await api("PUT", "/api/templates/" + q(t.name), body); else await api("POST", "/api/templates", body);
        dlg.close(); toast("저장됨"); await loadTemplates();
      } catch (err) { $("#tErr").textContent = err.message; }
    };
    dlg.showModal();
  }
  $("#newTemplate").addEventListener("click", () => templateDialog(null));
  function deleteTemplate(t) {
    confirmBox({ title: "템플릿 삭제 — " + t.name, text: "사용 중인 템플릿은 삭제되지 않습니다.", expect: t.name, danger: true,
      run: async () => { await api("DELETE", "/api/templates/" + q(t.name)); toast("삭제됨"); await loadTemplates(); } });
  }

  // ---------- client bindings
  async function loadBindings() {
    try { bindings = (await api("GET", "/api/bindings")).bindings; renderBindings(); } catch (e) { toast(e.message, true); }
  }
  function renderBindings() {
    const f = $("#bindForm");
    const gs = groups.filter(g => g.kind === "all" ? global() : true);
    fill(f.group, gs.map(g => opt(g.name, g.name + (g.kind === "super" ? "  (상위그룹)" : g.kind === "all" ? "  (전체)" : ""))), true);
    fill(f.template, templates.map(t => opt(t.name)), true);
    const tb = $("#bindings tbody"); tb.replaceChildren();
    bindings.forEach(b => tb.append(el("tr", null, el("td", { text: b.client }), el("td", { text: b.group }), el("td", { text: b.template }), el("td", null, tplChips(b.template)), ...evidenceCells(b),
      el("td", null, writer() ? el("button", { class: "ghost", text: "삭제", onclick: () => askRemove("매핑 삭제 — " + b.client, b.group + " 그룹의 " + b.template + " 권한을 회수합니다.", "/api/bindings?client=" + q(b.client) + "&group=" + q(b.group), loadBindings) }) : null))));
    $("#bindEmpty").classList.toggle("hidden", bindings.length > 0);
  }
  $("#bindForm").addEventListener("submit", async (e) => {
    e.preventDefault(); const f = e.target; $("#bindErr").textContent = "";
    try { await api("PUT", "/api/bindings", { client: f.client.value.trim(), group: f.group.value, template: f.template.value, ...grantBody(f) }); f.client.value = ""; f.approvalCode.value = ""; toast("매핑됨"); await loadBindings(); }
    catch (err) { $("#bindErr").textContent = err.message; }
  });

  // ---------- managers
  async function loadManagers() {
    try { managers = (await api("GET", "/api/managers")).managers; renderManagers(); } catch (e) { toast(e.message, true); }
  }
  function renderManagers() {
    const f = $("#mgrForm");
    fill(f.scope, groups.filter(g => g.kind === "all" ? global() : true).map(g => opt(g.name, g.name + (g.kind === "super" ? "  (상위그룹)" : g.kind === "all" ? "  (전체)" : ""))), true);
    const tb = $("#managers tbody"); tb.replaceChildren();
    managers.forEach(m => tb.append(el("tr", null, el("td", { text: m.identity }), el("td", { text: m.scope === "ALL" ? "전체 (ALL)" : m.scope }), el("td", { text: ROLE_LABEL[m.role] || m.role }), ...evidenceCells(m),
      el("td", null, writer() && !m.root ? el("button", { class: "ghost", text: "삭제", onclick: () => askRemove("관리 권한 회수 — " + m.identity, m.scope + " 범위의 " + m.role + " 권한을 회수합니다.", "/api/managers?identity=" + q(m.identity) + "&scope=" + q(m.scope), loadManagers) }) : null))));
  }
  $("#mgrForm").addEventListener("submit", async (e) => {
    e.preventDefault(); const f = e.target; $("#mgrErr").textContent = "";
    try { await api("PUT", "/api/managers", { identity: f.identity.value.trim(), scope: f.scope.value, role: f.role.value, ...grantBody(f) }); f.identity.value = ""; f.approvalCode.value = ""; toast("부여됨"); await loadManagers(); }
    catch (err) { $("#mgrErr").textContent = err.message; }
  });

  // ---------- audit and logs
  const LOG_HELP = {
    client: "클라이언트 포트(KMIP·클라이언트 REST)로 들어온 요청과 그 결과입니다. 관리 API 기록은 섞이지 않습니다.",
    admin: "관리 API 포트로 들어온 요청과 권한·키 변경 이벤트입니다. 승인번호와 담당자가 함께 남습니다. 이 로그를 조회·내보내기·검증한 사실도 기록됩니다.",
    console: "콘솔의 로그인·로그아웃, OTP, 접속 실패 기록입니다."
  };
  const CAT = { authentication: "인증", "key-lifecycle": "키 수명주기", "key-access": "키 조회·반출", "permission-change": "권한 변경", "audit-access": "감사로그 접근", "api-access": "API 접근", system: "시스템", "audit-maintenance": "감사로그 관리", event: "이벤트" };
  const OUT = { success: "성공", failure: "실패", denied: "거부" };
  let logRows = [];
  function auditQuery(extra) {
    const f = $("#logFilterForm"), p = new URLSearchParams();
    for (const k of ["from", "to", "category", "outcome", "who", "q"]) { const v = f[k].value.trim(); if (v) p.set(k, v); }
    for (const [k, v] of Object.entries(extra || {})) p.set(k, v);
    return p.toString();
  }
  async function loadLogs() {
    $("#logHelp").textContent = LOG_HELP[curLog];
    $("#auditVerdict").textContent = ""; $("#auditVerdict").className = "muted";
    try {
      const r = await api("GET", (curLog === "console" ? "/api/logs/console?" : "/api/logs/" + curLog + "?") + auditQuery({ limit: 500 }));
      logRows = Array.isArray(r) ? r : r.entries; renderLogs();
    } catch (e) { toast(e.message, true); }
    loadReviews();
  }
  function renderLogs() {
    const tb = $("#logTable tbody"); tb.replaceChildren();
    logRows.forEach(r => tb.append(el("tr", null,
      el("td", { text: String(r.seq || "") }), el("td", { text: fmt(r.time) }), el("td", { text: CAT[r.category] || r.category || "" }),
      el("td", { text: r.who + (r.via ? " (via " + r.via + ")" : "") }), el("td", { text: r.op }),
      el("td", { class: "id", title: r.target || "", text: r.target ? short(r.target.split(",")[0]) + (r.target.includes(",") ? " …" : "") : "" }),
      el("td", { text: r.approval || "" }), el("td", { text: r.owner || "" }),
      el("td", { text: r.detail || "" }), el("td", { class: r.outcome === "success" ? "" : "err-cell", title: r.result, text: (OUT[r.outcome] || r.outcome || "") + (r.outcome !== "success" && r.result ? " · " + r.result : "") }),
      el("td", { text: r.remote || "" }))));
  }
  async function loadReviews() {
    const tb = $("#reviewTable tbody"); tb.replaceChildren();
    if (curLog === "console") { return; }
    try {
      const r = await api("GET", "/api/audit/reviews");
      (r.reviews || []).forEach(e => tb.append(el("tr", null, el("td", { text: fmt(e.time) }), el("td", { text: e.who }), el("td", { text: e.target }), el("td", { text: e.detail + (e.approval ? " [" + e.approval + "]" : "") }))));
    } catch (_) { /* not an auditor of that log */ }
  }
  document.querySelectorAll("[data-log]").forEach(b => b.addEventListener("click", () => {
    curLog = b.dataset.log; document.querySelectorAll("[data-log]").forEach(x => x.classList.toggle("active", x === b)); loadLogs();
  }));
  $("#logRefresh").addEventListener("click", loadLogs);
  $("#logFilterForm").addEventListener("submit", e => { e.preventDefault(); loadLogs(); });
  $("#auditVerify").addEventListener("click", async () => {
    const v = $("#auditVerdict");
    try {
      const r = await api("GET", "/api/audit/verify?log=" + curLog);
      v.textContent = r.ok ? "무결성 확인: " + r.entries + "건 (순번 " + r.firstSeq + "–" + r.lastSeq + ", 파일 " + r.files + "개, MAC " + (r.macChecked ? "검증" : "미검증") + ")"
        : "⚠ 변조 의심: " + r.problem + " — " + r.where;
      v.className = r.ok ? "ok" : "err";
    } catch (e) { toast(e.message, true); }
  });
  $("#auditExport").addEventListener("click", async () => {
    try {
      const r = await fetch("/api/audit/export?" + auditQuery({ log: curLog }), { credentials: "same-origin" });
      if (!r.ok) { let m = "HTTP " + r.status; try { const d = await r.json(); m = (d.error && (d.error.message || d.error)) || m; } catch (_) { /* binary */ } throw new Error(m); }
      const blob = await r.blob(), a = document.createElement("a");
      a.href = URL.createObjectURL(blob); a.download = "audit-" + curLog + "-" + new Date().toISOString().slice(0, 10) + ".zip"; document.body.append(a); a.click(); a.remove();
      setTimeout(() => URL.revokeObjectURL(a.href), 5000); toast("증적을 내려받았습니다 (내보내기 기록이 남습니다)");
    } catch (e) { toast(e.message, true); }
  });
  $("#auditReviewBtn").addEventListener("click", () => { $("#reviewForm").classList.toggle("hidden"); $("#reviewErr").textContent = ""; });
  $("#reviewCancel").addEventListener("click", () => $("#reviewForm").classList.add("hidden"));
  $("#reviewForm").addEventListener("submit", async e => {
    e.preventDefault(); const f = e.target; $("#reviewErr").textContent = "";
    const body = { log: curLog, from: f.from.value, to: f.to.value, finding: f.finding.value, note: f.note.value.trim() };
    if (f.approvalCode.value.trim()) body.approvalCode = f.approvalCode.value.trim();
    try { await api("POST", "/api/audit/reviews", body); f.reset(); f.classList.add("hidden"); toast("검토 기록을 남겼습니다"); loadLogs(); }
    catch (err) { $("#reviewErr").textContent = err.message; }
  });

  // ---------- evidence dialog (approval number + responsible person for every change)
  function askEvidence({ title, text, fields, danger, go }) {
    const dlg = $("#evDlg"), form = $("#evForm"), box = $("#evFields");
    $("#evTitle").textContent = title; $("#evText").textContent = text || ""; $("#evErr").textContent = "";
    box.replaceChildren(...fields.map(f => el("label", null, f.label, el("input", { name: f.name, type: f.type || "text", maxlength: f.max || 64, autocomplete: "off", placeholder: f.placeholder || "" }))));
    $("#evGo").className = danger ? "danger" : "primary";
    form.onsubmit = async (e) => {
      e.preventDefault();
      const v = {}; fields.forEach(f => { v[f.name] = form.elements[f.name].value.trim(); });
      try { await go(v); dlg.close(); } catch (err) { $("#evErr").textContent = err.message; }
    };
    $("#evCancel").onclick = () => dlg.close();
    dlg.showModal(); (box.querySelector("input") || $("#evGo")).focus();
  }
  const EVID = [{ name: "approvalCode", label: "승인번호 (필수)" }, { name: "owner", label: "담당자 (필수)" }];

  // ---------- password change
  let pwRulesText = "";
  async function loadRules() {
    try {
      const st = (await api("GET", "/api/settings")).settings.password;
      pwRulesText = "규칙: " + st.minLength + "자 이상, 대문자·소문자·숫자·기호 중 " + st.minClasses + "종 이상" + (st.forbidUsername ? ", 계정 이름 포함 금지" : "") + (st.forbidRepeat ? ", 같은 문자 3회 연속 금지" : "") + (st.history ? ", 최근 " + st.history + "회 비밀번호 재사용 금지" : "") + ".";
    } catch (_) { pwRulesText = "비밀번호 규칙은 관리자가 정합니다. 12자 이상, 대문자·소문자·숫자·기호 중 3종 이상이 기본값입니다."; }
    document.querySelectorAll(".pwRules, #pwRules").forEach(e => { e.textContent = pwRulesText; });
  }
  async function submitPw(f, errEl) {
    errEl.textContent = "";
    if (f.new.value !== f.again.value) { errEl.textContent = "새 비밀번호 확인이 일치하지 않습니다."; return false; }
    try { await api("POST", "/api/password", { current: f.current.value, new: f.new.value }); f.reset(); return true; }
    catch (e) { errEl.textContent = e.message; return false; }
  }
  async function showPwForce() {
    $("#login").classList.add("hidden"); $("#app").classList.add("hidden"); $("#enroll").classList.add("hidden"); $("#pwForce").classList.remove("hidden");
    $("#pwForceWhy").textContent = "비밀번호가 만료되었거나 관리자가 설정한 임시 비밀번호입니다. 새 비밀번호를 정해야 계속할 수 있습니다.";
    $("#pwForceErr").textContent = "";
    try { const st = await fetch("/api/settings", { credentials: "same-origin" }); void st; } catch (_) { /* rules shown after the change */ }
    $("#pwRules").textContent = "규칙: 관리자가 정한 길이·문자 종류 규칙을 만족해야 합니다. 맞지 않으면 사유가 표시됩니다.";
  }
  $("#pwForceForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    if (await submitPw(e.target, $("#pwForceErr"))) { $("#pwForce").classList.add("hidden"); toast("비밀번호를 변경했습니다"); await afterLogin(); }
  });
  $("#pwForceLogout").addEventListener("click", async () => { try { await api("POST", "/api/logout"); } catch (_) {} showLogin(); });
  $("#changePw").addEventListener("click", async () => { await loadRules(); $("#pwErr").textContent = ""; $("#pwDlg").showModal(); });
  $("#pwCancel").addEventListener("click", () => $("#pwDlg").close());
  $("#pwForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    if (await submitPw(e.target, $("#pwErr"))) { $("#pwDlg").close(); toast("비밀번호를 변경했습니다. 다른 기기의 로그인은 종료됩니다."); }
  });

  // ---------- dashboard
  const LV = { ok: ["정상", "ok"], warn: ["주의", "warn"], critical: ["위험", "critical"] };
  const dur = (sec) => { if (!sec && sec !== 0) return ""; const d = Math.floor(sec / 86400), h = Math.floor(sec % 86400 / 3600), m = Math.floor(sec % 3600 / 60); return d ? d + "일 " + h + "시간" : h ? h + "시간 " + m + "분" : m + "분"; };
  const pill = (t, c) => el("span", { class: "pill " + c, text: t });
  const svcLabel = { kms: "KMS 키 서버", console: "관리 콘솔" };
  const meter = (pct) => el("div", { class: "meter " + (pct >= 90 ? "crit" : pct >= 80 ? "warn" : "") }, el("i", { style: "width:" + Math.min(100, pct) + "%" }));
  let dashTimer = null, dashData = null;

  async function loadDash(quiet, refresh) {
    try {
      const d = await api("GET", "/api/system" + (refresh ? "?refresh=1" : "")); dashData = d; renderDash(d);
    } catch (e) { if (!quiet) toast(e.message, true); }
    clearInterval(dashTimer);
    dashTimer = setInterval(() => { if (currentTab === "dashboard" && !document.hidden && !document.querySelector("dialog[open]")) loadDash(true); else if (currentTab !== "dashboard") clearInterval(dashTimer); }, 15000);
  }
  function card(title, ...rows) { return el("div", { class: "card" }, el("h4", { text: title }), ...rows); }
  const row = (k, v) => el("div", { class: "row" }, el("span", { class: "muted", text: k }), el("span", null, v));

  function renderDash(d) {
    const [lt, lc] = LV[d.overall.level] || LV.ok, b = $("#dashBanner");
    b.className = "banner " + lc;
    b.replaceChildren("시스템 상태: " + lt, (d.overall.findings || []).length ? el("ul", null, (d.overall.findings || []).map(f => el("li", { text: (f.level === "critical" ? "● " : "▲ ") + f.text }))) : el("div", { class: "muted", style: "font-weight:400", text: "모든 점검 항목이 정상입니다." }));
    $("#dashTime").textContent = "점검 시각 " + fmt(d.time) + " · 15초마다 자동 갱신";

    const st = d.backend.status || {}, keys = st.keys || {};
    const cards = [];
    cards.push(card("키 서버", el("div", { class: "big" }, d.backend.reachable ? pill("가동 중", "ok") : pill("응답 없음", "crit")),
      row("보호 방식", st.sealer || "-"), row("가동 시간", dur(st.uptimeSeconds)), row("DB 크기", st.dbBytes ? (st.dbBytes / 1024).toFixed(0) + " KB" : "-"), row("전체 키", String(st.totalKeys ?? "-"))));
    cards.push(card("키 상태 분포", ...(Object.keys(keys).length ? Object.entries(keys).map(([k, n]) => row(STATE_LABEL[k] || k, String(n))) : [el("div", { class: "muted", text: "키 없음" })])));
    const lg = d.logins || {};
    cards.push(card("콘솔 로그인 (24시간)", row("성공", String(lg.success24h ?? 0)), row("실패", el("span", { class: lg.failed24h ? "err" : "", text: String(lg.failed24h ?? 0) })), row("잠긴 계정", el("span", { class: lg.lockedAccounts ? "err" : "", text: String(lg.lockedAccounts ?? 0) })),
      row("활성 세션", String((d.console || {}).sessions ?? 0)), row("콘솔 계정", String((d.console || {}).users ?? 0))));
    const au = (st.audit) || {};
    cards.push(card("감사 로그 기록", row("클라이언트 로그 순번", String(((au.client) || {}).seq ?? "-")), row("관리 로그 순번", String(((au.admin) || {}).seq ?? "-")), row("보관 하한", (au.retentionDays ?? "-") + "일"), row("외부 전송(syslog)", au.syslog ? "사용" : "미사용")));
    const sc = d.selfcheck;
    if (sc && sc.report) {
      const rp = sc.report;
      cards.push(card("자가점검 (KMIP·API)", el("div", { class: "big" }, rp.ok ? pill("정상", "ok") : pill("실패", "crit")),
        ...(rp.results || []).map(x => row(x.name, el("span", { class: x.ok ? "" : "err", title: x.error || x.detail || "", text: x.ok ? x.latencyMs + " ms" : "실패" }))), row("마지막 점검", fmt(rp.time)), row("주기", Math.round(sc.intervalSeconds / 60) + "분")));
    } else if (sc) cards.push(card("자가점검 (KMIP·API)", el("div", { class: "muted", text: sc.ran ? "" : "첫 점검 대기 중" })));
    $("#dashCards").replaceChildren(...cards);

    // services
    const tb = $("#dashSvc tbody"); tb.replaceChildren();
    const ag = d.agent || {};
    (ag.services || []).forEach(sv => {
      const run = sv.running, health = sv.health === "unhealthy" ? pill("unhealthy", "crit") : run ? pill(sv.health === "healthy" ? "실행 중 · healthy" : "실행 중", "ok") : pill(sv.status === "missing" ? "컨테이너 없음" : "중지됨", "crit");
      const btn = (act, label, cls) => el("button", { class: cls || "ghost", text: label, onclick: () => serviceAction(sv.name, act) });
      tb.append(el("tr", null, el("td", { text: (svcLabel[sv.name] || sv.name) + " (" + sv.name + ")" }), el("td", null, health), el("td", { text: run ? dur(sv.uptimeSeconds) : "-" }),
        el("td", { text: String(sv.restartCount) }), el("td", { class: "id", title: sv.image || "", text: short(sv.image || "") }),
        el("td", null, d.canControl ? [run ? null : btn("start", "시작", "primary"), run ? btn("restart", "재기동") : null, run ? btn("stop", "중지", "danger") : null] : null)));
    });
    $("#dashAgentNote").textContent = !ag.configured ? "서비스 제어 에이전트가 설정되지 않아 컨테이너 상태와 시작·중지는 사용할 수 없습니다." :
      ag.error ? "에이전트에 연결할 수 없습니다: " + ag.error : d.canControl ? "시작·중지·재기동은 승인번호와 담당자를 입력해야 하며 감사 기록에 남습니다." : "서비스 제어는 전체 관리자(admin) 권한이 필요합니다. 현재는 조회만 가능합니다.";

    // ports
    const pt = $("#dashPorts tbody"); pt.replaceChildren();
    (d.probes || []).forEach(p => pt.append(el("tr", null, el("td", { text: p.name }), el("td", { class: "id", text: p.addr }), el("td", null, p.up ? pill("열림", "ok") : pill("닫힘", "crit")),
      el("td", { text: p.up ? p.latencyMs + " ms" : (p.error || "") }), el("td", { text: p.certCn || "" }), el("td", null, p.certExpires ? [fmt(p.certExpires) + " ", pill(p.certDays + "일", p.certDays < 7 ? "crit" : p.certDays < 30 ? "warn" : "ok")] : ""))));
    if (!(d.probes || []).length) pt.append(el("tr", null, el("td", { colspan: "6", class: "muted", text: "점검할 포트가 설정되지 않았습니다." })));

    // audit
    const at = $("#dashAudit tbody"); at.replaceChildren();
    (d.audit || []).forEach(a => at.append(el("tr", null, el("td", { text: a.log }), el("td", null, a.ok ? pill("이상 없음", "ok") : pill("변조 의심", "crit"), a.ok ? "" : " " + a.problem + " " + (a.where || "")),
      el("td", { text: String(a.entries) }), el("td", { text: String(a.lastSeq) }), el("td", { text: fmt(a.checkedAt) }))));

    // host
    const hb = $("#dashHost"); hb.replaceChildren();
    const h = ag.host || {};
    (h.disks || []).forEach(x => hb.append(card("디스크 " + x.path, meter(x.usedPct), row("사용률", x.usedPct + "%"), row("여유", x.freeGB + " GB / " + x.totalGB + " GB"))));
    if (h.memTotalMB) { const used = Math.round(100 * (h.memTotalMB - h.memAvailMB) / h.memTotalMB); hb.append(card("메모리", meter(used), row("사용률", used + "%"), row("가용", h.memAvailMB + " MB / " + h.memTotalMB + " MB"))); }
    if (h.cpus) hb.append(card("CPU·가동", row("부하(1분)", h.load1.toFixed(2) + " / " + h.cpus + " 코어"), row("호스트 가동", dur(h.uptimeSeconds))));
    if (!hb.children.length) hb.append(el("div", { class: "muted", text: "호스트 정보는 에이전트 연결 시 표시됩니다." }));
  }
  $("#dashRefresh").addEventListener("click", () => loadDash());
  $("#dashVerify").addEventListener("click", () => loadDash(false, true));

  const ACT = { start: ["시작", "서비스를 시작합니다."], stop: ["중지", "서비스를 중지합니다. 중지된 동안 해당 기능을 사용할 수 없습니다."], restart: ["재기동", "서비스를 재시작합니다. 잠시 연결이 끊깁니다."] };
  function serviceAction(name, action) {
    const [label, text] = ACT[action];
    let warn = text;
    if (name === "kms" && action !== "start") warn += " 키 서버가 멈추면 모든 클라이언트(KMIP·REST, localhsm 동기화)가 키를 받을 수 없습니다.";
    if (name === "console" && action !== "start") warn += " 이 화면(관리 콘솔)도 함께 끊깁니다. " + (action === "stop" ? "다시 시작하려면 서버에서 직접 시작해야 합니다." : "잠시 후 새로고침하세요.");
    askEvidence({
      title: (svcLabel[name] || name) + " " + label, text: warn, danger: action === "stop",
      fields: [...EVID, { name: "confirm", label: "확인을 위해 서비스 이름 \"" + name + "\" 을 입력", placeholder: name }],
      go: async (v) => {
        try { await api("POST", "/api/system/services/" + q(name) + "/" + action, { approvalCode: v.approvalCode, owner: v.owner, confirm: v.confirm }); }
        catch (e) { if (name === "console" && /Failed to fetch|NetworkError|HTTP 50[24]/.test(e.message)) { toast("콘솔이 재시작 중입니다. 잠시 후 새로고침하세요."); return; } throw e; }
        toast((svcLabel[name] || name) + " " + label + " 완료"); setTimeout(() => loadDash(true), 1500);
      }
    });
  }

  // ---------- accounts and security settings
  const FLD = ["minLength", "minClasses", "history", "maxAgeDays", "warnDays", "forbidUsername", "forbidRepeat", "forceChange", "maxFails", "windowMinutes", "lockMinutes", "ttlHours", "idleMinutes"];
  let canEditSec = false;
  async function loadSecurity() {
    try {
      const r = await api("GET", "/api/settings"), st = r.settings, f = $("#secForm");
      canEditSec = r.canEdit;
      const val = { ...st.password, ...st.lockout, ...st.session };
      FLD.forEach(k => { const i = f.elements[k]; if (i.type === "checkbox") i.checked = !!val[k]; else i.value = val[k]; i.disabled = !canEditSec; });
      f.elements.approvalCode.disabled = f.elements.owner.disabled = !canEditSec; $("#secSave").classList.toggle("hidden", !canEditSec);
      $("#secMeta").textContent = st.changedAt ? "마지막 변경: " + fmt(st.changedAt) + " · " + st.changedBy + " · 승인번호 " + (st.approval || "-") + " · 담당자 " + (st.owner || "-") : "기본값을 사용 중입니다.";
      $("#newUser").classList.toggle("hidden", !canEditSec);
    } catch (e) { toast(e.message, true); }
    loadUsers();
  }
  async function loadUsers() {
    try {
      const us = (await api("GET", "/api/users")).users, tb = $("#userTable tbody"); tb.replaceChildren();
      us.forEach(u => {
        const state = u.locked ? pill(u.lockedUntil ? "잠김 (" + fmt(u.lockedUntil) + "까지)" : "잠김 (관리자 해제 필요)", "crit") : u.mustChange ? pill("비밀번호 변경 필요", "warn") : u.expired ? pill("비밀번호 만료", "crit") : pill("정상", "ok");
        const pwText = u.pwChangedAt ? fmt(u.pwChangedAt) + (u.expiresInDays != null ? " (" + u.expiresInDays + "일 남음)" : "") : "-";
        const act = (label, op, text, withPw, cls) => el("button", { class: cls || "ghost", text: label, onclick: () => userAction(u.name, op, label, text, withPw) });
        tb.append(el("tr", null, el("td", { text: u.name }), el("td", null, state, u.failedRecent ? el("span", { class: "muted small", text: " 최근 실패 " + u.failedRecent + "회" }) : ""), el("td", { text: pwText }),
          el("td", null, u.otp ? pill("등록", "ok") : pill("미등록", "off")), el("td", { text: u.lastLogin ? fmt(u.lastLogin) + (u.lastIp ? " · " + u.lastIp : "") : "-" }),
          el("td", null, canEditSec ? [u.locked ? act("잠금 해제", "unlock", "계정의 잠금을 풀고 실패 횟수를 지웁니다.", false, "primary") : null, act("비밀번호 재설정", "reset-password", "임시 비밀번호를 지정합니다. 사용자의 로그인은 모두 종료되고 다음 로그인에서 변경해야 합니다.", true),
            u.otp ? act("OTP 초기화", "reset-otp", "OTP 등록을 지웁니다. 다음 로그인에서 다시 등록합니다.", false) : null] : null)));
      });
    } catch (e) { toast(e.message, true); }
  }
  function userAction(name, op, label, text, withPw) {
    askEvidence({ title: label + " — " + name, text, fields: [...(withPw ? [{ name: "password", label: "임시 비밀번호", type: "password", max: 128 }] : []), ...EVID],
      go: async (v) => { await api("POST", "/api/users/" + q(name) + "/" + op, { password: v.password, approvalCode: v.approvalCode, owner: v.owner }); toast(label + " 완료"); await loadUsers(); } });
  }
  $("#newUser").addEventListener("click", () => askEvidence({ title: "콘솔 계정 추가", text: "임시 비밀번호로 만들고, 사용자는 첫 로그인에서 비밀번호를 바꿉니다. 관리 권한은 「관리자」 탭에서 따로 부여합니다.",
    fields: [{ name: "name", label: "계정 이름" }, { name: "password", label: "임시 비밀번호", type: "password", max: 128 }, ...EVID],
    go: async (v) => { await api("POST", "/api/users", { name: v.name, password: v.password, approvalCode: v.approvalCode, owner: v.owner }); toast("계정을 만들었습니다"); await loadUsers(); } }));
  $("#usersRefresh").addEventListener("click", loadSecurity);
  $("#secForm").addEventListener("submit", async (e) => {
    e.preventDefault(); const f = e.target; $("#secErr").textContent = "";
    const n = (k) => parseInt(f.elements[k].value, 10), c = (k) => f.elements[k].checked;
    const body = {
      password: { minLength: n("minLength"), minClasses: n("minClasses"), history: n("history"), maxAgeDays: n("maxAgeDays"), warnDays: n("warnDays"), forbidUsername: c("forbidUsername"), forbidRepeat: c("forbidRepeat"), forceChange: c("forceChange") },
      lockout: { maxFails: n("maxFails"), windowMinutes: n("windowMinutes"), lockMinutes: n("lockMinutes") }, session: { ttlHours: n("ttlHours"), idleMinutes: n("idleMinutes") },
      approvalCode: f.elements.approvalCode.value.trim(), owner: f.elements.owner.value.trim()
    };
    try { await api("PUT", "/api/settings", body); f.elements.approvalCode.value = ""; toast("보안 설정을 저장했습니다. 즉시 적용됩니다."); await loadSecurity(); }
    catch (err) { $("#secErr").textContent = err.message; }
  });

  // ---------- boot
  (async function () {
    try { await afterLogin(); } catch (_) { showLogin(); }
  })();
})();
