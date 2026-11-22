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
    $("#app").classList.add("hidden"); $("#enroll").classList.add("hidden"); $("#login").classList.remove("hidden");
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
    try { catalog = await api("GET", "/api/catalog"); } catch (e) { toast(e.message, true); }
    try { const s = await api("GET", "/api/status"); $("#kmsInfo").textContent = "· " + (s.sealer || ""); } catch (_) { $("#kmsInfo").textContent = ""; }
    await Promise.all([loadGroups(), loadTemplates()]);
    await loadKeys();
    clearInterval(timer); timer = setInterval(() => { if (!document.hidden && !document.querySelector("dialog[open]") && currentTab === "keys") loadKeys(true); }, 20000);
  }
  async function afterLogin() {
    me = await api("GET", "/api/me");
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
    ["keys", "groups", "templates", "clients", "managers", "logs", "lifecycle"].forEach(t => $("#tab-" + t).classList.toggle("hidden", t !== currentTab));
    ({ keys: loadKeys, groups: loadGroups, templates: loadTemplates, clients: loadBindings, managers: loadManagers, logs: loadLogs })[currentTab]?.();
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

  // ---------- confirm helper
  function confirmBox({ title, text, expect, danger, run }) {
    const dlg = $("#confirmDlg"); $("#cTitle").textContent = title; $("#cText").textContent = text; $("#cErr").textContent = ""; $("#cType").value = "";
    $("#cTypeWrap").classList.toggle("hidden", !expect); $("#cExpect").textContent = expect || "";
    $("#cGo").className = danger ? "danger" : "primary";
    $("#confirmForm").onsubmit = async (e) => {
      if (e.submitter && e.submitter.value === "cancel") return;
      e.preventDefault(); $("#cErr").textContent = "";
      if (expect && $("#cType").value !== expect) { $("#cErr").textContent = "입력값이 일치하지 않습니다."; return; }
      $("#cGo").disabled = true;
      try { await run(); dlg.close(); } catch (err) { $("#cErr").textContent = err.message; } finally { $("#cGo").disabled = false; }
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
      el("div", null, el("b", { text: g.name }), el("span", { class: "muted", text: "  " + (g.description || "") }), el("br"), el("span", { class: "muted small", text: "키 " + g.keyCount + "개 · 매핑 " + g.clientCount + " · 관리자 " + g.managerCount })),
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
    f.name.value = g ? g.name : ""; f.name.readOnly = editing; f.description.value = g ? g.description : "";
    $("#gParentWrap").classList.toggle("hidden", k !== "service");
    const supers = groups.filter(x => x.kind === "super");
    fill(f.parent, [opt("", "(없음)"), ...supers.map(x => opt(x.name))]); f.parent.value = g ? (g.parent || "") : (parent || "");
    f.onsubmit = async (e) => {
      if (e.submitter && e.submitter.value === "cancel") return;
      e.preventDefault(); $("#gErr").textContent = "";
      const body = { name: f.name.value, kind: k, parent: k === "service" ? f.parent.value : "", description: f.description.value };
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
      const bt = el("table", null, el("thead", null, el("tr", null, el("th", { text: "클라이언트" }), el("th", { text: "템플릿" }), el("th"))),
        el("tbody", null, bs.map(b => el("tr", null, el("td", { text: b.client }), el("td", null, tplChips(b.template)),
          el("td", null, writer() ? el("button", { class: "ghost", text: "삭제", onclick: async () => { try { await api("DELETE", "/api/bindings?client=" + q(b.client) + "&group=" + q(b.group)); await loadBindings(); draw(); } catch (e) { $("#sErr").textContent = e.message; } } }) : null)))));
      $("#sBind").replaceChildren(bs.length ? bt : el("p", { class: "muted small", text: "매핑된 클라이언트가 없습니다." }));
      const mt = el("table", null, el("thead", null, el("tr", null, el("th", { text: "사용자" }), el("th", { text: "역할" }), el("th"))),
        el("tbody", null, ms.map(m => el("tr", null, el("td", { text: m.identity }), el("td", { text: ROLE_LABEL[m.role] || m.role }),
          el("td", null, writer() && !m.root ? el("button", { class: "ghost", text: "삭제", onclick: async () => { try { await api("DELETE", "/api/managers?identity=" + q(m.identity) + "&scope=" + q(m.scope)); await loadManagers(); draw(); } catch (e) { $("#sErr").textContent = e.message; } } }) : null)))));
      $("#sMgr").replaceChildren(ms.length ? mt : el("p", { class: "muted small", text: "이 그룹에 직접 지정된 관리자가 없습니다 (상위·전체 관리자는 포함되지 않음)." }));
    };
    const bf = $("#sBindForm"), mf = $("#sMgrForm");
    fill(bf.template, templates.map(t => opt(t.name)));
    bf.classList.toggle("hidden", !writer()); mf.classList.toggle("hidden", !writer());
    bf.onsubmit = async (e) => { e.preventDefault(); try { await api("PUT", "/api/bindings", { client: bf.client.value.trim(), group: g.name, template: bf.template.value }); bf.client.value = ""; $("#sErr").textContent = ""; await loadBindings(); draw(); } catch (err) { $("#sErr").textContent = err.message; } };
    mf.onsubmit = async (e) => { e.preventDefault(); try { await api("PUT", "/api/managers", { identity: mf.identity.value.trim(), scope: g.name, role: mf.role.value }); mf.identity.value = ""; $("#sErr").textContent = ""; await loadManagers(); draw(); } catch (err) { $("#sErr").textContent = err.message; } };
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
        global() ? el("div", { class: "actions" }, el("button", { class: "ghost", text: "수정", onclick: () => templateDialog(t) }),
          t.builtin ? null : el("button", { class: "ghost", text: "삭제", onclick: () => deleteTemplate(t) })) : null));
    });
  }
  function templateDialog(t) {
    const dlg = $("#tplDlg"), f = $("#tplForm"); f.reset(); $("#tErr").textContent = "";
    $("#tTitle").textContent = t ? "템플릿 수정 — " + t.name : "새 권한 템플릿";
    f.name.value = t ? t.name : ""; f.name.readOnly = !!t; f.description.value = t ? t.description : "";
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
      const body = { name: f.name.value, description: f.description.value, operations: ops };
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
    bindings.forEach(b => tb.append(el("tr", null, el("td", { text: b.client }), el("td", { text: b.group }), el("td", { text: b.template }), el("td", null, tplChips(b.template)),
      el("td", null, writer() ? el("button", { class: "ghost", text: "삭제", onclick: async () => { try { await api("DELETE", "/api/bindings?client=" + q(b.client) + "&group=" + q(b.group)); toast("삭제됨"); loadBindings(); } catch (e) { toast(e.message, true); } } }) : null))));
    $("#bindEmpty").classList.toggle("hidden", bindings.length > 0);
  }
  $("#bindForm").addEventListener("submit", async (e) => {
    e.preventDefault(); const f = e.target; $("#bindErr").textContent = "";
    try { await api("PUT", "/api/bindings", { client: f.client.value.trim(), group: f.group.value, template: f.template.value }); f.client.value = ""; toast("매핑됨"); await loadBindings(); }
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
    managers.forEach(m => tb.append(el("tr", null, el("td", { text: m.identity }), el("td", { text: m.scope === "ALL" ? "전체 (ALL)" : m.scope }), el("td", { text: ROLE_LABEL[m.role] || m.role }),
      el("td", null, writer() && !m.root ? el("button", { class: "ghost", text: "삭제", onclick: async () => { try { await api("DELETE", "/api/managers?identity=" + q(m.identity) + "&scope=" + q(m.scope)); toast("삭제됨"); loadManagers(); } catch (e) { toast(e.message, true); } } }) : null))));
  }
  $("#mgrForm").addEventListener("submit", async (e) => {
    e.preventDefault(); const f = e.target; $("#mgrErr").textContent = "";
    try { await api("PUT", "/api/managers", { identity: f.identity.value.trim(), scope: f.scope.value, role: f.role.value }); f.identity.value = ""; toast("부여됨"); await loadManagers(); }
    catch (err) { $("#mgrErr").textContent = err.message; }
  });

  // ---------- logs
  const LOG_HELP = {
    client: "클라이언트 포트(KMIP·클라이언트 REST)로 들어온 요청과 그 결과입니다. 관리 API 기록은 섞이지 않습니다.",
    admin: "관리 API 포트로 들어온 요청입니다. 콘솔을 통한 요청은 실제 사용자 이름과 중계 콘솔(via)이 함께 기록됩니다.",
    console: "콘솔의 로그인·로그아웃과 접속 실패 기록입니다."
  };
  let logRows = [];
  async function loadLogs() {
    $("#logHelp").textContent = LOG_HELP[curLog];
    try { const r = await api("GET", curLog === "console" ? "/api/logs/console" : "/api/logs/" + curLog + "?limit=500"); logRows = Array.isArray(r) ? r : r.entries; renderLogs(); } catch (e) { toast(e.message, true); }
  }
  function renderLogs() {
    const f = $("#logFilter").value.trim().toLowerCase();
    const tb = $("#logTable tbody"); tb.replaceChildren();
    logRows.filter(r => !f || JSON.stringify(r).toLowerCase().includes(f)).forEach(r => tb.append(el("tr", null,
      el("td", { text: fmt(r.time) }), el("td", { text: r.kind === "event" ? "이벤트" : "요청" }), el("td", { text: r.who + (r.via ? " (via " + r.via + ")" : "") }), el("td", { text: r.op }),
      el("td", { class: "id", title: r.target || "", text: r.target ? short(r.target.split(",")[0]) + (r.target.includes(",") ? " …" : "") : "" }),
      el("td", { text: r.detail || "" }), el("td", { class: r.result === "ok" ? "" : "err-cell", text: r.result }), el("td", { text: r.remote || "" }))));
  }
  document.querySelectorAll("[data-log]").forEach(b => b.addEventListener("click", () => {
    curLog = b.dataset.log; document.querySelectorAll("[data-log]").forEach(x => x.classList.toggle("active", x === b)); loadLogs();
  }));
  $("#logRefresh").addEventListener("click", loadLogs);
  $("#logFilter").addEventListener("input", renderLogs);

  // ---------- boot
  (async function () {
    try { await afterLogin(); } catch (_) { showLogin(); }
  })();
})();
