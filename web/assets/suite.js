(function () {
  "use strict";
  const $ = (s, r) => (r || document).querySelector(s);
  const $$ = (s, r) => Array.from((r || document).querySelectorAll(s));
  const reduce = matchMedia("(prefers-reduced-motion: reduce)").matches;
  const store = {
    get(k, d) { try { const v = localStorage.getItem("ip:" + k); return v === null ? d : JSON.parse(v); } catch (_) { return d; } },
    set(k, v) { try { localStorage.setItem("ip:" + k, JSON.stringify(v)); } catch (_) {} }
  };

  /* ─────────────────────────────────────────── synthetic sample data */
  const DATA = {
    kpis: [
      { id: "open",    icon: "i-search",       label: "Open findings",      value: 127, delta: "9% up",   dir: "up",   note: "vs 90 days ago" },
      { id: "new",     icon: "i-flag",         label: "New findings",       value: 67,  delta: "5% down", dir: "down", note: "vs 90 days ago" },
      { id: "closed",  icon: "i-check-circle", label: "Closed findings",    value: 235, delta: "8% down", dir: "down", note: "vs 90 days ago" },
      { id: "mttr",    icon: "i-clock",        label: "Avg time to triage", value: 390, delta: "24% up",  dir: "up",   note: "seconds, median" }
    ],
    severity: {
      all:   [{ k: "critical", n: 9, t: "9 Critical" }, { k: "high", n: 11, t: "11 High" }, { k: "medium", n: 6, t: "6 Medium" }],
      open:  [{ k: "critical", n: 6, t: "6 Critical" }, { k: "high", n: 8,  t: "8 High" },  { k: "medium", n: 3, t: "3 Medium" }],
      close: [{ k: "critical", n: 3, t: "3 Critical" }, { k: "high", n: 3,  t: "3 High" },  { k: "medium", n: 3, t: "3 Medium" }]
    },
    state: {
      all:   ["9 Pending fix", "6 In progress", "6 Reset ready"],
      open:  ["9 Pending fix", "6 In progress", "0 Reset ready"],
      close: ["0 Pending fix", "0 In progress", "6 Reset ready"]
    },
    months: [
      { m: "Jan", v: 248 }, { m: "Feb", v: 215 }, { m: "Mar", v: 230 },
      { m: "Apr", v: 325, hot: true }, { m: "May", v: 240 }, { m: "Jun", v: 250 }
    ],
    findings: [
      { ioc: "203.0.113.10",  type: "ip",   sev: "critical", src: "ThreatFox + 4",  seen: "2 min ago" },
      { ioc: "cdn.example.org", type: "domain", sev: "high", src: "URLhaus + 2",    seen: "14 min ago" },
      { ioc: "5d41402abc…f90", type: "hash", sev: "high",    src: "OTX + 3",        seen: "38 min ago" },
      { ioc: "198.51.100.42", type: "ip",   sev: "medium",   src: "AbuseIPDB + 1",  seen: "1 hr ago" },
      { ioc: "secure-login.example.com", type: "domain", sev: "medium", src: "OTX + 1", seen: "3 hrs ago" }
    ],
    surface: { score: 68, ip: 56, svc: 24 }
  };

  /* Projects, external/internal pentest and password audits came from the
     reference composition, not from this product — IntelPulse triages
     indicators, it does not run engagements. A sidebar that lists features
     nothing behind it implements is the fastest way to lose a reviewer, so
     every entry below is a view this console actually renders. */
  const NAV = [
    { group: "Posture", icon: "i-grid", open: true, items: [
      { id: "dashboard", label: "Overview" },
      { id: "surface", label: "Attack surface" },
      { id: "activity", label: "Triage history" }
    ] },
    { group: "Indicators", icon: "i-search", open: false, items: [
      { id: "triage", label: "Triage queue" },
      { id: "all-findings", label: "All indicators" }
    ] },
    { item: { id: "campaigns", label: "Campaigns", icon: "i-target", badge: "12" } },
    { item: { id: "narratives", label: "Attack narratives", icon: "i-doc" } },
    { item: { id: "sources", label: "Intelligence sources", icon: "i-globe" } },
    { item: { id: "tickets", label: "SOC tickets", icon: "i-flag" } }
  ];

  /* The weights and authority values are the ones backend/app ships. A source
     with no key configured reports "skipped" — never "clean". */
  const SOURCES = [
    { name: "AbuseIPDB",      kind: "live",    weight: 1.0,  authority: 0.80, note: "Address reputation, corroboration-weighted" },
    { name: "AlienVault OTX", kind: "live",    weight: 0.9,  authority: 0.70, note: "Community pulses, prone to syndication" },
    { name: "ThreatFox",      kind: "live",    weight: 1.2,  authority: 0.95, note: "abuse.ch — confirmed command and control" },
    { name: "URLhaus",        kind: "live",    weight: 1.1,  authority: 0.95, note: "abuse.ch — malware distribution URLs" },
    { name: "GreyNoise",      kind: "live",    weight: 0.6,  authority: 0.50, note: "Context: is this an internet-wide scanner" },
    { name: "Local blocklist",kind: "offline", weight: 1.0,  authority: 0.90, note: "Feodo Tracker and FireHOL, imported" },
    { name: "GeoIP / ASN",    kind: "offline", weight: 0.25, authority: 0.30, note: "MaxMind GeoLite2 — hosting context only" },
    { name: "CVE lookup",     kind: "offline", weight: 0,    authority: 0,    note: "Local NVD slice and the CISA KEV list" }
  ];

  const icon = (id, cls) => '<svg' + (cls ? ' class="' + cls + '"' : "") + '><use href="#' + id + '"/></svg>';

  /* ───────────────────────────────────────────────────────── theme */
  function applyTheme(mode) {
    document.documentElement.setAttribute("data-theme", mode);
    $("#theme-icon").innerHTML = '<use href="#' + (mode === "dark" ? "i-sun" : "i-moon") + '"/>';
    $("#theme-btn").setAttribute("aria-label", mode === "dark" ? "Switch to light theme" : "Switch to dark theme");
    store.set("theme", mode);
  }
  applyTheme(store.get("theme", "light"));
  $("#theme-btn").addEventListener("click", (event) => {
    const next = document.documentElement.getAttribute("data-theme") === "dark" ? "light" : "dark";
    const swap = () => { applyTheme(next); drawAll(); };
    toast(next === "dark" ? "Dark theme on" : "Light theme on");
    if (reduce || typeof document.startViewTransition !== "function") { swap(); return; }
    /* Wipe the new theme in as a circle growing out of the button itself. */
    const box = event.currentTarget.getBoundingClientRect();
    const x = box.left + box.width / 2, y = box.top + box.height / 2;
    const reach = Math.hypot(Math.max(x, innerWidth - x), Math.max(y, innerHeight - y));
    document.startViewTransition(swap).ready.then(() => {
      document.documentElement.animate(
        { clipPath: ["circle(0px at " + x + "px " + y + "px)", "circle(" + reach + "px at " + x + "px " + y + "px)"] },
        { duration: 560, easing: "cubic-bezier(.22, 1, .36, 1)", pseudoElement: "::view-transition-new(root)" }
      );
    }).catch(() => {});
  });

  /* ──────────────────────────────────────────────────────── toast */
  let toastTimer;
  function toast(message) {
    const el = $("#toast");
    el.innerHTML = icon("i-check-circle") + "<span>" + message + "</span>";
    el.classList.add("on");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => el.classList.remove("on"), 2400);
  }

  /* ─────────────────────────────────────────────── number counters */
  function countTo(node, to, suffix) {
    if (reduce) { node.textContent = to + (suffix || ""); return; }
    const start = performance.now(), from = 0, dur = 900;
    const ease = (t) => 1 - Math.pow(1 - t, 3);
    (function step(now) {
      const t = Math.min(1, (now - start) / dur);
      node.textContent = Math.round(from + (to - from) * ease(t)) + (suffix || "");
      if (t < 1) requestAnimationFrame(step);
    })(start);
  }

  /* ───────────────────────────────────────────────── chart pieces */
  function severityBar(host, key) {
    const rows = DATA.severity[key];
    const total = rows.reduce((s, r) => s + r.n, 0);
    host.innerHTML = rows.map((r) =>
      '<span class="' + r.k + '" style="flex:' + r.n + ' 1 0">' + r.t + "</span>").join("") +
      '<span class="rest" title="' + (30 - total) + ' unclassified"></span>';
  }

  function stateRow(host, key) {
    host.innerHTML = DATA.state[key].map((s) => "<div>" + s + "</div>").join("");
  }

  function gauge(host, value) {
    const pct = Math.max(0, Math.min(100, value)) / 100;
    const R = 78, CX = 105, CY = 96, W = 210, H = 118;
    const arc = (from, to, color, width) => {
      const a0 = Math.PI * (1 + from), a1 = Math.PI * (1 + to);
      const x0 = CX + Math.cos(a0) * R, y0 = CY + Math.sin(a0) * R;
      const x1 = CX + Math.cos(a1) * R, y1 = CY + Math.sin(a1) * R;
      return '<path d="M ' + x0.toFixed(1) + " " + y0.toFixed(1) + " A " + R + " " + R + " 0 0 1 " +
        x1.toFixed(1) + " " + y1.toFixed(1) + '" fill="none" stroke="' + color +
        '" stroke-width="' + width + '" stroke-linecap="round"/>';
    };
    host.innerHTML =
      '<div class="gauge"><svg viewBox="0 0 ' + W + " " + H + '" role="img" aria-label="Attack surface score ' + value + ' of 100">' +
        arc(0, 1, "var(--ground-2)", 17) +
        arc(0.52, 1, "#ffd3c4", 17) +
        arc(0, Math.max(0.03, pct * 0.72), "var(--flame)", 17) +
        '<circle cx="' + (CX + Math.cos(Math.PI * (1 + pct * 0.72)) * R).toFixed(1) + '" cy="' +
          (CY + Math.sin(Math.PI * (1 + pct * 0.72)) * R).toFixed(1) +
          '" r="7" fill="var(--paper)" stroke="var(--flame)" stroke-width="3"/>' +
      '</svg><div class="read"><b data-count="' + value + '">0</b><span>Assets</span></div></div>';
    const n = $("[data-count]", host);
    if (n) countTo(n, value);
  }

  function barChart(host, opts) {
    const max = Math.max(...DATA.months.map((m) => m.v));
    host.innerHTML = '<div class="bars">' + DATA.months.map((m) => {
      const h = Math.round((m.v / max) * 100);
      return '<div class="col' + (m.hot ? " hot" : "") + '" tabindex="0" title="' + m.m + ": " + m.v + ' assets">' +
        '<div class="stick" style="height:' + h + "%" + (opts && opts.animate === false ? "" : ";--h:" + h + "%") + '">' +
        (m.hot ? '<span class="tag">' + m.v + " assets</span>" : "") + "</div>" +
        '<span class="x">' + m.m + "</span></div>";
    }).join("") + "</div>";
  }

  function lineChart(host) {
    const series = [
      { color: "var(--flame)", pts: [22, 30, 26, 44, 58, 72, 78] },
      { color: "var(--ink)",   pts: [14, 18, 24, 30, 38, 46, 52] },
      { color: "var(--azure)", pts: [8, 11, 15, 18, 24, 29, 33] }
    ];
    const W = 320, H = 96, pad = 6;
    const path = (pts) => pts.map((p, i) => {
      const x = pad + (i / (pts.length - 1)) * (W - pad * 2);
      const y = H - pad - (p / 90) * (H - pad * 2);
      return (i ? "L" : "M") + x.toFixed(1) + " " + y.toFixed(1);
    }).join(" ");
    host.innerHTML = '<svg viewBox="0 0 ' + W + " " + H + '" style="width:100%;height:auto" role="img" aria-label="Signal strength by source over seven days">' +
      [0, 1, 2, 3].map((i) => '<line x1="0" x2="' + W + '" y1="' + (pad + i * ((H - pad * 2) / 3)) + '" y2="' +
        (pad + i * ((H - pad * 2) / 3)) + '" stroke="var(--line)" stroke-width="1"/>').join("") +
      series.map((s) => '<path d="' + path(s.pts) + '" fill="none" stroke="' + s.color +
        '" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>').join("") +
      series.map((s) => {
        const last = s.pts[s.pts.length - 1];
        return '<circle cx="' + (W - pad) + '" cy="' + (H - pad - (last / 90) * (H - pad * 2)).toFixed(1) +
          '" r="3.4" fill="' + s.color + '" stroke="var(--paper)" stroke-width="2"/>';
      }).join("") + "</svg>";
  }

  /* ───────────────────────────────────────────── console rendering */
  function sideNav(host, prefix) {
    host.innerHTML = NAV.map((entry, i) => {
      if (entry.item) {
        const it = entry.item;
        return '<button class="nav-item" data-pane="' + it.id + '" id="' + prefix + "-" + it.id + '">' +
          icon(it.icon) + "<span>" + it.label + "</span>" +
          (it.badge ? '<span class="badge-n' + (it.blue ? " blue" : "") + '">' + it.badge + "</span>" : "") +
          "</button>";
      }
      return '<button class="nav-group" aria-expanded="' + entry.open + '" data-group="' + i + '">' +
          icon(entry.icon, "i") + "<span>" + entry.group + "</span>" + icon("i-chev", "chev") +
        "</button>" +
        '<div class="sub" data-sub="' + i + '" style="height:' + (entry.open ? "auto" : "0") + '">' +
          entry.items.map((it) => '<button class="nav-item" data-pane="' + it.id + '">' +
            "<span>" + it.label + "</span></button>").join("") +
        "</div>";
    }).join("");

    $$("[data-group]", host).forEach((btn) => btn.addEventListener("click", () => {
      const sub = $('[data-sub="' + btn.dataset.group + '"]', host);
      const open = btn.getAttribute("aria-expanded") === "true";
      btn.setAttribute("aria-expanded", String(!open));
      if (open) {
        sub.style.height = sub.scrollHeight + "px";
        requestAnimationFrame(() => { sub.style.height = "0"; });
      } else {
        sub.style.height = sub.scrollHeight + "px";
        sub.addEventListener("transitionend", function done() {
          sub.style.height = "auto";
          sub.removeEventListener("transitionend", done);
        });
      }
    }));
    $$(".nav-item", host).forEach((item) => item.addEventListener("click", () => {
      $$(".nav-item", host).forEach((n) => n.removeAttribute("aria-current"));
      item.setAttribute("aria-current", "true");
      const pane = item.dataset.pane;
      if (host.id === "side-nav-full") { renderConsole(pane); openDrawer(false); }
      else { location.hash = "#/console"; setTimeout(() => renderConsole(pane), 60); }
      toast(($("span", item)?.textContent || item.textContent).trim() + " opened");
    }));
    const first = $(".nav-item", host);
    if (first) first.setAttribute("aria-current", "true");
  }

  function kpiCards() {
    return '<div class="kpis">' + DATA.kpis.map((k) =>
      '<article class="card hoverable kpi">' +
        '<div class="kpi-top"><span class="kpi-ic">' + icon(k.icon) + "</span><b>" + k.label + "</b>" +
          '<button class="kpi-more" aria-label="Options for ' + k.label + '">' + icon("i-dots") + "</button></div>" +
        '<div class="val num" data-count="' + k.value + '">0</div>' +
        '<div class="kpi-foot"><small>' + k.note + "</small>" +
          '<span class="chip ' + k.dir + '">' + icon(k.dir === "up" ? "i-up" : "i-down") + k.delta + "</span></div>" +
      "</article>").join("") + "</div>";
  }

  function panelsMarkup(compact) {
    return '<div class="panel-row">' +
      '<section class="card panel">' +
        '<div class="panel-head"><h4>Finding overview</h4>' +
          '<div class="seg" role="group" aria-label="Filter findings">' +
            '<button data-filter="all" aria-pressed="true">All</button>' +
            '<button data-filter="open" aria-pressed="false">Open</button>' +
            '<button data-filter="close" aria-pressed="false">Close</button></div></div>' +
        '<div class="label-xs">Severity</div><div class="sev" data-sev></div>' +
        '<div class="label-xs" style="margin-top:14px">State</div><div class="state-row" data-state></div>' +
        (compact ? "" : '<div class="label-xs" style="margin-top:18px">Latest</div>' +
          '<div class="table-wrap"><table class="table"><thead><tr><th>Indicator</th><th>Type</th><th>Severity</th><th>Sources</th><th>Seen</th></tr></thead><tbody>' +
          DATA.findings.map((f) => '<tr><td class="mono" title="' + f.ioc + '">' + f.ioc + "</td><td>" + f.type +
            '</td><td><span class="pill-sev ' + f.sev + '">' + f.sev + "</span></td><td>" + f.src +
            '</td><td style="color:var(--ink-3)">' + f.seen + "</td></tr>").join("") + "</tbody></table></div>") +
      "</section>" +
      '<section class="card panel">' +
        '<div class="panel-head"><h4>Attack surface</h4>' +
          '<button class="kpi-more" aria-label="Panel options">' + icon("i-dots") + "</button></div>" +
        '<div data-gauge></div>' +
        '<div class="legend-row"><i style="background:var(--flame)"></i> IP addresses <span class="n">' + DATA.surface.ip + "</span></div>" +
        '<div class="legend-row"><i style="background:#ffd3c4"></i> Services <span class="n">' + DATA.surface.svc + "</span></div>" +
        (compact ? "" : '<div class="label-xs" style="margin-top:14px">Assets over time</div><div data-bars></div>') +
      "</section></div>";
  }

  function wirePanels(scope) {
    const sev = $("[data-sev]", scope), st = $("[data-state]", scope);
    if (sev) severityBar(sev, "all");
    if (st) stateRow(st, "all");
    const g = $("[data-gauge]", scope);
    if (g) gauge(g, DATA.surface.score);
    const b = $("[data-bars]", scope);
    if (b) barChart(b);
    $$(".seg button", scope).forEach((btn) => btn.addEventListener("click", () => {
      const group = btn.parentElement;
      $$("button", group).forEach((x) => x.setAttribute("aria-pressed", String(x === btn)));
      const key = btn.dataset.filter;
      const host = group.closest(".card") || scope;
      const s = $("[data-sev]", host) || $("#sev-landing");
      const t = $("[data-state]", host) || $("#state-landing");
      if (s) severityBar(s, key);
      if (t) stateRow(t, key);
      toast(btn.textContent + " findings");
    }));
    $$("[data-count]", scope).forEach((n) => countTo(n, Number(n.dataset.count)));
  }

  function sourcesMarkup() {
    const row = (src) => '<tr><td><strong>' + src.name + "</strong><br>" +
      '<span style="color:var(--ink-3);font-size:11.5px">' + src.note + "</span></td>" +
      '<td><span class="tag ' + src.kind + '">' + src.kind + "</span></td>" +
      '<td class="mono">' + (src.weight ? src.weight.toFixed(2) : "\u2014") + "</td>" +
      '<td class="mono">' + (src.authority ? src.authority.toFixed(2) : "\u2014") + "</td></tr>";
    return '<section class="card panel">' +
      '<div class="panel-head"><h4>Every source, and what its word is worth</h4></div>' +
      '<p style="color:var(--ink-2);font-size:12.5px;margin-bottom:12px">Weight decides how much a source ' +
      'moves the weighted mean. Authority decides how high it can hold the score on its own — one confirmed ' +
      'ThreatFox listing still reads critical when four quiet sources disagree.</p>' +
      '<div class="table-wrap"><table class="table"><thead><tr><th>Source</th><th>Kind</th>' +
      "<th>Weight</th><th>Authority</th></tr></thead><tbody>" +
      SOURCES.map(row).join("") + "</tbody></table></div>" +
      '<p style="color:var(--ink-3);font-size:11.5px;margin-top:12px">A source with no API key configured ' +
      "reports <code>skipped</code>. It never reports <em>clean</em> \u2014 the difference matters when " +
      "someone reads the ticket six months later.</p></section>";
  }

  /* Every pane below is a view this console renders from the loaded dataset.
     Nothing here is a label over an empty room. */
  const PANES = {
    dashboard: () => ({ title: "Welcome back, analyst", sub: "Remediation efficacy and the attack surface, as of this morning.", body: kpiCards() + panelsMarkup(false) }),
    surface:   () => ({ title: "Attack surface", sub: "What is reachable, and how much of it is scored.", body: panelsMarkup(false) }),
    activity:  () => ({ title: "Triage history", sub: "Every triage this workspace has run, newest first.", body: panelsMarkup(true) }),
    triage:    () => ({ title: "Triage queue", sub: "What needs an analyst next, sorted by composite score.", body: kpiCards() + panelsMarkup(true) }),
    "all-findings": () => ({ title: "All indicators", sub: "Every indicator across every open case.", body: panelsMarkup(false) }),
    campaigns: () => ({ title: "Campaigns", sub: "12 campaigns correlated from the current indicator set.", body: panelsMarkup(true) }),
    narratives:() => ({ title: "Attack narratives", sub: "The story each campaign tells, in order.", body: kpiCards() }),
    sources:   () => ({ title: "Intelligence sources", sub: "The weight and the authority behind every verdict.", body: sourcesMarkup() }),
    tickets:   () => ({ title: "SOC tickets", sub: "Generated tickets and the evidence exported with them.", body: kpiCards() })
  };

  function renderConsole(pane) {
    const spec = (PANES[pane] || PANES.dashboard)();
    const host = $("#console-body");
    host.innerHTML =
      '<header class="console-head route">' +
        "<div><h3>" + spec.title + (pane === "dashboard" ? ' <span aria-hidden="true">👋</span>' : "") +
          "</h3><p>" + spec.sub + "</p></div>" +
        /* Gone from here: a notification bell with nothing behind it, an avatar
           for an account that does not exist, and a "Testing status: Active"
           pill that reported on nothing. What is left either works or states a
           fact about the data. */
        '<div class="head-right">' +
          '<button class="round-btn" id="c-search" aria-label="Ask the assistant">' + icon("i-search") + "</button>" +
          '<a class="btn btn-dark btn-sm" href="workbench.html">Live triage' + icon("i-arrow") + "</a>" +
          '<span class="status-pill">Sample data <span class="on">synthetic</span></span>' +
          '<button class="round-btn" id="c-collapse" aria-label="Collapse sidebar">' + icon("i-sidebar") + "</button>" +
        "</div>" +
      "</header>" + '<div class="route">' + spec.body + "</div>";
    wirePanels(host);
    // It used to toast "Search is a demo control". It opens the assistant now,
    // which is the thing on this page that actually answers a question.
    $("#c-search").addEventListener("click", () => window.IntelPulseAssistant?.open(true));
    $("#c-collapse").addEventListener("click", () => {
      /* Wide enough for two columns: collapse the rail to icons. Narrow: the
         rail is a drawer, so the same button opens it. */
      if (narrow.matches) { openDrawer(true); return; }
      $("#console-full").classList.toggle("compact");
      toast($("#console-full").classList.contains("compact") ? "Sidebar collapsed" : "Sidebar expanded");
    });
    $("#c-collapse").setAttribute("aria-label", narrow.matches ? "Open the menu" : "Collapse sidebar");
  }

  function renderPreview() {
    const host = $("#console-preview");
    host.innerHTML =
      '<header class="console-head">' +
        '<div><h3>Welcome back, analyst <span aria-hidden="true">👋</span></h3>' +
        "<p>Remediation efficacy and the attack surface, as of this morning.</p></div>" +
        '<div class="head-right"><span class="status-pill">Sample data <span class="on">synthetic</span></span></div>' +
      "</header>" + kpiCards() + panelsMarkup(true);
    wirePanels(host);
  }

  /* ─────────────────────────────────────────────────────── routing */
  /* ───────────────────────────────── drawers: the console rail, the nav menu */
  const narrow = matchMedia("(max-width: 900px)");

  function openDrawer(open) {
    const shell = $("#console-full");
    if (!shell) return;
    shell.classList.toggle("drawer", open);
    $("#drawer-scrim").classList.toggle("on", open);
    document.body.style.overflow = open ? "hidden" : "";
    if (open) $(".nav-item", $("#side-nav-full"))?.focus();
  }
  $("#drawer-scrim").addEventListener("click", () => openDrawer(false));
  $("#side-close").addEventListener("click", () => openDrawer(false));

  function openMenu(open) {
    $("#menu").classList.toggle("on", open);
    $("#menu-scrim").classList.toggle("on", open);
    $("#burger").setAttribute("aria-expanded", String(open));
    $("#burger-icon").innerHTML = '<use href="#' + (open ? "i-close" : "i-menu") + '"/>';
    $("#burger").setAttribute("aria-label", open ? "Close the menu" : "Open the menu");
    if (open) $("a", $("#menu"))?.focus();
  }
  $("#burger").addEventListener("click", () => openMenu(!$("#menu").classList.contains("on")));
  $("#menu-scrim").addEventListener("click", () => openMenu(false));
  $$("#menu a, #menu button").forEach((el) => el.addEventListener("click", () => openMenu(false)));

  /* Going back to two columns must not leave a drawer stranded open. */
  narrow.addEventListener("change", (event) => {
    if (!event.matches) { openDrawer(false); openMenu(false); }
    const collapse = $("#c-collapse");
    if (collapse) collapse.setAttribute("aria-label", event.matches ? "Open the menu" : "Collapse sidebar");
  });

  addEventListener("keydown", (event) => {
    if (event.key !== "Escape") return;
    if ($("#menu").classList.contains("on")) { openMenu(false); $("#burger").focus(); }
    if ($("#console-full")?.classList.contains("drawer")) { openDrawer(false); }
  });

  function route() {
    const toConsole = location.hash.startsWith("#/console");
    $("#page-home").hidden = toConsole;
    $("#page-console").hidden = !toConsole;
    const label = toConsole ? "Back to site" : "Open console";
    [$("#nav-cta"), $("#menu-cta")].forEach((cta) => {
      cta.dataset.route = toConsole ? "home" : "console";
      cta.innerHTML = label + '<svg><use href="#i-arrow"/></svg>';
    });
    if (toConsole) {
      renderConsole($(".nav-item[aria-current='true']", $("#side-nav-full"))?.dataset.pane || "dashboard");
      $("#page-console").classList.remove("route"); void $("#page-console").offsetWidth;
      $("#page-console").classList.add("route");
    }
    openDrawer(false);
    openMenu(false);
    window.scrollTo({ top: 0, behavior: reduce ? "auto" : "smooth" });
  }
  addEventListener("hashchange", route);

  document.addEventListener("click", (event) => {
    const routeBtn = event.target.closest("[data-route]");
    if (routeBtn) {
      event.preventDefault();
      const want = routeBtn.dataset.route === "console" ? "#/console" : "#/home";
      const here = location.hash.startsWith("#/console") ? "#/console" : "#/home";
      /* Already there: the link still has a job — take the reader back to the top. */
      if (want === here) scrollTo({ top: 0, behavior: reduce ? "auto" : "smooth" });
      else location.hash = want;
      return;
    }
    const more = event.target.closest(".kpi-more");
    if (more) { toast("Panel menu is a demo control"); return; }
    const scrollBtn = event.target.closest("[data-scroll]");
    if (scrollBtn) {
      event.preventDefault();
      if (location.hash.startsWith("#/console")) location.hash = "#/home";
      setTimeout(() => {
        const target = $(scrollBtn.dataset.scroll);
        if (target) target.scrollIntoView({ behavior: reduce ? "auto" : "smooth", block: "start" });
      }, 80);
    }
  });

  /* ────────────────────────────────────── feature cards, mail, misc */
  $$("#features .feature").forEach((card) => card.addEventListener("click", () => {
    $$("#features .feature").forEach((c) => c.setAttribute("aria-pressed", String(c === card)));
    toast($("h3", card).textContent + " — highlighted");
  }));

  $("#mail-form").addEventListener("submit", (event) => {
    event.preventDefault();
    const input = $("#mail"), note = $("#mail-note");
    const ok = /^[^\s@]+@[^\s@]+\.[a-z]{2,}$/i.test(input.value.trim());
    input.setAttribute("aria-invalid", String(!ok));
    note.textContent = ok ? "Thanks — you are on the list." : "That does not look like an email address.";
    note.style.color = ok ? "var(--ink-3)" : "var(--flame)";
    if (ok) { toast("Subscribed with " + input.value.trim()); input.value = ""; }
  });

  /* ───────────────────────────────────── scroll: progress, reveal, parallax */
  const observer = new IntersectionObserver((entries) => {
    entries.forEach((entry) => { if (entry.isIntersecting) { entry.target.classList.add("in"); observer.unobserve(entry.target); } });
  }, { rootMargin: "0px 0px -8% 0px", threshold: 0.08 });
  $$(".rise").forEach((node, i) => { node.style.transitionDelay = Math.min(i * 40, 240) + "ms"; observer.observe(node); });

  let lastY = 0;
  function onScroll() {
    const y = scrollY;
    const max = document.body.scrollHeight - innerHeight;
    $("#progress").style.width = (max > 0 ? (y / max) * 100 : 0) + "%";
    $("#nav").classList.toggle("hide", y > lastY && y > 220);
    $("#to-top").classList.toggle("on", y > 520);
    lastY = y;
    if (!reduce) {
      $$(".cloud").forEach((cloud) => {
        const depth = Number(cloud.dataset.depth || 0.2);
        cloud.style.transform = "translate3d(0," + (y * depth).toFixed(1) + "px,0)";
      });
      const preview = $("#preview");
      if (preview) preview.classList.toggle("flat", y > 120);
    }
  }
  addEventListener("scroll", onScroll, { passive: true });

  $("#to-top").addEventListener("click", () => scrollTo({ top: 0, behavior: reduce ? "auto" : "smooth" }));

  /* ── the sources rail: one run scrolls out while its twin scrolls in, so the
     loop never shows a seam. Drag, wheel and arrow keys all move it by hand. */
  (function sideScroller() {
    const rail = $("#marquee"), run = $(".mq-run", rail);
    let hold = false, drag = null;
    const pause = () => { hold = true; }, resume = () => { hold = false; };
    rail.addEventListener("pointerenter", pause);
    rail.addEventListener("pointerleave", resume);
    rail.addEventListener("focusin", pause);
    rail.addEventListener("focusout", resume);
    rail.addEventListener("pointerdown", (event) => {
      drag = { x: event.clientX, from: rail.scrollLeft };
      rail.setPointerCapture(event.pointerId);
      rail.classList.add("grabbing");
    });
    rail.addEventListener("pointermove", (event) => {
      if (drag) rail.scrollLeft = drag.from - (event.clientX - drag.x);
    });
    const release = () => { drag = null; rail.classList.remove("grabbing"); };
    rail.addEventListener("pointerup", release);
    rail.addEventListener("pointercancel", release);

    /* Chromium snaps a programmatic scrollLeft to whole pixels, so writing
       "+= 0.4" every frame would round straight back and never move. Carry the
       position in a float and write that; resync whenever something else
       (a drag, the wheel, arrow keys) moves the rail out from under us. */
    let pos = 0, applied = -1;
    (function step() {
      const span = run.getBoundingClientRect().width;
      if (span > 0) {
        if (applied < 0 || Math.abs(rail.scrollLeft - applied) > 1.5) pos = rail.scrollLeft;
        if (!hold && !drag && !reduce) pos += 0.4;
        /* Three identical runs: stay inside the middle one so a shift of exactly
           one run is invisible, and neither edge can hit the scroll clamp. */
        if (pos >= span * 2) pos -= span;
        else if (pos < span * 0.5) pos += span;
        rail.scrollLeft = pos;
        applied = rail.scrollLeft;
      }
      requestAnimationFrame(step);
    })();
  })();

  /* The preview is a device mock: render it at its real width, then scale it
     to the frame so the internals keep their true proportions. */
  function fitPreview() {
    const frame = $("#preview"), scaler = $("#preview-scaler");
    if (!frame || !scaler) return;
    const scale = Math.min(1, frame.clientWidth / 1180);
    scaler.style.transform = "scale(" + scale.toFixed(4) + ")";
    frame.style.height = Math.round(scaler.scrollHeight * scale) + "px";
  }
  addEventListener("resize", fitPreview);

  /* ────────────────────────────────────────────────────────── boot */
  function drawAll() {
    severityBar($("#sev-landing"), "all");
    stateRow($("#state-landing"), "all");
    gauge($("#gauge-landing"), DATA.surface.score);
    barChart($("#bars-showcase"));
    barChart($("#bento-bars"));
    lineChart($("#bento-line"));
    renderPreview();
    requestAnimationFrame(fitPreview);
    if (!$("#page-console").hidden) renderConsole("dashboard");
  }

  sideNav($("#side-nav-preview"), "pv");
  sideNav($("#side-nav-full"), "full");
  drawAll();
  $$("#page-home .seg button").forEach((btn) => btn.addEventListener("click", () => {
    const group = btn.parentElement;
    $$("button", group).forEach((x) => x.setAttribute("aria-pressed", String(x === btn)));
    severityBar($("#sev-landing"), btn.dataset.filter);
    stateRow($("#state-landing"), btn.dataset.filter);
  }));
  route();
  onScroll();
  fitPreview();
  addEventListener("load", fitPreview);

  /* ══════════════════════════════════════════════════════════ assistant
     A help panel, and deliberately not a chat bot. Every answer below is
     assembled here in the browser from two sources: this project's own
     documentation (the scoring constants are the same numbers backend/app
     ships) and the sample dataset already loaded on this page. There is no
     model call and no network request, which is why the panel says so in
     writing rather than leaving you to guess. Where an answer would be a
     guess, it says it does not know and offers the topics it does have. */
  (function assistant() {
    const esc = (t) => String(t).replace(/[&<>"']/g, (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
    const sev = (key) => DATA.severity[key].map((b) => b.n + " " + b.k).join(", ");
    const total = (key) => DATA.severity[key].reduce((n, b) => n + b.n, 0);

    /* label → what pressing it does. Kept as data so the answer HTML never
       has to carry a function or an inline handler past the CSP. */
    const ACT = {
      console: ["Open the console", () => { location.hash = "#/console"; }],
      workbench: ["Open the workbench", () => { location.href = "workbench.html"; }],
      graph: ["Open the campaign graph", () => { location.href = "explorer.html"; }],
      scoring: ["Show the scoring section", () => jump("#scoring")],
      how: ["Show how it correlates", () => jump("#how")],
      evidence: ["Show the evidence view", () => jump("#evidence")],
      sources: ["Show the sources", () => jump("#sources")],
      theme: ["Switch the theme", () => $("#theme-btn").click()]
    };
    function jump(sel) {
      if (location.hash.startsWith("#/console")) location.hash = "#/home";
      setTimeout(() => $(sel)?.scrollIntoView({ behavior: reduce ? "auto" : "smooth", block: "start" }), 90);
    }

    const KB = [
      { id: "what",
        keys: ["what is intelpulse", "what does it do", "what is this", "tell me about intelpulse", "intelpulse", "overview", "purpose"],
        html: "<p><strong>IntelPulse correlates one alert across every intelligence source in a single pass.</strong></p>" +
              "<p>Paste an indicator list, a raw syslog line or a JSON alert export. It pulls the indicators out, " +
              "queries every applicable source concurrently, scores them into one auditable verdict, maps how they " +
              "relate, and writes the SOC ticket at the end of it.</p>" +
              "<p>The usual cost of that is six browser tabs per alert. This is one request.</p>",
        acts: ["how", "workbench"] },

      { id: "scoring",
        keys: ["scoring", "score", "scored", "formula", "math", "arithmetic", "calculate", "calculated", "computed", "weighted mean", "how does scoring work"],
        html: "<p>A source never decides on its own. Every provider is normalised to a 0–1 signal, then:</p>" +
              "<pre>score = 100 × max(\n    Σ(weight × signal) / Σ(weight),   ← weighted mean, over the\n                                     providers that ANSWERED\n    max(signal × authority)          ← authority floor\n)</pre>" +
              "<p>The weighted mean is the consensus. The authority floor is the safety net: one confirmed " +
              "ThreatFox C2 listing still reads critical even when four quiet sources drag the mean down.</p>",
        acts: ["scoring", "workbench"], src: "backend/app/scoring.py · docs/SCORING.md" },

      { id: "authority",
        keys: ["authority", "authority floor", "floor", "trust", "how much do you trust"],
        html: "<p>Each source carries an authority value — how much one confirmed hit from it is worth on its own:</p>" +
              "<ul><li>ThreatFox <code>0.95</code> · URLhaus <code>0.95</code> — confirmed C2 / distribution</li>" +
              "<li>Local blocklist <code>0.90</code> — curated historical feeds</li>" +
              "<li>AbuseIPDB <code>0.80</code> — crowd-sourced, corroboration-weighted</li>" +
              "<li>AlienVault OTX <code>0.70</code> — community pulses, prone to syndication</li>" +
              "<li>GreyNoise <code>0.50</code> — context more than verdict</li>" +
              "<li>GeoIP <code>0.30</code> — hosting context only</li></ul>" +
              "<p>The floor is <code>max(signal × authority)</code>. It is why a single trustworthy hit cannot be averaged away.</p>",
        acts: ["scoring"], src: "backend/app/scoring.py" },

      { id: "weights",
        keys: ["weights", "weighting", "how much does each source count"],
        html: "<p>The weights in the mean: ThreatFox <code>1.2</code>, URLhaus <code>1.1</code>, " +
              "AbuseIPDB <code>1.0</code>, local blocklist <code>1.0</code>, OTX <code>0.9</code>, " +
              "GreyNoise <code>0.6</code>, GeoIP/ASN <code>0.25</code>.</p>" +
              "<p>They are configuration, not constants baked into the logic, and the API returns them with " +
              "the verdict — so any score can be reproduced from the evidence that produced it.</p>",
        src: "backend/app/config.py" },

      { id: "verdict",
        keys: ["verdict", "bands", "thresholds", "how high is high", "what counts as critical", "what makes it critical"],
        html: "<p>Bands on the 0–100 composite:</p>" +
              "<ul><li><strong>critical</strong> — 85 and above</li><li><strong>high</strong> — 70 to 84</li>" +
              "<li><strong>medium</strong> — 40 to 69</li><li><strong>low</strong> — 15 to 39</li>" +
              "<li><strong>informational</strong> — below 15</li></ul>" +
              "<p>Severity is never carried by colour alone anywhere in this interface — every band is labelled.</p>",
        src: "backend/app/scoring.py" },

      { id: "confidence",
        keys: ["confidence", "confident", "how confident", "how sure", "certainty", "reliable", "how confident are you"],
        html: "<p>Confidence is reported <strong>separately from the score</strong>, because 85/100 from one " +
              "source is not 85/100 from five.</p>" +
              "<p>It is built from coverage (how many applicable sources actually answered) and agreement " +
              "(how close their signals are), so a lone verdict reads as a lone verdict rather than as certainty.</p>",
        src: "docs/SCORING.md" },

      { id: "modifiers",
        keys: ["modifiers", "greynoise benign", "benign", "allowlist", "blocklist", "allow list", "block list", "noise", "false positive"],
        html: "<p>After the composite, the adjustments an analyst would make by hand:</p>" +
              "<ul><li><strong>GreyNoise says benign</strong> — score × 0.45. Mass scanners are noise, not a campaign.</li>" +
              "<li><strong>On the allowlist</strong> — forced to 0.</li>" +
              "<li><strong>On the blocklist</strong> — floored at 90.</li></ul>" +
              "<p>Each applied modifier is listed on the indicator, so nothing moves the number invisibly.</p>",
        acts: ["workbench"], src: "backend/app/scoring.py" },

      { id: "sources",
        keys: ["sources", "vendors", "providers", "apis", "which services", "who do you query", "third party"],
        html: "<p>Live sources, all queried concurrently:</p>" +
              "<ul><li><strong>AbuseIPDB</strong> — address reputation</li><li><strong>AlienVault OTX</strong> — campaign pulses</li>" +
              "<li><strong>GreyNoise</strong> — is this just an internet-wide scanner</li>" +
              "<li><strong>ThreatFox</strong> (abuse.ch) — confirmed C2</li><li><strong>URLhaus</strong> (abuse.ch) — malware distribution URLs</li></ul>" +
              "<p>A source with no key configured reports <code>skipped</code>. It never reports <em>clean</em> — " +
              "the difference matters when someone reads the ticket later.</p>",
        acts: ["sources"], src: "docs/API.md" },

      { id: "offline",
        keys: ["offline", "feodo", "firehol", "kev", "cisa", "nvd", "cve", "geolite", "maxmind", "geoip", "no keys", "without api keys"],
        html: "<p>It still works with no API keys at all. The offline datasets carry the triage:</p>" +
              "<ul><li><strong>Feodo Tracker</strong> and <strong>FireHOL</strong> — historical C2 and blocklists</li>" +
              "<li><strong>CISA KEV</strong> — known exploited vulnerabilities</li>" +
              "<li><strong>NVD slice</strong> — local CVE lookups</li>" +
              "<li><strong>MaxMind GeoLite2</strong> — hosting and ASN context</li></ul>" +
              "<p>Import them with <code>make feeds</code>.</p>",
        acts: ["sources"] },

      { id: "ioctypes",
        keys: ["ioc", "what can i paste", "what can it read", "input", "formats", "hash", "domain", "url", "syslog", "json", "refang", "defang"],
        html: "<p>Paste whatever the alert actually gave you:</p>" +
              "<ul><li>IPv4 and IPv6 addresses</li><li>Domains and URLs, defanged or not (<code>hxxp://bad[.]top</code> is fine)</li>" +
              "<li>MD5 / SHA1 / SHA256 hashes</li><li>CVE identifiers</li><li>Raw syslog lines and JSON alert exports</li></ul>" +
              "<p>Private, loopback, CGNAT and documentation ranges are dropped before any lookup leaves the machine.</p>",
        acts: ["workbench"], src: "backend/app/ioc.py" },

      { id: "triage",
        keys: ["run a triage", "how do i run", "try it", "get started", "start", "use it", "paste an alert", "demo"],
        html: "<p>The workbench is the tool: paste into the ingest box, press <code>⌘↵</code>, and the " +
              "indicators, the evidence behind each score, the graph and the ticket all appear together.</p>" +
              "<p>The console here is the posture view over the same dataset — metrics, severity split, attack surface.</p>",
        acts: ["workbench", "console"] },

      { id: "graph",
        keys: ["graph", "relationship", "campaign", "network", "map", "visualise", "visualize", "explorer"],
        html: "<p>The relationship graph is where the point of a correlation tool shows up: shared infrastructure " +
              "between two malware families is a picture, not a table.</p>" +
              "<p>Hub-to-cluster edges alone would only make a star — the cross-links between clusters are the part " +
              "worth looking at.</p>",
        acts: ["graph", "workbench"] },

      { id: "ticket",
        keys: ["ticket", "report", "jira", "servicenow", "markdown", "export", "output", "soc ticket"],
        html: "<p>Every triage ends in a ticket written to be pasted straight into Jira or ServiceNow: severity " +
              "with a priority SLA, an executive summary, what each source said in its own words, the MITRE ATT&amp;CK " +
              "techniques the evidence actually supports, and a containment checklist scoped to the indicator type.</p>" +
              "<p>Indicators are defanged in the report, so a ticket comment can never be click-through.</p>",
        acts: ["workbench"], src: "backend/app/reporting.py" },

      { id: "data",
        keys: ["real data", "is this real", "synthetic", "fake", "sample data", "dataset", "made up", "where does this data come from"],
        html: "<p>Everything on this page is <strong>synthetic</strong>. The addresses are RFC 5737 documentation " +
              "ranges (<code>203.0.113.0/24</code>, <code>198.51.100.0/24</code>) and the domains are RFC 2606 " +
              "reserved names. Nothing here describes a real host, and no vendor API is called in demo mode.</p>" +
              "<p>Point the workbench at a running backend and the same screens are driven by real responses.</p>",
        acts: ["workbench"] },

      { id: "privacy",
        keys: ["privacy", "private", "leave", "send", "track", "tracking", "telemetry", "upload", "does anything leave"],
        html: "<p>Nothing leaves this tab. The page has no analytics, no telemetry and no backend — the demo " +
              "engine is a JavaScript port of the Python scoring module, running in your browser.</p>" +
              "<p>This assistant is the same: it matches your question against a list of topics compiled into the " +
              "page and reads the dataset already loaded. No model is called.</p>" },

      { id: "security",
        keys: ["security", "ssrf", "xss", "csp", "rate limit", "hardening", "safe", "injection", "secure"],
        html: "<p>A tool that renders attacker-controlled text has to assume the text is hostile:</p>" +
              "<ul><li><strong>Egress is allowlisted</strong> — twelve known hosts, HTTPS only, every resolved " +
              "address checked against private, loopback, link-local and metadata space, on redirects too</li>" +
              "<li><strong>Output is encoded</strong>, with a CSP behind it that forbids inline script</li>" +
              "<li><strong>Sliding-window rate limits</strong> per bucket, and bounded request bodies</li>" +
              "<li><strong>Logs mask credentials</strong> before anything is written</li></ul>" +
              "<p>Each control has a test that proves it — 63 on the backend alone.</p>",
        src: "docs/SECURITY.md" },

      { id: "live",
        keys: ["live api", "backend", "docker", "self host", "run locally", "install", "deploy", "compose"],
        html: "<p><code>docker compose up --build</code> brings up the API on <code>:8000</code> and the dashboard " +
              "on <code>:8080</code>. Switch the workbench to <strong>Live API</strong>, point it at the backend, and " +
              "the same screens run on real AbuseIPDB / OTX / GreyNoise / abuse.ch responses.</p>" +
              "<p>FastAPI, async httpx, Celery, Redis, PostgreSQL.</p>",
        acts: ["workbench"] },

      { id: "shortcuts",
        keys: ["shortcuts", "keyboard", "hotkey", "command palette"],
        html: "<p>On this page: <code>?</code> opens this assistant, <code>Esc</code> closes whatever is open.</p>" +
              "<p>In the workbench: <code>⌘K</code> for the command palette, <code>⌘↵</code> to run a triage, " +
              "<code>/</code> to focus the ingest box, <code>g i</code> / <code>g g</code> / <code>g t</code> / " +
              "<code>g h</code> to jump between views, <code>t</code> to cycle the theme.</p>",
        acts: ["workbench"] },

      { id: "theme",
        keys: ["theme", "dark mode", "light mode", "dark", "light", "night"],
        html: "<p>The button beside the logo switches it, and the choice is remembered. Where the browser supports " +
              "View Transitions the new theme wipes in as a circle growing out of the button itself.</p>" +
              "<p>Under <code>prefers-reduced-motion</code> the swap is instant and every other animation on the page stops.</p>",
        acts: ["theme"] },

      { id: "tests",
        keys: ["tests", "tested", "quality", "how is it tested", "coverage"],
        html: "<p>63 backend tests (extraction, scoring, API contract, reports, security controls), 21 node tests " +
              "(the JavaScript engine pinned to the Python rules, plus design-system guards), and browser suites " +
              "that drive a real Chromium.</p>" +
              "<p>One of them clicks every visible button on this page and fails if any of them does nothing.</p>" },

      { id: "stack",
        keys: ["stack", "built with", "technology", "tech", "framework", "language"],
        html: "<p>Backend: FastAPI, async httpx with concurrent fan-out, SQLAlchemy 2.0, Celery + Redis, PostgreSQL " +
              "(SQLite for local runs).</p>" +
              "<p>Front end: no framework and no build step. Plain HTML, a CSS custom-property token system and " +
              "vanilla JavaScript — a reviewer clones the repo and opens the file.</p>" },

      { id: "author",
        keys: ["who built", "author", "vinit", "rami", "contact", "portfolio", "hire"],
        html: "<p>Built by Vinit Rami as part of a defensive-security portfolio. The source, the design notes and " +
              "the security write-up are all in the repository.</p>" },

      /* ── answers computed from the dataset on the page, not written by hand */
      { id: "now",
        keys: ["how many findings", "current findings", "right now", "summary", "how many", "status", "overview of findings", "severity split"],
        live: () => "<p>On the dataset loaded here: <strong>" + total("all") + " findings</strong> — " + sev("all") + ".</p>" +
              "<p>By state: " + DATA.state.all.join(", ").toLowerCase() + ". Open cases account for " +
              total("open") + " of them (" + sev("open") + ").</p>",
        acts: ["console"], src: "the sample dataset on this page" },

      { id: "criticals",
        keys: ["critical findings", "what is critical", "worst indicators", "worst findings", "most severe", "show me the critical", "which indicators", "list the indicators", "list findings", "top findings", "worst"],
        live: () => {
          const rows = DATA.findings.filter((f) => f.sev === "critical" || f.sev === "high");
          return "<p>The " + rows.length + " indicators at high or critical in this sample:</p><ul>" +
            rows.map((f) => "<li><code>" + esc(f.ioc) + "</code> — " + f.sev + ", " + esc(f.src) +
              ", seen " + esc(f.seen) + "</li>").join("") + "</ul>" +
            "<p>All of them are RFC 5737 / RFC 2606 placeholders. None is a real host.</p>";
        },
        acts: ["console"], src: "the sample dataset on this page" },

      { id: "surface",
        keys: ["attack surface", "surface", "exposure", "exposed", "assets", "gauge"],
        live: () => "<p>The attack-surface score here is <strong>" + DATA.surface.score + "</strong>, over " +
              (DATA.surface.ip + DATA.surface.svc) + " assets — " + DATA.surface.ip + " IP addresses and " +
              DATA.surface.svc + " services.</p>" +
              "<p>It is a posture number, not a verdict: it says how much is reachable, not how bad any one thing is.</p>",
        acts: ["console"], src: "the sample dataset on this page" },

      { id: "metrics",
        keys: ["kpis", "metrics", "mttr", "time to triage", "how fast", "closed findings"],
        live: () => "<p>" + DATA.kpis.map((k) => "<strong>" + esc(k.label) + "</strong> " + k.value +
              " (" + esc(k.delta) + ", " + esc(k.note) + ")").join("<br>") + "</p>" +
              "<p>Median time to triage is the one worth watching — it is the number the whole tool exists to move.</p>",
        acts: ["console"], src: "the sample dataset on this page" },

      { id: "trend",
        keys: ["trend", "over time", "months", "busiest", "history", "assets over time"],
        live: () => {
          const peak = DATA.months.reduce((a, b) => (b.v > a.v ? b : a));
          return "<p>Assets over the last six months: " + DATA.months.map((m) => esc(m.m) + " " + m.v).join(", ") +
            ".</p><p><strong>" + esc(peak.m) + "</strong> is the peak at " + peak.v +
            " — the month worth asking a question about.</p>";
        },
        acts: ["console"], src: "the sample dataset on this page" }
    ];

    const CHIPS = [
      "How is the score calculated?",
      "What sources do you query?",
      "Is this real data?",
      "What is critical right now?",
      "How do I run a triage?",
      "What about SSRF and rate limits?"
    ];

    const norm = (t) => t.toLowerCase().replace(/[^a-z0-9+ ]+/g, " ").replace(/\s+/g, " ").trim();
    function match(question) {
      const text = norm(question);
      if (!text) return null;
      const words = text.split(" ");
      let best = null, high = 0;
      for (const entry of KB) {
        let score = 0;
        for (const key of entry.keys) {
          /* Longer phrases are more specific, so they outrank short ones: without
             this, "what is critical right now" tied between the findings summary
             and the critical list purely on KB order. */
          if (key.includes(" ")) { if (text.includes(key)) score += 1.2 + key.length / 12; continue; }
          for (const word of words) {
            if (word === key) { score += 1; break; }
            /* a light stem: "scoring" should find "score", "vendors" "vendor" */
            if (key.length >= 4 && word.length >= 4 && (word.startsWith(key.slice(0, 4)) && key.startsWith(word.slice(0, 4)))) {
              score += 0.7; break;
            }
          }
        }
        if (score > high) { high = score; best = entry; }
      }
      return high >= 1 ? best : null;
    }

    const log = $("#ai-log"), panel = $("#ai-panel"), fab = $("#ai-fab"), input = $("#ai-input");
    let greeted = false;

    function bubble(who, html, acts, src) {
      const row = document.createElement("div");
      row.className = "ai-msg " + who;
      row.innerHTML = '<div class="ai-bubble">' + html + "</div>" +
        (acts && acts.length ? '<div class="ai-acts">' + acts.map((key) =>
          '<button type="button" data-act="' + key + '">' + esc(ACT[key][0]) + "</button>").join("") + "</div>" : "") +
        (src ? '<p class="ai-src">Source: ' + esc(src) + "</p>" : "");
      log.appendChild(row);
      log.scrollTop = log.scrollHeight;
      return row;
    }

    function ask(question) {
      const text = String(question || "").trim().slice(0, 300);
      if (!text) return;
      bubble("you", "<p>" + esc(text) + "</p>");
      const wait = document.createElement("div");
      wait.className = "ai-msg bot";
      wait.innerHTML = '<div class="ai-bubble ai-typing"><i></i><i></i><i></i></div>';
      log.appendChild(wait);
      log.scrollTop = log.scrollHeight;
      setTimeout(() => {
        wait.remove();
        const hit = match(text);
        if (!hit) {
          bubble("bot",
            "<p>I do not have an answer for that one, and I would rather say so than invent it.</p>" +
            "<p>What I can cover: the scoring model and its weights, the sources and the offline feeds, what you " +
            "can paste, the graph, the generated ticket, the security controls, and anything about the dataset " +
            "loaded on this page.</p>",
            ["scoring", "sources", "workbench"]);
          return;
        }
        bubble("bot", hit.live ? hit.live() : hit.html, hit.acts, hit.src);
      }, reduce ? 0 : 260);
    }

    log.addEventListener("click", (event) => {
      const button = event.target.closest("[data-act]");
      if (!button) return;
      const entry = ACT[button.dataset.act];
      if (entry) { entry[1](); if (matchMedia("(max-width: 560px)").matches) open(false); }
    });

    $("#ai-chips").innerHTML = CHIPS.map((q) =>
      '<button type="button">' + esc(q) + "</button>").join("");
    $("#ai-chips").addEventListener("click", (event) => {
      const button = event.target.closest("button");
      if (button) ask(button.textContent);
    });

    $("#ai-form").addEventListener("submit", (event) => {
      event.preventDefault();
      ask(input.value);
      input.value = "";
    });

    function open(on) {
      panel.classList.toggle("on", on);
      panel.setAttribute("aria-hidden", String(!on));
      $("#ai-scrim").classList.toggle("on", on && matchMedia("(max-width: 560px)").matches);
      fab.setAttribute("aria-expanded", String(on));
      if (!on) { fab.focus(); return; }
      if (!greeted) {
        greeted = true;
        bubble("bot",
          "<p>Ask me about how IntelPulse scores an indicator, which sources it queries, what you can paste " +
          "into it, or anything about the dataset on this page.</p>" +
          "<p>I answer from this project's documentation and the data already loaded here — so if I do not know " +
          "something, I will say that rather than make it up.</p>");
      }
      setTimeout(() => input.focus({ preventScroll: true }), 120);
    }
    fab.addEventListener("click", () => open(true));
    $("#ai-close").addEventListener("click", () => open(false));
    $("#ai-scrim").addEventListener("click", () => open(false));
    addEventListener("keydown", (event) => {
      const typing = /^(INPUT|TEXTAREA|SELECT)$/.test(event.target.tagName) || event.target.isContentEditable;
      if (event.key === "Escape" && panel.classList.contains("on")) { open(false); return; }
      if (event.key === "?" && !typing && !panel.classList.contains("on")) { event.preventDefault(); open(true); }
    });

    window.IntelPulseAssistant = { ask, open, topics: KB.map((e) => e.id) };
  })();

  window.IntelPulseSuite = { data: DATA, render: drawAll, toast };
})();
