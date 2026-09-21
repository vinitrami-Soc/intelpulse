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

  const NAV = [
    { group: "Reporting", icon: "i-grid", open: true, items: [
      { id: "dashboard", label: "Dashboard" }, { id: "activity", label: "Activity" }, { id: "documents", label: "Documents" }
    ] },
    { group: "Findings", icon: "i-search", open: false, items: [
      { id: "all-findings", label: "All findings" }, { id: "triage", label: "Triage queue" }
    ] },
    { item: { id: "attacks", label: "All attacks", icon: "i-target", badge: "12" } },
    { item: { id: "narratives", label: "Attack narratives", icon: "i-doc" } },
    { item: { id: "active", label: "Active attack", icon: "i-bot" } },
    { item: { id: "surface", label: "Attack surface", icon: "i-layers" } },
    { item: { id: "projects", label: "Projects", icon: "i-folder", badge: "28", blue: true } },
    { item: { id: "external", label: "External pentest", icon: "i-globe" } },
    { item: { id: "internal", label: "Internal pentest", icon: "i-shield" } },
    { item: { id: "passwords", label: "Password audits", icon: "i-key" } }
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
      if (host.id === "side-nav-full") renderConsole(pane);
      else { location.hash = "#/console"; setTimeout(() => renderConsole(pane), 60); }
      toast(item.textContent.trim() + " opened");
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
          DATA.findings.map((f) => "<tr><td class=\"mono\">" + f.ioc + "</td><td>" + f.type +
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

  const PANES = {
    dashboard: () => ({ title: "Welcome back, analyst", sub: "Remediation efficacy and the attack surface, as of this morning.", body: kpiCards() + panelsMarkup(false) }),
    activity:  () => ({ title: "Activity", sub: "Every triage this workspace has run, newest first.", body: panelsMarkup(true) }),
    documents: () => ({ title: "Documents", sub: "Generated SOC tickets and exported evidence.", body: kpiCards() }),
    "all-findings": () => ({ title: "All findings", sub: "Indicators across every open case.", body: panelsMarkup(false) }),
    triage:    () => ({ title: "Triage queue", sub: "What needs an analyst next, sorted by composite score.", body: kpiCards() + panelsMarkup(true) }),
    attacks:   () => ({ title: "All attacks", sub: "12 campaigns correlated from the current indicator set.", body: panelsMarkup(true) }),
    narratives:() => ({ title: "Attack narratives", sub: "The story each campaign tells, in order.", body: kpiCards() }),
    active:    () => ({ title: "Active attack", sub: "Live indicators still resolving.", body: panelsMarkup(true) }),
    surface:   () => ({ title: "Attack surface", sub: "Everything exposed, scored.", body: panelsMarkup(false) }),
    projects:  () => ({ title: "Projects", sub: "28 engagements sharing this intelligence.", body: kpiCards() }),
    external:  () => ({ title: "External pentest", sub: "Findings from outside the perimeter.", body: panelsMarkup(true) }),
    internal:  () => ({ title: "Internal pentest", sub: "Findings from inside the estate.", body: panelsMarkup(true) }),
    passwords: () => ({ title: "Password audits", sub: "Credential exposure across the directory.", body: kpiCards() })
  };

  function renderConsole(pane) {
    const spec = (PANES[pane] || PANES.dashboard)();
    const host = $("#console-body");
    host.innerHTML =
      '<header class="console-head route">' +
        "<div><h3>" + spec.title + ' <span aria-hidden="true">👋</span></h3><p>' + spec.sub + "</p></div>" +
        '<div class="head-right">' +
          '<button class="round-btn" id="c-search" aria-label="Search">' + icon("i-search") + "</button>" +
          '<a class="btn btn-dark btn-sm" href="workbench.html">Live triage' + icon("i-arrow") + "</a>" +
          '<span class="status-pill">Testing status <span class="on">Active</span></span>' +
          '<button class="round-btn" id="c-bell" aria-label="Notifications">' + icon("i-bell") + '<span class="ping"></span></button>' +
          '<span class="avatar" role="img" aria-label="Your profile"></span>' +
          '<button class="round-btn" id="c-collapse" aria-label="Collapse sidebar">' + icon("i-sidebar") + "</button>" +
        "</div>" +
      "</header>" + '<div class="route">' + spec.body + "</div>";
    wirePanels(host);
    $("#c-search").addEventListener("click", () => toast("Search is a demo control"));
    $("#c-bell").addEventListener("click", () => toast("3 new findings since your last visit"));
    $("#c-collapse").addEventListener("click", () => {
      $("#console-full").classList.toggle("compact");
      toast($("#console-full").classList.contains("compact") ? "Sidebar collapsed" : "Sidebar expanded");
    });
  }

  function renderPreview() {
    const host = $("#console-preview");
    host.innerHTML =
      '<header class="console-head">' +
        '<div><h3>Welcome back, analyst <span aria-hidden="true">👋</span></h3>' +
        "<p>Remediation efficacy and the attack surface, as of this morning.</p></div>" +
        '<div class="head-right"><span class="status-pill">Testing status <span class="on">Active</span></span>' +
        '<span class="avatar" role="img" aria-label="Profile"></span></div>' +
      "</header>" + kpiCards() + panelsMarkup(true);
    wirePanels(host);
  }

  /* ─────────────────────────────────────────────────────── routing */
  function route() {
    const toConsole = location.hash.startsWith("#/console");
    $("#page-home").hidden = toConsole;
    $("#page-console").hidden = !toConsole;
    const cta = $("#nav-cta");
    cta.dataset.route = toConsole ? "home" : "console";
    cta.innerHTML = (toConsole ? "Back to site" : "Open console") + '<svg><use href="#i-arrow"/></svg>';
    if (toConsole) {
      renderConsole($(".nav-item[aria-current='true']", $("#side-nav-full"))?.dataset.pane || "dashboard");
      $("#page-console").classList.remove("route"); void $("#page-console").offsetWidth;
      $("#page-console").classList.add("route");
    }
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

  window.IntelPulseSuite = { data: DATA, render: drawAll, toast };
})();
