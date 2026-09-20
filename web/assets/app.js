/* IntelPulse dashboard controller.
 *
 * Two runtimes behind one interface:
 *   demo — engine.js scores a bundled synthetic dataset in the browser, so the
 *          GitHub Pages build works with no backend and no API keys;
 *   live — the same screens driven by a running FastAPI service.
 * The mode is stated on every screen and in every generated report: sample data
 * must never be mistaken for live vendor intelligence.
 *
 * Everything rendered here — log lines, vendor responses, stored cases — is
 * treated as attacker-controlled. See escapeHtml() and safeUrl() below.
 */
(function () {
  "use strict";

  const E = window.IntelPulseEngine;
  const C = window.IntelPulseCharts;
  const K = window.IntelPulseCmdK;
  const DEMO = window.INTELPULSE_DEMO;
  const $ = (sel, scope) => (scope || document).querySelector(sel);
  const $$ = (sel, scope) => Array.from((scope || document).querySelectorAll(sel));

  const store = {
    get(key, fallback) {
      try { const raw = localStorage.getItem("intelpulse:" + key); return raw === null ? fallback : JSON.parse(raw); }
      catch (_) { return fallback; }
    },
    set(key, value) {
      try { localStorage.setItem("intelpulse:" + key, JSON.stringify(value)); } catch (_) { /* private mode */ }
    }
  };

  const state = {
    mode: store.get("mode", "demo"),
    apiBase: store.get("apiBase", "http://localhost:8000"),
    // Dark is the product default — a SOC floor is dark and an analyst should
    // not have to fix that on first load. `system` is one keypress away.
    theme: store.get("theme", "dark"),
    railCollapsed: store.get("railCollapsed", false),
    result: null,
    health: null,
    lists: store.get("lists", []),
    history: store.get("history", []),
    cy: null,
    tab: "triage",
    pendingTab: null
  };

  // ————————————————————————————————————————————— safety
  const escapeHtml = (value) => String(value == null ? "" : value)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;");

  /* Escaping makes a URL safe to sit inside an attribute; it does not make the
     URL safe to follow. `javascript:alert(1)` survives HTML escaping intact, so
     every href that comes from a provider response, a stored case, or a backend
     an analyst typed the address of is scheme-checked here first. */
  function safeUrl(value) {
    const raw = String(value == null ? "" : value).trim();
    if (!/^https?:\/\//i.test(raw)) return null;
    try {
      const parsed = new URL(raw);
      return parsed.protocol === "http:" || parsed.protocol === "https:" ? parsed.href : null;
    } catch (_) { return null; }
  }

  const linkOrText = (url, label, cls) => {
    const href = safeUrl(url);
    return href
      ? '<a class="' + cls + '" href="' + escapeHtml(href) + '" target="_blank" rel="noopener noreferrer">' + escapeHtml(label) + "</a>"
      : '<span class="' + cls + '">' + escapeHtml(label) + "</span>";
  };

  // ———————————————————————————————————————————— chrome
  const SEV_GLYPH = {
    critical: '<svg viewBox="0 0 10 10" aria-hidden="true"><path d="M5 0 10 9H0Z"/></svg>',
    high: '<svg viewBox="0 0 10 10" aria-hidden="true"><path d="M5 0 9.5 5 5 10 .5 5Z"/></svg>',
    medium: '<svg viewBox="0 0 10 10" aria-hidden="true"><rect x="1" y="1" width="8" height="8" rx="1.5"/></svg>',
    low: '<svg viewBox="0 0 10 10" aria-hidden="true"><circle cx="5" cy="5" r="4"/></svg>',
    informational: '<svg viewBox="0 0 10 10" aria-hidden="true"><rect x="1" y="4" width="8" height="2" rx="1"/></svg>',
    allowlisted: '<svg viewBox="0 0 10 10" aria-hidden="true"><path d="M1 5.4 3.8 8.2 9 2.4" fill="none" stroke="currentColor" stroke-width="2"/></svg>'
  };

  const badge = (verdict) =>
    '<span class="badge ' + escapeHtml(verdict) + '">' + (SEV_GLYPH[verdict] || SEV_GLYPH.informational) +
    escapeHtml(verdict) + "</span>";

  const sevVar = (verdict) => "var(--sev-" + (verdict === "allowlisted" ? "ok" : verdict) + ")";

  function toast(message, action) {
    const el = $("#toast");
    el.innerHTML =
      '<svg viewBox="0 0 24 24" fill="none" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M20 6 9 17l-5-5"/></svg>' +
      "<span>" + escapeHtml(message) + "</span>" +
      (action ? '<button class="btn small ghost" id="toast-action" style="margin-left:8px">' +
        escapeHtml(action.label) + "</button>" : "");
    el.classList.add("show");
    el.style.pointerEvents = action ? "auto" : "none";
    if (action) {
      $("#toast-action").addEventListener("click", () => {
        action.run();
        el.classList.remove("show");
      });
    }
    clearTimeout(toast._timer);
    toast._timer = setTimeout(() => el.classList.remove("show"), action ? 6000 : 2800);
  }

  /* Errors belong next to the field that caused them, not in a toast that
     disappears — and the field must carry the state for assistive tech too. */
  function setFieldError(inputId, errorId, message) {
    const input = $("#" + inputId);
    const box = $("#" + errorId);
    if (message) {
      input.setAttribute("aria-invalid", "true");
      box.querySelector("span").textContent = message;
      box.hidden = false;
      input.focus();
    } else {
      input.removeAttribute("aria-invalid");
      box.hidden = true;
    }
    return !message;
  }

  /* Embedded contexts (an iframe on a sandboxed host, some corporate browsers)
     silently drop script-started downloads. Rather than a button that appears
     to do nothing, copy the payload and say so. */
  const embedded = (() => {
    try { return window.self !== window.top; } catch (_) { return true; }
  })();

  function download(filename, content, type) {
    if (embedded) {
      navigator.clipboard.writeText(content)
        .then(() => toast("Downloads are blocked in the embedded view — copied to your clipboard instead."))
        .catch(() => toast("Downloads and clipboard are both blocked here. Open the page in its own tab."));
      return;
    }
    const blob = new Blob([content], { type: type || "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1500);
  }

  // ————————————————————————————————————————————— theme
  /* Single source of truth for colour at runtime: read the token, never repeat
     its value in JavaScript. */
  function themeColor(name) {
    return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  }

  function applyTheme(theme) {
    state.theme = theme;
    store.set("theme", theme);
    const root = document.documentElement;
    if (theme === "system") root.removeAttribute("data-theme");
    else root.setAttribute("data-theme", theme);

    const dark = theme === "dark" || (theme === "system" &&
      matchMedia("(prefers-color-scheme: dark)").matches);
    $("#theme-icon").innerHTML = dark
      ? '<path d="M20 13.5A8.2 8.2 0 0 1 10.5 4a8.5 8.5 0 1 0 9.5 9.5Z"/>'
      : '<circle cx="12" cy="12" r="4.2"/><path d="M12 2v2.5M12 19.5V22M2 12h2.5M19.5 12H22M4.9 4.9l1.8 1.8M17.3 17.3l1.8 1.8M19.1 4.9l-1.8 1.8M6.7 17.3l-1.8 1.8"/>';
    $("#theme-toggle").setAttribute("aria-label", "Theme: " + theme + " (press t)");
    const meta = $('meta[name="theme-color"]');
    // Read the live token rather than repeating its value here, so the browser
    // chrome can never drift from the surface it is supposed to match.
    if (meta) meta.content = themeColor("--surface-0") || "#0b1020";
    if (state.result && state.tab === "graph") renderGraph(state.result);
  }

  const cycleTheme = () => {
    const next = { system: "dark", dark: "light", light: "system" }[state.theme] || "dark";
    applyTheme(next);
    toast("Theme: " + next);
  };

  // ———————————————————————————————————————— API client
  async function api(path, options) {
    const base = state.apiBase.replace(/\/+$/, "");
    const response = await fetch(base + path, Object.assign({
      headers: { "Content-Type": "application/json" }
    }, options || {}));
    if (!response.ok) {
      let detail = response.statusText;
      try { detail = (await response.json()).detail || detail; } catch (_) { /* non-JSON error */ }
      throw new Error(detail);
    }
    const type = response.headers.get("content-type") || "";
    return type.includes("application/json") ? response.json() : response.text();
  }

  async function checkHealth() {
    const pill = $("#conn-pill");
    if (state.mode === "demo") {
      state.health = null;
      pill.className = "pill demo";
      pill.innerHTML = '<span class="dot"></span> Demo · synthetic data';
      renderProviders(null);
      return;
    }
    pill.className = "pill";
    pill.innerHTML = '<span class="dot"></span> connecting…';
    try {
      const health = await api("/api/health");
      state.health = health;
      const live = health.providers.filter((p) => p.configured).length;
      pill.className = "pill live";
      pill.innerHTML = '<span class="dot"></span> Live · ' + live + "/" + health.providers.length + " sources";
      renderProviders(health);
    } catch (error) {
      state.health = null;
      pill.className = "pill err";
      pill.innerHTML = '<span class="dot"></span> backend unreachable';
      renderProviders(null, error.message);
    }
  }

  function renderProviders(health, errorMessage) {
    const box = $("#providers");
    if (state.mode === "demo") {
      box.innerHTML = '<div class="chips">' +
        ["abuseipdb", "otx", "threatfox", "urlhaus", "greynoise", "local_blocklist", "geoip", "nvd"]
          .map((name) => '<span class="chip">' + name + "</span>").join("") + "</div>" +
        '<p style="color:var(--ink-3);font-size:12px;margin:10px 0 0">Demo mode scores a bundled synthetic dataset in your browser with the same weights as the API. Switch to <b>Live API</b> for real vendor lookups.</p>';
      return;
    }
    if (!health) {
      box.innerHTML = '<p style="color:var(--sev-high);font-size:12.5px;margin:0">Cannot reach <code>' +
        escapeHtml(state.apiBase) + "</code>" + (errorMessage ? " — " + escapeHtml(errorMessage) : "") +
        '.</p><p style="color:var(--ink-3);font-size:12px;margin:8px 0 0">Start it with <code>docker compose up</code>, or switch back to demo mode.</p>';
      return;
    }
    box.innerHTML = '<div class="chips">' + health.providers.map((p) =>
      '<span class="chip"' + (p.configured ? ' style="border-color:var(--accent-line);color:var(--accent)"' : "") + ">" +
      escapeHtml(p.name) + " · " + (p.configured ? "ready" : "no key") + "</span>").join("") + "</div>" +
      '<dl class="kv" style="margin-top:12px">' +
      "<dt>database</dt><dd>" + escapeHtml(health.database) + "</dd>" +
      "<dt>cache</dt><dd>" + escapeHtml(health.cache.backend) + " · hit rate " +
      Math.round((health.cache.hit_rate || 0) * 100) + "%</dd>" +
      "<dt>offline feed rows</dt><dd>" + health.offline_datasets.feed_entries.toLocaleString() + "</dd>" +
      "<dt>local CVE records</dt><dd>" + health.offline_datasets.cve_records.toLocaleString() + "</dd></dl>";
  }

  // ————————————————————————————————————————— ingest
  function showSkeleton(text) {
    const guess = Math.min(4, Math.max(1, (E.extract(text, { allowDocumentation: true }) || []).length));
    $("#results").hidden = false;
    $("#intro").hidden = true;
    $("#summary").textContent = "";
    $("#kpi").innerHTML = ["Case verdict", "Top score", "Indicators", "Source coverage"]
      .map((label) =>
        '<div class="stat"><div class="k">' + label +
        '</div><div class="v"><span class="sk-line" style="display:block;width:64%;height:18px;margin-top:5px"></span></div></div>')
      .join("");
    $("#panel-triage").innerHTML = '<div class="skeleton">' +
      Array.from({ length: guess }, () =>
        '<div class="sk-card">' +
          '<div class="sk-row"><span class="sk-line" style="max-width:30px"></span>' +
          '<span class="sk-line" style="max-width:200px"></span>' +
          '<span class="sk-line" style="max-width:64px"></span></div>' +
          '<div class="sk-line" style="width:86%"></div>' +
          '<div class="sk-line" style="width:62%"></div>' +
        "</div>").join("") +
      '<div class="sk-note"><span class="spinner"></span> Querying every applicable source concurrently…</div></div>';
    switchTab("triage");
  }

  async function runTriage() {
    const text = $("#input").value.trim();
    if (!text) {
      setFieldError("input", "input-error", "Paste at least one indicator, a log line, or a JSON alert.");
      return;
    }
    setFieldError("input", "input-error", null);

    // Easter egg: the oldest joke in the shell, answered politely.
    if (/^\s*sudo\b/i.test(text)) {
      toast("IntelPulse does not need root — it needs indicators.");
    }

    const button = $("#run");
    button.disabled = true;
    button.setAttribute("aria-busy", "true");
    button.innerHTML = '<span class="spinner"></span> Triaging…';
    showSkeleton(text);
    try {
      const title = $("#title").value.trim() || "Ad-hoc triage";
      let result;
      if (state.mode === "demo") {
        result = E.demoTriage(text, DEMO, { title, lists: state.lists });
      } else {
        result = await api("/api/triage", {
          method: "POST",
          body: JSON.stringify({ text, title, persist: true })
        });
        result.mode = "live";
      }
      if (!result.indicators.length) {
        setFieldError("input", "input-error",
          "No routable indicators in that input — private and reserved address space is dropped on purpose.");
        $("#results").hidden = true;
        $("#intro").hidden = false;
        return;
      }
      state.result = result;
      pushHistory(result);
      renderResult(result);
    } catch (error) {
      toast("Triage failed: " + error.message);
      $("#panel-triage").innerHTML =
        '<div class="empty"><svg viewBox="0 0 24 24"><path d="M12 8v5M12 16.5v.01"/><circle cx="12" cy="12" r="9"/></svg>' +
        "<b>That triage did not complete</b>" + escapeHtml(error.message) + "</div>";
    } finally {
      button.disabled = false;
      button.removeAttribute("aria-busy");
      button.innerHTML = 'Run triage <kbd>⌘↵</kbd>';
    }
  }

  async function runExtract() {
    const text = $("#input").value.trim();
    if (!text) { toast("Nothing to parse yet."); return; }
    let indicators;
    if (state.mode === "demo") {
      indicators = E.extract(text, { allowDocumentation: true });
    } else {
      try { indicators = (await api("/api/extract", { method: "POST", body: JSON.stringify({ text }) })).indicators; }
      catch (error) { toast("Extract failed: " + error.message); return; }
    }
    const counts = indicators.reduce((acc, i) => { acc[i.type] = (acc[i.type] || 0) + 1; return acc; }, {});
    $("#preview").innerHTML = indicators.length
      ? '<div class="chips">' + indicators.map((i) =>
          '<span class="chip">' + escapeHtml(i.type) + " · " + escapeHtml(i.value) + "</span>").join("") +
        '</div><p style="color:var(--ink-3);font-size:11.5px;margin:8px 0 0">' +
        Object.entries(counts).map(([k, v]) => v + " " + k).join(" · ") +
        " — parsed locally, no API quota spent.</p>"
      : '<p style="color:var(--ink-3);font-size:12px;margin:0">No routable indicators found. Private and reserved address space and filenames are dropped on purpose.</p>';
  }

  // ———————————————————————————————————————— rendering
  function renderResult(result) {
    $("#results").hidden = false;
    $("#intro").hidden = true;

    const answered = result.indicators.reduce((sum, i) => sum + (i.providers_answered || 0), 0);
    const queried = result.indicators.reduce((sum, i) => sum + (i.providers_queried || 0), 0);
    const worst = result.indicators.slice().sort((a, b) => b.score - a.score)[0];
    const allSources = result.indicators.reduce((acc, i) => acc.concat(i.sources || []), []);

    $("#kpi").innerHTML =
      '<div class="stat" id="hero-stat">' +
        '<div class="k">Case verdict</div>' +
        '<div class="hero"><span class="figure" id="hero-figure" style="color:' + sevVar(result.verdict) + '">0</span>' +
        '<span class="of">/100 &nbsp;' + badge(result.verdict) + "</span></div>" +
        '<div style="margin-top:8px">' + C.meter(result.score / 100, result.verdict, "block") + "</div>" +
      "</div>" +
      '<div class="stat"><div class="k">Indicators</div><div class="v"><span id="kpi-iocs">0</span>' +
        "<small> parsed</small></div>" +
        '<div style="color:var(--ink-3);font-size:11px;margin-top:4px">' +
        escapeHtml(Object.entries(result.indicators.reduce((acc, i) => { acc[i.type] = (acc[i.type] || 0) + 1; return acc; }, {}))
          .map(([k, v]) => v + " " + k).join(" · ")) + "</div></div>" +
      '<div class="stat"><div class="k">Source coverage</div><div class="v"><span id="kpi-cov">0</span>' +
        "<small>/" + queried + " answered</small></div>" + C.coverageStrip(allSources) + "</div>" +
      '<div class="stat"><div class="k">Enrichment</div><div class="v"><span id="kpi-ms">0</span>' +
        "<small> ms</small></div>" +
        '<div style="color:var(--ink-3);font-size:11px;margin-top:4px">' +
        (result.cache_hits ? result.cache_hits + " cached lookup(s)" : "no cache hits") + "</div></div>";

    C.tweenNumber($("#hero-figure"), result.score, { duration: 620 });
    C.tweenNumber($("#kpi-iocs"), result.indicators.length, { duration: 420 });
    C.tweenNumber($("#kpi-cov"), answered, { duration: 420 });
    C.tweenNumber($("#kpi-ms"), result.duration_ms, { duration: 520 });

    $("#summary").innerHTML = escapeHtml(result.summary);
    renderIndicators(result);
    renderReport(result);

    if (state.pendingTab) {
      const target = state.pendingTab;
      state.pendingTab = null;
      switchTab(target);   // writes the hash back, so URL and view agree
    }
    if (state.tab === "graph") renderGraph(result);
    if (state.tab === "history") renderHistory();

    $("#hero-stat").addEventListener("dblclick", () => showScoringMath(worst));
  }

  const PAGE_SIZE = 25;

  function renderIndicators(result, options) {
    const showAll = Boolean(options && options.showAll);
    const sorted = result.indicators.slice().sort((a, b) => b.score - a.score);
    const visible = showAll ? sorted : sorted.slice(0, PAGE_SIZE);
    const hidden = sorted.length - visible.length;

    $("#panel-triage").innerHTML = '<div class="ioc-list">' + visible.map((indicator, index) => {
      const factLine = ([key, value]) =>
        '<div class="fact" title="' + escapeHtml(key) + '"><span class="fk">' + escapeHtml(key) + '</span><span class="fv">' +
        escapeHtml(Array.isArray(value) ? value.join(", ") : typeof value === "object" ? JSON.stringify(value) : value) +
        "</span></div>";

      /* Facts stay attached to the source that reported them — merging them is
         how an analyst ends up citing the wrong vendor in a ticket. */
      const sources = (indicator.sources || []).map((s) => {
        const facts = Object.entries(s.facts || {})
          .filter(([, v]) => v !== null && v !== "" && v !== undefined && !(Array.isArray(v) && !v.length))
          .slice(0, 8).map(factLine).join("");
        return '<div class="source"><div class="name">' + escapeHtml(s.label || s.provider) + "</div>" +
          '<div class="state ' + escapeHtml(s.status) + '">' + escapeHtml(s.status) +
          (s.cached ? " · cached" : "") + (s.latency_ms ? " · " + s.latency_ms + "ms" : "") + "</div>" +
          (s.error ? '<div style="color:var(--ink-3);font-size:11px;margin-top:4px">' + escapeHtml(s.error) + "</div>" : "") +
          (facts ? '<div class="facts">' + facts + "</div>" : "") +
          (safeUrl(s.reference)
            ? '<a href="' + escapeHtml(safeUrl(s.reference)) + '" target="_blank" rel="noopener noreferrer" style="font-size:11px;display:inline-block;margin-top:6px">vendor page ↗</a>'
            : "") + "</div>";
      }).join("");

      return '<article class="ioc' + (index === 0 ? " open" : "") + '" data-ioc="' + escapeHtml(indicator.value) +
        '" style="animation-delay:' + (C.reduceMotion() ? 0 : index * 55) + 'ms">' +
        '<button class="ioc-top" type="button" aria-expanded="' + (index === 0) + '">' +
          '<svg class="ioc-chevron" viewBox="0 0 24 24" aria-hidden="true"><path d="M9 6l6 6-6 6"/></svg>' +
          '<span class="ioc-type">' + escapeHtml(indicator.type) + "</span>" +
          '<span class="ioc-value">' + escapeHtml(indicator.value) + "</span>" +
          badge(indicator.verdict) +
          '<span class="ioc-score tnum" style="color:' + sevVar(indicator.verdict) + '">' + indicator.score + "</span>" +
        "</button>" +
        '<div class="ioc-detail">' +
          '<dl class="kv">' +
            "<dt>confidence</dt><dd>" + Math.round(indicator.confidence * 100) + "% &nbsp;" +
              C.meter(indicator.confidence) + " &nbsp;<span style=\"color:var(--ink-3)\">" +
              indicator.providers_answered + "/" + indicator.providers_queried + " sources answered</span></dd>" +
            (indicator.context ? "<dt>log context</dt><dd class=\"mono\" style=\"font-size:11.5px\">" + escapeHtml(indicator.context) + "</dd>" : "") +
          "</dl>" +
          C.contributionChart(indicator.evidence, { title: "Why this score" }) +
          ((indicator.modifiers || []).length
            ? '<div class="chart"><div class="chart-head"><span class="chart-title">Modifiers applied</span></div>' +
              '<ul class="actions">' + indicator.modifiers.map((m) => "<li>" + escapeHtml(m) + "</li>").join("") + "</ul></div>"
            : "") +
          ((indicator.malware_families || []).length || (indicator.attack_techniques || []).length || (indicator.tags || []).length
            ? '<div class="chips">' +
              (indicator.malware_families || []).map((f) => '<span class="chip malware">' + escapeHtml(f) + "</span>").join("") +
              (indicator.attack_techniques || []).map((t) => linkOrText(t.url, t.id + " · " + t.name, "chip attack")).join("") +
              (indicator.tags || []).map((t) => '<span class="chip">' + escapeHtml(t) + "</span>").join("") +
              "</div>"
            : "") +
          '<div class="source-grid">' + sources + "</div>" +
          ((indicator.containment || []).length
            ? '<div class="chart"><div class="chart-head"><span class="chart-title">Recommended containment</span></div>' +
              '<ul class="actions">' + indicator.containment.map((a) => "<li>" + escapeHtml(a) + "</li>").join("") + "</ul></div>"
            : "") +
          '<div class="btn-row">' +
            '<button class="btn small ghost" data-copy="' + escapeHtml(indicator.value) + '">Copy IOC</button>' +
            '<button class="btn small ghost" data-allow="' + escapeHtml(indicator.value) + '" data-type="' + escapeHtml(indicator.type) + '">Allowlist</button>' +
            '<button class="btn small ghost" data-block="' + escapeHtml(indicator.value) + '" data-type="' + escapeHtml(indicator.type) + '">Blocklist</button>' +
            '<button class="btn small ghost" data-math="' + escapeHtml(indicator.value) + '">Scoring math</button>' +
          "</div>" +
        "</div></article>";
    }).join("") + "</div>" +
      (hidden > 0
        ? '<div class="btn-row" style="justify-content:center"><button class="btn ghost" id="show-all">' +
          "Show all " + sorted.length + " indicators (" + hidden + " more)</button></div>"
        : "");

    C.bindTableToggles($("#panel-triage"));
    const showAllButton = $("#show-all");
    if (showAllButton) {
      showAllButton.addEventListener("click", () => renderIndicators(result, { showAll: true }));
    }
  }

  function renderReport(result) {
    const markdown = E.toMarkdown(result, { demo: (result.mode || state.mode) === "demo" });
    $("#report").textContent = markdown;
    $("#report").dataset.markdown = markdown;
  }

  /* The maths behind a verdict, in the open. Bound to the "Scoring math" button
     and to a double-click on the hero figure. */
  function showScoringMath(indicator) {
    if (!indicator) return;
    const rows = (indicator.evidence || []).slice().sort((a, b) => b.weighted - a.weighted);
    const weightSum = rows.reduce((sum, r) => sum + r.weight, 0);
    const weightedSum = rows.reduce((sum, r) => sum + r.weighted, 0);
    const mean = weightSum ? weightedSum / weightSum : 0;
    const floor = rows.reduce((max, r) => Math.max(max, r.signal * (E.AUTHORITY[r.provider] || 0.5)), 0);

    openSheet("Scoring math — " + indicator.value,
      '<table class="table-view"><thead><tr><th>Source</th><th>Signal</th><th>Weight</th><th>Weighted</th><th>Authority</th><th>Floor</th></tr></thead><tbody>' +
      rows.map((r) => {
        const authority = E.AUTHORITY[r.provider] || 0.5;
        return "<tr><td>" + escapeHtml(r.provider) + '</td><td class="num">' + r.signal.toFixed(2) +
          '</td><td class="num">' + r.weight + '</td><td class="num">' + r.weighted.toFixed(2) +
          '</td><td class="num">' + authority + '</td><td class="num">' + (r.signal * authority).toFixed(2) + "</td></tr>";
      }).join("") + "</tbody></table>" +
      '<pre class="report" style="margin-top:14px">' +
      "weighted mean   = " + weightedSum.toFixed(2) + " / " + weightSum.toFixed(2) + " = " + mean.toFixed(3) + "\n" +
      "authority floor = " + floor.toFixed(3) + "\n" +
      "score           = 100 × max(" + mean.toFixed(3) + ", " + floor.toFixed(3) + ") = " +
      Math.round(Math.max(mean, floor) * 100) + "\n" +
      ((indicator.modifiers || []).length ? "modifiers       = " + indicator.modifiers.join("; ") + "\n" : "") +
      "final           = " + indicator.score + "/100 (" + indicator.verdict.toUpperCase() + ")" +
      "</pre>");
  }

  // ————————————————————————————————————————— history
  function pushHistory(result) {
    const entry = {
      case_id: result.case_id, title: result.title, verdict: result.verdict,
      score: result.score, indicator_count: result.indicators.length,
      mode: result.mode || state.mode, created_at: new Date().toISOString()
    };
    state.history = [entry].concat(state.history).slice(0, 25);
    store.set("history", state.history);
    if (state.tab === "history") renderHistory();
  }

  async function renderHistory() {
    const box = $("#panel-history");
    let rows = state.history;
    if (state.mode === "live") {
      try {
        rows = (await api("/api/cases?limit=25")).map((c) => ({
          case_id: c.id, title: c.title, verdict: c.verdict, score: c.max_score,
          indicator_count: c.indicator_count, mode: "live", created_at: c.created_at
        }));
      } catch (_) { /* fall back to local history */ }
    }
    if (!rows.length) {
      box.innerHTML = '<div class="empty"><svg viewBox="0 0 24 24" stroke-linecap="round"><circle cx="12" cy="12" r="9"/><path d="M12 7v5.5l3.5 2"/></svg><b>No cases yet</b>Every triage you run is recorded here.</div>';
      return;
    }
    box.innerHTML = '<table class="history"><thead><tr><th>Case</th><th>Title</th><th>Verdict</th>' +
      "<th>Score</th><th>IOCs</th><th>Mode</th><th>When</th></tr></thead><tbody>" +
      rows.map((row) => '<tr><td class="mono" style="font-size:11px">' +
        escapeHtml(String(row.case_id).slice(0, 8)) + "</td><td>" + escapeHtml(row.title) +
        "</td><td>" + badge(row.verdict) + '</td><td class="mono tnum">' + row.score +
        '</td><td class="mono tnum">' + row.indicator_count +
        '</td><td class="mono" style="font-size:11px">' + escapeHtml(row.mode || "") + '</td><td class="mono" style="font-size:11px">' +
        escapeHtml(formatWhen(row.created_at)) + "</td></tr>").join("") +
      "</tbody></table>";
  }

  /* Intl throws on a malformed locale tag — and some environments really do
     report one (`en-US@posix`). A date column is not worth taking the whole
     dashboard down for, so the formatter is built defensively and falls back. */
  const WHEN = (() => {
    for (const locale of [navigator.language, "en-GB"]) {
      try {
        return new Intl.DateTimeFormat(locale, {
          day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit"
        });
      } catch (_) { /* try the next candidate */ }
    }
    return null;
  })();

  const formatWhen = (value) => {
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return "—";
    try {
      return WHEN ? WHEN.format(date) : date.toISOString().replace("T", " ").slice(0, 16);
    } catch (_) {
      return date.toISOString().replace("T", " ").slice(0, 16);
    }
  };

  // ——————————————————————————————————————————— graph
  const svgView = { scale: 1, x: 0, y: 0 };

  function applySvgView() {
    const root = $("#graph .svg-root");
    if (root) {
      root.setAttribute("transform",
        "translate(" + svgView.x + "," + svgView.y + ") scale(" + svgView.scale.toFixed(3) + ")");
    }
  }

  function graphCommand(command) {
    if (state.cy) {
      if (command === "in") state.cy.zoom(state.cy.zoom() * 1.3);
      else if (command === "out") state.cy.zoom(state.cy.zoom() / 1.3);
      else if (command === "fit") state.cy.fit(undefined, 30);
      else if (command === "export") {
        const dataUrl = state.cy.png({ full: true, scale: 2, bg: getComputedStyle(document.body).backgroundColor });
        if (embedded) {
          window.open(dataUrl, "_blank", "noopener");
          toast("Downloads are blocked in the embedded view — the image opened in a new tab.");
          return;
        }
        const link = document.createElement("a");
        link.href = dataUrl;
        link.download = "intelpulse-graph.png";
        link.click();
        toast("Graph exported as PNG.");
      }
      return;
    }
    const svg = $("#graph svg");
    if (!svg) { toast("Run a triage first."); return; }
    if (command === "in") svgView.scale = Math.min(4, svgView.scale * 1.25);
    else if (command === "out") svgView.scale = Math.max(0.35, svgView.scale / 1.25);
    else if (command === "fit") { svgView.scale = 1; svgView.x = 0; svgView.y = 0; }
    else if (command === "export") {
      download("intelpulse-graph.svg", '<?xml version="1.0" encoding="UTF-8"?>\n' + svg.outerHTML, "image/svg+xml");
      toast("Graph exported as SVG.");
      return;
    }
    applySvgView();
  }

  /* Deterministic force-directed layout drawn as inline SVG — used when the
     Cytoscape CDN is blocked, so the graph tab always shows the relationships
     rather than an apology. */
  function renderFallbackGraph(container, graph) {
    const width = container.clientWidth || 900;
    const height = 520;
    const nodes = graph.nodes.map((n, index) => {
      const angle = (index / Math.max(1, graph.nodes.length)) * Math.PI * 2;
      const radius = n.data.root ? height * 0.18 : height * 0.36;
      return {
        id: n.data.id, data: n.data,
        x: width / 2 + Math.cos(angle) * radius,
        y: height / 2 + Math.sin(angle) * radius
      };
    });
    const index = new Map(nodes.map((n) => [n.id, n]));
    const edges = graph.edges
      .map((e) => ({ source: index.get(e.data.source), target: index.get(e.data.target), label: e.data.label }))
      .filter((e) => e.source && e.target);

    for (let step = 0; step < 220; step++) {
      nodes.forEach((a) => {
        let fx = 0, fy = 0;
        nodes.forEach((b) => {
          if (a === b) return;
          const dx = a.x - b.x, dy = a.y - b.y;
          const distance = Math.max(24, Math.hypot(dx, dy));
          const repulsion = 9000 / (distance * distance);
          fx += (dx / distance) * repulsion;
          fy += (dy / distance) * repulsion;
        });
        edges.forEach((edge) => {
          const other = edge.source === a ? edge.target : edge.target === a ? edge.source : null;
          if (!other) return;
          const dx = other.x - a.x, dy = other.y - a.y;
          const distance = Math.max(1, Math.hypot(dx, dy));
          const attraction = (distance - 120) * 0.012;
          fx += (dx / distance) * attraction * distance * 0.1;
          fy += (dy / distance) * attraction * distance * 0.1;
        });
        a.x = Math.min(width - 60, Math.max(60, a.x + Math.max(-12, Math.min(12, fx))));
        a.y = Math.min(height - 40, Math.max(34, a.y + Math.max(-12, Math.min(12, fy))));
      });
    }

    const colorFor = (node) => node.data.verdict ? themeColor("--sev-" +
      (node.data.verdict === "allowlisted" ? "ok" : node.data.verdict)) : themeColor("--ramp-3");

    const shapeFor = (node) => {
      const size = node.data.root ? 15 : 10;
      const color = colorFor(node);
      if (node.data.kind === "malware" || node.data.kind === "actor") {
        return '<polygon points="0,' + (-size * 1.3) + " " + (size * 0.9) + "," + size + " " +
          (-size * 0.9) + "," + size + '" fill="' + color + '" stroke="' + themeColor("--line-2") + '"/>';
      }
      if (["asn", "country", "pulse"].includes(node.data.kind)) {
        return '<rect x="' + -size * 1.4 + '" y="' + -size * 0.8 + '" width="' + size * 2.8 +
          '" height="' + size * 1.6 + '" rx="4" fill="' + color + '" stroke="' + themeColor("--line-2") + '"/>';
      }
      return '<circle r="' + size + '" fill="' + color + '" stroke="' +
        (node.data.root ? themeColor("--accent") : themeColor("--line-2")) +
        '" stroke-width="' + (node.data.root ? 2 : 1) + '"/>';
    };

    container.innerHTML = '<svg class="svg-graph" viewBox="0 0 ' + width + " " + height +
      '" role="img" aria-label="Indicator relationship graph"><g class="svg-root">' +
      edges.map((edge) =>
        '<g><line class="edge" x1="' + edge.source.x.toFixed(1) + '" y1="' + edge.source.y.toFixed(1) +
        '" x2="' + edge.target.x.toFixed(1) + '" y2="' + edge.target.y.toFixed(1) + '"/>' +
        '<text class="edge-label" x="' + ((edge.source.x + edge.target.x) / 2).toFixed(1) +
        '" y="' + ((edge.source.y + edge.target.y) / 2 - 3).toFixed(1) + '" text-anchor="middle">' +
        escapeHtml(edge.label) + "</text></g>").join("") +
      nodes.map((node) =>
        '<g class="node" data-node="' + escapeHtml(node.id) + '" transform="translate(' +
        node.x.toFixed(1) + "," + node.y.toFixed(1) + ')">' + shapeFor(node) +
        '<text y="' + (node.data.root ? 28 : 22) + '" text-anchor="middle">' +
        escapeHtml(String(node.data.label).slice(0, 26)) + "</text></g>").join("") +
      "</g></svg>";
    svgView.scale = 1; svgView.x = 0; svgView.y = 0;

    $$("#graph .node").forEach((element) => element.addEventListener("click", () => focusIoc(element.dataset.node)));
  }

  function focusIoc(nodeId) {
    if (!nodeId || !nodeId.startsWith("ioc:")) return;
    const card = $$(".ioc").find((el) => el.dataset.ioc === nodeId.slice(4));
    if (!card) return;
    switchTab("triage");
    card.classList.add("open");
    card.querySelector(".ioc-top").setAttribute("aria-expanded", "true");
    card.scrollIntoView({ behavior: C.reduceMotion() ? "auto" : "smooth", block: "center" });
  }

  function renderGraph(result) {
    const container = $("#graph");
    const graph = result.graph || E.buildGraph(result.indicators);
    if (!graph.nodes.length) {
      container.innerHTML = '<div class="empty"><b>Nothing to plot</b>No relationships were returned for these indicators.</div>';
      return;
    }
    if (typeof cytoscape === "undefined") {
      renderFallbackGraph(container, graph);
      $("#graph-note").textContent = "Cytoscape CDN unavailable — rendered with the built-in SVG layout.";
      return;
    }
    $("#graph-note").textContent = "";
    if (state.cy) { state.cy.destroy(); state.cy = null; }

    const nodes = graph.nodes.map((node) => {
      const copy = JSON.parse(JSON.stringify(node));
      copy.data.color = copy.data.verdict
        ? themeColor("--sev-" + (copy.data.verdict === "allowlisted" ? "ok" : copy.data.verdict))
        : themeColor("--ramp-3");
      return copy;
    });

    state.cy = cytoscape({
      container,
      elements: { nodes, edges: graph.edges },
      style: [
        { selector: "node", style: {
          "background-color": "data(color)", label: "data(label)", color: themeColor("--ink-2"),
          "font-size": "10px", "font-family": "JetBrains Mono, monospace", "text-valign": "bottom",
          "text-margin-y": 6, "text-wrap": "ellipsis", "text-max-width": "130px",
          width: 20, height: 20, "border-width": 1, "border-color": themeColor("--line-2")
        } },
        { selector: "node[?root]", style: { width: 32, height: 32, "border-width": 2, "border-color": themeColor("--accent"), "font-size": "11px" } },
        { selector: 'node[kind = "malware"]', style: { shape: "star", width: 26, height: 26 } },
        { selector: 'node[kind = "asn"], node[kind = "country"]', style: { shape: "round-rectangle" } },
        { selector: 'node[kind = "hash"]', style: { shape: "hexagon" } },
        { selector: 'node[kind = "url"]', style: { shape: "diamond" } },
        { selector: "edge", style: {
          width: 1.2, "line-color": themeColor("--line-2"), "target-arrow-color": themeColor("--line-2"),
          "target-arrow-shape": "triangle", "curve-style": "bezier", label: "data(label)",
          "font-size": "8px", color: themeColor("--ink-3"), "text-rotation": "autorotate",
          "text-background-opacity": 0
        } },
        { selector: "node:selected", style: { "border-width": 3, "border-color": themeColor("--accent") } }
      ],
      layout: { name: "cose", animate: !C.reduceMotion(), animationDuration: 420, padding: 30, nodeRepulsion: 9000, idealEdgeLength: 90 }
    });
    state.cy.on("tap", "node", (event) => focusIoc(event.target.id()));
  }

  // ———————————————————————————————————————————— lists
  async function addToList(value, iocType, listType) {
    if (state.mode === "live") {
      try {
        await api("/api/lists", {
          method: "POST",
          body: JSON.stringify({ value, ioc_type: iocType, list_type: listType, reason: "added from dashboard" })
        });
        toast(value + " added to the " + listType + "list.");
      } catch (error) { toast("Could not update list: " + error.message); }
      return;
    }
    state.lists = state.lists.filter((entry) => entry.value.toLowerCase() !== value.toLowerCase());
    state.lists.push({ value, ioc_type: iocType, list_type: listType, reason: "added from dashboard (demo)" });
    store.set("lists", state.lists);
    toast(value + " " + listType + "listed — re-run the triage to see the override.");
  }

  // ————————————————————————————————————————— sheets
  function openSheet(title, bodyHtml) {
    const scrim = $("#sheet-scrim");
    $("#sheet-title").textContent = title;
    $("#sheet-body").innerHTML = bodyHtml;
    scrim.hidden = false;
    $("#sheet-close").focus();
  }
  const closeSheet = () => { $("#sheet-scrim").hidden = true; };

  const SHORTCUTS = [
    ["Command palette", ["⌘", "K"]],
    ["Run triage", ["⌘", "↵"]],
    ["Focus the ingest box", ["/"]],
    ["Go to indicators", ["g", "i"]],
    ["Go to graph", ["g", "g"]],
    ["Go to SOC ticket", ["g", "t"]],
    ["Go to history", ["g", "h"]],
    ["Cycle theme", ["t"]],
    ["Collapse the rail", ["["]],
    ["This help", ["?"]],
    ["Close any overlay", ["esc"]]
  ];

  const showShortcuts = () => openSheet("Keyboard shortcuts",
    SHORTCUTS.map(([label, keys]) =>
      '<div class="shortcut-row"><span>' + escapeHtml(label) + '</span><span class="keys">' +
      keys.map((k) => "<kbd>" + escapeHtml(k) + "</kbd>").join("") + "</span></div>").join("") +
    '<p style="color:var(--ink-3);font-size:12px;margin:14px 0 0">On Windows and Linux, ⌘ is Ctrl.</p>');

  // ——————————————————————————————————————— navigation
  function switchTab(name, options) {
    state.tab = name;
    if (!(options && options.fromHash)) {
      const hash = "#" + name;
      if (location.hash !== hash) history.replaceState(null, "", hash);
    }
    $$(".rail-btn[data-nav]").forEach((button) =>
      button.setAttribute("aria-current", String(button.dataset.nav === name)));
    $$(".tabs button").forEach((button) =>
      button.setAttribute("aria-selected", String(button.dataset.tab === name)));
    $$(".tab-panel").forEach((panel) => { panel.hidden = panel.id !== "panel-" + name; });
    if (name === "graph" && state.result) renderGraph(state.result);
    if (name === "history") renderHistory();
  }

  function navigate(target) {
    if (target === "sources" || target === "scoring") {
      $$(".rail-btn[data-nav]").forEach((b) => b.setAttribute("aria-current", String(b.dataset.nav === target)));
      $("#card-" + target).scrollIntoView({ behavior: C.reduceMotion() ? "auto" : "smooth", block: "start" });
      return;
    }
    if (!state.result) {
      $("#input").focus();
      toast("Run a triage to populate this view.");
      return;
    }
    switchTab(target);
    $("#results").scrollIntoView({ behavior: C.reduceMotion() ? "auto" : "smooth", block: "start" });
  }

  function setRail(collapsed) {
    state.railCollapsed = collapsed;
    $("#app").classList.toggle("rail-collapsed", collapsed);
    const toggle = $("#rail-toggle");
    toggle.setAttribute("aria-expanded", String(!collapsed));
    toggle.querySelector("svg").innerHTML = collapsed ? '<path d="M9 6l6 6-6 6"/>' : '<path d="M15 6l-6 6 6 6"/>';
    toggle.querySelector("span").textContent = collapsed ? "Expand" : "Collapse";
    store.set("railCollapsed", collapsed);
  }

  function setMode(mode) {
    state.mode = mode;
    store.set("mode", mode);
    $$("#mode-switch button").forEach((button) =>
      button.setAttribute("aria-pressed", String(button.dataset.mode === mode)));
    $("#demo-banner").classList.toggle("hidden", mode !== "demo");
    $("#api-config").hidden = mode !== "live";
    checkHealth();
  }

  // ———————————————————————————————————————— commands
  function commands() {
    return [
      { id: "run", group: "Triage", icon: "play", label: "Run triage", hint: "⌘↵", keywords: "enrich score analyse", run: runTriage },
      { id: "parse", group: "Triage", icon: "search", label: "Parse only (no API quota)", keywords: "extract indicators", run: runExtract },
      { id: "clear", group: "Triage", icon: "trash", label: "Clear the workspace", keywords: "reset empty", run: clearWorkspace },
      ...DEMO.scenarios.map((scenario) => ({
        id: "scenario-" + scenario.id, group: "Sample scenarios", icon: "file",
        label: "Load: " + scenario.label, keywords: "demo example sample",
        run: () => loadScenario(scenario.id)
      })),
      { id: "go-triage", group: "Go to", icon: "list", label: "Indicators", hint: "g i", run: () => navigate("triage") },
      { id: "go-graph", group: "Go to", icon: "graph", label: "Relationship graph", hint: "g g", run: () => navigate("graph") },
      { id: "go-report", group: "Go to", icon: "doc", label: "SOC ticket", hint: "g t", run: () => navigate("report") },
      { id: "go-history", group: "Go to", icon: "clock", label: "Case history", hint: "g h", run: () => navigate("history") },
      { id: "go-sources", group: "Go to", icon: "shield", label: "Intelligence sources", run: () => navigate("sources") },
      { id: "copy-md", group: "Ticket", icon: "copy", label: "Copy the ticket as Markdown",
        when: () => Boolean(state.result), run: copyReport },
      { id: "dl-md", group: "Ticket", icon: "download", label: "Download the ticket (.md)",
        when: () => Boolean(state.result), run: () => downloadReport("md") },
      { id: "dl-json", group: "Ticket", icon: "download", label: "Download the ticket (.json)",
        when: () => Boolean(state.result), run: () => downloadReport("json") },
      { id: "math", group: "Ticket", icon: "doc", label: "Explain the scoring math",
        when: () => Boolean(state.result),
        run: () => showScoringMath(state.result.indicators.slice().sort((a, b) => b.score - a.score)[0]) },
      { id: "mode-demo", group: "Workspace", icon: "shield", label: "Switch to demo data", when: () => state.mode !== "demo", run: () => setMode("demo") },
      { id: "mode-live", group: "Workspace", icon: "shield", label: "Switch to the live API", when: () => state.mode !== "live", run: () => setMode("live") },
      { id: "theme", group: "Workspace", icon: "theme", label: "Cycle theme (system / dark / light)", hint: "t", run: cycleTheme },
      { id: "rail", group: "Workspace", icon: "list", label: "Collapse or expand the rail", hint: "[", run: () => setRail(!state.railCollapsed) },
      { id: "shortcuts", group: "Workspace", icon: "keyboard", label: "Keyboard shortcuts", hint: "?", run: showShortcuts },
      { id: "night", group: "Workspace", icon: "theme", label: "Toggle night-watch mode", keywords: "konami crt scanline easter egg", run: toggleNightWatch }
    ];
  }

  function loadScenario(id) {
    const scenario = DEMO.scenarios.find((s) => s.id === id);
    if (!scenario) return;
    $("#input").value = scenario.text;
    $("#title").value = scenario.label;
    runExtract();
    toast("Loaded: " + scenario.label);
  }

  function clearWorkspace() {
    const previous = { text: $("#input").value, title: $("#title").value, result: state.result };
    $("#input").value = "";
    $("#preview").innerHTML = "";
    $("#results").hidden = true;
    $("#intro").hidden = false;
    state.result = null;
    renderEmptyState();
    if (previous.text) {
      // Destructive, so it is reversible rather than confirmed — an analyst
      // mid-shift should not have to answer a dialog to clear a box.
      toast("Workspace cleared.", {
        label: "Undo",
        run: () => {
          $("#input").value = previous.text;
          $("#title").value = previous.title;
          if (previous.result) { state.result = previous.result; renderResult(previous.result); }
          runExtract();
        }
      });
    }
  }

  function copyReport() {
    navigator.clipboard.writeText($("#report").dataset.markdown || "")
      .then(() => toast("Markdown ticket copied."))
      .catch(() => toast("Clipboard blocked by the browser."));
  }

  function downloadReport(kind) {
    if (!state.result) return;
    const stem = "intelpulse-" + state.result.case_id.slice(0, 8);
    if (kind === "json") {
      const ticket = E.toTicketJson(state.result, { demo: (state.result.mode || state.mode) === "demo" });
      download(stem + ".json", JSON.stringify(ticket, null, 2), "application/json");
    } else {
      download(stem + ".md", $("#report").dataset.markdown, "text/markdown");
    }
    toast("Ticket downloaded.");
  }

  // ————————————————————————————————————— easter eggs
  function toggleNightWatch() {
    const on = document.body.classList.toggle("night-watch");
    toast(on ? "Night watch engaged — 03:00 shift colours." : "Back to daylight.");
  }

  const KONAMI = ["ArrowUp", "ArrowUp", "ArrowDown", "ArrowDown", "ArrowLeft", "ArrowRight", "ArrowLeft", "ArrowRight", "b", "a"];
  let konamiIndex = 0;

  function konami(event) {
    const expected = KONAMI[konamiIndex];
    if (event.key === expected || event.key.toLowerCase() === expected) {
      konamiIndex++;
      if (konamiIndex === KONAMI.length) { konamiIndex = 0; toggleNightWatch(); }
    } else {
      konamiIndex = event.key === KONAMI[0] ? 1 : 0;
    }
  }

  function consoleBanner() {
    const accent = themeColor("--accent") || "#887aee";
    const muted = themeColor("--ink-3") || "#8fa0bd";
    const style = "color:" + accent + ";font-family:monospace";
    console.log("%c\n  ██ ███ ██ ████ ██   ████  ██ ██ ██   ███  ████\n" +
      "  ██ ██ ███ ██   ██ ██  ██  ██ ██ ██ ██  ██   ██\n" +
      "  ██ ██  ██ ████ ████   ████  ██ ██  ███ ███  ████\n", style);
    console.log("%cIntelPulse — threat intelligence & triage workbench", "font-weight:bold");
    console.log("%cTry ⌘K. The engine is at window.IntelPulseEngine — scoring is open, audit it.", "color:" + muted);
    console.log("%cBuilt by Vinit Rami · https://vinitrami-soc.github.io/", "color:" + muted);
  }

  // ———————————————————————————————————————— keyboard
  let pendingG = 0;

  function onKeydown(event) {
    const typing = /^(INPUT|TEXTAREA)$/.test(event.target.tagName);

    if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
      event.preventDefault(); K.toggle(); return;
    }
    if ((event.metaKey || event.ctrlKey) && event.key === "Enter") {
      event.preventDefault(); runTriage(); return;
    }
    if (event.key === "Escape") { closeSheet(); return; }
    if (K.isOpen()) return;

    if (!typing) {
      konami(event);

      /* A pending "g" owns the next key: `g t` must reach the ticket, not the
         theme toggle, and `g g` must not restart the sequence. Sequence first,
         single-key shortcuts second. */
      if (pendingG && Date.now() - pendingG < 900) {
        const target = { i: "triage", g: "graph", t: "report", h: "history" }[event.key];
        pendingG = 0;
        if (target) { event.preventDefault(); navigate(target); return; }
      }
      if (event.key === "g") { pendingG = Date.now(); return; }
      pendingG = 0;

      if (event.key === "/") { event.preventDefault(); $("#input").focus(); return; }
      if (event.key === "?") { event.preventDefault(); showShortcuts(); return; }
      if (event.key === "t") { cycleTheme(); return; }
      if (event.key === "[") { setRail(!state.railCollapsed); return; }
    }
  }

  // ———————————————————————————————————————————— init
  function readFile(file) {
    if (file.size > 5 * 1024 * 1024) { toast("File is larger than 5 MB."); return; }
    const reader = new FileReader();
    reader.onload = () => {
      $("#input").value = String(reader.result).slice(0, 200000);
      $("#title").value = "Upload — " + file.name;
      runExtract();
      toast(file.name + " loaded — press Run triage.");
    };
    reader.readAsText(file);
  }

  const STARTER_BLURB = {
    firewall: "Three source addresses from a perimeter block burst — one is a confirmed C2, one is noise.",
    phishing: "A reported mail: sender, link, relay and attachment hash in one paste.",
    edr: "A JSON alert straight off the endpoint agent, CVE included."
  };

  function renderEmptyState() {
    $("#starters").innerHTML = DEMO.scenarios.map((scenario) =>
      '<button class="starter" data-scenario="' + escapeHtml(scenario.id) + '" type="button">' +
        "<b>" + escapeHtml(scenario.label) + "</b>" +
        "<span>" + escapeHtml(STARTER_BLURB[scenario.id] || "Sample scenario.") + "</span>" +
        '<span class="go">Load and triage →</span>' +
      "</button>").join("");

    const recent = state.history.slice(0, 4);
    $("#recent-cases").innerHTML = recent.length
      ? '<div class="recent"><h3>Recent cases</h3>' + recent.map((row) =>
          '<button type="button" data-history="' + escapeHtml(row.case_id) + '">' +
          badge(row.verdict) + "<span>" + escapeHtml(row.title) + "</span>" +
          '<span class="when">' + escapeHtml(formatWhen(row.created_at)) + "</span></button>").join("") +
        "</div>"
      : "";
  }

  function init() {
    applyTheme(state.theme);
    setRail(state.railCollapsed);
    matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => {
      if (state.theme === "system") applyTheme("system");
    });

    $$("#mode-switch button").forEach((button) =>
      button.addEventListener("click", () => setMode(button.dataset.mode)));
    $$(".rail-btn[data-nav]").forEach((button) =>
      button.addEventListener("click", () => navigate(button.dataset.nav)));
    $$(".tabs button").forEach((button) =>
      button.addEventListener("click", () => switchTab(button.dataset.tab)));
    $$(".graph-tools button").forEach((button) =>
      button.addEventListener("click", () => graphCommand(button.dataset.graph)));

    $("#rail-toggle").addEventListener("click", () => setRail(!state.railCollapsed));
    $("#theme-toggle").addEventListener("click", cycleTheme);
    $("#cmd-hint").addEventListener("click", () => K.open());
    $("#shortcuts-btn").addEventListener("click", showShortcuts);
    $("#sheet-close").addEventListener("click", closeSheet);
    $("#sheet-scrim").addEventListener("mousedown", (event) => {
      if (event.target === $("#sheet-scrim")) closeSheet();
    });

    $("#api-base").value = state.apiBase;
    $("#api-save").addEventListener("click", () => {
      const value = $("#api-base").value.trim() || "http://localhost:8000";
      if (!safeUrl(value)) {
        setFieldError("api-base", "api-error", "Enter a full http:// or https:// URL, for example http://localhost:8000.");
        return;
      }
      setFieldError("api-base", "api-error", null);
      state.apiBase = value;
      store.set("apiBase", state.apiBase);
      checkHealth();
    });
    $("#api-base").addEventListener("input", () => setFieldError("api-base", "api-error", null));
    $("#input").addEventListener("input", () => {
      if ($("#input").getAttribute("aria-invalid")) setFieldError("input", "input-error", null);
    });

    $("#run").addEventListener("click", runTriage);
    $("#parse").addEventListener("click", runExtract);
    $("#clear").addEventListener("click", clearWorkspace);

    renderEmptyState();
    $("#starters").addEventListener("click", (event) => {
      const button = event.target.closest("button[data-scenario]");
      if (!button) return;
      loadScenario(button.dataset.scenario);
      runTriage();
    });
    $("#recent-cases").addEventListener("click", (event) => {
      const button = event.target.closest("button[data-history]");
      if (button) { switchTab("history"); navigate("history"); }
    });

    $("#samples").innerHTML = DEMO.scenarios.map((scenario) =>
      '<button data-scenario="' + escapeHtml(scenario.id) + '">' + escapeHtml(scenario.label) + "</button>").join("");
    $("#samples").addEventListener("click", (event) => {
      const button = event.target.closest("button[data-scenario]");
      if (button) loadScenario(button.dataset.scenario);
    });

    const drop = $("#dropzone");
    const picker = $("#file");
    drop.addEventListener("click", () => picker.click());
    picker.addEventListener("change", () => { if (picker.files[0]) readFile(picker.files[0]); });
    ["dragenter", "dragover"].forEach((type) => drop.addEventListener(type, (event) => {
      event.preventDefault(); drop.classList.add("drag");
    }));
    ["dragleave", "drop"].forEach((type) => drop.addEventListener(type, (event) => {
      event.preventDefault(); drop.classList.remove("drag");
    }));
    drop.addEventListener("drop", (event) => {
      const file = event.dataTransfer.files[0];
      if (file) readFile(file);
    });

    document.addEventListener("click", (event) => {
      const head = event.target.closest(".ioc-top");
      if (head) {
        const card = head.parentElement;
        const open = card.classList.toggle("open");
        head.setAttribute("aria-expanded", String(open));
        return;
      }
      const copy = event.target.closest("[data-copy]");
      if (copy) {
        navigator.clipboard.writeText(copy.dataset.copy).then(() => toast("Indicator copied."));
        return;
      }
      const allow = event.target.closest("[data-allow]");
      if (allow) { addToList(allow.dataset.allow, allow.dataset.type, "allow"); return; }
      const block = event.target.closest("[data-block]");
      if (block) { addToList(block.dataset.block, block.dataset.type, "block"); return; }
      const math = event.target.closest("[data-math]");
      if (math && state.result) {
        showScoringMath(state.result.indicators.find((i) => i.value === math.dataset.math));
      }
    });

    $("#copy-report").addEventListener("click", copyReport);
    $("#download-md").addEventListener("click", () => downloadReport("md"));
    $("#download-json").addEventListener("click", () => downloadReport("json"));

    document.addEventListener("keydown", onKeydown);
    K.mount({ commands: commands() });

    setMode(state.mode);
    const fromHash = (location.hash || "").replace("#", "");
    const valid = ["triage", "graph", "report", "history"].includes(fromHash);
    switchTab(valid ? fromHash : "triage", { fromHash: true });
    /* The skeleton lives in the indicators panel, so a run pulls the view
       there. If the analyst arrived on a deep link to another tab, honour it
       once the result actually exists. */
    if (valid && fromHash !== "triage") state.pendingTab = fromHash;
    window.addEventListener("hashchange", () => {
      const name = (location.hash || "").replace("#", "");
      if (["triage", "graph", "report", "history"].includes(name) && name !== state.tab) {
        switchTab(name, { fromHash: true });
      }
    });
    consoleBanner();
  }

  /* A small, deliberate debug surface: the browser tests drive `render` with
     hostile payloads and assert `safeUrl` directly, and an analyst can inspect
     the last result from the console. It exposes nothing a page script could
     not already reach. */
  window.IntelPulse = {
    render: renderResult,
    safeUrl,
    openPalette: () => K.open(),
    get result() { return state.result; },
    get mode() { return state.mode; },
    get theme() { return state.theme; }
  };

  document.addEventListener("DOMContentLoaded", init);
})();
