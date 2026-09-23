/* Interactive console panes: the analyst workbench and the campaign graph.
 *
 * Both used to be separate pages (workbench.html, explorer.html) with their own
 * chrome, their own stylesheet and their own look — so opening "Live triage"
 * from the console meant leaving it for something that did not resemble it.
 * They live inside the console now, in its sidebar, its header and its cards.
 *
 * What moved and what did not:
 *   - Scoring, extraction, the graph model, diffs and the ticket formats are all
 *     engine.js, unchanged. Nothing here re-implements a rule; it renders them.
 *   - The evidence charts are charts.js, unchanged.
 *   - The rendering is new, written against the console's own components
 *     (.card.panel, .kpis, .seg, .table, .pill-sev) instead of the old page's.
 *   - localStorage keys are the old workbench's, so a visitor's case history,
 *     snapshots and allow/block lists carry across.
 *
 * Each pane is { title, sub, body(), mount(root, ctx) }. mount wires the pane
 * and returns an unmount that removes every listener and aborts any live
 * request still in flight — the console calls it before painting another pane,
 * so a slow triage cannot render into a view that has already gone.
 *
 * Everything that reaches the DOM from a provider, a log line or a stored case
 * is escaped, and every href from those places is scheme-checked. The input box
 * is only ever read from `.value` and never written back as markup.
 */
(function () {
  "use strict";

  const E = window.IntelPulseEngine;
  const C = window.IntelPulseCharts;
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

  const esc = (value) => String(value == null ? "" : value)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;");

  /* Escaping makes a URL safe inside an attribute; it does not make it safe to
     follow. `javascript:alert(1)` survives HTML escaping intact, so every href
     from a provider, a stored case or a backend is scheme-checked first. */
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
      ? '<a class="' + cls + '" href="' + esc(href) + '" target="_blank" rel="noopener noreferrer">' + esc(label) + "</a>"
      : '<span class="' + cls + '">' + esc(label) + "</span>";
  };

  /* Severity is never colour alone: hue, a glyph and the word, every time. */
  const SEV_GLYPH = {
    critical: '<svg viewBox="0 0 10 10" aria-hidden="true"><path d="M5 0 10 9H0Z"/></svg>',
    high: '<svg viewBox="0 0 10 10" aria-hidden="true"><path d="M5 0 9.5 5 5 10 .5 5Z"/></svg>',
    medium: '<svg viewBox="0 0 10 10" aria-hidden="true"><rect x="1" y="1" width="8" height="8" rx="1.5"/></svg>',
    low: '<svg viewBox="0 0 10 10" aria-hidden="true"><circle cx="5" cy="5" r="4"/></svg>',
    informational: '<svg viewBox="0 0 10 10" aria-hidden="true"><rect x="1" y="4" width="8" height="2" rx="1"/></svg>',
    allowlisted: '<svg viewBox="0 0 10 10" aria-hidden="true"><path d="M1 5.4 3.8 8.2 9 2.4" fill="none" stroke="currentColor" stroke-width="2"/></svg>'
  };
  const VERDICTS = Object.keys(SEV_GLYPH);
  const verdictOf = (v) => (VERDICTS.includes(v) ? v : "informational");
  const badge = (verdict) => {
    const v = verdictOf(verdict);
    return '<span class="wb-badge ' + v + '">' + SEV_GLYPH[v] + esc(v) + "</span>";
  };
  const sevVar = (verdict) => "var(--sev-" + (verdict === "allowlisted" ? "ok"
    : verdict === "informational" ? "info" : verdictOf(verdict)) + ")";

  /* Intl throws on a malformed locale tag, and some environments report one.
     A date column is not worth taking the pane down for. */
  const WHEN = (() => {
    for (const locale of [navigator.language, "en-GB"]) {
      try { return new Intl.DateTimeFormat(locale, { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit" }); }
      catch (_) { /* next */ }
    }
    return null;
  })();
  const formatWhen = (value) => {
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return "—";
    try { return WHEN ? WHEN.format(date) : date.toISOString().replace("T", " ").slice(0, 16); }
    catch (_) { return date.toISOString().replace("T", " ").slice(0, 16); }
  };

  function download(filename, content, type) {
    const blob = new Blob([content], { type });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = filename;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  const cssVar = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();

  /* ════════════════════════════════════════════════════ the workbench ══ */

  /* Module-level, so leaving the pane and coming back finds the case still open. */
  const wb = {
    mode: store.get("mode", "demo"),
    apiBase: store.get("apiBase", "http://localhost:8000"),
    lists: store.get("lists", []),
    history: store.get("history", []),
    health: null,
    result: null,
    showAll: false,
    draft: { text: "", title: "" }
  };

  const STARTER_BLURB = {
    firewall: "Three source addresses from a perimeter block burst — one is a confirmed C2, one is noise.",
    phishing: "A reported mail: sender, link, relay and attachment hash in one paste.",
    edr: "A JSON alert straight off the endpoint agent, CVE included."
  };
  const SINK_LABELS = { jira: "Jira", servicenow: "ServiceNow" };
  const PAGE_SIZE = 25;

  function workbenchBody() {
    const scenarios = (DEMO && DEMO.scenarios) || [];
    return '<div class="wb" data-wb>' +
      '<div class="panel-row wb-top">' +
        '<section class="card panel wb-input-card">' +
          '<div class="panel-head"><h4>Paste an alert</h4>' +
            '<div class="seg" role="group" aria-label="Where the intelligence comes from">' +
              '<button type="button" data-mode="demo" aria-pressed="' + (wb.mode === "demo") + '">Demo data</button>' +
              '<button type="button" data-mode="live" aria-pressed="' + (wb.mode === "live") + '">Live API</button>' +
            "</div></div>" +
          '<label class="label-xs" for="wb-input">Alert, log lines, JSON export or a list of indicators</label>' +
          '<textarea id="wb-input" class="wb-input" rows="7" spellcheck="false" autocomplete="off" ' +
            'aria-describedby="wb-error wb-hint" placeholder="Sep 18 02:14:11 fw-edge-01 kernel: [UFW BLOCK] SRC=203.0.113.10 DST=10.20.4.15 DPT=445"></textarea>' +
          '<p class="wb-error" id="wb-error" role="alert" hidden></p>' +
          '<p class="wb-hint" id="wb-hint">Defanged notation is fine. Private and reserved address space, usernames and filenames are dropped before anything is looked up.</p>' +
          '<div class="wb-row">' +
            '<input id="wb-title" class="wb-field" type="text" placeholder="Case title (optional)" aria-label="Case title" autocomplete="off" spellcheck="false">' +
            '<label class="btn btn-light btn-sm wb-file">Upload a file' +
              '<input type="file" id="wb-file" accept=".txt,.log,.csv,.json" class="sr-only"></label>' +
          "</div>" +
          '<div class="wb-row wb-actions">' +
            '<button type="button" class="btn btn-dark" id="wb-run" data-act="run">Run triage <kbd>Ctrl ↵</kbd></button>' +
            '<button type="button" class="btn btn-light btn-sm" data-act="preview">Preview indicators</button>' +
            '<button type="button" class="btn btn-light btn-sm" data-act="clear">Clear</button>' +
          "</div>" +
          '<div id="wb-preview" class="wb-preview" aria-live="polite"></div>' +
          '<div class="wb-live" id="wb-live"' + (wb.mode === "live" ? "" : " hidden") + ">" +
            '<label class="label-xs" for="wb-api">API address</label>' +
            '<div class="wb-row"><input id="wb-api" class="wb-field" type="url" inputmode="url" spellcheck="false" autocomplete="off" aria-describedby="wb-api-error" value="' + esc(wb.apiBase) + '">' +
              '<button type="button" class="btn btn-light btn-sm" data-act="connect">Connect</button></div>' +
            '<p class="wb-error" id="wb-api-error" role="alert" hidden></p>' +
          "</div>" +
        "</section>" +
        '<section class="card panel wb-side">' +
          '<div class="panel-head"><h4>Start from a sample</h4></div>' +
          '<div class="wb-starters">' + scenarios.map((s) =>
            '<button type="button" class="wb-starter" data-scenario="' + esc(s.id) + '"><b>' + esc(s.label) + "</b>" +
            "<span>" + esc(STARTER_BLURB[s.id] || "Sample scenario.") + "</span></button>").join("") + "</div>" +
          '<div class="label-xs" style="margin-top:16px">Sources <span id="wb-conn" class="wb-conn"></span></div>' +
          '<div id="wb-providers"></div>' +
        "</section>" +
      "</div>" +

      '<div id="wb-results" class="wb-results" hidden>' +
        '<div class="kpis wb-kpis" id="wb-kpis"></div>' +
        '<section class="card panel"><div class="panel-head"><h4>What this case is</h4>' +
          '<span class="wb-mode-note" id="wb-mode-note"></span></div>' +
          '<p class="wb-summary" id="wb-summary"></p></section>' +
        '<section class="card panel"><div class="panel-head"><h4>Every indicator, and why it scored</h4>' +
          '<span class="label-xs" id="wb-count"></span></div><div id="wb-iocs"></div></section>' +
        '<section class="card panel wb-graph-card"><div class="panel-head"><h4>How they relate</h4>' +
            '<span class="label-xs">hover or tab to a node · select an indicator to open its evidence</span></div>' +
            '<div id="wb-graph" class="wb-graph"></div></section>' +
          '<section class="card panel"><div class="panel-head"><h4>SOC ticket</h4></div>' +
            '<div class="wb-row wb-actions">' +
              '<button type="button" class="btn btn-dark btn-sm" data-act="copy-report">Copy Markdown</button>' +
              '<button type="button" class="btn btn-light btn-sm" data-act="download-md">Download .md</button>' +
              '<button type="button" class="btn btn-light btn-sm" data-act="download-json">Download .json</button>' +
              '<button type="button" class="btn btn-flame btn-sm" id="wb-raise" data-act="raise" hidden></button>' +
            "</div>" +
            '<p class="wb-hint" id="wb-ticket-note" role="status" aria-live="polite"></p>' +
            '<pre class="wb-report" id="wb-report" tabindex="0" aria-label="Ticket preview"></pre></section>' +
      "</div>" +

      '<section class="card panel"><div class="panel-head"><h4>Case history</h4>' +
        '<span class="label-xs">last 25, this browser' + (wb.mode === "live" ? " or the API" : "") + "</span></div>" +
        '<div id="wb-history"></div></section>' +

      '<dialog class="wb-dialog" id="wb-dialog" role="dialog" aria-modal="true" aria-labelledby="wb-dialog-title">' +
        '<div class="wb-dialog-head"><h4 id="wb-dialog-title"></h4>' +
          '<button type="button" class="round-btn" data-act="close-dialog" aria-label="Close"><svg><use href="#i-close"/></svg></button></div>' +
        '<div id="wb-dialog-body"></div></dialog>' +
    "</div>";
  }

  function mountWorkbench(root, ctx) {
    const toast = (ctx && ctx.toast) || (() => {});
    const inflight = new Set();       // AbortControllers for live requests
    let alive = true;
    let dialogReturn = null;

    const q = (sel) => $(sel, root);

    async function api(path, options) {
      const controller = new AbortController();
      inflight.add(controller);
      try {
        const base = wb.apiBase.replace(/\/+$/, "");
        const response = await fetch(base + path, Object.assign({
          headers: { "Content-Type": "application/json" }, signal: controller.signal
        }, options || {}));
        if (!response.ok) {
          let detail = response.statusText;
          try { detail = (await response.json()).detail || detail; } catch (_) { /* non-JSON error */ }
          throw new Error(detail);
        }
        const type = response.headers.get("content-type") || "";
        return type.includes("application/json") ? response.json() : response.text();
      } finally { inflight.delete(controller); }
    }

    function setError(message) {
      const box = q("#wb-error"), input = q("#wb-input");
      if (message) {
        box.textContent = message; box.hidden = false;
        input.setAttribute("aria-invalid", "true");
      } else {
        box.textContent = ""; box.hidden = true;
        input.removeAttribute("aria-invalid");
      }
    }

    /* ─── mode and connection ─── */
    function renderProviders(errorMessage) {
      const box = q("#wb-providers"), conn = q("#wb-conn");
      if (wb.mode === "demo") {
        conn.className = "wb-conn demo"; conn.textContent = "demo · synthetic";
        box.innerHTML = '<div class="wb-chips">' +
          ["AbuseIPDB", "OTX", "ThreatFox", "URLhaus", "GreyNoise", "Local blocklist", "GeoIP", "NVD"]
            .map((n) => '<span class="wb-chip">' + n + "</span>").join("") + "</div>" +
          '<p class="wb-hint">Demo mode scores a bundled synthetic dataset in your browser with the same weights as the API. Switch to <b>Live API</b> for real vendor lookups.</p>';
        return;
      }
      if (!wb.health) {
        conn.className = "wb-conn err"; conn.textContent = "unreachable";
        box.innerHTML = '<p class="wb-hint wb-warn">Cannot reach <code>' + esc(wb.apiBase) + "</code>" +
          (errorMessage ? " — " + esc(errorMessage) : "") + ".</p>" +
          '<p class="wb-hint">Start it with <code>docker compose up</code>, or switch back to demo data.</p>';
        return;
      }
      const h = wb.health;
      const live = (h.providers || []).filter((p) => p.configured).length;
      conn.className = "wb-conn live"; conn.textContent = "live · " + live + "/" + (h.providers || []).length + " sources";
      box.innerHTML = '<div class="wb-chips">' + (h.providers || []).map((p) =>
        '<span class="wb-chip' + (p.configured ? " on" : "") + '">' + esc(p.name) + " · " +
        (p.configured ? "ready" : "no key") + "</span>").join("") + "</div>" +
        '<dl class="wb-kv" style="margin-top:12px">' +
          "<dt>database</dt><dd>" + esc(h.database) + "</dd>" +
          "<dt>cache</dt><dd>" + esc(h.cache && h.cache.backend) + " · hit rate " +
            Math.round(((h.cache && h.cache.hit_rate) || 0) * 100) + "%</dd>" +
        "</dl>";
    }

    async function checkHealth() {
      if (wb.mode === "demo") { wb.health = null; renderProviders(); renderTicketButton(); return; }
      q("#wb-conn").className = "wb-conn"; q("#wb-conn").textContent = "connecting…";
      try {
        wb.health = await api("/api/health");
        if (!alive) return;
        renderProviders();
      } catch (error) {
        if (!alive || error.name === "AbortError") return;
        wb.health = null;
        renderProviders(error.message);
      }
      renderTicketButton();
    }

    function setMode(mode) {
      wb.mode = mode === "live" ? "live" : "demo";
      store.set("mode", wb.mode);
      $$("[data-mode]", root).forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.mode === wb.mode)));
      q("#wb-live").hidden = wb.mode !== "live";
      checkHealth();
      renderHistory();
    }

    /* ─── ingest ─── */
    async function preview() {
      const text = q("#wb-input").value.trim();
      const box = q("#wb-preview");
      if (!text) { box.innerHTML = ""; toast("Nothing to parse yet."); return; }
      let indicators;
      if (wb.mode === "demo") {
        indicators = E.extract(text, { allowDocumentation: true });
      } else {
        try { indicators = (await api("/api/extract", { method: "POST", body: JSON.stringify({ text }) })).indicators; }
        catch (error) { if (error.name !== "AbortError") toast("Extract failed: " + error.message); return; }
      }
      if (!alive) return;
      const counts = indicators.reduce((acc, i) => { acc[i.type] = (acc[i.type] || 0) + 1; return acc; }, {});
      box.innerHTML = indicators.length
        ? '<div class="wb-chips">' + indicators.map((i) =>
            '<span class="wb-chip"><b>' + esc(i.type) + "</b> " + esc(i.value) + "</span>").join("") +
          '</div><p class="wb-hint">' + Object.entries(counts).map(([k, v]) => v + " " + esc(k)).join(" · ") +
          " — parsed locally, no API quota spent.</p>"
        : '<p class="wb-hint">No routable indicators. Private and reserved address space, usernames and filenames are dropped on purpose.</p>';
    }

    function loadScenario(id) {
      const scenario = ((DEMO && DEMO.scenarios) || []).find((s) => s.id === id);
      if (!scenario) return;
      q("#wb-input").value = scenario.text;
      q("#wb-title").value = scenario.label;
      setError(null);
      runTriage();
    }

    function readFile(file) {
      if (!file) return;
      if (file.size > 5 * 1024 * 1024) { toast("That file is larger than 5 MB."); return; }
      const reader = new FileReader();
      reader.onload = () => {
        if (!alive) return;
        q("#wb-input").value = String(reader.result).slice(0, 200000);
        q("#wb-title").value = "Upload — " + file.name;
        setError(null);
        preview();
        toast(file.name + " loaded — press Run triage.");
      };
      reader.readAsText(file);
    }

    function clearWorkspace() {
      const previous = { text: q("#wb-input").value, title: q("#wb-title").value, result: wb.result };
      q("#wb-input").value = ""; q("#wb-title").value = "";
      q("#wb-preview").innerHTML = "";
      setError(null);
      wb.result = null;
      q("#wb-results").hidden = true;
      if (previous.text || previous.result) {
        /* Destructive, so reversible rather than confirmed: clearing a box is
           not worth a dialog in the middle of a shift. */
        toast("Workspace cleared — press Undo to bring it back.");
        showUndo(() => {
          q("#wb-input").value = previous.text; q("#wb-title").value = previous.title;
          if (previous.result) { wb.result = previous.result; renderResult(previous.result); }
        });
      }
    }

    function showUndo(restore) {
      const box = q("#wb-preview");
      box.innerHTML = '<p class="wb-hint">Cleared. <button type="button" class="wb-link" data-act="undo">Undo</button></p>';
      wb.undo = restore;
    }

    /* ─── triage ─── */
    async function runTriage() {
      const text = q("#wb-input").value.trim();
      if (!text) { setError("Paste at least one indicator, a log line, or a JSON alert."); q("#wb-input").focus(); return; }
      setError(null);
      const button = q("#wb-run");
      button.disabled = true;
      button.setAttribute("aria-busy", "true");
      button.innerHTML = '<span class="wb-spinner" aria-hidden="true"></span> Triaging…';
      if (wb.mode === "live") {
        /* The same skeleton the console paints while a view loads, so a slow
           vendor reads as work in progress rather than a frozen page. */
        q("#wb-results").hidden = false;
        q("#wb-kpis").innerHTML = '<div class="skeleton wb-skeleton" aria-hidden="true"><div class="sk-row">' +
          '<span class="sk sk-kpi"></span><span class="sk sk-kpi"></span><span class="sk sk-kpi"></span><span class="sk sk-kpi"></span>' +
          '</div><span class="sk sk-panel"></span></div>';
      }
      try {
        const title = q("#wb-title").value.trim() || "Ad-hoc triage";
        let result;
        if (wb.mode === "demo") {
          result = E.demoTriage(text, DEMO, { title, lists: wb.lists });
        } else {
          result = await api("/api/triage", { method: "POST", body: JSON.stringify({ text, title, persist: true }) });
          result.mode = "live";
        }
        if (!alive) return;
        if (!result.indicators || !result.indicators.length) {
          setError("No routable indicators in that input — private and reserved address space is dropped on purpose.");
          q("#wb-results").hidden = true;
          return;
        }
        wb.showAll = false;
        wb.result = attachDiffs(result);
        pushHistory(result);
        renderResult(result);
        q("#wb-results").scrollIntoView({ behavior: C.reduceMotion() ? "auto" : "smooth", block: "start" });
      } catch (error) {
        if (!alive || error.name === "AbortError") return;
        toast("Triage failed: " + error.message);
        setError("That triage did not complete: " + error.message);
        if (wb.result) renderResult(wb.result); else q("#wb-results").hidden = true;
      } finally {
        if (alive) {
          button.disabled = false;
          button.removeAttribute("aria-busy");
          button.innerHTML = "Run triage <kbd>Ctrl ↵</kbd>";
        }
      }
    }

    /* Live mode gets its diffs from the API, which reads the case store. Demo
       mode keeps the last snapshot per indicator here and runs the identical
       comparison from the engine, so the renderer does not care which it got. */
    function attachDiffs(result) {
      const seen = store.get("snapshots", {});
      if (!Array.isArray(result.diffs) || !result.diffs.length) {
        result.diffs = (result.indicators || []).map((indicator) => {
          const previous = seen[indicator.value];
          return E.diffSnapshots(E.snapshotOf(indicator), previous ? previous.snapshot : null, {
            value: indicator.value,
            previous_case_id: previous ? previous.case_id : null,
            previous_at: previous ? previous.at : null
          });
        });
      }
      (result.indicators || []).forEach((indicator) => {
        seen[indicator.value] = { snapshot: E.snapshotOf(indicator), case_id: result.case_id, at: new Date().toISOString() };
      });
      store.set("snapshots", seen);
      return result;
    }

    function pushHistory(result) {
      const entry = {
        case_id: result.case_id, title: result.title, verdict: result.verdict, score: result.score,
        indicator_count: result.indicators.length, mode: result.mode || wb.mode, created_at: new Date().toISOString()
      };
      wb.history = [entry].concat(wb.history).slice(0, 25);
      store.set("history", wb.history);
      renderHistory();
    }

    /* ─── rendering ─── */
    function kpi(label, iconId, valueHtml, footHtml, extra) {
      return '<article class="card kpi wb-kpi' + (extra || "") + '">' +
        '<div class="kpi-top"><span class="kpi-ic"><svg><use href="#' + iconId + '"/></svg></span><b>' + label + "</b></div>" +
        valueHtml + '<div class="kpi-foot">' + footHtml + "</div></article>";
    }

    function renderResult(result) {
      q("#wb-results").hidden = false;
      const answered = result.indicators.reduce((s, i) => s + (i.providers_answered || 0), 0);
      const queried = result.indicators.reduce((s, i) => s + (i.providers_queried || 0), 0);
      const allSources = result.indicators.reduce((acc, i) => acc.concat(i.sources || []), []);
      const byType = Object.entries(result.indicators.reduce((acc, i) => { acc[i.type] = (acc[i.type] || 0) + 1; return acc; }, {}))
        .map(([k, v]) => v + " " + k).join(" · ");
      const worst = result.indicators.slice().sort((a, b) => b.score - a.score)[0];

      q("#wb-kpis").innerHTML =
        kpi("Case verdict", "i-shield",
          '<div class="wb-hero"><span class="val num" id="wb-hero" style="color:' + sevVar(result.verdict) + '">0</span>' +
          '<span class="wb-of">/100</span>' + badge(result.verdict) + "</div>",
          '<button type="button" class="wb-link" data-math="' + esc(worst ? worst.value : "") + '">How was this scored?</button>',
          " wb-kpi-hero") +
        kpi("Indicators", "i-target", '<div class="val num" id="wb-n">0</div>', "<small>" + esc(byType) + "</small>") +
        kpi("Sources answered", "i-globe", '<div class="val num"><span id="wb-cov">0</span><small class="wb-of">/' + queried + "</small></div>",
          C.coverageStrip(allSources)) +
        kpi("Enrichment", "i-clock", '<div class="val num"><span id="wb-ms">0</span><small class="wb-of"> ms</small></div>',
          "<small>" + (result.cache_hits ? result.cache_hits + " cached lookup(s)" : "no cache hits") + "</small>");

      C.tweenNumber(q("#wb-hero"), result.score, { duration: 620 });
      C.tweenNumber(q("#wb-n"), result.indicators.length, { duration: 420 });
      C.tweenNumber(q("#wb-cov"), answered, { duration: 420 });
      C.tweenNumber(q("#wb-ms"), result.duration_ms || 0, { duration: 520 });

      q("#wb-summary").textContent = result.summary || "";
      q("#wb-mode-note").innerHTML = (result.mode || wb.mode) === "demo"
        ? '<span class="status-pill">Sample data <span class="on">synthetic</span></span>'
        : '<span class="status-pill">Live <span class="on">vendor data</span></span>';
      renderIndicators(result);
      renderReport(result);
      renderResultGraph(result);
      renderTicketButton();
    }

    function diffPanel(diff) {
      if (!diff || diff.first_seen) return "";
      const tone = diff.escalated ? "worse" : diff.de_escalated ? "better" : "same";
      const when = diff.previous_at ? formatWhen(diff.previous_at) : null;
      const delta = diff.score_delta > 0 ? "+" + diff.score_delta : diff.score_delta < 0 ? String(diff.score_delta) : "0";
      return '<div class="chart wb-diff"><div class="chart-head">' +
          '<span class="chart-title">Since the last triage' + (when ? " · " + esc(when) : "") + "</span>" +
          /* Not a severity badge: "worse" is a direction of travel, not a verdict. */
          '<span class="wb-diff-tag ' + tone + '">' +
            (!diff.changed ? "no change" : diff.escalated ? "worse" : diff.de_escalated ? "better" : "changed") + "</span>" +
        "</div>" +
        /* Escaped although they should be numbers: in live mode they come from the API. */
        '<dl class="wb-kv"><dt>score</dt><dd class="num">' + esc(diff.previous_score) + " → " + esc(diff.score) +
          ' <span class="wb-muted">(' + esc(delta) + ")</span></dd>" +
          (diff.verdict_changed ? "<dt>verdict</dt><dd>" + esc(String(diff.previous_verdict)) + " → " + esc(String(diff.verdict)) + "</dd>" : "") +
          (diff.new_malware_families.length ? "<dt>new malware</dt><dd>" + diff.new_malware_families.map(esc).join(", ") + "</dd>" : "") +
          (diff.sources_added.length ? "<dt>now answering</dt><dd>" + diff.sources_added.map(esc).join(", ") + "</dd>" : "") +
          (diff.sources_removed.length ? "<dt>stopped answering</dt><dd>" + diff.sources_removed.map(esc).join(", ") + "</dd>" : "") +
          (diff.new_attack_ids.length ? "<dt>new techniques</dt><dd>" + diff.new_attack_ids.map(esc).join(", ") + "</dd>" : "") +
        "</dl></div>";
    }

    function renderIndicators(result) {
      const sorted = result.indicators.slice().sort((a, b) => b.score - a.score);
      const visible = wb.showAll ? sorted : sorted.slice(0, PAGE_SIZE);
      const hidden = sorted.length - visible.length;
      q("#wb-count").textContent = sorted.length + " indicator" + (sorted.length === 1 ? "" : "s");

      q("#wb-iocs").innerHTML = '<div class="wb-ioc-list">' + visible.map((indicator, index) => {
        const factLine = ([key, value]) =>
          /* The key column truncates; the title keeps the whole name one hover away. */
          '<div class="wb-fact" title="' + esc(key) + '"><span class="wb-fk">' + esc(key) + '</span><span class="wb-fv">' +
          esc(Array.isArray(value) ? value.join(", ") : typeof value === "object" ? JSON.stringify(value) : value) + "</span></div>";
        /* Facts stay attached to the source that reported them: merging them is
           how an analyst ends up citing the wrong vendor in a ticket. */
        const sources = (indicator.sources || []).map((s) => {
          const facts = Object.entries(s.facts || {})
            .filter(([, v]) => v !== null && v !== "" && v !== undefined && !(Array.isArray(v) && !v.length))
            .slice(0, 8).map(factLine).join("");
          const href = safeUrl(s.reference);
          return '<div class="wb-source"><div class="wb-source-name">' + esc(s.label || s.provider) + "</div>" +
            '<div class="wb-state ' + esc(s.status) + '">' + esc(s.status) +
              (s.cached ? " · cached" : "") + (s.latency_ms ? " · " + esc(s.latency_ms) + "ms" : "") + "</div>" +
            (s.error ? '<div class="wb-hint">' + esc(s.error) + "</div>" : "") +
            (facts ? '<div class="wb-facts">' + facts + "</div>" : "") +
            (href ? '<a class="wb-link" href="' + esc(href) + '" target="_blank" rel="noopener noreferrer">vendor page ↗</a>' : "") +
          "</div>";
        }).join("");
        const open = index === 0;
        const id = "wb-ioc-" + index;
        return '<article class="wb-ioc' + (open ? " open" : "") + '" data-ioc="' + esc(indicator.value) + '">' +
          '<button type="button" class="wb-ioc-top" aria-expanded="' + open + '" aria-controls="' + id + '">' +
            '<svg class="wb-chev" viewBox="0 0 24 24" aria-hidden="true"><path d="M9 6l6 6-6 6"/></svg>' +
            '<span class="wb-type">' + esc(indicator.type) + "</span>" +
            '<span class="wb-value">' + esc(indicator.value) + "</span>" +
            badge(indicator.verdict) +
            '<span class="wb-score num" style="color:' + sevVar(indicator.verdict) + '">' + esc(indicator.score) + "</span>" +
          "</button>" +
          '<div class="wb-ioc-detail" id="' + id + '"' + (open ? "" : " hidden") + ">" +
            '<dl class="wb-kv">' +
              "<dt>confidence</dt><dd>" + Math.round((indicator.confidence || 0) * 100) + "% " +
                C.meter(indicator.confidence) + ' <span class="wb-muted">' + esc(indicator.providers_answered) + "/" +
                esc(indicator.providers_queried) + " sources answered</span></dd>" +
              (indicator.context ? '<dt>log context</dt><dd class="wb-mono">' + esc(indicator.context) + "</dd>" : "") +
            "</dl>" +
            diffPanel((result.diffs || []).find((d) => d.value === indicator.value)) +
            C.contributionChart(indicator.evidence, { title: "Why this score" }) +
            ((indicator.modifiers || []).length
              ? '<div class="chart"><div class="chart-head"><span class="chart-title">Modifiers applied</span></div>' +
                '<ul class="wb-list">' + indicator.modifiers.map((m) => "<li>" + esc(m) + "</li>").join("") + "</ul></div>" : "") +
            ((indicator.malware_families || []).length || (indicator.attack_techniques || []).length || (indicator.tags || []).length
              ? '<div class="wb-chips">' +
                (indicator.malware_families || []).map((f) => '<span class="wb-chip malware">' + esc(f) + "</span>").join("") +
                (indicator.attack_techniques || []).map((t) => linkOrText(t.url, t.id + " · " + t.name, "wb-chip attack")).join("") +
                (indicator.tags || []).map((t) => '<span class="wb-chip">' + esc(t) + "</span>").join("") + "</div>" : "") +
            '<div class="wb-source-grid">' + sources + "</div>" +
            ((indicator.containment || []).length
              ? '<div class="chart"><div class="chart-head"><span class="chart-title">Recommended containment</span></div>' +
                '<ul class="wb-list">' + indicator.containment.map((a) => "<li>" + esc(a) + "</li>").join("") + "</ul></div>" : "") +
            '<div class="wb-row wb-actions">' +
              '<button type="button" class="btn btn-light btn-sm" data-copy="' + esc(indicator.value) + '">Copy</button>' +
              '<button type="button" class="btn btn-light btn-sm" data-list="allow" data-value="' + esc(indicator.value) + '" data-type="' + esc(indicator.type) + '">Allowlist</button>' +
              '<button type="button" class="btn btn-light btn-sm" data-list="block" data-value="' + esc(indicator.value) + '" data-type="' + esc(indicator.type) + '">Blocklist</button>' +
              '<button type="button" class="btn btn-light btn-sm" data-math="' + esc(indicator.value) + '">Scoring math</button>' +
            "</div>" +
          "</div></article>";
      }).join("") + "</div>" +
      (hidden > 0 ? '<div class="wb-row" style="justify-content:center"><button type="button" class="btn btn-light btn-sm" data-act="show-all">' +
        "Show all " + sorted.length + " indicators (" + hidden + " more)</button></div>" : "");
      C.bindTableToggles(q("#wb-iocs"));
    }

    function renderReport(result) {
      const markdown = E.toMarkdown(result, { demo: (result.mode || wb.mode) === "demo" });
      const report = q("#wb-report");
      report.textContent = markdown;       /* textContent: the ticket is data, never markup */
      report.dataset.markdown = markdown;
    }

    /* ─── the result's own graph ─── */
    /* ─── how they relate ───
       Indicators are gauges (the ring fills to the score, the colour is the
       verdict), everything they point at is a pill coloured by kind from the
       campaign graph's validated set, and a link is solid when the source was
       confident about it (0.7 or more) and dashed when it was not. Hovering or
       focusing a node lights its neighbourhood and names each link; the same
       facts are in the list under the graph, so nothing lives only on hover. */
    const GRAPH_CAP = 25;             // the indicator list pages at 25; so does the graph
    const KIND_OF = {
      malware: "malware", actor: "malware",
      asn: "infra", country: "infra",
      ip: "ioc", domain: "ioc", url: "ioc", hash: "ioc", email: "ioc"
    };
    const KIND_NAME = { malware: "Malware or actor", infra: "Infrastructure", ioc: "Related indicator", ref: "Report or CVE" };
    const KIND_ICON = {
      malware: "i-bot", actor: "i-target", asn: "i-layers", country: "i-flag", ip: "i-target",
      domain: "i-globe", url: "i-globe", hash: "i-key", email: "i-doc", pulse: "i-doc", cve: "i-shield"
    };
    const RING = 21, RING_C = 2 * Math.PI * RING;
    /* Severity is never colour alone: the glyph and the word ride with it. */
    const SEV_CHAR = { critical: "▲", high: "◆", medium: "■", low: "●", informational: "▬", allowlisted: "✓" };
    const clip = (text, max) => { const t = String(text); return t.length > max ? t.slice(0, max - 1) + "…" : t; };

    function graphModel(graph, indicators) {
      /* Keep the 25 highest-scoring indicators and what they point at. */
      const scoreOf = new Map((indicators || []).map((i) => [i.value, i]));
      const roots = graph.nodes.filter((n) => n.data.root)
        .sort((a, b) => (b.data.score || 0) - (a.data.score || 0));
      const keptRoots = new Set(roots.slice(0, GRAPH_CAP).map((n) => n.data.id));
      const keptEdges = graph.edges.filter((e) => keptRoots.has(e.data.source) || keptRoots.has(e.data.target));
      const keep = new Set(keptRoots);
      keptEdges.forEach((e) => { keep.add(e.data.source); keep.add(e.data.target); });
      const nodes = graph.nodes.filter((n) => keep.has(n.data.id)).map((n) => {
        const d = n.data, root = Boolean(d.root);
        const verdict = verdictOf(d.verdict);
        const label = clip(d.label, root ? 24 : 22);
        const mono = root || ["ip", "domain", "url", "hash", "asn", "cve"].includes(d.kind);
        /* Text width is estimated rather than measured: the layout runs before
           anything is in the DOM. Mono is 6.6px a character at 11px, sans 6.1. */
        const textW = label.length * (mono ? 6.6 : 6.1);
        const node = {
          id: String(d.id), data: d, root, verdict, label, mono,
          kind: root ? "root" : (KIND_OF[d.kind] || "ref"),
          indicator: root ? scoreOf.get(String(d.id).replace(/^ioc:/, "")) || null : null,
          w: root ? Math.max(60, textW + 10) : Math.round(textW + 44), h: root ? 90 : 26,
          oy: root ? 16 : 0, x: 0, y: 0
        };
        return node;
      });
      const index = new Map(nodes.map((n) => [n.id, n]));
      const edges = keptEdges.map((e, i) => ({
        i, source: index.get(String(e.data.source)), target: index.get(String(e.data.target)),
        label: String(e.data.label || "related to"), confidence: Number(e.data.confidence)
      })).filter((e) => e.source && e.target);
      /* Weak means a source said so. A link with no confidence at all is drawn
         plain: unknown is not the same as unsure. */
      edges.forEach((e) => { e.weak = Number.isFinite(e.confidence) && e.confidence < 0.7; });
      nodes.forEach((n) => { n.links = edges.filter((e) => e.source === n || e.target === n); });
      return { nodes, edges, index, hidden: Math.max(0, roots.length - GRAPH_CAP) };
    }

    /* Deterministic: the same case always draws the same picture. Connected
       groups get a cell each, roots start in their cell, their neighbours on a
       circle round them, and a short relaxation settles springs, a weak
       repulsion and box-against-box collisions. */
    function layoutGraph(model, width) {
      const { nodes, edges } = model;
      const parent = new Map(nodes.map((n) => [n.id, n.id]));
      const find = (x) => { while (parent.get(x) !== x) { parent.set(x, parent.get(parent.get(x))); x = parent.get(x); } return x; };
      edges.forEach((e) => { const a = find(e.source.id), b = find(e.target.id); if (a !== b) parent.set(a, b); });
      const groups = new Map();
      nodes.forEach((n) => { const g = find(n.id); if (!groups.has(g)) groups.set(g, []); groups.get(g).push(n); });
      const comps = [...groups.values()].sort((a, b) =>
        Math.max(...b.map((n) => n.data.score || 0)) - Math.max(...a.map((n) => n.data.score || 0)) || b.length - a.length);

      const area = nodes.reduce((sum, n) => sum + (n.w + 40) * (n.h + 34), 0);
      const height = Math.round(Math.min(900, Math.max(width < 520 ? 360 : 400, (area / width) * 1.7)));
      const cols = Math.max(1, Math.min(comps.length, Math.round(Math.sqrt(comps.length * width / height))));
      const rows = Math.ceil(comps.length / cols);
      comps.forEach((comp, ci) => {
        const cx = ((ci % cols) + 0.5) * width / cols, cy = (Math.floor(ci / cols) + 0.5) * height / rows;
        const roots = comp.filter((n) => n.root);
        roots.forEach((r, ri) => { r.ax = cx; r.ay = cy; r.x = cx + (ri - (roots.length - 1) / 2) * 120; r.y = cy - 10; });
        const around = new Map();
        comp.filter((n) => !n.root).forEach((n) => {
          const owners = n.links.map((e) => (e.source === n ? e.target : e.source)).filter((o) => o.root);
          n.ax = cx; n.ay = cy;
          if (owners.length > 1) {
            n.x = owners.reduce((s, o) => s + o.x, 0) / owners.length;
            n.y = owners.reduce((s, o) => s + o.y, 0) / owners.length + 70;
            return;
          }
          const owner = owners[0] || roots[0] || { x: cx, y: cy, id: "" };
          if (!around.has(owner.id)) around.set(owner.id, []);
          around.get(owner.id).push(n);
          n.owner = owner;
        });
        around.forEach((list) => list.forEach((n, k) => {
          const angle = -Math.PI / 2 + (k + 0.5) * (2 * Math.PI / list.length);
          n.x = n.owner.x + Math.cos(angle) * 125; n.y = n.owner.y + Math.sin(angle) * 105;
        }));
      });

      const pad = 12;
      for (let step = 0, steps = 260; step < steps; step++) {
        const alpha = 1 - step / steps;
        edges.forEach((e) => {
          const a = e.source, b = e.target;
          const rest = (a.root ? 36 : a.w / 2) + (b.root ? 36 : b.w / 2) + 72;
          const dx = b.x - a.x, dy = b.y - a.y, d = Math.max(1, Math.hypot(dx, dy));
          const f = (d - rest) * 0.06 * alpha, fx = (dx / d) * f, fy = (dy / d) * f;
          const wa = a.root ? 0.25 : 1, wb = b.root ? 0.25 : 1;
          a.x += fx * wa; a.y += fy * wa; b.x -= fx * wb; b.y -= fy * wb;
        });
        for (let i = 0; i < nodes.length; i++) {
          const a = nodes[i];
          a.x += (a.ax - a.x) * 0.012 * alpha; a.y += (a.ay - a.y) * 0.012 * alpha;
          for (let j = i + 1; j < nodes.length; j++) {
            const b = nodes[j];
            const dx = b.x - a.x, dy = (b.y + b.oy) - (a.y + a.oy);
            const d2 = Math.max(400, dx * dx + dy * dy), push = 2600 * alpha / d2, d = Math.sqrt(d2);
            a.x -= (dx / d) * push; a.y -= (dy / d) * push; b.x += (dx / d) * push; b.y += (dy / d) * push;
            /* boxes that still overlap separate along the shallower axis */
            const ox = (a.w + b.w) / 2 + pad - Math.abs(dx), oy = (a.h + b.h) / 2 + pad - Math.abs(dy);
            if (ox > 0 && oy > 0) {
              if (ox < oy) { const m = (ox / 2) * Math.sign(dx || 1); a.x -= m; b.x += m; }
              else { const m = (oy / 2) * Math.sign(dy || 1); a.y -= m; b.y += m; }
            }
          }
        }
        nodes.forEach((n) => {
          n.x = Math.min(width - n.w / 2 - 6, Math.max(n.w / 2 + 6, n.x));
          n.y = Math.min(height - n.h / 2 - n.oy - 6, Math.max(n.h / 2 - n.oy + 6, n.y));
        });
      }
      return height;
    }

    /* How far from a node's centre a link becomes visible: the ring's edge for
       an indicator, the pill's border for anything else. */
    function reach(n, ux, uy) {
      if (n.root) {
        /* Below the ring sit the value and the verdict (y 28 to 60, the node's
           width across). A link heading into that block becomes visible where
           it leaves it; any other way, at the ring. */
        if (uy <= 0) return 30;
        const enter = 28 / uy, exitX = Math.abs(ux) > 1e-6 ? (n.w / 2) / Math.abs(ux) : Infinity, exitY = 60 / uy;
        return enter < exitX ? Math.max(30, Math.min(exitX, exitY)) : 30;
      }
      const tx = Math.abs(ux) > 1e-6 ? (n.w / 2) / Math.abs(ux) : Infinity;
      const ty = Math.abs(uy) > 1e-6 ? (n.h / 2) / Math.abs(uy) : Infinity;
      return Math.min(tx, ty);
    }
    function edgePath(e) {
      const a = e.source, b = e.target;
      const mx = (a.x + b.x) / 2, my = (a.y + b.y) / 2, dx = b.x - a.x, dy = b.y - a.y;
      const bend = (e.i % 2 ? -1 : 1) * 0.12;
      const cx = mx - dy * bend, cy = my + dx * bend;
      /* The link's name goes halfway along the part you can see, not halfway
         between the centres, which on a short link is on top of a node. */
      const len = Math.max(1, Math.hypot(dx, dy)), ux = dx / len, uy = dy / len;
      const ra = reach(a, ux, uy), rb = reach(b, -ux, -uy);
      const visible = Math.max(0, len - ra - rb);
      const t = Math.min(0.8, Math.max(0.2, (ra + visible / 2) / len));
      /* A name only goes on a link that has room for it, measured along the
         link's own direction; the readout names every link either way. */
      e.labelW = e.label.length * 5.7 + 14;
      e.fits = visible >= Math.abs(ux) * e.labelW + Math.abs(uy) * 18 + 8;
      e.mid = {
        x: (1 - t) * (1 - t) * a.x + 2 * (1 - t) * t * cx + t * t * b.x,
        y: (1 - t) * (1 - t) * a.y + 2 * (1 - t) * t * cy + t * t * b.y
      };
      return "M" + a.x.toFixed(1) + " " + a.y.toFixed(1) + "Q" + cx.toFixed(1) + " " + cy.toFixed(1) + " " +
        b.x.toFixed(1) + " " + b.y.toFixed(1);
    }

    function nodeMarkup(n, delay) {
      const rel = n.links.map((e) => e.label + " " + (e.source === n ? e.target : e.source).data.label);
      const title = "<title>" + esc(n.data.label + (rel.length ? " — " + rel.join("; ") : "")) + "</title>";
      const open = '<g class="wb-node ' + (n.root ? "root ioc sev-" + n.verdict : "ent k-" + n.kind) +
        '" data-node="' + esc(n.id) + '" transform="translate(' + n.x.toFixed(1) + "," + n.y.toFixed(1) + ')">' + title +
        '<g class="wb-node-body" style="--d:' + delay + 'ms">';
      if (n.root) {
        const score = Math.max(0, Math.min(100, Number(n.data.score) || 0));
        return open +
          '<circle class="wb-glow" r="44"/>' +
          (n.verdict === "critical" ? '<circle class="wb-pulse" r="' + RING + '"/>' : "") +
          '<g class="wb-hit" tabindex="0" role="button" aria-label="' + esc("Open the evidence for " + n.data.label +
            ", " + n.verdict + ", score " + score) + '">' +
            '<circle class="wb-hit-area" r="27"/>' +
            '<circle class="wb-ring-track" r="' + RING + '"/>' +
            /* a zero-length arc with a round cap still paints a dot, so a 0 draws no arc */
            (score > 0 ? '<circle class="wb-ring" r="' + RING + '" transform="rotate(-90)" stroke-dasharray="' +
              (RING_C * score / 100).toFixed(1) + " " + RING_C.toFixed(1) + '"/>' : "") +
            '<circle class="wb-core" r="15.5"/>' +
            '<text class="wb-score" y="4.5" text-anchor="middle">' + esc(score) + "</text>" +
          "</g>" +
          '<text class="wb-label mono" y="' + (RING + 17) + '" text-anchor="middle">' + esc(n.label) + "</text>" +
          '<text class="wb-sub" y="' + (RING + 31) + '" text-anchor="middle">' + esc(SEV_CHAR[n.verdict] + " " + n.verdict.toUpperCase()) + "</text>" +
          "</g></g>";
      }
      const left = -n.w / 2;
      return open +
        '<rect class="wb-pill" x="' + left.toFixed(1) + '" y="-13" width="' + n.w.toFixed(1) + '" height="26" rx="13"/>' +
        '<circle class="wb-kdot" cx="' + (left + 14).toFixed(1) + '" r="9"/>' +
        '<use class="wb-gicon" href="#' + (KIND_ICON[n.data.kind] || "i-dots") + '" x="' + (left + 8.5).toFixed(1) +
          '" y="-5.5" width="11" height="11"/>' +
        '<text class="wb-plabel' + (n.mono ? " mono" : "") + '" x="' + (left + 29).toFixed(1) + '" y="3.8">' + esc(n.label) + "</text>" +
        "</g></g>";
    }

    function renderResultGraph(result) {
      const box = q("#wb-graph");
      const graph = result.graph || E.buildGraph(result.indicators || []);
      if (!graph || !graph.nodes || !graph.nodes.length) {
        box.innerHTML = '<p class="wb-hint">Nothing to relate: a single indicator has no neighbours.</p>';
        return;
      }
      const model = graphModel(graph, result.indicators);
      const width = Math.max(320, Math.round(box.clientWidth || 640));
      const height = layoutGraph(model, width);
      const { nodes, edges } = model;
      /* Roots first, then outward: each node's entrance waits on the one it hangs off. */
      const delay = (n) => n.root ? nodes.filter((m) => m.root).indexOf(n) * 70
        : 180 + Math.min(600, Math.round(Math.hypot(n.x - (n.owner || n).x, n.y - (n.owner || n).y) * 1.6));
      /* Animate a case once. A theme flip remounts the view, and replaying the
         entrance for a picture the analyst has already read is noise. */
      const animate = !C.reduceMotion() && wb.graphShown !== result.case_id;
      wb.graphShown = result.case_id;
      const roots = nodes.filter((n) => n.root).length;
      const stat = (value, label) => '<span class="wb-gstat"><b>' + esc(value) + "</b> " + esc(label) + "</span>";

      box.innerHTML =
        '<div class="wb-gstats">' +
          stat(roots, roots === 1 ? "indicator" : "indicators") +
          stat(nodes.length - roots, "linked entities") +
          stat(edges.length, (edges.length === 1 ? "link" : "links") + ", " +
            edges.filter((e) => !e.weak).length + " of them confident") +
        "</div>" +
        '<div class="wb-gstage' + (animate ? " enter" : "") + '">' +
          '<svg class="wb-svg" viewBox="0 0 ' + width + " " + height + '" width="' + width + '" height="' + height +
            '" role="group" aria-label="How the indicators in this case relate to each other">' +
            '<defs><pattern id="wb-dots" width="18" height="18" patternUnits="userSpaceOnUse">' +
              '<circle class="wb-dot" cx="1.5" cy="1.5" r="1"/></pattern>' +
              '<filter id="wb-blur" x="-50%" y="-50%" width="200%" height="200%"><feGaussianBlur stdDeviation="9"/></filter></defs>' +
            '<rect class="wb-field" width="' + width + '" height="' + height + '" fill="url(#wb-dots)"/>' +
            '<g class="wb-edges">' + edges.map((e) =>
              '<path class="wb-edge' + (e.weak ? " weak" : "") + '" data-edge="' + e.i + '" d="' + edgePath(e) +
                '" style="--d:' + (animate ? Math.max(delay(e.source), delay(e.target)) - 80 : 0) + 'ms"/>').join("") + "</g>" +
            '<g class="wb-nodes">' + nodes.map((n) => nodeMarkup(n, animate ? delay(n) : 0)).join("") + "</g>" +
            /* Link names, drawn last so they sit above the nodes; shown only for the node in focus. */
            '<g class="wb-elabels" aria-hidden="true">' + edges.map((e) => {
              const w = e.labelW;
              return '<g class="wb-elabel' + (e.fits ? "" : " tight") + '" data-edge="' + e.i + '" transform="translate(' + e.mid.x.toFixed(1) + "," + e.mid.y.toFixed(1) + ')">' +
                '<rect x="' + (-w / 2).toFixed(1) + '" y="-9" width="' + w.toFixed(1) + '" height="18" rx="9"/>' +
                '<text y="3.5" text-anchor="middle">' + esc(e.label) + "</text></g>";
            }).join("") + "</g>" +
          "</svg>" +
          '<div class="wb-gread" role="status" aria-live="polite" hidden></div>' +
        "</div>" +
        '<div class="wb-glegend" aria-label="Legend">' +
          '<span class="wb-gkey"><svg viewBox="-12 -12 24 24" aria-hidden="true"><circle class="wb-ring-track" r="9"/>' +
            '<circle class="wb-ring key" r="9" transform="rotate(-90)" stroke-dasharray="40 57"/></svg>Indicator: the ring fills to the score</span>' +
          ["malware", "infra", "ioc", "ref"].map((k) =>
            '<span class="wb-gkey"><i class="wb-kswatch k-' + k + '"></i>' + esc(KIND_NAME[k]) + "</span>").join("") +
          '<span class="wb-gkey"><svg viewBox="0 0 26 8" aria-hidden="true"><path class="wb-edge" d="M1 4H25"/></svg>Confident link</span>' +
          '<span class="wb-gkey"><svg viewBox="0 0 26 8" aria-hidden="true"><path class="wb-edge weak" d="M1 4H25"/></svg>Weaker link</span>' +
        "</div>" +
        (model.hidden ? '<p class="wb-hint">Showing the ' + GRAPH_CAP + " highest-scoring indicators; the list above has all " +
          esc(model.hidden + GRAPH_CAP) + ".</p>" : "") +
        /* The same graph as a list, for anyone who cannot read the picture. */
        '<details class="wb-graph-table"><summary>Read the relationships as a list</summary><ul>' +
          edges.map((e) => "<li>" + esc(e.source.data.label) + " — " + esc(e.label) + " → " + esc(e.target.data.label) +
            (e.weak ? " (weaker link)" : "") + "</li>").join("") + "</ul></details>";
      graphState = { model, width, active: null };
    }

    /* One node at a time is "in focus": its links and neighbours stay lit, the
       rest of the picture steps back, and a readout names what it is. */
    let graphState = null;
    function lightNode(id) {
      const stage = q("#wb-graph .wb-gstage");
      if (!stage || !graphState) return;
      const svg = stage.querySelector("svg"), read = stage.querySelector(".wb-gread");
      const node = id ? graphState.model.index.get(id) : null;
      if (graphState.active === (node && node.id)) return;
      graphState.active = node ? node.id : null;
      $$(".is-lit", svg).forEach((el) => el.classList.remove("is-lit"));
      svg.classList.toggle("has-focus", Boolean(node));
      if (!node) { read.hidden = true; return; }
      const lit = new Set([node.id]);
      node.links.forEach((e) => {
        lit.add(e.source.id); lit.add(e.target.id);
        $$('[data-edge="' + e.i + '"]', svg).forEach((el) => el.classList.add("is-lit"));
      });
      $$(".wb-node", svg).forEach((el) => { if (lit.has(el.dataset.node)) el.classList.add("is-lit"); });

      /* Built with textContent throughout: every string here came from a log
         line or a provider response. */
      read.textContent = "";
      const add = (tag, cls, text) => { const el = document.createElement(tag); if (cls) el.className = cls; el.textContent = text; read.appendChild(el); return el; };
      add("div", "wb-gread-title" + (node.mono ? " mono" : ""), node.data.label);
      if (node.root) {
        const ind = node.indicator;
        add("div", "wb-gread-sub", String(node.data.kind || "indicator").toUpperCase() + " · score " +
          Math.round(Number(node.data.score) || 0) + "/100 · " + node.verdict);
        if (ind) add("div", "wb-gread-row", (ind.providers_answered || 0) + " of " + (ind.providers_queried || 0) + " sources answered");
      } else {
        add("div", "wb-gread-sub", KIND_NAME[node.kind] + (node.data.kind ? " · " + node.data.kind : ""));
        if (node.data.source_provider) add("div", "wb-gread-row", "Reported by " + node.data.source_provider);
      }
      node.links.slice(0, 5).forEach((e) => {
        const other = e.source === node ? e.target : e.source;
        add("div", "wb-gread-link", (e.source === node ? e.label + " → " : "← " + e.label + " · ") + other.data.label +
          (e.weak ? " (weaker)" : ""));
      });
      if (node.links.length > 5) add("div", "wb-gread-row", "and " + (node.links.length - 5) + " more");
      if (node.root) add("div", "wb-gread-hint", "Click or press Enter to open the evidence");
      read.hidden = false;

      /* In whichever corner of the stage covers least of what is lit: the node
         and its neighbours are what the reader is looking at. */
      const scale = svg.getBoundingClientRect().width / graphState.width;
      const box = [...lit].map((id) => graphState.model.index.get(id)).reduce((acc, n) => ({
        l: Math.min(acc.l, (n.x - n.w / 2) * scale), r: Math.max(acc.r, (n.x + n.w / 2) * scale),
        t: Math.min(acc.t, (n.y + n.oy - n.h / 2) * scale), b: Math.max(acc.b, (n.y + n.oy + n.h / 2) * scale)
      }), { l: Infinity, r: -Infinity, t: Infinity, b: -Infinity });
      const stageW = stage.clientWidth, stageH = stage.clientHeight, cardW = read.offsetWidth, cardH = read.offsetHeight, m = 10;
      const corners = [[m, m], [stageW - cardW - m, m], [m, stageH - cardH - m], [stageW - cardW - m, stageH - cardH - m]];
      const overlap = ([x, y]) => Math.max(0, Math.min(x + cardW, box.r) - Math.max(x, box.l)) *
        Math.max(0, Math.min(y + cardH, box.b) - Math.max(y, box.t));
      const [left, top] = corners.reduce((best, c) => (overlap(c) < overlap(best) ? c : best));
      read.style.left = Math.max(m, left) + "px";
      read.style.top = Math.max(m, top) + "px";
    }
    function onGraphPointer(event) {
      /* A finger has no hover: a tap shows a node (see onClick), and content
         scrolling under a resting touch point must not light one up. */
      if (event.pointerType === "touch") return;
      const g = event.target.closest && event.target.closest("#wb-graph .wb-node");
      if (event.type === "pointerover" && g) lightNode(g.dataset.node);
      if (event.type === "pointerout" && g && !(event.relatedTarget && g.contains(event.relatedTarget))) {
        const next = event.relatedTarget && event.relatedTarget.closest && event.relatedTarget.closest("#wb-graph .wb-node");
        if (!next) lightNode(null);
      }
    }
    function onGraphFocus(event) {
      const g = event.target.closest && event.target.closest("#wb-graph .wb-node");
      if (event.type === "focusin" && g) lightNode(g.dataset.node);
      if (event.type === "focusout" && g) lightNode(null);
    }

    function focusIoc(nodeId) {
      if (!nodeId || !String(nodeId).startsWith("ioc:")) return;
      const value = String(nodeId).slice(4);
      const card = $$(".wb-ioc", root).find((el) => el.dataset.ioc === value);
      if (!card) return;
      toggleIoc(card, true);
      card.scrollIntoView({ behavior: C.reduceMotion() ? "auto" : "smooth", block: "center" });
      card.querySelector(".wb-ioc-top").focus({ preventScroll: true });
    }

    function toggleIoc(card, force) {
      const open = typeof force === "boolean" ? force : !card.classList.contains("open");
      card.classList.toggle("open", open);
      card.querySelector(".wb-ioc-top").setAttribute("aria-expanded", String(open));
      card.querySelector(".wb-ioc-detail").hidden = !open;
    }

    /* ─── scoring math, in a real dialog ─── */
    function showScoringMath(indicator, trigger) {
      if (!indicator) return;
      const rows = (indicator.evidence || []).slice().sort((a, b) => b.weighted - a.weighted);
      const weightSum = rows.reduce((s, r) => s + r.weight, 0);
      const weightedSum = rows.reduce((s, r) => s + r.weighted, 0);
      const mean = weightSum ? weightedSum / weightSum : 0;
      const floor = rows.reduce((max, r) => Math.max(max, r.signal * (E.AUTHORITY[r.provider] || 0.5)), 0);
      q("#wb-dialog-title").textContent = "Scoring math — " + indicator.value;
      q("#wb-dialog-body").innerHTML =
        '<div class="table-wrap"><table class="table wb-math"><thead><tr><th>Source</th><th>Signal</th><th>Weight</th>' +
        "<th>Weighted</th><th>Authority</th><th>Floor</th></tr></thead><tbody>" +
        rows.map((r) => {
          const authority = E.AUTHORITY[r.provider] || 0.5;
          return '<tr><td data-label="Source">' + esc(r.provider) + '</td><td data-label="Signal" class="mono">' + r.signal.toFixed(2) +
            '</td><td data-label="Weight" class="mono">' + esc(r.weight) + '</td><td data-label="Weighted" class="mono">' + r.weighted.toFixed(2) +
            '</td><td data-label="Authority" class="mono">' + authority + '</td><td data-label="Floor" class="mono">' + (r.signal * authority).toFixed(2) + "</td></tr>";
        }).join("") + "</tbody></table></div>" +
        '<pre class="wb-report wb-math-out">' + esc(
          "weighted mean   = " + weightedSum.toFixed(2) + " / " + weightSum.toFixed(2) + " = " + mean.toFixed(3) + "\n" +
          "authority floor = " + floor.toFixed(3) + "\n" +
          "score           = 100 × max(" + mean.toFixed(3) + ", " + floor.toFixed(3) + ") = " + Math.round(Math.max(mean, floor) * 100) + "\n" +
          ((indicator.modifiers || []).length ? "modifiers       = " + indicator.modifiers.join("; ") + "\n" : "") +
          "final           = " + indicator.score + "/100 (" + String(indicator.verdict).toUpperCase() + ")") + "</pre>";
      const dialog = q("#wb-dialog");
      dialogReturn = trigger || document.activeElement;
      if (typeof dialog.showModal === "function") dialog.showModal();
      else dialog.setAttribute("open", "");
      q('#wb-dialog [data-act="close-dialog"]').focus();
    }
    function closeDialog() {
      const dialog = q("#wb-dialog");
      if (dialog.open) { if (typeof dialog.close === "function") dialog.close(); else dialog.removeAttribute("open"); }
    }

    /* ─── lists, report, ticket ─── */
    async function addToList(value, type, list) {
      if (wb.mode === "live") {
        try {
          await api("/api/lists", { method: "POST", body: JSON.stringify({ value, ioc_type: type, list_type: list, reason: "added from the console" }) });
          toast(value + " added to the " + list + "list.");
        } catch (error) { if (error.name !== "AbortError") toast("Could not update the list: " + error.message); }
        return;
      }
      wb.lists = wb.lists.filter((e) => String(e.value).toLowerCase() !== String(value).toLowerCase());
      wb.lists.push({ value, ioc_type: type, list_type: list, reason: "added from the console (demo)" });
      store.set("lists", wb.lists);
      toast(value + " " + list + "listed — run the triage again to see the override.");
    }

    function copyText(text, done) {
      const fallback = () => toast("The browser blocked the clipboard.");
      if (!navigator.clipboard) { fallback(); return; }
      navigator.clipboard.writeText(text).then(() => toast(done)).catch(fallback);
    }

    function downloadReport(kind) {
      if (!wb.result) return;
      const stem = "intelpulse-" + String(wb.result.case_id || "case").slice(0, 8);
      if (kind === "json") {
        const ticket = E.toTicketJson(wb.result, { demo: (wb.result.mode || wb.mode) === "demo" });
        download(stem + ".json", JSON.stringify(ticket, null, 2), "application/json");
      } else {
        download(stem + ".md", q("#wb-report").dataset.markdown || "", "text/markdown");
      }
      toast("Ticket downloaded.");
    }

    /* Downloading Markdown and pasting it by hand is the step that gets skipped,
       so this is here — but only when the backend says it can deliver. */
    function renderTicketButton() {
      const button = q("#wb-raise"), note = q("#wb-ticket-note");
      if (!button) return;
      const sinks = (wb.mode === "live" && wb.health && Array.isArray(wb.health.ticket_sinks))
        ? wb.health.ticket_sinks.filter((s) => SINK_LABELS[s]) : [];
      button.hidden = sinks.length === 0 || !wb.result;
      if (button.hidden) { if (note && wb.mode === "demo") note.textContent = ""; return; }
      button.dataset.sink = sinks[0];
      button.textContent = "Raise in " + SINK_LABELS[sinks[0]];
      button.disabled = false;
    }

    async function raiseTicket() {
      const button = q("#wb-raise"), note = q("#wb-ticket-note");
      const sink = button.dataset.sink;
      if (!wb.result || !sink || wb.mode !== "live") return;
      const label = button.textContent;
      button.disabled = true; button.textContent = "Raising…"; note.textContent = "";
      try {
        const ticket = await api("/api/cases/" + encodeURIComponent(wb.result.case_id) + "/ticket?sink=" + encodeURIComponent(sink), { method: "POST" });
        if (!alive) return;
        note.innerHTML = "Raised as " + linkOrText(ticket.url, ticket.key || "the ticket", "wb-link") + ".";
        toast("Raised " + (ticket.key || "the ticket") + " in " + SINK_LABELS[sink]);
      } catch (error) {
        if (!alive || error.name === "AbortError") return;
        note.textContent = "Could not raise the ticket: " + error.message;
      } finally {
        if (alive) { button.disabled = false; button.textContent = label; }
      }
    }

    /* ─── history ─── */
    async function renderHistory() {
      const box = q("#wb-history");
      if (!box) return;
      let rows = wb.history;
      if (wb.mode === "live") {
        try {
          rows = (await api("/api/cases?limit=25")).map((c) => ({
            case_id: c.id, title: c.title, verdict: c.verdict, score: c.max_score,
            indicator_count: c.indicator_count, mode: "live", created_at: c.created_at
          }));
        } catch (_) { /* fall back to this browser's history */ }
        if (!alive) return;
      }
      if (!rows.length) {
        box.innerHTML = '<div class="empty-state"><b>No cases yet</b><span>Every triage you run is recorded here, newest first.</span></div>';
        return;
      }
      box.innerHTML = '<div class="table-wrap"><table class="table wb-history"><thead><tr><th>Case</th><th>Title</th>' +
        "<th>Verdict</th><th>Score</th><th>When</th></tr></thead><tbody>" +
        rows.map((r) => '<tr><td data-label="Case" class="mono">' + esc(String(r.case_id || "").slice(0, 8)) +
          '</td><td data-label="Title">' + esc(r.title) + '</td><td data-label="Verdict">' + badge(r.verdict) +
          '</td><td data-label="Score" class="mono">' + esc(r.score) + " · " + esc(r.indicator_count) + ' IOC</td><td data-label="When" class="mono">' +
          esc(formatWhen(r.created_at)) + "</td></tr>").join("") + "</tbody></table></div>";
    }

    /* ─── wiring: one delegated listener, so unmount is one removal ─── */
    function onClick(event) {
      const t = event.target;
      const mode = t.closest("[data-mode]");
      if (mode) { setMode(mode.dataset.mode); return; }
      const scenario = t.closest("[data-scenario]");
      if (scenario) { loadScenario(scenario.dataset.scenario); return; }
      const top = t.closest(".wb-ioc-top");
      if (top) { toggleIoc(top.closest(".wb-ioc")); return; }
      const node = t.closest(".wb-node.root");
      if (node) { focusIoc(node.dataset.node); return; }
      const entity = t.closest("#wb-graph .wb-node.ent");
      if (entity) { lightNode(graphState && graphState.active === entity.dataset.node ? null : entity.dataset.node); return; }
      if (t.closest("#wb-graph .wb-gstage")) { lightNode(null); return; }
      const copy = t.closest("[data-copy]");
      if (copy) { copyText(copy.dataset.copy, "Copied " + copy.dataset.copy); return; }
      const list = t.closest("[data-list]");
      if (list) { addToList(list.dataset.value, list.dataset.type, list.dataset.list); return; }
      const math = t.closest("[data-math]");
      if (math && wb.result) {
        showScoringMath(wb.result.indicators.find((i) => i.value === math.dataset.math), math);
        return;
      }
      const act = t.closest("[data-act]");
      if (!act) return;
      switch (act.dataset.act) {
        case "run": runTriage(); break;
        case "preview": preview(); break;
        case "clear": clearWorkspace(); break;
        case "undo": if (wb.undo) { wb.undo(); wb.undo = null; q("#wb-preview").innerHTML = ""; } break;
        case "connect": {
          /* On the field, not in a toast: an error that disappears before it is
             read, next to nothing, is how a typo becomes an hour of debugging. */
          const field = q("#wb-api"), box = q("#wb-api-error");
          const value = field.value.trim();
          if (!safeUrl(value)) {
            field.setAttribute("aria-invalid", "true");
            box.textContent = "That is not an address. Use the full URL, starting with http:// or https://";
            box.hidden = false; field.focus();
            return;
          }
          field.removeAttribute("aria-invalid"); box.hidden = true; box.textContent = "";
          wb.apiBase = value; store.set("apiBase", value); checkHealth(); break;
        }
        case "show-all": wb.showAll = true; renderIndicators(wb.result); break;
        case "copy-report": copyText(q("#wb-report").dataset.markdown || "", "Markdown ticket copied."); break;
        case "download-md": downloadReport("md"); break;
        case "download-json": downloadReport("json"); break;
        case "raise": raiseTicket(); break;
        case "close-dialog": closeDialog(); break;
      }
    }
    function onKey(event) {
      if ((event.metaKey || event.ctrlKey) && event.key === "Enter" && root.contains(event.target)) {
        event.preventDefault(); runTriage(); return;
      }
      const node = event.target.closest && event.target.closest(".wb-node.root");
      if (node && (event.key === "Enter" || event.key === " ")) { event.preventDefault(); focusIoc(node.dataset.node); }
      if (event.key === "Escape" && graphState && graphState.active) { lightNode(null); }
    }
    function onChange(event) {
      if (event.target.id === "wb-file") { readFile(event.target.files[0]); event.target.value = ""; }
    }
    function onInput(event) {
      if (event.target.id === "wb-input") { wb.draft.text = event.target.value; if (event.target.value.trim()) setError(null); }
      if (event.target.id === "wb-title") wb.draft.title = event.target.value;
    }
    const dialog = q("#wb-dialog");
    function onDialogClose() { if (dialogReturn && dialogReturn.focus) dialogReturn.focus(); dialogReturn = null; }
    function onDialogClick(event) { if (event.target === dialog) closeDialog(); }   /* the backdrop */

    root.addEventListener("click", onClick);
    root.addEventListener("keydown", onKey);
    root.addEventListener("change", onChange);
    root.addEventListener("input", onInput);
    root.addEventListener("pointerover", onGraphPointer);
    root.addEventListener("pointerout", onGraphPointer);
    root.addEventListener("focusin", onGraphFocus);
    root.addEventListener("focusout", onGraphFocus);
    dialog.addEventListener("close", onDialogClose);
    dialog.addEventListener("click", onDialogClick);

    /* What the browser suite drives: rendering a hand-built result (a hostile
       provider response, say) and the URL check itself. Only while mounted. */
    window.IntelPulse = {
      render(result) { wb.result = result; renderResult(result); },
      safeUrl,
      get result() { return wb.result; }
    };

    /* Coming back to the pane finds the draft and the open case where they were. */
    q("#wb-input").value = wb.draft.text;
    q("#wb-title").value = wb.draft.title;
    checkHealth();
    renderHistory();
    if (wb.result) renderResult(wb.result);

    return function unmount() {
      alive = false;
      if (window.IntelPulse && window.IntelPulse.safeUrl === safeUrl) delete window.IntelPulse;
      inflight.forEach((c) => c.abort());
      inflight.clear();
      closeDialog();
      root.removeEventListener("click", onClick);
      root.removeEventListener("keydown", onKey);
      root.removeEventListener("change", onChange);
      root.removeEventListener("input", onInput);
      root.removeEventListener("pointerover", onGraphPointer);
      root.removeEventListener("pointerout", onGraphPointer);
      root.removeEventListener("focusin", onGraphFocus);
      root.removeEventListener("focusout", onGraphFocus);
      dialog.removeEventListener("close", onDialogClose);
      dialog.removeEventListener("click", onDialogClick);
    };
  }

  /* ═══════════════════════════════════════════════ the campaign graph ══ */

  /* Every value here is synthetic: RFC 5737 documentation addresses, RFC 2606
     reserved names and invented family names. Nothing describes a real host. */
  const CLUSTERS = [
    { id: "sb",   label: "SampleBot C2",            kind: "malware", pct: 31, seen: 2017, nodes: 8, sev: "critical" },
    { id: "ldr",  label: "SampleLoader",            kind: "malware", pct: 22, seen: 2018, nodes: 6, sev: "high" },
    { id: "phk",  label: "SamplePhishKit",          kind: "malware", pct: 17, seen: 2019, nodes: 6, sev: "high" },
    { id: "stl",  label: "SampleStealer",           kind: "malware", pct: 11, seen: 2020, nodes: 5, sev: "medium" },
    { id: "rat",  label: "SampleRAT",               kind: "malware", pct: 14, seen: 2022, nodes: 5, sev: "high" },
    { id: "as1",  label: "AS200019 · hosting", kind: "infra",   pct: 38, seen: 2016, nodes: 7, sev: "high" },
    { id: "as2",  label: "AS14061 · cloud",    kind: "infra",   pct: 25, seen: 2018, nodes: 6, sev: "medium" },
    { id: "as3",  label: "AS24940 · transit",  kind: "infra",   pct: 13, seen: 2017, nodes: 5, sev: "low" },
    { id: "dns",  label: "example.org · DNS",  kind: "infra",   pct: 22, seen: 2019, nodes: 6, sev: "medium" },
    { id: "bp",   label: "Bulletproof range",       kind: "infra",   pct: 19, seen: 2021, nodes: 5, sev: "high" },
    { id: "ioc1", label: "203.0.113.0/24",          kind: "ioc",     pct: 24, seen: 2020, nodes: 7, sev: "critical" },
    { id: "ioc2", label: "198.51.100.0/24",         kind: "ioc",     pct: 13, seen: 2021, nodes: 5, sev: "medium" },
    { id: "ioc3", label: "Payload hashes",          kind: "ioc",     pct: 27, seen: 2019, nodes: 7, sev: "high" },
    { id: "ioc4", label: "Phishing URLs",           kind: "ioc",     pct: 19, seen: 2022, nodes: 6, sev: "high" },
    { id: "ioc5", label: "Sender domains",          kind: "ioc",     pct: 16, seen: 2023, nodes: 5, sev: "medium" },
    { id: "ioc6", label: "TLS fingerprints",        kind: "ioc",     pct: 12, seen: 2024, nodes: 5, sev: "low" }
  ];
  /* Cross-links: the point of the view is that two clusters share infrastructure. */
  const LINKS = [
    ["sb", "as1"], ["ldr", "as1"], ["phk", "dns"], ["ioc1", "as1"],
    ["ioc3", "ldr"], ["ioc4", "phk"], ["stl", "as2"], ["rat", "bp"], ["ioc5", "dns"]
  ];
  /* Node colours are tokens in suite.css (--cg-hub and the rest), read when the
     graph draws: SVG presentation attributes cannot take var(). Labels and edges
     read the theme's ink, so the view works on the dark console as well. */
  const KINDS = ["hub", "malware", "infra", "ioc"];
  const kindColor = (kind) => cssVar("--cg-" + kind);
  const KIND_LABEL = { hub: "Campaign", malware: "Malware family", infra: "Infrastructure", ioc: "Indicator group" };
  const YEARS = [2016, 2017, 2018, 2019, 2020, 2021, 2022, 2023, 2024];
  /* What the severity control steps through. It used to be labelled "Filter by
     severity" and only re-sorted the clusters; it filters now. */
  const SEV_STEPS = [
    { label: "All severities", keep: () => true },
    { label: "High and critical", keep: (c) => c.sev === "critical" || c.sev === "high" },
    { label: "Critical only", keep: (c) => c.sev === "critical" }
  ];
  const cg = { year: 2024, layout: "radial", zoom: 1, sev: 0, focus: null };

  function graphBody() {
    return '<div class="cg" data-cg>' +
      '<div class="kpis cg-kpis" id="cg-kpis"></div>' +
      '<section class="card panel cg-panel">' +
        '<div class="panel-head"><h4>IR-2026-114 · what the campaign is built from</h4>' +
          '<div class="cg-tools" role="toolbar" aria-label="Graph view">' +
            '<div class="seg" role="group" aria-label="Layout">' +
              '<button type="button" data-layout="radial" aria-pressed="' + (cg.layout === "radial") + '">Radial</button>' +
              '<button type="button" data-layout="tree" aria-pressed="' + (cg.layout === "tree") + '">By share</button></div>' +
            '<button type="button" class="round-btn" data-zoom="out" aria-label="Zoom out"><span aria-hidden="true">−</span></button>' +
            '<button type="button" class="round-btn" data-zoom="in" aria-label="Zoom in"><span aria-hidden="true">+</span></button>' +
            '<button type="button" class="btn btn-light btn-sm" data-zoom="fit">Fit</button>' +
            /* data-cg-sev, not the console's own severity hook: wirePanels() renders a
               severity bar into whatever element carries that under #console-body,
               and it was finding this button. */
            '<button type="button" class="btn btn-light btn-sm" data-cg-sev id="cg-sev" aria-live="polite"></button>' +
          "</div></div>" +
        '<div class="cg-stage" id="cg-stage">' +
          '<svg class="cg-svg" id="cg-svg" role="img" aria-label="Relationship graph of a synthetic threat campaign"></svg>' +
          '<div class="cg-readout" id="cg-readout" role="status" aria-live="polite"></div>' +
        "</div>" +
        '<div class="cg-foot">' +
          '<div class="cg-legend" id="cg-legend" aria-label="Legend"></div>' +
          '<div class="cg-years"><span class="label-xs" id="cg-years-label">First seen up to</span>' +
            '<div class="seg cg-year-seg" role="group" aria-labelledby="cg-years-label">' +
              YEARS.map((y) => '<button type="button" data-year="' + y + '" aria-pressed="' + (y === cg.year) + '">' + y + "</button>").join("") +
            "</div>" +
            '<button type="button" class="btn btn-light btn-sm" data-play>Play the timeline</button></div>' +
        "</div>" +
        '<p class="wb-hint">Synthetic dataset — RFC 5737 addresses, RFC 2606 names and invented family names. No live vendor data.</p>' +
      "</section>" +
      '<section class="card panel"><div class="panel-head"><h4>Every cluster in view</h4></div>' +
        '<div id="cg-table"></div></section>' +
    "</div>";
  }

  function mountGraph(root, ctx) {
    const go = (ctx && ctx.go) || ((h) => { location.hash = h; });
    const svgNS = "http://www.w3.org/2000/svg";
    const stage = $("#cg-stage", root), svg = $("#cg-svg", root), readout = $("#cg-readout", root);
    const reduce = C.reduceMotion();
    let W = 960, H = 560, timer = null, raf = 0;
    const el = (name, attrs) => {
      const node = document.createElementNS(svgNS, name);
      for (const key in attrs) node.setAttribute(key, attrs[key]);
      return node;
    };
    const rnd = (seed) => { const x = Math.sin(seed * 9973) * 43758.5453; return x - Math.floor(x); };
    const visible = () => CLUSTERS.filter((c) => c.seen <= cg.year && SEV_STEPS[cg.sev].keep(c));

    function defs() {
      const d = el("defs");
      for (const kind of KINDS) {
        const g = el("radialGradient", { id: "cg-g-" + kind, cx: "34%", cy: "28%", r: "78%" });
        g.appendChild(el("stop", { offset: "0%", "stop-color": cssVar("--cg-glint"), "stop-opacity": ".82" }));
        g.appendChild(el("stop", { offset: "26%", "stop-color": kindColor(kind), "stop-opacity": ".98" }));
        g.appendChild(el("stop", { offset: "100%", "stop-color": kindColor(kind), "stop-opacity": ".55" }));
        d.appendChild(g);
      }
      const soft = el("filter", { id: "cg-soft", x: "-60%", y: "-60%", width: "220%", height: "220%" });
      soft.appendChild(el("feGaussianBlur", { stdDeviation: "12" }));
      d.appendChild(soft);
      return d;
    }

    function layout() {
      const cx = W / 2, cy = H / 2;
      const base = Math.min(W, H) * 0.30 * cg.zoom;
      const nodes = [], edges = [];
      const live = visible();
      nodes.push({ id: "hub", label: "IR-2026-114", sub: "active campaign", kind: "hub", x: cx, y: cy,
        r: 16 * cg.zoom, pct: 100, seen: 2016, sev: "critical", nodes: live.length });
      const ordered = cg.layout === "tree" ? live.slice().sort((a, b) => b.pct - a.pct) : live;
      ordered.forEach((cluster, index) => {
        const turn = (index / Math.max(1, ordered.length)) * Math.PI * 2 - Math.PI / 2;
        const jitter = cg.layout === "tree" ? 0 : (rnd(index + 3) - 0.5) * 0.42;
        const angle = turn + jitter;
        const radius = base * (cg.layout === "tree" ? 0.72 + (index % 3) * 0.24 : 0.66 + rnd(index + 11) * 0.62);
        const x = cx + Math.cos(angle) * radius * 1.32;
        const y = cy + Math.sin(angle) * radius * 0.92;
        nodes.push(Object.assign({}, cluster, { x, y, r: (7 + cluster.pct * 0.15) * cg.zoom, slot: 0 }));
        edges.push({ a: "hub", b: cluster.id, kind: "primary" });
        for (let n = 0; n < cluster.nodes; n++) {
          const ca = angle + (rnd(index * 17 + n) - 0.5) * 1.5;
          const cr = radius * (1.2 + rnd(index * 31 + n) * 0.34);
          nodes.push({ id: cluster.id + "-" + n, kind: cluster.kind, child: true,
            x: cx + Math.cos(ca) * cr * 1.32, y: cy + Math.sin(ca) * cr * 0.92, r: (2 + rnd(n + index) * 2.2) * cg.zoom });
          edges.push({ a: cluster.id, b: cluster.id + "-" + n, kind: "child" });
        }
      });
      const present = new Set(nodes.map((n) => n.id));
      LINKS.forEach(([a, b]) => { if (present.has(a) && present.has(b)) edges.push({ a, b, kind: "cross" }); });
      return { nodes, edges, live };
    }

    function render() {
      const rect = stage.getBoundingClientRect();
      W = Math.max(320, rect.width || 960);
      H = Math.max(360, Math.min(620, Math.round(W * 0.62)));
      stage.style.height = H + "px";
      svg.setAttribute("viewBox", "0 0 " + W + " " + H);
      const { nodes, edges, live } = layout();
      const index = new Map(nodes.map((n) => [n.id, n]));
      const ink = cssVar("--ink"), ink3 = cssVar("--ink-3"), line = cssVar("--line-2");
      svg.textContent = "";
      svg.appendChild(defs());
      const hub = index.get("hub");
      svg.appendChild(el("circle", { cx: hub.x, cy: hub.y, r: 70 * cg.zoom, fill: kindColor("hub"), opacity: ".18", filter: "url(#cg-soft)" }));

      const edgeLayer = el("g", { "stroke-linecap": "round", fill: "none" });
      edges.forEach((e) => {
        const a = index.get(e.a), b = index.get(e.b);
        if (!a || !b) return;
        edgeLayer.appendChild(el("line", {
          x1: a.x, y1: a.y, x2: b.x, y2: b.y,
          stroke: e.kind === "primary" ? kindColor("hub") : e.kind === "cross" ? kindColor("infra") : line,
          "stroke-opacity": e.kind === "child" ? ".9" : ".45",
          "stroke-width": e.kind === "primary" ? 1.2 : e.kind === "cross" ? 1 : 0.6,
          "stroke-dasharray": e.kind === "cross" ? "3 5" : ""
        }));
      });
      svg.appendChild(edgeLayer);

      /* Two labels within 26px on the same side collide; nudge them apart. */
      const labelled = nodes.filter((n) => !n.child && n.id !== "hub");
      ["left", "right"].forEach((side) => {
        const column = labelled.filter((n) => (side === "right" ? n.x >= W / 2 : n.x < W / 2)).sort((a, b) => a.y - b.y);
        for (let i = 1; i < column.length; i++) {
          const gap = (column[i].y + column[i].slot) - (column[i - 1].y + column[i - 1].slot);
          if (gap < 26) column[i].slot += 26 - gap;
        }
      });

      const nodeLayer = el("g");
      /* Labels go on their own layer, drawn last. Inside each node's group they
         were painted over by every node drawn after them, so a member dot could
         sit in the middle of "203.0.113.0/24". The layer ignores the pointer,
         so hover and focus still land on the node itself. */
      const labelLayer = el("g", { class: "cg-labels", "pointer-events": "none" });
      nodes.forEach((node) => {
        const group = el("g", { class: "cg-node" + (node.child ? " child" : "") });
        if (!node.child) {
          group.setAttribute("tabindex", "0");
          group.setAttribute("role", "button");
          group.setAttribute("aria-label", node.label + ", " + KIND_LABEL[node.kind].toLowerCase() +
            (node.id === "hub" ? "" : ", " + node.pct + "% of the graph, " + node.sev));
          group.dataset.id = node.id;
          group.appendChild(el("circle", { cx: node.x, cy: node.y, r: node.r + 3.5, fill: "none",
            stroke: kindColor(node.kind), "stroke-opacity": ".35", "stroke-width": "1" }));
        }
        group.appendChild(el("circle", { cx: node.x, cy: node.y, r: node.r, fill: "url(#cg-g-" + node.kind + ")",
          stroke: kindColor(node.kind), "stroke-opacity": node.child ? ".4" : ".7", "stroke-width": node.child ? ".4" : ".8" }));
        if (!node.child) {
          /* Labels radiate outward on the side the node sits on, like spokes. */
          const out = node.id === "hub" ? 1 : (node.x >= W / 2 ? 1 : -1);
          const lx = node.x + out * (node.r + 8), ly = node.y + (node.slot || 0);
          const label = el("text", { x: lx, y: ly - 1, "text-anchor": out === 1 ? "start" : "end", fill: ink,
            "font-size": (node.id === "hub" ? 12.5 : 11) * Math.min(1.2, cg.zoom), "font-weight": node.id === "hub" ? "700" : "600" });
          label.textContent = node.label;
          labelLayer.appendChild(label);
          const sub = el("text", { x: lx, y: ly + 11, "text-anchor": out === 1 ? "start" : "end", fill: ink3,
            "font-size": 9.5 * Math.min(1.2, cg.zoom), class: "cg-mono" });
          sub.textContent = node.id === "hub" ? node.sub : node.pct + "% · " + node.sev;
          labelLayer.appendChild(sub);
        }
        nodeLayer.appendChild(group);
      });
      svg.appendChild(nodeLayer);
      svg.appendChild(labelLayer);
      renderMeta(nodes, live);
      if (cg.focus && index.get(cg.focus)) showReadout(index.get(cg.focus), true);
      else hideReadout(true);
    }

    function renderMeta(nodes, live) {
      const counts = { malware: 0, infra: 0, ioc: 0 };
      live.forEach((c) => { counts[c.kind]++; });
      const links = LINKS.filter(([a, b]) => live.some((c) => c.id === a) && live.some((c) => c.id === b)).length;
      const critical = live.filter((c) => c.sev === "critical").length;
      /* Every figure here is counted from the data on screen. The standalone
         page showed "98% coverage", "57% actionable" and "32% unenriched" as
         fixed text; nothing produced them. */
      const tile = (label, iconId, value, note) => '<article class="card kpi"><div class="kpi-top"><span class="kpi-ic">' +
        '<svg><use href="#' + iconId + '"/></svg></span><b>' + label + '</b></div><div class="val num">' + value +
        '</div><div class="kpi-foot"><small>' + note + "</small></div></article>";
      $("#cg-kpis", root).innerHTML =
        tile("Clusters in view", "i-layers", live.length, "of " + CLUSTERS.length + " up to " + cg.year) +
        tile("Nodes", "i-target", nodes.length - 1, "clusters and their members") +
        tile("Shared infrastructure", "i-globe", links, "cross-links between clusters") +
        tile("Critical clusters", "i-flag", critical, SEV_STEPS[cg.sev].label.toLowerCase());
      $("#cg-legend", root).innerHTML = ["hub", "malware", "infra", "ioc"].map((k) =>
        '<span class="cg-key"><i style="background:var(--cg-' + k + ')"></i>' + KIND_LABEL[k] +
        ' <b class="num">' + (k === "hub" ? 1 : counts[k]) + "</b></span>").join("");
      $("#cg-sev", root).textContent = SEV_STEPS[cg.sev].label;
      $("#cg-table", root).innerHTML = live.length
        ? '<div class="table-wrap"><table class="table cg-table"><thead><tr><th>Cluster</th><th>Kind</th><th>Severity</th>' +
          "<th>Share</th><th>First seen</th></tr></thead><tbody>" +
          live.slice().sort((a, b) => b.pct - a.pct).map((c) =>
            '<tr><td data-label="Cluster">' + esc(c.label) + '</td><td data-label="Kind">' + esc(KIND_LABEL[c.kind]) +
            '</td><td data-label="Severity">' + badge(c.sev) + '</td><td data-label="Share" class="mono">' + c.pct +
            '%</td><td data-label="First seen" class="mono">' + c.seen + "</td></tr>").join("") + "</tbody></table></div>"
        : '<div class="empty-state"><b>Nothing in view</b><span>No cluster was first seen by ' + cg.year +
          " at this severity. Widen the filter or move the timeline forward.</span></div>";
    }

    function showReadout(node, pin) {
      readout.innerHTML =
        '<div class="cg-rt">' + esc(node.label) + "</div>" +
        '<div class="cg-rs">' + esc(node.id === "hub" ? "campaign hub" : KIND_LABEL[node.kind].toLowerCase()) +
          " · first seen " + esc(node.seen) + "</div>" +
        '<div class="cg-rbar"><i style="width:' + node.pct + "%;background:var(--cg-" + node.kind + ')"></i></div>' +
        '<dl class="wb-kv"><dt>share</dt><dd>' + node.pct + "%</dd><dt>" + (node.id === "hub" ? "clusters" : "members") +
        "</dt><dd>" + node.nodes + "</dd><dt>severity</dt><dd>" + badge(node.sev) + "</dd></dl>";
      const rect = stage.getBoundingClientRect(), scale = rect.width / W;
      let left = node.x * scale + 18, top = node.y * scale - 16;
      left = Math.max(8, Math.min(left, rect.width - 222));
      top = Math.max(8, Math.min(top, rect.height - 150));
      readout.style.left = left + "px"; readout.style.top = top + "px";
      readout.classList.add("on");
      readout.dataset.pinned = pin ? "1" : "";
    }
    function hideReadout(force) {
      if (force || !readout.dataset.pinned) { readout.classList.remove("on"); if (force) readout.dataset.pinned = ""; }
    }

    const nodeFor = (target) => {
      const g = target.closest && target.closest(".cg-node:not(.child)");
      if (!g) return null;
      return layout().nodes.find((n) => n.id === g.dataset.id) || null;
    };

    function setYear(year) {
      cg.year = year;
      $$("[data-year]", root).forEach((b) => b.setAttribute("aria-pressed", String(Number(b.dataset.year) === year)));
      render();
    }

    function onClick(event) {
      const t = event.target;
      const layoutBtn = t.closest("[data-layout]");
      if (layoutBtn) {
        cg.layout = layoutBtn.dataset.layout;
        $$("[data-layout]", root).forEach((b) => b.setAttribute("aria-pressed", String(b === layoutBtn)));
        render(); return;
      }
      const zoom = t.closest("[data-zoom]");
      if (zoom) {
        cg.zoom = zoom.dataset.zoom === "in" ? Math.min(1.7, cg.zoom * 1.18)
          : zoom.dataset.zoom === "out" ? Math.max(0.62, cg.zoom / 1.18) : 1;
        render(); return;
      }
      if (t.closest("[data-cg-sev]")) { cg.sev = (cg.sev + 1) % SEV_STEPS.length; cg.focus = null; render(); return; }
      const year = t.closest("[data-year]");
      if (year) { stopPlay(); setYear(Number(year.dataset.year)); return; }
      if (t.closest("[data-play]")) { play(); return; }
      const node = nodeFor(t);
      if (node) { cg.focus = cg.focus === node.id ? null : node.id; if (cg.focus) showReadout(node, true); else hideReadout(true); return; }
      if (t.closest("#cg-stage")) { cg.focus = null; hideReadout(true); }
    }
    function onOver(event) { const n = nodeFor(event.target); if (n) showReadout(n, false); }
    function onOut(event) { if (nodeFor(event.target)) hideReadout(false); }
    function onKey(event) {
      const n = nodeFor(event.target);
      if (n && (event.key === "Enter" || event.key === " ")) { event.preventDefault(); cg.focus = n.id; showReadout(n, true); }
      if (event.key === "Escape") { cg.focus = null; hideReadout(true); }
    }
    function onFocusIn(event) { const n = nodeFor(event.target); if (n) showReadout(n, false); }

    function play() {
      if (reduce) { setYear(2024); return; }
      stopPlay();
      let step = 0;
      timer = setInterval(() => {
        setYear(YEARS[step]);
        if (++step >= YEARS.length) stopPlay();
      }, 320);
    }
    function stopPlay() { if (timer) { clearInterval(timer); timer = null; } }
    function onResize() { cancelAnimationFrame(raf); raf = requestAnimationFrame(render); }

    root.addEventListener("click", onClick);
    root.addEventListener("mouseover", onOver);
    root.addEventListener("mouseout", onOut);
    root.addEventListener("keydown", onKey);
    root.addEventListener("focusin", onFocusIn);
    addEventListener("resize", onResize);
    /* A theme flip changes --ink under the labels; the SVG reads it at draw time. */
    const themeWatch = new MutationObserver(onResize);
    themeWatch.observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });
    render();

    void go;
    return function unmount() {
      stopPlay();
      cancelAnimationFrame(raf);
      themeWatch.disconnect();
      removeEventListener("resize", onResize);
      root.removeEventListener("click", onClick);
      root.removeEventListener("mouseover", onOver);
      root.removeEventListener("mouseout", onOut);
      root.removeEventListener("keydown", onKey);
      root.removeEventListener("focusin", onFocusIn);
    };
  }

  window.IntelPulsePanes = {
    workbench: {
      title: "Analyst workbench",
      sub: "Paste an alert. Every indicator is scored in one pass, with the evidence behind it.",
      body: workbenchBody,
      mount: mountWorkbench
    },
    graph: {
      title: "Campaign graph",
      sub: "What one campaign is built from, and which parts of it share infrastructure.",
      body: graphBody,
      mount: mountGraph
    }
  };
})();
