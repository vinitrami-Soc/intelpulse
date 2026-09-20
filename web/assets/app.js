/* IntelPulse dashboard controller.
 *
 * Two runtimes behind one UI:
 *   demo — engine.js scores the bundled synthetic dataset in the browser, so
 *          the GitHub Pages build works with no backend and no API keys;
 *   live — the same screens driven by a running FastAPI service.
 * The mode is always stated on screen: a reviewer must never mistake sample
 * data for live vendor intelligence.
 */
(function () {
  "use strict";

  const E = window.IntelPulseEngine;
  const DEMO = window.INTELPULSE_DEMO;
  const $ = (sel, scope) => (scope || document).querySelector(sel);
  const $$ = (sel, scope) => Array.from((scope || document).querySelectorAll(sel));

  const store = {
    get(key, fallback) {
      try { const raw = localStorage.getItem("intelpulse:" + key); return raw ? JSON.parse(raw) : fallback; }
      catch (_) { return fallback; }
    },
    set(key, value) {
      try { localStorage.setItem("intelpulse:" + key, JSON.stringify(value)); } catch (_) { /* private mode */ }
    }
  };

  const state = {
    mode: store.get("mode", "demo"),
    apiBase: store.get("apiBase", "http://localhost:8000"),
    result: null,
    health: null,
    lists: store.get("lists", []),
    history: store.get("history", []),
    cy: null
  };

  // ------------------------------------------------------------------ utils
  const escapeHtml = (value) => String(value == null ? "" : value)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;");

  const scoreColor = (verdict) => ({
    critical: "var(--critical)", high: "var(--high)", medium: "var(--medium)",
    low: "var(--low)", allowlisted: "var(--ok)"
  }[verdict] || "var(--ink-3)");

  function toast(message) {
    const el = $("#toast");
    el.textContent = message;
    el.classList.add("show");
    clearTimeout(toast._timer);
    toast._timer = setTimeout(() => el.classList.remove("show"), 2600);
  }

  function download(filename, content, type) {
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

  // ------------------------------------------------------------ API client
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
    const contentType = response.headers.get("content-type") || "";
    return contentType.includes("application/json") ? response.json() : response.text();
  }

  async function checkHealth() {
    const pill = $("#conn-pill");
    if (state.mode === "demo") {
      state.health = null;
      pill.className = "pill demo";
      pill.innerHTML = '<span class="dot"></span> Demo mode · synthetic dataset';
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
      pill.innerHTML = '<span class="dot"></span> Live · ' + live + "/" + health.providers.length + " sources configured";
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
      box.innerHTML = '<p class="chips">' + [
        "abuseipdb", "otx", "threatfox", "urlhaus", "greynoise", "local_blocklist", "geoip", "nvd"
      ].map((name) => '<span class="chip skip">' + name + " · sample</span>").join("") + "</p>" +
        '<p style="color:var(--ink-3);font-size:12.5px;margin:10px 0 0">Demo mode scores a bundled synthetic dataset in your browser using the same weights as the API. Switch to <b>Live API</b> and point it at a running IntelPulse backend for real vendor lookups.</p>';
      return;
    }
    if (!health) {
      box.innerHTML = '<p style="color:var(--high);font-size:13px;margin:0">Cannot reach <code>' +
        escapeHtml(state.apiBase) + "</code>" + (errorMessage ? " — " + escapeHtml(errorMessage) : "") +
        '.</p><p style="color:var(--ink-3);font-size:12.5px;margin:8px 0 0">Start it with <code>docker compose up</code>, or switch back to demo mode.</p>';
      return;
    }
    box.innerHTML = '<p class="chips">' + health.providers.map((p) =>
      '<span class="chip ' + (p.configured ? "" : "skip") + '">' + escapeHtml(p.name) +
      " · " + (p.configured ? "ready" : "no key") + "</span>").join("") + "</p>" +
      '<dl class="kv" style="margin-top:12px">' +
      "<dt>database</dt><dd>" + escapeHtml(health.database) + "</dd>" +
      "<dt>cache</dt><dd>" + escapeHtml(health.cache.backend) + " · hit rate " +
      Math.round((health.cache.hit_rate || 0) * 100) + "%</dd>" +
      "<dt>offline feed rows</dt><dd>" + health.offline_datasets.feed_entries.toLocaleString() + "</dd>" +
      "<dt>local CVE records</dt><dd>" + health.offline_datasets.cve_records.toLocaleString() + "</dd>" +
      "<dt>geoip databases</dt><dd>" + (health.offline_datasets.geoip_city ? "city ✓" : "city ✗") + " · " +
      (health.offline_datasets.geoip_asn ? "asn ✓" : "asn ✗") + "</dd></dl>";
  }

  // ------------------------------------------------------------- triage run
  async function runTriage() {
    const text = $("#input").value.trim();
    if (!text) { toast("Paste some indicators or a log snippet first."); return; }

    const button = $("#run");
    button.disabled = true;
    button.innerHTML = '<span class="spinner"></span> Triaging…';
    try {
      const title = $("#title").value.trim() || "Ad-hoc triage";
      let result;
      if (state.mode === "demo") {
        result = E.demoTriage(text, DEMO, { title: title, lists: state.lists });
      } else {
        result = await api("/api/triage", {
          method: "POST",
          body: JSON.stringify({ text: text, title: title, persist: true })
        });
        result.mode = "live";
      }
      if (!result.indicators.length) { toast("No usable indicators found in that input."); return; }
      state.result = result;
      pushHistory(result);
      renderResult(result);
      $("#results").scrollIntoView({ behavior: "smooth", block: "start" });
    } catch (error) {
      toast("Triage failed: " + error.message);
    } finally {
      button.disabled = false;
      button.innerHTML = "▶ Run triage";
    }
  }

  async function runExtract() {
    const text = $("#input").value.trim();
    if (!text) { toast("Nothing to parse yet."); return; }
    let indicators;
    if (state.mode === "demo") {
      indicators = E.extract(text, { allowDocumentation: true });
    } else {
      try { indicators = (await api("/api/extract", { method: "POST", body: JSON.stringify({ text: text }) })).indicators; }
      catch (error) { toast("Extract failed: " + error.message); return; }
    }
    const counts = indicators.reduce((acc, i) => { acc[i.type] = (acc[i.type] || 0) + 1; return acc; }, {});
    $("#preview").innerHTML = indicators.length
      ? '<div class="chips">' + indicators.map((i) =>
          '<span class="chip">' + escapeHtml(i.type) + " · " + escapeHtml(i.value) + "</span>").join("") +
        '</div><p style="color:var(--ink-3);font-size:12px;margin:9px 0 0">' +
        Object.entries(counts).map(([k, v]) => v + " " + k).join(" · ") +
        " — parsed locally, no API quota spent.</p>"
      : '<p style="color:var(--ink-3);font-size:12.5px;margin:0">No routable indicators found. Private/reserved addresses and filenames are deliberately dropped.</p>';
  }

  // --------------------------------------------------------------- history
  function pushHistory(result) {
    const entry = {
      case_id: result.case_id, title: result.title, verdict: result.verdict,
      score: result.score, indicator_count: result.indicators.length,
      mode: result.mode || state.mode, created_at: new Date().toISOString()
    };
    state.history = [entry].concat(state.history).slice(0, 25);
    store.set("history", state.history);
    if ($("#tab-history").getAttribute("aria-selected") === "true") renderHistory();
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
      box.innerHTML = '<div class="empty"><b>No cases yet</b>Run a triage and it will be recorded here.</div>';
      return;
    }
    box.innerHTML = '<table class="history"><thead><tr><th>Case</th><th>Title</th><th>Verdict</th>' +
      "<th>Score</th><th>IOCs</th><th>Mode</th><th>When</th></tr></thead><tbody>" +
      rows.map((row) => "<tr><td class=\"mono\" style=\"font-size:11.5px\">" +
        escapeHtml(String(row.case_id).slice(0, 8)) + "</td><td>" + escapeHtml(row.title) +
        '</td><td><span class="badge ' + escapeHtml(row.verdict) + '">' + escapeHtml(row.verdict) +
        "</span></td><td class=\"mono\">" + row.score + "</td><td class=\"mono\">" + row.indicator_count +
        "</td><td class=\"mono\" style=\"font-size:11.5px\">" + escapeHtml(row.mode || "") + "</td><td class=\"mono\" style=\"font-size:11.5px\">" +
        escapeHtml(String(row.created_at || "").replace("T", " ").slice(0, 16)) + "</td></tr>").join("") +
      "</tbody></table>";
  }

  // --------------------------------------------------------------- results
  function renderResult(result) {
    $("#results").hidden = false;
    const answered = result.indicators.reduce((sum, i) => sum + (i.providers_answered || 0), 0);
    const queried = result.indicators.reduce((sum, i) => sum + (i.providers_queried || 0), 0);

    $("#stats").innerHTML = [
      ["Case verdict", '<span class="badge ' + result.verdict + '">' + result.verdict + "</span>"],
      ["Top score", result.score + "<small>/100</small>"],
      ["Indicators", result.indicators.length + "<small> parsed</small>"],
      ["Source coverage", answered + "<small>/" + queried + " answered · " + result.duration_ms + "ms</small>"]
    ].map(([k, v]) => '<div class="stat"><div class="k">' + k + '</div><div class="v">' + v + "</div></div>").join("");

    $("#summary").innerHTML = escapeHtml(result.summary);
    renderIndicators(result);
    renderReport(result);
    if ($("#tab-graph").getAttribute("aria-selected") === "true") renderGraph(result);
  }

  function renderIndicators(result) {
    const sorted = result.indicators.slice().sort((a, b) => b.score - a.score);
    $("#panel-triage").innerHTML = '<div class="ioc-list">' + sorted.map((indicator, index) => {
      const evidence = (indicator.evidence || []).map((e) =>
        '<li><span class="src">' + escapeHtml(e.provider) + '</span><span class="why">' +
        escapeHtml(e.rationale) + '</span><span class="sig">' + e.signal.toFixed(2) + "</span></li>").join("");
      const modifiers = (indicator.modifiers || []).map((m) =>
        '<li><span class="src">modifier</span><span class="why">' + escapeHtml(m) + "</span></li>").join("");
      /* Facts stay attached to the source that reported them — merging them into
         one list is how an analyst ends up citing the wrong vendor in a ticket. */
      const factLine = ([key, value]) => '<div style="display:flex;gap:8px;margin-top:3px">' +
        '<span style="color:var(--ink-3);min-width:96px">' + escapeHtml(key) + "</span><span>" +
        escapeHtml(Array.isArray(value) ? value.join(", ") : typeof value === "object" ? JSON.stringify(value) : value) +
        "</span></div>";
      const sources = (indicator.sources || []).map((s) => {
        const facts = Object.entries(s.facts || {})
          .filter(([, v]) => v !== null && v !== "" && v !== undefined && !(Array.isArray(v) && !v.length))
          .slice(0, 8).map(factLine).join("");
        return '<div class="source"><div class="name">' + escapeHtml(s.label || s.provider) + "</div>" +
          '<div class="state ' + escapeHtml(s.status) + '">' + escapeHtml(s.status) +
          (s.cached ? " · cached" : "") + (s.latency_ms ? " · " + s.latency_ms + "ms" : "") + "</div>" +
          (s.error ? '<div style="color:var(--ink-3);font-size:11px;margin-top:4px">' + escapeHtml(s.error) + "</div>" : "") +
          (facts ? '<div style="font:500 11.5px var(--mono);margin-top:6px;color:var(--ink-2)">' + facts + "</div>" : "") +
          (s.reference ? '<a href="' + escapeHtml(s.reference) + '" target="_blank" rel="noopener" style="font-size:11px;display:inline-block;margin-top:6px">vendor page ↗</a>' : "") +
          "</div>";
      }).join("");

      return '<article class="ioc' + (index === 0 ? " open" : "") + '" data-ioc="' + escapeHtml(indicator.value) + '">' +
        '<div class="ioc-top">' +
          '<span class="ioc-type">' + escapeHtml(indicator.type) + "</span>" +
          '<span class="ioc-value">' + escapeHtml(indicator.value) + "</span>" +
          '<span class="badge ' + escapeHtml(indicator.verdict) + '">' + escapeHtml(indicator.verdict) + "</span>" +
          '<span class="ioc-score" style="color:' + scoreColor(indicator.verdict) + '">' + indicator.score + "</span>" +
        "</div>" +
        '<div class="ioc-detail">' +
          '<div class="score-bar"><i style="width:' + indicator.score + "%;background:" + scoreColor(indicator.verdict) + '"></i></div>' +
          '<dl class="kv" style="margin-top:12px">' +
            "<dt>confidence</dt><dd>" + Math.round(indicator.confidence * 100) + "% (" +
              indicator.providers_answered + "/" + indicator.providers_queried + " sources answered)</dd>" +
            (indicator.context ? "<dt>log context</dt><dd class=\"mono\" style=\"font-size:12px\">" + escapeHtml(indicator.context) + "</dd>" : "") +
          "</dl>" +
          ((indicator.malware_families || []).length || (indicator.attack_techniques || []).length || (indicator.tags || []).length
            ? '<div class="chips">' +
              (indicator.malware_families || []).map((f) => '<span class="chip malware">' + escapeHtml(f) + "</span>").join("") +
              (indicator.attack_techniques || []).map((t) => '<a class="chip attack" href="' + escapeHtml(t.url) +
                '" target="_blank" rel="noopener">' + escapeHtml(t.id) + " · " + escapeHtml(t.name) + "</a>").join("") +
              (indicator.tags || []).map((t) => '<span class="chip">' + escapeHtml(t) + "</span>").join("") +
              "</div>"
            : "") +
          (evidence || modifiers ? '<ul class="evidence">' + evidence + modifiers + "</ul>" : "") +
          '<div class="source-grid">' + sources + "</div>" +
          ((indicator.containment || []).length
            ? "<h4 style=\"margin:16px 0 0;font-size:12px;letter-spacing:.08em;text-transform:uppercase;color:var(--ink-3);font-family:var(--mono)\">Recommended containment</h4>" +
              '<ul class="actions">' + indicator.containment.map((a) => "<li>" + escapeHtml(a) + "</li>").join("") + "</ul>"
            : "") +
          '<div class="btn-row">' +
            '<button class="btn small ghost" data-copy="' + escapeHtml(indicator.value) + '">Copy IOC</button>' +
            '<button class="btn small ghost" data-allow="' + escapeHtml(indicator.value) + '" data-type="' + escapeHtml(indicator.type) + '">Allowlist</button>' +
            '<button class="btn small ghost" data-block="' + escapeHtml(indicator.value) + '" data-type="' + escapeHtml(indicator.type) + '">Blocklist</button>' +
          "</div>" +
        "</div></article>";
    }).join("") + "</div>";
  }

  function renderReport(result) {
    const markdown = E.toMarkdown(result, { demo: (result.mode || state.mode) === "demo" });
    $("#report").textContent = markdown;
    $("#report").dataset.markdown = markdown;
  }

  /* Deterministic force-directed layout drawn as inline SVG. Used when the
     Cytoscape CDN is blocked (corporate proxy, offline demo) so the graph tab
     always shows the relationships rather than an apology. */
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

    const shapeFor = (node) => {
      const size = node.data.root ? 15 : 10;
      const color = node.data.color || "#7d8597";
      if (node.data.kind === "malware" || node.data.kind === "actor") {
        return '<polygon points="' + [0, -size * 1.3, size * 0.9, size, -size * 0.9, size]
          .join(" ").replace(/(-?\d+\.?\d*) (-?\d+\.?\d*)( |$)/g, "$1,$2 ") +
          '" fill="' + color + '" stroke="#22304d"/>';
      }
      if (node.data.kind === "asn" || node.data.kind === "country" || node.data.kind === "pulse") {
        return '<rect x="' + -size * 1.4 + '" y="' + -size * 0.8 + '" width="' + size * 2.8 +
          '" height="' + size * 1.6 + '" rx="4" fill="' + color + '" stroke="#22304d"/>';
      }
      return '<circle r="' + size + '" fill="' + color + '" stroke="' +
        (node.data.root ? "#4cc9f0" : "#22304d") + '" stroke-width="' + (node.data.root ? 2 : 1) + '"/>';
    };

    container.innerHTML = '<svg class="svg-graph" viewBox="0 0 ' + width + " " + height +
      '" role="img" aria-label="Indicator relationship graph">' +
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
      "</svg>";

    $$("#graph .node").forEach((element) => element.addEventListener("click", () => {
      const id = element.dataset.node;
      if (!id.startsWith("ioc:")) return;
      const card = $$(".ioc").find((el) => el.dataset.ioc === id.slice(4));
      if (card) { switchTab("triage"); card.classList.add("open"); card.scrollIntoView({ behavior: "smooth", block: "center" }); }
    }));
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
    state.cy = cytoscape({
      container: container,
      elements: { nodes: graph.nodes, edges: graph.edges },
      style: [
        {
          selector: "node",
          style: {
            "background-color": "data(color)",
            "label": "data(label)",
            "color": "#c7d4ea",
            "font-size": "10px",
            "font-family": "ui-monospace, monospace",
            "text-valign": "bottom",
            "text-margin-y": 6,
            "text-wrap": "ellipsis",
            "text-max-width": "130px",
            "width": 22, "height": 22,
            "border-width": 1, "border-color": "#22304d"
          }
        },
        { selector: 'node[?root]', style: { width: 34, height: 34, "border-width": 2, "border-color": "#4cc9f0", "font-size": "11px" } },
        { selector: 'node[kind = "malware"]', style: { shape: "star", width: 28, height: 28 } },
        { selector: 'node[kind = "asn"], node[kind = "country"]', style: { shape: "round-rectangle" } },
        { selector: 'node[kind = "hash"]', style: { shape: "hexagon" } },
        { selector: 'node[kind = "url"]', style: { shape: "diamond" } },
        {
          selector: "edge",
          style: {
            width: 1.2, "line-color": "#22304d", "target-arrow-color": "#22304d",
            "target-arrow-shape": "triangle", "curve-style": "bezier",
            label: "data(label)", "font-size": "8px", color: "#5d6e8c",
            "text-rotation": "autorotate", "text-background-opacity": 0
          }
        }
      ],
      layout: { name: "cose", animate: false, padding: 30, nodeRepulsion: 9000, idealEdgeLength: 90 }
    });
    state.cy.on("tap", "node", (event) => {
      const id = event.target.id();
      if (!id.startsWith("ioc:")) return;
      const card = $$(".ioc").find((el) => el.dataset.ioc === id.slice(4));
      if (card) { switchTab("triage"); card.classList.add("open"); card.scrollIntoView({ behavior: "smooth", block: "center" }); }
    });
  }

  // ------------------------------------------------------------------ lists
  async function addToList(value, iocType, listType) {
    if (state.mode === "live") {
      try {
        await api("/api/lists", {
          method: "POST",
          body: JSON.stringify({ value: value, ioc_type: iocType, list_type: listType, reason: "added from dashboard" })
        });
        toast(value + " added to the " + listType + "list.");
      } catch (error) { toast("Could not update list: " + error.message); }
      return;
    }
    state.lists = state.lists.filter((entry) => entry.value.toLowerCase() !== value.toLowerCase());
    state.lists.push({ value: value, ioc_type: iocType, list_type: listType, reason: "added from dashboard (demo)" });
    store.set("lists", state.lists);
    toast(value + " added to the local " + listType + "list — re-run the triage to see the override.");
  }

  // ------------------------------------------------------------------- tabs
  function switchTab(name) {
    $$(".tabs button").forEach((button) => {
      const selected = button.dataset.tab === name;
      button.setAttribute("aria-selected", selected ? "true" : "false");
    });
    $$(".tab-panel").forEach((panel) => { panel.hidden = panel.id !== "panel-" + name; });
    if (name === "graph" && state.result) renderGraph(state.result);
    if (name === "history") renderHistory();
  }

  // ------------------------------------------------------------------- wire
  function setMode(mode) {
    state.mode = mode;
    store.set("mode", mode);
    $$("#mode-switch button").forEach((button) =>
      button.setAttribute("aria-pressed", button.dataset.mode === mode ? "true" : "false"));
    $("#demo-banner").classList.toggle("hidden", mode !== "demo");
    $("#api-config").hidden = mode !== "live";
    checkHealth();
  }

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

  function init() {
    $$("#mode-switch button").forEach((button) =>
      button.addEventListener("click", () => setMode(button.dataset.mode)));

    $("#api-base").value = state.apiBase;
    $("#api-save").addEventListener("click", () => {
      state.apiBase = $("#api-base").value.trim() || "http://localhost:8000";
      store.set("apiBase", state.apiBase);
      checkHealth();
    });

    $("#run").addEventListener("click", runTriage);
    $("#parse").addEventListener("click", runExtract);
    $("#clear").addEventListener("click", () => {
      $("#input").value = ""; $("#preview").innerHTML = ""; $("#results").hidden = true; state.result = null;
    });

    $("#samples").innerHTML = DEMO.scenarios.map((scenario) =>
      '<button data-scenario="' + scenario.id + '">▸ ' + escapeHtml(scenario.label) + "</button>").join("");
    $("#samples").addEventListener("click", (event) => {
      const button = event.target.closest("button[data-scenario]");
      if (!button) return;
      const scenario = DEMO.scenarios.find((s) => s.id === button.dataset.scenario);
      $("#input").value = scenario.text;
      $("#title").value = scenario.label;
      runExtract();
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

    $$(".tabs button").forEach((button) =>
      button.addEventListener("click", () => switchTab(button.dataset.tab)));

    document.addEventListener("click", (event) => {
      const head = event.target.closest(".ioc-top");
      if (head) { head.parentElement.classList.toggle("open"); return; }

      const copy = event.target.closest("[data-copy]");
      if (copy) {
        navigator.clipboard.writeText(copy.dataset.copy).then(() => toast("Indicator copied."));
        return;
      }
      const allow = event.target.closest("[data-allow]");
      if (allow) { addToList(allow.dataset.allow, allow.dataset.type, "allow"); return; }
      const block = event.target.closest("[data-block]");
      if (block) { addToList(block.dataset.block, block.dataset.type, "block"); }
    });

    $("#copy-report").addEventListener("click", () => {
      navigator.clipboard.writeText($("#report").dataset.markdown || "").then(() => toast("Markdown ticket copied."));
    });
    $("#download-md").addEventListener("click", () => {
      if (!state.result) return;
      download("intelpulse-" + state.result.case_id.slice(0, 8) + ".md", $("#report").dataset.markdown, "text/markdown");
    });
    $("#download-json").addEventListener("click", () => {
      if (!state.result) return;
      const ticket = E.toTicketJson(state.result, { demo: (state.result.mode || state.mode) === "demo" });
      download("intelpulse-" + state.result.case_id.slice(0, 8) + ".json", JSON.stringify(ticket, null, 2), "application/json");
    });

    document.addEventListener("keydown", (event) => {
      if ((event.metaKey || event.ctrlKey) && event.key === "Enter") { event.preventDefault(); runTriage(); }
    });

    setMode(state.mode);
    switchTab("triage");
  }

  document.addEventListener("DOMContentLoaded", init);
})();
