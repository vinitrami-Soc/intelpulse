/* IntelPulse · the printable report: a case laid out as a document, for reading and for the PDF.
 *
 * It says what the Markdown ticket says (engine.js briefing() and checklist(), word for word
 * with the server), in the order a reader needs it: the priority and the score first, then the
 * executive summary (the bottom line, what was found, what to do now, how sure), the
 * indicators, the evidence behind each, and the checklist. The workbench shows it as a page;
 * "Download PDF" prints it, and the browser's own Save as PDF makes the file: no library,
 * and nothing leaves the page.
 *
 * Every value in it is the case's data, so every value is escaped. Nothing is parsed as markup.
 */
(function () {
  "use strict";

  const esc = (value) => String(value == null ? "" : value).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
  const engine = () => window.IntelPulseEngine;
  const num = (value) => { const n = Number(value); return Number.isFinite(n) ? n : 0; };
  const pct = (ratio) => Math.round(Math.max(0, Math.min(1, num(ratio))) * 100);
  const LEVELS = ["critical", "high", "medium", "low", "informational", "allowlisted"];
  const level = (verdict) => (LEVELS.includes(verdict) ? verdict : "informational");
  const defanged = (value) => engine().defang(String(value == null ? "" : value));
  const pill = (verdict) => '<span class="rp-pill ' + level(verdict) + '">' + esc(String(verdict || "").toUpperCase()) + "</span>";
  const bar = (ratio, tone) => '<span class="rp-bar"><i class="' + tone + '" style="width:' + pct(ratio) + '%"></i></span>';
  const sourceName = (indicator, id) => {
    const named = (indicator.sources || []).find((s) => s && s.provider === id);
    return named && named.label ? String(named.label).replace(/\s*\([^)]*\)$/, "") : String(id || "").replace(/_/g, " ");
  };
  /* The overview's "ThreatFox + 4": the heaviest source with a signal of 0.5 or more, and how many more agreed. */
  function flaggedBy(indicator) {
    const flagged = (indicator.evidence || []).filter((e) => num(e && e.signal) >= 0.5)
      .sort((a, b) => num(b.weighted) - num(a.weighted));
    if (!flagged.length) return "none";
    return sourceName(indicator, flagged[0].provider) + (flagged.length > 1 ? " + " + (flagged.length - 1) : "");
  }

  /* The summary names its lead indicator as a code span (`...`), for the Markdown ticket. */
  const withCode = (text) => String(text).split(/(`[^`]*`)/).map((part) =>
    /^`[^`]*`$/.test(part) ? '<code class="rp-ioc">' + esc(part.slice(1, -1)) + "</code>" : esc(part)).join("");

  function ring(score, verdict) {
    const r = 42, around = 2 * Math.PI * r, share = Math.max(0, Math.min(100, num(score))) / 100;
    return '<svg class="rp-ring" viewBox="0 0 100 100" role="img" aria-label="Case score ' + esc(num(score)) + ' of 100">' +
      '<circle class="rp-ring-track" cx="50" cy="50" r="' + r + '"/>' +
      '<circle class="rp-ring-fill ' + level(verdict) + '" cx="50" cy="50" r="' + r + '" stroke-dasharray="' +
        (around * share).toFixed(1) + " " + around.toFixed(1) + '" transform="rotate(-90 50 50)"/>' +
      '<text x="50" y="52" class="rp-ring-n">' + esc(num(score)) + "</text>" +
      '<text x="50" y="68" class="rp-ring-of">of 100</text></svg>';
  }

  function evidenceCard(indicator) {
    const rows = (indicator.evidence || []).slice().sort((a, b) => num(b.weighted) - num(a.weighted)).map((e) =>
      '<div class="rp-ev"><span class="rp-ev-name">' + esc(sourceName(indicator, e.provider)) + "</span>" +
        bar(e.signal, num(e.signal) >= 0.5 ? "hit" : "quiet") +
        '<span class="rp-ev-n">' + num(e.signal).toFixed(2) + "</span>" +
        (e.rationale ? '<span class="rp-ev-why">' + esc(e.rationale) + "</span>" : "") +
      "</div>").join("");
    const tags = [].concat(
      (indicator.malware_families || []).slice(0, 4).map((f) => '<span class="rp-tag malware">' + esc(f) + "</span>"),
      (indicator.attack_techniques || []).slice(0, 4).map((t) => '<span class="rp-tag attack">' + esc(t && t.id) +
        (t && t.name ? " · " + esc(t.name) : "") + "</span>"),
      (indicator.tags || []).slice(0, 6).map((t) => '<span class="rp-tag">' + esc(t) + "</span>"));
    return '<article class="rp-card">' +
      '<header class="rp-card-head"><code class="rp-ioc">' + esc(defanged(indicator.value)) + "</code>" +
        '<span class="rp-type">' + esc(indicator.type) + "</span>" + pill(indicator.verdict) +
        '<b class="rp-score">' + esc(num(indicator.score)) + "</b></header>" +
      '<p class="rp-card-sub">Confidence ' + pct(indicator.confidence) + "% · " + esc(num(indicator.providers_answered)) + " of " +
        esc(num(indicator.providers_queried)) + " sources answered · flagged by " + esc(flaggedBy(indicator)) + "</p>" +
      (rows ? '<div class="rp-evs">' + rows + "</div>" : '<p class="rp-muted">No source reported anything about this indicator.</p>') +
      (tags.length ? '<div class="rp-tags">' + tags.join("") + "</div>" : "") +
      ((indicator.modifiers || []).length ? '<ul class="rp-mods">' + indicator.modifiers.map((m) => "<li>" + esc(m) + "</li>").join("") + "</ul>" : "") +
    "</article>";
  }

  /* The report as markup. options.demo marks a demo case; options.generated is a Date (now). */
  function html(result, options) {
    const opts = options || {};
    const E = engine();
    const indicators = (result.indicators || []).slice().sort((a, b) => num(b.score) - num(a.score));
    const brief = E.briefing(result);
    const queried = indicators.reduce((sum, i) => sum + num(i.providers_queried), 0);
    const answered = indicators.reduce((sum, i) => sum + num(i.providers_answered), 0);
    const when = (opts.generated || new Date()).toISOString().slice(0, 16).replace("T", " ") + " UTC";
    const acting = indicators.filter((i) => !["informational", "allowlisted"].includes(i.verdict));
    const quiet = indicators.filter((i) => ["informational", "allowlisted"].includes(i.verdict));
    const checklist = E.checklist(indicators).filter((group) => group.actions.length);
    const stat = (label, value) => "<div><dt>" + label + "</dt><dd>" + value + "</dd></div>";

    return '<article class="rp" aria-label="Case report">' +
      '<header class="rp-top">' +
        '<span class="rp-brand"><span class="rp-mark"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M3 12h4l3 8 4-16 3 8h4"/></svg></span>' +
          '<b translate="no">IntelPulse</b><span class="rp-kind">SOC triage report</span></span>' +
        '<span class="rp-when">' + esc(when) + "</span>" +
      "</header>" +
      (opts.demo ? '<p class="rp-demo">Demo: scored in the browser from the bundled synthetic dataset. No live intelligence was queried.</p>' : "") +

      '<section class="rp-hero ' + level(result.verdict) + '">' +
        ring(result.score, result.verdict) +
        '<div class="rp-hero-text">' +
          '<p class="rp-eyebrow">Case ' + esc(result.case_id) + "</p>" +
          "<h1>" + esc(result.title || "Untitled case") + "</h1>" +
          '<div class="rp-hero-tags">' + pill(result.verdict) + '<span class="rp-prio">' + esc(brief.priority) + "</span></div>" +
        "</div>" +
      "</section>" +
      '<dl class="rp-stats">' +
        stat("Indicators", esc(indicators.length)) +
        stat("Actionable", esc(brief.actionable)) +
        stat("Sources answered", esc(answered) + "<small> of " + esc(queried) + "</small>") +
        stat("Enrichment", esc(num(result.duration_ms)) + "<small> ms</small>") +
      "</dl>" +

      '<section class="rp-brief">' +
        "<h2>Executive summary</h2>" +
        '<p class="rp-bottom"><b>Bottom line.</b> ' + esc(brief.bottomLine) + "</p>" +
        '<div class="rp-cols">' +
          '<div><h3>What we found</h3><p>' + withCode(brief.found) + "</p></div>" +
          '<div><h3>How sure</h3><p>' + esc(brief.sure) + "</p></div>" +
        "</div>" +
        "<h3>What to do now</h3>" +
        '<ol class="rp-steps">' + brief.steps.map((step) => "<li>" + esc(step) + "</li>").join("") + "</ol>" +
      "</section>" +

      (indicators.length ? '<section class="rp-section"><h2>Indicators</h2>' +
        '<table class="rp-table"><thead><tr><th>Indicator</th><th>Type</th><th>Verdict</th><th>Score</th><th>Confidence</th><th>Flagged by</th></tr></thead><tbody>' +
        indicators.map((i) => "<tr>" +
          '<td><code class="rp-ioc">' + esc(defanged(i.value)) + "</code></td>" +
          "<td>" + esc(i.type) + "</td><td>" + pill(i.verdict) + "</td>" +
          '<td class="rp-num"><span class="rp-scorebar">' + bar(num(i.score) / 100, level(i.verdict)) + "<b>" + esc(num(i.score)) + "</b></span></td>" +
          '<td class="rp-num">' + pct(i.confidence) + "%</td>" +
          "<td>" + esc(flaggedBy(i)) + "</td></tr>").join("") +
        "</tbody></table></section>" : "") +

      (acting.length ? '<section class="rp-section"><h2>Evidence and attribution</h2>' + acting.map(evidenceCard).join("") +
        (quiet.length ? '<p class="rp-muted">Also checked, with nothing against them: ' +
          quiet.map((i) => '<code class="rp-ioc">' + esc(defanged(i.value)) + "</code>").join(", ") + ".</p>" : "") +
        "</section>" : "") +

      '<section class="rp-section"><h2>Containment checklist</h2>' +
        (checklist.length ? checklist.map((group) =>
          '<div class="rp-check"><p class="rp-check-head"><code class="rp-ioc">' + esc(defanged(group.indicator.value)) + "</code>" +
            pill(group.indicator.verdict) + "</p>" +
            "<ul>" + group.actions.map((a) => '<li><span class="rp-box" aria-hidden="true"></span>' + esc(a) + "</li>").join("") + "</ul></div>"
        ).join("") : '<p class="rp-muted">' + esc(brief.steps[0]) + "</p>") +
      "</section>" +

      '<section class="rp-section rp-notes"><h2>How to read this report</h2><ul>' +
        "<li><b>Score.</b> A weighted composite of what the sources said, not one vendor's verdict. Levels: " + esc(brief.levels) + ".</li>" +
        "<li><b>Confidence.</b> How much of the picture answered and agreed, not how certain it is that something is malicious.</li>" +
        "<li><b>Coverage.</b> " + esc(answered) + " of " + esc(queried) + " source lookups returned data. A source that was down is left out of the score, never counted as clean.</li>" +
        "<li><b>Defanged.</b> Indicators are written so that none is one click away; refang before using them in a tool.</li>" +
      "</ul></section>" +
      '<footer class="rp-foot"><span>Generated by IntelPulse</span><span>Case ' + esc(result.case_id) + "</span></footer>" +
    "</article>";
  }

  /* Print the report on its own. The rest of the page is hidden only while it prints, and the
     title (which the browser offers as the file's name) names the case. */
  function print(result, options) {
    let host = document.getElementById("print-root");
    if (!host) {
      host = document.createElement("div");
      host.id = "print-root";
      document.body.appendChild(host);
    }
    host.innerHTML = html(result, options);
    const title = document.title;
    const name = String(result.title || "case").replace(/[^\w .-]+/g, " ").replace(/\s+/g, " ").trim().slice(0, 80);
    document.title = "IntelPulse report, " + (name || "case");
    document.body.classList.add("printing");
    let done = false;
    const finish = () => {
      if (done) return;
      done = true;
      document.body.classList.remove("printing");
      document.title = title;
      host.innerHTML = "";
      window.removeEventListener("afterprint", finish);
    };
    window.addEventListener("afterprint", finish);
    window.print();
    /* print() blocks in most browsers and afterprint follows; where it returns at once, the
       report stays until then, and a second press simply prints it again. */
    return finish;
  }

  window.IntelPulseReport = { html, print };
})();
