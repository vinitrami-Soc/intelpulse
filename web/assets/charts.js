/* Chart primitives for IntelPulse.
 *
 * The forms here were chosen by the data's job, not by what looks busy:
 *
 *   case score        -> hero figure (one number, one view)
 *   evidence weight   -> horizontal bars, ONE hue (magnitude), direct-labelled
 *   confidence        -> meter (a single ratio against a limit)
 *   source coverage   -> one labelled cell per provider, not a donut
 *
 * The ramp is sequential and validated on both surfaces; severity colour never
 * appears without a label beside it.
 */
(function (root, factory) {
  const api = factory();
  root.IntelPulseCharts = api;
  if (typeof module === "object" && module.exports) module.exports = api;
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  const esc = (value) => String(value == null ? "" : value)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;");

  const reduceMotion = () =>
    typeof matchMedia === "function" && matchMedia("(prefers-reduced-motion: reduce)").matches;

  /** Sequential step: 1 = weakest, 5 = strongest, in whichever theme is live. */
  function rampStep(value) {
    const clamped = Math.max(0, Math.min(1, Number(value) || 0));
    return 1 + Math.round(clamped * 4);
  }

  /**
   * Evidence contribution chart.
   * One bar per source that answered, sorted by weighted contribution, so the
   * reader's first question — "why is this 95?" — is answered top-down.
   */
  /* A finite number or 0. Evidence arrives from the API in live mode, and a
     string where a number belongs either crashed .toFixed() or, for the weight,
     went into the markup unescaped. Found by mutating every field of a real
     result; pinned by the browser suite. */
  const num = (value) => { const n = Number(value); return Number.isFinite(n) ? n : 0; };

  function contributionChart(evidence, options) {
    options = options || {};
    const rows = (Array.isArray(evidence) ? evidence : []).map((row) => Object.assign({}, row, {
      signal: num(row && row.signal), weight: num(row && row.weight), weighted: num(row && row.weighted)
    })).sort((a, b) => b.weighted - a.weighted);
    if (!rows.length) return "";
    const max = Math.max(...rows.map((r) => r.weighted), 0.001);

    const bars = rows.map((row, index) => {
      const share = Math.max(0.02, row.weighted / max);
      const step = rampStep(row.signal);
      const delay = reduceMotion() ? 0 : index * 45;
      return (
        '<div class="bar-row' + (row.signal < 0.05 ? " muted" : "") + '"' +
        ' title="' + esc(row.provider + ": " + row.rationale) + '">' +
          '<span class="bar-label">' + esc(row.provider) + "</span>" +
          '<span class="bar-track">' +
            '<span class="bar-fill" style="width:' + (share * 100).toFixed(1) + "%;" +
            "background:var(--ramp-" + step + ");animation-delay:" + delay + 'ms"></span>' +
          "</span>" +
          '<span class="bar-value tnum">' + row.signal.toFixed(2) + "</span>" +
        "</div>"
      );
    }).join("");

    const table =
      '<table class="table-view" hidden><caption class="sr-only">Evidence contributions by source</caption>' +
      "<thead><tr><th>Source</th><th>Signal</th><th>Weight</th><th>Weighted</th><th>Rationale</th></tr></thead><tbody>" +
      rows.map((row) =>
        "<tr><td>" + esc(row.provider) + '</td><td class="num">' + row.signal.toFixed(2) +
        '</td><td class="num">' + row.weight + '</td><td class="num">' + row.weighted.toFixed(2) +
        "</td><td>" + esc(row.rationale) + "</td></tr>").join("") +
      "</tbody></table>";

    return (
      '<div class="chart">' +
        '<div class="chart-head">' +
          '<span class="chart-title">' + esc(options.title || "Why this score") + "</span>" +
          '<button class="chart-note" data-table-toggle type="button">Show table</button>' +
        "</div>" +
        '<div class="bars">' + bars + "</div>" +
        table +
      "</div>"
    );
  }

  /** Confidence meter. Fill carries state; the track is the same ramp, lighter. */
  function meter(ratio, severity, extraClass) {
    const pct = Math.round(Math.max(0, Math.min(1, Number(ratio) || 0)) * 100);
    return '<span class="meter' + (severity ? " sev-" + esc(severity) : "") +
      (extraClass ? " " + esc(extraClass) : "") +
      '" role="img" aria-label="' + pct + '%"><i style="width:' + pct + '%"></i></span>';
  }

  /** One cell per provider lookup: green-ish = answered, amber = failed, grey = skipped. */
  function coverageStrip(sources) {
    return '<span class="coverage">' + (sources || []).map((source) =>
      '<i data-state="' + esc(source.status) + '" title="' +
      esc((source.label || source.provider) + ": " + source.status +
        (source.error ? ": " + source.error : "")) + '"></i>').join("") + "</span>";
  }

  /**
   * Count a number up to its value. Perceived performance, not decoration: the
   * eye follows the rise and lands on the figure. Skipped entirely under
   * prefers-reduced-motion, where it just appears.
   */
  function tweenNumber(element, to, options) {
    options = options || {};
    const duration = options.duration || 520;
    const suffix = options.suffix || "";
    const target = Number(to) || 0;
    if (reduceMotion() || duration <= 0) {
      element.textContent = String(Math.round(target)) + suffix;
      return;
    }
    const from = Number(options.from || 0);
    const start = performance.now();
    const easeOutCubic = (t) => 1 - Math.pow(1 - t, 3);

    function frame(now) {
      const t = Math.min(1, (now - start) / duration);
      element.textContent = String(Math.round(from + (target - from) * easeOutCubic(t))) + suffix;
      if (t < 1) requestAnimationFrame(frame);
    }
    requestAnimationFrame(frame);
  }

  /** Wire the "Show table" toggles inside a container (WCAG-clean equivalent). */
  function bindTableToggles(scope) {
    (scope || document).querySelectorAll("[data-table-toggle]").forEach((button) => {
      if (button.dataset.bound) return;
      button.dataset.bound = "1";
      button.addEventListener("click", () => {
        const chart = button.closest(".chart");
        const table = chart.querySelector(".table-view");
        const bars = chart.querySelector(".bars");
        const showTable = table.hasAttribute("hidden");
        table.toggleAttribute("hidden", !showTable);
        bars.toggleAttribute("hidden", showTable);
        button.textContent = showTable ? "Show chart" : "Show table";
      });
    });
  }

  return {
    contributionChart,
    meter,
    coverageStrip,
    tweenNumber,
    bindTableToggles,
    rampStep,
    reduceMotion
  };
});
