/* The console's findings model.
 *
 * This used to be three hand-written tables inside suite.js: a severity list
 * per filter, a state list per filter, and every count written twice — once as
 * a number and once inside its own label. Nothing held them together, so they
 * came apart: the bar sized its last band as "30 minus whatever is on screen"
 * and invented 21 unclassified findings under the Closed filter, while the
 * state row summed to 21 against a severity total of 26.
 *
 * There is one table now. A band knows how many of its findings are awaiting
 * triage, how many are in progress and how many are closed, and every view the
 * console draws is derived from those three numbers. "Open plus closed equals
 * all" is not a rule anyone has to remember, because open IS awaiting plus in
 * progress and all IS those plus closed — there is nothing left to keep in
 * step. The same goes for the labels: a band's text is its own count.
 *
 * Kept out of suite.js so the arithmetic can be tested in Node rather than
 * only through a browser at three filter settings — see
 * tests/console-model.test.mjs. Same dual export as engine.js.
 */
(function (root, factory) {
  const api = factory();
  root.IntelPulseConsole = api;
  if (typeof module === "object" && module.exports) module.exports = api;
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  /* The five bands of the scoring model, and where each band's findings stand.
     These fifteen numbers are the only facts in this file. */
  const BANDS = [
    { k: "critical", label: "Critical",      awaiting: 4, progress: 2, closed: 3 },
    { k: "high",     label: "High",          awaiting: 5, progress: 3, closed: 3 },
    { k: "medium",   label: "Medium",        awaiting: 2, progress: 1, closed: 3 },
    { k: "low",      label: "Low",           awaiting: 2, progress: 1, closed: 2 },
    { k: "info",     label: "Informational", awaiting: 4, progress: 2, closed: 3 }
  ];

  /* The three states a finding is actually in. "Reset ready" named nothing in
     a triage tool. Order is the order they are drawn in. */
  const STATES = [
    { id: "awaiting", label: "Awaiting triage" },
    { id: "progress", label: "In progress" },
    { id: "closed",   label: "Closed" }
  ];

  /* Which states each filter includes. This is the whole definition of the
     three filters — everything else follows from it. */
  const FILTERS = {
    all:   ["awaiting", "progress", "closed"],
    open:  ["awaiting", "progress"],
    close: ["closed"]
  };

  function statesOf(filter) {
    const included = FILTERS[filter];
    if (!included) throw new Error("unknown filter: " + filter);
    return included;
  }

  function countIn(band, filter) {
    return statesOf(filter).reduce((n, id) => n + band[id], 0);
  }

  /* [{ k, label, n, text }] — one entry per band, in scoring order. `text` is
     what the bar prints, derived from the count so the two cannot disagree. */
  function severity(filter) {
    return BANDS.map((band) => {
      const n = countIn(band, filter);
      return { k: band.k, label: band.label, n: n, text: n + " " + band.label };
    });
  }

  /* [{ id, label, n, text }] — always all three states, because a filter that
     hides a state reads as missing rather than empty. Excluded ones are 0. */
  function states(filter) {
    const included = statesOf(filter);
    return STATES.map((state) => {
      const n = included.indexOf(state.id) === -1
        ? 0
        : BANDS.reduce((sum, band) => sum + band[state.id], 0);
      return { id: state.id, label: state.label, n: n, text: n + " " + state.label };
    });
  }

  const sum = (rows) => rows.reduce((n, row) => n + row.n, 0);

  function total(filter) { return sum(severity(filter)); }
  function stateTotal(filter) { return sum(states(filter)); }

  return {
    BANDS: BANDS, STATES: STATES, FILTERS: Object.keys(FILTERS),
    severity: severity, states: states, total: total, stateTotal: stateTotal
  };
});
