/* The console's findings model.
 *
 * The bug this file exists to prevent shipped once already: the severity bar
 * sized its last band as "30 minus whatever is on screen", so filtering to
 * Closed claimed 21 unclassified findings out of nowhere, and the state row
 * summed to 21 against a severity total of 26. It was caught by eye, in a
 * screenshot, after it was live.
 *
 * Three Playwright checks pinned it afterwards — one per filter. These pin it
 * per filter AND per band, in Node, without a browser, and they assert the
 * properties rather than the numbers wherever a property is what actually
 * matters. A hardcoded expectation would only catch a typo; these catch a
 * fifth band being added with no closed count, or a filter being redefined.
 *
 *   node --test web/tests/
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const M = require("../assets/console-model.js");

test("every filter is a filter the model knows", () => {
  assert.deepEqual(M.FILTERS, ["all", "open", "close"]);
  assert.throws(() => M.severity("nope"), /unknown filter/);
  assert.throws(() => M.states("nope"), /unknown filter/);
});

test("severity reconciles with state under every filter", () => {
  for (const filter of M.FILTERS) {
    assert.equal(M.total(filter), M.stateTotal(filter),
      filter + ": " + M.total(filter) + " findings by severity against " +
      M.stateTotal(filter) + " by state");
  }
});

test("open plus closed equals all, band by band", () => {
  const open = M.severity("open"), closed = M.severity("close"), all = M.severity("all");
  for (let i = 0; i < all.length; i++) {
    assert.equal(open[i].k, all[i].k);
    assert.equal(closed[i].k, all[i].k);
    assert.equal(open[i].n + closed[i].n, all[i].n,
      all[i].label + ": " + open[i].n + " open + " + closed[i].n +
      " closed against " + all[i].n + " in total");
  }
});

test("a band's label carries its own count", () => {
  for (const filter of M.FILTERS) {
    for (const band of M.severity(filter)) {
      assert.equal(band.text, band.n + " " + band.label);
    }
    for (const state of M.states(filter)) {
      assert.equal(state.text, state.n + " " + state.label);
    }
  }
});

test("the bar always draws all five bands, the state row always all three", () => {
  /* A filter that drops a row reads as missing rather than empty, and a band
     sized by count alone would vanish at zero. Both stay, both stay labelled. */
  for (const filter of M.FILTERS) {
    assert.equal(M.severity(filter).length, 5, filter + " dropped a severity band");
    assert.equal(M.states(filter).length, 3, filter + " dropped a state");
  }
});

test("no count is negative and no filter is empty", () => {
  for (const filter of M.FILTERS) {
    assert.ok(M.total(filter) > 0, filter + " has no findings at all");
    for (const band of M.severity(filter)) {
      assert.ok(band.n >= 0, band.label + " went negative under " + filter);
    }
  }
});

test("the Closed filter shows only closed work, Open only unclosed", () => {
  const byId = (rows) => Object.fromEntries(rows.map((r) => [r.id, r.n]));
  const closed = byId(M.states("close"));
  assert.equal(closed.awaiting, 0);
  assert.equal(closed.progress, 0);
  assert.ok(closed.closed > 0);

  const open = byId(M.states("open"));
  assert.equal(open.closed, 0);
  assert.ok(open.awaiting > 0 && open.progress > 0);
});

test("the bands are the five the scoring model defines, in order", () => {
  assert.deepEqual(M.severity("all").map((b) => b.k),
    ["critical", "high", "medium", "low", "info"]);
});

test("the numbers on the page are the ones the model derives", () => {
  /* The one place a literal belongs: these are what the landing page showed
     before the tables were replaced by derivations, so the refactor is pinned
     as behaviour-preserving rather than merely self-consistent. */
  assert.deepEqual(M.severity("all").map((b) => b.text),
    ["9 Critical", "11 High", "6 Medium", "5 Low", "9 Informational"]);
  assert.deepEqual(M.severity("open").map((b) => b.text),
    ["6 Critical", "8 High", "3 Medium", "3 Low", "6 Informational"]);
  assert.deepEqual(M.severity("close").map((b) => b.text),
    ["3 Critical", "3 High", "3 Medium", "2 Low", "3 Informational"]);
  assert.deepEqual(M.states("all").map((s) => s.text),
    ["17 Awaiting triage", "9 In progress", "14 Closed"]);
  assert.deepEqual([M.total("all"), M.total("open"), M.total("close")], [40, 26, 14]);
});
