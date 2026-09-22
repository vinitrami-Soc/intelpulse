/* Parity tests for the browser engine.
 *
 * The dashboard's demo mode re-implements the backend's extraction and scoring
 * in JavaScript. These tests pin the JS side to the same behaviour the Python
 * suite pins (backend/tests/test_ioc.py, test_scoring.py), so the two cannot
 * drift silently.
 *
 *   node --test web/tests/
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const E = require("../assets/engine.js");

const SYSLOG = `Jan 12 09:22:11 fw01 kernel: DROP SRC=185.220.101.34 DST=10.0.0.5 PROTO=TCP DPT=443
Jan 12 09:22:14 proxy01: CONNECT hxxp://malicious-update[.]top/beacon.bin 200
Jan 12 09:23:02 edr01: sha256=9f2c4a1b8e7d6c5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f
Jan 12 09:24:44 mail01: sender=payroll@totally-legit-hr[.]ru`;

test("extracts typed indicators from raw syslog", () => {
  const byType = {};
  E.extract(SYSLOG).forEach((i) => { byType[i.type] = i.value; });
  assert.equal(byType.ip, "185.220.101.34");
  assert.equal(byType.url, "http://malicious-update.top/beacon.bin");
  assert.equal(byType.email, "payroll@totally-legit-hr.ru");
  assert.ok(byType.hash.startsWith("9f2c4a1b"));
});

test("drops private, reserved and documentation address space", () => {
  const values = E.extract("10.0.0.5 192.168.1.1 127.0.0.1 169.254.1.1 203.0.113.9 8.8.8.8")
    .map((i) => i.value);
  assert.deepEqual(values, ["8.8.8.8"]);
});

test("documentation ranges are opt-in for the bundled demo dataset", () => {
  assert.equal(E.extract("203.0.113.9").length, 0);
  assert.equal(E.extract("203.0.113.9", { allowDocumentation: true }).length, 1);
});

test("filenames and version strings are not domains", () => {
  assert.deepEqual(E.extract("svchost.exe loaded v1.2.3 from update.log"), []);
});

test("JSON alert exports are walked", () => {
  const payload = '{"Event":{"src_ip":"45.155.205.233","url":"http://drop.example.co/win.exe"}}';
  const types = new Set(E.extract(payload).map((i) => i.type));
  assert.ok(types.has("ip") && types.has("url"));
});

const ip = { value: "185.220.101.34", type: "ip" };
const source = (provider, key, value, extra) => Object.assign({
  provider, label: provider, status: "ok",
  signals: [{ key, value, rationale: provider + " says " + value }],
  facts: {}, tags: [], malware_families: [], attack_ids: [], relations: []
}, extra || {});

test("one authoritative hit survives five quiet sources", () => {
  const verdict = E.scoreIndicator(ip, [
    source("threatfox", "threatfox", 0.95, { malware_families: ["QakBot"] }),
    source("abuseipdb", "abuseipdb", 0), source("otx", "otx", 0), source("geoip", "geoip", 0)
  ]);
  assert.ok(verdict.score >= 85, "expected >=85, got " + verdict.score);
  assert.ok(["high", "critical"].includes(verdict.verdict));
});

test("skipped providers do not deflate the score", () => {
  const answered = [source("abuseipdb", "abuseipdb", 0.9)];
  const skipped = { provider: "otx", label: "otx", status: "skipped", signals: [], facts: {} };
  assert.equal(
    E.scoreIndicator(ip, answered.concat(skipped)).score,
    E.scoreIndicator(ip, answered).score
  );
});

test("GreyNoise benign damps the verdict", () => {
  const damped = E.scoreIndicator(ip, [
    source("abuseipdb", "abuseipdb", 0.8),
    source("greynoise", "greynoise", 0.05, { facts: { classification: "benign", actor: "Shodan" } })
  ]);
  const undamped = E.scoreIndicator(ip, [source("abuseipdb", "abuseipdb", 0.8)]);
  assert.ok(damped.score < undamped.score);
  assert.ok(damped.modifiers.some((m) => m.includes("background noise")));
});

test("allowlist forces zero, blocklist forces high", () => {
  const allowed = E.scoreIndicator(ip, [source("threatfox", "threatfox", 0.95)],
    { value: ip.value, list_type: "allow", reason: "our CDN" });
  assert.equal(allowed.score, 0);
  assert.equal(allowed.verdict, "allowlisted");

  const blocked = E.scoreIndicator(ip, [source("abuseipdb", "abuseipdb", 0)],
    { value: ip.value, list_type: "block", reason: "IR-2024-11" });
  assert.ok(blocked.score >= 90);
});

test("ATT&CK ids are derived from tags when the vendor gives none", () => {
  const ids = E.deriveAttackIds([
    source("abuseipdb", "abuseipdb", 0.7, { tags: ["SSH", "Brute-Force"] }),
    source("urlhaus", "urlhaus", 0.9, { malware_families: ["Emotet loader"] })
  ]);
  assert.ok(ids.includes("T1110") && ids.includes("T1105"));
});

test("verdict bands match the backend", () => {
  assert.equal(E.verdictFor(5), "informational");
  assert.equal(E.verdictFor(20), "low");
  assert.equal(E.verdictFor(50), "medium");
  assert.equal(E.verdictFor(72), "high");
  assert.equal(E.verdictFor(95), "critical");
});

function loadDataset() {
  require("../assets/demo-data.js");   // assigns onto globalThis outside a browser
  return globalThis.INTELPULSE_DEMO;
}

test("demo triage produces a scored, graphed, reportable case", () => {
  const dataset = loadDataset();
  const result = E.demoTriage(dataset.scenarios[0].text, dataset, { title: "unit test" });

  assert.ok(result.indicators.length >= 3);
  assert.equal(result.verdict, "critical");
  assert.ok(result.graph.nodes.length > result.indicators.length, "graph should add related entities");

  const markdown = E.toMarkdown(result, { demo: true });
  assert.ok(markdown.includes("# SOC Triage Report — unit test"));
  assert.ok(markdown.includes("## 4. Recommended containment actions"));
  assert.ok(markdown.includes("Demo mode"), "demo reports must say they are synthetic");
  assert.ok(markdown.includes("203[.]0[.]113[.]10"), "indicators must be defanged");

  const ticket = E.toTicketJson(result, { demo: true });
  assert.equal(ticket.mode, "demo (synthetic dataset)");
  assert.ok(ticket.priority.startsWith("P1"));
});

test("indicators outside the demo dataset are not invented", () => {
  const result = E.demoTriage("8.8.4.4", loadDataset(), {});
  assert.equal(result.indicators[0].score, 0);
  assert.ok(result.indicators[0].sources.every((s) => s.status === "skipped"));
});

/* ─────────────────────────── triage diff parity
 * The browser engine re-implements backend/app/services/history.py so demo
 * mode can show the same "what changed" panel with no backend. These pin the
 * two to the same band order, the same idea of which sources answered, and
 * the same summary wording — the strings are asserted because they are what
 * an analyst reads.
 */
const snapOf = (over = {}) => E.snapshotOf({
  score: 50, verdict: "medium", sources: [{ provider: "otx", status: "ok" }],
  malware_families: [], attack_techniques: [], ...over
});

test("the diff band order matches the Python one", () => {
  assert.deepEqual(E.BANDS, ["informational", "low", "medium", "high", "critical"]);
});

test("only sources that answered count as answering", () => {
  const s = E.snapshotOf({
    score: 90, verdict: "critical",
    sources: [
      { provider: "urlhaus", status: "ok" },
      { provider: "otx", status: "clean" },
      { provider: "threatfox", status: "skipped" },
      { provider: "greynoise", status: "error" }
    ],
    malware_families: ["SamplePhishKit"],
    attack_techniques: [{ id: "T1566.002" }, { id: "T1566" }]
  });
  assert.deepEqual(s.answering, ["otx", "urlhaus"]);
  assert.deepEqual(s.attack_ids, ["T1566", "T1566.002"]);
  assert.equal(s.score, 90);
});

test("a missing result snapshots to the empty shape", () => {
  assert.deepEqual(E.snapshotOf(null),
    { score: 0, verdict: "informational", answering: [], malware_families: [], attack_ids: [] });
});

test("a first sighting says so and claims no delta", () => {
  const d = E.diffSnapshots(snapOf(), null);
  assert.equal(d.first_seen, true);
  assert.equal(d.score_delta, 0);
  assert.equal(d.summary, "First time this indicator has been triaged.");
});

test("an unchanged indicator reports no change", () => {
  const d = E.diffSnapshots(snapOf(), snapOf());
  assert.equal(d.changed, false);
  assert.equal(d.summary, "No change since the last triage.");
});

test("a worse verdict is an escalation, and leads the summary", () => {
  const d = E.diffSnapshots(
    snapOf({ score: 92, verdict: "critical", sources: [{ provider: "otx", status: "ok" }, { provider: "threatfox", status: "ok" }] }),
    snapOf({ score: 40, verdict: "medium" })
  );
  assert.equal(d.escalated, true);
  assert.equal(d.de_escalated, false);
  assert.equal(d.score_delta, 52);
  assert.deepEqual(d.sources_added, ["threatfox"]);
  assert.ok(d.summary.startsWith("Escalated from medium to critical"), d.summary);
});

test("a better verdict is a de-escalation", () => {
  const d = E.diffSnapshots(snapOf({ score: 20, verdict: "low" }), snapOf({ score: 80, verdict: "high" }));
  assert.equal(d.escalated, false);
  assert.equal(d.de_escalated, true);
  assert.equal(d.score_delta, -60);
  assert.ok(d.summary.startsWith("Dropped from high to low"), d.summary);
});

test("a source going quiet is named, and a lost family is not called new", () => {
  const d = E.diffSnapshots(
    snapOf({ sources: [], malware_families: [] }),
    snapOf({ sources: [{ provider: "greynoise", status: "ok" }], malware_families: ["Gone"] })
  );
  assert.deepEqual(d.sources_removed, ["greynoise"]);
  assert.deepEqual(d.new_malware_families, []);
  assert.ok(d.summary.includes("stopped answering: greynoise"), d.summary);
});

test("a band from an older release compares as changed with no direction", () => {
  const d = E.diffSnapshots(snapOf({ verdict: "medium" }), snapOf({ verdict: "weird-old-band" }));
  assert.equal(d.verdict_changed, true);
  assert.equal(d.escalated, false);
  assert.equal(d.de_escalated, false);
});

test("a score move with no band change still reads as a delta", () => {
  const d = E.diffSnapshots(snapOf({ score: 62 }), snapOf({ score: 50 }));
  assert.equal(d.verdict_changed, false);
  assert.ok(d.summary.startsWith("Score up 12 to 62"), d.summary);
});
