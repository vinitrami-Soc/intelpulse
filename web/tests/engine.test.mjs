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
