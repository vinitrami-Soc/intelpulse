/* Screenshots of a server, for the README and the release notes.
 *
 * Against a new server (as `make test-server` starts one, with ALLOW_DOCUMENTATION_RANGES=true so
 * the RFC 5737 sample addresses are kept), it sets the server up, fills a workspace through the API
 * (a block list, a few triaged cases, a pushed alert, two teammates, a queue in several states), then
 * signs in in Chromium and saves each view to docs/screenshots/server-*.png at twice the pixels.
 *
 *   INTELPULSE_SERVER_URL=http://127.0.0.1:8124/ INTELPULSE_SETUP_CODE=... \
 *   PLAYWRIGHT_MODULE=.../playwright/index.mjs node scripts/screenshots-server.mjs
 *
 * Every address is from RFC 5737 and every name is made up: nothing here is a real alert.
 */
import { mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const { chromium } = await import(process.env.PLAYWRIGHT_MODULE || "playwright");
const BASE = (process.env.INTELPULSE_SERVER_URL || "http://127.0.0.1:8124/").replace(/\/?$/, "/");
const CODE = process.env.INTELPULSE_SETUP_CODE;
const OUT = join(dirname(fileURLToPath(import.meta.url)), "..", "docs", "screenshots");
const PASSWORD = "correct horse battery staple";
if (!CODE) { console.error("set INTELPULSE_SETUP_CODE (python -m app.cli setup-code)"); process.exit(2); }
mkdirSync(OUT, { recursive: true });

/* one person's session over fetch: the cookie by hand, the CSRF token from the answer */
function client() {
  let cookie = "", csrf = "";
  return async function call(method, path, body, headers = {}) {
    const response = await fetch(new URL(path, BASE), {
      method, headers: Object.assign({ "Content-Type": "application/json" }, cookie && { Cookie: cookie },
        csrf && method !== "GET" && { "X-CSRF-Token": csrf }, headers),
      body: body === undefined ? undefined : JSON.stringify(body)
    });
    const set = response.headers.get("set-cookie");
    if (set && set.startsWith("ip_session=")) cookie = set.split(";")[0];
    const answer = response.status === 204 ? null : await response.json().catch(() => null);
    if (answer && answer.csrf) csrf = answer.csrf;
    if (!response.ok) throw new Error(`${method} ${path}: ${response.status} ${JSON.stringify(answer)}`);
    return answer;
  };
}

const ada = client();
await ada("POST", "/api/setup", { code: CODE, username: "ada", password: PASSWORD, organization: "Northwind SOC",
  display_name: "Ada Okafor" });
for (const [username, name] of [["bea", "Bea Torres"], ["cal", "Cal Moreau"]]) {
  await ada("POST", "/api/users", { username, display_name: name, password: PASSWORD, role: "analyst" });
}
const team = await ada("GET", "/api/users");
const id = (name) => team.find((u) => u.username === name).id;

for (const [value, reason] of [["203.0.113.66", "C2 for the June intrusion"], ["198.51.100.23", "phishing kit host"]]) {
  await ada("POST", "/api/lists", { value, list_type: "block", reason });
}
await ada("POST", "/api/lists", { value: "192.0.2.10", list_type: "allow", reason: "our own scanner" });

const cases = [];
for (const [title, text] of [
  ["Perimeter block burst on fw-edge-01",
    "Nov 03 02:14:11 fw-edge-01 kernel: [UFW BLOCK] SRC=203.0.113.66 DST=10.20.4.15 DPT=445\n" +
    "Nov 03 02:14:12 fw-edge-01 kernel: [UFW BLOCK] SRC=198.51.100.77 DST=10.20.4.15 DPT=3389\n" +
    "Nov 03 02:14:13 fw-edge-01 kernel: [UFW BLOCK] SRC=192.0.2.10 DST=10.20.4.16 DPT=22"],
  ["Reported mail: invoice link", "From the user report: hxxp://198[.]51[.]100[.]23/invoice-0932.zip, relay 198.51.100.24"],
  ["VPN sign-ins from a new network", "vpn-gw-02 auth ok user=jng from 203.0.113.140\nvpn-gw-02 auth ok user=jng from 203.0.113.141"],
  ["Proxy denies to a known C2", "squid TCP_DENIED/403 CONNECT 203.0.113.66:443 user=svc_backup"],
  ["Scanner noise on the DMZ", "ids: ET SCAN from 192.0.2.10 to 10.30.0.0/24"]
]) {
  cases.push(await ada("POST", "/api/triage", { text, title }));
}
const token = await ada("POST", "/api/tokens", { name: "edr-forwarder", scope: "ingest" });
const pushed = await fetch(new URL("/api/alerts", BASE), {
  method: "POST", headers: { "Content-Type": "application/json", Authorization: "Bearer " + token.token },
  body: JSON.stringify({
    source: "edr", alert_id: "edr-5521", title: "EDR: beacon from LON-WS-0442", severity: "high",
    description: "Periodic HTTPS beacon every 60 s from svchost.exe to an address on the block list.",
    entities: [{ kind: "host", name: "LON-WS-0442" }, { kind: "user", name: "jng" }],
    attack_techniques: ["T1071.001", "T1573"],
    indicators: ["203.0.113.66"],
    evidence: [{ time: "2026-11-03T08:12:00Z", label: "beacon", text: "svchost.exe -> 203.0.113.66:443 every 60 s" }]
  })
});
if (!pushed.ok) throw new Error("pushing the alert: " + pushed.status);

await ada("PATCH", `/api/cases/${cases[0].case_id}`, { status: "in_progress", assignee_id: id("bea") });
await ada("PATCH", `/api/cases/${cases[1].case_id}`, { status: "in_progress", assignee_id: id("cal") });
await ada("PATCH", `/api/cases/${cases[4].case_id}`, { status: "closed", closed_reason: "benign" });
await ada("PATCH", "/api/settings", { retention_days: 30 });
await ada("POST", "/api/invites", { role: "analyst" });

const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 2 });
const shot = async (name) => {
  await page.waitForTimeout(700);
  await page.screenshot({ path: join(OUT, name) });
  console.log("saved docs/screenshots/" + name);
};

await page.goto(BASE + "#/signin", { waitUntil: "load" });
await page.waitForSelector("#account-username");
await shot("server-signin.png");
await page.fill("#account-username", "ada");
await page.fill("#account-password", PASSWORD);
await page.click("#account-submit");
await page.waitForFunction(() => location.hash.startsWith("#/console/"), null, { timeout: 10000 });

for (const [pane, ready, name] of [
  ["dashboard", "#console-body .kpi", "server-overview.png"],
  ["triage", "#console-body table tbody tr", "server-queue.png"],
  ["surface", "#console-body table tbody tr", "server-surface.png"],
  ["settings", "#st-providers [data-provider]", "server-settings.png"],
  ["team", "#console-body table tbody tr", "server-team.png"],
  ["audit", "#au-list tbody tr", "server-audit.png"]
]) {
  await page.evaluate((p) => { location.hash = "#/console/" + p; }, pane);
  await page.waitForSelector(ready, { timeout: 10000 }).catch(() => console.warn("no " + ready + " on " + pane));
  await shot(name);
}
await page.goto(BASE + "privacy.html", { waitUntil: "load" });
await shot("privacy.png");
await browser.close();
