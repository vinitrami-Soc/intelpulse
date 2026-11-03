/* Browser suite against a real IntelPulse server: the console in server mode.
 *
 * The other suites run the static demo. This one runs the same pages served by
 * the app, on SQLite, with no provider keys: a new server is set up with its
 * one-time code, the owner triages from the workbench and the case lands in
 * their workspace, then they sign out and back in with the keyboard alone.
 *
 * Run (see .github/workflows/intelpulse.yml, job "server"):
 *   cd backend && ENCRYPTION_KEY=... DATABASE_URL=sqlite+aiosqlite:///$PWD/s.db \
 *     uvicorn app.main:app --port 8124 &
 *   INTELPULSE_SETUP_CODE=$(python -m app.cli setup-code | tail -1) \
 *     INTELPULSE_SERVER_URL=http://127.0.0.1:8124/ node web/tests/server.spec.mjs
 */
let chromium;
try {
  ({ chromium } = await import(process.env.PLAYWRIGHT_MODULE || "playwright"));
} catch (error) {
  console.error("Playwright is required for these tests: npm i -D playwright");
  process.exit(2);
}

const BASE = process.env.INTELPULSE_SERVER_URL || "http://127.0.0.1:8124/";
const CODE = process.env.INTELPULSE_SETUP_CODE || "";
if (!CODE) {
  console.error("INTELPULSE_SETUP_CODE is not set: run `python -m app.cli setup-code` on the server first");
  process.exit(2);
}
const ORIGIN = new URL(BASE).origin;
const PASSWORD = "correct horse battery staple";
let failures = 0;
const check = (name, ok, detail) => {
  console.log((ok ? "PASS  " : "FAIL  ") + name + (detail ? "  — " + detail : ""));
  if (!ok) failures++;
};

const browser = await chromium.launch();
const context = await browser.newContext({ viewport: { width: 1280, height: 900 } });
const page = await context.newPage();
const errors = [], outside = [], cspReports = [], writes = [];
page.on("pageerror", (e) => errors.push(e.message));
page.on("dialog", async (d) => { errors.push("dialog: " + d.message()); await d.dismiss(); });
page.on("console", (m) => {
  if (/Content Security Policy/i.test(m.text())) cspReports.push(m.text().slice(0, 140));
  else if (m.type() === "error" && !/status of 40[13]/.test(m.text())) errors.push("console: " + m.text());
});
page.on("request", (r) => {
  const url = r.url();
  if (!url.startsWith(ORIGIN) && !/^(data|blob):/.test(url)) outside.push(url);
  if (r.method() !== "GET" && new URL(url).pathname.startsWith("/api/")) {
    writes.push({ path: new URL(url).pathname, method: r.method(), headers: r.headers() });
  }
});
const hash = () => page.evaluate(() => location.hash);
const text = (sel) => page.$eval(sel, (el) => el.textContent.trim()).catch(() => "");
const visible = (sel) => page.$eval(sel, (el) => !el.closest("[hidden]") && el.getClientRects().length > 0).catch(() => false);

// ——————————————————————————————————————— 1. a new server asks to be set up
await page.goto(BASE + "#/console/workbench", { waitUntil: "domcontentloaded" });
await page.waitForSelector("#account-form", { timeout: 8000 });
check("a new server sends the console to #/setup", (await hash()) === "#/setup", await hash());
check("the setup page has one h1, and says so", (await page.$$eval("h1", (hs) => hs.filter((h) => h.getClientRects().length).length)) === 1 &&
  /set up this server/i.test(await text("#account-title")));
check("the first field has the focus", await page.evaluate(() => document.activeElement && document.activeElement.id === "account-code"));

await page.fill("#account-code", "AAAA-BBBB-CCCC-DDDD");
await page.fill("#account-organization", "Acme SOC");
await page.fill("#account-username", "ada");
await page.fill("#account-password", PASSWORD);
await page.click("#account-submit");
await page.waitForFunction(() => !document.querySelector("#account-error").hidden, null, { timeout: 5000 }).catch(() => {});
check("a wrong setup code is refused, in words", /setup code is not right/i.test(await text("#account-error")), await text("#account-error"));

await page.fill("#account-code", CODE);
await page.fill("#account-password", "too short");
await page.click("#account-submit");
check("a short password is caught before it is sent",
  /at least 12/i.test(await text("#account-error")) &&
  (await page.getAttribute("#account-password", "aria-invalid")) === "true");

await page.fill("#account-password", PASSWORD);
await page.click("#account-submit");
await page.waitForFunction(() => location.hash.startsWith("#/console/"), null, { timeout: 8000 }).catch(() => {});
check("setting up signs the owner in and opens the page they asked for", (await hash()) === "#/console/workbench", await hash());
await page.waitForSelector("#wb-input", { timeout: 8000 });
check("the header names who is signed in", /ada/i.test(await text("#c-who")) && /owner/i.test(await text("#c-who")),
  await text("#c-who"));
check("and names the workspace the workbench works in", /Acme SOC/.test(await text("#c-workspace")), await text("#c-workspace"));
check("the session cookie is out of the page's reach", await page.evaluate(() => !document.cookie.includes("ip_session")));

// ——————————————————————————————————————— 2. a triage lands in the workspace
check("the workbench triages on the server", /live/.test(await text("#wb-source")), await text("#wb-source"));
check("and asks for no API address or token", !(await page.$("#wb-api, #wb-token, [data-mode]")));
await page.fill("#wb-input", "Sep 18 02:14:11 fw-edge-01 kernel: [UFW BLOCK] SRC=185.220.101.34 DST=10.20.4.15 DPT=445");
await page.fill("#wb-title", "Server suite: perimeter block");
await page.click("#wb-run");
await page.waitForSelector("#wb-results:not([hidden]) .wb-ioc", { timeout: 20000 }).catch(() => {});
check("the result renders", await visible("#wb-results .wb-ioc"));
const note = await text("#wb-mode-note");
check("and is not labelled demo data", !/demo/i.test(note), note);
const triage = writes.find((w) => w.path === "/api/triage");
check("the triage carried the session's CSRF token", Boolean(triage && triage.headers["x-csrf-token"]));
check("and no Authorization header", Boolean(triage) && !triage.headers.authorization);
await page.waitForFunction(() => /Server suite/.test(document.querySelector("#wb-history")?.textContent || ""), null, { timeout: 8000 }).catch(() => {});
check("the case history shows the case, from the workspace", /Server suite: perimeter block/.test(await text("#wb-history")));
const cases = await page.evaluate(async () => (await fetch("/api/cases", { credentials: "same-origin" })).json());
check("the server stored it in the owner's workspace", Array.isArray(cases) && cases.some((c) => c.title === "Server suite: perimeter block"),
  Array.isArray(cases) ? cases.length + " case(s)" : JSON.stringify(cases).slice(0, 80));

// ——————————————————————————————————————— 2b. every view reads the workspace's own cases
const api = (path, init) => page.evaluate(async ([path, init]) => {
  const csrf = (await (await fetch("/api/session", { credentials: "same-origin" })).json()).csrf;
  const response = await fetch(path, Object.assign({ credentials: "same-origin" }, init || {}, {
    headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf }
  }));
  return { status: response.status, body: await response.json().catch(() => null) };
}, [path, init]);
const HOSTILE = '<img src=x onerror="window.__pwned=1">Hostile title';
for (const [n, title] of [[1, "Ransomware staging on LON-WS-0442"], [2, HOSTILE]]) {
  const pushed = await api("/api/alerts", { method: "POST", body: JSON.stringify({
    source: "dwellwatch", alert_id: "DW-" + n, title, severity: "high", attack_techniques: ["T1486"],
    entities: [{ kind: "host", name: "LON-WS-0442" }, { kind: "user", name: "j.okafor" },
      ...(n === 2 ? [{ kind: "host", name: '<svg onload="window.__pwned=2">' }] : [])] }) });
  check("an integration pushes alert " + n, pushed.status === 201, String(pushed.status));
}
const view = async (pane, ready) => {
  await page.evaluate((p) => { location.hash = "#/console/" + p; }, pane);
  await page.waitForSelector(ready, { timeout: 8000 }).catch(() => {});
};
// two cases that share a blocked address are one campaign, which the graph draws
const blocked = await api("/api/lists", { method: "POST",
  body: JSON.stringify({ value: "185.220.101.77", list_type: "block", reason: "server suite" }) });
check("an admin blocks an address", blocked.status === 201, String(blocked.status));
for (const title of ["Campaign suite: first", "Campaign suite: second"]) {
  const run = await api("/api/triage", { method: "POST", body: JSON.stringify({ indicators: ["185.220.101.77"], title }) });
  check("a case names the blocked address: " + title, run.status === 200 && run.body.verdict !== "informational",
    run.status + " " + (run.body && run.body.verdict));
}
const stats = (await api("/api/stats")).body;

await view("dashboard", "#sv-kpis .kpi");
const kpis = await page.$$eval("#sv-kpis .kpi", (cards) => cards.map((c) => [c.querySelector("b").textContent, c.querySelector(".val").textContent]));
check("the overview counts the workspace's open cases", kpis.some(([label, value]) => label === "Open cases" && Number(value) === stats.open),
  JSON.stringify(kpis) + " vs open " + stats.open);
const banded = await page.$$eval("[data-sv-sev] span", (spans) => spans.reduce((n, s) => n + parseInt(s.textContent, 10), 0));
check("its severity bar adds up to the workspace's cases", banded === stats.cases, banded + " vs " + stats.cases);
check("the header says live, in the workspace, not sample data",
  /Acme SOC/.test(await text("#c-workspace")) && !/sample data/i.test(await text("#console-body .console-head")));
check("no sample indicator is shown", !/203\.0\.113\.10|cdn\.example\.org/.test(await text("#console-panels")));

await view("all-findings", "#sv-ind table, #sv-ind .empty-state");
const indicators = (await api("/api/indicators?limit=200")).body;
const listed = await page.$$eval("#sv-ind tbody tr", (rows) => rows.length);
check("all indicators lists each of the workspace's indicators once", listed === indicators.length && listed > 0,
  listed + " rows vs " + indicators.length);
check("including the one triaged above", /185\.220\.101\.34/.test(await text("#sv-ind")));

await view("activity", "#sv-cases table");
const allCases = (await api("/api/cases?limit=200")).body;
check("the triage history lists every case", (await page.$$eval("#sv-cases tbody tr", (r) => r.length)) === allCases.length,
  allCases.length + " cases");
check("a hostile case title is shown as text, never run", await page.evaluate(() =>
  window.__pwned === undefined && !document.querySelector("#sv-cases img") &&
  document.querySelector("#sv-cases").textContent.includes('<img src=x onerror="window.__pwned=1">')));
await page.fill("#sv-q", "perimeter");
await page.click("#sv-search button[type=submit]");
await page.waitForFunction(() => document.querySelectorAll("#sv-cases tbody tr").length === 1, null, { timeout: 5000 }).catch(() => {});
check("and searching finds the case by its title", /Server suite: perimeter block/.test(await text("#sv-cases")) &&
  (await page.$$eval("#sv-cases tbody tr", (r) => r.length)) === 1);
const searched = await page.$eval("#sv-cases [data-hold]", (el) => el.dataset.hold);
await page.click("#sv-cases [data-hold]");
await page.waitForFunction(() => /Release/.test(document.querySelector("#sv-cases [data-hold]")?.textContent || ""), null, { timeout: 5000 }).catch(() => {});
check("an admin holds a case from the history", (await api("/api/cases/" + searched)).body.held === true);
await page.click("#sv-cases [data-hold]");
await page.waitForFunction(() => /^Hold$/.test(document.querySelector("#sv-cases [data-hold]")?.textContent || ""), null, { timeout: 5000 }).catch(() => {});
check("and releases it", (await api("/api/cases/" + searched)).body.held === false);
await page.click("#sv-cases [data-drop-input]");
check("deleting an input asks twice", /Press again/.test(await text("#sv-cases [data-drop-input]")));
await page.click("#sv-cases [data-drop-input]");
await page.waitForFunction(() => /input deleted/.test(document.querySelector("#sv-cases")?.textContent || ""), null, { timeout: 5000 }).catch(() => {});
const dropped = (await api("/api/cases/" + searched)).body;
check("and then the input is gone, the verdict stays", dropped.input_deleted_at && dropped.raw_input === null && Boolean(dropped.verdict));

await view("triage", "#sv-cases [data-status]");
const caseId = await page.$eval("#sv-cases [data-status]", (el) => el.dataset.status);
await page.selectOption('[data-status="' + caseId + '"]', "in_progress");
await page.waitForFunction(() => document.querySelector("#toast")?.textContent.includes("Case updated"), null, { timeout: 5000 }).catch(() => {});
const me = (await api("/api/users")).body.find((m) => m.username === "ada");
/* The change re-renders the queue: wait for the new row (its status select enabled, and showing the
   new status) before the next control, or the click lands on a select that is about to go. */
const rerendered = (id) => page.waitForFunction((id) => {
  const select = document.querySelector('[data-status="' + id + '"]');
  return Boolean(select) && !select.disabled && select.value === "in_progress" &&
    !document.querySelector('[data-assign="' + id + '"]').disabled;
}, id, { timeout: 8000 }).catch(() => {});
await rerendered(caseId);
await page.selectOption('[data-assign="' + caseId + '"]', String(me.id));
await page.waitForFunction(async ([id, uid]) => {
  const c = await (await fetch("/api/cases/" + id, { credentials: "same-origin" })).json();
  return c.status === "in_progress" && c.assignee && c.assignee.id === uid;
}, [caseId, me.id], { timeout: 5000, polling: 300 }).catch(() => {});
const worked = (await api("/api/cases/" + caseId)).body;
check("the queue's controls move the case: in progress, and taken", worked.status === "in_progress" && worked.assignee?.username === "ada",
  worked.status + " / " + (worked.assignee && worked.assignee.username));
const update = writes.find((w) => w.path === "/api/cases/" + caseId && w.method === "PATCH");
check("each change carried the session's CSRF token", Boolean(update && update.headers["x-csrf-token"]));

await view("surface", "#sv-assets table");
check("the attack surface names the host the alerts named", /LON-WS-0442/.test(await text("#sv-assets")) &&
  /j\.okafor/.test(await text("#sv-assets")));
check("and a hostile host name is text, never markup", await page.evaluate(() =>
  window.__pwned === undefined && !document.querySelector("#sv-assets svg[onload]") &&
  document.querySelector("#sv-assets").textContent.includes('<svg onload="window.__pwned=2">')));
await view("narratives", "#sv-stories .sv-card");
check("the narratives tell the pushed alert's technique", /Impact/.test(await text("#sv-stories")) && /T1486/.test(await text("#sv-stories")));
await view("tickets", "#sv-tickets .empty-state, #sv-tickets table");
check("a workspace with no ticket says how to raise one", /No tickets yet/.test(await text("#sv-tickets")));
await view("sources", "#sv-sources table");
const providers = (await api("/api/sources")).body.providers;
check("the sources view lists every provider the workspace has", (await page.$$eval("#sv-sources tbody tr", (r) => r.length)) === providers.length);
await view("campaigns", "#cg-svg .cg-node");
check("the campaign graph draws the workspace's own campaign", /185\.220\.101\.77/.test(await text("#cg-table")) &&
  (await page.$$eval("#cg-svg .cg-node", (nodes) => nodes.length)) >= 2, await text("#cg-table"));
check("with its cases beneath it, and nothing of the sample",
  /Campaign suite: first/.test(await text("#sv-campaign-cases")) && /Campaign suite: second/.test(await text("#sv-campaign-cases")) &&
  !/IR-2026-114|Synthetic dataset/.test(await text("#sv-campaigns")));
check("one h1 or none on every view: the console's titles are h3", await page.evaluate(() =>
  document.querySelectorAll("#page-console h1").length <= 1));

// ——————————————————————————————————————— 2c. the workspace's own panes, as its owner
check("the sidebar lists the workspace's panes for an admin", await page.$$eval("#nav-workspace .nav-item",
  (items) => items.map((i) => i.dataset.pane).join(",")) === "settings,team,tokens,audit,profile,server");

await view("server", "#sv-srv-signup");
await page.waitForFunction(() => /Sign-up is closed/.test(document.querySelector("#sv-srv-now")?.textContent || ""), null, { timeout: 5000 }).catch(() => {});
check("the Server pane says sign-up is closed, as it starts", /Sign-up is closed/.test(await text("#sv-srv-now")));
await page.check("#sv-srv-signup");
await page.click("#sv-srv button[type=submit]");
await page.waitForFunction(() => /Sign-up is open/.test(document.querySelector("#sv-srv-now")?.textContent || ""), null, { timeout: 5000 }).catch(() => {});
check("the owner opens sign-up from the Server pane", (await api("/api/server")).body.signup === true);
check("the Server pane shows each workspace's triage budget", await page.inputValue("#sv-srv-budget") === "500");
await page.fill("#sv-srv-budget", "750");
await page.click("#sv-srv button[type=submit]");
await page.waitForFunction(() => /Saved/.test(document.querySelector("#sv-srv-status")?.textContent || ""), null, { timeout: 5000 }).catch(() => {});
check("the owner sets the triage budget from the Server pane", (await api("/api/server")).body.triage_daily_budget === 750);

await view("settings", "#st-providers [data-provider]");
await page.uncheck('[data-provider="otx"]');
await page.waitForFunction(() => /Off: otx/.test(document.querySelector("#st-prov-status")?.textContent || ""), null, { timeout: 5000 }).catch(() => {});
const otx = (await api("/api/settings")).body.providers.find((p) => p.name === "otx");
check("switching a source off in Settings turns it off on the server", otx && otx.enabled === false);
const KEY = "suite-test-key-0000wxyz";
await page.fill("#st-key-otx", KEY);
await page.click('[data-key="otx"] button[type=submit]');
await page.waitForFunction(() => /Set: /.test(document.querySelector("#st-key-otx")?.placeholder || ""), null, { timeout: 5000 }).catch(() => {});
check("a provider key is saved, and only its last four characters come back",
  /^Set: •+wxyz$/.test(await page.getAttribute("#st-key-otx", "placeholder") || "") &&
  !(await page.evaluate((k) => document.documentElement.outerHTML.includes(k), KEY)));

await view("tokens", "#tk-new");
await page.fill("#tk-name", "siem-forwarder");
await page.selectOption("#tk-scope", "ingest");
await page.click("#tk-new button[type=submit]");
await page.waitForSelector("#tk-value", { timeout: 5000 }).catch(() => {});
const token = await page.$eval("#tk-value", (el) => el.value).catch(() => "");
check("a new API token is shown once, to copy", /^ipt_/.test(token));
const scoped = await page.evaluate(async (t) => (await fetch("/api/stats", { headers: { Authorization: "Bearer " + t } })).status, token);
check("and it works with its scope only: ingest cannot read", scoped === 403, String(scoped));
await page.click("[data-hide-token]");
await view("audit", "#au-list");
await view("tokens", "#tk-list [data-revoke], #tk-list table");
check("once the pane closes, the token is nowhere on the page",
  !(await page.evaluate((t) => document.documentElement.outerHTML.includes(t), token)));
await page.click("#tk-list [data-revoke]");
await page.click("#tk-list [data-revoke]");
await page.waitForFunction(() => /Revoked/.test(document.querySelector("#tk-status")?.textContent || ""), null, { timeout: 5000 }).catch(() => {});
const revoked = (await api("/api/tokens")).body.find((t) => t.name === "siem-forwarder");
check("revoking takes two presses and no dialog, and the server agrees", Boolean(revoked && revoked.revoked_at));

await view("team", "#tm-add");
await page.fill("#tm-username", "dora");
await page.fill("#tm-name", "Dora");
await page.fill("#tm-password", PASSWORD);
await page.click("#tm-add button[type=submit]");
await page.waitForFunction(() => /Added dora/.test(document.querySelector("#tm-add-status")?.textContent || ""), null, { timeout: 5000 }).catch(() => {});
const dora = (await api("/api/users")).body.find((m) => m.username === "dora");
check("an admin adds a member from Team, who must choose their own password", Boolean(dora && dora.must_change_password));
check("and Team lists them", /Dora/.test(await text("#tm-list")));
await page.selectOption("#tm-inv-role", "analyst");
await page.click("#tm-invite button[type=submit]");
await page.waitForSelector("#tm-inv-link", { timeout: 5000 }).catch(() => {});
const inviteLink = await page.$eval("#tm-inv-link", (el) => el.value).catch(() => "");
check("an admin makes an invitation link, shown once", /#\/join\/[A-Za-z0-9_-]{20,}$/.test(inviteLink), inviteLink.slice(0, 60));
await page.waitForFunction(() => /open/.test(document.querySelector("#tm-inv-list")?.textContent || ""), null, { timeout: 5000 }).catch(() => {});
check("and the invitations list it as open, without its token",
  /open/.test(await text("#tm-inv-list")) && !(await text("#tm-inv-list")).includes(inviteLink.split("/join/")[1] || "-"));
await page.click("[data-hide-invite]");

await view("audit", "#au-list table");
await page.click("#au-verify");
await page.waitForFunction(() => /chain/.test(document.querySelector("#au-verdict")?.textContent || ""), null, { timeout: 5000 }).catch(() => {});
check("Verify the chain says the audit chain holds", /The chain holds/.test(await text("#au-verdict")), await text("#au-verdict"));
await page.fill("#au-action", "token.");
await page.click("#au-filter button[type=submit]");
await page.waitForFunction(() => document.querySelectorAll("#au-list tbody tr").length >= 2 &&
  [...document.querySelectorAll("#au-list tbody tr")].every((r) => r.textContent.includes("token.")), null, { timeout: 5000 }).catch(() => {});
check("the audit log filters by an action's start", (await page.$$eval("#au-list tbody tr", (rows) =>
  rows.length >= 2 && rows.every((r) => /token\.(created|revoked)/.test(r.textContent)))));

await view("profile", "#pf-form");
await page.waitForFunction(() => document.querySelector("#pf-name")?.value === "ada", null, { timeout: 5000 }).catch(() => {});
await page.fill("#pf-name", "Ada Lovelace");
await page.click("#pf-form button[type=submit]");
await page.waitForFunction(() => /Ada Lovelace/.test(document.querySelector("#c-who")?.textContent || ""), null, { timeout: 5000 }).catch(() => {});
check("Profile changes the name, and the header follows", /Ada Lovelace/.test(await text("#c-who")), await text("#c-who"));
await view("workbench", "#wb-input");

// ——————————————————————————————————————— 3. signing out closes the console
await page.click("#c-signout");
await page.waitForFunction(() => location.hash === "#/signin", null, { timeout: 5000 }).catch(() => {});
check("signing out lands on #/signin", (await hash()) === "#/signin", await hash());
await page.evaluate(() => { location.hash = "#/console/workbench"; });
await page.waitForFunction(() => location.hash === "#/signin", null, { timeout: 5000 }).catch(() => {});
check("the console sends a signed-out visitor to #/signin", (await hash()) === "#/signin", await hash());
const anonymous = await page.evaluate(async () => (await fetch("/api/cases", { credentials: "same-origin" })).status);
check("and the API agrees: the session is gone", anonymous === 401, String(anonymous));

// ——————————————————————————————————————— 4. signing in with the keyboard alone
await page.waitForSelector("#account-username", { timeout: 5000 });
check("the sign-in form takes the focus", await page.evaluate(() => document.activeElement && document.activeElement.id === "account-username"));
check("a server that sends no email offers no password reset", !(await page.$("#account-to-forgot")));
await page.evaluate(() => { location.hash = "#/forgot"; });
await page.waitForFunction(() => location.hash === "#/signin", null, { timeout: 5000 }).catch(() => {});
check("and its reset page leads back to sign-in", (await hash()) === "#/signin", await hash());
await page.waitForSelector("#account-username", { timeout: 5000 }).catch(() => {});
await page.focus("#account-username");
await page.keyboard.type("ada");
await page.keyboard.press("Tab");
await page.keyboard.type("not the password");
await page.keyboard.press("Enter");
await page.waitForFunction(() => !document.querySelector("#account-error").hidden, null, { timeout: 5000 }).catch(() => {});
check("a wrong password is refused, and the field says so", /wrong username or password/i.test(await text("#account-error")) &&
  (await page.getAttribute("#account-password", "aria-invalid")) === "true", await text("#account-error"));
check("the wrong password is cleared, and the focus is on it", await page.evaluate(() =>
  document.activeElement.id === "account-password" && document.activeElement.value === ""));
await page.keyboard.type(PASSWORD);
await page.keyboard.press("Enter");
await page.waitForFunction(() => location.hash.startsWith("#/console/"), null, { timeout: 8000 }).catch(() => {});
check("signing in returns to the page that sent the visitor away", (await hash()) === "#/console/workbench", await hash());

// ——————————————————————————————————————— 5. a member an admin made chooses their own password
const made = await page.evaluate(async (password) => {
  const csrf = (await (await fetch("/api/session", { credentials: "same-origin" })).json()).csrf;
  const response = await fetch("/api/users", {
    method: "POST", credentials: "same-origin",
    headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
    body: JSON.stringify({ username: "carl", display_name: "Carl", password })
  });
  return response.status;
}, PASSWORD);
check("the owner adds a member", made === 201, String(made));
await page.click("#c-signout");
await page.waitForFunction(() => location.hash === "#/signin", null, { timeout: 5000 }).catch(() => {});
await page.fill("#account-username", "carl");
await page.fill("#account-password", PASSWORD);
await page.click("#account-submit");
await page.waitForFunction(() => location.hash === "#/password", null, { timeout: 8000 }).catch(() => {});
check("a member with an admin-set password is sent to choose their own", (await hash()) === "#/password", await hash());
await page.fill("#account-current", PASSWORD);
await page.fill("#account-password", "carl's very own passphrase");
await page.click("#account-submit");
await page.waitForFunction(() => location.hash.startsWith("#/console/"), null, { timeout: 8000 }).catch(() => {});
check("and then reaches the console", (await hash()).startsWith("#/console/"), await hash());
check("as themselves", /Carl/.test(await text("#c-who")), await text("#c-who"));
check("an analyst's sidebar has only their own panes", await page.$$eval("#nav-workspace .nav-item",
  (items) => items.map((i) => i.dataset.pane).join(",")) === "audit,profile");
await page.evaluate(() => { location.hash = "#/console/settings"; });
await page.waitForSelector("#console-panels .empty-state", { timeout: 5000 }).catch(() => {});
check("and Settings, opened by its address, says only an admin can", /Only an admin/.test(await text("#console-panels")));

// ——————————————————————————————————————— 5b. someone new signs up for a workspace of their own
await page.click("#c-signout");
await page.waitForFunction(() => location.hash === "#/signin", null, { timeout: 5000 }).catch(() => {});
await page.waitForSelector("#account-to-signup", { timeout: 5000 }).catch(() => {});
check("the sign-in page offers sign-up while the owner allows it", await visible("#account-to-signup"));
await page.click("#account-to-signup");
await page.waitForSelector("#account-name", { timeout: 5000 }).catch(() => {});
check("sign-up asks who it is for, and starts at just me",
  (await page.isChecked('input[name="kind"][value="individual"]')) && (await page.isHidden("#account-org-field")));
await page.check('input[name="kind"][value="organization"]');
check("an organization is asked for its name", await page.isVisible("#account-organization"));
await page.check('input[name="kind"][value="individual"]');
await page.fill("#account-name", "Ivy");
await page.fill("#account-username", "ivy");
await page.fill("#account-password", PASSWORD);
await page.click("#account-submit");
await page.waitForFunction(() => location.hash.startsWith("#/console/"), null, { timeout: 8000 }).catch(() => {});
await page.waitForSelector("#c-who", { timeout: 5000 }).catch(() => {});
check("signing up opens the console, in a workspace of one's own",
  /Ivy/.test(await text("#c-who")) && /Ivy/.test(await text("#c-workspace")), await text("#c-who") + " / " + await text("#c-workspace"));
await view("activity", "#sv-cases .empty-state, #sv-cases table");
check("and the new workspace holds none of Acme's cases",
  (await page.$$eval("#sv-cases tbody tr", (rows) => rows.length)) === 0 && Boolean(await page.$("#sv-cases .empty-state")));

// ——————————————————————————————————————— 5c. an invitation, opened by the person it was made for
await page.click("#c-signout");
await page.waitForFunction(() => location.hash === "#/signin", null, { timeout: 5000 }).catch(() => {});
await page.goto(inviteLink);
await page.waitForFunction(() => /Join /.test(document.querySelector("#account-title")?.textContent || ""), null, { timeout: 8000 }).catch(() => {});
check("the invitation says whose workspace it opens, and as what",
  /Join Acme SOC/.test(await text("#account-title")) && /as an analyst/.test(await text(".account-lead")), await text("#account-title"));
await page.fill("#account-name", "Jo");
await page.fill("#account-username", "joan");
await page.fill("#account-password", PASSWORD);
await page.click("#account-submit");
await page.waitForFunction(() => location.hash.startsWith("#/console/"), null, { timeout: 8000 }).catch(() => {});
await page.waitForSelector("#c-who", { timeout: 5000 }).catch(() => {});
check("joining opens the console, in the inviting workspace", /Jo/.test(await text("#c-who")) && /Acme SOC/.test(await text("#c-workspace")),
  await text("#c-who") + " / " + await text("#c-workspace"));
/* asked from outside the page: a 404 in the page's own console would read as a script error */
const reused = (await fetch(ORIGIN + "/api/join/check", { method: "POST", headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ token: inviteLink.split("/join/")[1] }) })).status;
check("and the link no longer works", reused === 404, String(reused));

// ——————————————————————————————————————— 6. small screens and the whole run
await page.click("#c-signout");
await page.waitForFunction(() => location.hash === "#/signin", null, { timeout: 5000 }).catch(() => {});
for (const width of [320, 768, 1440]) {
  await page.setViewportSize({ width, height: 800 });
  await page.waitForTimeout(150);
  const fit = await page.evaluate(() => ({
    scroll: document.documentElement.scrollWidth, view: innerWidth,
    form: document.querySelector("#account-form").getBoundingClientRect().width
  }));
  check("the sign-in form fits at " + width + " px", fit.scroll <= fit.view && fit.form > 0, JSON.stringify(fit));
}
check("nothing was fetched from another host", outside.length === 0, outside.slice(0, 3).join(", "));
check("the page policy reported nothing", cspReports.length === 0, cspReports[0] || "");
check("no script errors, no dialogs", errors.length === 0, errors.slice(0, 3).join(" | "));

await browser.close();
console.log(failures ? `\n${failures} check(s) failed` : "\nall checks passed");
process.exit(failures ? 1 : 0);
