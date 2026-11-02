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

// ——————————————————————————————————————— 5. small screens and the whole run
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
