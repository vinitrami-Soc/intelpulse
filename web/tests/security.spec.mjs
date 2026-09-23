/* Browser security suite — the attacks from docs/SECURITY-AUDIT.md, kept.
 *
 * The workbench renders text from three places an attacker can reach: the log
 * an analyst pastes, the API it is pointed at (and every vendor behind it),
 * and whatever is already in this browser's storage. Every check below plays
 * one of those as hostile and asserts that nothing becomes markup, nothing
 * crashes, and nothing executes.
 *
 * Run:  python3 -m http.server 8123 --directory web   # one terminal
 *       node web/tests/security.spec.mjs              # another
 */
let chromium;
try {
  ({ chromium } = await import(process.env.PLAYWRIGHT_MODULE || "playwright"));
} catch (error) {
  console.error("Playwright is required for these tests: npm i -D playwright");
  process.exit(2);
}

const ROOT = (process.env.INTELPULSE_URL || "http://127.0.0.1:8123/") + "index.html";
const WB = ROOT + "#/console/workbench";
let failures = 0;
const check = (name, ok, detail) => {
  console.log((ok ? "PASS  " : "FAIL  ") + name + (detail ? "  — " + detail : ""));
  if (!ok) failures++;
};

const browser = await chromium.launch();
const outsideAll = [];
const MARK = (tag) => '"><i data-pwn="' + String(tag).replace(/"/g, "") + '">x</i><"';

/* A page that records what should never happen: an alert, an uncaught error,
   a request to somewhere that is not this site or the mocked API. */
async function openPage(options = {}) {
  const context = await browser.newContext({ viewport: { width: 1440, height: 1000 } });
  if (options.storage) {
    await context.addInitScript((entries) => {
      if (sessionStorage.getItem("__seeded")) return;
      for (const [k, v] of Object.entries(entries)) localStorage.setItem(k, v);
      sessionStorage.setItem("__seeded", "1");
    }, options.storage);
  }
  const page = await context.newPage();
  const seen = { dialogs: 0, errors: [], outside: [] };
  page.on("dialog", async (d) => { seen.dialogs++; await d.dismiss(); });
  page.on("pageerror", (e) => seen.errors.push(e.message));
  page.on("request", (r) => {
    const url = r.url();
    /* the CSP probe's image is aimed at evil.example on purpose; CSP must stop it */
    if (/^https:\/\/evil\.example\/pixel\.png/.test(url)) return;
    /* this site, the mocked API, the documented default API address, fonts */
    if (!/^(https?:\/\/127\.0\.0\.1|http:\/\/localhost:8000\/api\/|data:|blob:|https:\/\/fonts\.(googleapis|gstatic)\.com)/.test(url)) { seen.outside.push(url); outsideAll.push(url); }
  });
  await page.goto(options.url || WB, { waitUntil: "domcontentloaded" });
  if (!options.noWait) await page.waitForSelector("#wb-input", { timeout: 8000 });
  return { context, page, seen };
}
const injected = (page) => page.evaluate(() => {
  const found = [...document.querySelectorAll("[data-pwn]")].map((e) => e.getAttribute("data-pwn"));
  document.querySelectorAll("[data-pwn]").forEach((e) => e.remove());
  return found;
});

// ——————————— 1. every field of a real result, one at a time, made hostile
{
  const { context, page, seen } = await openPage();
  const out = await page.evaluate(async (MARKSRC) => {
    const MARK = new Function("tag", "return " + MARKSRC)();
    const E = window.IntelPulseEngine, DEMO = window.INTELPULSE_DEMO;
    const scen = DEMO.scenarios.find((s) => s.id === "firewall");
    const base = E.demoTriage(scen.text, DEMO, { title: "t", lists: [] });
    base.graph = E.buildGraph(base.indicators);
    base.diffs = base.indicators.map((i) => E.diffSnapshots(E.snapshotOf(i), E.snapshotOf(i),
      { value: i.value, previous_case_id: "c", previous_at: "2026-01-01T00:00:00Z" }));
    const paths = [];
    (function walk(o, path) {
      if (path.length) paths.push(path);
      if (o && typeof o === "object") for (const k of Object.keys(o)) walk(o[k], path.concat(k));
    })(base, []);
    const found = new Set(), crashed = [];
    let renders = 0;
    for (const path of paths) {
      const tag = path.join(".");
      let orig = base; for (const k of path) orig = orig[k];
      const variants = orig && typeof orig === "object"
        ? [null, "str", 7, Array.isArray(orig) ? {} : []]
        : [MARK(tag), null, 7, true, {}, [MARK(tag)]];
      for (const v of variants) {
        const copy = structuredClone(base);
        let o = copy; for (let i = 0; i < path.length - 1; i++) o = o[path[i]];
        o[path[path.length - 1]] = v;
        renders++;
        try {
          window.IntelPulse.render(copy);
          const g = document.querySelector("#wb-graph .wb-node");
          if (g) g.dispatchEvent(new PointerEvent("pointerover", { bubbles: true, pointerType: "mouse" }));
        } catch (e) { crashed.push(tag + ": " + e.message.slice(0, 60)); }
        document.querySelectorAll("[data-pwn]").forEach((el) => { found.add(el.getAttribute("data-pwn")); el.remove(); });
      }
    }
    return { paths: paths.length, renders, found: [...found], crashed };
  }, MARK.toString());
  check("no field of a result can inject markup", out.found.length === 0,
    out.renders + " hostile renders over " + out.paths + " fields" + (out.found.length ? "; injected via " + out.found.slice(0, 4).join(", ") : ""));
  check("no field of a result can crash the view", out.crashed.length === 0,
    out.crashed.slice(0, 3).join(" | ") || "0 crashes");
  check("the fuzz raised no uncaught errors and no dialogs", seen.errors.length === 0 && seen.dialogs === 0,
    seen.errors[0] || "");
  await context.close();
}

// ——————————— 2. a hostile API: every response, every field
{
  const { context, page, seen } = await openPage();
  let authSeen = null, tokenInUrl = false;
  await page.route("**/api/**", async (route) => {
    const url = route.request().url();
    authSeen = route.request().headers()["authorization"] || authSeen;
    if (url.includes("hostile-token-123")) tokenInUrl = true;
    const json = (body, status = 200) => route.fulfill({ status, contentType: "application/json", body: JSON.stringify(body) });
    if (url.includes("/api/health")) {
      return json({ status: MARK("h.status"), database: MARK("h.db"), cache: { backend: MARK("h.cache"), hit_rate: MARK("h.rate") },
        providers: [{ name: MARK("h.p.name"), configured: MARK("h.p.conf") }, { name: 7, configured: true }, null, "junk"] });
    }
    if (url.includes("/api/extract")) {
      return json({ indicators: [{ type: MARK("x.type"), value: MARK("x.value") }, null, 7], count: MARK("x.count") });
    }
    if (url.includes("/api/cases") && route.request().method() === "GET") {
      return json([{ id: MARK("c.id"), title: MARK("c.title"), verdict: MARK("c.verdict"), max_score: MARK("c.score"),
        indicator_count: MARK("c.n"), created_at: MARK("c.at") }, null, 7]);
    }
    if (url.includes("/ticket")) return json({ sink: "jira", key: MARK("t.key"), url: "javascript:alert(document.domain)" });
    if (url.includes("/api/triage")) {
      return json(await page.evaluate((MARKSRC) => {
        const MARK = new Function("tag", "return " + MARKSRC)();
        const EN = window.IntelPulseEngine, DEMO = window.INTELPULSE_DEMO;
        const r = EN.demoTriage(DEMO.scenarios[0].text, DEMO, { title: "t", lists: [] });
        r.graph = EN.buildGraph(r.indicators);
        /* every string at once, and every number as markup */
        (function walk(o, path) {
          for (const k of Object.keys(o)) {
            if (o[k] && typeof o[k] === "object") walk(o[k], path.concat(k));
            else if (typeof o[k] === "string" || typeof o[k] === "number") o[k] = MARK(path.concat(k).join("."));
          }
        })(r, []);
        return r;
      }, MARK.toString()));
    }
    return json({ detail: MARK("detail") }, 500);
  });
  await page.click('button[data-mode="live"]');
  await page.fill("#wb-api", "http://127.0.0.1:9999");
  await page.fill("#wb-token", "hostile-token-123");
  await page.click('[data-act="connect"]');
  await page.waitForTimeout(500);
  const afterHealth = await injected(page);
  await page.fill("#wb-input", "185.220.101.34 evil.example.com");
  await page.click('[data-act="preview"]');
  await page.waitForTimeout(400);
  const afterPreview = await injected(page);
  await page.click("#wb-run");
  await page.waitForTimeout(1500);
  const graphNode = await page.$("#wb-graph .wb-node");
  if (graphNode) await graphNode.dispatchEvent("pointerover", { pointerType: "mouse" });
  await page.waitForTimeout(200);
  const afterTriage = await injected(page);
  const links = await page.evaluate(() => [...document.querySelectorAll("#console-panels a")].map((a) => a.getAttribute("href")));
  check("a hostile health response stays text", afterHealth.length === 0, afterHealth.join(", "));
  check("a hostile extract response stays text", afterPreview.length === 0, afterPreview.join(", "));
  check("a result that is hostile in every field at once stays text", afterTriage.length === 0, afterTriage.slice(0, 4).join(", "));
  check("no javascript: link survives a hostile API", links.every((h) => h && /^https?:/i.test(h)), links.length + " links");
  check("the token rides in the Authorization header", authSeen === "Bearer hostile-token-123", String(authSeen));
  check("and never in a URL", !tokenInUrl);
  const stored = await page.evaluate(() => ({
    local: Object.keys(localStorage).some((k) => (localStorage.getItem(k) || "").includes("hostile-token-123")),
    session: sessionStorage.getItem("intelpulse:apiToken")
  }));
  check("the token is kept for the tab only, never in localStorage", !stored.local && stored.session === "hostile-token-123");
  check("a hostile API raises no uncaught errors or dialogs", seen.errors.length === 0 && seen.dialogs === 0, seen.errors[0] || "");
  await context.close();
}

// ——————————— 3. poisoned browser storage
{
  const poison = {
    "intelpulse:history": JSON.stringify([{ case_id: MARK("s.id"), title: MARK("s.title"), verdict: MARK("s.verdict"),
      score: MARK("s.score"), indicator_count: MARK("s.n"), created_at: MARK("s.at") }, null, 7, "junk"]),
    "intelpulse:lists": JSON.stringify({ not: "an array" }),
    "intelpulse:snapshots": '{"__proto__": {"polluted": true}, "185.220.101.34": "junk"}',
    "intelpulse:mode": JSON.stringify(MARK("s.mode")),
    "intelpulse:apiBase": JSON.stringify("javascript:alert(1)"),
    "intelpulse:theme": JSON.stringify(MARK("s.theme"))
  };
  const { context, page, seen } = await openPage({ storage: poison });
  const first = await injected(page);
  await page.click('.wb-starter[data-scenario="firewall"]');
  await page.waitForTimeout(1200);
  const polluted = await page.evaluate(() => ({}).polluted === true || Object.prototype.polluted === true);
  const afterRun = await injected(page);
  const fine = await page.evaluate(() => document.querySelector("#wb-hero")?.textContent);
  check("poisoned history, lists, snapshots and settings stay text", first.length === 0 && afterRun.length === 0,
    first.concat(afterRun).join(", "));
  check("poisoned storage cannot pollute Object.prototype", !polluted);
  check("the workbench still works on poisoned storage", fine === "95" && seen.errors.length === 0,
    "hero " + fine + (seen.errors[0] ? "; " + seen.errors[0] : ""));
  check("a javascript: API address from storage is never used", await page.evaluate(() =>
    !document.querySelector("#wb-api") || !/^javascript:/i.test(document.querySelector("#wb-api").value)));
  await context.close();
}

// ——————————— 4. the address bar
{
  for (const hash of ["#/console/<img src=x onerror=alert(1)>", '#/console/workbench"><i data-pwn="hash">', "#/console/__proto__", "#javascript:alert(1)"]) {
    const { context, page, seen } = await openPage({ url: ROOT + hash, noWait: true });
    await page.waitForTimeout(700);
    const hit = await injected(page);
    check("the route " + hash.slice(0, 34) + " renders nothing from itself", hit.length === 0 && seen.dialogs === 0 && seen.errors.length === 0,
      seen.errors[0] || "");
    await context.close();
  }
  const { context, page } = await openPage({ url: (process.env.INTELPULSE_URL || "http://127.0.0.1:8123/") + "workbench.html?next=https://evil.example", noWait: true });
  await page.waitForTimeout(900);
  check("the old workbench address redirects only into the console", /index\.html#\/console\/workbench$/.test(page.url()), page.url());
  await context.close();
}

// ——————————— 5. the policy the page runs under
{
  const { context, page } = await openPage();
  /* eval has to be tried from a script the page loaded itself: code sent in
     through DevTools is exempt from CSP, and an earlier version of this check
     "found" eval allowed that way. A same-origin URL is what script-src 'self'
     admits, so the probe is served from one. */
  await page.route("**/__csp-probe.js", (route) => route.fulfill({
    contentType: "application/javascript",
    body: "try { eval('1'); window.__evalRan = true; } catch (_) {}" +
          "try { new Function('return 1')(); window.__fnRan = true; } catch (_) {}" +
          "window.__probeLoaded = true;"
  }));
  await page.addScriptTag({ url: "/__csp-probe.js" });
  await page.waitForFunction(() => window.__probeLoaded === true);
  const probe = await page.evaluate(() => ({ evalRan: Boolean(window.__evalRan), fnRan: Boolean(window.__fnRan) }));
  const csp = await page.evaluate(async () => {
    const violations = [];
    document.addEventListener("securitypolicyviolation", (e) => violations.push(e.violatedDirective));
    const s = document.createElement("script");
    s.textContent = "window.__inlineRan = true";
    document.body.appendChild(s);
    const b = document.createElement("button");
    b.setAttribute("onclick", "window.__handlerRan = true");
    document.body.appendChild(b); b.click(); b.remove();
    const img = document.createElement("img");
    img.src = "https://evil.example/pixel.png";
    document.body.appendChild(img); img.remove();
    await new Promise((r) => setTimeout(r, 300));
    return { inline: Boolean(window.__inlineRan), handler: Boolean(window.__handlerRan), violations };
  });
  check("an injected inline script does not run", !csp.inline);
  check("an injected event-handler attribute does not run", !csp.handler);
  check("eval and new Function are refused to the page's own scripts", !probe.evalRan && !probe.fnRan, JSON.stringify(probe));
  check("an injected image cannot call out to another host", csp.violations.some((v) => /img-src/.test(v)), csp.violations.join(", "));
  const tabnab = await page.evaluate(async () => {
    location.hash = "#/home";
    await new Promise((r) => setTimeout(r, 400));
    return [...document.querySelectorAll('a[target="_blank"]')].filter((a) => !/noopener/.test(a.rel || "")).map((a) => a.href);
  });
  check("every link that opens a tab cuts the opener", tabnab.length === 0, tabnab.join(", "));
  await context.close();
}

// ——————————— 6. a paste built to make the extractor backtrack
{
  const { context, page, seen } = await openPage();
  const took = await page.evaluate(() => {
    const E = window.IntelPulseEngine;
    const started = performance.now();
    for (const text of ["a.".repeat(95000), "1.".repeat(95000), "CVE-".repeat(47500)]) E.extract(text);
    return Math.round(performance.now() - started);
  });
  check("a 190,000-character pathological paste does not freeze the tab", took < 3000, took + " ms for three");
  await context.close();
}
check("no page in this suite called out to an unexpected host", outsideAll.length === 0, outsideAll.slice(0, 3).join(", "));

await browser.close();
console.log(failures ? `\n${failures} check(s) failed` : "\nall checks passed");
process.exit(failures ? 1 : 0);
