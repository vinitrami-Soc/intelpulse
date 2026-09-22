/* Browser tests for the analyst workbench and the campaign graph: security
 * behaviour and the interactions that make them usable.
 *
 * These are the checks unit tests cannot make — that attacker-controlled log
 * text never becomes DOM, that a hostile provider response cannot inject a
 * javascript: link, that a slow or dead backend degrades instead of freezing,
 * and that the evidence, the dialog, the graphs and the diffs actually work in
 * a real browser.
 *
 * Both are views inside the console on index.html (#/console/workbench and
 * #/console/campaigns); the site and the rest of the console are covered by
 * suite.spec.mjs. They used to be separate pages, workbench.html and
 * explorer.html, which are now redirects. What that move retired, and why, is
 * written down at the end of this file.
 *
 * Run:  python3 -m http.server 8123 --directory web   # one terminal
 *       node web/tests/ui.spec.mjs                    # another
 * Needs Playwright with Chromium available.
 */
let chromium;
try {
  // PLAYWRIGHT_MODULE lets a globally installed Playwright be used without
  // adding a node_modules tree to a project that otherwise has no build step.
  ({ chromium } = await import(process.env.PLAYWRIGHT_MODULE || "playwright"));
} catch (error) {
  console.error("Playwright is required for these tests: npm i -D playwright");
  console.error("(or set PLAYWRIGHT_MODULE to an installed copy)");
  process.exit(2);
}

const ROOT = (process.env.INTELPULSE_URL || "http://127.0.0.1:8123/") + "index.html";
const WB = ROOT + "#/console/workbench";
const CG = ROOT + "#/console/campaigns";
let failures = 0;
const check = (name, ok, detail) => {
  console.log((ok ? "PASS  " : "FAIL  ") + name + (detail ? "  — " + detail : ""));
  if (!ok) failures++;
};

const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
let alerted = false;
page.on("dialog", async (d) => { alerted = true; await d.dismiss(); });
const errors = [];
page.on("pageerror", (e) => errors.push(e.message));

/* The console paints its header first and fills the pane on the next frame,
   so wait for the pane's own element rather than for the load event. */
async function openWorkbench(target = page) {
  await target.goto(WB, { waitUntil: "domcontentloaded" });
  await target.waitForSelector("#wb-input", { timeout: 8000 });
}
async function starter(target, id) {
  await target.click('.wb-starter[data-scenario="' + id + '"]');   // a starter loads and runs
  await target.waitForSelector("#wb-results:not([hidden]) .wb-ioc", { timeout: 8000 });
  await target.waitForTimeout(700);                                // let the counters land
}

await openWorkbench();

// ——————————————————————————————————— 1. XSS from a pasted log
const payload = `Sep 18 02:14 fw01: SRC=203.0.113.10 <script>window.__pwned=1;alert(1)</script>
<img src=x onerror="window.__pwned2=1">
"><svg/onload=alert(2)> javascript:alert(3)
hxxp://evil[.]example[.]com/"><script>alert(4)</script>`;
await page.fill("#wb-input", payload);
await page.click("#wb-run");
await page.waitForTimeout(900);

const xss = await page.evaluate(() => {
  const pane = document.querySelector("#console-panels");
  return {
    pwned: Boolean(window.__pwned || window.__pwned2),
    scriptTags: pane.querySelectorAll("script").length,
    imgTags: pane.querySelectorAll("img").length,
    hrefs: Array.from(pane.querySelectorAll("a")).map((a) => a.getAttribute("href")),
    rendered: document.querySelector("#wb-results").textContent.includes("<script>")
  };
});
check("attacker-controlled log text never executes", !xss.pwned && !alerted);
check("no script or img element is injected from log text", xss.scriptTags === 0 && xss.imgTags === 0);
check("the payload is rendered as visible text", xss.rendered);
check("only https vendor links survive", xss.hrefs.every((h) => h.startsWith("https://")), xss.hrefs.length + " links");

/* The console's toast used to take markup. The workbench toasts indicator
   values, which come out of pasted logs, so it takes text now. */
const toastMarkup = await page.evaluate(() => {
  const value = '<img src=x id="toast-injected">';
  const button = document.createElement("button");
  button.dataset.list = "block"; button.dataset.value = value; button.dataset.type = "domain";
  document.querySelector("#wb-iocs").appendChild(button);
  button.click();
  button.remove();
  return { injected: Boolean(document.querySelector("#toast-injected")),
    shown: document.querySelector("#toast").textContent.includes(value) };
});
check("a toast shows an indicator as text, not markup", !toastMarkup.injected && toastMarkup.shown,
  JSON.stringify(toastMarkup));

// —————————————————————————— 2. hostile provider response / URL schemes
const badHref = await page.evaluate(() => {
  const fake = {
    case_id: "x", title: "t", verdict: "high", score: 80, duration_ms: 1, summary: "", cache_hits: 0,
    indicators: [{
      value: "1.2.3.4", type: "ip", score: 80, verdict: "high", confidence: 0.8,
      evidence: [], modifiers: [], tags: [], malware_families: [],
      providers_queried: 1, providers_answered: 1,
      attack_techniques: [{ id: "T1", name: "x", tactic: "y", url: "javascript:alert(9)" }],
      containment: [],
      sources: [{ provider: "p", label: "p", status: "ok", facts: {}, signals: [], relations: [], reference: "javascript:alert(8)" }]
    }],
    graph: { nodes: [], edges: [] }, mode: "demo"
  };
  window.IntelPulse.render(fake);
  return Array.from(document.querySelectorAll("#wb-results a")).map((a) => a.getAttribute("href"));
});
check("javascript: URLs from a provider response are dropped", badHref.length === 0, JSON.stringify(badHref));

const schemes = await page.evaluate(() =>
  ["javascript:alert(1)", "data:text/html,<script>", "vbscript:x", " javascript:alert(1)",
   "JaVaScRiPt:alert(1)", "https://otx.alienvault.com/x", "http://localhost:8000/y"]
    .map((u) => [u, window.IntelPulse.safeUrl(u)]));
check("safeUrl rejects every non-http(s) scheme",
  schemes.filter(([u]) => !u.startsWith("http")).every(([, out]) => out === null));
check("safeUrl keeps ordinary vendor links",
  schemes.filter(([u]) => u.startsWith("http")).every(([, out]) => out !== null));

// ———————————————————————————— 3. a dead backend degrades, never freezes
await page.click('button[data-mode="live"]');
await page.waitForTimeout(250);
await page.route("**/api/**", async (route) => {
  await new Promise((r) => setTimeout(r, 2500));
  await route.abort();
});
await page.fill("#wb-api", "http://127.0.0.1:9999");
await page.click('[data-act="connect"]');
await page.fill("#wb-input", "8.8.8.8 1.1.1.1");
await page.click("#wb-run");
await page.waitForTimeout(600);
const loading = await page.evaluate(() => ({
  bones: document.querySelectorAll("#wb-kpis .sk").length,
  button: document.querySelector("#wb-run").textContent.trim()
}));
check("skeleton placeholders render while sources are queried", loading.bones >= 1, loading.bones + " placeholders");
check("the run button reports in-flight state", /Triaging/.test(loading.button), loading.button);

await page.waitForTimeout(3200);
const recovered = await page.evaluate(() => ({
  toast: document.querySelector("#toast").textContent,
  button: document.querySelector("#wb-run").textContent.trim(),
  disabled: document.querySelector("#wb-run").disabled,
  inline: document.querySelector("#wb-error").hidden ? "" : document.querySelector("#wb-error").textContent
}));
check("a dead backend degrades with a message, not a freeze",
  !recovered.disabled && /run triage/i.test(recovered.button) && /failed/i.test(recovered.toast),
  recovered.toast);
check("the failure is also written next to the box, where it stays", /did not complete/i.test(recovered.inline),
  recovered.inline.slice(0, 70));
await page.unroute("**/api/**");
await page.click('button[data-mode="demo"]');

// ————————————————————————————————————————— 4. a real triage
await starter(page, "firewall");
const result = await page.evaluate(() => ({
  hero: document.querySelector("#wb-hero")?.textContent,
  bars: document.querySelectorAll("#wb-iocs .bar-row").length,
  barWidths: Array.from(document.querySelectorAll("#wb-iocs .bar-fill")).map((f) => Math.round(f.getBoundingClientRect().width)),
  meters: document.querySelectorAll("#wb-results .meter").length,
  coverage: document.querySelectorAll("#wb-results .coverage i").length,
  badges: Array.from(document.querySelectorAll(".wb-ioc .wb-badge")).map((b) => b.textContent.trim())
}));
check("the hero figure lands on the case score", result.hero === "95", "got " + result.hero);
check("evidence contribution bars render with real widths",
  result.bars > 0 && result.barWidths.some((w) => w > 40) && new Set(result.barWidths).size > 2,
  result.bars + " bars");
check("meters and the coverage strip render", result.meters >= 2 && result.coverage > 0,
  result.meters + " meters, " + result.coverage + " coverage cells");
check("every severity badge carries its label, not just a colour",
  result.badges.length > 0 && result.badges.every((b) => /critical|high|medium|low|informational|allowlisted/i.test(b)));
check("the run lands in the history list",
  await page.evaluate(() => document.querySelector("#wb-history").textContent.includes("95")));

// ——————————————————————————————— 5. the chart has a table equivalent
await page.click("#wb-iocs [data-table-toggle]");
await page.waitForTimeout(200);
check("the chart offers a table view (WCAG-clean equivalent)",
  await page.evaluate(() => {
    const table = document.querySelector("#wb-iocs .chart .table-view");
    return table && !table.hasAttribute("hidden") && table.querySelectorAll("tbody tr").length > 0;
  }));
await page.click("#wb-iocs [data-table-toggle]");

// ————————————————————————————— 6. the scoring math, in a real dialog
await page.click("[data-math]");
await page.waitForTimeout(350);
const math = await page.evaluate(() => ({
  open: document.querySelector("#wb-dialog").open,
  title: document.querySelector("#wb-dialog-title").textContent,
  body: document.querySelector("#wb-dialog-body").textContent,
  focus: document.activeElement.getAttribute("data-act"),
  columns: [...document.querySelectorAll("#wb-dialog .wb-math th")].map((th) => {
    const r = th.getBoundingClientRect(), box = document.querySelector("#wb-dialog").getBoundingClientRect();
    return r.right <= box.right + 1;
  })
}));
check("the scoring math shows the actual arithmetic",
  math.open && /Scoring math/.test(math.title) && /weighted mean/.test(math.body) && /authority floor/.test(math.body));
check("every column of the arithmetic fits the dialog", math.columns.length === 6 && math.columns.every(Boolean),
  math.columns.filter(Boolean).length + " of " + math.columns.length);
check("the dialog takes focus on its close button", math.focus === "close-dialog", String(math.focus));
await page.keyboard.press("Escape");
await page.waitForTimeout(250);
const closed = await page.evaluate(() => ({
  open: document.querySelector("#wb-dialog").open,
  back: document.activeElement.hasAttribute("data-math")
}));
check("Escape closes it and focus returns to what opened it", !closed.open && closed.back, JSON.stringify(closed));

// ————————————————————————————— 7. the investigation graph
const graph = await page.evaluate(() => {
  const nodes = [...document.querySelectorAll("#wb-graph .wb-node")];
  const at = nodes.map((n) => (n.getAttribute("transform").match(/translate\(([-\d.]+),([-\d.]+)\)/) || []).slice(1).map(Number));
  let closest = Infinity;
  for (let i = 0; i < at.length; i++) for (let j = i + 1; j < at.length; j++) {
    closest = Math.min(closest, Math.hypot(at[i][0] - at[j][0], at[i][1] - at[j][1]));
  }
  const text = document.querySelector("#wb-graph .wb-node text");
  return {
    nodes: nodes.length,
    strayText: [...document.querySelectorAll("#wb-graph svg text")].filter((t) => !t.closest(".wb-node")).length,
    named: nodes.filter((n) => / — /.test(n.querySelector("title")?.textContent || "")).length,
    closest: Math.round(closest),
    halo: text ? getComputedStyle(text).paintOrder : "",
    table: document.querySelectorAll("#wb-graph details li").length
  };
});
check("it plots the investigation", graph.nodes > 3, graph.nodes + " nodes");
check("no edge shouts its name until you ask", graph.strayText === 0, graph.strayText + " edge labels");
check("hovering a node names its relationships", graph.named > 0, graph.named + " nodes carry them");
check("no two nodes sit on top of each other", graph.closest >= 40, graph.closest + " units apart at the closest");
check("labels carry a halo so they survive an edge", /stroke/.test(graph.halo), graph.halo);
check("the graph has a text equivalent", graph.table > 0, graph.table + " relationships listed");

await page.focus("#wb-graph .wb-node.ioc");
await page.keyboard.press("Enter");
await page.waitForTimeout(400);
check("a graph node opens that indicator's evidence from the keyboard",
  await page.evaluate(() => {
    const value = document.querySelector("#wb-graph .wb-node.ioc").dataset.node.replace(/^ioc:/, "");
    const card = [...document.querySelectorAll(".wb-ioc")].find((c) => c.dataset.ioc === value);
    return Boolean(card) && card.querySelector(".wb-ioc-top").getAttribute("aria-expanded") === "true";
  }));

// ————————————————————————————— 8. accessibility & layout
const a11y = await page.evaluate(() => ({
  skip: Boolean(document.querySelector("a.skip")),
  /* hidden ones included would count the ticket button, empty until a sink is
     configured and hidden from everyone, assistive tech too, until then */
  labelled: [...document.querySelectorAll("#console-panels button")].filter((b) => !b.closest("[hidden]"))
    .every((b) => b.textContent.trim() || b.getAttribute("aria-label")),
  dialog: Boolean(document.querySelector('#wb-dialog[role="dialog"][aria-modal="true"]')),
  live: Boolean(document.querySelector("#toast[aria-live]")),
  alert: Boolean(document.querySelector('#wb-error[role="alert"]')),
  expanded: Boolean(document.querySelector(".wb-ioc-top[aria-expanded]"))
}));
check("skip link, labelled buttons, modal roles and live regions exist",
  Object.values(a11y).every(Boolean), JSON.stringify(a11y));

await page.keyboard.press("Control+Enter");
check("Ctrl+Enter outside the box does not run anything", !(await page.evaluate(() =>
  document.querySelector("#wb-run").hasAttribute("aria-busy"))));

const still = await browser.newPage({ viewport: { width: 1440, height: 1000 }, reducedMotion: "reduce" });
await openWorkbench(still);
await still.click('.wb-starter[data-scenario="firewall"]');
await still.waitForTimeout(250);
check("reduced motion is honoured (the hero figure is final, not tweening)",
  (await still.evaluate(() => document.querySelector("#wb-hero").textContent)) === "95");
await still.close();

for (const width of [390, 768, 1024, 1440]) {
  await page.setViewportSize({ width, height: 900 });
  await page.waitForTimeout(300);
  const overflow = await page.evaluate(() =>
    document.documentElement.scrollWidth - document.documentElement.clientWidth);
  check("no horizontal overflow at " + width + "px", overflow <= 0, "overflow " + overflow + "px");
}
await page.setViewportSize({ width: 1440, height: 1000 });

// ——————————————— 9. deep links, the pane lifecycle, undo, long input
const fresh = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
await openWorkbench(fresh);
check("the workbench can be linked to directly",
  await fresh.evaluate(() => [...document.querySelectorAll("#console-body h3")]
    .some((h) => h.textContent.includes("Analyst workbench"))));
await fresh.fill("#wb-input", "203.0.113.10 draft that should survive");
await fresh.click('#side-nav-full .nav-item[data-pane="campaigns"]');
await fresh.waitForSelector("#cg-svg");
const away = await fresh.evaluate(() => ({ hash: location.hash, hook: "IntelPulse" in window }));
check("picking the graph in the sidebar puts it in the address bar", away.hash === "#/console/campaigns", away.hash);
check("leaving the workbench unmounts it", !away.hook);
await fresh.click('#side-nav-full .nav-item[data-pane="workbench"]');
await fresh.waitForSelector("#wb-input");
check("a draft survives a trip to another view",
  (await fresh.inputValue("#wb-input")) === "203.0.113.10 draft that should survive");
check("and the address bar follows", (await fresh.evaluate(() => location.hash)) === "#/console/workbench");
await fresh.reload({ waitUntil: "domcontentloaded" });
check("the workbench survives a reload", Boolean(await fresh.waitForSelector("#wb-input", { timeout: 8000 })));
await fresh.close();

await page.fill("#wb-input", "203.0.113.10 is the one to check");
const before = await page.inputValue("#wb-input");
await page.click('[data-act="clear"]');
await page.waitForTimeout(300);
check("clearing offers an undo rather than a confirmation dialog",
  await page.isVisible('[data-act="undo"]'));
await page.click('[data-act="undo"]');
await page.waitForTimeout(300);
check("undo restores the cleared input", (await page.inputValue("#wb-input")) === before);

const manyIocs = Array.from({ length: 60 }, (_, i) => `185.220.${Math.floor(i / 256)}.${i + 1}`).join(" ");
await page.fill("#wb-input", manyIocs);
await page.click("#wb-run");
await page.waitForTimeout(1200);
const paging = await page.evaluate(() => ({
  cards: document.querySelectorAll(".wb-ioc").length,
  more: Boolean(document.querySelector('[data-act="show-all"]'))
}));
check("a long list pages instead of rendering everything at once",
  paging.cards <= 25 && paging.more, paging.cards + " cards");
await page.click('[data-act="show-all"]');
await page.waitForTimeout(500);
check("show-all expands the full list",
  (await page.evaluate(() => document.querySelectorAll(".wb-ioc").length)) > 25);

// ————————————————— 10. component states: error, busy, touch, contrast
await page.fill("#wb-input", "");
await page.click("#wb-run");
await page.waitForTimeout(300);
const emptyError = await page.evaluate(() => ({
  invalid: document.querySelector("#wb-input").getAttribute("aria-invalid"),
  shown: !document.querySelector("#wb-error").hidden,
  message: document.querySelector("#wb-error").textContent,
  describedBy: document.querySelector("#wb-input").getAttribute("aria-describedby") || "",
  focused: document.activeElement.id
}));
check("an empty run reports inline, on the field, not in a toast",
  emptyError.invalid === "true" && emptyError.shown && emptyError.message.length > 10);
check("the error is announced and the field takes focus",
  emptyError.describedBy.split(/\s+/).includes("wb-error") && emptyError.focused === "wb-input",
  emptyError.describedBy + " / " + emptyError.focused);

await page.fill("#wb-input", "8.8.8.8");
await page.waitForTimeout(200);
check("typing clears the error state",
  (await page.evaluate(() => document.querySelector("#wb-input").getAttribute("aria-invalid"))) === null);

await page.fill("#wb-input", "no indicators in this sentence at all");
await page.click("#wb-run");
await page.waitForTimeout(700);
check("an input with nothing routable explains why",
  await page.evaluate(() => !document.querySelector("#wb-error").hidden &&
    /routable/i.test(document.querySelector("#wb-error").textContent)));

await page.click('button[data-mode="live"]');
await page.waitForTimeout(250);
await page.fill("#wb-api", "not-a-url");
await page.click('[data-act="connect"]');
await page.waitForTimeout(250);
check("a malformed backend URL is rejected at the field",
  await page.evaluate(() => document.querySelector("#wb-api").getAttribute("aria-invalid") === "true" &&
    !document.querySelector("#wb-api-error").hidden && document.activeElement.id === "wb-api"));
await page.fill("#wb-api", "http://localhost:8000");
await page.click('button[data-mode="demo"]');

/* The run button must report busy and then recover. A demo triage finishes in
   about a millisecond, so this watches the attribute rather than sampling it. */
const busySeen = await page.evaluate(() => new Promise((resolve) => {
  const button = document.querySelector("#wb-run");
  const records = [];
  // Read the records, not the live attribute: by the time the callback runs the
  // attribute may already have been removed again.
  const observer = new MutationObserver((list) =>
    list.forEach((record) => records.push(record.oldValue)));
  observer.observe(button, { attributes: true, attributeOldValue: true, attributeFilter: ["aria-busy"] });
  document.querySelector("#wb-input").value = "203.0.113.10";
  button.click();
  setTimeout(() => {
    observer.disconnect();
    resolve({ seen: records.length >= 2 && records[0] === null, after: button.getAttribute("aria-busy") });
  }, 900);
}));
check("the run button carries aria-busy while in flight and clears it after",
  busySeen.seen && busySeen.after === null, JSON.stringify(busySeen));

await page.fill("#wb-input", "203.0.113.10");
await page.focus("#wb-input");
await page.keyboard.press("Control+Enter");
await page.waitForTimeout(500);
check("Ctrl+Enter in the box runs the triage",
  await page.evaluate(() => document.querySelector(".wb-ioc")?.dataset.ioc === "203.0.113.10"));

// touch targets on a coarse pointer, both views
/* Graph nodes are held to WCAG 2.5.8's 24px minimum rather than the 44px
   used for every other control: at 44 a node's target would overlap its
   neighbours'. Nothing is lost by it: an indicator's card and a cluster's row
   in the table carry the same information at full size. */
const touch = await browser.newPage({ viewport: { width: 414, height: 896 }, hasTouch: true, isMobile: true });
await openWorkbench(touch);
await starter(touch, "firewall");
const targets = () => touch.evaluate(() => {
  const sized = (list) => Array.from(document.querySelectorAll(list))
    .filter((el) => !el.closest("[hidden]") && el.getClientRects().length)
    .map((el) => ({ what: (el.getAttribute("aria-label") || el.textContent || el.id || el.tagName).trim().slice(0, 24),
      h: Math.round(el.getBoundingClientRect().height), w: Math.round(el.getBoundingClientRect().width) }));
  const nodes = ".wb-node.ioc, .cg-node[tabindex]";
  return {
    controls: sized("#console-panels button, #console-panels input:not([type=file]), #console-panels select")
      .filter((el) => el.h < 44),
    nodes: sized(nodes).filter((el) => Math.min(el.h, el.w) < 24)
  };
});
const wbTargets = await targets();
check("every workbench control clears 44px on a touch device", wbTargets.controls.length === 0,
  wbTargets.controls.slice(0, 4).map((e) => e.what + " " + e.h + "px").join(", "));
check("every graph node clears the 24px minimum", wbTargets.nodes.length === 0,
  wbTargets.nodes.slice(0, 4).map((e) => e.what + " " + Math.min(e.h, e.w) + "px").join(", "));
await touch.goto(CG, { waitUntil: "domcontentloaded" });
await touch.waitForSelector("#cg-svg .cg-node");
const cgTargets = await targets();
check("every campaign-graph control clears 44px on a touch device", cgTargets.controls.length === 0,
  cgTargets.controls.slice(0, 4).map((e) => e.what + " " + e.h + "px").join(", "));
check("every campaign cluster clears the 24px minimum", cgTargets.nodes.length === 0,
  cgTargets.nodes.slice(0, 4).map((e) => e.what + " " + Math.min(e.h, e.w) + "px").join(", "));
/* As a sideways scroller the year control showed 2016 to 2020 on a phone and
   hid the year that was selected. Every year has to be on screen. */
const years = await touch.evaluate(() => [...document.querySelectorAll("[data-year]")].map((el) => {
  const r = el.getBoundingClientRect();
  return { year: el.dataset.year, on: r.left >= 0 && r.right <= document.documentElement.clientWidth };
}));
check("on a phone every year is on screen, the selected one included",
  years.length === 9 && years.every((y) => y.on), years.filter((y) => !y.on).map((y) => y.year).join(", ") || "all 9");
await touch.close();

// ———————————————————————— forced colours (Windows High Contrast)
const hc = await browser.newPage({ viewport: { width: 1280, height: 900 }, forcedColors: "active" });
await openWorkbench(hc);
await starter(hc, "firewall");
const contrast = await hc.evaluate(() => {
  const outlined = (el) => {
    const cs = getComputedStyle(el);
    return cs.borderTopWidth !== "0px" || cs.outlineWidth !== "0px";
  };
  const visible = (list) => Array.from(document.querySelectorAll(list)).filter((el) => el.getClientRects().length);
  return {
    bars: visible("#wb-iocs .bar-fill").every(outlined),
    badges: visible(".wb-badge").every(outlined),
    cards: visible(".wb-ioc").every(outlined)
  };
});
check("meaning survives forced-colors mode (fills keep an outline)",
  contrast.bars && contrast.badges && contrast.cards, JSON.stringify(contrast));
await hc.close();

check("no uncaught page errors in the workbench", errors.length === 0, errors.slice(0, 2).join(" | "));

/* ——————————————————————————————————————— 11. the campaign graph
 * The standalone graph needed Cytoscape from a CDN and fell back to a second
 * renderer without it, so the tests ran one path and laptops took the other.
 * The console view is plain SVG: there is one path, and this is it.
 */
{
  const cg = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
  const cgErrors = [];
  cg.on("pageerror", (e) => cgErrors.push(e.message));
  await cg.goto(CG, { waitUntil: "domcontentloaded" });
  await cg.waitForSelector("#cg-svg .cg-node");
  await cg.waitForTimeout(300);

  const state = () => cg.evaluate(() => ({
    nodes: document.querySelectorAll("#cg-svg .cg-node").length,
    labels: document.querySelectorAll("#cg-svg .cg-labels text").length,
    rows: document.querySelectorAll("#cg-table tbody tr").length,
    kpi: document.querySelector("#cg-kpis .val")?.textContent.trim(),
    sev: document.querySelector("#cg-sev").textContent.trim(),
    /* every cluster's position and size: the hub sits in the middle in both
       layouts, so one node alone cannot tell them apart */
    first: [...document.querySelectorAll("#cg-svg .cg-node:not(.child) circle")]
      .map((c) => c.getAttribute("cx") + "/" + c.getAttribute("r")).join(" ")
  }));
  const start = await state();
  check("the campaign graph plots its clusters", start.nodes > 20 && start.rows > 10,
    start.nodes + " nodes, " + start.rows + " clusters in the table");
  check("its headline figure is counted from the data on screen", String(start.rows) === start.kpi,
    start.kpi + " vs " + start.rows + " rows");

  const layer = await cg.evaluate(() => {
    const labels = document.querySelector("#cg-svg .cg-labels");
    const text = labels?.querySelector("text");
    return {
      last: labels === document.querySelector("#cg-svg").lastElementChild,
      inert: labels?.getAttribute("pointer-events") === "none",
      halo: text ? getComputedStyle(text).paintOrder : ""
    };
  });
  check("labels are drawn last, above every node, and never take a click",
    layer.last && layer.inert, JSON.stringify(layer));
  check("graph labels carry a halo", /stroke/.test(layer.halo), layer.halo);

  await cg.click('[data-zoom="in"]');
  await cg.waitForTimeout(250);
  const zoomed = await state();
  check("the graph toolbar changes the view", zoomed.first !== start.first,
  start.first.split(" ")[0] + " → " + zoomed.first.split(" ")[0]);
  await cg.click('[data-zoom="fit"]');
  await cg.click('[data-layout="tree"]');
  await cg.waitForTimeout(250);
  const tree = await state();
  check("the layout switch redraws and says which is on",
    tree.first !== start.first &&
      (await cg.getAttribute('[data-layout="tree"]', "aria-pressed")) === "true" &&
      (await cg.getAttribute('[data-layout="radial"]', "aria-pressed")) === "false");
  await cg.click('[data-layout="radial"]');

  await cg.click('[data-year="2019"]');
  await cg.waitForTimeout(250);
  const y2019 = await state();
  check("the timeline hides what had not been seen yet", y2019.rows > 0 && y2019.rows < start.rows,
    start.rows + " → " + y2019.rows + " clusters");
  await cg.click('[data-year="2024"]');
  await cg.waitForTimeout(200);

  const steps = [];
  for (let i = 0; i < 3; i++) {
    await cg.click("[data-cg-sev]");
    await cg.waitForTimeout(200);
    const s = await state();
    steps.push(s.rows + " (" + s.sev + ")");
  }
  const counts = steps.map((s) => parseInt(s, 10));
  check("the severity control filters rather than re-sorts",
    counts[0] < start.rows && counts[1] < counts[0] && counts[2] === start.rows, steps.join(" → "));

  await cg.focus("#cg-svg .cg-node[tabindex]");
  await cg.keyboard.press("Enter");
  await cg.waitForTimeout(250);
  const readout = await cg.evaluate(() => document.querySelector("#cg-readout").textContent.trim());
  check("a cluster opens its readout from the keyboard", readout.length > 5, readout.slice(0, 50));
  await cg.keyboard.press("Escape");
  await cg.waitForTimeout(300);
  check("Escape closes the readout",
    await cg.evaluate(() => {
      const r = document.querySelector("#cg-readout");
      return r.hidden || !r.classList.contains("on") || getComputedStyle(r).opacity === "0";
    }));

  await cg.evaluate(() => document.documentElement.setAttribute("data-theme", "dark"));
  await cg.waitForTimeout(400);
  const dark = await cg.evaluate(() => ({
    label: document.querySelector("#cg-svg .cg-labels text")?.getAttribute("fill"),
    ink: getComputedStyle(document.documentElement).getPropertyValue("--ink").trim()
  }));
  check("graph labels follow the theme instead of a fixed near-black", dark.label === dark.ink,
    dark.label + " vs --ink " + dark.ink);

  for (const width of [390, 768]) {
    await cg.setViewportSize({ width, height: 900 });
    await cg.waitForTimeout(350);
    const over = await cg.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    check("the campaign graph has no horizontal overflow at " + width + "px", over <= 0, "overflow " + over + "px");
  }
  check("the campaign graph raises no errors", cgErrors.length === 0, cgErrors[0]);
  await cg.close();
}

/* ───────────────────────────── what changed since the last triage
 * Re-running the same indicator should say so. The first sighting stays
 * silent on purpose: "nothing to compare" is not worth a row on every new
 * indicator, and the panel appearing out of nowhere is the signal.
 */
{
  const diffPage = await browser.newPage();
  const diffErrors = [];
  diffPage.on("pageerror", (e) => diffErrors.push(String(e)));
  await openWorkbench(diffPage);
  const triage = async () => {
    await diffPage.fill("#wb-input", "185.220.101.34");
    await diffPage.click("#wb-run");
    await diffPage.waitForTimeout(1200);
  };

  await triage();
  check("a first sighting shows no diff panel",
    (await diffPage.$$(".wb-diff")).length === 0,
    (await diffPage.$$(".wb-diff")).length + " panels");

  await triage();
  const panels = await diffPage.$$eval(".wb-diff", (els) =>
    els.map((el) => el.textContent.replace(/\s+/g, " ").trim()));
  check("a repeat triage shows what changed", panels.length >= 1, panels.length + " panels");
  check("identical input reports no change",
    (panels[0] || "").includes("no change"), (panels[0] || "(none)").slice(0, 80));
  check("the panel names the previous score",
    /score\s*\d+\s*→\s*\d+/.test(panels[0] || ""), (panels[0] || "").slice(0, 80));

  await triage();
  check("the diff raises no script errors", diffErrors.length === 0, diffErrors[0]);
  await diffPage.close();
}

/* ─────────────────────────────────────── retired with the standalone pages
 * These checks covered chrome that belonged to workbench.html and did not come
 * into the console with the workbench:
 *   - the ⌘K command palette (eight checks). The console has no palette; its
 *     sidebar and the assistant cover the same destinations.
 *   - the g g / g t / g h / g i key sequences and the ? shortcuts sheet: they
 *     switched the old page's tabs, and the pane is one scrolling view.
 *   - t cycling three themes, and the theme surviving a reload: the console
 *     has one theme button, tested in suite.spec.mjs ("the theme button
 *     switches to dark", "the choice survives a reload").
 *   - [ collapsing the rail: the console's sidebar collapse is tested there.
 *   - the Konami easter egg.
 *   - loading the real Cytoscape from its CDN: neither view depends on it now.
 */

await browser.close();
console.log(failures ? `\n${failures} check(s) failed` : "\nall checks passed");
process.exit(failures ? 1 : 0);
