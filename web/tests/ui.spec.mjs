/* Browser tests for the dashboard: security behaviour and the interactions
 * that make it usable.
 *
 * These are the checks unit tests cannot make — that attacker-controlled log
 * text never becomes DOM, that a hostile provider response cannot inject a
 * javascript: link, that a slow or dead backend degrades instead of freezing,
 * and that the command palette, key sequences, theme and charts actually work
 * in a real browser.
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

const BASE = process.env.INTELPULSE_URL || "http://127.0.0.1:8123/";
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

const activePanel = () =>
  page.evaluate(() => Array.from(document.querySelectorAll(".tab-panel")).find((p) => !p.hidden)?.id);

await page.goto(BASE, { waitUntil: "domcontentloaded" });
await page.waitForTimeout(400);

// ——————————————————————————————————— 1. XSS from a pasted log
const payload = `Sep 18 02:14 fw01: SRC=203.0.113.10 <script>window.__pwned=1;alert(1)</script>
<img src=x onerror="window.__pwned2=1">
"><svg/onload=alert(2)> javascript:alert(3)
hxxp://evil[.]example[.]com/"><script>alert(4)</script>`;
await page.fill("#input", payload);
await page.click("#run");
await page.waitForTimeout(900);

const xss = await page.evaluate(() => ({
  pwned: Boolean(window.__pwned || window.__pwned2),
  scriptTags: document.querySelectorAll("#panel-triage script").length,
  imgTags: document.querySelectorAll("#panel-triage img").length,
  hrefs: Array.from(document.querySelectorAll("#panel-triage a")).map((a) => a.getAttribute("href")),
  rendered: document.querySelector("#panel-triage").textContent.includes("<script>")
}));
check("attacker-controlled log text never executes", !xss.pwned && !alerted);
check("no script or img element is injected from log text", xss.scriptTags === 0 && xss.imgTags === 0);
check("the payload is rendered as visible text", xss.rendered);
check("only https vendor links survive", xss.hrefs.every((h) => h.startsWith("https://")));

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
  return Array.from(document.querySelectorAll("#panel-triage a")).map((a) => a.getAttribute("href"));
});
check("javascript: URLs from a provider response are dropped", badHref.length === 0);

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
await page.fill("#api-base", "http://127.0.0.1:9999");
await page.click("#api-save");
await page.fill("#input", "8.8.8.8 1.1.1.1");
await page.click("#run");
await page.waitForTimeout(600);
const loading = await page.evaluate(() => ({
  cards: document.querySelectorAll(".sk-card").length,
  button: document.querySelector("#run").textContent.trim()
}));
check("skeleton placeholders render while sources are queried", loading.cards >= 1);
check("the run button reports in-flight state", /Triaging/.test(loading.button));

await page.waitForTimeout(3200);
const recovered = await page.evaluate(() => ({
  toast: document.querySelector("#toast").textContent,
  button: document.querySelector("#run").textContent.trim(),
  disabled: document.querySelector("#run").disabled
}));
check("a dead backend degrades with a message, not a freeze",
  !recovered.disabled && /run triage/i.test(recovered.button) && /failed/i.test(recovered.toast));
await page.unroute("**/api/**");
await page.click('button[data-mode="demo"]');

// ————————————————————————————————————————— 4. a real triage
await page.click('button[data-scenario="firewall"]');
await page.click("#run");
await page.waitForTimeout(1000);

const result = await page.evaluate(() => ({
  hero: document.querySelector("#kpi .figure")?.textContent,
  bars: document.querySelectorAll(".bar-row").length,
  barWidths: Array.from(document.querySelectorAll(".bar-fill")).map((f) => Math.round(f.getBoundingClientRect().width)),
  meters: document.querySelectorAll(".meter").length,
  coverage: document.querySelectorAll(".coverage i").length,
  badges: Array.from(document.querySelectorAll(".ioc .badge")).map((b) => b.textContent.trim())
}));
check("the hero figure lands on the case score", result.hero === "95", "got " + result.hero);
check("evidence contribution bars render with real widths",
  result.bars > 0 && result.barWidths.some((w) => w > 40) && new Set(result.barWidths).size > 2);
check("meters and the coverage strip render", result.meters >= 2 && result.coverage > 0);
check("every severity badge carries its label, not just a colour",
  result.badges.length > 0 && result.badges.every((b) => /critical|high|medium|low|informational|allowlisted/i.test(b)));

// ——————————————————————————————— 5. the chart has a table equivalent
await page.click("[data-table-toggle]");
await page.waitForTimeout(200);
check("the chart offers a table view (WCAG-clean equivalent)",
  await page.evaluate(() => {
    const table = document.querySelector(".chart .table-view");
    return table && !table.hasAttribute("hidden") && table.querySelectorAll("tbody tr").length > 0;
  }));
await page.click("[data-table-toggle]");

// —————————————————————————————————————— 6. command palette
await page.keyboard.press("Control+k");
await page.waitForTimeout(300);
check("⌘K opens the command palette", await page.isVisible(".cmdk"));
const allCommands = await page.evaluate(() => document.querySelectorAll(".cmdk-item").length);
await page.keyboard.type("ticket");
await page.waitForTimeout(250);
const cmdk = await page.evaluate(() => ({
  items: Array.from(document.querySelectorAll(".cmdk-item")).map((i) => i.textContent.trim()),
  marks: document.querySelectorAll(".cmdk-item mark").length,
  selected: document.querySelectorAll('.cmdk-item[aria-selected="true"]').length
}));
/* Fuzzy search is subsequence-based and matches the label, its group and its
   keywords — the same contract Linear and Raycast use. So the assertions are:
   the list narrows, and the commands that really are about the ticket rank at
   the top. */
check("typing narrows the palette", cmdk.items.length > 0 && cmdk.items.length < allCommands,
  cmdk.items.length + " of " + allCommands);
check("the best matches rank first",
  cmdk.items.slice(0, 3).every((t) => /ticket/i.test(t)), cmdk.items.slice(0, 3).join(" | "));
check("matched characters are highlighted", cmdk.marks > 0);
check("exactly one item is selected at a time", cmdk.selected === 1);

// A command found only through its keywords, never its label.
await page.fill(".cmdk-input input", "konami");
await page.waitForTimeout(250);
check("commands are findable by keyword, not just label",
  /night-watch/i.test(await page.evaluate(() =>
    document.querySelector(".cmdk-item")?.textContent || "")));

await page.fill(".cmdk-input input", "ticket");
await page.waitForTimeout(200);
await page.keyboard.press("ArrowDown");
await page.keyboard.press("Enter");
await page.waitForTimeout(400);
check("Enter runs the selected command", !(await page.isVisible(".cmdk")));

await page.keyboard.press("Control+k");
await page.waitForTimeout(200);
await page.keyboard.press("Escape");
await page.waitForTimeout(200);
check("Escape closes the palette", !(await page.isVisible(".cmdk")));

// —————————————————————————————————— 7. keyboard navigation
for (const [keys, panel] of [[["g", "g"], "panel-graph"], [["g", "t"], "panel-report"],
                             [["g", "h"], "panel-history"], [["g", "i"], "panel-triage"]]) {
  await page.keyboard.press(keys[0]);
  await page.keyboard.press(keys[1]);
  await page.waitForTimeout(450);
  check("key sequence " + keys.join(" ") + " navigates", (await activePanel()) === panel);
}

await page.keyboard.press("?");
await page.waitForTimeout(300);
check("? opens the shortcuts sheet",
  (await page.isVisible("#sheet-scrim")) && (await page.$$eval(".shortcut-row", (r) => r.length)) > 5);
await page.keyboard.press("Escape");

// ————————————————————————————————————————— 8. theming
const themeCycle = [];
for (let i = 0; i < 3; i++) {
  await page.keyboard.press("t");
  await page.waitForTimeout(250);
  themeCycle.push(await page.evaluate(() => document.documentElement.getAttribute("data-theme")));
}
check("t cycles dark → light → system", themeCycle.join(",") === "light,,dark", themeCycle.join(","));

await page.evaluate(() => localStorage.setItem("intelpulse:theme", '"light"'));
await page.reload({ waitUntil: "domcontentloaded" });
await page.waitForTimeout(400);
check("the theme choice survives a reload",
  (await page.evaluate(() => document.documentElement.getAttribute("data-theme"))) === "light");
check("light mode keeps text readable against its surface",
  await page.evaluate(() => {
    const cs = getComputedStyle(document.body);
    return cs.color !== cs.backgroundColor && /255|251|252/.test(cs.backgroundColor);
  }));
await page.evaluate(() => localStorage.setItem("intelpulse:theme", '"dark"'));

// ———————————————————————————————————————— 9. the rail
await page.reload({ waitUntil: "domcontentloaded" });
await page.waitForTimeout(400);
const railBefore = await page.evaluate(() => document.querySelector("#rail").getBoundingClientRect().width);
await page.keyboard.press("[");
await page.waitForTimeout(400);
const railAfter = await page.evaluate(() => document.querySelector("#rail").getBoundingClientRect().width);
check("[ collapses the rail to icons", railAfter < railBefore && railAfter < 80, railBefore + " -> " + railAfter);
await page.keyboard.press("[");

// ———————————————————————————— 10. scoring math + graph tools
await page.click('button[data-scenario="firewall"]');
await page.click("#run");
await page.waitForTimeout(900);
await page.click("[data-math]");
await page.waitForTimeout(350);
const math = await page.evaluate(() => ({
  title: document.querySelector("#sheet-title").textContent,
  body: document.querySelector("#sheet-body").textContent
}));
check("the scoring math sheet shows the actual arithmetic",
  /Scoring math/.test(math.title) && /weighted mean/.test(math.body) && /authority floor/.test(math.body));
await page.keyboard.press("Escape");

await page.keyboard.press("g");
await page.keyboard.press("g");
await page.waitForTimeout(1100);
const zoomBefore = await page.evaluate(() =>
  document.querySelector(".svg-root")?.getAttribute("transform") ||
  (window.IntelPulse.result ? "cytoscape" : "none"));
await page.click('.graph-tools button[data-graph="in"]');
await page.click('.graph-tools button[data-graph="in"]');
await page.waitForTimeout(300);
const zoomAfter = await page.evaluate(() =>
  document.querySelector(".svg-root")?.getAttribute("transform") || "cytoscape");
check("the graph toolbar changes the view", zoomBefore !== zoomAfter || zoomAfter === "cytoscape");

// ————————————————————————————————————— 11. easter egg
await page.keyboard.press("g");
await page.keyboard.press("i");
for (const key of ["ArrowUp", "ArrowUp", "ArrowDown", "ArrowDown", "ArrowLeft", "ArrowRight", "ArrowLeft", "ArrowRight", "b", "a"]) {
  await page.keyboard.press(key);
}
await page.waitForTimeout(300);
check("the konami sequence engages night-watch mode",
  await page.evaluate(() => document.body.classList.contains("night-watch")));
await page.evaluate(() => document.body.classList.remove("night-watch"));

// ————————————————————————————— 12. accessibility & layout
const a11y = await page.evaluate(() => ({
  skip: Boolean(document.querySelector("a.skip")),
  labelled: Array.from(document.querySelectorAll(".icon-btn")).every((b) => b.getAttribute("aria-label")),
  dialog: Boolean(document.querySelector('[role="dialog"][aria-modal="true"]')),
  live: Boolean(document.querySelector('#toast[aria-live]')),
  expanded: Boolean(document.querySelector(".ioc-top[aria-expanded]"))
}));
check("skip link, labelled icon buttons, modal roles and a live region exist",
  a11y.skip && a11y.labelled && a11y.dialog && a11y.live && a11y.expanded);

await page.emulateMedia({ reducedMotion: "reduce" });
await page.reload({ waitUntil: "domcontentloaded" });
await page.click('button[data-scenario="firewall"]');
await page.click("#run");
await page.waitForTimeout(700);
check("reduced motion is honoured (the hero figure is final, not tweening)",
  (await page.evaluate(() => document.querySelector("#kpi .figure").textContent)) === "95");
await page.emulateMedia({ reducedMotion: "no-preference" });

for (const width of [390, 768, 1024, 1440]) {
  await page.setViewportSize({ width, height: 900 });
  await page.waitForTimeout(250);
  const overflow = await page.evaluate(() =>
    document.documentElement.scrollWidth - document.documentElement.clientWidth);
  check("no horizontal overflow at " + width + "px", overflow <= 0, "overflow " + overflow + "px");
}

// ——————————————————————————————— 13. deep links, undo, long input
await page.setViewportSize({ width: 1440, height: 1000 });
await page.goto(BASE + "#report", { waitUntil: "domcontentloaded" });
await page.reload({ waitUntil: "domcontentloaded" });   // a hash-only goto never re-runs init
await page.waitForTimeout(400);
await page.click('button[data-scenario="firewall"]');
await page.click("#run");
await page.waitForTimeout(900);
check("a tab can be deep-linked from the URL", (await activePanel()) === "panel-report");

await page.keyboard.press("g");
await page.keyboard.press("g");
await page.waitForTimeout(400);
check("navigating updates the URL", (await page.evaluate(() => location.hash)) === "#graph");

await page.keyboard.press("g");
await page.keyboard.press("i");
await page.waitForTimeout(300);
const before = await page.inputValue("#input");
await page.click("#clear");
await page.waitForTimeout(300);
check("clearing offers an undo rather than a confirmation dialog",
  await page.isVisible("#toast-action"));
await page.click("#toast-action");
await page.waitForTimeout(400);
check("undo restores the cleared input", (await page.inputValue("#input")) === before);

const manyIocs = Array.from({ length: 60 }, (_, i) => `185.220.${Math.floor(i / 256)}.${i + 1}`).join(" ");
await page.fill("#input", manyIocs);
await page.click("#run");
await page.waitForTimeout(1200);
const paging = await page.evaluate(() => ({
  cards: document.querySelectorAll(".ioc").length,
  more: Boolean(document.querySelector("#show-all"))
}));
check("a long list pages instead of rendering everything at once",
  paging.cards <= 25 && paging.more, paging.cards + " cards");
await page.click("#show-all");
await page.waitForTimeout(500);
check("show-all expands the full list",
  (await page.evaluate(() => document.querySelectorAll(".ioc").length)) > 25);

// ————————————————— 14. component states: error, disabled, touch, contrast
await page.goto(BASE, { waitUntil: "domcontentloaded" });
await page.waitForTimeout(400);
await page.fill("#input", "");
await page.click("#run");
await page.waitForTimeout(300);
const emptyError = await page.evaluate(() => ({
  invalid: document.querySelector("#input").getAttribute("aria-invalid"),
  shown: !document.querySelector("#input-error").hidden,
  message: document.querySelector("#input-error span").textContent,
  describedBy: document.querySelector("#input").getAttribute("aria-describedby"),
  focused: document.activeElement.id
}));
check("an empty run reports inline, on the field, not in a toast",
  emptyError.invalid === "true" && emptyError.shown && emptyError.message.length > 10);
check("the error is announced and the field takes focus",
  emptyError.describedBy === "input-error" && emptyError.focused === "input");

await page.fill("#input", "8.8.8.8");
await page.waitForTimeout(200);
check("typing clears the error state",
  (await page.evaluate(() => document.querySelector("#input").getAttribute("aria-invalid"))) === null);

await page.fill("#input", "no indicators in this sentence at all");
await page.click("#run");
await page.waitForTimeout(700);
check("an input with nothing routable explains why",
  await page.evaluate(() => !document.querySelector("#input-error").hidden &&
    /routable/i.test(document.querySelector("#input-error span").textContent)));

await page.click('button[data-mode="live"]');
await page.waitForTimeout(250);
await page.fill("#api-base", "not-a-url");
await page.click("#api-save");
await page.waitForTimeout(250);
check("a malformed backend URL is rejected at the field",
  await page.evaluate(() => document.querySelector("#api-base").getAttribute("aria-invalid") === "true" &&
    !document.querySelector("#api-error").hidden));
await page.fill("#api-base", "http://localhost:8000");
await page.click('button[data-mode="demo"]');

/* The run button must report busy and then recover. A demo triage finishes in
   about a millisecond, so this watches the attribute rather than sampling it. */
const busySeen = await page.evaluate(() => new Promise((resolve) => {
  const button = document.querySelector("#run");
  const records = [];
  // Read the records, not the live attribute: by the time the callback runs the
  // attribute may already have been removed again.
  const observer = new MutationObserver((list) =>
    list.forEach((record) => records.push(record.oldValue)));
  observer.observe(button, { attributes: true, attributeOldValue: true, attributeFilter: ["aria-busy"] });
  document.querySelector("#input").value = "203.0.113.10";
  button.click();
  setTimeout(() => {
    observer.disconnect();
    resolve({ seen: records.length >= 2 && records[0] === null, after: button.getAttribute("aria-busy") });
  }, 900);
}));
check("the run button carries aria-busy while in flight and clears it after",
  busySeen.seen && busySeen.after === null, JSON.stringify(busySeen));

// touch targets on a coarse pointer
const touch = await browser.newPage({ viewport: { width: 414, height: 896 }, hasTouch: true, isMobile: true });
await touch.goto(BASE, { waitUntil: "domcontentloaded" });
await touch.waitForTimeout(500);
const small = await touch.evaluate(() =>
  Array.from(document.querySelectorAll(".icon-btn, .tabs button, .seg button, .rail-btn"))
    .filter((el) => el.offsetParent !== null)
    .map((el) => ({ cls: el.className, h: Math.round(el.getBoundingClientRect().height) }))
    .filter((el) => el.h < 44));
check("every visible control clears 44px on a touch device", small.length === 0,
  small.slice(0, 3).map((e) => e.cls + " " + e.h + "px").join(", "));
await touch.close();

// ———————————————————————— 15. forced colours (Windows High Contrast)
const hc = await browser.newPage({ viewport: { width: 1280, height: 900 }, forcedColors: "active" });
await hc.goto(BASE, { waitUntil: "domcontentloaded" });
await hc.click('button[data-scenario="firewall"]');
await hc.click("#run");
await hc.waitForTimeout(900);
const contrast = await hc.evaluate(() => {
  const outlined = (el) => {
    const cs = getComputedStyle(el);
    return cs.borderTopWidth !== "0px" || cs.outlineWidth !== "0px";
  };
  return {
    bars: Array.from(document.querySelectorAll(".bar-fill")).every(outlined),
    badges: Array.from(document.querySelectorAll(".badge")).every(outlined),
    cards: Array.from(document.querySelectorAll(".ioc")).every(outlined)
  };
});
check("meaning survives forced-colors mode (fills keep an outline)",
  contrast.bars && contrast.badges && contrast.cards, JSON.stringify(contrast));
await hc.close();

check("no uncaught page errors", errors.length === 0, errors.slice(0, 2).join(" | "));

await browser.close();
console.log(failures ? `\n${failures} check(s) failed` : "\nall checks passed");
process.exit(failures ? 1 : 0);
