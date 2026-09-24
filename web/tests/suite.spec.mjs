/* Browser tests for the landing page and operator console (web/index.html).
 *
 * The workbench tests cover the analyst tool; these cover the surface in front
 * of it. The rule this file exists to enforce is simple: every control a
 * visitor can see does something. A button that looks pressable and answers
 * nothing is a bug, so the sweep below clicks all of them and fails on any
 * that leave the page unchanged.
 *
 * It also pins the three things that broke while the page was being built —
 * the side scroller (a fractional scrollLeft is rounded away by Chromium), the
 * scaled hero mock (a centre transform-origin pushes it off a phone screen),
 * and the theme wipe — so they cannot regress silently.
 *
 * Run:  python3 -m http.server 8123 --directory web   # one terminal
 *       node web/tests/suite.spec.mjs                 # another
 * Needs Playwright with Chromium available.
 */
let chromium;
try {
  ({ chromium } = await import(process.env.PLAYWRIGHT_MODULE || "playwright"));
} catch {
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
const errors = [];
page.on("pageerror", (e) => errors.push(e.message));
page.on("console", (m) => {
  if (m.type() === "error" && !/net::|favicon|font/i.test(m.text())) errors.push("console: " + m.text());
});

await page.goto(BASE, { waitUntil: "domcontentloaded" });
await page.waitForTimeout(1200);

/* ───────────────────────────────────────────────────────── structure */
check("the landing page renders its hero", await page.$eval("h1", (h) => h.textContent.trim().length > 20));
check("the hero mock draws the console", (await page.$$("#console-preview .kpi")).length === 4);
check("the severity bar draws all five bands", (await page.$$("#sev-landing span")).length === 5,
  (await page.$$eval("#sev-landing span", (els) => els.map((e) => e.textContent.trim()).join(" \u00b7 "))));

/* The hatched remainder used to be sized as "30 minus whatever is shown", so
   filtering to Closed invented 21 unclassified findings. Every band is data
   now, and the three filters have to reconcile with the state row. */
for (const filter of ["All", "Open", "Closed"]) {
  await page.evaluate((f) => {
    [...document.querySelectorAll("#page-home .seg button")].find((b) => b.textContent.trim() === f)?.click();
  }, filter);
  await page.waitForTimeout(320);
  const sums = await page.evaluate(() => {
    const count = (t) => parseInt(t, 10) || 0;
    const sev = [...document.querySelectorAll("#sev-landing span")].reduce((s, e) => s + count(e.textContent), 0);
    const state = [...document.querySelectorAll("#state-landing div")].reduce((s, e) => s + count(e.textContent), 0);
    return { sev, state };
  });
  check("the " + filter + " filter reconciles severity with state",
    sums.sev > 0 && sums.sev === sums.state, sums.sev + " vs " + sums.state);
}
await page.evaluate(() => {
  [...document.querySelectorAll("#page-home .seg button")].find((b) => b.textContent.trim() === "All")?.click();
});
await page.waitForTimeout(280);
check("the attack-surface gauge draws", (await page.$$("#gauge-landing svg")).length === 1);
check("the hero mock is inert", await page.$eval("#preview-scaler", (el) =>
  el.hasAttribute("inert") && getComputedStyle(el).pointerEvents === "none"),
  "a scaled picture of the console must not be a second set of controls");

/* ───────────────────────── every visible control answers when clicked */
/* The page's own CSP forbids inline script — which is the point of having it —
   so the probe goes in through the debugger rather than a <script> tag. */
const installProbe = () => page.evaluate(() => {
  window.__probe = {
    mut: 0,
    list() {
      return [...document.querySelectorAll('button, a[href], [role="button"]')].filter((el) => {
        const r = el.getBoundingClientRect();
        if (r.width <= 1 || r.height <= 1 || el.offsetParent === null) return false;
        /* Controls inside a CLOSED overlay are not being offered to anyone yet;
           they get their own checks, opened. Named explicitly rather than by
           computed opacity, which would also skip every section still waiting
           on its reveal animation. */
        return !el.closest(".menu:not(.on)") && !el.closest("#ai-panel:not(.on)");
      });
    },
    label: (el) => (el.textContent || el.getAttribute("aria-label") || el.tagName)
      .trim().replace(/\s+/g, " ").slice(0, 40)
  };
  new MutationObserver((records) => { window.__probe.mut += records.length; })
    .observe(document.documentElement, { subtree: true, childList: true, attributes: true, characterData: true });
});
await installProbe();

const page_of = (url) => url.split("#")[0];
async function reset(where) {
  /* Some controls are ordinary links to the workbench or the graph. Following
     one is a correct answer, not a failure — come back and carry on. */
  if (page_of(page.url()) !== page_of(BASE)) {
    await page.goto(BASE, { waitUntil: "domcontentloaded" });
    await installProbe();
    await page.waitForTimeout(700);
  }
  /* Instant, not smooth. The page sets `html { scroll-behavior: smooth }`, so a
     bare scrollTo(0, 0) from the bottom of the page is an animation that is still
     running when the next probe calls scrollIntoView -- which jumps into place and
     is then dragged back up by the tail of the old scroll. A footer control, at
     the very end of the page, ended up below the viewport and read as "not
     hit-testable" on some runs and not others. Measured: centre y 1049 in a
     1000px viewport. Settling the reveal animation was tried first and did not
     remove it. This made it rarer but not gone; the probe below re-measures. */
  await page.evaluate((w) => {
    location.hash = w === "console" ? "#/console" : "#/home";
    scrollTo({ top: 0, behavior: "instant" });
  }, where);
  await page.waitForTimeout(260);
  if (where === "console") {
    await page.evaluate(() => {
      const shell = document.querySelector("#console-full");
      if (shell && shell.classList.contains("compact")) document.querySelector("#c-collapse")?.click();
      document.querySelectorAll("#side-nav-full [data-group]").forEach((g) => {
        if (g.getAttribute("aria-expanded") !== "true") g.click();
      });
      [...document.querySelectorAll("#side-nav-full .nav-item")]
        .find((n) => n.dataset.pane === "dashboard")?.click();
    });
    await page.waitForTimeout(480);
  }
}

const inert = [];
let probed = 0;
/* A link with target="_blank" answers a click by opening a new tab and leaves
   this page exactly as it was, so none of the signals below can see it. The
   footer grew its first such links (the source code, the scoring doc, the
   author) and the sweep called all three dead. Opening a tab is as much an
   answer as following a link to the workbench — count the popup, then close it.
   Playwright reports a popup only once its first navigation commits, and
   github.com took longer than the sweep's 360ms in CI (measured locally: 200 to
   320ms even with the request failing). So a navigation that leaves the site is
   answered with a stub page -- the sweep no longer depends on github.com being
   reachable or quick -- and a link that opens a tab gets up to 3s to do it.
   Only navigations are stubbed: fonts and the like still load for real. */
let popped = 0;
page.context().on("page", (tab) => { popped++; tab.close().catch(() => {}); });
await page.context().route((url) => url.hostname !== new URL(BASE).hostname, (route) =>
  route.request().isNavigationRequest()
    ? route.fulfill({ status: 200, contentType: "text/html", body: "<!doctype html><title>stub</title>" })
    : route.continue());
async function sweep(where) {
  await reset(where);
  const total = await page.evaluate(() => window.__probe.list().length);
  for (let i = 0; i < total; i++) {
    /* Read before the click: a stubbed popup can be reported before this
       evaluate resolves, and a count taken after it would already include it. */
    const poppedBefore = popped;
    const shot = await page.evaluate(async (index) => {
      const el = window.__probe.list()[index];
      if (!el) return null;
      const label = window.__probe.label(el);
      /* Up to three tries. The page can still be settling (a web font swapping
         in reflows every section above the footer), and a control measured
         mid-reflow sat below a viewport it fits in. One that is still out of
         reach after three tries is reported, with what is in the way. */
      let box;
      for (let attempt = 0; attempt < 3; attempt++) {
        el.scrollIntoView({ block: "center", behavior: "instant" });
        /* A control pinned to the viewport (the brand, the theme button) does
           not move the page when scrolled into view. Leave the page off the
           very top so a "back to top" control has something to do and its
           answer shows — but stay under the 220px mark, past which the nav
           tucks itself away. */
        if (scrollY < 8) scrollTo({ top: 180, behavior: "instant" });
        await new Promise((r) => setTimeout(r, 140));
        box = el.getBoundingClientRect();
        const cy = box.top + box.height / 2;
        if (cy >= 0 && cy <= innerHeight) break;
      }
      const hit = document.elementFromPoint(box.left + box.width / 2, box.top + box.height / 2);
      const reachable = !!hit && (el.contains(hit) || hit.contains(el));
      /* Name what is in the way, so a failure says what to fix instead of
         only that something is wrong. */
      const blocker = reachable ? "" : !hit
        ? "nothing: centre " + Math.round(box.left + box.width / 2) + "," + Math.round(box.top + box.height / 2)
          + " is outside the " + innerWidth + "x" + innerHeight + " viewport (box h=" + Math.round(box.height) + ", scrollY " + Math.round(scrollY) + ")"
        : hit.tagName.toLowerCase()
        + (hit.id ? "#" + hit.id : "") + (hit.classList.length ? "." + [...hit.classList].join(".") : "")
        + " at " + Math.round(box.left + box.width / 2) + "," + Math.round(box.top + box.height / 2);
      window.__probe.mut = 0;
      window.__probe.before = { hash: location.hash, y: Math.round(scrollY) };
      el.click();
      return { label, reachable, blocker, opensTab: el.matches('a[target="_blank"]') };
    }, i);
    if (!shot) continue;
    probed++;
    await page.waitForTimeout(360);
    for (let waited = 0; shot.opensTab && popped === poppedBefore && waited < 3000; waited += 100) {
      await page.waitForTimeout(100);
    }
    let answered = page_of(page.url()) !== page_of(BASE) || popped > poppedBefore;
    if (!answered) {
      const now = await page.evaluate(() => ({
        mut: window.__probe.mut, hash: location.hash, y: Math.round(scrollY), before: window.__probe.before
      })).catch(() => null);
      answered = !now || now.mut > 0 || now.hash !== now.before.hash || Math.abs(now.y - now.before.y) > 4;
    }
    if (!shot.reachable) inert.push(where + " › " + shot.label + " (not hit-testable, under " + shot.blocker + ")");
    else if (!answered) inert.push(where + " › " + shot.label + " (no effect)");
    await reset(where);
  }
}
await sweep("home");
await sweep("console");
check("every visible control answers a click", inert.length === 0,
  inert.length ? probed + " probed, dead: " + inert.slice(0, 6).join("; ") : probed + " controls probed");

/* ── the brand link is the one control whose answer is invisible from the top */
await reset("home");
await page.evaluate(() => scrollTo(0, 2400));
await page.waitForTimeout(400);
await page.evaluate(() => scrollBy(0, -120));   // scrolling up brings the nav back
await page.waitForTimeout(500);
await page.click("#nav .brand");
await page.waitForTimeout(900);
check("the brand mark returns you to the top", await page.evaluate(() => scrollY) < 40);

/* The assistant's controls only exist once it is open, so the sweep above
   cannot reach them. They answer to the same rule. */
await reset("home");
/* The sweep clicked the assistant open on its way past; the button hides itself
   behind the panel while it is open, so put it back first. */
await page.evaluate(() => {
  if (document.querySelector("#ai-panel").classList.contains("on")) document.querySelector("#ai-close").click();
});
await page.waitForTimeout(400);
await page.click("#ai-fab");
await page.waitForTimeout(500);
check("the assistant opens from its button", await page.$eval("#ai-panel", (el) => el.classList.contains("on")));
const chips = await page.$$("#ai-chips button");
check("it suggests somewhere to start", chips.length >= 4, chips.length + " suggestions");
const saidBefore = (await page.$$("#ai-log .ai-msg.bot")).length;
await chips[0].click();
await page.waitForTimeout(600);
check("a suggestion is answered", (await page.$$("#ai-log .ai-msg.bot")).length === saidBefore + 1);
check("the answer carries its source",
  (await page.$$eval("#ai-log .ai-src", (els) => els.length)) >= 1);
const acts = await page.$$("#ai-log [data-act]");
check("the answer offers somewhere to go", acts.length >= 1);
/* An assistant that shrugs at plain English is worse than no assistant. These
   are the questions a visitor actually types — two of them were reported from a
   phone, both answered "I do not have an answer for that one". */
const DECLINED = "do not have an answer";
async function ask(question) {
  await page.fill("#ai-input", question);
  await page.press("#ai-input", "Enter");
  await page.waitForTimeout(500);
  return page.$eval("#ai-log .ai-msg.bot:last-child", (el) => el.textContent.trim());
}

const MUST_ANSWER = [
  "Take me to the main page",
  "About",
  "help",
  "what can you do",
  "go home",
  "open the workbench",
  "take me to the top",
  "who built this",
  "show me the graph",
  "what is this"
];
const shrugged = [];
for (const question of MUST_ANSWER) {
  const answer = await ask(question);
  if (answer.includes(DECLINED)) shrugged.push(question);
}
check("the assistant answers plain-English requests",
  shrugged.length === 0, shrugged.join(" · ") || MUST_ANSWER.length + " asked");

/* Every question the panel offers must be one it can answer. Suggesting a
   question and then declining it is the worst version of this bug. */
const offered = await page.$$eval("#ai-chips button", (els) => els.map((e) => e.textContent.trim()));
const badChips = [];
for (const question of offered) {
  if ((await ask(question)).includes(DECLINED)) badChips.push(question);
}
check("every suggestion it offers is one it can answer",
  badChips.length === 0, badChips.join(" · ") || offered.length + " suggestions");

/* "Take me to the main page" should take you there, not describe the journey. */
await page.evaluate(() => { location.hash = "#/console/sources"; });
await page.waitForTimeout(600);
const navAnswer = await ask("take me to the main page");
const goHome = await page.$('#ai-log .ai-msg.bot:last-child [data-act="home"]');
check("a navigation request offers the button that performs it",
  goHome !== null && !navAnswer.includes(DECLINED),
  navAnswer.slice(0, 60));
if (goHome) {
  await goHome.click();
  await page.waitForTimeout(700);
  check("and pressing it lands on the site, not the console",
    (await page.evaluate(() => location.hash)) === "#/home",
    await page.evaluate(() => location.hash));
  await page.click("#ai-fab").catch(() => {});
  await page.waitForTimeout(400);
}

await page.click("#ai-close");
await page.waitForTimeout(400);
check("the close button closes it", !(await page.$eval("#ai-panel", (el) => el.classList.contains("on"))));

/* ─────────────────────────────────────────────────── the side scroller */
await reset("home");
await page.evaluate(() => document.querySelector("#sources").scrollIntoView({ block: "center" }));
await page.waitForTimeout(450);
const at = () => page.evaluate(() => document.querySelector("#marquee").scrollLeft);
const runs = await page.$$("#sources .mq-run");
const span = await page.$eval("#sources .mq-run", (el) => el.getBoundingClientRect().width);
const track = await page.$eval("#sources .mq-track", (el) => el.getBoundingClientRect().width);
check("the rail is built from three identical runs", runs.length === 3 && Math.abs(track - span * 3) < 3,
  "a shift of exactly one run has to be invisible");
check("the second and third runs are hidden from assistive tech",
  await page.$$eval("#sources .mq-run", (els) => els.slice(1).every((e) => e.getAttribute("aria-hidden") === "true")));

const before = await at();
await page.waitForTimeout(1400);
const after = await at();
check("the rail advances on its own", after - before > 12, Math.round(after - before) + "px in 1.4s");

await page.hover("#marquee");
await page.waitForTimeout(120);
const held0 = await at();
await page.waitForTimeout(800);
const held1 = await at();
check("the rail stops under the cursor", Math.abs(held1 - held0) < 1);

const rail = await page.$eval("#marquee", (el) => {
  const r = el.getBoundingClientRect();
  return { x: r.x + r.width / 2, y: r.y + r.height / 2 };
});
await page.mouse.move(rail.x, rail.y);
await page.mouse.down();
await page.mouse.move(rail.x - 220, rail.y, { steps: 12 });
await page.mouse.up();
const dragged = await at();
/* Modulo one run: a drag that crosses the seam wraps by exactly one run,
   which is invisible by design. Measured raw, a drag that started near the
   seam read as -1419px for 220 and failed CI for the wrap, not the drag. */
const travelled = (from, to) => (((to - from) % span) + span) % span;
check("the rail can be dragged", Math.abs(travelled(held1, dragged) - 220) < 40,
  Math.round(travelled(held1, dragged)) + "px for a 220px drag");

/* A long drag that sets out just before the seam. Positioned from the drag's
   start, it wrote past the end of the track, the browser clamped it, and the
   rail stopped following the pointer: 565px for a 700px drag. */
await page.evaluate((s) => { document.querySelector("#marquee").scrollLeft = Math.round(s * 2 - 100); }, span);
await page.waitForTimeout(80);
const longFrom = await at();
await page.mouse.move(rail.x + 350, rail.y);
await page.mouse.down();
await page.mouse.move(rail.x - 350, rail.y, { steps: 35 });
await page.mouse.up();
const longTo = await at();
check("a long drag across the seam keeps following the pointer", Math.abs(travelled(longFrom, longTo) - 700) < 40,
  Math.round(travelled(longFrom, longTo)) + "px for a 700px drag");

await page.mouse.move(rail.x, rail.y);
await page.mouse.down();
await page.mouse.move(rail.x + 1400, rail.y, { steps: 20 });
await page.mouse.up();
const back = await at();
check("dragging the other way wraps instead of hitting a wall",
  back > span * 0.4 && back < span * 2.1, Math.round(back) + "px, run span " + Math.round(span));

await page.mouse.move(6, 6);
const left0 = await at();
await page.waitForTimeout(900);
check("the rail resumes when the cursor leaves", (await at()) - left0 > 8);

/* ───────────────────────────────────────────────────────────── theme */
/* The nav tucks away while you scroll down, so come back to the top first. */
await page.evaluate(() => scrollTo(0, 0));
await page.waitForTimeout(500);
await page.click("#theme-btn");
await page.waitForTimeout(900);
check("the theme button switches to dark", await page.evaluate(() => document.documentElement.dataset.theme) === "dark");
check("the icon flips to its opposite",
  await page.$eval("#theme-icon use", (u) => u.getAttribute("href")) === "#i-sun");
await page.reload({ waitUntil: "domcontentloaded" });
await page.waitForTimeout(900);
check("the choice survives a reload", await page.evaluate(() => document.documentElement.dataset.theme) === "dark");
check("dark mode still draws the charts", (await page.$$("#gauge-landing svg")).length === 1);
await page.click("#theme-btn");
await page.waitForTimeout(900);
check("the theme button switches back to light", await page.evaluate(() => document.documentElement.dataset.theme) === "light");

/* ──────────────────────────────────────────────────────────── routing */
await page.evaluate(() => { location.hash = "#/console"; });
await page.waitForTimeout(700);
check("the console route shows the console", await page.$eval("#page-console", (el) => !el.hidden));
check("the console route hides the landing page", await page.$eval("#page-home", (el) => el.hidden));
check("the nav call-to-action offers the way back",
  (await page.$eval("#nav-cta", (el) => el.textContent)).includes("Back to site"));
check("the console renders its metrics", (await page.$$("#console-body .kpi")).length === 4);
check("the console renders the findings table", (await page.$$("#console-body .table tbody tr")).length >= 4);
check("the console links on to the live workbench",
  (await page.$eval("#console-body .head-right a", (el) => el.getAttribute("href"))) === "#/console/workbench");

await page.evaluate(() => {
  [...document.querySelectorAll("#side-nav-full .nav-item")].find((n) => n.dataset.pane === "campaigns")?.click();
});
await page.waitForTimeout(500);
check("a sidebar entry changes the pane",
  (await page.$eval("#console-body h3", (h) => h.textContent)).includes("Campaign graph"));
/* The sidebar used to list Projects, pentests and password audits — features
   this product does not have. Every entry now has to render something. */
const panes = await page.$$eval("#side-nav-full .nav-item", (els) => els.map((e) => e.dataset.pane));
check("the sidebar lists nothing the product does not do",
  !panes.some((p) => ["projects", "external", "internal", "passwords", "active"].includes(p)),
  panes.join(", "));
await page.evaluate(() => {
  [...document.querySelectorAll("#side-nav-full .nav-item")].find((n) => n.dataset.pane === "sources")?.click();
});
await page.waitForTimeout(500);
check("the sources view shows the real weights and authority values",
  (await page.$eval("#console-body", (el) => el.textContent)).includes("0.95") &&
  (await page.$$eval("#console-body .table tbody tr", (r) => r.length)) >= 8);
await page.evaluate(() => {
  [...document.querySelectorAll("#side-nav-full .nav-item")].find((n) => n.dataset.pane === "dashboard")?.click();
});
await page.waitForTimeout(420);

await page.click("#c-collapse");
await page.waitForTimeout(420);
check("the sidebar collapses", await page.$eval("#console-full", (el) => el.classList.contains("compact")));
await page.click("#c-collapse");
await page.waitForTimeout(420);
check("the sidebar comes back", await page.$eval("#console-full", (el) => !el.classList.contains("compact")));

const firstSeg = await page.$("#console-body .seg button:nth-child(2)");
const bandsBefore = await page.$$eval("#console-body [data-sev] span", (n) => n.length);
await firstSeg.click();
await page.waitForTimeout(400);
check("a severity filter redraws the bar",
  (await page.$$eval("#console-body [data-sev] span", (n) => n.length)) !== bandsBefore ||
  (await page.$eval("#console-body .seg button:nth-child(2)", (b) => b.getAttribute("aria-pressed"))) === "true");

/* The findings table is the one thing wide enough to burst its card: nowrap
   cells made an auto-layout table grow straight through the panel edge. */
for (const width of [1440, 1024, 390]) {
  await page.setViewportSize({ width, height: 900 });
  await page.evaluate(() => {
    location.hash = "#/console";
    [...document.querySelectorAll("#side-nav-full .nav-item")]
      .find((n) => n.dataset.pane === "dashboard")?.click();
  });
  await page.waitForTimeout(700);
  const fit = await page.evaluate(() => {
    const wrap = document.querySelector("#console-body .table-wrap");
    if (!wrap) return null;
    const card = wrap.closest(".card");
    return {
      spill: Math.round(wrap.getBoundingClientRect().right - card.getBoundingClientRect().right),
      scrolls: wrap.scrollWidth > wrap.clientWidth,
      page: document.documentElement.scrollWidth - document.documentElement.clientWidth
    };
  });
  check("the findings table stays inside its card at " + width + "px",
    !!fit && fit.spill <= 0 && fit.page === 0,
    fit ? "spill " + fit.spill + "px, page over " + fit.page + "px" : "no table found");
}
await page.setViewportSize({ width: 1440, height: 1000 });

/* Web Interface Guidelines: stateful UI should be deep-linkable, and the
   browser chrome colour should match the page it is sitting above. */
await page.evaluate(() => { location.hash = "#/console/sources"; });
await page.waitForTimeout(800);
check("a console view can be linked to directly",
  (await page.$eval("#console-body h3", (h) => h.textContent)).includes("Intelligence sources"),
  await page.$eval("#console-body h3", (h) => h.textContent.trim()));

/* Reported: the sources were a table you could only read. Every row opens a
   guide for someone meeting the source for the first time. */
{
  const closed = await page.$$eval(".src-detail", (rows) => rows.filter((r) => !r.hidden).length);
  await page.click(".src-row:nth-of-type(3) td[data-label='Weight']");
  await page.waitForTimeout(200);
  const guide = await page.evaluate(() => {
    const btn = document.querySelectorAll(".src-open")[1];
    const detail = document.getElementById(btn.getAttribute("aria-controls"));
    return { expanded: btn.getAttribute("aria-expanded"), shown: !detail.hidden, text: detail.textContent,
      sources: document.querySelectorAll(".src-open").length, guides: document.querySelectorAll(".src-guide").length };
  });
  check("each intelligence source opens a guide that says why it is asked and what it gives",
    closed === 0 && guide.expanded === "true" && guide.shown && /Why IntelPulse asks it/.test(guide.text) &&
      /What it gives back/.test(guide.text) && guide.sources === guide.guides && guide.sources >= 8,
    JSON.stringify({ closed, expanded: guide.expanded, shown: guide.shown, sources: guide.sources }));
  await page.focus(".src-open");
  await page.keyboard.press("Enter");
  check("a source guide opens from the keyboard too",
    await page.$eval(".src-open", (b) => b.getAttribute("aria-expanded") === "true"));
}

await page.evaluate(() => {
  [...document.querySelectorAll("#side-nav-full .nav-item")].find((n) => n.dataset.pane === "campaigns")?.click();
});
await page.waitForTimeout(600);
check("picking a view puts it in the address bar",
  (await page.evaluate(() => location.hash)) === "#/console/campaigns",
  await page.evaluate(() => location.hash));

await page.reload({ waitUntil: "domcontentloaded" });
await page.waitForTimeout(1100);
check("and it survives a reload",
  (await page.$eval("#console-body h3", (h) => h.textContent)).includes("Campaign graph"));

/* Measure what is actually painted under the browser chrome rather than
   trusting the tag: read the topmost non-fixed surface at the top of the
   viewport and take the colour it starts with. */
/* Ten sidebar entries sit between the top of the console and the findings.
   The first Tab should offer a way past them — and taking it must not navigate. */
for (const [where, hash, target] of [
  ["the site", "#/home", "page-home"],
  ["the console", "#/console/all-findings", "console-body"]
]) {
  await page.evaluate((h) => { location.hash = h; }, hash);
  /* Reload rather than blur: it is the only way to be sure the tab sequence
     starts at the top of the document and not wherever the last check left it. */
  await page.reload({ waitUntil: "domcontentloaded" });
  await page.waitForTimeout(1100);
  await page.keyboard.press("Tab");
  const first = await page.evaluate(() => document.activeElement.id);
  check("the first tab stop on " + where + " is the skip link", first === "skip", first || "(none)");
  await page.keyboard.press("Enter");
  await page.waitForTimeout(500);
  check("taking it lands in the content, not another page",
    (await page.evaluate(() => document.activeElement.id)) === target &&
    (await page.evaluate(() => location.hash)) === hash,
    (await page.evaluate(() => document.activeElement.id)) + " @ " + (await page.evaluate(() => location.hash)));
}

/* A panel with no rows should say why, not sit blank under its heading. The
   dataset is bundled today, which is exactly why the empty branch is easy to
   forget — it never fires until the data comes from somewhere real. */
await page.evaluate(() => { location.hash = "#/console/dashboard"; });
await page.waitForTimeout(800);
check("the console fills in behind its skeleton",
  (await page.$$(".skeleton")).length === 0 &&
  (await page.$$eval("#console-panels .card", (e) => e.length)) >= 4,
  (await page.$$eval("#console-panels .card", (e) => e.length)) + " panels");

await page.evaluate(() => { window.IntelPulseSuite.data.findings.length = 0; });
await page.evaluate(() => { location.hash = "#/console/sources"; });
await page.waitForTimeout(600);
await page.evaluate(() => { location.hash = "#/console/dashboard"; });
await page.waitForTimeout(800);
const emptied = await page.$$eval(".empty-state", (els) =>
  els.map((el) => el.textContent.replace(/\s+/g, " ").trim()));
check("an empty dataset renders a reason, not a blank table",
  emptied.length >= 1 && /No indicators yet/.test(emptied[0] || ""),
  emptied[0] || "(nothing)");
check("the empty state says what would fill it",
  /workbench/i.test(emptied[0] || ""), (emptied[0] || "").slice(0, 70));

await page.reload({ waitUntil: "domcontentloaded" });
await page.waitForTimeout(1100);

/* A hash is user input. "#/console/__proto__" is a URL anyone can type, and a
   bare object lookup answers it with Object.prototype, or with a function
   ("constructor", "hasOwnProperty") that is then called. */
for (const junk of ["__proto__", "constructor", "hasOwnProperty", "toString", "nope"]) {
  await page.evaluate((h) => { location.hash = "#/console/" + h; }, junk);
  await page.waitForTimeout(500);
  const heading = await page.$eval("#console-body h3", (h) => h.textContent.trim()).catch(() => "");
  check("#/console/" + junk + " falls back to the dashboard",
    heading.length > 0 && heading !== "undefined", heading || "(nothing rendered)");
}

/* Redrawing on a theme flip must redraw the view that is open — swapping the
   body back to the dashboard leaves the URL and the sidebar lying about it. */
await page.evaluate(() => { location.hash = "#/console/sources"; });
await page.waitForTimeout(600);
await page.click("#theme-btn");
await page.waitForTimeout(900);
check("flipping the theme keeps the open view",
  (await page.$eval("#console-body h3", (h) => h.textContent)).includes("Intelligence sources"),
  await page.$eval("#console-body h3", (h) => h.textContent.trim()));
await page.click("#theme-btn");
await page.waitForTimeout(900);

/* The theme toggle swaps inside document.startViewTransition() with a 560ms
   reveal. While that runs, the live content sits behind the transition's
   snapshot and elementsFromPoint() returns only <html> — so a fixed wait read
   an empty paint whenever the transition started late, which under load it
   does. Measured: 18 of 20 runs empty on main, arriving from deep in the page.
   The product was right the whole time (the sky's first stop is exactly the
   meta colour in both themes); the test was reading the page mid-animation.
   Wait for the transition to finish instead of guessing how long it takes. */
const themeSettled = () => page.waitForFunction(() => !document.getAnimations().some((a) =>
  String((a.effect && a.effect.pseudoElement) || "").includes("view-transition")), null, { timeout: 4000 });

const chrome = async () => page.evaluate(() => {
  const stack = document.elementsFromPoint(Math.round(innerWidth / 2), 2);
  const el = stack.find((n) => getComputedStyle(n).position !== "fixed" &&
    getComputedStyle(n).background !== "none") || document.body;
  let paint = "";
  for (let n = el; n && !paint; n = n.parentElement) {
    const cs = getComputedStyle(n);
    const stop = cs.backgroundImage.match(/rgba?\([\d.,\s]+\)/);
    if (stop) paint = stop[0];
    else if (cs.backgroundColor && cs.backgroundColor !== "rgba(0, 0, 0, 0)") paint = cs.backgroundColor;
  }
  const rgb = (paint.match(/[\d.]+/g) || []).slice(0, 3).map(Number);
  return {
    meta: document.querySelector('meta[name="theme-color"]').content.trim().toLowerCase(),
    paint: "#" + rgb.map((n) => Math.round(n).toString(16).padStart(2, "0")).join(""),
    where: el.tagName.toLowerCase() + "." + (el.className || "")
  };
});

for (const [where, hash] of [["the site", "#/home"], ["the console", "#/console/dashboard"]]) {
  // Instant: a smooth scroll to the top is an animation too.
  await page.evaluate((h) => { location.hash = h; scrollTo({ top: 0, behavior: "instant" }); }, hash);
  await page.waitForTimeout(700);
  await themeSettled();
  const light = await chrome();
  check("the browser chrome matches " + where, light.meta === light.paint,
    light.meta + " vs " + light.paint + " (" + light.where + ")");
  await page.click("#theme-btn");
  await page.waitForTimeout(900);
  await themeSettled();
  const dark = await chrome();
  check("and still matches it in the dark", dark.meta === dark.paint,
    dark.meta + " vs " + dark.paint);
  check("so the chrome changed with the theme", light.meta !== dark.meta,
    light.meta + " \u2192 " + dark.meta);
  await page.click("#theme-btn");
  await page.waitForTimeout(900);
}

/* ──────────────────────────────────────────────── footer and anchors
   The footer's "Notify me" form went: it told visitors they were subscribed
   with no backend behind it. What replaced it is checked here in a real
   browser rather than only statically. */
await page.evaluate(() => { location.hash = "#/home"; });
await page.waitForTimeout(500);
const foot = await page.$$eval("footer.foot a", (links) => links.map((a) => ({
  href: a.getAttribute("href"), target: a.target, rel: a.rel, text: a.textContent.trim()
})));
const external = foot.filter((l) => /^https?:/.test(l.href));
check("every footer link that leaves the site opens safely in a new tab",
  external.length > 0 && external.every((l) => l.target === "_blank" && /noopener/.test(l.rel)),
  external.length + " external, " + external.filter((l) => !/noopener/.test(l.rel)).length + " without noopener");
check("the footer has no two links to the same place",
  new Set(foot.map((l) => l.href)).size === foot.length,
  foot.length + " links, " + new Set(foot.map((l) => l.href)).size + " destinations");
await page.click('footer.foot a[data-route="console"]');
await page.waitForTimeout(700);
check("the footer's console link opens the console, not a scroll position",
  (await page.evaluate(() => location.hash)).startsWith("#/console"));
await page.evaluate(() => { location.hash = "#/home"; });
await page.waitForTimeout(500);

await page.evaluate(() => { scrollTo(0, 0); location.hash = "#how"; });
await page.waitForTimeout(1100);
const heading = await page.$eval("#how h2", (el) => el.getBoundingClientRect().top);
const navBottom = await page.$eval("#nav", (el) => el.getBoundingClientRect().bottom);
check("an anchor jump clears the floating nav", heading > navBottom - 4,
  "heading at " + Math.round(heading) + ", nav ends at " + Math.round(navBottom));

/* ───────────────────────────────────────────────────────── responsive */
for (const width of [390, 768, 1280]) {
  await page.setViewportSize({ width, height: 900 });
  await page.evaluate(() => { location.hash = "#/home"; scrollTo(0, 0); });
  await page.waitForTimeout(800);
  const overflow = await page.evaluate(() =>
    document.documentElement.scrollWidth - document.documentElement.clientWidth);
  check("no sideways scroll at " + width + "px", overflow === 0, overflow + "px over");
  const fit = await page.evaluate(() => {
    const frame = document.querySelector("#preview").getBoundingClientRect();
    const shot = document.querySelector("#preview-scaler .console").getBoundingClientRect();
    return { left: shot.left - frame.left, right: frame.right - shot.right, width: shot.width };
  });
  check("the hero mock sits inside its frame at " + width + "px",
    fit.left > -2 && fit.right > -2 && fit.width > 40,
    "left " + Math.round(fit.left) + ", right " + Math.round(fit.right));
}
await page.setViewportSize({ width: 1440, height: 1000 });

/* ──────────────────────────────────────────────────── reduced motion */
const still = await browser.newPage({ viewport: { width: 1280, height: 900 }, reducedMotion: "reduce" });
const stillErrors = [];
still.on("pageerror", (e) => stillErrors.push(e.message));
await still.goto(BASE, { waitUntil: "domcontentloaded" });
await still.waitForTimeout(1000);
await still.evaluate(() => document.querySelector("#sources").scrollIntoView({ block: "center" }));
await still.waitForTimeout(400);
const quiet0 = await still.evaluate(() => document.querySelector("#marquee").scrollLeft);
await still.waitForTimeout(1200);
const quiet1 = await still.evaluate(() => document.querySelector("#marquee").scrollLeft);
check("the rail holds still for prefers-reduced-motion", Math.abs(quiet1 - quiet0) < 1);
await still.evaluate(() => scrollTo(0, 0));
await still.waitForTimeout(300);
check("reduced motion still reveals the sections",
  await still.$eval("#how .rise", (el) => getComputedStyle(el).opacity === "1"));
await still.click("#theme-btn");
await still.waitForTimeout(500);
check("the theme button works without the wipe",
  await still.evaluate(() => document.documentElement.dataset.theme) === "dark");
check("reduced motion raises no errors", stillErrors.length === 0, stillErrors[0]);
await still.close();

/* ───────────────────────────────────────────────────────────── errors */
check("the page raises no script errors", errors.length === 0, errors.slice(0, 3).join(" | "));

await browser.close();
console.log("\n" + (failures ? failures + " FAILED" : "all checks passed"));
process.exit(failures ? 1 : 0);
