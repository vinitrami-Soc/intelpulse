/* Browser tests for phones and tablets, and for the assistant panel.
 *
 * The site suite drives a desktop viewport. These are the checks that only
 * fail on a small screen — and the reason the file exists is that they did:
 * below 900px the console kept its two-column grid, so the entire main column
 * was laid out off-screen and clipped away by the shell's own overflow. The
 * page reported zero horizontal overflow the whole time, which is exactly why
 * "no overflow" is not the same thing as "usable on a phone".
 *
 * Run:  python3 -m http.server 8123 --directory web   # one terminal
 *       node web/tests/mobile.spec.mjs                # another
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

async function phone(width = 390, height = 844) {
  const context = await browser.newContext({
    viewport: { width, height }, hasTouch: true, isMobile: true, deviceScaleFactor: 2
  });
  const page = await context.newPage();
  const errors = [];
  page.on("pageerror", (e) => errors.push(e.message));
  page.on("console", (m) => {
    if (m.type() === "error" && !/net::|favicon|font/i.test(m.text())) errors.push("console: " + m.text());
  });
  await page.goto(BASE, { waitUntil: "domcontentloaded" });
  await page.waitForTimeout(1300);
  return { context, page, errors };
}

/* ─────────────────────────────────────────── layout, every screen size */
for (const [name, width, height] of [
  ["phone 360", 360, 740], ["phone 390", 390, 844], ["phone landscape", 844, 390],
  ["tablet 768", 768, 1024], ["tablet 820", 820, 1180], ["tablet landscape", 1024, 768]
]) {
  const { context, page } = await phone(width, height);
  for (const route of ["home", "console"]) {
    await page.evaluate((r) => { location.hash = r === "console" ? "#/console" : "#/home"; scrollTo(0, 0); }, route);
    await page.waitForTimeout(700);
    const shot = await page.evaluate(() => {
      const de = document.documentElement;
      const body = document.querySelector("#console-body");
      /* The hero mock is a scaled, inert picture of the console — its contents
         are not controls and must not be measured as if they were. */
      const live = (el) => !el.closest("#preview") && !el.closest("[inert]");
      /* A control inside a CLOSED overlay is not being offered to anyone, and it
         measures small because the panel is scaled down while hidden. Ask the
         browser what is actually visible rather than guessing from offsetParent,
         which is null for every position:fixed element anyway. */
      const shown = (el) => el.checkVisibility
        ? el.checkVisibility({ opacityProperty: true, visibilityProperty: true })
        : el.offsetParent !== null;
      const small = [];
      document.querySelectorAll('button, a[href], input, [role="button"]').forEach((el) => {
        const r = el.getBoundingClientRect();
        if (r.width < 1 || r.height < 1 || !shown(el) || !live(el)) return;
        if (r.height < 43.5 || r.width < 30) {
          small.push((el.textContent || el.getAttribute("aria-label") || el.tagName)
            .trim().replace(/\s+/g, " ").slice(0, 24) + " " + Math.round(r.width) + "x" + Math.round(r.height));
        }
      });
      return {
        overflow: de.scrollWidth - de.clientWidth,
        small,
        mainWidth: body ? Math.round(body.getBoundingClientRect().width) : null,
        viewport: de.clientWidth
      };
    });
    check("no sideways scroll on " + name + " (" + route + ")", shot.overflow === 0, shot.overflow + "px over");
    check("every control clears 44px on " + name + " (" + route + ")", shot.small.length === 0,
      shot.small.slice(0, 4).join(" · "));
    /* The regression this file was written for. Above 900px two columns are
       correct, so the rule only applies where the rail becomes a drawer. */
    if (route === "console" && width <= 900) {
      check("the console body fills the screen on " + name,
        shot.mainWidth !== null && shot.mainWidth > shot.viewport * 0.8,
        shot.mainWidth + "px of " + shot.viewport + "px");
    }
  }
  await context.close();
}

/* ───────────────────────────────────────────────────── the nav drawer */
{
  const { context, page, errors } = await phone();
  check("the burger appears on a phone", await page.$eval("#burger", (el) => el.offsetParent !== null));
  await page.tap("#burger");
  await page.waitForTimeout(450);
  check("the burger opens the menu", await page.$eval("#menu", (el) => el.classList.contains("on")));
  check("the menu says it is open", await page.$eval("#burger", (el) => el.getAttribute("aria-expanded")) === "true");
  const links = await page.$$eval("#menu a, #menu button", (els) => els.map((e) => e.textContent.trim()));
  check("the menu carries every section the desktop nav has", links.length >= 7, links.length + " entries");
  check("the menu reaches the workbench and the graph",
    (await page.$$eval("#menu a", (els) => els.map((e) => e.getAttribute("href"))))
      .filter((h) => /workbench|explorer/.test(h)).length === 2);
  await page.touchscreen.tap(195, 800);
  await page.waitForTimeout(450);
  check("tapping away closes the menu", !(await page.$eval("#menu", (el) => el.classList.contains("on"))));

  await page.tap("#burger");
  await page.waitForTimeout(400);
  await page.keyboard.press("Escape");
  await page.waitForTimeout(400);
  check("Escape closes the menu", !(await page.$eval("#menu", (el) => el.classList.contains("on"))));

  await page.tap("#burger");
  await page.waitForTimeout(400);
  await page.tap('#menu a[href="#sources"]');
  await page.waitForTimeout(1200);
  check("a menu link scrolls the page and closes the menu",
    (await page.evaluate(() => Math.round(scrollY))) > 200 &&
    !(await page.$eval("#menu", (el) => el.classList.contains("on"))));

  check("the pill drops its call to action so it cannot wrap",
    await page.$eval("#nav-cta", (el) => getComputedStyle(el).display === "none"));
  check("the drawer carries that call to action instead",
    (await page.$eval("#menu-cta", (el) => el.textContent.trim())).includes("Open console"));
  await page.evaluate(() => { location.hash = "#/console"; });
  await page.waitForTimeout(700);
  check("and its label flips with the route",
    (await page.$eval("#menu-cta", (el) => el.textContent.trim())).includes("Back to site"));
  check("the nav drawer raises no errors", errors.length === 0, errors[0]);
  await context.close();
}

/* ───────────────────────────────────────────────── the console drawer */
{
  const { context, page } = await phone();
  await page.evaluate(() => { location.hash = "#/console"; });
  await page.waitForTimeout(800);
  check("the rail is off-canvas until asked for",
    await page.$eval("#console-side", (el) => el.getBoundingClientRect().right < 1));
  await page.tap("#c-collapse");
  await page.waitForTimeout(500);
  check("the header button opens the rail", await page.$eval("#console-full", (el) => el.classList.contains("drawer")));
  check("the rail is on screen once open",
    await page.$eval("#console-side", (el) => el.getBoundingClientRect().left > -2));
  await page.tap('#side-nav-full .nav-item[data-pane="campaigns"]');
  await page.waitForTimeout(700);
  check("choosing a pane changes the view and puts the rail away",
    (await page.$eval("#console-body h3", (h) => h.textContent)).includes("Campaigns") &&
    !(await page.$eval("#console-full", (el) => el.classList.contains("drawer"))));
  check("only the dashboard gets the wave",
    !(await page.$eval("#console-body h3", (h) => h.textContent)).includes("\u{1F44B}"));

  /* Re-picking the view that is already open assigns the same hash, which fires
     no hashchange. If the router is the only thing that closes the drawer, the
     phone is left with an open rail over a locked page — a dead end. */
  await page.tap("#c-collapse");
  await page.waitForTimeout(450);
  await page.tap('#side-nav-full .nav-item[data-pane="campaigns"]');
  await page.waitForTimeout(700);
  check("re-picking the open view still puts the rail away",
    !(await page.$eval("#console-full", (el) => el.classList.contains("drawer"))) &&
    (await page.evaluate(() => document.body.style.overflow)) !== "hidden",
    "drawer " + (await page.$eval("#console-full", (el) => el.className)) +
    " / body overflow " + (await page.evaluate(() => document.body.style.overflow || "(none)")));

  await page.tap("#c-collapse");
  await page.waitForTimeout(450);
  await page.keyboard.press("Escape");
  await page.waitForTimeout(450);
  check("Escape closes the rail", !(await page.$eval("#console-full", (el) => el.classList.contains("drawer"))));

  await page.tap("#c-collapse");
  await page.waitForTimeout(450);
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.waitForTimeout(600);
  check("growing the window does not strand the drawer open",
    !(await page.$eval("#console-full", (el) => el.classList.contains("drawer"))) &&
    (await page.evaluate(() => document.body.style.overflow)) !== "hidden");
  await context.close();
}

/* ──────────────────────────────────────── readable data on a phone */
{
  const { context, page } = await phone();
  await page.evaluate(() => { location.hash = "#/console"; });
  await page.waitForTimeout(900);
  const bands = await page.$$eval("#console-body [data-sev] span", (els) =>
    els.map((el) => ({ text: el.textContent.trim(), clipped: el.scrollWidth > el.clientWidth + 1 })));
  check("severity labels are not cut short", bands.length === 5 && bands.every((b) => !b.clipped),
    bands.map((b) => b.text).join(", "));
  const table = await page.evaluate(() => {
    const wrap = document.querySelector("#console-body .table-wrap");
    const card = wrap.closest(".card");
    return {
      spill: Math.round(wrap.getBoundingClientRect().right - card.getBoundingClientRect().right),
      scrolls: wrap.scrollWidth > wrap.clientWidth
    };
  });
  check("the findings table stays in its card and scrolls instead of squeezing",
    table.spill <= 0 && table.scrolls, "spill " + table.spill + "px");
  await context.close();
}

/* The hero mock contains a picture of the console rail. A drawer rule written
   for ".side" matched it too and pinned that picture to the viewport. */
{
  const { context, page } = await phone();
  const mock = await page.evaluate(() => {
    const side = document.querySelector("#preview .side");
    const frame = document.querySelector("#preview").getBoundingClientRect();
    const box = side.getBoundingClientRect();
    return {
      position: getComputedStyle(side).position,
      inside: box.left >= frame.left - 2 && box.right <= frame.right + 2
    };
  });
  check("the hero mock's own rail stays inside the mock",
    mock.position === "static" && mock.inside, "position " + mock.position + ", inside " + mock.inside);
  await context.close();
}

/* Controls that only exist once an overlay is open still have to be tappable. */
{
  const { context, page } = await phone();
  /* Measure only the overlay under test: a CLOSED panel is scaled down while
     hidden, so its buttons read as 43px and would fail for the wrong reason. */
  const measure = (selector) => page.evaluate((sel) => {
    const small = [];
    document.querySelectorAll(sel)
      .forEach((el) => {
        const r = el.getBoundingClientRect();
        if (r.width < 1 || r.height < 1) return;
        if (r.height < 43.5) small.push((el.textContent || el.getAttribute("aria-label") || el.tagName)
          .trim().replace(/\s+/g, " ").slice(0, 24) + " " + Math.round(r.height));
      });
    return small;
  }, selector);
  await page.tap("#burger");
  await page.waitForTimeout(450);
  let small = await measure(".menu a, .menu button");
  check("the open nav drawer clears 44px", small.length === 0, small.slice(0, 3).join(" · "));
  await page.keyboard.press("Escape");
  await page.waitForTimeout(350);
  await page.tap("#ai-fab");
  await page.waitForTimeout(500);
  small = await measure("#ai-panel button, #ai-panel input");
  check("the open assistant clears 44px", small.length === 0, small.slice(0, 3).join(" · "));
  await page.keyboard.press("Escape");
  await page.waitForTimeout(350);
  await page.evaluate(() => { location.hash = "#/console"; });
  await page.waitForTimeout(800);
  await page.tap("#c-collapse");
  await page.waitForTimeout(500);
  small = await measure("#console-side button");
  check("the open console rail clears 44px", small.length === 0, small.slice(0, 3).join(" · "));
  await context.close();
}

/* ───────────────────────────────── hero type answers to a short screen */
{
  const { context, page } = await phone(844, 390);
  const fit = await page.evaluate(() => {
    const h = document.querySelector(".hero h1").getBoundingClientRect();
    return { height: Math.round(h.height), viewport: innerHeight };
  });
  check("the hero headline does not fill a landscape phone", fit.height < fit.viewport * 0.5,
    fit.height + "px of " + fit.viewport + "px");
  await context.close();
}

/* ══════════════════════════════════════════════════════ the assistant */
{
  const { context, page, errors } = await phone(1280, 900);
  check("the assistant offers itself without being hunted for",
    await page.$eval("#ai-fab", (el) => {
      const r = el.getBoundingClientRect();
      return r.width > 0 && r.height > 0 && r.bottom <= innerHeight + 1 && r.right <= innerWidth + 1;
    }));
  await page.click("#ai-fab");
  await page.waitForTimeout(500);
  check("the button opens the panel", await page.$eval("#ai-panel", (el) => el.classList.contains("on")));
  check("it greets you once", (await page.$$("#ai-log .ai-msg.bot")).length === 1);
  check("it says where its answers come from",
    (await page.$eval("#ai-note, .ai-note", (el) => el.textContent)).includes("No model is called"));

  const last = () => page.evaluate(() => {
    const all = [...document.querySelectorAll("#ai-log .ai-msg.bot .ai-bubble")];
    return all[all.length - 1].textContent;
  });
  async function ask(question) {
    await page.fill("#ai-input", question);
    await page.click("#ai-form button");
    await page.waitForTimeout(340);
    return last();
  }

  /* Each expected fragment is a fact that lives in the repository, so a wrong
     answer here means the panel and the code have drifted apart. */
  const QA = [
    ["how is the score calculated", "weighted mean"],
    ["what is the authority floor", "0.95"],
    ["what weights do you use", "1.2"],
    ["what are the verdict bands", "85 and above"],
    ["how confident are you in a score", "separately"],
    ["what does greynoise benign do", "0.45"],
    ["which sources do you query", "AbuseIPDB"],
    ["can it work without api keys", "Feodo"],
    ["what can I paste into it", "SHA256"],
    ["tell me about ssrf", "allowlisted"],
    ["is this real data", "RFC 5737"],
    ["does anything leave my browser", "Nothing leaves"],
    ["what is critical right now", "203.0.113.10"],
    ["how many findings are there", "40 findings"],
    ["what is the attack surface", "68"],
    ["which month was busiest", "Apr"],
    ["how do I install it", "docker compose"],
    ["what is intelpulse", "single pass"]
  ];
  let wrong = [];
  for (const [question, want] of QA) {
    const answer = await ask(question);
    if (!answer.includes(want)) wrong.push(question + " (wanted “" + want + "”)");
  }
  check("it answers what it claims to know", wrong.length === 0,
    wrong.length ? wrong.slice(0, 3).join("; ") : QA.length + " questions, all correct");

  const dunno = await ask("what is the best pizza in Naples");
  check("it says it does not know rather than inventing an answer",
    dunno.includes("do not have an answer"), dunno.replace(/\s+/g, " ").slice(0, 60));

  /* It echoes what you typed, so it has to encode it. */
  let alerted = false;
  page.on("dialog", async (d) => { alerted = true; await d.dismiss(); });
  await ask('<img src=x onerror="alert(1)"> <script>alert(2)</script>');
  await page.waitForTimeout(400);
  const injected = await page.evaluate(() =>
    document.querySelectorAll("#ai-log img, #ai-log script").length);
  check("a question cannot inject markup", injected === 0 && !alerted,
    injected + " nodes, alert " + alerted);

  await page.click("#ai-chips button");
  await page.waitForTimeout(420);
  check("the suggested questions work", (await last()).length > 40);

  const before = await page.evaluate(() => location.hash);
  await page.click('#ai-log [data-act="console"]');
  await page.waitForTimeout(700);
  check("an answer's action actually goes somewhere",
    (await page.evaluate(() => location.hash)) !== before &&
    (await page.evaluate(() => location.hash)).includes("console"));

  await page.keyboard.press("Escape");
  await page.waitForTimeout(400);
  check("Escape closes the panel", !(await page.$eval("#ai-panel", (el) => el.classList.contains("on"))));
  await page.keyboard.press("?");
  await page.waitForTimeout(400);
  check("? opens it again", await page.$eval("#ai-panel", (el) => el.classList.contains("on")));

  check("the assistant raises no errors", errors.length === 0, errors[0]);
  await context.close();
}

/* the panel has to fit the screen it is on, including a long code answer */
for (const [name, width, height] of [["desktop", 1440, 900], ["tablet", 768, 1024], ["phone", 390, 844]]) {
  const { context, page } = await phone(width, height);
  await page.click("#ai-fab");
  await page.waitForTimeout(450);
  await page.fill("#ai-input", "how is the score calculated");
  await page.click("#ai-form button");
  await page.waitForTimeout(500);
  const fit = await page.evaluate(() => {
    const panel = document.querySelector("#ai-panel").getBoundingClientRect();
    let spill = 0;
    document.querySelectorAll("#ai-log *").forEach((el) => {
      const r = el.getBoundingClientRect();
      spill = Math.max(spill, Math.round(r.right - panel.right), Math.round(panel.left - r.left));
    });
    return {
      spill,
      onScreen: panel.right <= innerWidth + 1 && panel.left >= -1 && panel.bottom <= innerHeight + 1,
      pageOverflow: document.documentElement.scrollWidth - document.documentElement.clientWidth
    };
  });
  check("the assistant fits its panel on " + name, fit.spill <= 0 && fit.onScreen && fit.pageOverflow === 0,
    "spill " + fit.spill + "px, on screen " + fit.onScreen + ", page over " + fit.pageOverflow + "px");
  await context.close();
}

await browser.close();
console.log("\n" + (failures ? failures + " FAILED" : "all checks passed"));
process.exit(failures ? 1 : 0);
