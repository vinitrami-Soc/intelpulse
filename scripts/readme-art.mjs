/* The README's key art: docs/readme/*.png, from docs/readme/art.html.
 *
 *   PLAYWRIGHT_MODULE=.../playwright/index.mjs node scripts/readme-art.mjs
 *
 * It serves the repository on 127.0.0.1 for the length of the run, takes two fresh shots of the
 * public demo (the workbench on the firewall sample, and its "How was this scored?" dialog, in the
 * dark theme) into docs/readme/shots/, then saves each <section class="slide"> of art.html as
 * docs/readme/<id>.png at twice the pixels, and the repository's social preview at 1280 x 640.
 * The server views it shows come from docs/screenshots/server-*.png: make those first with
 * scripts/screenshots-server.mjs. Everything in them is sample data (RFC 5737, made-up names).
 */
import { createServer } from "node:http";
import { mkdirSync, readFileSync, statSync } from "node:fs";
import { dirname, extname, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";

const { chromium } = await import(process.env.PLAYWRIGHT_MODULE || "playwright");
const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const OUT = join(ROOT, "docs", "readme");
mkdirSync(join(OUT, "shots"), { recursive: true });

const TYPES = { ".html": "text/html", ".css": "text/css", ".js": "text/javascript", ".json": "application/json",
  ".png": "image/png", ".gif": "image/gif", ".svg": "image/svg+xml", ".woff2": "font/woff2" };
const server = createServer((req, res) => {
  const path = normalize(decodeURIComponent(new URL(req.url, "http://x").pathname)).replace(/^([/\\])+/, "");
  const file = join(ROOT, path.endsWith("/") || path === "" ? join(path, "index.html") : path);
  try {
    if (!file.startsWith(ROOT) || !statSync(file).isFile()) throw new Error("no");
    res.writeHead(200, { "Content-Type": TYPES[extname(file)] || "application/octet-stream" });
    res.end(readFileSync(file));
  } catch {
    res.writeHead(404).end();
  }
});
await new Promise((ok) => server.listen(0, "127.0.0.1", ok));
const BASE = `http://127.0.0.1:${server.address().port}/`;

const browser = await chromium.launch();

/* 1. the demo, dark, on the firewall sample */
const demo = await browser.newPage({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 2 });
await demo.goto(BASE + "web/index.html", { waitUntil: "load" });
await demo.evaluate(() => localStorage.setItem("ip:theme", JSON.stringify("dark")));
await demo.goto(BASE + "web/index.html#/console/workbench", { waitUntil: "load" });
await demo.reload({ waitUntil: "load" });   // the theme is read once, at load
/* the site's floating bar, the assistant and the back-to-top button would sit over the findings */
await demo.addStyleTag({ content: ".nav-shell, .ai-fab, .to-top, #progress { display: none !important; }" });
await demo.waitForSelector('.wb-starter[data-scenario="firewall"]');
await demo.click('.wb-starter[data-scenario="firewall"]');
await demo.waitForSelector("#wb-results:not([hidden]) .wb-ioc", { timeout: 10000 });
await demo.waitForTimeout(1200);
await demo.evaluate(() => {
  const results = document.querySelector("#wb-results");
  window.scrollTo({ top: results.getBoundingClientRect().top + window.scrollY - 24, behavior: "instant" });
});
await demo.waitForTimeout(600);
await demo.screenshot({ path: join(OUT, "shots", "workbench.png") });
await demo.click("[data-math]");
await demo.waitForSelector("#wb-dialog[open]");
await demo.waitForTimeout(500);
await (await demo.$("#wb-dialog")).screenshot({ path: join(OUT, "shots", "scoring.png") });
await demo.close();
console.log("saved docs/readme/shots/workbench.png and scoring.png");

/* 2. the slides */
async function render(scale, ids) {
  /* One slide at a time, alone on a page the size of the slide: an element screenshot of a
     slide among others came out clipped at the wrong scale. */
  const page = await browser.newPage({ viewport: { width: 1400, height: 1200 }, deviceScaleFactor: scale });
  await page.goto(BASE + "docs/readme/art.html", { waitUntil: "load" });
  await page.evaluate(async () => {
    await document.fonts.ready;
    await Promise.all([...document.images].map((img) => img.decode().catch(() => {})));
  });
  for (const [id, file] of ids) {
    const size = await page.evaluate((only) => {
      document.body.style.padding = "0";
      document.body.style.display = "block";
      for (const slide of document.querySelectorAll(".slide")) slide.style.display = slide.id === only ? "" : "none";
      const box = document.getElementById(only).getBoundingClientRect();
      return { width: Math.round(box.width), height: Math.round(box.height) };
    }, id);
    await page.setViewportSize(size);
    await page.waitForTimeout(300);
    await page.screenshot({ path: join(OUT, file), omitBackground: true });
    console.log("saved docs/readme/" + file + " (" + size.width + " x " + size.height + ")");
  }
  await page.close();
}
await render(2, ["hero", "how", "work", "soc", "private", "numbers", "more"].map((id) => [id, id + ".png"]));
await render(1, [["social", "social-preview.png"]]);

await browser.close();
server.close();
