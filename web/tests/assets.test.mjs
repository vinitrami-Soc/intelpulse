/* One origin for everything a page loads.
 *
 * The console used to fetch Outfit and JetBrains Mono from Google Fonts, which
 * told a third party every time someone opened a SOC tool. The fonts are
 * bundled now (SIL OFL 1.1); these guards keep it that way and keep the bundle
 * whole.
 *
 * Run: node --test web/tests/
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const web = join(dirname(fileURLToPath(import.meta.url)), "..");
const pages = readdirSync(web).filter((name) => name.endsWith(".html"));

test("no page loads a stylesheet, script, font or image from another host", () => {
  for (const name of pages) {
    const html = readFileSync(join(web, name), "utf8");
    /* <a href> may leave the site (the source code, the author); nothing a page loads may */
    const loads = [...html.matchAll(/<(link|script|img|source|iframe)\b[^>]*\b(?:href|src)\s*=\s*["']([^"']+)["']/gi)]
      .map((m) => m[2]);
    for (const url of loads) {
      assert.ok(!/^(https?:)?\/\//i.test(url), `${name} loads ${url} from another host`);
    }
    assert.doesNotMatch(html, /fonts\.(googleapis|gstatic)\.com/, `${name} still mentions Google Fonts`);
  }
});

test("every bundled font file exists, and so do the licences", () => {
  const css = readFileSync(join(web, "assets", "fonts.css"), "utf8");
  const files = [...css.matchAll(/url\("([^"]+)"\)/g)].map((m) => m[1]);
  assert.ok(files.length >= 4, "fonts.css names no files");
  for (const file of files) {
    assert.ok(existsSync(join(web, "assets", file)), `fonts.css names ${file}, which is missing`);
  }
  for (const licence of ["Outfit-OFL.txt", "JetBrainsMono-OFL.txt"]) {
    const text = readFileSync(join(web, "assets", "fonts", licence), "utf8");
    assert.match(text, /SIL Open Font License, Version 1\.1/, `${licence} is not the OFL`);
  }
});

test("the fonts are declared under the names the design tokens use", () => {
  const css = readFileSync(join(web, "assets", "fonts.css"), "utf8");
  const tokens = readFileSync(join(web, "assets", "tokens.css"), "utf8");
  for (const family of ["Outfit", "JetBrains Mono"]) {
    assert.ok(css.includes(`font-family: "${family}"`), `fonts.css does not declare ${family}`);
    assert.ok(tokens.includes(`"${family}"`), `tokens.css does not use ${family}`);
  }
  const index = readFileSync(join(web, "index.html"), "utf8");
  assert.ok(index.indexOf("assets/fonts.css") < index.indexOf("assets/suite.css"),
    "index.html must load fonts.css before suite.css");
});
