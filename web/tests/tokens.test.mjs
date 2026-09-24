/* Design-system guards.
 *
 * The rules in .claude/skills/design-system-intelpulse/SKILL.md are only real
 * if something fails when they are broken. This file is that something: it
 * enforces the rules that are checkable statically, so the next change — mine
 * or an agent's — cannot quietly reintroduce a raw hex or a `transition: all`.
 *
 * Run: node --test web/tests/
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const assets = join(here, "..", "assets");
const read = (name) => readFileSync(join(assets, name), "utf8");

/* tokens.css is the reference palette: every value in it was validated there
   (contrast, the ordinal ramp, the severity washes) and SKILL.md documents it.
   suite.css is the stylesheet the pages load; the guards below hold the values
   it copies to the reference, so a recolour happens in one place. */
const SUITE_CSS = read("suite.css");
const TOKENS_CSS = read("tokens.css");
const SOURCES = ["charts.js", "console-panes.js"].map((name) => [name, read(name)]);

/** Strip comments so a hex quoted in prose does not fail the build. */
const stripComments = (css) => css.replace(/\/\*[\s\S]*?\*\//g, "");

/**
 * Pull out every at-rule body by matching braces. A newline-anchored regex
 * silently swallows the rules after a single-line `@keyframes`, which is how
 * this guard first "found" a violation that was not there.
 */
function extractBlocks(css, atRule) {
  const blocks = [];
  let index = css.indexOf(atRule);
  while (index !== -1) {
    const open = css.indexOf("{", index);
    if (open === -1) break;
    let depth = 0;
    let cursor = open;
    for (; cursor < css.length; cursor++) {
      if (css[cursor] === "{") depth++;
      else if (css[cursor] === "}" && --depth === 0) break;
    }
    blocks.push(css.slice(open + 1, cursor));
    index = css.indexOf(atRule, cursor);
  }
  return blocks;
}

/* The token blocks of a sheet: the light :root and the dark override. */
function tokenBlocks(css) {
  const body = (selector) => {
    const at = css.indexOf(selector + " {");
    return at < 0 ? "" : css.slice(at, css.indexOf("}", at));
  };
  return { light: body(":root"), dark: body(':root[data-theme="dark"]') };
}

test("the workbench and graph styles take their colour from tokens", () => {
  /* suite.css predates this rule and still carries raw colour in the site's
     own rules; the workbench and graph rules (.wb, .cg) were written to it and
     are held to it. */
  const offenders = [];
  for (const [, selector, body] of stripComments(SUITE_CSS).matchAll(/([^{}]+)\{([^{}]*)\}/g)) {
    if (!/(^|[\s,>+~])\.(wb|cg)[-\s.:,[>]|(^|[\s,>+~])\.(wb|cg)$/m.test(selector.trim())) continue;
    if (/#[0-9a-fA-F]{3,8}\b/.test(body)) offenders.push(selector.trim().replace(/\s+/g, " ").slice(0, 60));
  }
  assert.deepEqual(offenders, [], "raw hex in workbench or graph rules: " + JSON.stringify(offenders));
});

test("component JavaScript never hard-codes a colour", () => {
  for (const [name, source] of SOURCES) {
    const code = source.replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, "");
    const hits = code.match(/#[0-9a-fA-F]{6}\b/g) || [];
    // The only permitted literals are the documented fallbacks for a missing
    // custom property, which must sit next to a themeColor() call.
    const allowed = hits.filter((hex) => new RegExp('themeColor\\([^)]*\\)\\s*\\|\\|\\s*"' + hex + '"').test(code)
      || new RegExp('"' + hex + '"\\s*\\)').test(code));
    assert.equal(hits.length - allowed.length, 0,
      name + " hard-codes " + JSON.stringify(hits.filter((h) => !allowed.includes(h))));
  }
});

test("the evidence ramp is complete in both themes", () => {
  /* This used to slice from ":root {" to the first '[data-theme="light"]',
     which is inside the prefers-color-scheme block at the end of the file: the
     "dark" slice held both themes and the "light" one held only that fallback. */
  const blocks = tokenBlocks(TOKENS_CSS);
  for (const scope of ["dark", "light"]) {
    const block = blocks[scope];
    assert.ok(block, "tokens.css has no " + scope + " token block");
    for (let step = 1; step <= 5; step++) {
      assert.match(block, new RegExp("--ramp-" + step + ":\\s*#[0-9a-f]{6}", "i"),
        scope + " theme is missing --ramp-" + step);
    }
  }
});

test("every severity has a token in both themes", () => {
  for (const name of ["critical", "high", "medium", "low", "info", "ok"]) {
    const matches = TOKENS_CSS.match(new RegExp("--sev-" + name + ":", "g")) || [];
    assert.ok(matches.length >= 2, "--sev-" + name + " is not defined for both themes");
  }
});

test("only transform and opacity are animated", () => {
  assert.doesNotMatch(SUITE_CSS, /transition:\s*all/, "transition: all is forbidden");
  const keyframeBodies = extractBlocks(stripComments(SUITE_CSS), "@keyframes");
  assert.ok(keyframeBodies.length >= 4, "found only " + keyframeBodies.length + " @keyframes");
  const animatable = /^(transform|opacity|translate|scale|rotate|box-shadow|background|content|)$/;
  for (const body of keyframeBodies) {
    /* After a brace or a semicolon, not only at the start of a line: every
       keyframe in suite.css is written on one line, and a line-anchored match
       read none of them. */
    const properties = [...body.matchAll(/(?:^|[{;])\s*([a-z-]+)\s*:/gm)].map((m) => m[1]);
    for (const property of properties) {
      assert.match(property, animatable, "animating " + property + " is not allowed");
    }
  }
});

test("reduced motion, forced colours and coarse pointers are all handled", () => {
  assert.match(SUITE_CSS, /@media \(prefers-reduced-motion: reduce\)/);
  assert.match(SUITE_CSS, /@media \(forced-colors: active\)/);
  assert.match(SUITE_CSS, /@media \(pointer: coarse\)/);
});

test("every custom property suite.css reads is one it defines", () => {
  /* --r-md was read in two rules and defined nowhere, so both fell back to a
     radius of zero without a word. A var() with its own fallback is exempt. */
  const css = stripComments(SUITE_CSS);
  const defined = new Set([...css.matchAll(/(--[\w-]+)\s*:/g)].map((m) => m[1]));
  const missing = [...new Set([...css.matchAll(/var\((--[\w-]+)\s*\)/g)].map((m) => m[1]))]
    .filter((name) => !defined.has(name));
  assert.deepEqual(missing, [], "read but never defined: " + missing.join(", "));
});

test("suite.css carries the severity and ramp values exactly as validated", () => {
  const values = (block) => Object.fromEntries([...block.matchAll(/(--(?:sev|ramp)-[\w-]+):\s*([^;]+);/g)]
    .map((m) => [m[1], m[2].trim().toLowerCase().replace(/\s+/g, " ")]));
  const suite = tokenBlocks(SUITE_CSS), reference = tokenBlocks(TOKENS_CSS);
  for (const theme of ["light", "dark"]) {
    const want = values(reference[theme]), have = values(suite[theme]);
    assert.ok(Object.keys(want).length >= 17, "tokens.css " + theme + " lost its severity tokens");
    for (const [name, value] of Object.entries(want)) {
      assert.equal(have[name], value, "suite.css " + theme + " " + name + " is " + have[name] + ", tokens.css says " + value);
    }
  }
});

/* ─────────────────── Web Interface Guidelines, the checkable subset
 * Fetched rules, not remembered ones: github.com/vercel-labs/web-interface-guidelines
 */
/* workbench.html and explorer.html are redirects into the console now. They
   stay in the list: a page is still a page, and the stubs are held to the same
   rules as the one they point at. */
const PAGES = ["index.html", "workbench.html", "explorer.html"]
  .map((name) => [name, readFileSync(join(here, "..", name), "utf8")]);
const SHEETS = [["suite.css", SUITE_CSS]];

test("no focus outline is removed without a visible replacement", () => {
  for (const [name, css] of SHEETS) {
    for (const rule of stripComments(css).split("}")) {
      if (!/outline:\s*none/.test(rule)) continue;
      assert.match(rule, /box-shadow|outline-offset|border-color/,
        name + " drops the focus ring with nothing in its place: " + rule.trim().slice(0, 70));
    }
  }
});

test("every icon-only control has an accessible name", () => {
  for (const [name, html] of PAGES) {
    const buttons = html.match(/<(?:button|a)\b[^>]*>[\s\S]*?<\/(?:button|a)>/g) || [];
    for (const tag of buttons) {
      const open = tag.slice(0, tag.indexOf(">") + 1);
      const inner = tag.slice(open.length, tag.lastIndexOf("<"));
      // text left once markup and entities are stripped
      const words = inner.replace(/<[^>]*>/g, "").replace(/&[a-z]+;/g, "").trim();
      if (words.length > 0) continue;
      assert.match(open, /aria-label=/,
        name + " has an icon-only control with no aria-label: " + open.slice(0, 70));
    }
  }
});

/* Walk the markup keeping a stack of whether a translate="no" ancestor is open.
   Only standalone wordmarks (a text node that is nothing but the brand) are
   checked — prose that happens to mention the product should still translate. */
function unmarkedWordmarks(html) {
  const VOID = new Set(["meta", "link", "img", "br", "hr", "input", "use", "path",
    "source", "area", "col", "embed", "track", "wbr", "circle", "rect", "line"]);
  const token = /<\/?([a-z][a-z0-9]*)\b([^>]*?)(\/?)>|(?<=>)IntelPulse(?=<)/gi;
  const open = [];
  const strays = [];
  let m;
  while ((m = token.exec(html))) {
    if (m[0][0] === "I") {                                   // a text node that is only the wordmark
      if (!open.some((e) => e.marked)) strays.push(html.slice(Math.max(0, m.index - 70), m.index + 12));
      continue;
    }
    const name = m[1].toLowerCase();
    if (m[0][1] === "/") {
      const at = open.map((e) => e.name).lastIndexOf(name);
      if (at >= 0) open.length = at;                         // also drops anything left unclosed
    } else if (!VOID.has(name) && m[3] !== "/") {
      open.push({ name, marked: /translate="no"/.test(m[2]) });
    }
  }
  return strays;
}

/* WCAG relative luminance, so a colour decision is computed rather than
   eyeballed. Both themes, both stylesheets: dark mode is not inferred from
   light-mode values, because a ratio that holds on white can fail on #0d0f12. */
const srgb = (hexColour) => {
  let h = hexColour.replace("#", "");
  if (h.length === 3) h = [...h].map((c) => c + c).join("");
  return [0, 2, 4].map((i) => parseInt(h.slice(i, i + 2), 16));
};
const channel = (c) => (c / 255 <= 0.04045 ? c / 255 / 12.92 : ((c / 255 + 0.055) / 1.055) ** 2.4);
const luminance = (rgb) => 0.2126 * channel(rgb[0]) + 0.7152 * channel(rgb[1]) + 0.0722 * channel(rgb[2]);
function contrast(fg, bg) {
  const a = luminance(srgb(fg)), b = luminance(srgb(bg));
  const [hi, lo] = a > b ? [a, b] : [b, a];
  return (hi + 0.05) / (lo + 0.05);
}

function themeTokens(css) {
  const themes = { light: {}, dark: {} };
  for (const block of css.matchAll(/(:root(?:\[data-theme="dark"\])?)\s*\{([^}]*)\}/g)) {
    const into = block[1].includes("dark") ? themes.dark : themes.light;
    for (const decl of block[2].matchAll(/(--[\w-]+):\s*(#[0-9a-fA-F]{3,8})/g)) into[decl[1]] = decl[2];
  }
  return themes;
}

test("text clears WCAG on every surface, in both themes", () => {
  /* Body and secondary text carry the 4.5:1 body threshold; --ink-3 is the
     faint meta tier, held to 3:1. A pair only counts when the stylesheet
     declares both halves of it, so each sheet is checked on its own names. */
  const sheets = [
    ["suite.css", read("suite.css"), ["--paper", "--ground", "--ground-2"]],
    ["tokens.css", TOKENS_CSS, ["--surface-0", "--surface-1", "--surface-2", "--surface-3"]]
  ];
  let checked = 0;
  for (const [name, css, surfaces] of sheets) {
    const themes = themeTokens(css);
    for (const theme of ["light", "dark"]) {
      const t = themes[theme];
      for (const [ink, floor] of [["--ink", 4.5], ["--ink-2", 4.5], ["--ink-3", 3]]) {
        for (const surface of surfaces) {
          if (!t[ink] || !t[surface]) continue;
          const r = contrast(t[ink], t[surface]);
          checked++;
          assert.ok(r >= floor, name + " " + theme + ": " + ink + " on " + surface +
            " is " + r.toFixed(2) + ":1, under " + floor + ":1 (" + t[ink] + " on " + t[surface] + ")");
        }
      }
    }
  }
  assert.ok(checked >= 30, "only " + checked + " pairs were checked — the token names have moved");
});

test("the stylesheets agree on the shared ink tokens", () => {
  /* suite.css and tokens.css each declare the text ramp. Raising --ink-3 to
     clear 3:1 once meant editing every copy, and one was missed on the first
     pass (there were four then: explorer.html and a fallback in app.js too).
     Drift between them is a contrast bug nobody would look for. */
  const declared = (css) => {
    const root = css.slice(css.indexOf(":root {"), css.indexOf("}", css.indexOf(":root {")));
    return Object.fromEntries([...root.matchAll(/(--ink(?:-[23])?):\s*(#[0-9a-fA-F]{6})/g)]
      .map((m) => [m[1], m[2].toLowerCase()]));
  };
  const copies = [
    ["suite.css", declared(read("suite.css"))],
    ["tokens.css", declared(TOKENS_CSS)]
  ];
  const [, reference] = copies[0];
  for (const token of ["--ink", "--ink-2", "--ink-3"]) {
    for (const [name, values] of copies) {
      assert.equal(values[token], reference[token],
        name + " declares " + token + " as " + values[token] +
        " while suite.css says " + reference[token]);
    }
  }
});

test("a modal scrim is dark enough to isolate what it sits under", () => {
  /* Below about 40% the page behind a drawer or a dialog still competes for
     attention on a light surface. The console's drawer and the workbench's
     scoring dialog sit on the same page and should isolate it the same way. */
  const alphaOf = (match) => Number(match[1].split(",")[3]);
  const drawer = SUITE_CSS.match(/\.drawer-scrim\s*\{[^}]*rgba\(([^)]+)\)/);
  const dialog = SUITE_CSS.match(/\.wb-dialog::backdrop\s*\{[^}]*rgba\(([^)]+)\)/);
  assert.ok(drawer, "suite.css declares no drawer scrim");
  assert.ok(dialog, "suite.css declares no backdrop for the workbench dialog");
  for (const [name, alpha] of [["drawer", alphaOf(drawer)], ["dialog", alphaOf(dialog)]]) {
    assert.ok(alpha >= 0.4 && alpha <= 0.6,
      "the " + name + " scrim is " + Math.round(alpha * 100) + "% — outside the 40-60% band");
  }
  assert.ok(Math.abs(alphaOf(drawer) - alphaOf(dialog)) <= 0.06,
    "the drawer and the dialog scrim differently: " + alphaOf(drawer) + " vs " + alphaOf(dialog));
});

test("an icon's stroke is set by its size, not by whoever added it", () => {
  /* Icons are drawn in a 24-unit viewBox, so the stroke a reader SEES is
     stroke-width x rendered-size / 24. Holding that near 1.2px keeps every
     icon the same visual weight whatever its box — which is why the scale runs
     the opposite way to the sizes. Before this guard, 15px icons shipped with
     five different stroke widths (1.8, 1.9, 2.0, 2.1 and 2.3), which is drift
     wearing the costume of optical compensation. */
  const TIERS = [[9, 3], [12, 2.4], [14, 2.1], [17, 1.8]];
  const strokeFor = (px) => (TIERS.find(([limit]) => px <= limit) || [0, 1.3])[1];

  const wrong = [];
  for (const [name, css] of [["suite.css", SUITE_CSS]]) {
    for (const rule of stripComments(css).split("}")) {
      const size = rule.match(/width:\s*(\d+)px/);
      const stroke = rule.match(/stroke-width:\s*([\d.]+)/);
      if (!size || !stroke) continue;
      const want = strokeFor(Number(size[1]));
      if (Number(stroke[1]) !== want) {
        wrong.push(`${name}: ${size[1]}px icon has stroke ${stroke[1]}, expected ${want}`);
      }
    }
  }
  assert.deepEqual(wrong, [], wrong.join(" | "));
});

test("every page has exactly one h1", () => {
  for (const [name, html] of PAGES) {
    const ones = [...html.matchAll(/<h1\b/g)].length;
    assert.equal(ones, 1, name + " has " + ones + " level-one headings");
  }
});

test("heading levels never skip a rank", () => {
  /* A jump from h2 to h4 reads as a missing section to anything navigating by
     heading. The campaign graph's h1 is visually hidden — a page whose content
     is a canvas still needs a heading. */
  for (const [name, html] of PAGES) {
    const levels = [...html.matchAll(/<h([1-6])\b/g)].map((m) => Number(m[1]));
    for (let i = 1; i < levels.length; i++) {
      assert.ok(levels[i] - levels[i - 1] <= 1,
        name + " jumps h" + levels[i - 1] + " to h" + levels[i] +
        " (" + levels.map((l) => "h" + l).join(" ") + ")");
    }
  }
});

test("the brand wordmark is not offered to auto-translation", () => {
  for (const [name, html] of PAGES) {
    const strays = unmarkedWordmarks(html);
    assert.deepEqual(strays, [],
      name + " renders the wordmark with no translate=\"no\" above it: " + strays.join(" | "));
  }
});

test("scrollable overlays contain their scroll", () => {
  const suite = SUITE_CSS;
  const drawer = suite.slice(suite.indexOf("#console-side {"), suite.indexOf("#console-side {") + 400);
  assert.match(drawer, /overscroll-behavior/,
    "the console drawer scrolls the page behind it once it hits its end");
});

/* This used to check the one email field on index.html by slicing from its
   first occurrence. That field belonged to the footer's "Notify me" form,
   which is gone (it told visitors they were subscribed with no backend to
   subscribe them to). A slice from indexOf(-1) would then have checked the
   last 260 characters of the page and failed for the wrong reason, so the
   guard now walks every email field on every page: it still fires the day
   someone adds one without the right attributes. */
test("no email field invites a spellchecker or the wrong keyboard", () => {
  for (const [name, html] of PAGES) {
    for (const match of html.matchAll(/<input[^>]*type="email"[^>]*>/g)) {
      assert.match(match[0], /spellcheck="false"/, name + ": email input still spellchecks");
      assert.match(match[0], /inputmode="email"/, name + ": email input does not ask for the email keyboard");
    }
  }
});

/* Reported from a phone: "whenever I click on footer links it opens mostly the
   same page". It did. Nineteen links led to seven places, nine of them to the
   same #sources anchor -- including four named after vendors (AbuseIPDB,
   GreyNoise...) that read as external links and were not. */
function footerOf(html) {
  const start = html.indexOf("<footer");
  return start < 0 ? "" : html.slice(start, html.indexOf("</footer>", start));
}
const footerLinks = (html) =>
  [...footerOf(html).matchAll(/<a\b[^>]*href="([^"]+)"[^>]*>([\s\S]*?)<\/a>/g)]
    .map((m) => ({ href: m[1], text: m[2].replace(/<[^>]+>/g, "").trim() }));

test("every footer link goes somewhere different", () => {
  const index = PAGES.find(([n]) => n === "index.html")[1];
  const links = footerLinks(index);
  assert.ok(links.length > 0, "the footer has no links at all");
  const seen = new Map();
  for (const { href, text } of links) {
    assert.ok(!seen.has(href),
      "footer links \u201c" + seen.get(href) + "\u201d and \u201c" + text + "\u201d both go to " + href);
    seen.set(href, text);
  }
});

test("the footer does not scroll the page it is already on", () => {
  // In-page sections are what the header navigation is for. A footer link that
  // only scrolls back up the same page is the complaint, verbatim.
  const index = PAGES.find(([n]) => n === "index.html")[1];
  const scrolls = footerLinks(index).filter(({ href }) => /^#[a-z]/i.test(href));
  assert.equal(scrolls.length, 0,
    "footer links that only scroll this page: " + scrolls.map((l) => l.text + " \u2192 " + l.href).join(", "));
});

test("the footer carries what a visitor actually looks for there", () => {
  const index = PAGES.find(([n]) => n === "index.html")[1];
  const hrefs = footerLinks(index).map((l) => l.href);
  assert.ok(hrefs.some((h) => h.includes("github.com")), "no link to the source code");
  assert.ok(hrefs.some((h) => h.startsWith("https://vinitrami-soc.github.io")), "no link back to the author");
  assert.ok(hrefs.includes("#/console/workbench"), "no link to the workbench, the thing the page is selling");
});

test("no form claims to subscribe anyone", () => {
  // There is no backend on the demo. "You are on the list" was not true.
  // Comments are stripped first: the one explaining why the form went would
  // otherwise trip the check, and a visitor never reads a comment.
  for (const [name, html] of PAGES) {
    const visible = html.replace(/<!--[\s\S]*?-->/g, "");
    assert.ok(!/on the list|Notify me|subscribed/i.test(visible),
      name + " still offers a subscription it cannot honour");
  }
});

test("the skill file and the implementation agree on the token names", () => {
  const skill = readFileSync(
    join(here, "..", "..", ".claude", "skills", "design-system-intelpulse", "SKILL.md"), "utf8");
  for (const token of ["--surface-0", "--ink-3", "--accent", "--ramp-1", "--sev-critical"]) {
    assert.ok(skill.includes(token), "SKILL.md does not document " + token);
    assert.ok(TOKENS_CSS.includes(token), "tokens.css does not define " + token);
  }
});
