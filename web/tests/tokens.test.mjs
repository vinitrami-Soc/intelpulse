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

const APP_CSS = read("app.css");
const TOKENS_CSS = read("tokens.css");
const SOURCES = ["app.js", "charts.js", "cmdk.js"].map((name) => [name, read(name)]);

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

test("colour lives in tokens.css and nowhere else", () => {
  const offenders = stripComments(APP_CSS)
    .split("\n")
    .map((line, index) => [index + 1, line])
    .filter(([, line]) => /#[0-9a-fA-F]{3,8}\b/.test(line));
  assert.deepEqual(offenders, [], "raw hex in app.css: " + JSON.stringify(offenders));
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

test("the evidence ramp is complete and ordered in both themes", () => {
  for (const scope of ["dark", "light"]) {
    const block = scope === "dark"
      ? TOKENS_CSS.slice(TOKENS_CSS.indexOf(":root {"), TOKENS_CSS.indexOf('[data-theme="light"]'))
      : TOKENS_CSS.slice(TOKENS_CSS.indexOf('[data-theme="light"]'));
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
  assert.doesNotMatch(APP_CSS, /transition:\s*all/, "transition: all is forbidden");
  const keyframeBodies = extractBlocks(stripComments(APP_CSS), "@keyframes");
  const animatable = /^(transform|opacity|translate|scale|rotate|box-shadow|background|content|)$/;
  for (const body of keyframeBodies) {
    const properties = (body.match(/^\s*([a-z-]+):/gm) || [])
      .map((p) => p.trim().replace(":", ""));
    for (const property of properties) {
      assert.match(property, animatable, "animating " + property + " is not allowed");
    }
  }
});

test("reduced motion, forced colours and coarse pointers are all handled", () => {
  assert.match(APP_CSS, /@media \(prefers-reduced-motion: reduce\)/);
  assert.match(APP_CSS, /@media \(forced-colors: active\)/);
  assert.match(APP_CSS, /@media \(pointer: coarse\)/);
});

test("focus is never removed without a replacement", () => {
  const outlineNone = stripComments(APP_CSS).match(/outline:\s*none/g) || [];
  // Each one must sit in a rule that also sets a box-shadow ring.
  const rules = stripComments(APP_CSS).split("}");
  for (const rule of rules) {
    if (/outline:\s*none/.test(rule)) {
      assert.match(rule, /box-shadow/, "outline removed without a visible replacement: " + rule.trim().slice(0, 80));
    }
  }
  assert.ok(outlineNone.length <= 2, "too many outline:none rules to audit by hand");
});

/* ─────────────────── Web Interface Guidelines, the checkable subset
 * Fetched rules, not remembered ones: github.com/vercel-labs/web-interface-guidelines
 */
const PAGES = ["index.html", "workbench.html", "explorer.html"]
  .map((name) => [name, readFileSync(join(here, "..", name), "utf8")]);
const SHEETS = [["app.css", APP_CSS], ["suite.css", read("suite.css")],
  ["explorer.html", PAGES.find(([n]) => n === "explorer.html")[1]]];

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

test("the three surfaces agree on the shared ink tokens", () => {
  /* suite.css, tokens.css and explorer.html each declare the text ramp. That is
     three copies of the same decision, and raising --ink-3 to clear 3:1 meant
     editing all three — the fourth copy, a fallback in app.js, was missed on the
     first pass. Drift between them is a contrast bug nobody would look for. */
  const declared = (css) => {
    const root = css.slice(css.indexOf(":root {"), css.indexOf("}", css.indexOf(":root {")));
    return Object.fromEntries([...root.matchAll(/(--ink(?:-[23])?):\s*(#[0-9a-fA-F]{6})/g)]
      .map((m) => [m[1], m[2].toLowerCase()]));
  };
  const copies = [
    ["suite.css", declared(read("suite.css"))],
    ["tokens.css", declared(TOKENS_CSS)],
    ["explorer.html", declared(PAGES.find(([n]) => n === "explorer.html")[1])]
  ];
  const [, reference] = copies[0];
  for (const token of ["--ink", "--ink-2", "--ink-3"]) {
    for (const [name, values] of copies) {
      assert.equal(values[token], reference[token],
        name + " declares " + token + " as " + values[token] +
        " while suite.css says " + reference[token]);
    }
    /* app.js carries the documented fallback for when the property is missing. */
    const fallback = read("app.js").match(
      new RegExp('themeColor\\("' + token + '"\\)\\s*\\|\\|\\s*"(#[0-9a-fA-F]{6})"'));
    if (fallback) {
      assert.equal(fallback[1].toLowerCase(), reference[token],
        "app.js falls back to " + fallback[1] + " for " + token +
        " while the stylesheets say " + reference[token]);
    }
  }
});

test("a modal scrim is dark enough to isolate what it sits under", () => {
  /* Below about 40% the page behind a drawer or a command palette still
     competes for attention on a light surface; the site's own drawer scrim is
     at 42% and the workbench should not be weaker than it. Dark themes can go
     heavier, so only the light value is held to the band. */
  const light = TOKENS_CSS.match(/--overlay:\s*rgba\(([^)]+)\)/);
  assert.ok(light, "tokens.css declares no --overlay scrim");
  const alpha = Number(light[1].split(",")[3]);
  assert.ok(alpha >= 0.4 && alpha <= 0.6,
    "the light scrim is " + Math.round(alpha * 100) + "% — outside the 40-60% band");

  const site = read("suite.css").match(/\.drawer-scrim\s*\{[^}]*rgba\(([^)]+)\)/);
  assert.ok(site, "suite.css declares no drawer scrim");
  const siteAlpha = Number(site[1].split(",")[3]);
  assert.ok(Math.abs(siteAlpha - alpha) <= 0.06,
    "the two surfaces scrim differently: site " + siteAlpha + " vs workbench " + alpha);
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
  const suite = read("suite.css");
  const drawer = suite.slice(suite.indexOf("#console-side {"), suite.indexOf("#console-side {") + 400);
  assert.match(drawer, /overscroll-behavior/,
    "the console drawer scrolls the page behind it once it hits its end");
});

test("the email field does not invite a spellchecker or the wrong keyboard", () => {
  const index = PAGES.find(([n]) => n === "index.html")[1];
  const field = index.slice(index.indexOf('<input type="email"'), index.indexOf('<input type="email"') + 260);
  assert.match(field, /spellcheck="false"/, "email input still spellchecks");
  assert.match(field, /inputmode="email"/, "email input does not ask for the email keyboard");
});

test("the skill file and the implementation agree on the token names", () => {
  const skill = readFileSync(
    join(here, "..", "..", "..", ".claude", "skills", "design-system-intelpulse", "SKILL.md"), "utf8");
  for (const token of ["--surface-0", "--ink-3", "--accent", "--ramp-1", "--sev-critical"]) {
    assert.ok(skill.includes(token), "SKILL.md does not document " + token);
    assert.ok(TOKENS_CSS.includes(token), "tokens.css does not define " + token);
  }
});
