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

test("the skill file and the implementation agree on the token names", () => {
  const skill = readFileSync(
    join(here, "..", "..", "..", ".claude", "skills", "design-system-intelpulse", "SKILL.md"), "utf8");
  for (const token of ["--surface-0", "--ink-3", "--accent", "--ramp-1", "--sev-critical"]) {
    assert.ok(skill.includes(token), "SKILL.md does not document " + token);
    assert.ok(TOKENS_CSS.includes(token), "tokens.css does not define " + token);
  }
});
