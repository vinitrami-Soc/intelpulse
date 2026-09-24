---
name: design-system-intelpulse
description: Implementation-ready design rules for the IntelPulse triage workbench — tokens, component states, chart forms, and accessibility gates. Use when creating or changing any UI in web/.
---

<!-- Authored to the TypeUI skill blueprint (github.com/rodgersgitau/type-ui,
     registry: github.com/bergside/awesome-design-skills, MIT), taking the
     `enterprise` skill as the starting point: dark cloud-platform surfaces,
     modular grid, strong data hierarchy. Values below are this project's own
     and are validated in-repo, not inherited. -->
<!-- TYPEUI_SH_MANAGED_START -->

# IntelPulse Design System

## Mission
IntelPulse is a security-operations triage console an analyst stares at for a
whole shift. The interface must make the evidence behind a verdict findable in
seconds, stay readable at 03:00, and never let decoration compete with data.

## Brand
- Product: IntelPulse — threat intelligence & triage workbench
- Audience: SOC analysts and blue-team engineers, keyboard-first, high alert volume
- Surface: dense single-page web dashboard (demo build on GitHub Pages, live build against a FastAPI service)

## Style Foundations
- Visual style: dark-first cloud-platform console; hairline borders and a 1px
  inset highlight instead of drop shadows; glass only on things that float
  (the scoring dialog, the graph readout, the toast, the assistant)
- Typography: Inter for interface, JetBrains Mono **only** for machine data
  (indicators, hashes, log lines, numeric columns). Scale 10/11/12/13/14/15/20/52
- Spacing: 4 / 8 / 12 / 16 / 24 / 32 / 48 (dense dashboard rhythm, 4px base)
- Radii: 6 / 10 / 14 / 999
- Motion: `--t-micro` 110ms · `--t-base` 180ms · `--t-slow` 280ms;
  entrances `cubic-bezier(.16,1,.3,1)`, exits faster
- Colour tokens live in `web/assets/tokens.css`. Semantic names only:
  `--surface-0..3`, `--line`, `--line-2`, `--ink`, `--ink-2`, `--ink-3`,
  `--accent`, `--ramp-1..5`, `--sev-critical|high|medium|low|info|ok`

### Validated data-visualisation colour
- The evidence ramp **must** pass the ordinal gate on both surfaces (monotone
  lightness, ≥0.06 step gaps, light end ≥2:1 vs surface, single hue):
  dark `#5346b0 #6d5ed4 #887aee #a79cf7 #c6befc` on `#0b1020`;
  light `#b3a6ef #9587e6 #7768d6 #584ab8 #3b3190` on `#fbfcfe`.
- `--ramp-5` **must** always be the strongest signal in whichever theme is live.
- Severity **must not** be encoded by colour alone. SOC semantics force
  red→orange→amber adjacency, which cannot clear the normal-vision separation
  floor, so every severity carries hue **and** a glyph (▲ critical, ◆ high,
  ■ medium, ● low, ▬ informational, ✓ allowlisted) **and** the verdict in text.
- New palettes **must** be re-validated before use; do not eyeball contrast.

## One palette, one stylesheet

The site and the console (`web/index.html`) — including the analyst workbench
and the campaign graph, which are console views (`#/console/workbench`,
`#/console/campaigns`, built in `assets/console-panes.js`) — load one
stylesheet, `assets/suite.css`. `assets/tokens.css` is the validated reference:
the severity and ramp values in `suite.css` **must** equal it, and a guard fails
the build when they drift. Workbench and graph rules are scoped under `.wb` /
`.cg` and **must not** carry raw colour. It is one light-first palette: one hot accent `--accent` `#fe5729`, warm-biased neutrals, Outfit for
interface, JetBrains Mono for machine data only.

- **Two flames, and they are not interchangeable.** `--accent` carries fills,
  rules and glows. Anything with text on it, and any accent-coloured text, uses
  `--accent-strong` `#d93d15` — white on `--accent` is 3.18:1.
- **The evidence ramp is azure, not warm.** Flame owns the accent and the
  severity end of the scale; a warm ramp reads as "this is bad" at every step.
- **Recompute, never recolour.** A palette change means re-running the ordinal
  gate for the ramp and the 4.5:1 check for every severity against its card,
  its page AND its own tinted wash. The wash is the one that gets missed.
- **Graph categories are validated against the field they sit on**, at both its
  brightest and its deepest point, with an OKLab separation floor of 0.12.

## Accessibility
- Target: WCAG 2.2 AA, keyboard-first.
- Every interactive element **must** have a visible `:focus-visible` ring
  (2px `--accent`, 2px offset). Never remove an outline without a replacement.
- Icon-only controls **must** carry `aria-label`; decorative glyphs **must**
  carry `aria-hidden="true"`.
- Overlays **must** use `role="dialog"` + `aria-modal`, trap focus, close on
  Escape, and return focus to the trigger.
- Disclosures **must** expose `aria-expanded`; async status **must** land in an
  `aria-live="polite"` region; in-flight controls **must** set `aria-busy`.
- Controls **must** clear 44×44px under `@media (pointer: coarse)`.
- `prefers-reduced-motion: reduce` **must** disable animation, not just shorten it.
- `forced-colors: active` **must** keep meaning: any fill that carries meaning
  gains an outline, focus uses `Highlight`.
- There **must** be no horizontal overflow at 390 / 768 / 1024 / 1440px.

## Writing Tone
Concise, operational, second person where it helps. Name the fix in an error.
Say what a number means, not how impressive it is. No exclamation marks.

## Rules: Do
- Use semantic tokens.
  *Don't:* `color: #f43f5e` in a component — use `var(--sev-critical)`.
- Define every state a control can be in: default, hover, focus-visible, active,
  disabled, loading, error.
  *Don't:* an input that only styles `:focus` and shows failures in a toast.
- Put errors next to the field, set `aria-invalid`, and move focus there.
  *Don't:* a red toast that disappears before the analyst reads it.
- Pick the chart form from the data's job: one number → hero figure; magnitude
  by category → one-hue bars; a single ratio → meter; relationships → graph.
  *Don't:* a donut for coverage, a gauge for a score, or two y-axes.
- Ship a table view beside any chart.
  *Don't:* a canvas an assistive-tech user cannot read.
- Make destructive actions reversible.
  *Don't:* a confirm dialog for clearing a text box — offer undo instead.
- Reserve monospace for machine data.
  *Don't:* monospaced body copy because it "looks technical".
- State the data's provenance on screen (demo vs live) wherever a verdict shows.
  *Don't:* present sample data in a way that could be read as vendor output.

## Rules: Don't
- Do not encode severity, status or any meaning through colour alone.
- Do not animate anything but `transform` and `opacity`; never `transition: all`.
- Do not use drop shadows for depth on static surfaces; use a border + inset.
- Do not introduce a spacing or type value outside the scale.
- Do not render provider- or log-derived text without escaping it, or a
  provider-supplied URL without an `http(s)` scheme check.
- Do not let a sticky bar cover a scroll target — set `scroll-margin-top`.
- Do not add a dependency to the dashboard; it ships as static files.

## Expected Behavior
- Foundations first, then components, then copy.
- When aesthetics and accessibility conflict, accessibility wins and the
  trade-off is written down.
- Prefer one honest number with its evidence over a denser screen.

## Guideline Authoring Workflow
1. Restate the design intent in one sentence.
2. Define tokens and constraints before components.
3. Specify anatomy, variants, states and interaction per component.
4. Add testable accessibility acceptance criteria.
5. Add anti-patterns and migration notes.
6. End with a QA checklist that runs in review.

## Required Output Structure
Context and goals · design tokens and foundations · component rules (anatomy,
variants, states, responsive behaviour) · accessibility acceptance criteria ·
content and tone with examples · anti-patterns · QA checklist.

## Component Rule Expectations
- Keyboard, pointer and touch behaviour **must** all be specified.
- Spacing, type and colour **must** be named as tokens.
- Long labels, overflow, empty and loading states **must** be handled; a card
  holds a 64-character hash without breaking the grid.
- Lists **should** page at 25 items rather than render unbounded DOM.

## Quality Gates
Run before calling any UI change done:
- [ ] `make test-web` — engine parity plus the static design guards.
- [ ] `make test-ui` — 307 Chromium checks, all green.
- [ ] Every new rule anchors to a token, a threshold or an example.
- [ ] Every new control has all seven states.
- [ ] Keyboard-only pass: reach every action, escape every overlay.
- [ ] Both themes reviewed on the same screen, not just dark.
- [ ] Re-run the palette validator if any data colour changed.
- [ ] Screenshot at 390px and 1440px; no horizontal scrollbar.

## Example Constraint Language
- "must" = non-negotiable; "should" = recommendation.
- Anchor to numbers: "44×44px", "≥2:1 against the surface", "180ms".
- Pair every do-rule with a concrete don't-example, as above.

<!-- TYPEUI_SH_MANAGED_END -->
