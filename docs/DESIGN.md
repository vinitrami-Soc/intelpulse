# Design system

IntelPulse is a tool people stare at for eight hours. The interface is built
for that: dense, keyboard-first, quiet by default, and loud only where the data
is actually alarming.

Reference points are the tools analysts already keep open — Linear and Raycast
for the command surface, Sentinel and Datadog for severity semantics and data
density — implemented with no framework and no build step, because the whole
dashboard has to serve identically from GitHub Pages, nginx or
`python -m http.server`.

---

## Colour, computed rather than chosen

The data-visualisation colours are validated with a script, not an eye. The
evidence ramp passes the full ordinal gate on **both** surfaces — monotone
lightness, ≥0.06 step gaps, light end ≥2:1 against its surface, single hue:

```
dark   #5346b0 #6d5ed4 #887aee #a79cf7 #c6befc   on #0b1020   ALL PASS
light  #b3a6ef #9587e6 #7768d6 #584ab8 #3b3190   on #fbfcfe   ALL PASS
```

In both themes `--ramp-5` is the *strongest* signal, so "more" reads as more in
dark mode (lighter) and in light mode (darker) without the chart code caring
which theme is live.

### Severity is not a palette problem

SOC semantics force red → orange → amber to sit next to each other, and no
honest stepping gets orange and amber past the normal-vision separation floor
while "red still means critical". Rather than pretend otherwise, severity is
encoded three times over:

| Channel | How |
| --- | --- |
| Hue | critical rose · high orange · medium amber · low sky · informational slate |
| Glyph | ▲ critical · ◆ high · ■ medium · ● low · ▬ informational · ✓ allowlisted |
| Text | every badge spells the verdict out |

No chart fill ever carries severity alone. The one chart with fills — the
evidence contribution bar — uses the validated single-hue ramp.

## The forms, chosen by the data's job

| What the reader needs | Form | Not |
| --- | --- | --- |
| The one number the case turns on | **Hero figure**, 52px, same sans as everything else | A gauge or donut |
| Why that number | **Horizontal bars**, one hue, sorted by weighted contribution, direct-labelled | A radar chart |
| How much to trust it | **Meter** — fill carries state, track is a lighter step of the same ramp | A second number pretending to be a score |
| Which sources answered | **One cell per provider**, labelled on hover | A donut of "coverage %" |
| The relationships | **Node graph** (Cytoscape, with a built-in SVG fallback) | A table of pairs |

Every chart ships a table view (`Show table`) — the WCAG-clean equivalent, not
an afterthought.

## Type

Inter for the interface; **JetBrains Mono only for machine data** — indicators,
hashes, log lines, numbers in columns. That split is what lets an analyst find
the evidence without reading it: if it is monospaced, a machine said it.
`tabular-nums` on columns, proportional figures on the hero.

## Space and elevation

A dense scale (4 / 8 / 12 / 16 / 24 / 32). Depth comes from a hairline border
plus a 1px inset highlight — not a drop shadow. The only real shadow in the
system belongs to things that genuinely float: the command palette, the sheet,
the graph toolbar, the toast.

## Motion

| Token | Duration | Use |
| --- | --- | --- |
| `--t-micro` | 110ms | hovers, presses, state flips |
| `--t-base` | 180ms | panels, theme swap, overlays in |
| `--t-slow` | 280ms | bars growing, cards rising |

Entrances use `cubic-bezier(.16, 1, .3, 1)`; exits leave faster. Only
`transform` and `opacity` are animated. The hero figure counts up because the
eye follows a rise and lands on the number — and it does not, at all, under
`prefers-reduced-motion`, which the whole system honours in one rule.

## Interaction model

The command palette (<kbd>⌘K</kbd>) is the primary surface once you know the
tool: fuzzy subsequence matching over labels, groups and keywords, with recent
commands weighted up.

| Key | Action |
| --- | --- |
| `⌘K` | Command palette |
| `⌘↵` | Run triage |
| `/` | Focus the ingest box |
| `g i` / `g g` / `g t` / `g h` | Indicators · Graph · Ticket · History |
| `t` | Cycle theme (dark → light → system) |
| `[` | Collapse the rail |
| `?` | Shortcut sheet |
| `Esc` | Close any overlay |

A pending `g` owns the next key, so `g t` reaches the ticket instead of
toggling the theme. Tabs are deep-linkable (`#graph`, `#report`), so a URL
pasted into a ticket opens the view it describes.

## Accessibility

Skip link; one `h1` and hierarchical headings; `aria-label` on every icon-only
button and `aria-hidden` on decorative glyphs; `role="dialog"`/`aria-modal` on
overlays with focus return; `aria-expanded` on disclosures; an `aria-live`
region for toasts; visible `:focus-visible` rings everywhere; `touch-action:
manipulation` and deliberate tap-highlight; `overscroll-behavior: contain` in
scrollable overlays; safe-area insets on the shell. Verified at 390 / 768 /
1024 / 1440px with zero horizontal overflow.

Destructive actions are reversible rather than confirmed: **Clear** offers an
undo in the toast instead of a dialog an analyst has to dismiss mid-shift.

## Easter eggs

Small, deliberate, and never in the way of the data:

1. **Konami code** (`↑↑↓↓←→←→ B A`) — "night watch": a CRT scanline wash and
   green accents for the 03:00 shift. Also in the palette as *Toggle
   night-watch mode*. Cosmetic only; it never touches a verdict.
2. **`sudo` at the start of a paste** — the tool answers politely and triages
   anyway.
3. **Console banner** — an ASCII wordmark and a pointer to
   `window.IntelPulseEngine`, because the scoring is meant to be audited.
4. **Double-click the hero figure** — opens the scoring arithmetic for the
   worst indicator: weighted mean, authority floor, modifiers, final verdict.
   Hidden, but genuinely useful; also reachable from every indicator's
   **Scoring math** button.

## The rules are machine-readable, and enforced

The design system is not only written down for people — it ships as an agent
skill at [`.claude/skills/design-system-intelpulse/SKILL.md`](../../.claude/skills/design-system-intelpulse/SKILL.md),
authored to the [TypeUI](https://github.com/rodgersgitau/type-ui) skill
blueprint with the `enterprise` skill from
[awesome-design-skills](https://github.com/bergside/awesome-design-skills) (MIT)
as the starting point: dark cloud-platform surfaces, modular grid, strong data
hierarchy. The token values, chart rules and severity encoding are this
project's own and are validated here, not inherited.

That format matters because the next change to this UI will probably be made by
an agent. `SKILL.md` states each rule as **must** or **should**, anchors every
one to a token or a threshold, and pairs each do-rule with a concrete
don't-example — so "use semantic tokens" is not advice, it is a constraint.

A rule nothing can fail is decoration, so the checkable ones have guards in
`web/tests/tokens.test.mjs`:

| Rule | Guard |
| --- | --- |
| Colour lives in `tokens.css` | no raw hex in `app.css`, or in component JS beyond one documented fallback |
| Both themes are complete | every `--ramp-1..5` and every `--sev-*` defined twice |
| Only `transform`/`opacity` animate | keyframe bodies parsed by brace matching; `transition: all` banned |
| Motion, contrast and touch are handled | `prefers-reduced-motion`, `forced-colors`, `pointer: coarse` blocks must exist |
| Focus is never removed silently | any `outline: none` must sit with a `box-shadow` ring |
| The skill and the code agree | token names in `SKILL.md` must exist in `tokens.css` |

The browser suite covers what only a browser can answer: 44px touch targets on
a coarse pointer, meaning surviving `forced-colors: active`, inline field
errors taking focus, `aria-busy` during a run.

Writing those guards immediately caught three of my own violations — `#fff` on
the wordmark, hard-coded hexes in the console banner and the `theme-color`
meta — and one bug in the guard itself, where a newline-anchored regex swallowed
the rules after a single-line `@keyframes` and reported a violation that did
not exist.

## The shareable demo build

`make artifact` (`scripts/build-artifact.mjs`) emits `dist/artifact/` — the same
app with the outer document removed and the meta CSP dropped, for hosts that
supply their own. The assets ship unchanged, so what a reviewer clicks is this
repo's code rather than a mock-up of it.

One behaviour differs by necessity: embedded hosts block script-started
downloads, so when the page detects it is framed, **Download .md / .json** copies
the ticket to the clipboard and says so, and the graph export opens in a new
tab. A button that silently does nothing is worse than one that tells you where
the file went.

## Why no framework

Three static files, no build step, no `node_modules`, no supply chain. A
reviewer clones the repo and opens `web/index.html`. The trade-off is that
demo-mode scoring is implemented twice (Python and JavaScript) — which is why
`web/tests/engine.test.mjs` pins the JS engine to the Python rules.
