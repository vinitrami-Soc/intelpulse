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
| The relationships | **Node graph**, SVG drawn in the page, with the pairs listed underneath | A table of pairs on its own |

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
system belongs to things that genuinely float: the scoring dialog, the graph
readout, the toast, the assistant.

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

The workbench and the campaign graph are views in the console, so they move
the way the rest of it does: the sidebar picks a view, and every view has an
address (`#/console/workbench`, `#/console/campaigns`) that can be pasted into
a ticket, bookmarked or reloaded.

| Key | Action |
| --- | --- |
| `Ctrl ↵` / `⌘ ↵` | Run triage, from anywhere in the workbench |
| `Tab`, then `Enter` | Reach a graph node and open it — an indicator's evidence, or a cluster's readout |
| `Esc` | Close the scoring dialog or the graph readout; focus goes back where it was |

The workbench's own page used to carry a command palette, `g`-key sequences
and a shortcut sheet. They switched between that page's tabs and did not come
into the console, which has one scrolling view per address and a sidebar that
is always on screen.

## Accessibility

Skip link; one `h1` and hierarchical headings; `aria-label` on every icon-only
button and `aria-hidden` on decorative glyphs; `role="dialog"`/`aria-modal` on
overlays with focus return; `aria-expanded` on disclosures; an `aria-live`
region for toasts; visible `:focus-visible` rings everywhere; `touch-action:
manipulation` and deliberate tap-highlight; `overscroll-behavior: contain` in
scrollable overlays; safe-area insets on the shell. Verified at 390 / 768 /
1024 / 1440px with zero horizontal overflow.

Destructive actions are reversible rather than confirmed: **Clear** offers an
undo right under the box instead of a dialog an analyst has to dismiss
mid-shift.

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
| Colour lives in tokens | no raw hex in the workbench and graph rules of `suite.css`, or in component JS |
| One set of values | every `--sev-*` and `--ramp-*` in `suite.css` equals the validated value in `tokens.css`, both themes |
| Nothing reads a token that is not there | every `var(--x)` in `suite.css` without a fallback names a defined property |
| Both themes are complete | every `--ramp-1..5` and every `--sev-*` defined in each theme |
| Only `transform`/`opacity` animate | keyframe bodies parsed by brace matching; `transition: all` banned |
| Motion, contrast and touch are handled | `prefers-reduced-motion`, `forced-colors`, `pointer: coarse` blocks must exist |
| Focus is never removed silently | any `outline: none` must sit with a visible replacement in the same rule |
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

## The site and the console

`web/index.html` is the page a visitor lands on: a light, sky-gradient marketing
page with a console route behind it. It was built to a set of reference shots of
a light cybersecurity SaaS — the brief was the *composition*, not the company.

What was taken: the light sky gradient with soft cloud shapes, the floating pill
navigation, a single hot accent (`--flame`, `#fe5729`) against near-black text,
glass cards with generous radii, the alternating text/figure showcase rows, the
device mock of the product under the hero, the sources rail, and the rounded
call-to-action band above the footer. What was not taken: any wordmark, logo,
copy or claim belonging to anyone. Every figure on the page is IntelPulse's own
synthetic dataset, and the page says so in the footer.

### Phones and tablets

The page reported zero horizontal overflow on a phone for days while being
unusable on one. Below 900px the console kept its two-column grid, so the whole
main column was laid out off-screen and quietly clipped by the shell's own
`overflow: hidden`. Nothing scrolled sideways because there was nothing left to
scroll — the content was simply gone.

That is the reason `web/tests/mobile.spec.mjs` exists, and why it asserts the
console body covers at least 80% of the viewport rather than just checking for
overflow. What the pass turned up:

* **Two drawers.** Below 900px the site nav becomes a burger drawer (it carries
  every section, both sibling pages and the route button — not a subset), and
  the console rail slides in from the left. Both close on a tap outside, on
  `Escape`, and after you pick something. Widening the window closes them, so a
  rotation cannot strand one open with the page scroll still locked.
* **44px, everywhere, on coarse pointers only.** A `@media (pointer: coarse)`
  block floors every control — including the ones that look like text, such as
  the footer columns and the desktop nav links on a touch tablet.
* **The severity bar stacks below 560px.** Proportional widths printed
  "6 Mediu". Since severity is never carried by colour alone here, the labels
  could not be dropped, so the bar becomes a column of full-width rows instead.
* **The headline answers to viewport height.** `clamp(34px, 5.6vw, 62px)` reads
  the width, and a phone on its side is 844×390 — so the hero filled the entire
  screen. A `max-height` query caps it.
* **The pill drops its call to action under 560px.** Brand, theme, burger and a
  button do not fit, and the button wrapped onto two lines. The drawer carries
  it, and its label flips with the route like the pill's does.

Two bugs were introduced *by* this work and caught by the same pass, which is
the argument for writing the test before trusting the fix:

* A drawer rule written for `.side` also matched the hero mock's picture of the
  rail, pulled it out of the scaled mock and pinned it to the viewport. The
  rule is `#console-side` now.
* `.route { animation: … both }` leaves the animation's transform applied for
  good, and Chromium keeps a containing block with it — so `position: fixed`
  children stopped being fixed to the viewport and the closed drawer sat 10px
  on screen. `backwards` gives the same entrance and lets go afterwards.

### The assistant, and what it is not

The panel behind the button in the corner is a **help assistant, not a chat
bot**. There is no model behind it and no network call: it matches the question
against a list of topics compiled into the page, and computes the rest from the
dataset already loaded. The panel says exactly that, in the panel, where it can
be read — not in a tooltip.

Three rules hold it honest:

* **It does not guess.** Below the match threshold it says it has no answer and
  names the topics it does have. A confident wrong answer about how a security
  tool scores an indicator is worse than no answer.
* **Its facts are the repository's facts.** The weights, the authority values
  and the verdict bands in the answers are the numbers `backend/app` ships, and
  `mobile.spec.mjs` asserts each one — so the panel and the code cannot drift
  apart without a test going red.
* **It encodes what you type.** The panel echoes the question back, which makes
  it an injection surface like any other; the test pastes an `<img onerror>`
  and a `<script>` into it and asserts neither becomes DOM.

Every answer that has somewhere to go carries the button for it, so the panel
is a way through the product rather than a place to read about it.

### One palette, finally

For a while the site and console ran a light, flame-accented palette while the
analyst workbench and the campaign graph ran their own dark ones — violet in
one, teal in the other. Three palettes in one product is a thing a reviewer
notices before anything else, and the caveat that used to sit here said as much.

All four surfaces now speak the same language: light first, paper surfaces, one
hot accent, Outfit for interface and JetBrains Mono reserved for machine data.
Dark is a first-class alternative on the workbench and the site, not an
inversion — an analyst on a night shift gets a room built for it, with the same
accent.

Bringing them over meant recomputing, not recolouring:

* **The evidence ramp changed hue.** Flame owns the accent and the severity end
  of the scale, so a warm ramp would read as "this is bad" at every step. The
  ramp is a single azure hue instead, and it passes the full ordinal gate on
  both themes and against both its card and its page — the numbers are written
  into the top of `web/assets/tokens.css`.
* **There are two flames.** `--accent` `#fe5729` is the brand colour and carries
  fills, rules and glows; white on it is 3.18:1, which is fine for a 4px bar and
  not fine for a label. Anything that puts text on the accent, or sets accent
  text on paper, uses `--accent-strong` `#d93d15` (4.54:1).
* **Every severity was re-derived** so it clears 4.5:1 against its card, its
  page *and* its own tinted wash — the last of those is the one usually missed,
  because a colour that passes on white can fail on its own 10% background.
* **The graph's four categories were computed against the sky**, not picked to
  look nice on it: each mark clears 3:1 against the brightest and the deepest
  part of the field, and the closest pair is 0.129 apart in OKLab against a
  0.12 floor. Colour still is not the only channel — every cluster is labelled.

### Naming, and what was cut

The console's sidebar was lifted from the reference composition along with its
layout, and it listed Projects, External pentest, Internal pentest, Password
audits and Active attack. IntelPulse triages indicators; it does not run
engagements or audit directories. A sidebar advertising features nothing
behind it implements is the fastest way to lose a reviewer, so every entry is
now a view this console actually renders:

| Was | Is | Why |
| --- | --- | --- |
| Reporting → Dashboard | Posture → **Overview** | "Dashboard" names a shape, not a subject |
| Documents | **SOC tickets** | What the product actually produces |
| Activity | **Triage history** | What the list is of |
| All findings | **All indicators** | The product's own noun |
| All attacks | **Campaigns** | Matches the graph and the ATT&CK mapping |
| Projects, pentests, password audits, Active attack | *removed* | Not features of this product |
| — | **Intelligence sources** | New, and real: every source with its weight and authority |

The landing page had the same problem in miniature. `#platform`, `#pricing`
and `#resources` are section names from a SaaS template — and there is no
pricing, because there is no product to buy. They are `#how`, `#scoring`,
`#evidence` and `#sources` now, which is what the sections contain.

Three things went from the console header for the same reason: a notification
bell that reported a number nobody counted, an avatar for an account that does
not exist, and a "Testing status: Active" pill that reported on nothing. The
search button used to answer "Search is a demo control" — it opens the
assistant now, which is the thing on the page that answers questions.

### The relationship graph

The first version was unreadable, and all three causes were layout rather than
colour: every edge carried a rotated label, node labels had no background so
they sat on whatever line ran underneath, and the repulsion was low enough that
disconnected components stranded in a corner while the rest overlapped.

Edge labels are a hover and selection detail now — `attributed to` and
`announced by` belong under the cursor, not on screen all at once. Every label
draws a small card behind it, so crossing an edge costs nothing. Nodes carry a
ring of their own colour at low opacity, which reads as depth without an image.

The layout needed tuning in both directions. Raising `nodeRepulsion` far enough
to separate the labels made the graph so large that the fit shrank everything
to unreadable — a graph that fits the box but needs a magnifier has not been
laid out, it has been hidden. The layout is now sized to keep edges a little
longer than a label is wide, and a `layoutstop` handler refuses to zoom below
0.85 and lets you pan instead.

### Every control does something

The page has a lot of surface — two routes, a sidebar with collapsible groups,
segment filters, panel menus, a sign-up form, four footer columns. It would be
easy to leave half of it as decoration. So the rule is stated and then enforced:
`web/tests/suite.spec.mjs` enumerates every visible `button`, `a[href]` and
`[role="button"]` on both routes, clicks each one, and fails the suite if any
click leaves the page unchanged. The first run found fifteen dead controls —
three footer icons pointing at `#/home`, two unwired panel menus, and a brand
mark that did nothing when you were already at the top. They are wired now, and
the test is what keeps them wired.

The hero's device mock went the other way. It is a real render of the console
scaled down, so its buttons were real buttons — a second, tiny, confusing set of
controls. It is now `inert` with `pointer-events: none`: a picture of the
product, which is what it was always meant to be.

### The side rail

The sources strip scrolls sideways on its own, stops under the cursor, and can
be dragged, wheeled or arrow-keyed. Two things about it are worth writing down.

* **A fractional `scrollLeft` is rounded away.** Chromium snaps a programmatic
  scroll offset to whole pixels, so `rail.scrollLeft += 0.4` every frame writes
  `1639.4`, gets `1639` back, and never moves. The position is kept in a float
  and written to `scrollLeft`; the loop resyncs from the element whenever
  something else (a drag, the wheel) has moved it.
* **Three runs, not two.** With two copies you can loop forwards seamlessly, but
  dragging backwards hits `scrollLeft: 0` and stops dead. With three identical
  runs the rail parks in the middle one and wraps by exactly one run width in
  either direction — a shift that is invisible because the runs are identical.

### The theme button

It does the obvious thing (swap `data-theme`, persist the choice) and one extra:
where `document.startViewTransition` exists, the new theme wipes in as a circle
growing out of the button that was pressed, sized so the circle always reaches
the furthest corner. Under `prefers-reduced-motion`, or without the API, the
swap is instant and nothing else changes.

### The hero mock, and a transform-origin worth remembering

The mock renders at its true 1180px width and is then scaled to whatever the
frame is, so the internals keep their real proportions instead of being
re-laid-out at 390px. That only works from `transform-origin: top left`. With
`top center` — the value that looks more natural — the fixed point is the middle
of the *1180px scaler*, not the middle of the frame, so on a phone the whole
mock lands outside the frame and the hero shows an empty white box. It did,
until a responsive screenshot caught it.

## Campaign graph

The campaign graph is a second view of the same investigation, built to a
reference composition a reviewer sent over: a radial campaign graph, a
first-seen timeline, a legend and a stats dock. It began as its own page,
`web/explorer.html`, on a dark teal ground; it is a console view now, on the
console's own surfaces, and the old address redirects.

What was taken from the reference is the *composition and treatment* — panel
language, node materiality, the way labels radiate outward from the hub, the
timeline rail. What was not taken is anyone's identity: no borrowed wordmark,
no third-party logos, and the data is IntelPulse's own synthetic dataset
(RFC 5737 addresses, RFC 2606 names, invented family names), labelled as such
on screen.

Notes from building it:

* **Labels radiate, they do not stack.** Each cluster's label sits on the side
  away from the hub with `text-anchor` flipped, then a pass pushes any two
  labels within 26px apart. Without it, "SampleStealer" and "SampleRAT" printed
  on top of each other.
* **Spheres are two circles and a gradient**, not an image: a blurred colour
  disc for the glow, a thin ring, then a radial gradient with its highlight
  offset to 34%/28% so the light reads as coming from one place.
* **Cross-links carry the point.** Hub-to-cluster edges alone make a star;
  the dashed violet edges between clusters are what show two families sharing
  infrastructure, which is the reason to look at a graph at all.
* **The year filter is cumulative**, and the page opens on the full graph
  rather than an empty slice — a view that starts empty shows nothing.
* **Every figure beside it is counted.** The standalone page showed "98%",
  "57%" and "32% unenriched" that no data produced, a severity button that
  only re-sorted, and an ask box wired to nothing. The console view counts its
  KPIs from the clusters in view, its severity control filters, and the ask
  box is gone — the site's assistant is one button away.
* **Labels are drawn last, on their own layer**, with a halo in the page's
  ground colour and `pointer-events: none`, so a later node never paints over
  an earlier label and a label never steals a click from a node.

## Why no framework

Three static files, no build step, no `node_modules`, no supply chain. A
reviewer clones the repo and opens `web/index.html`. The trade-off is that
demo-mode scoring is implemented twice (Python and JavaScript) — which is why
`web/tests/engine.test.mjs` pins the JS engine to the Python rules.
