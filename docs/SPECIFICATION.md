# Project specification

> Companion to the [README](../README.md). The README says what IntelPulse does and how to run it;
> this document says what it is *specified* to do, what changed along the way and why, and what is
> planned next. Depth on individual subjects lives in [SCORING.md](SCORING.md),
> [SECURITY.md](SECURITY.md), [API.md](API.md) and [DESIGN.md](DESIGN.md).

---

## 1. Project title

**IntelPulse — Automated Threat Intelligence & Triage Workbench**

A SOC analyst opens roughly six browser tabs to triage one alert: AbuseIPDB for reputation, OTX for
campaign context, GreyNoise to rule out internet-wide scanning, ThreatFox and URLhaus for the
payload, GeoIP for hosting. Six tabs across forty alerts a shift is where triage time goes, and
where indicators get missed.

IntelPulse collapses that pass into one request: parse the indicators out of whatever you paste,
query every applicable source concurrently, score them into a single auditable verdict, map how they
relate, and write the ticket.

**Live:** https://vinitrami-soc.github.io/intelpulse/ — `intelpulse/index.html` redirects to
`web/`, which is where the four surfaces are served from.

---

## 2. Main keypoints and features

### Keypoints

| | |
| --- | --- |
| **One pass, not six tabs** | Every applicable source is queried concurrently for every indicator. A dead vendor degrades the result rather than failing the request. |
| **It shows its arithmetic** | The score is not a black box. Every verdict carries the per-source signals, weights and authority values that produced it. |
| **It runs with no backend** | The entire front end works from a static host on bundled synthetic data. There is nothing to install to evaluate it. |
| **It says "skipped", never "clean"** | A source with no API key configured reports that it was skipped. Absence of evidence is never rendered as evidence of absence. |
| **Nothing leaves the tab in demo mode** | No analytics, no telemetry, no model calls. The in-page assistant reads the project's own documentation. |

### Feature set

**Ingestion.** Plain indicator lists, firewall and proxy syslog, Windows EVTX-as-JSON, SIEM alert
exports, and file upload (`.log` `.txt` `.csv` `.json`) up to 5 MB. Defanged notation — `1.2.3[.]4`,
`hxxp://` — is refanged automatically. RFC 1918, loopback and CGNAT space are dropped before
anything leaves the building, as are filenames that look like indicators (`svchost.exe`).

**Enrichment.** Seven providers: AbuseIPDB, AlienVault OTX, ThreatFox, URLhaus, GreyNoise, GeoIP,
and a local blocklist assembled from Feodo Tracker and FireHOL. One `httpx.AsyncClient`, one task per
(indicator × provider), a global semaphore, per-provider timeouts, and `return_exceptions=True`.

**Scoring.** A weighted mean of the sources that actually answered, floored by the most authoritative
single hit:

```
score = 100 × max(
    Σ(weight × signal) / Σ(weight),   ← consensus, over providers that ANSWERED
    max(signal × authority)           ← authority floor
)
```

The mean is the consensus; the floor is the safety net. One confirmed ThreatFox C2 listing still
reads critical when four quiet sources drag the mean down. Confidence is reported separately from
score, because "80/100 from one source" and "80/100 from five" are different claims.

| Provider | Weight | Authority | Role |
| --- | --- | --- | --- |
| ThreatFox | 1.2 | 0.95 | abuse.ch — confirmed command and control |
| URLhaus | 1.1 | 0.95 | abuse.ch — malware distribution URLs |
| AbuseIPDB | 1.0 | 0.80 | Address reputation, corroboration-weighted |
| Local blocklist | 1.0 | 0.90 | Feodo Tracker and FireHOL, imported offline |
| AlienVault OTX | 0.9 | 0.70 | Community pulses, prone to syndication |
| GreyNoise | 0.6 | 0.50 | Context: is this internet-wide scanning |
| GeoIP | 0.25 | 0.30 | Hosting context only |

Verdict bands: **critical** ≥ 85, **high** ≥ 70, **medium** ≥ 40, **low** ≥ 15, informational below.
A GreyNoise benign classification applies a 0.45 multiplier; analyst allow and block lists override.

**Output.** A SOC ticket with executive summary, per-indicator evidence, MITRE ATT&CK technique
mapping and containment actions, exportable as Markdown or JSON.

**Security.** Request body limits, sliding-window rate limiting (30/min for triage, which spends
third-party quota; 60/min writes; 240/min reads), egress policy enforcement against SSRF, credential
masking in logs, and output encoding plus URL-scheme validation on every piece of attacker-controlled
text the interface renders. Full posture in [SECURITY.md](SECURITY.md).

**Operations.** Case history, audit trail, per-(provider, indicator) caching so re-triaging the same
indicator does not spend quota twice, and a health endpoint that reports which providers are actually
configured.

---

## 3. The website and what each part does

Four surfaces, one palette, no framework and no build step. Everything serves identically from
GitHub Pages, nginx or `python -m http.server`.

### 3.1 Landing site — `web/index.html`

Four sections, named for their subject rather than for the shape of a SaaS template:

- **How it works** (`#how`) — the correlation pass, end to end.
- **Scoring** (`#scoring`) — the formula above, stated rather than asserted.
- **Evidence** (`#evidence`) — what a verdict looks like when you open it up.
- **Sources** (`#sources`) — every provider with the weight and authority behind its word.

It also carries a scaled, inert preview of the console, a newsletter field, and the assistant.

### 3.2 Operator console — `web/index.html#/console/…`

A posture view over the same synthetic dataset. Nine panes, each deep-linkable:

`Overview` · `Attack surface` · `Triage history` · `Triage queue` · `All indicators` ·
`Campaigns` · `Attack narratives` · `Intelligence sources` · `SOC tickets`

Every view has a real URL — `#/console/sources` — so it can be shared, bookmarked and reloaded.
Findings are summarised as four KPI cards, a five-band severity bar (Critical, High, Medium, Low,
Informational) and a state row (Awaiting triage, In progress, Closed) that reconciles with it under
every filter.

### 3.3 Analyst workbench — `web/workbench.html`

The tool itself. Paste an alert, run it, read the evidence behind every verdict, take the ticket.

- Dual runtime: **demo mode** on bundled synthetic data, **live mode** against a running FastAPI
  backend. The toggle is explicit and the current mode is always on screen.
- Command palette (`⌘K` / `Ctrl-K`) with fuzzy search over 18 analyst actions.
- Case verdict, indicator breakdown, source coverage and enrichment timing as a KPI row.
- Per-indicator evidence: which source said what, with what weight, and how that produced the score.
- Relationship graph, generated ticket, case history, allow/block lists.

### 3.4 Campaign graph — `web/explorer.html`

A Cytoscape relationship graph over a synthetic campaign: the hub, malware families, infrastructure
and indicators as four computed colour categories. Radial and cluster layouts, zoom, severity filter,
cluster sort and fit-to-view. Edge labels appear on hover and selection rather than permanently, so
the graph reads at rest.

### 3.5 The assistant

A panel on the landing site and console that answers from the project's own documentation and the
dataset already loaded on the page. It runs entirely in the browser — **no model is called and
nothing leaves the tab**. It covers the scoring model, the sources, what you can paste, the graph,
the ticket, the security controls, the loaded findings, and navigation between the four surfaces.
When it does not know, it says so and lists what it does cover rather than inventing an answer.

---

## 4. Improvements and changes

The interface was rebuilt twice and then debugged against real devices. What follows is the honest
record, including the parts that were wrong.

### 4.1 Correctness of the data the UI claimed

**The severity bar invented its own remainder.** It drew Critical, High and Medium, then a hatched
block sized as "30 minus whatever is on screen". Filtering to Closed therefore claimed 21
unclassified findings that did not exist, and the number lived only in a `title` attribute where
nobody could see it. The state row summed to 21 against a severity total of 26. Three tables were
maintained by hand, with every count written twice — once as a number, once inside its own label.

The model is now one table of fifteen numbers (five bands × awaiting/in progress/closed) in
`web/assets/console-model.js`. Everything else is derived, so *open + closed = all* is not a rule
anyone has to remember — open **is** awaiting plus in progress. It sits outside `suite.js` so the
arithmetic is unit-tested in Node rather than only through a browser at three filter settings.

**The sidebar described a product this is not.** Projects, external pentest, internal pentest,
password audits and active attack came from a reference composition. IntelPulse triages indicators;
it does not run engagements. Those entries are gone, the rest are named for their subject, and a real
view replaced them: Intelligence sources, listing every provider with its weight and authority.

**Three controls reported on nothing** — a notification bell with no notifications, an avatar for an
account that does not exist, a "Testing status: Active" pill. Removed.

### 4.2 Navigation and routing

The open console view was kept in a DOM attribute, so `#/console` was the only address the console
ever had. Making views deep-linkable was a fix in itself and exposed four more bugs:

- `PANES[name]` was a bare lookup on user input. `#/console/__proto__` returned `Object.prototype`
  and rendered nothing; `#/console/toString` drew a heading reading literally `undefined`.
- Re-selecting the view already open assigned the hash it already held, which fires no `hashchange`,
  so the router never ran. On a phone that left the drawer open over a page with `overflow: hidden`
   — a dead end with no way out but reload.
- A theme flip redrew the console as the dashboard whatever was open, while the URL and the sidebar
  went on claiming the old view.
- The "already there, so scroll to the top" branch compared `#/console` against `#/console/dashboard`
  and was therefore dead code.

The workbench and campaign graph were also one-way doors — once in, nothing led back to the site.
Both now link home and carry a labelled "Back to site".

### 4.3 Mobile and tablet

Below 900px a two-column grid laid the console's main column off-screen, clipped by
`overflow: hidden`, while reporting zero horizontal overflow. Both the console sidebar and the
workbench rail are drawers now — scrim, tap-outside, Escape, and dismissal on selection.

Two bugs found later on a real phone, after the first merge:

- **Capsules wrapped their own labels.** `.chip` had no `white-space: nowrap`, so "9% up" broke
  across two lines and the pill rendered 39px tall — which reads as a rendering fault, not a badge.
  It did this at every phone and tablet width. All four capsule classes are covered by one rule now.
- **The case-verdict badge was clipped off its card.** `.hero` is a flex row with a 42px number,
  `/100` and the badge, with `flex-wrap: nowrap` and a `&nbsp;` gluing `/100` to the badge as one
  unbreakable run: 161px of content in a 64px box, so CRITICAL was cut. The row wraps now, and below
  560px the verdict takes the full row.

### 4.4 The assistant

It declined seven of the ten plainest things a visitor could type, including "take me to the main
page" and "about". The knowledge base answered questions *about* the product and had no idea what to
do with a request to *go* somewhere — which is most of what people ask an assistant embedded in a
page. Five entries closed that gap, each offering the button that performs the action.

Widening keywords carried a cost that showed up immediately: a bare `about` key made "tell me about
ssrf" answer the what-is-this entry on a tie. Words like *about*, *top* and *back* name an intent
only when they **are** the whole question; inside "tell me about X" they are framing. They are
matched against the full text now.

### 4.5 Accessibility and contrast

- Two AA failures in the severity component (3.18:1 and 3.63:1 on bold 10–11px labels) fixed with
  dedicated text-on-accent tokens.
- `--ink-3` was 2.98:1 on `--ground-2` against a 3:1 floor, and 2.75:1 on `--surface-3`. Now
  `#7b8490`, which clears 3:1 on all four light surfaces. The value was solved for, not picked.
- A skip link on the site (the console sidebar is nine entries deep before the findings).
- `index.html` jumped h2 → h4 at the footer; the campaign graph had no `h1` at all and shouted
  `LEGEND` into the DOM where a screen reader reads it.
- Nine icon-only buttons on the graph had a `title` and no accessible name. A `title` is not one.
- The campaign graph's search box removed its focus ring with nothing in its place.
- Light-mode modal scrim was 34%, under the 40–60% band and weaker than the site's own 42%.

### 4.6 Testing and CI

262 assertions passed on one machine and nothing enforced them on a push. There is a workflow now —
three browser jobs plus backend and static guards, paths-filtered and concurrency-cancelled.

Two testing problems were worth more than the tests they fixed:

- **The graph tests never exercised Cytoscape.** The sandbox that wrote them cannot reach the CDN, so
  only the SVG fallback ever ran. The CDN is stubbed with a local copy now, and eight checks run
  against the real library.
- **Contrast was recomputed by hand every time a colour moved.** It is a standing guard now: every
  ink tier against every surface, both themes, both stylesheets — 42 pairs, with dark mode never
  inferred from light-mode values.

Current totals: **63** backend (pytest + ruff) · **40** Node (engine parity, findings model, design
guards) · **64** workbench · **78** site and console · **83** phone, tablet and assistant.

---

## 5. Future updates

Nothing below is implemented. Ordered by what would earn its place soonest.

### Near term

- **Split `suite.js`.** At ~1,100 lines it does routing, charts, console rendering and the assistant
  in one IIFE. The workbench is already split across five files; the site should follow the same
  pattern. Extracting the findings model was the first step.
- **Normalise icon stroke widths.** They run 1.1 to 3 across the two stylesheets. Some of that is
  genuine optical compensation — a 9px chip needs a heavier stroke than a 17px icon — but not all of
  it. This needs eyes on a real screen, not a numeric rule.
- **Bulk actions in the console.** Select several findings and act on them together.
- **Empty and loading states in the console.** The workbench has them; the console assumes data.

### Medium term

- **More providers.** VirusTotal, Shodan, Censys, and MISP as both source and destination.
- **Persistent case store.** Cases currently live in browser storage in demo mode. A real backing
  store would make triage history meaningful across sessions and analysts.
- **Ticket integrations.** Jira and ServiceNow as export targets rather than copy-paste Markdown.
- **Diff between triages.** Re-running an indicator should show what changed since last time — new
  pulses, a changed GreyNoise classification, a fresh blocklist hit.
- **Saved views and filters** in the console, shareable by URL the way panes already are.

### Longer term

- **Scheduled re-triage** of open cases, so a verdict that ages badly surfaces itself.
- **Multi-analyst workflow**: assignment, handover notes, and an audit trail that spans people.
- **Detection feedback loop**: mark a verdict wrong and have that weight future scoring, with the
  adjustment visible in the arithmetic rather than hidden in a model.
- **Visual regression tests.** Several bugs in this project were only visible to a human eye on a
  real phone. Screenshot diffing in CI would have caught the wrapped capsules and the clipped badge.

---

## 6. UI and UX

### Principle

IntelPulse is a tool people stare at for eight hours. The interface is built for that: dense,
keyboard-first, quiet by default, and loud only where the data is actually alarming. Reference points
are the tools analysts already keep open — Linear and Raycast for the command surface, Sentinel and
Datadog for severity semantics and data density.

### Colour, computed rather than chosen

Data-visualisation colour is validated by a script, not by eye. The evidence ramp passes a full
ordinal gate on both surfaces: monotone OKLab lightness, step gaps ≥ 0.06, light end ≥ 2:1 against
its surface, single hue (≤ 12° spread). Categorical colours hold an OKLab ΔE floor of 0.12 — the
campaign graph's four categories sit at a closest pair of 0.129.

One light-first palette spans all four surfaces. `--flame` (`#fe5729`) is for fills only; anything
carrying text uses `--flame-ink` (`#d93d15`, white on it = 4.54:1) or `--flame-ink-2` (`#b3300e`,
5.69:1 on `--flame-wash`). Every colour decision lives in tokens, and a test fails the build if a raw
hex appears in a component stylesheet or in component JavaScript.

### Accessibility as a gate, not a review

These are enforced by the 40 static guards, not by intention:

- Body and secondary text ≥ 4.5:1, faint meta ≥ 3:1, on **every** surface in **both** themes.
- No focus outline removed without a visible replacement; `:focus-visible` preferred over `:focus`.
- Every icon-only control has an accessible name.
- Every page has exactly one `h1` and heading levels never skip a rank.
- Colour is never the only channel — severity carries a label, a glyph and a lightness rank.
- Only `transform` and `opacity` are animated; `transition: all` is forbidden.
- `prefers-reduced-motion`, `forced-colors` and `pointer: coarse` are all handled.
- The brand wordmark is marked `translate="no"` so auto-translation leaves it alone.

### Touch and responsive

Every control clears 44×44px on a touch device, asserted across six viewports from a 360px phone to
tablet landscape. Scrollable overlays contain their scroll. `theme-color` follows both theme and
route, measured against the colour actually painted at the top of the viewport rather than compared
against another copy of the same guess. Safe-area insets are respected on fixed bars.

### Motion

Micro-interactions sit in the 110–280ms range with a single shared easing curve. The theme change is
a View Transition wiping from the button itself. Route entrances replay only on an actual route
change, and every one of them is skipped entirely under `prefers-reduced-motion`.

### What the interface refuses to do

- No control that looks pressable and answers nothing. A test sweeps every visible control on both
  routes, clicks it, and fails on any that leaves the page unchanged.
- No number shown that the data cannot justify — the invented remainder is the cautionary tale.
- No emoji used as a structural icon.
- No question suggested by the assistant that the assistant cannot answer.

### Known gap

Icon stroke widths are inconsistent (1.1–3). It is recorded in §5 rather than fixed, because
normalising it is a perceptual judgement and the change was not verifiable from a terminal. A
half-applied token scale reads as a system without being one, which is worse than the current state.
