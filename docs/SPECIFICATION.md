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

**Live:** https://vinitrami-soc.github.io/intelpulse/ — the root `index.html` redirects to
`web/`, which serves the site and the console.

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
mapping and containment actions, exportable as Markdown or JSON — or raised directly in **Jira**
(REST v3) or **ServiceNow** (Table API) in one request. A sink is configured by an operator through
the environment, never by a request, and the egress allowlist is widened for exactly those hosts.
The dashboard offers the button only when the backend reports a sink it can actually deliver to.

**Change tracking.** Re-triaging an indicator reports what moved since the last time: score delta,
band change and its direction, sources that started or stopped answering, and malware families or
ATT&CK techniques that are new. A provider that was skipped or errored did not answer, so a vendor
outage is never reported as an intelligence change. The browser engine carries the same comparison,
so demo mode has it with no backend.

**Security.** Request body limits, sliding-window rate limiting (30/min for triage, which spends
third-party quota; 60/min writes; 240/min reads), egress policy enforcement against SSRF, credential
masking in logs, and output encoding plus URL-scheme validation on every piece of attacker-controlled
text the interface renders. Full posture in [SECURITY.md](SECURITY.md).

**Operations.** Case history, audit trail, and a health endpoint that reports which providers are
configured and which ticket sinks are reachable.

Quota discipline is enforced rather than assumed: `triage()` de-duplicates its input, and
`Provider.lookup` single-flights per (provider, indicator), so concurrent callers for the same pair
collapse to one upstream fetch instead of each spending a unit. Nine tests count real fetches
against a provider whose network is a counter — including one that proves distinct lookups are still
concurrent, because collapsing duplicates must not turn a fan-out into a queue.

---

## 3. The website and what each part does

One page, one palette, no framework and no build step: the landing site, and a console that holds
the posture views, the analyst workbench and the campaign graph. Everything serves identically from
GitHub Pages, nginx or `python -m http.server`.

### 3.1 Landing site — `web/index.html`

Four sections, named for their subject rather than for the shape of a SaaS template:

- **How it works** (`#how`) — the correlation pass, end to end.
- **Scoring** (`#scoring`) — the formula above, stated rather than asserted.
- **Evidence** (`#evidence`) — what a verdict looks like when you open it up.
- **Sources** (`#sources`) — every provider with the weight and authority behind its word.

It also carries a scaled, inert preview of the console, a newsletter field, and the assistant.

### 3.2 Operator console — `web/index.html#/console/…`

The console over the same synthetic dataset. Ten views, each deep-linkable:

`Workbench` · `Overview` · `Attack surface` · `Triage history` · `Triage queue` · `All indicators` ·
`Campaign graph` · `Attack narratives` · `Intelligence sources` · `SOC tickets`

Every view has a real URL — `#/console/sources` — so it can be shared, bookmarked and reloaded.
Findings are summarised as four KPI cards, a five-band severity bar (Critical, High, Medium, Low,
Informational) and a state row (Awaiting triage, In progress, Closed) that reconciles with it under
every filter.

### 3.3 Analyst workbench — `#/console/workbench`

The tool itself, as a console view. Paste an alert, run it, read the evidence behind every verdict,
take the ticket.

- Dual runtime: **demo mode** on bundled synthetic data, **live mode** against a running FastAPI
  backend. The toggle is explicit and the current mode is always on screen.
- Sample alerts to start from, file upload, an indicator preview before anything is looked up, and
  <kbd>Ctrl</kbd>/<kbd>⌘</kbd>+<kbd>↵</kbd> to run.
- Case verdict, indicator breakdown, source coverage and enrichment timing as the console's KPI row.
- Per-indicator evidence: which source said what, with what weight, and how that produced the score,
  with the arithmetic itself one button away in a real dialog.
- What changed since the last triage of the same indicator, the generated ticket, case history and
  allow/block lists.
- A relationship graph: each indicator is a gauge whose ring fills to its score, everything it points
  at is a pill coloured by kind, and a link is dashed when its source was less than 70% sure of it.
  Hovering or tabbing to a node lights its neighbourhood, names its links and opens a readout;
  selecting an indicator opens its evidence. It shows the 25 highest-scoring indicators, like the list.
- It keeps its draft while you look at another view and come back.

### 3.4 Campaign graph — `#/console/campaigns`

An SVG relationship graph over a synthetic campaign: the hub, malware families, infrastructure and
indicators as four computed colour categories. Radial and by-share layouts, zoom and fit, a
first-seen timeline you can play, and a severity filter. Every figure around it is counted from the
clusters on screen, every node is reachable by keyboard, and the whole graph is also a table.

The workbench and the graph were separate pages until the move described in 4.8; `workbench.html`
and `explorer.html` now redirect to these views.

### 3.5 The assistant

A panel on the landing site and console that answers from the project's own documentation and the
dataset already loaded on the page. It runs entirely in the browser — **no model is called and
nothing leaves the tab**. It covers the scoring model, the sources, what you can paste, the graph,
the ticket, the security controls, the loaded findings, and navigation between the site and the
console's views.
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

Three testing problems were worth more than the tests they fixed:

- **The graph tests never exercised Cytoscape.** The sandbox that wrote them cannot reach the CDN, so
  only the SVG fallback ever ran. The CDN was stubbed with a local copy so the real library got
  tested. Since 4.8 neither graph uses Cytoscape, so there is one rendering path and it is the one
  the tests drive.
- **Contrast was recomputed by hand every time a colour moved.** It is a standing guard now: every
  ink tier against every surface, both themes, both stylesheets — 42 pairs, with dark mode never
  inferred from light-mode values.
- **The extractor had eight tests over about five sample lines.** Regexes that survive five lines
  routinely die on five thousand, and these did — see 4.7.

Current totals: **200** backend (pytest + ruff, 34 of them the 2026 security audit's regressions)
· **56** Node (engine parity, findings model, triage-diff parity, design guards) · **96** workbench
and campaign graph · **85** site and console · **99** phone, tablet and assistant · **27** browser
security (hostile API, poisoned storage, CSP).

### 4.7 Measuring extraction instead of asserting it

Extraction is the front door: everything downstream — scoring, enrichment, the graph, the ticket —
acts on whatever comes out of it. It was covered by eight hand-written tests over roughly five
sample lines, which is enough to demonstrate the happy path and not enough to find anything.

A generated corpus replaced that: **3,400 lines across 15 log formats** (Cisco ASA, PAN-OS traffic
and threat, FortiGate, Suricata EVE, Zeek conn, Windows EVTX-as-JSON, Sysmon, CloudTrail, Squid,
nginx, mail headers, UFW, defanged reports, IOC lists and mixed pastes), each line carrying the exact
set of indicators the extractor is contracted to return. Every value is synthetic — RFC 5737
documentation addresses and RFC 2606 reserved names — so nothing in the corpus can be resolved or
contacted. The framing is what those products actually emit, and the framing is the part under test.

76% of the lines carry a trap: a value that looks extractable and must not be. Precision measured
without traps means nothing, so the trap density is asserted alongside the score.

Ground truth is the documented contract, not the extractor's own output. A corpus built from the
implementation's own results would measure nothing. Where the two disagreed, the disagreement was
reported — and it found five bugs, three of which had shipped:

1. **Carrier-grade NAT was queried as public space.** The README promised CGNAT was dropped; Python's
   `ipaddress` does not flag `100.64.0.0/10`, so it never was. The documentation described behaviour
   the code did not have.
2. **Usernames were read as domains** — 318 times in 3,400 lines. `j.doe` matched the domain pattern
   and `doe` was not on the file-extension denylist, so an employee's username was being sent to a
   third-party threat-intel vendor.
3. **File extensions were read as TLDs.** `x.php`, `index.html`, `core.dmp`, `web.config`. One cause
   sits under 2 and 3: a denylist of things that are *not* TLDs can never be complete. The check now
   tests membership of the published TLD list, refreshable from IANA with
   `python -m app.cli refresh-tlds`.
4. **The allowlist then swallowed real TLDs** — a bug introduced by the fix for 3 and found by
   probing that fix with real-world hostnames the corpus does not contain. `.zip`, `.mov` and `.sh`
   are live TLDs *and* file extensions, and attackers register them for exactly that reason.
   Position resolves it: a label in a URL host or after an `@` is declared to be a hostname; a bare
   token in a log line is not.
5. **A 5 MB upload took 14.1 seconds and blocked the event loop.** Found by the benchmark rather than
   the corpus. Masking URLs with one `str.replace` per URL, and re-finding each indicator's offset
   with `str.find`, each rescanned the whole input once per match — quadratic, inside a synchronous
   call in an async handler, so one upload stalled every other request on the worker. Both are
   single-pass now and the same upload takes **1.4 seconds**.

After the fixes: **precision 100.0%, recall 100.0%** over 9,325 expected indicators, zero traps
sprung. Throughput is ~11,300 lines/s line-at-a-time (p99 0.17 ms) and ~15,000 lines/s for a single
paste, flat in input size. `docs/EXTRACTION-BENCHMARK.md` is generated by
`python -m tests.corpus.report` and never typed by hand, so the documented figure and the figure the
test enforces cannot drift apart.

Three of these numbers are worth reading sceptically, so they are qualified here rather than quoted
bare. 100%/100% is a score against a corpus this project generates, not against the world; it means
the extractor satisfies its own contract on the shapes it was shown, which is exactly as strong as
the corpus is varied. The corpus scored 100% before the traps for findings 4 and 5 were added — a
perfect score is a prompt to go looking for what the corpus is not testing. And the first throughput
figures were wrong by roughly 7x because `tracemalloc` was running around the timing loop; time and
memory are measured in separate passes now.

---

### 4.8 The workbench and the graph move into the console

The workbench and the campaign graph were separate pages with their own layout, rail, type scale and
chrome, so leaving the console for them felt like leaving the product. They are console views now:
same sidebar, header, KPI cards, tables, empty states and theme, reached from the sidebar and from a
link like any other view. The scoring engine, charts and demo data are the same files, so every
number is unchanged. What the move changed:

- **A view lifecycle.** The console repainted views as strings. A view that owns listeners, timers
  and an open dialog needs to be told when it leaves, so views can now mount and unmount; the
  workbench keeps its draft across a trip to another view, and the graph stops its timeline.
- **Two collisions with the console, found by tests.** The console wired every segmented control to
  its findings filter and every `data-sev` element to its severity bar, which threw on the
  workbench's mode switch and drew a severity bar into the graph's filter button. Both now match only
  their own elements.
- **A markup sink closed.** The console's toast took HTML. The workbench toasts indicator values,
  which come out of pasted logs, so it takes text now; a test feeds it markup.
- **The graph's controls do what they say.** "Filter by severity" only re-sorted the clusters; it
  filters now. Its figures (98%, 57%, "32% unenriched") were invented and are gone; every number
  beside the graph is counted from what is on screen. An ask box that was not wired to anything is
  gone too.
- **The rail follows a long view.** The workbench runs to several screens and the sidebar scrolled
  away, leaving an empty column; it stays in view on desktop widths now.
- **Nothing hides off the side of a phone.** The graph's year control scrolled sideways and showed
  2016 to 2020, hiding the year that was selected; it wraps into three rows below 720px now.
- **Retired with the old pages:** the ⌘K palette, the `g`-key sequences and shortcut sheet, the
  three-way theme key and the easter eggs. The sidebar, the assistant and the console's theme button
  cover what they did. The browser tests that drove them were retired with them, each with its reason
  written into the suite; everything else was ported, and the suite grew from 69 to 79 checks.

## 5. Future updates

Nothing below is implemented. Ordered by what would earn its place soonest.

### Near term

- **Split `suite.js`.** At ~1,100 lines it does routing, charts, console rendering and the assistant
  in one IIFE. The workbench and graph views already live in their own file (`console-panes.js`)
  on top of the shared engine and charts; the rest of the console should follow. Extracting the
  findings model was the first step.
- **Bulk actions in the console.** Select several findings and act on them together.
- **More ticket sinks.** Jira and ServiceNow are in; PagerDuty and Slack are the obvious next two.
- **A distributed single-flight.** The current one is process-local, which is correct for the
  single-container deployment this targets but not for replicas behind a load balancer.

### Medium term

- **More providers.** VirusTotal, Shodan, Censys, and MISP as both source and destination.
- **Persistent case store.** Cases currently live in browser storage in demo mode. A real backing
  store would make triage history meaningful across sessions and analysts.
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

One light-first palette spans the site and the console. `--flame` (`#fe5729`) is for fills only; anything
carrying text uses `--flame-ink` (`#d93d15`, white on it = 4.54:1) or `--flame-ink-2` (`#b3300e`,
5.69:1 on `--flame-wash`). Every colour decision lives in tokens, and a test fails the build if a raw
hex appears in the workbench or graph styles or in component JavaScript.

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

### Icon weight, derived rather than picked

Icons are drawn in a 24-unit viewBox, so the stroke a reader actually sees is
`stroke-width × rendered-size / 24`. Holding that near 1.2px keeps every icon the same visual weight
whatever its box — which is why the scale runs the opposite way to the sizes:

| Icon size | Stroke | What the reader sees |
| --- | --- | --- |
| ≤ 9px | 3.0 | 1.00–1.13px |
| 10–12px | 2.4 | 1.00–1.20px |
| 13–14px | 2.1 | 1.14–1.23px |
| 15–17px | 1.8 | 1.13–1.28px |
| ≥ 18px | 1.3 | heavier, and meant to be — these are outline illustrations |

This was previously recorded as a known gap on the grounds that it was a perceptual judgement. That
was half right: 15px icons shipped with five different stroke widths (1.8, 1.9, 2.0, 2.1 and 2.3),
which is drift wearing the costume of optical compensation. The scale is computed from the formula
above, was verified against before-and-after renders rather than by eye, and a static guard now
fails the build on any icon that does not follow it.
