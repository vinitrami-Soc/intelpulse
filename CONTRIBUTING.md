# Contributing to IntelPulse

Thanks for helping. Wrong verdicts, missed indicators, new intelligence
sources, UI fixes, docs fixes and bug reports are all welcome.

## Ground rules

- **Never paste or commit real alerts or logs.** Real telemetry names your
  organisation's hosts, users and internal addresses. Rebuild the pattern with
  synthetic data instead: RFC 5737 addresses (`192.0.2.0/24`,
  `198.51.100.0/24`, `203.0.113.0/24`) and RFC 2606 names (`example.com`,
  `.test`, `.invalid`), the same convention the demo dataset follows.
- **No live malware and no working payloads**, anywhere in the repository,
  including tests. A hash or a URL only needs the right shape to exercise
  extraction.
- **Every change to extraction or scoring needs a test for what it catches and
  a test for what it must not catch.** A false positive costs an analyst more
  than a missed low signal.
- Be kind. This project follows the [Code of Conduct](CODE_OF_CONDUCT.md).

## Set up

```bash
git clone https://github.com/vinitrami-Soc/intelpulse.git && cd intelpulse
make install      # backend venv + dependencies
make test         # 200 backend tests, no network, no API keys, no Redis
make lint         # ruff
make test-web     # 56 node tests: engine parity, console model, design guards
```

The browser suites need Playwright and the dashboard served on `:8123`:

```bash
python3 -m http.server 8123 --directory web &
make test-ui      # ui, suite, mobile and security specs in Chromium
```

CI runs exactly these commands on every pull request
(`.github/workflows/intelpulse.yml`); `pip-audit` runs weekly on its own
(`.github/workflows/audit.yml`).

## Reporting a wrong verdict or a missed indicator

Open a [verdict report](https://github.com/vinitrami-Soc/intelpulse/issues/new/choose).
The most useful details are the verdict and score you got, the one you
expected, and the per-source evidence from the result, with anything
identifying your organisation removed.

## Changing extraction or scoring

The dashboard's demo mode re-implements the backend's extraction and scoring in
JavaScript, and the two are pinned together by tests. A change on one side is
not finished until the other side matches.

1. **Python first.** Extraction lives in `backend/app/ioc.py`; weights,
   authority floors and verdict bands in `backend/app/scoring.py`. Add tests in
   `backend/tests/test_ioc.py` or `test_scoring.py`. For extraction, check the
   3,400-line corpus still passes (`test_extraction_corpus.py`).
2. **Mirror it in `web/assets/engine.js`**, and extend
   `web/tests/engine.test.mjs` so the parity test covers the new behaviour.
3. **Update [docs/SCORING.md](docs/SCORING.md)** when a weight, a floor or a
   band changes. Scoring is meant to be auditable, so the document is part of
   the change.

## Adding an intelligence source

1. Subclass `Provider` from `backend/app/enrichment/base.py` in a new module
   under `backend/app/enrichment/`, and register it in `PROVIDERS` in
   `backend/app/enrichment/__init__.py`.
2. Add its API host to `ALLOWED_HOSTS` in `backend/app/net.py`. Outbound
   requests to any other host are refused, and that is deliberate.
3. Read its key from configuration (`backend/app/config.py`, `.env.example`).
   A source with no key must report itself as `skipped`, never as clean.
4. Stub it in the API tests. The backend suite must stay offline.

## Changing the UI

Follow the design system in
[`.claude/skills/design-system-intelpulse/SKILL.md`](.claude/skills/design-system-intelpulse/SKILL.md)
and [docs/DESIGN.md](docs/DESIGN.md). `web/tests/tokens.test.mjs` fails on the
rules that can be checked statically: raw colours instead of tokens,
`transition: all`, and so on. Treat every string that reaches the DOM as
hostile; the security spec will try to prove it.

## Pull requests

- One change per pull request, with a short description of what and why.
- Tests, lint and the browser suites must pass in CI.
- Add a line under *Unreleased* in [CHANGELOG.md](CHANGELOG.md).
- The pull request template has a checklist; please fill it in.
