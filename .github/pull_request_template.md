## What this changes

<!-- One or two sentences. Link the issue if there is one. -->

## How it was checked

- [ ] `make test` and `make lint` pass
- [ ] `make test-web` passes
- [ ] `make test-ui` passes, for any change under `web/`
- [ ] Extraction or scoring changes are mirrored in `web/assets/engine.js`, covered by the parity tests, and reflected in `docs/SCORING.md`
- [ ] A new or changed check has a test that fails without it, and one for what it must not catch
- [ ] No real alerts, logs or live malware; test data is synthetic (RFC 5737 / RFC 2606)
- [ ] A line is added under *Unreleased* in `CHANGELOG.md`
