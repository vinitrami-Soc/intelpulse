# The README's key art

The images on the [front page](../../README.md) are made, not drawn: `art.html` lays each one out as a
`<section class="slide">` in the console's own type (Outfit and JetBrains Mono, bundled) and palette,
and `scripts/readme-art.mjs` renders them.

```bash
# 1. the server views (docs/screenshots/server-*.png), against a new server with sample data
INTELPULSE_SERVER_URL=http://127.0.0.1:8124/ INTELPULSE_SETUP_CODE=... node scripts/screenshots-server.mjs
# 2. the demo shots (shots/) and every slide (*.png), from the repository itself
node scripts/readme-art.mjs
```

Both need Playwright (`PLAYWRIGHT_MODULE` can point at an installed copy). `social-preview.png` is
the repository's social preview (1280 x 640): GitHub takes it under Settings, General, Social preview.
Everything shown is synthetic: RFC 5737 addresses, RFC 2606 names, made-up people.
