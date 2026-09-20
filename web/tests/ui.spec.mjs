/* Browser tests for the dashboard's security and loading behaviour.
 *
 * These are the checks that unit tests cannot make: that attacker-controlled
 * log text never becomes DOM, that a hostile provider response cannot inject a
 * javascript: link, that a slow or dead backend degrades instead of freezing,
 * and that the rail and graph controls actually drive the view.
 *
 * Run:  python3 -m http.server 8123 --directory web   # in one terminal
 *       node web/tests/ui.spec.mjs                    # in another
 * Needs Playwright with Chromium available.
 */
let chromium;
try {
  // PLAYWRIGHT_MODULE lets a globally installed Playwright be used without
  // adding a node_modules tree to a project that otherwise has no build step.
  ({ chromium } = await import(process.env.PLAYWRIGHT_MODULE || 'playwright'));
} catch (error) {
  console.error('Playwright is required for these tests: npm i -D playwright');
  console.error('(or set PLAYWRIGHT_MODULE to an installed copy)');
  process.exit(2);
}

const BASE = process.env.INTELPULSE_URL || 'http://127.0.0.1:8123/';
let failures = 0;
const check = (name, ok, detail) => {
  console.log((ok ? 'PASS  ' : 'FAIL  ') + name + (detail ? '  — ' + detail : ''));
  if (!ok) failures++;
};

const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
let alerted = false;
page.on('dialog', async d => { alerted = true; await d.dismiss(); });
const errors = [];
page.on('pageerror', e => errors.push(e.message));

await page.goto(BASE, { waitUntil: 'domcontentloaded' });
await page.waitForTimeout(400);

// ---------- 1. XSS: attacker-controlled log content -------------------------
const payload = `Sep 18 02:14 fw01: SRC=203.0.113.10 <script>window.__pwned=1;alert(1)</script>
<img src=x onerror="window.__pwned2=1">
"><svg/onload=alert(2)> javascript:alert(3)
hxxp://evil[.]example[.]com/"><script>alert(4)</script>`;
await page.fill('#input', payload);
await page.click('#run');
await page.waitForTimeout(900);
const xss = await page.evaluate(() => ({
  pwned: Boolean(window.__pwned || window.__pwned2),
  scriptTags: document.querySelectorAll('#panel-triage script').length,
  imgTags: document.querySelectorAll('#panel-triage img').length,
  hrefs: Array.from(document.querySelectorAll('#panel-triage a')).map(a => a.getAttribute('href')),
  rendered: document.querySelector('#panel-triage').textContent.includes('<script>')
}));
check('attacker-controlled log text never executes', !xss.pwned && !alerted);
check('no script or img element is injected from log text', xss.scriptTags === 0 && xss.imgTags === 0);
check('payload is rendered as visible text', xss.rendered);
check('only https vendor links survive', xss.hrefs.every(h => h.startsWith('https://')));

// ---------- 2. javascript: href must never survive ---------------------------
const badHref = await page.evaluate(() => {
  const E = window.IntelPulseEngine;
  const fake = { case_id: 'x', title: 't', verdict: 'high', score: 80, duration_ms: 1, summary: '',
    indicators: [{ value: '1.2.3.4', type: 'ip', score: 80, verdict: 'high', confidence: .8,
      evidence: [], modifiers: [], tags: [], malware_families: [], providers_queried: 1, providers_answered: 1,
      attack_techniques: [{ id: 'T1', name: 'x', tactic: 'y', url: 'javascript:alert(9)' }],
      containment: [], sources: [{ provider: 'p', label: 'p', status: 'ok', facts: {}, signals: [],
        relations: [], reference: 'javascript:alert(8)' }] }], graph: { nodes: [], edges: [] }, mode: 'demo' };
  window.IntelPulse.render(fake);
  return Array.from(document.querySelectorAll('#panel-triage a')).map(a => a.getAttribute('href'));
});
check('javascript: URLs from a provider response are dropped', badHref.length === 0);
const schemes = await page.evaluate(() => ['javascript:alert(1)', 'data:text/html,<script>', 'vbscript:x',
  ' javascript:alert(1)', 'JaVaScRiPt:alert(1)', 'https://otx.alienvault.com/x', 'http://localhost:8000/y']
  .map(u => [u, window.IntelPulse.safeUrl(u)]));
check('safeUrl rejects every non-http(s) scheme',
  schemes.filter(([u]) => !u.startsWith('http')).every(([, out]) => out === null));
check('safeUrl keeps ordinary vendor links',
  schemes.filter(([u]) => u.startsWith('http')).every(([, out]) => out !== null));

// ---------- 3. skeleton loader on a slow backend -----------------------------
await page.click('button[data-mode="live"]');
await page.waitForTimeout(300);
await page.route('**/api/**', async route => {
  await new Promise(r => setTimeout(r, 2500));
  await route.abort();
});
await page.fill('#api-base', 'http://127.0.0.1:9999');
await page.click('#api-save');
await page.fill('#input', '8.8.8.8 1.1.1.1');
await page.click('#run');
await page.waitForTimeout(600);
const sk = await page.evaluate(() => ({
  cards: document.querySelectorAll('.sk-card').length,
  note: (document.querySelector('.sk-note') || {}).textContent || '',
  btn: document.querySelector('#run').textContent.trim()
}));
check('skeleton placeholders render while sources are queried', sk.cards >= 1);
check('the run button reports in-flight state', sk.btn.includes('Triaging'));
await page.waitForTimeout(3200);
const afterFail = await page.evaluate(() => ({ toast: (document.querySelector('#toast')||{}).textContent, btn: document.querySelector('#run').textContent.trim() }));
check('a dead backend degrades with a message, not a freeze',
  afterFail.btn === 'Run triage' && /failed/i.test(afterFail.toast || ''));
await page.unroute('**/api/**');

// ---------- 4. rail + graph toolbar ------------------------------------------
await page.click('button[data-mode="demo"]');
await page.click('button[data-scenario="firewall"]');
await page.click('#run');
await page.waitForTimeout(800);
await page.click('#rail-toggle');
await page.waitForTimeout(350);
const railOpen = await page.evaluate(() => ({
  open: document.querySelector('#app').classList.contains('rail-open'),
  width: document.querySelector('#rail').getBoundingClientRect().width,
  labelVisible: getComputedStyle(document.querySelector('.rail-btn span')).opacity
}));
check('the rail expands and reveals its labels',
  railOpen.open && railOpen.width > 150 && railOpen.labelVisible === '1');
await page.click('.rail-btn[data-nav="graph"]');
await page.waitForTimeout(900);
const before = await page.evaluate(() => (document.querySelector('.svg-root')||{}).getAttribute?.('transform') || 'none');
await page.click('.graph-tools button[data-graph="in"]');
await page.click('.graph-tools button[data-graph="in"]');
await page.waitForTimeout(250);
const after = await page.evaluate(() => (document.querySelector('.svg-root')||{}).getAttribute?.('transform') || 'none');
check('graph toolbar zoom changes the view', /scale\(1\.[0-9]/.test(after || ''));
await page.click('.rail-btn[data-nav="report"]');
await page.waitForTimeout(400);

check('no uncaught page errors', errors.length === 0, errors.slice(0, 2).join(' | '));

await browser.close();
console.log(failures ? `\n${failures} check(s) failed` : '\nall checks passed');
process.exit(failures ? 1 : 0);
