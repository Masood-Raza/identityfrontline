import { JSDOM, VirtualConsole } from 'jsdom';
import { readFileSync } from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');

// Serve the site so the page's relative fetch() of the catalog behaves as in production.
const srv = http.createServer((req, res) => {
  const f = path.join(root, req.url === '/' ? 'assessments.html' : decodeURIComponent(req.url.split('?')[0]));
  fs.readFile(f, (e, d) => {
    if (e) { res.writeHead(404); return res.end('not found'); }
    res.writeHead(200, { 'Content-Type': f.endsWith('.json') ? 'application/json' : 'text/html' });
    res.end(d);
  });
});
await new Promise(r => srv.listen(8211, r));

const errors = [];
const vc = new VirtualConsole();
vc.on('jsdomError', e => errors.push(e.message));
vc.on('error', (...a) => errors.push(a.join(' ')));

const dom = await JSDOM.fromURL('http://127.0.0.1:8211/assessments.html', {
  runScripts: 'dangerously',
  resources: 'usable',
  virtualConsole: vc,
  pretendToBeVisual: true,
  // jsdom ships no fetch; give the page Node's, with relative URLs resolved against the server.
  beforeParse(w) {
    w.fetch = (u, o) => fetch(new URL(u, 'http://127.0.0.1:8211/'), o);
    w.scrollTo = () => {};
  }
});

const { window } = dom;
window.scrollTo = () => {};
await new Promise(r => setTimeout(r, 900));
const doc = window.document;

let fail = 0;
const ok = (name, cond, extra = '') => {
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${name}${!cond && extra ? ' -> ' + extra : ''}`);
  if (!cond) fail++;
};
const $ = s => doc.querySelector(s);
const $$ = s => [...doc.querySelectorAll(s)];
const man = JSON.parse(fs.readFileSync(join(root, 'assets/catalog/manifest.json'), 'utf8'));

ok('no uncaught script errors', errors.length === 0, errors.join(' | '));
ok('catalog error banner hidden', $('#catalogError').hidden);

const fw = $$('#frameworks input');
ok('15 frameworks rendered from catalog', fw.length === 15, `got ${fw.length}`);
ok('framework labels are versioned',
  $$('#frameworks label').some(l => l.textContent.includes('v6.0.1')),
  $$('#frameworks label').map(l => l.textContent).join(' | '));

const secs = $$('#sectionScopes input');
ok('6 profile sections rendered', secs.length === 6, `got ${secs.length}`);
ok('all sections preselected on the M365 path', secs.every(i => i.checked));
ok('section labels carry check counts', $$('#sectionScopes label').some(l => /\(\d+\)/.test(l.textContent)));
ok('excluded sections disclosed', $$('#excludedScopes .excluded-item').length === 3);

// Walk to step 4 and read the rendered permission table.
const next = $('#next');
for (let i = 0; i < 3; i++) next.click();
ok('step 4 active', $('.panel[data-panel="4"]').classList.contains('active'));

let rows = $$('#permissions tr');
ok('17 permission rows for the full profile', rows.length === 17, `got ${rows.length}`);
ok('RoleManagement.Read.Directory shown', doc.querySelector('#permissions').textContent.includes('RoleManagement.Read.Directory'));
ok('AuditLog.Read.All shown', doc.querySelector('#permissions').textContent.includes('AuditLog.Read.All'));
ok('every row marked read-only', $$('#permissions .read-only').length === rows.length);
ok('consent note fired for Agreement.Read.All',
  $('#consentNote').textContent.includes('Agreement.Read.All'));

// The bug that dead-ended the old wizard: Back from the last step must re-enable Continue.
next.click();
ok('step 5 active', $('.panel[data-panel="5"]').classList.contains('active'));
ok('Continue disabled on last step', next.disabled);
$('#back').click();
ok('Continue re-enabled after Back from step 5', !next.disabled);

// The other bug: switching to the Entra path must not leak service permissions.
const entraChoice = $$('.choice').find(c => c.querySelector('input').value === 'entra');
entraChoice.click();
ok('Entra path narrows to 2 sections', $$('#sectionScopes input:checked').length === 2);
next.click(); // back to 4 -> re-render
$('#back').click();
const t = $('#permissions').textContent;
ok('Entra path shows 11 scopes', $$('#permissions tr').length === 11, `got ${$$('#permissions tr').length}`);
ok('Entra path leaks no SharePoint scope', !t.includes('SharePointTenantSettings'));
ok('Entra path leaks no Teams scope', !t.includes('TeamSettings'));
ok('Entra path leaks no Intune scope', !t.includes('DeviceManagement'));

// Manifest-driven download.
ok('download box rendered from manifest', $('#downloadBox').textContent.includes('v' + man.runner.version));
ok('SHA256 published on the page', /[0-9a-f]{64}/.test($('#downloadBox').textContent));
ok('download link points at the package',
  $('#downloadBox a')?.getAttribute('href') === man.runner.url,
  $('#downloadBox a')?.getAttribute('href'));
ok('unsigned build is labelled', $('.unsigned') !== null);

// Quickstart: the page must tell the user exactly what to run.
const qs = $('#quickstart').textContent;
ok('quickstart lists the run commands', $$('#quickstart .steps-list li').length >= 5,
  `got ${$$('#quickstart .steps-list li').length} steps`);
ok('quickstart names the downloaded zip', qs.includes(man.runner.file));
ok('quickstart offers the hash check', qs.includes(man.runner.sha256.toUpperCase()));
ok('quickstart shows -WhatIfPlan before the real run', qs.indexOf('-WhatIfPlan') < qs.indexOf('-TenantId'));
ok('quickstart shows -DryRun', qs.includes('-DryRun'));
ok('quickstart does not pass -RunPlan (auto-discovery)', !qs.includes('-RunPlan'));
ok('catalog provenance shown', $('#catalogMeta').textContent.includes('M365-Assess 2.13.0'));

console.log(`\n${fail === 0 ? 'all DOM checks passed' : fail + ' FAILED'}`);
srv.close();
window.close();
process.exit(fail ? 1 : 0);
