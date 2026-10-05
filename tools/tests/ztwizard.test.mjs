// Zero Trust standalone flow test. Same approach as wizard.test.mjs: loads the real page into
// jsdom, imports the real controller, drives permissions -> connect -> consent -> run -> results
// with Microsoft sign-in and Graph mocked. Areas are locked to identity + privileged throughout
// — there is no framework or scope step to skip past.
import { JSDOM } from 'jsdom';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { HARDENED, mockFetch, DNS_HARDENED } from './fixtures.mjs';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const html = readFileSync(join(root, 'zero-trust-assessment.html'), 'utf8');
const checksJson = readFileSync(join(root, 'assets/catalog/checks.json'), 'utf8');

let fail = 0;
const ok = (name, cond, extra = '') => {
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${name}${!cond && extra ? ' -> ' + extra : ''}`);
  if (!cond) fail++;
};
const tick = () => new Promise(r => setTimeout(r, 0));

// ---- static page assertions ---------------------------------------------------------------
ok('MSAL is loaded from a pinned version', /msal-browser@\d+\.\d+\.\d+\/lib\/msal-browser\.min\.js/.test(html));
ok('controller is loaded as a module', html.includes("import('./assets/app/zt-main.js')") && /<script type="module">/.test(html));
ok('a failed module import shows the boot banner instead of a blank wizard', /import\('\.\/assets\/app\/zt-main\.js'\)\.catch/.test(html));
ok('only three steps are declared', (html.match(/class="step[" ]/g) || []).length === 3, String((html.match(/class="step[" ]/g) || []).length));
ok('no trace of the framework or scope picker', !html.includes('id="frameworks"') && !html.includes('id="scopeAreas"'));
ok('no Exchange evidence file UI', !html.includes('evidenceFile') && !html.includes('evidenceRow'));
ok('links back to the Zero Trust overview and the full assessment', html.includes('href="zero-trust.html"') && html.includes('href="assessments.html"'));
ok('attribution present', html.includes('M365-Assess') && html.includes('MIT licensed'));

// ---- boot the real controller in jsdom ----------------------------------------------------
const dom = new JSDOM(html, { url: 'http://localhost:8080/zero-trust-assessment.html', pretendToBeVisual: true });
const { window } = dom;
window.scrollTo = () => {};
window.__IFFL_MANUAL_INIT = true;
globalThis.window = window;
globalThis.document = window.document;
globalThis.HTMLElement = window.HTMLElement;
globalThis.Blob = window.Blob;
globalThis.URL.createObjectURL = () => 'blob:mock';
globalThis.URL.revokeObjectURL = () => {};

const graph = mockFetch(HARDENED, { dns: DNS_HARDENED });
globalThis.fetch = async (url, opts) => {
  if (opts?.method === 'HEAD') return { ok: true, status: 200, headers: { get: (h) => (h === 'etag' ? 'v1' : null) } };
  if (String(url).includes('checks.json')) return { ok: true, status: 200, json: async () => JSON.parse(checksJson) };
  if (String(url).includes('app-tiers.json')) return { ok: true, status: 200, json: async () => JSON.parse(readFileSync(join(root, 'assets/catalog/app-tiers.json'), 'utf8')) };
  return graph(url, opts);
};

const { CONFIG } = await import('../../assets/app/config.js');
const history = await import('../../assets/app/history.js');
const mem = new Map();
history.useStorage({ getItem: k => (mem.has(k) ? mem.get(k) : null), setItem: (k, v) => mem.set(k, String(v)), removeItem: k => mem.delete(k) });
const zt = await import('../../assets/app/zt-main.js');

const $ = (s) => window.document.querySelector(s);
const $$ = (s) => [...window.document.querySelectorAll(s)];
const active = () => +$('.panel.active').dataset.panel;
const visible = (id) => !$(`#${id}`).hidden;

let granted = ['Policy.Read.All', 'Directory.Read.All', 'RoleManagement.Read.Directory', 'User.Read.All', 'Domain.Read.All', 'Application.Read.All', 'AccessReview.Read.All'];
let consentCalls = 0;
const authMock = {
  signIn: async () => ({ username: 'admin@contoso.com', tenantId: 'tid-1' }),
  getToken: async () => ({ token: 'tok', grantedScopes: [...granted] }),
  requestAdminConsent: async () => { consentCalls++; granted = [...granted, 'AuditLog.Read.All']; return { completed: true }; },
  signOut: () => {},
  reload: () => {},
  settleMs: 0
};

CONFIG.clientId = '11111111-2222-3333-4444-555555555555';
await zt.init(authMock);
await tick();

// ---- step 1: permissions -------------------------------------------------------------------
ok('step 1 active on load', active() === 1);
const permRows = $$('#permissions tr');
ok('permissions reflect exactly identity + privileged, no more', permRows.length === 8, `got ${permRows.length}`);
ok('every permission is read-only', $$('#permissions .read-only').length === 8);
ok('catalog meta names both areas', $('#catalogMeta').textContent.includes('Identity') && $('#catalogMeta').textContent.includes('privileged'));
ok('step 1 button leads to sign-in', $('#next').textContent.includes('sign-in'));

// ---- step 2: connect ------------------------------------------------------------------------
$('#next').click();
ok('step 2 active', active() === 2);
ok('Continue hidden on the connect step', $('#next').hidden);
ok('Run hidden before sign-in', !visible('btnRun'));

$('#tenantInput').value = 'contoso.onmicrosoft.com';
$('#btnSignIn').click(); await tick(); await tick();
ok('signed-in identity shown', $('#signedInAs').textContent === 'admin@contoso.com');
ok('missing scope reported by name', $('#connectStatus').textContent.includes('AuditLog.Read.All'));
ok('consent button offered when a scope is missing', visible('btnConsent'));

$('#btnConsent').click(); await tick(); await tick();
ok('consent was requested once', consentCalls === 1);
ok('consent success re-acquires token and clears the warning', /All required/.test($('#connectStatus').textContent));
ok('consent button hidden once granted', !visible('btnConsent'));

// ---- run --------------------------------------------------------------------------------
$('#btnRun').click();
for (let i = 0; i < 40 && active() !== 3; i++) await tick();
ok('run lands on results (step 3)', active() === 3);
ok('report only covers the two locked areas', zt.getState().report.areas.map(a => a.id).sort().join() === 'identity,privileged',
  zt.getState().report.areas.map(a => a.id).join());
ok('hero and stat tiles rendered', $$('#scoreCards .tile').length === 4);
ok('result rows match the report, nothing filtered to an "other" bucket', $$('#resultRows tr').length === zt.getState().report.results.length && !visible('otherWrap'));
ok('run metadata names both areas', $('#runMeta').textContent.includes('Identity') && $('#runMeta').textContent.includes('privileged'));
ok('framework rollup still renders (unfiltered)', $$('#frameworkRows tr').length > 0);
ok('downloads are wired', typeof $('#dlHtml').onclick === 'function' && typeof $('#dlXlsx').onclick === 'function');

console.log(`\n${fail === 0 ? 'all Zero Trust flow checks passed' : fail + ' FAILED'}`);
process.exit(fail ? 1 : 0);
