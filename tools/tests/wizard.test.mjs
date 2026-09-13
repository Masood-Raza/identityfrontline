// Flow test. Loads the real page into jsdom, imports the real controller, and drives the whole
// journey — frameworks, scope, permissions, sign-in, consent, run, results, download — with
// Microsoft sign-in and Graph mocked. Both regressions from the first wizard are covered.
import { JSDOM } from 'jsdom';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { HARDENED, DEFAULTS, mockFetch } from './fixtures.mjs';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const html = readFileSync(join(root, 'assessments.html'), 'utf8');
const checksJson = readFileSync(join(root, 'assets/catalog/checks.json'), 'utf8');

let fail = 0;
const ok = (name, cond, extra = '') => {
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${name}${!cond && extra ? ' -> ' + extra : ''}`);
  if (!cond) fail++;
};
const tick = () => new Promise(r => setTimeout(r, 0));

// ---- static page assertions ---------------------------------------------------------------
ok('MSAL is loaded from a pinned version', /msal-browser@\d+\.\d+\.\d+\/lib\/msal-browser\.min\.js/.test(html));
ok('controller is loaded as a module', html.includes('<script type="module" src="assets/app/main.js">'));
for (const stale of ['downloadBox', 'quickstart', 'sectionScopes', 'manifest.json', 'Invoke-IdentityFrontline', 'Download run plan']) {
  ok(`no trace of the runner flow: "${stale}"`, !html.includes(stale));
}
for (const scope of ['Directory.Read.All', 'AuditLog.Read.All', 'Policy.Read.All']) {
  ok(`page does not hard-code ${scope}`, !html.includes(scope));
}
ok('page states nothing reaches the site', /No tenant data passes through this website/.test(html));
ok('attribution present', html.includes('M365-Assess') && html.includes('MIT licensed'));

// ---- boot the real controller in jsdom ----------------------------------------------------
const dom = new JSDOM(html, { url: 'http://localhost:8080/assessments.html', pretendToBeVisual: true });
const { window } = dom;
window.scrollTo = () => {};
window.__IFFL_MANUAL_INIT = true;
globalThis.window = window;
globalThis.document = window.document;
globalThis.HTMLElement = window.HTMLElement;
globalThis.Blob = window.Blob;
globalThis.URL.createObjectURL = () => 'blob:mock';
globalThis.URL.revokeObjectURL = () => {};

let downloads = [];
const realCreate = window.document.createElement.bind(window.document);
window.document.createElement = (tag) => {
  const n = realCreate(tag);
  if (tag === 'a') n.click = () => downloads.push(n.download);
  return n;
};

let releaseStamp = 'v1';
let reloads = 0;
const graph = mockFetch(HARDENED);
globalThis.fetch = async (url, opts) => {
  if (opts?.method === 'HEAD') {
    return { ok: true, status: 200, headers: { get: (h) => (h === 'etag' ? releaseStamp : null) } };
  }
  if (String(url).includes('checks.json')) {
    return { ok: true, status: 200, json: async () => JSON.parse(checksJson) };
  }
  if (String(url).includes('app-tiers.json')) {
    return { ok: true, status: 200, json: async () => JSON.parse(readFileSync(join(root, 'assets/catalog/app-tiers.json'), 'utf8')) };
  }
  return graph(url, opts);
};

const { CONFIG } = await import('../../assets/app/config.js');
const history = await import('../../assets/app/history.js');
const mem = new Map();
history.useStorage({ getItem: k => (mem.has(k) ? mem.get(k) : null), setItem: (k, v) => mem.set(k, String(v)), removeItem: k => mem.delete(k) });
const main = await import('../../assets/app/main.js');

const $ = (s) => window.document.querySelector(s);
const $$ = (s) => [...window.document.querySelectorAll(s)];
const active = () => +$('.panel.active').dataset.panel;
const visible = (id) => !$(`#${id}`).hidden;

// Injected auth: first sign-in is short one scope, consent then grants it.
let granted = ['Policy.Read.All', 'Directory.Read.All', 'RoleManagement.Read.Directory', 'User.Read.All', 'Domain.Read.All'];
let consentCalls = 0;
const authMock = {
  signIn: async () => ({ username: 'admin@contoso.com', tenantId: 'tid-1' }),
  getToken: async () => ({ token: 'tok', grantedScopes: [...granted] }),
  requestAdminConsent: async () => {
    consentCalls++;
    granted = [...granted, 'AuditLog.Read.All', 'SharePointTenantSettings.Read.All', 'TeamworkAppSettings.Read.All', 'OrgSettings-Forms.Read.All'];
    return { completed: true };
  },
  signOut: () => {},
  reload: () => { reloads++; }
};

// ---- unconfigured deployment shows setup, never a broken sign-in -------------------------
// Force the placeholder regardless of what config.js ships with, so the setup path is always tested.
CONFIG.clientId = 'REPLACE_WITH_YOUR_CLIENT_ID';
await main.init(authMock);
await tick();
ok('setup notice shown when clientId is a placeholder', visible('setupNotice'));
ok('setup notice lists the exact scopes', $('#setupScopes').textContent.includes('AuditLog.Read.All'));
ok('setup notice lists the redirect URI', $('#setupRedirect').textContent.includes('assessments.html'));

// ---- step 1: frameworks from checks.json --------------------------------------------------
ok('step 1 active on load', active() === 1);
const fw = $$('#frameworks input');
ok('frameworks rendered from the check catalog', fw.length === 15, `got ${fw.length}`);
ok('framework labels are versioned', $$('#frameworks label').some(l => /v6\.0\.1|Rev 5|2022/.test(l.textContent)));
fw[0].checked = true; fw[0].onchange();
ok('selecting a framework updates state', main.getState().frameworks.size === 1);
fw[1].checked = true; fw[1].onchange();
const chosen = [fw[0].value, fw[1].value];
ok('two frameworks selected for the run', main.getState().frameworks.size === 2);

// ---- step 2: scope ----------------------------------------------------------------------
$('#next').click();
ok('step 2 active', active() === 2);
ok('four areas rendered with check counts', $$('#scopeAreas .choice').length === 4 && /37 checks/.test($('#scopeAreas').textContent));
ok('identity is preselected', $$('#scopeAreas input:checked').map(i => i.value).join() === 'identity');
ok('unreachable areas disclosed', $$('#scopeSoon .soon-item').length === 4);
// Add Collaboration. Permissions must follow the selection.
for (const id of ['collaboration']) { const i = $$('#scopeAreas input').find(x => x.value === id); i.checked = true; i.onchange(); }
ok('two areas selected', main.getState().areas.size === 2);
const idOnly = $$('#scopeAreas input').find(x => x.value === 'identity'); idOnly.checked = false; idOnly.onchange();
ok('identity can be deselected while other areas remain', main.getState().areas.size === 1 && !main.getState().areas.has('identity'));
idOnly.checked = true; idOnly.onchange();
ok('identity re-added', main.getState().areas.size === 2);

// ---- step 3: permissions ----------------------------------------------------------------
$('#next').click();
ok('step 3 active', active() === 3);
const permRows = $$('#permissions tr');
ok('permissions follow the area selection: 9 for identity + collaboration', permRows.length === 9, `got ${permRows.length}`);
ok('every permission is read-only', $$('#permissions .read-only').length === 9);
ok('SharePoint scope has a stated reason', $('#permissions').textContent.includes('SharePointTenantSettings.Read.All') && /sharing/i.test($('#permissions').textContent));
ok('AuditLog.Read.All has a stated reason', $('#permissions').textContent.includes('MFA registration'));
ok('step 3 button leads to sign-in', $('#next').textContent.includes('sign-in'));

// ---- step 4: connect --------------------------------------------------------------------
$('#next').click();
ok('step 4 active', active() === 4);
ok('Continue hidden on the connect step', $('#next').hidden);
ok('Run hidden before sign-in', !visible('btnRun'));

$('#btnSignIn').click(); await tick();
ok('empty tenant is rejected', /Enter your tenant/.test($('#connectStatus').textContent));

$('#tenantInput').value = 'contoso.onmicrosoft.com';
$('#btnSignIn').click(); await tick();
ok('placeholder clientId blocks sign-in with guidance', /no app registration/.test($('#connectStatus').textContent));

CONFIG.clientId = '11111111-2222-3333-4444-555555555555';
$('#btnSignIn').click(); await tick(); await tick();
ok('signed-in identity shown', $('#signedInAs').textContent === 'admin@contoso.com');
ok('missing scope reported by name', $('#connectStatus').textContent.includes('AuditLog.Read.All'));
ok('consent button offered when a scope is missing', visible('btnConsent'));
ok('Run offered even with reduced coverage', visible('btnRun'));

$('#btnConsent').click(); await tick(); await tick();
ok('consent was requested once', consentCalls === 1);
ok('consent success re-acquires token and clears the warning', /All required/.test($('#connectStatus').textContent));
ok('consent button hidden once granted', !visible('btnConsent'));

// ---- run --------------------------------------------------------------------------------
$('#btnRun').click();
for (let i = 0; i < 40 && active() !== 5; i++) await tick();
ok('run lands on results', active() === 5);
ok('score cards rendered, including partial', $$('#scoreCards .fact').length === 6 && /Warning/.test($('#scoreCards').textContent));
ok('hardened tenant shows 100% pass rate', $('#scoreCards').textContent.includes('100%'));
ok('in-scope findings listed', $$('#resultRows tr').length === main.getState().report.scope.inScopeCount, `got ${$$('#resultRows tr').length}`);
ok('framework rollup rendered', $$('#frameworkRows tr').length > 0);
ok('nothing unavailable on a full run', !visible('unavailableWrap'));
ok('run metadata names the tenant', $('#runMeta').textContent.includes('contoso.onmicrosoft.com'));

// ---- downloads --------------------------------------------------------------------------
$('#dlHtml').click(); $('#dlCsv').click(); $('#dlJson').click();
ok('three downloads produced', downloads.length === 3, downloads.join(','));
ok('download names carry tenant and date', downloads.every(d => /contoso-onmicrosoft-com-\d{4}-\d{2}-\d{2}\.(html|csv|json)$/.test(d)), downloads.join(','));

const { buildHtmlReport, buildWorkbook } = await import('../../assets/app/report.js');
const XLSXlib = (await import('xlsx')).default;
const rpt = buildHtmlReport(main.getState().report);
const { explorer: explorerFn } = await import('../../assets/app/explore.js');
ok('HTML report references nothing external', !/src="http|href="http|<link|@import|url\(/.test(rpt.replace(/https:\/\/github\.com\/Galvnyz\/M365-Assess/g, '')));
const scripts = [...rpt.matchAll(/<script>([\s\S]*?)<\/script>/g)].map(m => m[1]);
ok('the only script in the report is the embedded explorer, verbatim', scripts.length === 1 && scripts[0].includes(explorerFn.toString()));
ok('the embedded explorer has no network capability', !/fetch|XMLHttpRequest|import\(|WebSocket|navigator\.sendBeacon/.test(scripts[0]));
ok('report rows carry filter attributes', /<tr class="s-(pass|fail|warning)" data-status="(pass|fail|warning)" data-sev="[a-z]+" data-area="[a-z]+" data-changed="" data-text="/.test(rpt));
ok('long control lists fold past eight', /<details class="more"><summary>\+\d+ more<\/summary>/.test(rpt));
ok('executive summary is short paragraphs, not one block', (rpt.match(/<p class="lead">/g) || []).length >= 4);
ok('report detail cells carry no whitespace-only lines', !/<td>[^<]*\n\s*\n/.test(rpt));

// The standalone report must filter on its own, with no app around it.
{
  const rdom = new JSDOM(rpt, { runScripts: 'dangerously' });
  const d = rdom.window.document;
  const rows = () => [...d.querySelectorAll('tbody[data-explore] tr[data-status]')];
  const visible = () => rows().filter(r => !r.hasAttribute('hidden'));
  ok('standalone report: explorer toolbar present', !!d.querySelector('.explorer .x-search'));
  ok('standalone report: chip counts filled in', d.querySelector('.x-chip[data-value="fail"] .x-n').textContent === String(rows().filter(r => r.dataset.status === 'fail').length));
  ok('standalone report: everything visible by default', visible().length === rows().length && /^All \d+ findings$/.test(d.querySelector('.x-count').textContent));
  d.querySelector('.x-chip[data-value="critical"]').click();
  d.querySelector('.x-chip[data-value="high"]').click();
  ok('standalone report: Critical + High chips show only those severities', visible().length > 0 && visible().every(r => ['critical', 'high'].includes(r.dataset.sev)));
  d.querySelector('.x-chip[data-value="pass"]').click();
  ok('standalone report: keys combine with AND, values within a key with OR', visible().every(r => r.dataset.status === 'pass' && ['critical', 'high'].includes(r.dataset.sev)));
  const q = d.querySelector('.x-search'); q.value = 'entra-admin-001'; q.dispatchEvent(new rdom.window.Event('input'));
  ok('standalone report: search narrows further and can empty a table', d.querySelectorAll('tr.x-empty').length >= 1);
  d.querySelector('.x-clear').click();
  ok('standalone report: clear restores every row and removes empty-state rows', visible().length === rows().length && d.querySelectorAll('tr.x-empty').length === 0);
  q.value = 'CA-SIGNINRISK'; q.dispatchEvent(new rdom.window.Event('input'));
  ok('standalone report: search is case-insensitive and matches check IDs', visible().length >= 1 && visible().every(r => r.dataset.text.includes('ca-signinrisk')));
  q.value = '164.312(a)(2)(ii)'; q.dispatchEvent(new rdom.window.Event('input'));
  ok('standalone report: a control ID finds the checks that map to it', visible().length >= 1);
  ok('standalone report: filters hidden when printing', /@media print\{\.explorer\{display:none\}\}/.test(rpt));
}
ok('HTML report escapes content', !/<script>alert/.test(rpt));
ok('HTML report states data never left the browser', /No tenant data was transmitted/.test(rpt));

// ---- framework selection actually narrows the output ------------------------------------
const rep1 = main.getState().report;
ok('report records the two selected frameworks', JSON.stringify(rep1.frameworkFilter) === JSON.stringify(chosen), JSON.stringify(rep1.frameworkFilter));
ok('coverage table shows only the selected frameworks', $$('#frameworkRows tr').length === 2, `got ${$$('#frameworkRows tr').length}`);
ok('framework note names the scope', $('#frameworkNote').textContent.includes(main.getState().report.scope.frameworks[0].label));
const labels = chosen.map(id => JSON.parse(checksJson).frameworks[id].label);
ok('HTML report title names the scope', new RegExp(`<title>[^<]*${labels[0].replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`).test(rpt), rpt.match(/<title>[^<]*/)?.[0]);
ok('HTML report header states the scope', rpt.includes('Scope: ' + labels[0]));
ok('HTML report headline is scored against the scope', /Scored against the \d+ checks that map to/.test(rpt));
ok('HTML report also states the all-checks rate', /Across all \d+ checks regardless of framework/.test(rpt));
ok('HTML report lists out-of-scope findings separately', /Other findings — not mapped to/.test(rpt));
ok('page states the scope', $('#scopeNote').textContent.includes(labels[0]) && /Across all checks/.test($('#scopeNote').textContent));
ok('page findings title names the scope', $('#findingsTitle').textContent.includes(labels[0]));
ok('page shows out-of-scope findings in their own section', visible('otherWrap') && $$('#otherRows tr').length > 0);
ok('in-scope plus other rows equal all checks for two areas (54)', $$('#resultRows tr').length + $$('#otherRows tr').length === 54, String($$('#resultRows tr').length + $$('#otherRows tr').length));
ok('results include SharePoint and Teams checks', /SPO-SHARING-001/.test($('#resultRows').textContent + $('#otherRows').textContent) && /TEAMS-APPS-001/.test($('#resultRows').textContent + $('#otherRows').textContent));
ok('run metadata names the areas', /Collaboration/.test($('#runMeta').textContent));
ok('remember-this-run is on by default', $('#rememberRun').checked);
ok('first run: nothing to compare, and it was remembered', /First remembered run/.test($('#driftSummary').textContent) && mem.size === 1);
ok('first run: no drift badges', $$('#resultRows .drift').length === 0);
{
  const rows = () => $$('#resultRows tr[data-status], #otherRows tr[data-status]');
  const visible = () => rows().filter(r => !r.hasAttribute('hidden'));
  ok('page: explorer rendered above findings', !!$('#explorer .x-search') && $$('#explorer .x-chip').length >= 9);
  ok('page: area chips offered for a multi-area run', $$('#explorer .x-chip[data-key="area"]').length === 2);
  ok('page: no drift row of chips before a comparison exists', $$('#explorer .x-chip[data-key="changed"]').length === 0);
  $('#explorer .x-chip[data-value="collaboration"]').click();
  ok('page: area chip narrows to that area', visible().length > 0 && visible().every(r => r.dataset.area === 'collaboration'));
  ok('page: count reflects the filter', /^\d+ of \d+ findings$/.test($('#explorer .x-count').textContent));
  $('#explorer .x-clear').click();
  ok('page: clear restores all rows', visible().length === rows().length);
  const q = $('#explorer .x-search'); q.value = 'sharing'; q.dispatchEvent(new window.Event('input'));
  ok('page: search matches names and details', visible().length > 0 && visible().every(r => r.dataset.text.includes('sharing')));
  q.value = ''; q.dispatchEvent(new window.Event('input'));
  ok('page: executive summary is several paragraphs', $$('#execSummary p').length >= 3);
}
ok('first run: HTML report has no changes section', !/Changes since/.test(buildHtmlReport(main.getState().report)));
ok('run metadata names the scope', $('#runMeta').textContent.includes('Scope: '));
ok('executive summary rendered on page', /passed \d+ of \d+ scored checks/.test($('#execSummary').textContent), $('#execSummary').textContent);
ok('no priorities on a clean tenant', !visible('priorityWrap'));

// ---- Excel workbook, built for real and read back -----------------------------------------
globalThis.XLSX = XLSXlib;
const wb = buildWorkbook(rep1, XLSXlib);
ok('workbook has the four sheets', JSON.stringify(wb.SheetNames) === JSON.stringify(['Summary', 'Findings', 'Compliance matrix', 'Framework coverage']), wb.SheetNames.join(','));
const roundTrip = XLSXlib.read(XLSXlib.write(wb, { bookType: 'xlsx', type: 'array' }), { type: 'array' });
const matrix = XLSXlib.utils.sheet_to_json(roundTrip.Sheets['Compliance matrix'], { header: 1 });
ok('matrix has one row per in-scope check', matrix.length - 1 === rep1.scope.inScopeCount, `${matrix.length - 1} vs ${rep1.scope.inScopeCount}`);
ok('matrix columns are the selected frameworks only', matrix[0].length === 4 + chosen.length, matrix[0].join(' | '));
const findings = XLSXlib.utils.sheet_to_json(roundTrip.Sheets['Findings'], { header: 1 });
ok('findings sheet carries every result', findings.length - 1 === rep1.results.length);
ok('findings sheet has an autofilter', !!wb.Sheets['Findings']['!autofilter']);
const summarySheet = XLSXlib.utils.sheet_to_csv(roundTrip.Sheets['Summary']);
ok('summary sheet names the tenant and privacy statement', /contoso\.onmicrosoft\.com/.test(summarySheet) && /No tenant data was transmitted/.test(summarySheet));
$('#dlXlsx').click();
for (let i = 0; i < 20 && downloads.length < 4; i++) await tick();
ok('Excel download produced', downloads.some(d => d.endsWith('.xlsx')), downloads.join(','));

// ---- print: hands the self-contained report to a new window ----------------------------
let printed = false, written = '';
window.open = () => ({ document: { open() {}, write(h) { written = h; }, close() {} }, focus() {}, print() { printed = true; } });
$('#btnPrint').click();
await new Promise(r => setTimeout(r, 400));
ok('print opens the report in a new window', /Microsoft 365 security assessment/.test(written));
ok('print dialog invoked', printed);
ok('report carries print styles', /@media print/.test(written) && /@page/.test(written));

// ---- restart: the two original regressions ----------------------------------------------
$('#btnRestart').click(); await tick();
ok('restart returns to step 1', active() === 1);
ok('restart re-enables Continue (regression: dead-end after Back)', !$('#next').hidden && !$('#next').disabled);
ok('restart clears the session', main.getState().session === null);
ok('sign-in button label reset', $('#btnSignIn').textContent === 'Sign in with Microsoft');

// ---- degraded run: a denied source must not break the page ------------------------------
globalThis.fetch = (() => {
  const g = mockFetch(DEFAULTS, { deny: ['/reports/authenticationMethods'] });
  return async (url, o) => o?.method === 'HEAD'
    ? { ok: true, status: 200, headers: { get: (h) => (h === 'etag' ? releaseStamp : null) } }
    : String(url).includes('checks.json')
    ? { ok: true, status: 200, json: async () => JSON.parse(checksJson) } : g(url, o);
})();
$('#next').click(); $('#next').click(); $('#next').click();
$('#tenantInput').value = 'fabrikam.onmicrosoft.com';
$('#btnSignIn').click(); await tick(); await tick();
$('#btnRun').click();
for (let i = 0; i < 40 && active() !== 5; i++) await tick();
ok('degraded run still reaches results', active() === 5);
ok('unavailable section shown', visible('unavailableWrap'));
ok('unavailable reason is translated for the reader, not a stack trace', /does not include this permission/.test($('#unavailableRows').textContent), $('#unavailableRows').textContent);
ok('failures surfaced with severity', $$('#resultRows .status.fail').length > 10);
ok('partial compliance shown as Warning rows', $$('#resultRows .status.warning').length + $$('#otherRows .status.warning').length > 0);
ok('sev row carries the partial pill', /partial/.test($('#sevRow').textContent));
ok('remediation shown on failed rows', $$('#resultRows .rem').length > 0);
ok('fix-first list shown with five items on a failing tenant', visible('priorityWrap') && $$('#priorityList li').length === 5, `${$$('#priorityList li').length}`);
ok('executive summary names what to address first', /Address first:/.test($('#execSummary').textContent));
ok('framework selection survives a restart', main.getState().frameworks.size === 2 && $$('#frameworkRows tr').length === 2);

// ---- drift: same tenant, worse posture ----------------------------------------------------
const rep2 = main.getState().report;
ok('second run is compared with the first', !!rep2.drift && /Compared with the run on/.test($('#driftSummary').textContent));
ok('pass rate delta is negative and shown', rep2.drift.delta < 0 && /▼/.test($('#driftSummary').textContent), String(rep2.drift.delta));
ok('regressions listed', rep2.drift.regressed.length > 10 && $$('#driftRegressed li').length === rep2.drift.regressed.length, String(rep2.drift.regressed.length));
ok('nothing fixed on a worse run', rep2.drift.fixed.length === 0 && /None/.test($('#driftFixed').textContent));
ok('same areas both times: nothing new or dropped', rep2.drift.added.length === 0 && rep2.drift.dropped === 0);
ok('regressed rows carry a badge', $$('#resultRows .drift.down').length + $$('#otherRows .drift.down').length === rep2.drift.regressed.length);
ok('page: drift chips appear once a comparison exists', $$('#explorer .x-chip[data-key="changed"]').length === 4);
$('#explorer .x-chip[data-value="regressed"]').click();
ok('page: Regressed chip shows exactly the regressed checks', $$('#resultRows tr[data-status]:not([hidden]), #otherRows tr[data-status]:not([hidden])').length === rep2.drift.regressed.length);
$('#explorer .x-clear').click();
ok('executive summary mentions the change', /Since the run on/.test($('#execSummary').textContent));
const rpt2 = buildHtmlReport(rep2);
ok('HTML report has a changes section', /Changes since/.test(rpt2) && /Regressed/.test(rpt2));
ok('HTML report says comparison data stays in the browser', /kept only in the browser/.test(rpt2));
const wb2 = buildWorkbook(rep2, XLSXlib);
ok('workbook gains a Changes sheet', wb2.SheetNames.includes('Changes'));
ok('two runs remembered for the tenant', history.list(rep2.tenant).length === 2);
$('#btnForget').click();
ok('forget clears stored runs and says so', history.list(rep2.tenant).length === 0 && /forgotten/.test($('#driftSummary').textContent));
ok('forget hides the lists and the button', $('#driftLists').hidden && $('#btnForget').hidden);

// ---- a tab open across a deploy must not keep running stale code --------------------------
ok('same release: no reload so far', reloads === 0);
releaseStamp = 'v2';
$('#btnRestart').click(); await tick(); await tick();
ok('start again after a deploy reloads the page instead of restarting the wizard', reloads === 1);
ok('a stale tab stays on the results step rather than half-restarting', active() === 5);

console.log(`\n${fail === 0 ? 'all flow checks passed' : fail + ' FAILED'}`);
process.exit(fail ? 1 : 0);
