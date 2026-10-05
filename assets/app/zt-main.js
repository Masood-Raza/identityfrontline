// Identity Frontline — Zero Trust assessment (standalone).
//
// A dedicated, locked-scope entry point: Identity & access and Applications & privileged
// access only, no framework or area picker. Same engine, checks and report rendering as the
// full assessment (assets/app/engine.js, checks.js, report.js, explore.js) — only the wizard
// shell here is specific to this page. Flow: permissions -> connect -> run -> results.

import { CONFIG, isConfigured } from './config.js';
import * as auth from './auth.js';
import { missingScopes } from './auth.js';
import { runAssessment as realRun, scopesFor, checksFor } from './engine.js';
import { AREAS } from './checks.js';
import * as history from './history.js';
import { sortResults, downloadCsv, downloadJson, downloadHtml, downloadXlsx, downloadPlanMarkdown, printReport, executiveSummaryParts, scopeLabel, fixText, esc,
  areaCardsHtml, planHtml, signalsHtml, ticketText, effortLabel, ownerLabel, remediationPlan, heroHtml, alertBannerHtml, frameworkPickerHtml } from './report.js';
import { explorer, reportChrome, rowAttrs, explorerToolbar, EXPLORER_CSS, REPORT_CSS } from './explore.js';

const ZT_AREAS = ['identity', 'privileged'];

// Injectable for tests: the flow can be driven end to end with sign-in and Graph mocked.
const deps = {
  signIn: auth.signIn,
  getToken: auth.getToken,
  requestAdminConsent: auth.requestAdminConsent,
  signOut: auth.signOut,
  runAssessment: realRun,
  history,
  reload: () => window.location.reload(),
  settleMs: 4000
};

// Same staleness guard as the full assessment: a tab left open across a deploy keeps running
// what it loaded, and only reloads once every module answers and the release stamp has held
// still across two checks a few seconds apart.
const MODULES = ['zt-main.js', 'explore.js', 'report.js', 'engine.js', 'checks.js', 'history.js', 'auth.js', 'config.js'];
let bootStamp = null;
async function releaseStamp(file = 'zt-main.js') {
  try {
    const r = await fetch(`assets/app/${file}`, { method: 'HEAD', cache: 'no-cache' });
    if (!r.ok || !r.headers?.get) return null;
    return r.headers.get('etag') || r.headers.get('last-modified') || null;
  } catch { return null; }
}
const pause = (ms) => new Promise(r => setTimeout(r, ms));
async function releaseChanged() {
  const now = await releaseStamp();
  if (!bootStamp || !now || now === bootStamp) return false;
  await pause(deps.settleMs);
  const again = await releaseStamp();
  if (again !== now) return false;
  const all = await Promise.all(MODULES.map(m => releaseStamp(m)));
  return all.every(Boolean);
}

const el = (id) => document.getElementById(id);
const requiredScopes = () => scopesFor(ZT_AREAS);
const show = (id, on = true) => { const n = el(id); if (n) n.hidden = !on; };

const state = {
  step: 1,
  tenant: '',
  session: null,
  token: null,
  granted: [],
  report: null,
  busy: false
};

let checkCatalog = null;

// ---------------------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------------------
async function boot() {
  try {
    const res = await fetch('assets/catalog/checks.json', { cache: 'no-cache' });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    checkCatalog = await res.json();
  } catch {
    el('bootError').textContent =
      'The assessment catalog could not be loaded, so the planner is unavailable. Please reload the page.';
    show('bootError');
    return;
  }
  try {
    await bootUi();
  } catch (e) {
    el('bootError').textContent = `The assessment could not start (${e?.message || e}). Reload the page; if it persists, try again in a minute.`;
    show('bootError');
  }
}

async function bootUi() {
  if (!isConfigured()) {
    show('setupNotice');
    el('setupScopes').textContent = requiredScopes().join(', ');
    el('setupRedirect').textContent = CONFIG.redirectUri;
  }

  bootStamp = await releaseStamp();

  document.head.appendChild(Object.assign(document.createElement('style'), { textContent: EXPLORER_CSS }));
  document.head.appendChild(Object.assign(document.createElement('style'), { textContent: REPORT_CSS }));

  renderPermissions();
  renderMeta();
  wire();
  goto(1);
}

function renderMeta() {
  const n = checksFor(ZT_AREAS).length;
  const labels = AREAS.filter(a => ZT_AREAS.includes(a.id)).map(a => a.label).join(', ');
  el('catalogMeta').textContent =
    `${n} checks across ${labels} · registry ${checkCatalog.source.registry.dataVersion} · ${requiredScopes().length} read-only permissions`;
}

// ---------------------------------------------------------------------------------------
// Step 1 — permissions
// ---------------------------------------------------------------------------------------
function renderPermissions() {
  const why = {
    'Policy.Read.All': 'Conditional Access, authentication methods, consent and security defaults policies',
    'Directory.Read.All': 'Directory roles and tenant objects',
    'RoleManagement.Read.Directory': 'Who holds Global Administrator and other privileged roles',
    'User.Read.All': 'User and guest account counts',
    'Domain.Read.All': 'Verified domains and password expiry configuration',
    'AuditLog.Read.All': 'MFA registration report',
    'Application.Read.All': 'App registrations, enterprise applications, their credentials, owners, permissions and tenant-wide consent grants',
    'AccessReview.Read.All': 'Whether access reviews exist for guests and privileged roles'
  };
  el('permissions').innerHTML = requiredScopes().map(s => `
    <tr><td><code>${esc(s)}</code></td><td>Delegated</td>
    <td>${esc(why[s] || '')}</td>
    <td><span class="read-only">Read-only</span></td></tr>`).join('');
  el('scopeCount').textContent = requiredScopes().length;
}

// ---------------------------------------------------------------------------------------
// Navigation — three steps: permissions, connect & run, results.
// ---------------------------------------------------------------------------------------
function goto(n) {
  state.step = n;
  document.querySelectorAll('.panel').forEach(p => p.classList.toggle('active', +p.dataset.panel === n));
  document.querySelectorAll('.step').forEach(p => p.classList.toggle('active', +p.dataset.ind === n));
  el('back').style.visibility = n === 1 ? 'hidden' : 'visible';

  const next = el('next');
  next.hidden = n >= 2;
  next.textContent = n === 1 ? 'Continue to sign-in →' : 'Continue →';

  window.scrollTo({ top: el('start').offsetTop - 15, behavior: 'smooth' });
}

// ---------------------------------------------------------------------------------------
// Step 2 — connect, consent, run
// ---------------------------------------------------------------------------------------
function setStatus(msg, kind = 'info') {
  const n = el('connectStatus');
  n.className = `connect-status ${kind}`;
  n.innerHTML = msg;
  show('connectStatus');
}

function busy(on, label) {
  state.busy = on;
  ['btnSignIn', 'btnConsent', 'btnRun', 'next', 'back'].forEach(id => {
    const n = el(id); if (n) n.disabled = on;
  });
  if (label) setStatus(`<span class="spin"></span> ${esc(label)}`, 'info');
}

async function doSignIn() {
  const tenant = el('tenantInput').value.trim();
  if (!tenant) { setStatus('Enter your tenant domain or ID first.', 'warn'); return; }
  if (!isConfigured()) { setStatus('This deployment has no app registration configured yet. See the setup notice above.', 'warn'); return; }

  state.tenant = tenant;
  busy(true, 'Waiting for the Microsoft sign-in window…');
  try {
    state.session = await deps.signIn(requiredScopes(), tenant);
    const t = await deps.getToken(requiredScopes());
    state.token = t.token;
    state.granted = t.grantedScopes;

    const missing = missingScopes(requiredScopes(), state.granted);
    el('signedInAs').textContent = state.session.username || state.session.name || 'signed in';
    show('signedInRow');

    if (missing.length) {
      setStatus(
        `Signed in, but ${missing.length} permission${missing.length === 1 ? '' : 's'} still ${missing.length === 1 ? 'needs' : 'need'} administrator consent: ` +
        missing.map(m => `<code>${esc(m)}</code>`).join(', ') +
        '. Grant consent, or run anyway and those checks will report as Unknown.', 'warn');
      show('btnConsent');
    } else {
      setStatus('Signed in with all required read-only permissions granted.', 'ok');
      show('btnConsent', false);
    }
    show('btnRun');
    el('btnSignIn').textContent = 'Sign in as someone else';
  } catch (e) {
    setStatus(`Sign-in did not complete: ${esc(e.message || e)}`, 'warn');
  } finally {
    busy(false);
  }
}

async function doConsent() {
  busy(true, 'Waiting for the administrator consent window…');
  try {
    const outcome = await deps.requestAdminConsent(state.tenant, requiredScopes());
    if (outcome.completed) {
      setStatus('Consent granted. Re-acquiring a token with the new permissions…', 'info');
      const t = await deps.getToken(requiredScopes());
      state.token = t.token;
      state.granted = t.grantedScopes;
      const missing = missingScopes(requiredScopes(), state.granted);
      if (missing.length) {
        setStatus(`Consent recorded, but these are still missing: ${missing.map(m => `<code>${esc(m)}</code>`).join(', ')}.`, 'warn');
      } else {
        setStatus('All required read-only permissions are granted.', 'ok');
        show('btnConsent', false);
      }
    } else if (outcome.reason === 'popup-blocked') {
      setStatus('The consent window was blocked. Allow popups for this site and try again.', 'warn');
    } else if (outcome.error) {
      setStatus(`Consent was not granted: ${esc(outcome.errorDescription || outcome.error)}`, 'warn');
    } else {
      setStatus('The consent window closed before consent was granted.', 'warn');
    }
  } catch (e) {
    setStatus(`Consent failed: ${esc(e.message || e)}`, 'warn');
  } finally {
    busy(false);
  }
}

async function doRun() {
  busy(true, 'Starting…');
  show('progressWrap');
  try {
    if (await releaseChanged()) {
      setStatus('A newer version of this assessment has been published. Reloading to use it…', 'warn');
      deps.reload();
      return;
    }
    const t = await deps.getToken(requiredScopes());
    state.token = t.token;

    state.report = await deps.runAssessment({
      token: state.token,
      catalog: checkCatalog,
      tenant: { name: state.tenant, id: state.session?.tenantId },
      frameworks: [],
      areas: ZT_AREAS,
      onProgress: ({ phase, current, total, label }) => {
        const p = Math.round((current / total) * 100);
        el('progressBar').style.width = `${p}%`;
        el('progressLabel').textContent =
          phase === 'collect' ? `Reading ${label} (${current} of ${total})` : 'Evaluating checks…';
      }
    });

    const previous = deps.history.latest(state.report.tenant);
    state.report.drift = deps.history.diff(state.report, previous);
    state.report.remembered = el('rememberRun').checked ? deps.history.save(state.report) : false;

    renderResults(state.report);
    goto(3);
    setStatus('Assessment complete.', 'ok');
  } catch (e) {
    setStatus(`The assessment could not complete: ${esc(e.message || e)}`, 'warn');
  } finally {
    busy(false);
    show('progressWrap', false);
  }
}

// ---------------------------------------------------------------------------------------
// Step 3 — results (identical rendering to the full assessment's results step)
// ---------------------------------------------------------------------------------------
function renderResults(report) {
  const s = report.summary;
  el('scoreCards').innerHTML = heroHtml(report);
  el('alertBanner').innerHTML = alertBannerHtml(report);

  const sev = ['Critical', 'High', 'Medium', 'Low']
    .filter(k => s.failedBySeverity[k] > 0)
    .map(k => `<span class="pill ${k.toLowerCase()}">${s.failedBySeverity[k]} ${k}</span>`).join(' ');
  el('sevRow').innerHTML = (sev || '<span class="pill none">No failed checks</span>') +
    (s.warning ? ` <span class="pill warning">${s.warning} partial</span>` : '');

  el('execSummary').innerHTML = executiveSummaryParts(report).map(p => `<p>${esc(p)}</p>`).join('');
  el('areaCards').innerHTML = areaCardsHtml(report);

  const top = report.priorities || [];
  el('priorityList').innerHTML = top.map(r => `
    <li><b>${esc(r.name)}</b> <span class="sev ${esc(String(r.severity).toLowerCase())}">${esc(r.severity)}</span> <span class="effort ${esc(r.effort || '')}">${esc(effortLabel(r))}</span> <span class="hint">· ${esc(ownerLabel(r))}</span>
      <div class="hint" style="margin:4px 0 0">${esc(r.detail)}</div>
      ${r.remediation?.portal ? `<div class="rem"><b>Fix:</b> ${esc(r.remediation.portal)}</div>` : ''}
    </li>`).join('');
  show('priorityWrap', top.length > 0);

  const scope = scopeLabel(report);
  const sAll = report.summaryAll || s;
  el('scopeNote').innerHTML =
    `Scored across all ${report.results.length} checks for Identity &amp; access and Applications &amp; privileged access.` +
    (scope ? ` Across all checks regardless of framework: ${sAll.passRate === null ? 'n/a' : sAll.passRate + '%'} (${sAll.pass} of ${sAll.scored}).` : '');

  el('frameworkNote').textContent = 'Showing every framework these checks map to. Each row counts only the checks that map to that framework.';

  const badge = (r) => {
    const d = report.drift; if (!d) return '';
    if (d.regressed.some(x => x.id === r.id)) return ' <span class="drift down" title="Regressed since the previous run">▼</span>';
    if (d.fixed.some(x => x.id === r.id)) return ' <span class="drift up" title="Fixed since the previous run">▲</span>';
    if (d.added.some(x => x.id === r.id)) return ' <span class="drift new" title="Not assessed in the previous run">new</span>';
    return '';
  };
  const row = (r) => {
    const fixable = r.status === 'Fail' || r.status === 'Warning';
    return `
    <tr class="s-${r.status.toLowerCase()}" ${rowAttrs(r, report)}>
      <td><span class="status ${r.status.toLowerCase()}">${esc(r.status)}</span>${badge(r)}</td>
      <td><span class="sev ${esc(String(r.severity).toLowerCase())}">${esc(r.severity)}</span>${fixable ? `<br><span class="effort ${esc(r.effort || '')}">${esc(effortLabel(r))}</span>` : ''}</td>
      <td><div class="nm">${esc(r.name)}</div><code>${esc(r.id)}</code><div class="hint" style="margin:2px 0 0;font-size:12px">${esc(ownerLabel(r))}</div></td>
      <td>${esc(r.detail)}${fixable && r.remediation?.portal
        ? `<div class="rem"><b>Fix:</b> ${esc(fixText(r.remediation.portal))}</div>` : ''}${fixable ? `<br><button type="button" class="x-copy" data-ticket="${esc(ticketText(r, report))}">Copy as ticket</button>` : ''}</td>
    </tr>`;
  };
  const sorted = sortResults(report.results);
  el('resultRows').innerHTML = sorted.map(row).join('');
  el('findingsTitle').textContent = 'Findings';
  show('otherWrap', false);
  el('explorer').innerHTML = explorerToolbar(report);

  const plan = remediationPlan(report);
  el('planWrap').innerHTML = plan.length ? `<details class="plan-fold"><summary>Remediation plan by owner — ${plan.reduce((n, g) => n + g.items.length, 0)} items across ${plan.length} owner${plan.length === 1 ? '' : 's'}, ${plan.reduce((n, g) => n + g.quickWins, 0)} quick wins</summary>${planHtml(report).replace('<h2>Remediation plan</h2>', '')}</details>` : '';
  show('planWrap', plan.length > 0);
  el('signalsWrap').innerHTML = signalsHtml(report).replace('<h2>Microsoft security signals</h2>', '<h4 class="results-h">Microsoft security signals</h4>');
  show('signalsWrap', Boolean(report.signals));
  el('fwPicker').innerHTML = frameworkPickerHtml(report);
  explorer(document.querySelector('[data-panel="3"]'));
  reportChrome(document.querySelector('[data-panel="3"]'));

  el('frameworkRows').innerHTML = report.frameworks.map(f => `
    <tr><td>${esc(f.label)}</td><td class="num">${f.pass}</td><td class="num">${f.fail}</td>
    <td class="num">${f.warning || 0}</td>
    <td class="num">${f.passRate === null ? '—' : f.passRate + '%'}</td></tr>`).join('');

  if (report.unavailable.length) {
    el('unavailableRows').innerHTML = report.unavailable
      .map(u => `<li><b>${esc(u.label)}</b> — ${esc(u.reason)}</li>`).join('');
    show('unavailableWrap');
  } else {
    show('unavailableWrap', false);
  }

  renderDrift(report);

  el('runMeta').textContent =
    `${state.tenant} · ${new Date(report.started).toLocaleString()} · ${(report.durationMs / 1000).toFixed(1)}s · ` +
    `${(report.areas || []).map(a => a.label).join(', ')}`;
}

function renderDrift(report) {
  const d = report.drift;
  const runs = deps.history.list(report.tenant);
  const stored = runs.length;

  const earlier = runs.filter(r => r.started !== report.started);
  if (earlier.length > 1) {
    el('driftPick').innerHTML = earlier.slice().reverse().map(r =>
      `<option value="${esc(r.started)}"${d && d.previousStarted === r.started ? ' selected' : ''}>${esc(new Date(r.started).toLocaleString())} — ${r.passRate === null ? '—' : r.passRate + '%'}</option>`).join('');
    show('driftPickWrap');
  } else {
    show('driftPickWrap', false);
  }
  if (!d) {
    el('driftSummary').innerHTML = report.remembered
      ? 'First remembered run for this tenant. Run again later and this section will show what changed.'
      : 'This run was not remembered, so there is nothing to compare against next time.';
    show('driftLists', false);
    show('btnForget', stored > 0);
    return;
  }
  const when = new Date(d.previousStarted).toLocaleString();
  const arrow = d.delta === null ? '' : d.delta > 0 ? ` <b class="up">▲ ${d.delta} points</b>` : d.delta < 0 ? ` <b class="down">▼ ${Math.abs(d.delta)} points</b>` : ' <b>no change</b>';
  el('driftSummary').innerHTML =
    `Compared with the run on <b>${esc(when)}</b>: pass rate ${d.previousPassRate === null ? '—' : d.previousPassRate + '%'} → ${d.passRate === null ? '—' : d.passRate + '%'}${arrow}. ` +
    `<span class="pill none">${d.fixed.length} fixed</span> <span class="pill high">${d.regressed.length} regressed</span> ` +
    `<span class="pill low">${d.added.length} new</span> ${d.changed.length ? `<span class="pill warning">${d.changed.length} still failing, detail changed</span> ` : ''}` +
    `${d.dropped ? `${d.dropped} check${d.dropped === 1 ? '' : 's'} from the previous run not assessed this time. ` : ''}` +
    `${report.remembered ? '' : 'This run was not remembered.'}`;

  const li = (r, note) => `<li><b>${esc(r.name)}</b> <code>${esc(r.id)}</code>${note ? ` — ${esc(note)}` : ''}<div class="hint" style="margin:3px 0 0">${esc(r.detail)}</div></li>`;
  el('driftRegressed').innerHTML = d.regressed.map(r => li(r, `was ${r.previousStatus}, now ${r.status}`)).join('') || '<li class="hint">None.</li>';
  el('driftFixed').innerHTML = d.fixed.map(r => li(r, r.partial ? `was Fail, now Warning` : `was ${r.previousStatus}, now Pass`)).join('') || '<li class="hint">None.</li>';
  el('driftChanged').innerHTML = d.changed.map(r => li(r, `previously: ${r.previousDetail || r.previousStatus}`)).join('') || '<li class="hint">None.</li>';
  show('driftLists');
  show('btnForget');
}

// ---------------------------------------------------------------------------------------
// Wiring
// ---------------------------------------------------------------------------------------
function wire() {
  el('next').onclick = () => state.step < 2 && goto(state.step + 1);
  el('back').onclick = () => state.step > 1 && goto(state.step - 1);
  el('btnSignIn').onclick = doSignIn;
  el('btnConsent').onclick = doConsent;
  el('btnRun').onclick = doRun;

  el('dlHtml').onclick = () => state.report && downloadHtml(state.report);
  el('dlCsv').onclick = () => state.report && downloadCsv(state.report);
  el('dlJson').onclick = () => state.report && downloadJson(state.report);
  el('dlPlan').onclick = () => state.report && downloadPlanMarkdown(state.report);
  el('dlXlsx').onclick = async () => {
    if (!state.report) return;
    const b = el('dlXlsx');
    const label = b.textContent;
    b.disabled = true; b.textContent = 'Building workbook…';
    try { await downloadXlsx(state.report); }
    catch (e) { setStatus(`Excel export failed: ${esc(e.message || e)}`, 'warn'); }
    finally { b.disabled = false; b.textContent = label; }
  };
  el('btnPrint').onclick = () => {
    if (state.report && !printReport(state.report)) {
      setStatus('The print window was blocked. Allow popups for this site, or download the HTML report and print it.', 'warn');
    }
  };

  el('driftPick').onchange = () => {
    if (!state.report) return;
    const chosen = deps.history.list(state.report.tenant).find(r => r.started === el('driftPick').value);
    state.report.drift = deps.history.diff(state.report, chosen || null);
    renderResults(state.report);
  };

  el('btnForget').onclick = () => {
    if (!state.report) return;
    deps.history.forget(state.report.tenant);
    el('driftSummary').textContent = 'Stored runs for this tenant have been forgotten from this browser.';
    show('driftLists', false);
    show('btnForget', false);
  };

  el('btnRestart').onclick = async () => {
    if (await releaseChanged()) { deps.reload(); return; }
    deps.signOut();
    Object.assign(state, { session: null, token: null, granted: [], report: null });
    show('signedInRow', false);
    show('btnRun', false);
    show('btnConsent', false);
    show('connectStatus', false);
    el('btnSignIn').textContent = 'Sign in with Microsoft';
    goto(1);
  };

  el('tenantInput').addEventListener('keydown', e => {
    if (e.key === 'Enter') { e.preventDefault(); doSignIn(); }
  });

  const t = el('navToggle');
  if (t) t.onclick = () => el('mobileNav').classList.toggle('open');
}

export async function init(overrides = {}) {
  Object.assign(deps, overrides);
  await boot();
}

export const getState = () => state;

// Auto-start in the browser; tests import this module and call init() themselves.
if (typeof window !== 'undefined' && typeof document !== 'undefined' && !window.__IFFL_MANUAL_INIT) init();
