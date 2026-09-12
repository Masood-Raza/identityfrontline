// Identity Frontline — assessment planner and runner.
//
// Flow: frameworks -> scope -> tenant -> consent -> run. Everything after sign-in happens in
// this tab against Microsoft Graph directly; no tenant data reaches identityfrontline.com.

import { CONFIG, isConfigured } from './config.js';
import * as auth from './auth.js';
import { missingScopes } from './auth.js';
import { runAssessment as realRun, scopesFor, ALL_SCOPES, checksFor } from './engine.js';
import { AREAS } from './checks.js';
import { sortResults, downloadCsv, downloadJson, downloadHtml, downloadXlsx, printReport, executiveSummary, scopeLabel, fixText, esc } from './report.js';

// Injectable for tests: the flow can be driven end to end with sign-in and Graph mocked.
const deps = {
  signIn: auth.signIn,
  getToken: auth.getToken,
  requestAdminConsent: auth.requestAdminConsent,
  signOut: auth.signOut,
  runAssessment: realRun
};

const el = (id) => document.getElementById(id);
const requiredScopes = () => scopesFor([...state.areas]);
const show = (id, on = true) => { const n = el(id); if (n) n.hidden = !on; };

const state = {
  step: 1,
  frameworks: new Set(),
  areas: new Set(['identity']),
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

  if (!isConfigured()) {
    show('setupNotice');
    el('setupScopes').textContent = ALL_SCOPES.join(', ');
    el('setupRedirect').textContent = CONFIG.redirectUri;
  }

  renderFrameworks();
  renderScope();
  renderPermissions();
  renderMeta();
  wire();
  goto(1);
}

function renderMeta() {
  const c = checkCatalog;
  el('catalogMeta').textContent =
    `${c.counts.implemented} checks · registry ${c.source.registry.dataVersion} · ` +
    `${AREAS.length} areas · ${Object.keys(c.frameworks).length} frameworks · up to ${ALL_SCOPES.length} read-only permissions`;
}

// ---------------------------------------------------------------------------------------
// Step 1 — frameworks
// ---------------------------------------------------------------------------------------
function renderFrameworks() {
  const fw = Object.entries(checkCatalog.frameworks)
    .sort((a, b) => a[1].label.localeCompare(b[1].label));

  el('frameworks').innerHTML = fw.map(([id, f]) =>
    `<label class="tag" title="${esc(f.mappedChecks)} of ${checkCatalog.counts.implemented} checks map to this framework">
       <input type="checkbox" value="${esc(id)}">${esc(f.label)}</label>`).join('');

  el('frameworks').querySelectorAll('input').forEach(i => i.onchange = () => {
    i.checked ? state.frameworks.add(i.value) : state.frameworks.delete(i.value);
    updateSummary();
  });
}

// ---------------------------------------------------------------------------------------
// Step 2 — scope
// ---------------------------------------------------------------------------------------
function renderScope() {
  const counts = {};
  for (const a of AREAS) counts[a.id] = checksFor([a.id]).length;

  el('scopeAreas').innerHTML = AREAS.map(a => `
    <label class="choice${state.areas.has(a.id) ? ' selected' : ''}">
      <input type="checkbox" value="${esc(a.id)}"${state.areas.has(a.id) ? ' checked' : ''}>
      <b>${esc(a.label)}</b>
      <small>${esc(a.summary)} <em>${counts[a.id]} checks · ${scopesFor([a.id]).length} permissions.</em></small>
    </label>`).join('');

  el('scopeAreas').querySelectorAll('input').forEach(i => i.onchange = () => {
    i.checked ? state.areas.add(i.value) : state.areas.delete(i.value);
    // Never let the selection go empty: identity is the floor.
    if (!state.areas.size) { state.areas.add('identity'); renderScope(); return; }
    i.closest('.choice').classList.toggle('selected', i.checked);
    renderPermissions();
    updateSummary();
  });

  el('scopeSoon').innerHTML = [
    ['Exchange &amp; email security', 'Mail flow, anti-phishing, SPF/DKIM/DMARC. Not reachable through Microsoft Graph.'],
    ['Defender &amp; Purview', 'Defender for Office policies, DLP and retention. Not reachable through Microsoft Graph.']
  ].map(([t, d]) => `<p class="soon-item"><b>${t}</b> — ${d}</p>`).join('');
}

// ---------------------------------------------------------------------------------------
// Step 3 — permissions
// ---------------------------------------------------------------------------------------
function renderPermissions() {
  const why = {
    'Policy.Read.All': 'Conditional Access, authentication methods, consent and security defaults policies',
    'Directory.Read.All': 'Directory roles and tenant objects',
    'RoleManagement.Read.Directory': 'Who holds Global Administrator and other privileged roles',
    'User.Read.All': 'User and guest account counts',
    'Domain.Read.All': 'Verified domains and password expiry configuration',
    'AuditLog.Read.All': 'MFA registration report',
    'SharePointTenantSettings.Read.All': 'SharePoint and OneDrive sharing, sync and authentication settings',
    'TeamSettings.Read.All': 'Teams external access and meeting policy',
    'TeamworkAppSettings.Read.All': 'Teams app consent settings',
    'OrgSettings-Forms.Read.All': 'Microsoft Forms external sharing and phishing protection settings',
    'DeviceManagementConfiguration.Read.All': 'Intune compliance policies and configuration profiles',
    'DeviceManagementServiceConfig.Read.All': 'Intune enrolment restrictions and Autopilot profiles',
    'DeviceManagementManagedDevices.Read.All': 'Enrolled device counts and categories'
  };
  el('permissions').innerHTML = requiredScopes().map(s => `
    <tr><td><code>${esc(s)}</code></td><td>Delegated</td>
    <td>${esc(why[s] || '')}</td>
    <td><span class="read-only">Read-only</span></td></tr>`).join('');
  el('scopeCount').textContent = requiredScopes().length;
}

// ---------------------------------------------------------------------------------------
// Navigation
// ---------------------------------------------------------------------------------------
function goto(n) {
  state.step = n;
  document.querySelectorAll('.panel').forEach(p => p.classList.toggle('active', +p.dataset.panel === n));
  document.querySelectorAll('.step').forEach(p => p.classList.toggle('active', +p.dataset.ind === n));
  el('back').style.visibility = n === 1 ? 'hidden' : 'visible';

  const next = el('next');
  next.hidden = n >= 4;
  if (n === 3) next.textContent = 'Continue to sign-in →';
  else next.textContent = 'Continue →';

  if (n === 5) updateSummary();
  window.scrollTo({ top: el('start').offsetTop - 15, behavior: 'smooth' });
}

function updateSummary() {
  const n = state.frameworks.size;
  const areaLabels = AREAS.filter(a => state.areas.has(a.id)).map(a => a.label);
  el('planSummary').innerHTML =
    `<b>${checksFor([...state.areas]).length}</b> checks across <b>${areaLabels.join(', ')}</b> · ` +
    `<b>${n || Object.keys(checkCatalog.frameworks).length}</b> framework${n === 1 ? '' : 's'}` +
    `${n ? '' : ' (all)'} · <b>${requiredScopes().length}</b> read-only permissions`;
}

// ---------------------------------------------------------------------------------------
// Step 4 — connect, consent, run
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
    // Refresh the token so a long-running planning session cannot hit an expired one.
    const t = await deps.getToken(requiredScopes());
    state.token = t.token;

    state.report = await deps.runAssessment({
      token: state.token,
      catalog: checkCatalog,
      tenant: { name: state.tenant, id: state.session?.tenantId },
      frameworks: [...state.frameworks],
      areas: [...state.areas],
      onProgress: ({ phase, current, total, label }) => {
        const p = Math.round((current / total) * 100);
        el('progressBar').style.width = `${p}%`;
        el('progressLabel').textContent =
          phase === 'collect' ? `Reading ${label} (${current} of ${total})` : 'Evaluating checks…';
      }
    });

    renderResults(state.report);
    goto(5);
    setStatus('Assessment complete.', 'ok');
  } catch (e) {
    setStatus(`The assessment could not complete: ${esc(e.message || e)}`, 'warn');
  } finally {
    busy(false);
    show('progressWrap', false);
  }
}

// ---------------------------------------------------------------------------------------
// Step 5 — results
// ---------------------------------------------------------------------------------------
function renderResults(report) {
  const s = report.summary;
  el('scoreCards').innerHTML = [
    [s.passRate === null ? '—' : s.passRate + '%', 'Pass rate'],
    [s.pass, 'Passed'],
    [s.fail, 'Failed'],
    [s.warning, 'Warning'],
    [s.unknown, 'Unknown'],
    [s.notApplicable, 'N/A']
  ].map(([v, l]) => `<div class="fact"><b>${esc(v)}</b><span>${esc(l)}</span></div>`).join('');

  const sev = ['Critical', 'High', 'Medium', 'Low']
    .filter(k => s.failedBySeverity[k] > 0)
    .map(k => `<span class="pill ${k.toLowerCase()}">${s.failedBySeverity[k]} ${k}</span>`).join(' ');
  el('sevRow').innerHTML = (sev || '<span class="pill none">No failed checks</span>') +
    (s.warning ? ` <span class="pill warning">${s.warning} partial</span>` : '');

  el('execSummary').textContent = executiveSummary(report);

  const top = report.priorities || [];
  el('priorityList').innerHTML = top.map(r => `
    <li><b>${esc(r.name)}</b> <span class="sev ${esc(String(r.severity).toLowerCase())}">${esc(r.severity)}</span>
      <div class="hint" style="margin:4px 0 0">${esc(r.detail)}</div>
      ${r.remediation?.portal ? `<div class="rem"><b>Fix:</b> ${esc(r.remediation.portal)}</div>` : ''}
    </li>`).join('');
  show('priorityWrap', top.length > 0);

  const scope = scopeLabel(report);
  const sAll = report.summaryAll || s;
  el('scopeNote').innerHTML = scope
    ? `Scored against <b>${esc(scope)}</b>: ${report.scope.inScopeCount} of ${report.results.length} checks map to it. ` +
      `Across all checks regardless of framework: ${sAll.passRate === null ? 'n/a' : sAll.passRate + '%'} (${sAll.pass} of ${sAll.scored}).`
    : `Scored across all ${report.results.length} checks. Select frameworks in step 1 to score against a specific framework.`;

  el('frameworkNote').textContent = scope
    ? `Coverage for ${scope}. Each row counts only the checks that map to that framework, so rates differ from the headline when more than one is selected.`
    : 'Showing every framework. Each row counts only the checks that map to that framework.';

  const row = (r) => `
    <tr class="s-${r.status.toLowerCase()}">
      <td><span class="status ${r.status.toLowerCase()}">${esc(r.status)}</span></td>
      <td><span class="sev ${esc(String(r.severity).toLowerCase())}">${esc(r.severity)}</span></td>
      <td><div class="nm">${esc(r.name)}</div><code>${esc(r.id)}</code></td>
      <td>${esc(r.detail)}${r.status === 'Fail' && r.remediation?.portal
        ? `<div class="rem"><b>Fix:</b> ${esc(fixText(r.remediation.portal))}</div>` : ''}</td>
    </tr>`;
  const sorted = sortResults(report.results);
  el('resultRows').innerHTML = sorted.filter(r => r.inScope !== false).map(row).join('');
  const others = sorted.filter(r => r.inScope === false);
  el('findingsTitle').textContent = scope ? `Findings — ${scope}` : 'Findings';
  if (others.length) {
    el('otherTitle').textContent = `Other findings — not mapped to ${scope}`;
    el('otherNote').textContent =
      `${others.length} check${others.length === 1 ? '' : 's'} were assessed but do not map to the selected framework${report.scope.frameworks.length === 1 ? '' : 's'} ` +
      `(${others.filter(r => r.status === 'Fail' || r.status === 'Warning').length} failed or partial). They are excluded from the score above and shown here so nothing is hidden.`;
    el('otherRows').innerHTML = others.map(row).join('');
    show('otherWrap');
  } else {
    show('otherWrap', false);
  }

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

  el('runMeta').textContent =
    `${state.tenant} · ${new Date(report.started).toLocaleString()} · ${(report.durationMs / 1000).toFixed(1)}s · ` +
    `${(report.areas || []).map(a => a.label).join(', ')} · ` +
    (scope ? `Scope: ${scope}` : 'All frameworks');
}

// ---------------------------------------------------------------------------------------
// Wiring
// ---------------------------------------------------------------------------------------
function wire() {
  el('next').onclick = () => state.step < 4 && goto(state.step + 1);
  el('back').onclick = () => state.step > 1 && goto(state.step - 1);
  el('btnSignIn').onclick = doSignIn;
  el('btnConsent').onclick = doConsent;
  el('btnRun').onclick = doRun;

  el('dlHtml').onclick = () => state.report && downloadHtml(state.report);
  el('dlCsv').onclick = () => state.report && downloadCsv(state.report);
  el('dlJson').onclick = () => state.report && downloadJson(state.report);
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

  el('btnRestart').onclick = () => {
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
