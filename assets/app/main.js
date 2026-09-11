// Identity Frontline — assessment planner and runner.
//
// Flow: frameworks -> scope -> tenant -> consent -> run. Everything after sign-in happens in
// this tab against Microsoft Graph directly; no tenant data reaches identityfrontline.com.

import { CONFIG, isConfigured } from './config.js';
import * as auth from './auth.js';
import { missingScopes } from './auth.js';
import { runAssessment as realRun, REQUIRED_SCOPES } from './engine.js';
import { sortResults, downloadCsv, downloadJson, downloadHtml, esc } from './report.js';

// Injectable for tests: the flow can be driven end to end with sign-in and Graph mocked.
const deps = {
  signIn: auth.signIn,
  getToken: auth.getToken,
  requestAdminConsent: auth.requestAdminConsent,
  signOut: auth.signOut,
  runAssessment: realRun
};

const el = (id) => document.getElementById(id);
const show = (id, on = true) => { const n = el(id); if (n) n.hidden = !on; };

const state = {
  step: 1,
  frameworks: new Set(),
  scope: new Set(['Identity']),
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
    el('setupScopes').textContent = REQUIRED_SCOPES.join(', ');
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
    `${Object.keys(c.frameworks).length} frameworks · ${REQUIRED_SCOPES.length} read-only permissions`;
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
  const bySeverity = checkCatalog.counts.bySeverity;
  el('scopeAreas').innerHTML = `
    <label class="choice selected">
      <input type="checkbox" value="Identity" checked>
      <b>Identity &amp; access</b>
      <small>${checkCatalog.counts.implemented} checks across Conditional Access, MFA, administrators,
      consent, guests, passwords and authentication methods.
      ${bySeverity.Critical + bySeverity.High} rated high or critical.</small>
    </label>`;

  el('scopeSoon').innerHTML = [
    ['Exchange &amp; email security', 'Mail flow, anti-phishing, SPF/DKIM/DMARC.'],
    ['Intune &amp; devices', 'Compliance policies and configuration profiles.'],
    ['SharePoint, Teams &amp; Forms', 'External sharing and collaboration controls.'],
    ['Defender &amp; Purview', 'Secure Score, DLP and retention.']
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
    'AuditLog.Read.All': 'MFA registration report'
  };
  el('permissions').innerHTML = REQUIRED_SCOPES.map(s => `
    <tr><td><code>${esc(s)}</code></td><td>Delegated</td>
    <td>${esc(why[s] || '')}</td>
    <td><span class="read-only">Read-only</span></td></tr>`).join('');
  el('scopeCount').textContent = REQUIRED_SCOPES.length;
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
  el('planSummary').innerHTML =
    `<b>${checkCatalog.counts.implemented}</b> checks · ` +
    `<b>${n || Object.keys(checkCatalog.frameworks).length}</b> framework${n === 1 ? '' : 's'}` +
    `${n ? '' : ' (all)'} · <b>${REQUIRED_SCOPES.length}</b> read-only permissions`;
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
    state.session = await deps.signIn(REQUIRED_SCOPES, tenant);
    const t = await deps.getToken(REQUIRED_SCOPES);
    state.token = t.token;
    state.granted = t.grantedScopes;

    const missing = missingScopes(REQUIRED_SCOPES, state.granted);
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
    const outcome = await deps.requestAdminConsent(state.tenant, REQUIRED_SCOPES);
    if (outcome.completed) {
      setStatus('Consent granted. Re-acquiring a token with the new permissions…', 'info');
      const t = await deps.getToken(REQUIRED_SCOPES);
      state.token = t.token;
      state.granted = t.grantedScopes;
      const missing = missingScopes(REQUIRED_SCOPES, state.granted);
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
    const t = await deps.getToken(REQUIRED_SCOPES);
    state.token = t.token;

    state.report = await deps.runAssessment({
      token: state.token,
      catalog: checkCatalog,
      tenant: { name: state.tenant, id: state.session?.tenantId },
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
    [s.unknown, 'Unknown'],
    [s.notApplicable, 'N/A']
  ].map(([v, l]) => `<div class="fact"><b>${esc(v)}</b><span>${esc(l)}</span></div>`).join('');

  const sev = ['Critical', 'High', 'Medium', 'Low']
    .filter(k => s.failedBySeverity[k] > 0)
    .map(k => `<span class="pill ${k.toLowerCase()}">${s.failedBySeverity[k]} ${k}</span>`).join(' ');
  el('sevRow').innerHTML = sev || '<span class="pill none">No failed checks</span>';

  el('resultRows').innerHTML = sortResults(report.results).map(r => `
    <tr class="s-${r.status.toLowerCase()}">
      <td><span class="status ${r.status.toLowerCase()}">${esc(r.status)}</span></td>
      <td><span class="sev ${esc(String(r.severity).toLowerCase())}">${esc(r.severity)}</span></td>
      <td><div class="nm">${esc(r.name)}</div><code>${esc(r.id)}</code></td>
      <td>${esc(r.detail)}${r.status === 'Fail' && r.remediation?.portal
        ? `<div class="rem"><b>Fix:</b> ${esc(r.remediation.portal)}</div>` : ''}</td>
    </tr>`).join('');

  el('frameworkRows').innerHTML = report.frameworks.map(f => `
    <tr><td>${esc(f.label)}</td><td class="num">${f.pass}</td><td class="num">${f.fail}</td>
    <td class="num">${f.passRate === null ? '—' : f.passRate + '%'}</td></tr>`).join('');

  if (report.unavailable.length) {
    el('unavailableRows').innerHTML = report.unavailable
      .map(u => `<li><b>${esc(u.label)}</b> — ${esc(u.reason)}</li>`).join('');
    show('unavailableWrap');
  } else {
    show('unavailableWrap', false);
  }

  el('runMeta').textContent =
    `${state.tenant} · ${new Date(report.started).toLocaleString()} · ${(report.durationMs / 1000).toFixed(1)}s`;
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
