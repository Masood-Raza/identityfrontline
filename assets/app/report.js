// Identity Frontline — results rendering and offline report generation.
//
// Everything here runs on data already in the browser. The downloadable HTML report is fully
// self-contained: no scripts, no external references, safe to open offline or attach to a
// remediation ticket.

import { frameworksOf } from './engine.js';
import { EFFORT, OWNERS } from './checks.js';
import { explorer, reportChrome, rowAttrs, explorerToolbar, EXPLORER_CSS, REPORT_CSS } from './explore.js';

// ---------------------------------------------------------------------------------------
// Shared building blocks: tickets, the remediation plan, area cards, signals
// ---------------------------------------------------------------------------------------
const controlIds = (r, report) =>
  Object.values(frameworksOf(r, r.inScope === false ? [] : report.frameworkFilter)).map(m => m.controlId);

export const effortLabel = (r) => EFFORT[r.effort]?.label || '';
export const ownerLabel = (r) => OWNERS[r.owner] || OWNERS.identity;

// Markdown for one finding, shaped for a Jira / ServiceNow / Teams paste.
export function ticketText(r, report) {
  const lines = [
    `### ${r.name}`,
    '',
    `- **Check:** ${r.id}`,
    `- **Severity:** ${r.severity} · **Status:** ${r.status}${r.effort ? ` · **Effort:** ${effortLabel(r)}` : ''}`,
    `- **Owner:** ${ownerLabel(r)}`,
    `- **Tenant:** ${report.tenant?.name || 'tenant'} · assessed ${new Date(report.started).toLocaleString()}`,
    '',
    `**Finding:** ${r.detail}`
  ];
  if (r.rationale) lines.push('', `**Why it matters:** ${r.rationale}`);
  if (r.remediation?.portal) lines.push('', `**Fix:** ${fixText(r.remediation.portal)}`);
  if (r.remediation?.powershell) lines.push('', '```powershell', fixText(r.remediation.powershell), '```');
  const ids = controlIds(r, report);
  if (ids.length) lines.push('', `**Controls:** ${ids.slice(0, 12).join(', ')}${ids.length > 12 ? ` (+${ids.length - 12} more)` : ''}`);
  return lines.join('\n');
}

// Failures and partials grouped by who fixes them, each group ordered as the Fix-first list
// is: severity, then effort, then a concrete fix path.
export function remediationPlan(report) {
  const items = (report.results || []).filter(r => r.inScope !== false && (r.status === 'Fail' || r.status === 'Warning'));
  const sevRank = { Critical: 0, High: 1, Medium: 2, Low: 3 };
  const order = (a, b) => (a.status === 'Warning') - (b.status === 'Warning') ||
    (sevRank[a.severity] ?? 9) - (sevRank[b.severity] ?? 9) ||
    (EFFORT[a.effort]?.rank ?? 9) - (EFFORT[b.effort]?.rank ?? 9) || a.id.localeCompare(b.id);
  const groups = {};
  for (const r of items) (groups[r.owner || 'identity'] = groups[r.owner || 'identity'] || []).push(r);
  return Object.keys(OWNERS).filter(k => groups[k]).map(k => ({
    owner: k, label: OWNERS[k], items: groups[k].sort(order),
    quickWins: groups[k].filter(r => r.effort === 'quick').length
  }));
}

export function planMarkdown(report) {
  const plan = remediationPlan(report);
  const out = [`# Remediation plan — ${report.tenant?.name || 'tenant'}`, '',
    `Assessed ${new Date(report.started).toLocaleString()}${scopeLabel(report) ? ` · scope: ${scopeLabel(report)}` : ''}. ` +
    `${plan.reduce((n, g) => n + g.items.length, 0)} findings across ${plan.length} owner${plan.length === 1 ? '' : 's'}; ` +
    `${plan.reduce((n, g) => n + g.quickWins, 0)} are quick wins.`, ''];
  for (const g of plan) {
    out.push(`## ${g.label} — ${g.items.length} item${g.items.length === 1 ? '' : 's'}${g.quickWins ? ` (${g.quickWins} quick win${g.quickWins === 1 ? '' : 's'})` : ''}`, '');
    g.items.forEach((r, i) => { out.push(`${i + 1}. ` + ticketText(r, report).replace(/^### /, '').split('\n').join('\n   '), ''); });
  }
  out.push('---', 'Generated locally in the browser by Identity Frontline. No tenant data was transmitted.');
  return out.join('\n');
}

export function downloadPlanMarkdown(report) {
  download(`remediation-plan-${stamp(report)}.md`, planMarkdown(report), 'text/markdown;charset=utf-8');
}

// Area score cards; clickable, they toggle the matching area filter. The bar is segmented —
// pass/partial/fail as proportions of what was actually scored — rather than one bar at the
// pass-rate width, so a 90%-scored-but-half-Unknown area doesn't read the same as a clean one.
export function areaCardsHtml(report) {
  const areas = report.areaSummary || [];
  if (areas.length < 2) return '';
  return `<div class="area-cards">${areas.map(a => {
    const total = a.scored || 0;
    const pct = (n) => total ? Math.round((n / total) * 100) : 0;
    return `
    <button type="button" class="area-card" data-area-card="${esc(a.id)}" title="Show only ${esc(a.label)}">
      <span>${esc(a.label)}</span><b>${a.passRate === null ? '—' : a.passRate + '%'}</b>
      <div class="bar"><i class="seg-pass" style="width:${pct(a.pass)}%"></i><i class="seg-warn" style="width:${pct(a.warning)}%"></i><i class="seg-fail" style="width:${pct(a.fail)}%"></i></div>
      <small>${a.pass} passed · ${a.fail} failed${a.warning ? ` · ${a.warning} partial` : ''}${a.unknown ? ` · ${a.unknown} unknown` : ''}</small>
    </button>`;
  }).join('')}</div>`;
}

export function planHtml(report) {
  const plan = remediationPlan(report);
  if (!plan.length) return '';
  const total = plan.reduce((n, g) => n + g.items.length, 0);
  const quick = plan.reduce((n, g) => n + g.quickWins, 0);
  return `
  <h2>Remediation plan</h2>
  <p class="muted">${total} finding${total === 1 ? '' : 's'} grouped by who fixes them, in the order to work through: severity first, then the cheapest fix. ${quick} ${quick === 1 ? 'is a quick win' : 'are quick wins'} — portal settings that take minutes.</p>
  ${plan.map(g => `
  <h3>${esc(g.label)} <span class="muted">— ${g.items.length} item${g.items.length === 1 ? '' : 's'}${g.quickWins ? `, ${g.quickWins} quick` : ''}</span></h3>
  <table class="plan"><thead><tr><th>#</th><th>Check</th><th>Severity</th><th>Effort</th><th>What to do</th></tr></thead><tbody>
  ${g.items.map((r, i) => `<tr><td class="num">${i + 1}</td><td><b>${esc(r.name)}</b><div class="nm"><code>${esc(r.id)}</code> · ${esc(r.status === 'Warning' ? 'Partial' : r.status)}</div></td>
    <td><span class="sev ${esc(String(r.severity).toLowerCase())}">${esc(r.severity)}</span></td>
    <td><span class="effort ${esc(r.effort || '')}">${esc(effortLabel(r))}</span></td>
    <td>${esc(r.detail)}${r.remediation?.portal ? `<div class="rem"><b>Fix:</b> ${esc(fixText(r.remediation.portal))}</div>` : ''}${r.remediation?.powershell ? `<div class="rem"><code>${esc(fixText(r.remediation.powershell))}</code></div>` : ''}</td></tr>`).join('')}
  </tbody></table>`).join('')}`;
}

export function signalsHtml(report) {
  const sig = report.signals;
  if (!sig) return '';
  const ss = sig.secureScore, al = sig.alerts;
  const scoreBlock = ss ? `
  <div class="cards">
    <div class="card"><b>${ss.percent === null ? '—' : ss.percent + '%'}</b><span>Microsoft Secure Score</span></div>
    <div class="card"><b>${ss.current}</b><span>of ${ss.max} points</span></div>
    <div class="card"><b>${ss.daysOld === null ? '—' : ss.daysOld}</b><span>days since Microsoft last computed it</span></div>
    ${al ? `<div class="card"><b>${al.open}</b><span>open Defender alerts${al.high ? ` (${al.high} high)` : ''}</span></div>` : ''}
  </div>
  ${ss.actions.length ? `<h3>Top improvement actions by points available</h3>
  <table class="signals"><thead><tr><th>Action</th><th>Category</th><th class="num">Points</th><th>Cost</th><th>User impact</th></tr></thead><tbody>
  ${ss.actions.map(a => `<tr><td>${a.url ? `<a href="${esc(a.url)}" rel="noopener">${esc(a.title)}</a>` : esc(a.title)}</td><td>${esc(a.category)}</td><td class="num">+${Math.round(a.gap * 10) / 10} of ${a.max}</td><td>${esc(a.cost)}</td><td>${esc(a.impact)}</td></tr>`).join('')}
  </tbody></table>` : '<p class="muted">Every Secure Score improvement action is already implemented.</p>'}` : '<p class="muted">Secure Score was not available for this tenant.</p>';
  const alertBlock = al && al.items.length ? `
  <h3>Open Defender alerts (newest high first)</h3>
  <table class="signals"><thead><tr><th>Severity</th><th>Alert</th><th>Category</th><th>Status</th><th>Created</th></tr></thead><tbody>
  ${al.items.map(a => `<tr><td><span class="sev ${esc(a.severity)}">${esc(a.severity)}</span></td><td>${esc(a.title)}</td><td>${esc(a.category)}</td><td>${esc(a.status)}</td><td>${esc(a.created ? new Date(a.created).toLocaleString() : '')}</td></tr>`).join('')}
  </tbody></table>` : al ? '<p class="muted">No open Defender alerts.</p>' : '';
  return `<h2>Microsoft security signals</h2>
  <p class="muted">Microsoft\'s own posture number and its open alerts, read from the Defender portal APIs. They sit beside this assessment rather than inside its score.</p>
  ${scoreBlock}${alertBlock}`;
}

// The headline number and four stat tiles at the top of the results. When Microsoft's own
// Secure Score is available (the signals area was run and returned one), it leads — that is
// Microsoft's number, not ours, and a reader comparing the two wants to see it first. Otherwise
// the headline is the scope-aware pass rate already used everywhere else in the report.
export function heroHtml(report) {
  const s = report.summary;
  const scope = scopeLabel(report);
  const ss = report.signals?.secureScore;
  const useSecureScore = Boolean(ss && ss.percent !== null);
  const heroLabel = useSecureScore ? 'Microsoft Secure Score' : `Pass rate${scope ? ' — ' + scope : ''}`;
  const heroValue = useSecureScore ? `${ss.percent}%` : (s.passRate === null ? '—' : `${s.passRate}%`);
  const heroSub = useSecureScore
    ? `${ss.current} of ${ss.max} points${ss.daysOld === null ? '' : ` · updated ${ss.daysOld === 0 ? 'today' : ss.daysOld + (ss.daysOld === 1 ? ' day' : ' days') + ' ago'}`}`
    : (s.scored ? `${s.pass} of ${s.scored} checks passed` : `${s.total} check${s.total === 1 ? '' : 's'} assessed, none scorable`);
  const barPct = Math.max(0, Math.min(100, useSecureScore ? ss.percent : (s.passRate ?? 0)));

  const d = report.drift;
  const deltaHtml = d && d.delta !== null
    ? ` <span class="hero-delta ${d.delta > 0 ? 'up' : d.delta < 0 ? 'down' : ''}">${d.delta > 0 ? '▲' : d.delta < 0 ? '▼' : '='} ${Math.abs(d.delta)} pt${Math.abs(d.delta) === 1 ? '' : 's'} vs last run</span>`
    : (report.remembered ? '<span class="hero-delta">First run remembered for this tenant</span>' : '');

  const critCount = s.failedBySeverity?.Critical || 0;
  const tiles = [
    { n: critCount, label: 'Critical findings', cls: 'critical', hint: critCount ? 'need immediate attention' : 'none open' },
    { n: s.fail, label: 'Failed', cls: 'fail', hint: `of ${s.scored || s.total} checks` },
    { n: s.warning, label: 'Partial', cls: 'warning', hint: 'review and harden' },
    { n: s.pass, label: 'Passing', cls: 'pass', hint: 'controls validated' }
  ];

  return `
  <div class="hero">
    <div class="hero-score">
      <span class="hero-label">${esc(heroLabel)}</span>
      <b>${esc(heroValue)}</b>
      <div class="hero-bar"><i style="width:${barPct}%"></i></div>
      <span class="hero-sub">${esc(heroSub)}${deltaHtml}</span>
    </div>
    <div class="hero-tiles">
      ${tiles.map(t => `<div class="tile tile-${t.cls}"><b>${t.n}</b><span>${esc(t.label)}</span><small>${esc(t.hint)}</small></div>`).join('')}
    </div>
  </div>`;
}

// A single banner naming the Critical-severity failures, with a link that both jumps to the
// findings table and pre-applies the Fail + Critical filters. Nothing to show, nothing rendered.
export function alertBannerHtml(report) {
  const crit = (report.results || []).filter(r => r.inScope !== false && r.status === 'Fail' && r.severity === 'Critical');
  if (!crit.length) return '';
  const named = crit.slice(0, 2).map(r => r.name.replace(/\.$/, ''));
  const more = crit.length > 2 ? ` and ${crit.length - 2} more` : '';
  return `
  <div class="alert-banner" role="alert">
    <b>${crit.length} critical finding${crit.length === 1 ? '' : 's'}</b> need attention before anything else: ${named.map(esc).join('; ')}${more}.
    <a href="#findings" data-jump="status:fail,sev:critical">Review critical findings →</a>
  </div>`;
}

// A framework <select> driving a small detail panel (coverage %, gaps, checks assessed) for
// whichever framework is chosen — one framework at a time is easier to read than a full table
// when there are more than a couple. The full table stays too, further down, for comparison.
export function frameworkPickerHtml(report) {
  const fws = report.frameworks || [];
  if (!fws.length) return '';
  const scoped = report.frameworkFilter && report.frameworkFilter.length === 1 ? report.frameworkFilter[0] : null;
  const defaultId = scoped && fws.some(f => f.id === scoped) ? scoped : fws[0].id;
  const stats = {};
  fws.forEach(f => { stats[f.id] = { label: f.label, passRate: f.passRate, gaps: f.fail + f.warning, checks: f.scored }; });
  return `
  <div class="fw-picker">
    <label class="fw-select-label">Framework
      <select class="rc-fw-select">${fws.map(f => `<option value="${esc(f.id)}"${f.id === defaultId ? ' selected' : ''}>${esc(f.label)}</option>`).join('')}</select>
    </label>
    <div class="fw-panel" data-fw-id="${esc(defaultId)}"></div>
    <script type="application/json" class="rc-fw-data">${JSON.stringify(stats).replace(/</g, '\u003c')}</script>
  </div>`;
}

const SEVERITY_ORDER = ['Critical', 'High', 'Medium', 'Low', 'Unknown'];
const STATUS_ORDER = { Fail: 0, Warning: 1, Unknown: 2, NotApplicable: 3, Pass: 4 };

export const esc = (s) => String(s ?? '').replace(/[&<>"']/g, c =>
  ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

export const sortResults = (results) => [...results].sort((a, b) =>
  (STATUS_ORDER[a.status] - STATUS_ORDER[b.status]) ||
  (SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity)) ||
  a.id.localeCompare(b.id));

// ---------------------------------------------------------------------------------------
// Downloads
// ---------------------------------------------------------------------------------------
function download(filename, content, mime) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = Object.assign(document.createElement('a'), { href: url, download: filename });
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

const stamp = (report) =>
  `${(report.tenant?.name || 'tenant').replace(/[^a-z0-9]+/gi, '-').toLowerCase()}-${report.started.slice(0, 10)}`;

const csvCell = (v) => {
  const s = String(v ?? '');
  return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
};

// ---------------------------------------------------------------------------------------
// Narrative
// ---------------------------------------------------------------------------------------
const summariseList = (list) => ({
  pass: list.filter(r => r.status === 'Pass').length,
  fail: list.filter(r => r.status === 'Fail').length,
  warning: list.filter(r => r.status === 'Warning').length,
  other: list.filter(r => !['Pass', 'Fail', 'Warning'].includes(r.status)).length
});

// Upstream remediation strings arrive with PowerShell-escaped quotes (''x''); show them plainly.
export const fixText = (t) => String(t ?? '').replace(/''/g, "'");

// "HIPAA", "HIPAA and SOC 2", "HIPAA, SOC 2 and 2 more", or null when unfiltered.
export function scopeLabel(report) {
  const fw = report.scope?.frameworks || [];
  if (!fw.length) return null;
  const names = fw.map(f => f.label);
  if (names.length <= 2) return names.join(' and ');
  return `${names.slice(0, 2).join(', ')} and ${names.length - 2} more`;
}

export function executiveSummary(report) {
  return executiveSummaryParts(report).join(' ');
}

export function executiveSummaryParts(report) {
  const s = report.summary;
  const name = report.tenant?.name || 'The tenant';
  const parts = [];
  const scope = scopeLabel(report);
  const areas = (report.areas || []).map(a => a.label);

  if (areas.length) parts.push(`Areas assessed: ${areas.join(', ')}.`);
  if (scope) {
    parts.push(`Scope: ${scope} — ${report.scope.inScopeCount} of ${report.results.length} checks map to ${report.scope.frameworks.length === 1 ? 'this framework' : 'these frameworks'}.`);
  }

  if (s.scored === 0) {
    parts.push(`${name} could not be scored: none of the ${s.total} checks in scope had the data they needed.`);
  } else {
    parts.push(`${name} passed ${s.pass} of ${s.scored} scored checks${scope ? ' in scope' : ''} (${s.passRate}%).`);
  }

  const sev = ['Critical', 'High', 'Medium', 'Low']
    .filter(k => s.failedBySeverity[k] > 0)
    .map(k => `${s.failedBySeverity[k]} ${k.toLowerCase()}`);
  if (s.fail === 0 && !s.warning && s.scored > 0) {
    parts.push('No failing checks were found in the assessed scope.');
  } else if (sev.length) {
    parts.push(`${s.fail} check${s.fail === 1 ? '' : 's'} failed: ${sev.join(', ')}.`);
  }
  if (s.warning) parts.push(`${s.warning} check${s.warning === 1 ? ' is' : 's are'} partially compliant.`);
  if (s.quickWins > 0 && s.projectedPassRate !== null && s.projectedPassRate > s.passRate) {
    parts.push(`${s.quickWins} of the failing checks ${s.quickWins === 1 ? 'is a quick win' : 'are quick wins'} — portal settings that take minutes; fixing only those would raise the pass rate to ${s.projectedPassRate}%.`);
  }
  if (report.signals?.secureScore?.percent !== undefined && report.signals?.secureScore?.percent !== null) {
    const ss = report.signals.secureScore;
    parts.push(`Microsoft Secure Score is ${ss.percent}% (${ss.current} of ${ss.max})${report.signals.alerts ? `, with ${report.signals.alerts.open} open Defender alert${report.signals.alerts.open === 1 ? '' : 's'}${report.signals.alerts.high ? ` (${report.signals.alerts.high} high)` : ''}` : ''}.`);
  }

  const top = report.priorities || [];
  if (top.length) {
    // Keep check names intact: stripping "Ensure" turns "Ensure X is restricted" into a claim
    // that X is restricted.
    const lead = top.slice(0, 3).map(r => r.name.replace(/\.$/, ''));
    parts.push(`Address first: ${lead.join('; ')}.`);
  }

  if (s.unknown > 0) {
    parts.push(`${s.unknown} check${s.unknown === 1 ? '' : 's'} could not be evaluated and ${s.unknown === 1 ? 'is' : 'are'} excluded from the score${report.unavailable?.length ? ` (${report.unavailable.map(u => u.label.toLowerCase()).join(', ')} not collected)` : ''}.`);
  }

  const d = report.drift;
  if (d) {
    const when = new Date(d.previousStarted).toLocaleDateString();
    const dir = d.delta === null ? '' : d.delta > 0 ? `up ${d.delta} points` : d.delta < 0 ? `down ${Math.abs(d.delta)} points` : 'unchanged';
    parts.push(`Since the run on ${when} the pass rate is ${dir}: ${d.fixed.length} fixed, ${d.regressed.length} regressed, ${d.added.length} newly assessed.`);
  }

  parts.push('This is a point-in-time posture snapshot, not a certification.');
  return parts;
}

const frameworkCell = (r, filter) =>
  Object.entries(frameworksOf(r, filter)).map(([k, m]) => `${k}:${m.controlId}`).join(' | ');

export function downloadCsv(report) {
  const cols = ['CheckId', 'Name', 'Category', 'Severity', 'Status', 'InScope', 'Detail', 'Remediation', 'Frameworks'];
  const rows = sortResults(report.results).map(r => [
    r.id, r.name, r.category, r.severity, r.status, r.inScope === false ? 'No' : 'Yes', r.detail,
    fixText(r.remediation?.portal || r.remediation?.powershell || ''),
    frameworkCell(r, r.inScope === false ? [] : report.frameworkFilter)
  ]);
  // BOM so Excel opens UTF-8 correctly.
  const csv = '﻿' + [cols, ...rows].map(r => r.map(csvCell).join(',')).join('\r\n');
  download(`assessment-${stamp(report)}.csv`, csv, 'text/csv;charset=utf-8');
}

export function downloadJson(report) {
  download(`assessment-${stamp(report)}.json`, JSON.stringify(report, null, 2), 'application/json');
}

export function downloadHtml(report) {
  download(`assessment-${stamp(report)}.html`, buildHtmlReport(report), 'text/html;charset=utf-8');
}

// Opens the self-contained report in its own window and hands it to the print dialog, which
// is where "Save as PDF" lives in every browser. The report carries print styles.
export function printReport(report) {
  const w = window.open('', '_blank');
  if (!w) return false;
  w.document.open();
  w.document.write(buildHtmlReport(report));
  w.document.close();
  w.focus();
  // Give the new document a tick to lay out before the dialog snapshots it.
  setTimeout(() => { try { w.print(); } catch { /* user closed it */ } }, 250);
  return true;
}

// ---------------------------------------------------------------------------------------
// Excel workbook — Summary, Findings, Compliance matrix, Framework coverage
// ---------------------------------------------------------------------------------------
const XLSX_CDN = 'https://cdnjs.cloudflare.com/ajax/libs/xlsx/0.18.5/xlsx.full.min.js';

// SheetJS is ~900 KB, so it is loaded the first time someone asks for a workbook, not on page load.
export function ensureXlsx() {
  if (typeof XLSX !== 'undefined') return Promise.resolve(XLSX);
  return new Promise((resolve, reject) => {
    const s = document.createElement('script');
    s.src = XLSX_CDN;
    s.crossOrigin = 'anonymous';
    s.onload = () => (typeof XLSX !== 'undefined') ? resolve(XLSX) : reject(new Error('Excel library did not initialise.'));
    s.onerror = () => reject(new Error('Could not load the Excel library. Check your network or content blocker.'));
    document.head.appendChild(s);
  });
}

export function buildWorkbook(report, lib) {
  const X = lib;
  const wb = X.utils.book_new();
  const s = report.summary;
  const filter = report.frameworkFilter;
  const results = sortResults(report.results);

  // Which frameworks get a column in the matrix: the selection, or every one that appears.
  const fwIds = filter?.length
    ? filter
    : [...new Set(report.results.flatMap(r => Object.keys(r.frameworks || {})))].sort();
  const fwLabel = {};
  for (const r of report.results) for (const [k, m] of Object.entries(r.frameworks || {})) fwLabel[k] = m.label;

  // --- Summary ---
  const summary = [
    ['Microsoft 365 security assessment'],
    [],
    ['Areas assessed', (report.areas || []).map(a => a.label).join(', ')],
    ['Scope', scopeLabel(report) || 'All frameworks'],
    ['Checks in scope', report.scope ? report.scope.inScopeCount : report.results.length],
    ['Checks assessed', report.results.length],
    [],
    ['Tenant', report.tenant?.name || ''],
    ['Tenant ID', report.tenant?.id || ''],
    ['Assessed', new Date(report.started).toLocaleString()],
    ['Duration (s)', Math.round(report.durationMs / 1000)],
    [],
    ['Pass rate (in scope)', s.passRate === null ? 'n/a' : `${s.passRate}%`],
    ['Pass rate (all checks)', (report.summaryAll || s).passRate === null ? 'n/a' : `${(report.summaryAll || s).passRate}%`],
    ['Passed', s.pass], ['Failed', s.fail], ['Partially compliant', s.warning || 0], ['Unknown', s.unknown], ['Not applicable', s.notApplicable],
    ['Scored checks', s.scored], ['Total checks', s.total],
    [],
    ['Failed by severity'],
    ...['Critical', 'High', 'Medium', 'Low'].map(k => [k, s.failedBySeverity[k]]),
    [],
    ['Executive summary'],
    [executiveSummary(report)],
    [],
    ['Fix first'],
    ...(report.priorities || []).map((r, i) => [`${i + 1}. ${r.name}`, r.severity, r.id]),
    [],
    ['Not collected'],
    ...(report.unavailable?.length ? report.unavailable.map(u => [u.label, u.reason]) : [['(everything collected)']]),
    [],
    ['Generated locally in the browser. No tenant data was transmitted to identityfrontline.com.'],
    [`Control definitions and framework mappings from M365-Assess (c) Galvnyz, MIT licensed. Registry ${report.catalog?.source?.registry?.dataVersion || 'n/a'}.`],
    ['Posture snapshot and remediation guide, not a certification or formal audit opinion.']
  ];
  const wsSummary = X.utils.aoa_to_sheet(summary);
  wsSummary['!cols'] = [{ wch: 26 }, { wch: 90 }, { wch: 22 }];
  X.utils.book_append_sheet(wb, wsSummary, 'Summary');

  // --- Findings ---
  const findings = [
    ['Status', 'Severity', 'In scope', 'Check ID', 'Name', 'Category', 'Detail', 'Fix (portal)', 'Fix (PowerShell)', 'Licensing', 'Frameworks'],
    ...results.map(r => [
      r.status, r.severity, r.inScope === false ? 'No' : 'Yes', r.id, r.name, r.category, r.detail,
      fixText(r.remediation?.portal || ''), fixText(r.remediation?.powershell || ''), r.licensing || '',
      frameworkCell(r, r.inScope === false ? [] : filter)
    ])
  ];
  const wsFindings = X.utils.aoa_to_sheet(findings);
  wsFindings['!cols'] = [10, 10, 8, 26, 60, 14, 80, 50, 50, 10, 60].map(w => ({ wch: w }));
  wsFindings['!autofilter'] = { ref: `A1:K${findings.length}` };
  wsFindings['!freeze'] = { xSplit: 0, ySplit: 1 };
  X.utils.book_append_sheet(wb, wsFindings, 'Findings');

  // --- Compliance matrix: one row per check, one column per framework, cell = control IDs ---
  const matrix = [
    ['Check ID', 'Name', 'Severity', 'Status', ...fwIds.map(id => fwLabel[id] || id)],
    // Out-of-scope checks have no cell in any selected column, so they add nothing here.
    ...results.filter(r => r.inScope !== false).map(r => [
      r.id, r.name, r.severity, r.status,
      ...fwIds.map(id => r.frameworks?.[id]?.controlId || '')
    ])
  ];
  const wsMatrix = X.utils.aoa_to_sheet(matrix);
  wsMatrix['!cols'] = [{ wch: 26 }, { wch: 56 }, { wch: 10 }, { wch: 12 }, ...fwIds.map(() => ({ wch: 28 }))];
  wsMatrix['!autofilter'] = { ref: X.utils.encode_range({ s: { r: 0, c: 0 }, e: { r: matrix.length - 1, c: matrix[0].length - 1 } }) };
  wsMatrix['!freeze'] = { xSplit: 2, ySplit: 1 };
  X.utils.book_append_sheet(wb, wsMatrix, 'Compliance matrix');

  // --- Changes since the previous run ---
  if (report.drift) {
    const d = report.drift;
    const rows = [
      ['Compared with run', new Date(d.previousStarted).toLocaleString()],
      ['Pass rate then', d.previousPassRate === null ? 'n/a' : `${d.previousPassRate}%`],
      ['Pass rate now', d.passRate === null ? 'n/a' : `${d.passRate}%`],
      ['Fixed', d.fixed.length], ['Regressed', d.regressed.length], ['Newly assessed', d.added.length],
      ['Still failing, detail changed', d.changed.length], ['Unchanged', d.unchanged], ['Not assessed this time', d.dropped],
      [],
      ['Change', 'Check ID', 'Name', 'Severity', 'Previous status', 'Current status', 'Current detail'],
      ...d.regressed.map(r => ['Regressed', r.id, r.name, r.severity, r.previousStatus, r.status, r.detail]),
      ...d.fixed.map(r => ['Fixed', r.id, r.name, r.severity, r.previousStatus, r.status, r.detail]),
      ...d.changed.map(r => ['Detail changed', r.id, r.name, r.severity, r.previousStatus || r.status, r.status, r.detail]),
      ...d.added.map(r => ['New', r.id, r.name, r.severity, '', r.status, r.detail])
    ];
    const wsChanges = X.utils.aoa_to_sheet(rows);
    wsChanges['!cols'] = [{ wch: 22 }, { wch: 26 }, { wch: 56 }, { wch: 10 }, { wch: 15 }, { wch: 14 }, { wch: 80 }];
    X.utils.book_append_sheet(wb, wsChanges, 'Changes');
  }

  // --- Remediation plan ---
  {
    const rows = [['Owner', '#', 'Check ID', 'Name', 'Severity', 'Status', 'Effort', 'Detail', 'Portal fix', 'PowerShell', 'Controls']];
    for (const g of remediationPlan(report)) {
      g.items.forEach((r, i) => rows.push([g.label, i + 1, r.id, r.name, r.severity, r.status === 'Warning' ? 'Partial' : r.status, effortLabel(r), r.detail,
        fixText(r.remediation?.portal || ''), fixText(r.remediation?.powershell || ''), controlIds(r, report).join('; ')]));
    }
    const ws = X.utils.aoa_to_sheet(rows);
    ws['!cols'] = [{ wch: 26 }, { wch: 4 }, { wch: 26 }, { wch: 56 }, { wch: 10 }, { wch: 9 }, { wch: 18 }, { wch: 70 }, { wch: 60 }, { wch: 60 }, { wch: 40 }];
    X.utils.book_append_sheet(wb, ws, 'Remediation plan');
  }

  // --- Microsoft security signals ---
  if (report.signals) {
    const ss = report.signals.secureScore, al = report.signals.alerts;
    const rows = [];
    if (ss) {
      rows.push(['Microsoft Secure Score', ss.percent === null ? 'n/a' : `${ss.percent}%`], ['Points', `${ss.current} of ${ss.max}`], ['Last computed', ss.updated || ''], []);
      rows.push(['Improvement action', 'Category', 'Points available', 'Max', 'Implementation cost', 'User impact', 'Link']);
      for (const a of ss.actions) rows.push([a.title, a.category, Math.round(a.gap * 10) / 10, a.max, a.cost, a.impact, a.url]);
      rows.push([]);
    }
    if (al) {
      rows.push(['Open Defender alerts', al.open, 'High', al.high], []);
      rows.push(['Severity', 'Alert', 'Category', 'Status', 'Created', 'Source']);
      for (const a of al.items) rows.push([a.severity, a.title, a.category, a.status, a.created, a.source]);
    }
    const ws = X.utils.aoa_to_sheet(rows);
    ws['!cols'] = [{ wch: 60 }, { wch: 22 }, { wch: 16 }, { wch: 10 }, { wch: 20 }, { wch: 14 }, { wch: 60 }];
    X.utils.book_append_sheet(wb, ws, 'Security signals');
  }

  // --- Framework coverage ---
  const coverage = [
    ['Framework', 'Pass', 'Fail', 'Partial', 'Unknown', 'Scored', 'Pass rate', 'Failing controls'],
    ...report.frameworks.map(f => [
      f.label, f.pass, f.fail, f.warning || 0, f.unknown, f.scored,
      f.passRate === null ? 'n/a' : `${f.passRate}%`,
      f.failingControls.join(', ')
    ])
  ];
  const wsCoverage = X.utils.aoa_to_sheet(coverage);
  wsCoverage['!cols'] = [{ wch: 46 }, 6, 6, 8, 8, 8, 10].map(w => (typeof w === 'number' ? { wch: w } : w)).concat([{ wch: 90 }]);
  X.utils.book_append_sheet(wb, wsCoverage, 'Framework coverage');

  return wb;
}

export async function downloadXlsx(report) {
  const lib = await ensureXlsx();
  const wb = buildWorkbook(report, lib);
  const out = lib.write(wb, { bookType: 'xlsx', type: 'array' });
  download(`assessment-${stamp(report)}.xlsx`, out,
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
}

// ---------------------------------------------------------------------------------------
// Self-contained HTML report
// ---------------------------------------------------------------------------------------
export function buildHtmlReport(report) {
  const s = report.summary;
  const when = new Date(report.started).toLocaleString();
  const duration = report.durationMs !== undefined ? `${(report.durationMs / 1000).toFixed(1)}s` : null;

  const sevRow = SEVERITY_ORDER.slice(0, 4)
    .filter(k => s.failedBySeverity[k] > 0)
    .map(k => `<span class="pill ${k.toLowerCase()}">${s.failedBySeverity[k]} ${k}</span>`)
    .join(' ') || '<span class="pill none">No failures</span>';
  const warnPill = s.warning ? ` <span class="pill warning">${s.warning} partial</span>` : '';
  const areaList = report.areas || [];
  const areaLine = areaList.map(a => esc(a.label)).join(', ');

  // Control IDs beyond the first eight fold away: a check that maps to two hundred MITRE
  // techniques should not be two screens tall.
  const controlsCell = (r) => {
    const ids = Object.values(frameworksOf(r, r.inScope === false ? [] : report.frameworkFilter)).map(m => m.controlId);
    const head = ids.slice(0, 8).map(esc).join('<br>');
    const rest = ids.slice(8);
    return { text: ids.join(' '), html: rest.length ? `${head}<details class="more"><summary>+${rest.length} more</summary>${rest.map(esc).join('<br>')}</details>` : head };
  };
  const row = (r) => {
    const c = controlsCell(r);
    const fixable = r.status === 'Fail' || r.status === 'Warning';
    const fix = (fixable && r.remediation?.portal ? `<div class="rem"><b>Fix:</b> ${esc(fixText(r.remediation.portal))}</div>` : '') +
                (fixable && r.remediation?.powershell ? `<div class="rem"><code>${esc(fixText(r.remediation.powershell))}</code></div>` : '');
    const copy = fixable ? `<button type="button" class="x-copy" data-ticket="${esc(ticketText(r, report))}">Copy as ticket</button>` : '';
    return `<tr class="s-${r.status.toLowerCase()}" ${rowAttrs(r, report, c.text)}>` +
      `<td><span class="status ${r.status.toLowerCase()}">${esc(r.status)}</span></td>` +
      `<td><span class="sev ${esc(String(r.severity).toLowerCase())}">${esc(r.severity)}</span>${fixable ? `<br><span class="effort ${esc(r.effort || '')}">${esc(effortLabel(r))}</span>` : ''}</td>` +
      `<td><code>${esc(r.id)}</code><div class="nm">${esc(r.name)}</div><div class="nm">${esc(ownerLabel(r))}</div></td>` +
      `<td>${esc(r.detail)}${fix}${copy}</td>` +
      `<td class="fw">${c.html}</td></tr>`;
  };

  const sorted = sortResults(report.results);
  const findings = sorted.filter(r => r.inScope !== false).map(row).join('');
  const others = sorted.filter(r => r.inScope === false);
  const othersRows = others.map(row).join('');
  const othersSummary = summariseList(others);

  const priorities = (report.priorities || []).map((r, i) => `
    <li><b>${esc(r.name)}</b> <span class="sev ${esc(String(r.severity).toLowerCase())}">${esc(r.severity)}</span> <span class="effort ${esc(r.effort || '')}">${esc(effortLabel(r))}</span> <span class="muted">· ${esc(ownerLabel(r))}</span>
      <div class="muted">${esc(r.detail)}</div>
      ${r.remediation?.portal ? `<div class="rem"><b>Fix:</b> ${esc(fixText(r.remediation.portal))}</div>` : ''}
    </li>`).join('');

  const d = report.drift;
  const driftLi = (r, note) => `<li><b>${esc(r.name)}</b> <code>${esc(r.id)}</code> — ${esc(note)}<div class="muted">${esc(r.detail)}</div></li>`;
  const driftSection = d ? `
  <section id="changes" class="rc-section">
  <h2>Changes since ${esc(new Date(d.previousStarted).toLocaleString())}</h2>
  <p class="muted">Pass rate ${d.previousPassRate === null ? '—' : d.previousPassRate + '%'} → ${d.passRate === null ? '—' : d.passRate + '%'}.
  ${d.fixed.length} fixed, ${d.regressed.length} regressed, ${d.added.length} newly assessed, ${d.unchanged} unchanged${d.dropped ? `, ${d.dropped} not assessed this time` : ''}.
  Comparison data is kept only in the browser that ran the assessment.</p>
  ${d.regressed.length ? `<h3>Regressed</h3><ul class="drift">${d.regressed.map(r => driftLi(r, `was ${r.previousStatus}, now ${r.status}`)).join('')}</ul>` : ''}
  ${d.fixed.length ? `<h3>Fixed</h3><ul class="drift">${d.fixed.map(r => driftLi(r, r.partial ? 'was Fail, now Warning' : `was ${r.previousStatus}, now Pass`)).join('')}</ul>` : ''}
  ${d.changed.length ? `<h3>Still failing, detail changed</h3><ul class="drift">${d.changed.map(r => driftLi(r, `previously: ${r.previousDetail || r.previousStatus}`)).join('')}</ul>` : ''}
  </section>` : '';

  const scope = scopeLabel(report);
  const sAll = report.summaryAll || s;
  const scopeNote = scope
    ? `${report.scope.inScopeCount} of ${report.results.length} checks map to ${scope}. Controls shown are for the selected framework${report.scope.frameworks.length === 1 ? '' : 's'} only.`
    : 'All frameworks. Controls shown are every mapping for each check.';
  const overviewNote = scope
    ? `Scored against the ${report.scope.inScopeCount} checks that map to ${esc(scope)}; ${s.scored} of those could be scored. Across all ${report.results.length} checks regardless of framework the pass rate is ${sAll.passRate === null ? 'n/a' : sAll.passRate + '%'} (${sAll.pass} of ${sAll.scored}).`
    : `Pass rate counts only the ${s.scored} checks that could be scored.`;

  const frameworks = report.frameworks.map(f => `
    <tr>
      <td>${esc(f.label)}</td>
      <td class="num">${f.pass}</td>
      <td class="num">${f.fail}</td>
      <td class="num">${f.warning || 0}</td>
      <td class="num">${f.passRate === null ? '—' : f.passRate + '%'}</td>
      <td class="fw">${esc(f.failingControls.slice(0, 12).join(', '))}${f.failingControls.length > 12 ? ` +${f.failingControls.length - 12} more` : ''}</td>
    </tr>`).join('');

  const unavailable = report.unavailable.length ? `
    <h3>Not collected</h3>
    <p class="muted">These areas could not be read, so the checks depending on them are reported as Unknown and excluded from the pass rate.</p>
    <table><thead><tr><th>Area</th><th>Reason</th></tr></thead><tbody>
    ${report.unavailable.map(u => `<tr><td>${esc(u.label)}</td><td>${esc(u.reason)}</td></tr>`).join('')}
    </tbody></table>` : '';

  const planBlock = planHtml(report);
  const hasPlan = Boolean(planBlock);
  const hasDomains = Boolean(areaCardsHtml(report));
  const hasFrameworks = Boolean(report.frameworks.length);
  const hasSignals = Boolean(report.signals);

  // Sidebar: Executive links always include Overview and Posture score; the rest only when
  // that section actually exists in this report, so the nav never promises an empty page.
  const navLink = (href, label, badge) =>
    `<a href="${href}">${label}${badge !== undefined ? ` <span class="rc-badge">${badge}</span>` : ''}</a>`;
  const execLinks = [
    navLink('#overview', 'Overview'),
    navLink('#posture', 'Posture score'),
    d ? navLink('#changes', 'Changes since last run') : '',
    hasSignals ? navLink('#signals', 'Microsoft signals') : '',
    hasDomains ? navLink('#domains', 'Domain posture') : '',
    hasFrameworks ? navLink('#frameworks', 'Frameworks') : ''
  ].filter(Boolean).join('');
  const domainLinks = (report.areaSummary || []).map(a =>
    `<a href="#findings" data-jump="area:${esc(a.id)}">${esc(a.label)} <span class="rc-badge${a.fail + a.warning ? '' : ' rc-badge-zero'}">${a.fail + a.warning}</span></a>`).join('');
  const detailLinks = [
    navLink('#findings', 'All findings', report.results.length),
    hasPlan ? navLink('#plan', 'Remediation plan') : '',
    navLink('#appendix', 'Appendix')
  ].filter(Boolean).join('');

  const tenantFacts = [
    ['Tenant', esc(report.tenant?.name || 'Unknown')],
    report.tenant?.id && report.tenant.id !== report.tenant.name ? ['Tenant ID', esc(report.tenant.id)] : null,
    ['Run', esc(when)],
    duration ? ['Duration', esc(duration)] : null,
    ['Areas', String(areaList.length)],
    ['Scope', scope ? esc(scope) : 'All frameworks']
  ].filter(Boolean);

  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security assessment — ${esc(report.tenant?.name || 'tenant')}${scope ? ' — ' + esc(scope) : ''}</title>
<style>
:root{--bg:#080d1f;--bg-grad:radial-gradient(circle at 85% -10%,#16265a 0,transparent 45%),var(--bg);--panel:#0f1830;--panel-2:#131d38;--ink:#eef1f6;--muted:#9aa7bc;--rule:rgba(255,255,255,.11);--accent:#8c6cff;--accent-2:#35d7ff;--accent-grad:linear-gradient(90deg,#8c6cff,#35d7ff)}
:root[data-theme="light"]{--bg:#f5f7fa;--bg-grad:var(--bg);--panel:#ffffff;--panel-2:#f3f5f7;--ink:#0d1b2a;--muted:#5a6a7d;--rule:#dfe4ea;--accent:#8b0055;--accent-2:#c9366e;--accent-grad:linear-gradient(90deg,#8b0055,#c9366e)}
*{box-sizing:border-box}
html,body{margin:0}
body{background:var(--bg-grad);color:var(--ink);font:14px/1.6 -apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif}
a{color:var(--accent)}
.muted{color:var(--muted);font-size:13px}
h2{font-size:19px;margin:0 0 12px;padding-bottom:9px;border-bottom:1px solid var(--rule)}
h3{font-size:15px;margin:20px 0 8px}
code{font:12px ui-monospace,Consolas,monospace;background:var(--panel-2);padding:1px 4px;border-radius:2px}
table{width:100%;border-collapse:collapse;background:var(--panel);font-size:13px;margin-top:10px;border:1px solid var(--rule);border-radius:5px;overflow:hidden}
th{background:var(--panel-2);text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}
th,td{padding:10px 12px;border-bottom:1px solid var(--rule);vertical-align:top}
tr:last-child td{border-bottom:0}
td.num{text-align:right;font-variant-numeric:tabular-nums}
.pill{display:inline-block;padding:3px 10px;border-radius:11px;font-size:12px;margin-right:5px}
.pill.critical{background:#4a0d18;color:#fff}.pill.high{background:#fde2e2;color:#8c1d1d}
.pill.medium{background:#fff3d6;color:#7a4f00}.pill.warning{background:#fff3d6;color:#7a4f00}.pill.low{background:#e6eef7;color:#274b6d}.pill.none{background:#e5f5ee;color:#146c55}
.status{font-size:11px;padding:2px 8px;border-radius:10px;white-space:nowrap}
.status.pass{background:#e5f5ee;color:#146c55}.status.fail{background:#fde2e2;color:#8c1d1d}
.status.warning{background:#fff3d6;color:#7a4f00}.status.unknown{background:#eceff3;color:#5a6a7d}.status.notapplicable{background:#f2f2f2;color:#888}
.sev{font-size:11px;white-space:nowrap}.sev.critical{color:#c0364a;font-weight:700}.sev.high{color:#d6455f}
.sev.medium{color:#c98a00}.sev.low{color:#6e8cad}
.nm{margin-top:4px;color:var(--muted);font-size:12px}
.rem{margin-top:7px;padding-left:9px;border-left:2px solid var(--rule);font-size:12px;color:var(--muted)}
.fw{font-size:11px;color:var(--muted);max-width:230px;word-break:break-word}
tr.s-pass td{opacity:.72}
.lead{font-size:15px;line-height:1.7;max-width:900px;margin:0 0 10px}
.priorities{padding-left:22px;margin:0}.priorities li{margin-bottom:12px}.priorities li>b{font-size:14px}
.drift{padding-left:22px}.drift li{margin-bottom:9px}
.sev-row-report{margin:14px 0}
details.more{margin-top:4px}details.more summary{cursor:pointer;color:var(--accent-2);font-size:11px}
table.findings th:nth-child(1),table.findings td:nth-child(1){width:88px;white-space:nowrap}
table.findings th:nth-child(2),table.findings td:nth-child(2){width:78px;white-space:nowrap}
table.findings th:nth-child(3),table.findings td:nth-child(3){width:26%}
table.findings th:nth-child(5),table.findings td:nth-child(5){width:200px}
table.plan th:nth-child(1),table.plan td:nth-child(1){width:36px}table.plan th:nth-child(3),table.plan td:nth-child(3),table.plan th:nth-child(4),table.plan td:nth-child(4){width:110px;white-space:nowrap}
table.signals td a{color:var(--accent-2)}.sev.high,.sev.medium,.sev.low,.sev.informational{text-transform:capitalize}
${EXPLORER_CSS}
${REPORT_CSS}

/* ---- layout: sidebar + topbar shell, report-only (the live page has neither) ---- */
.rc-shell{display:flex;align-items:flex-start}
.rc-sidebar{flex:0 0 250px;width:250px;position:sticky;top:0;align-self:flex-start;height:100vh;overflow-y:auto;background:var(--panel);border-right:1px solid var(--rule);padding:20px 16px 30px}
.rc-nav-summary{display:none}
.rc-brand{margin-bottom:22px}
.rc-brand-mark{font-size:19px;font-weight:700;letter-spacing:.01em}
.rc-brand-mark em{color:var(--accent);font-style:normal}
.rc-brand-sub{display:block;font-size:10px;letter-spacing:.12em;color:var(--muted);margin-top:2px}
.rc-nav{display:flex;flex-direction:column;margin-bottom:22px}
.rc-nav-h{font-size:10.5px;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);margin:16px 0 6px;font-weight:700}
.rc-nav-h:first-child{margin-top:0}
.rc-nav a{display:flex;align-items:center;justify-content:space-between;gap:8px;padding:6px 8px;border-radius:4px;color:var(--ink);text-decoration:none;font-size:13px;line-height:1.35}
.rc-nav a:hover{background:var(--panel-2)}
.rc-nav a.active{background:var(--panel-2);color:var(--accent);font-weight:600}
.rc-badge{font-size:10.5px;background:var(--panel-2);color:var(--muted);border-radius:8px;padding:1px 7px;font-variant-numeric:tabular-nums}
.rc-badge-zero{opacity:.55}
.rc-tenant-card{border-top:1px solid var(--rule);padding-top:14px}
.rc-tenant-card dl{margin:8px 0 0;font-size:12px}
.rc-tenant-card dl>div{display:flex;justify-content:space-between;gap:10px;padding:3px 0;color:var(--muted)}
.rc-tenant-card dt{white-space:nowrap}
.rc-tenant-card dd{margin:0;color:var(--ink);text-align:right;word-break:break-word}
.rc-main{flex:1;min-width:0}
.rc-topbar{position:sticky;top:0;z-index:6;height:56px;background:var(--panel);border-bottom:1px solid var(--rule);display:flex;align-items:center;justify-content:space-between;padding:0 26px;gap:16px}
.rc-topbar-title{display:flex;flex-direction:column;line-height:1.25;overflow:hidden}
.rc-topbar-title b{font-size:14px}
.rc-topbar-title span{font-size:12px;color:var(--muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.rc-topbar-actions{display:flex;gap:8px;flex:0 0 auto}
.rc-theme,.rc-print{font:12px inherit;border:1px solid var(--rule);background:var(--panel-2);color:var(--ink);padding:7px 12px;border-radius:4px;cursor:pointer}
.rc-theme:hover,.rc-print:hover{border-color:var(--accent)}
.rc-content{max-width:1180px;margin:0 auto;padding:26px 28px 70px}
.rc-section{margin:0 0 42px;scroll-margin-top:66px}
.rc-appendix-note{margin-top:20px}
@media(min-width:881px){
  .rc-nav-toggle{display:block}
  .rc-nav-toggle summary{display:none}
  .rc-nav-toggle>*{display:block!important}
}
@media(max-width:880px){
  .rc-shell{display:block}
  .rc-sidebar{position:static;width:auto;height:auto;border-right:0;border-bottom:1px solid var(--rule)}
  .rc-nav-toggle summary{display:block;cursor:pointer;font-size:12px;letter-spacing:.08em;text-transform:uppercase;color:var(--muted);padding:6px 0}
}

/* ---- dark theme: the components imported from explore.js use literal light colors so they
   read correctly on the live page too; these overrides restyle them for the report's own
   default dark view, and are screen-only so print is always the light, paper-safe version. ---- */
@media screen{
:root:not([data-theme="light"]) .hero-score,
:root:not([data-theme="light"]) .tile,
:root:not([data-theme="light"]) .fw-picker,
:root:not([data-theme="light"]) .area-card,
:root:not([data-theme="light"]) .explorer,
:root:not([data-theme="light"]) .x-copy{background:var(--panel);border-color:var(--rule);color:var(--ink)}
:root:not([data-theme="light"]) .hero-bar,:root:not([data-theme="light"]) .fw-bar,:root:not([data-theme="light"]) .area-card .bar{background:var(--panel-2)}
:root:not([data-theme="light"]) .hero-bar i{background:var(--accent-grad)}
:root:not([data-theme="light"]) .fw-bar i{background:var(--accent-2)}
:root:not([data-theme="light"]) .hero-label,:root:not([data-theme="light"]) .hero-sub,:root:not([data-theme="light"]) .tile small,:root:not([data-theme="light"]) .fw-rate,:root:not([data-theme="light"]) .fw-panel small,:root:not([data-theme="light"]) .x-count,:root:not([data-theme="light"]) .area-card span,:root:not([data-theme="light"]) .area-card small{color:var(--muted)}
:root:not([data-theme="light"]) .x-search,:root:not([data-theme="light"]) .fw-select-label select{background:var(--panel-2);border-color:var(--rule);color:var(--ink)}
:root:not([data-theme="light"]) .x-chip{background:var(--panel-2);border-color:var(--rule);color:var(--ink)}
:root:not([data-theme="light"]) .x-clear{background:var(--panel-2);border-color:var(--rule);color:var(--ink)}
:root:not([data-theme="light"]) .x-copy{color:var(--accent-2)}
:root:not([data-theme="light"]) tr.x-empty td{color:var(--muted)}
}
@page{margin:14mm}
@media print{
:root{--bg:#fff;--bg-grad:#fff;--panel:#fff;--panel-2:#f3f5f7;--ink:#0d1b2a;--muted:#5a6a7d;--rule:#dfe4ea;--accent:#8b0055;--accent-2:#8b0055}
body{font-size:12px}
.rc-sidebar,.rc-topbar{display:none}
.rc-shell{display:block}
.rc-content{max-width:none;padding:0;margin:0}
.rc-section{break-inside:avoid-page;scroll-margin-top:0}
h2{break-after:avoid}
tr{break-inside:avoid}
table{font-size:11px}
th,td{padding:6px 8px}
.hero{break-inside:avoid}
.hero-score b{font-size:32px}
tr.s-pass td{opacity:1}
details.more{display:none}
}
</style></head>
<body>
<div class="rc-shell">
<aside class="rc-sidebar">
<details class="rc-nav-toggle" open>
<summary class="rc-nav-summary">Navigate</summary>
<div class="rc-brand"><span class="rc-brand-mark">Identity<em>Frontline</em></span><span class="rc-brand-sub">SECURITY REPORT</span></div>
<nav class="rc-nav">
<p class="rc-nav-h">Executive</p>
${execLinks}
${hasDomains ? `<p class="rc-nav-h">Domains</p>${domainLinks}` : ''}
<p class="rc-nav-h">Details</p>
${detailLinks}
</nav>
<div class="rc-tenant-card">
<p class="rc-nav-h">Tenant</p>
<dl>${tenantFacts.map(([k, v]) => `<div><dt>${k}</dt><dd>${v}</dd></div>`).join('')}</dl>
</div>
</details>
</aside>
<div class="rc-main">
<header class="rc-topbar">
<div class="rc-topbar-title"><b>Security posture report</b><span>${esc(report.tenant?.name || 'Tenant')}${scope ? ` · ${esc(scope)}` : ''}</span></div>
<div class="rc-topbar-actions">
<button type="button" class="rc-theme" aria-label="Switch theme" aria-pressed="false">◐</button>
<button type="button" class="rc-print">Print</button>
</div>
</header>
<main class="rc-content">

<section id="overview" class="rc-section">
<h2>Overview</h2>
<p class="muted">${esc(overviewNote)} Unknown and not-applicable results are excluded rather than counted as failures.</p>
${executiveSummaryParts(report).map(p => `<p class="lead">${esc(p)}</p>`).join('')}
</section>

<section id="posture" class="rc-section">
<h2>Posture score</h2>
${heroHtml(report)}
${alertBannerHtml(report)}
<p class="sev-row-report">${sevRow}${warnPill}</p>
${priorities ? `<h3>Fix first</h3><ol class="priorities">${priorities}</ol>` : ''}
</section>

${driftSection}

${hasSignals ? `<section id="signals" class="rc-section">${signalsHtml(report)}</section>` : ''}

${hasDomains ? `
<section id="domains" class="rc-section">
<h2>Security posture by domain</h2>
<p class="muted">Each bar shows passed, partial and failed as a share of what could be scored. Click a card to filter the findings table to that domain.</p>
${areaCardsHtml(report)}
</section>` : ''}

${hasFrameworks ? `
<section id="frameworks" class="rc-section">
<h2>Framework coverage</h2>
${frameworkPickerHtml(report)}
<p class="muted">One technical condition maps to many frameworks. These figures reflect only the ${s.total} checks in this assessment, not each framework in full.</p>
<table><thead><tr><th>Framework</th><th class="num">Pass</th><th class="num">Fail</th><th class="num">Partial</th><th class="num">Rate</th><th>Failing controls</th></tr></thead>
<tbody>${frameworks}</tbody></table>
</section>` : ''}

<section id="findings" class="rc-section">
<h2>Findings${scope ? ` — ${esc(scope)}` : ''}</h2>
<p class="muted">${esc(scopeNote)}</p>
${explorerToolbar(report)}
<table class="findings"><thead><tr><th>Status</th><th>Severity</th><th>Check</th><th>Detail</th><th>Controls</th></tr></thead>
<tbody data-explore>${findings}</tbody></table>
${others.length ? `
<h3>Other findings — not mapped to ${esc(scope)}</h3>
<p class="muted">${others.length} check${others.length === 1 ? '' : 's'} were assessed but do not map to the selected
framework${report.scope.frameworks.length === 1 ? '' : 's'}: ${othersSummary.pass} passed, ${othersSummary.fail} failed, ${othersSummary.other} other.
They are excluded from the score above and listed here so nothing is hidden. Controls shown are all their mappings.</p>
<table class="findings"><thead><tr><th>Status</th><th>Severity</th><th>Check</th><th>Detail</th><th>Controls</th></tr></thead>
<tbody data-explore>${othersRows}</tbody></table>` : ''}
</section>

${hasPlan ? `<section id="plan" class="rc-section">${planBlock}</section>` : ''}

<section id="appendix" class="rc-section">
<h2>Appendix</h2>
${unavailable}
<p class="muted rc-appendix-note">
Generated locally in the browser. No tenant data was transmitted to identityfrontline.com.<br>
Control definitions and framework mappings from
M365-Assess (&copy; Galvnyz, MIT licensed) &mdash; registry ${esc(report.catalog?.source?.registry?.dataVersion || 'n/a')}.<br>
This is a posture snapshot and remediation guide, not a certification or formal audit opinion.<br>
<strong>Confidential.</strong> Contains tenant configuration and administrator identities. Store and share it as you would any security assessment.
</p>
</section>

</main>
</div>
</div>
<script>(${explorer.toString()})(document.body);(${reportChrome.toString()})(document.body);</script>
</body></html>`;
}
