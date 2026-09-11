// Identity Frontline — results rendering and offline report generation.
//
// Everything here runs on data already in the browser. The downloadable HTML report is fully
// self-contained: no scripts, no external references, safe to open offline or attach to a
// remediation ticket.

import { frameworksOf } from './engine.js';

const SEVERITY_ORDER = ['Critical', 'High', 'Medium', 'Low', 'Unknown'];
const STATUS_ORDER = { Fail: 0, Unknown: 1, NotApplicable: 2, Pass: 3 };

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
  other: list.filter(r => r.status !== 'Pass' && r.status !== 'Fail').length
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
  const s = report.summary;
  const name = report.tenant?.name || 'The tenant';
  const parts = [];
  const scope = scopeLabel(report);

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
  if (s.fail === 0 && s.scored > 0) {
    parts.push('No failing checks were found in the assessed scope.');
  } else if (sev.length) {
    parts.push(`${s.fail} check${s.fail === 1 ? '' : 's'} failed: ${sev.join(', ')}.`);
  }

  const top = report.priorities || [];
  if (top.length) {
    const lead = top.slice(0, 3).map(r => r.name.replace(/^Ensure (that )?/i, '').replace(/\.$/, ''));
    parts.push(`Address first: ${lead.join('; ')}.`);
  }

  if (s.unknown > 0) {
    parts.push(`${s.unknown} check${s.unknown === 1 ? '' : 's'} could not be evaluated and ${s.unknown === 1 ? 'is' : 'are'} excluded from the score${report.unavailable?.length ? ` (${report.unavailable.map(u => u.label.toLowerCase()).join(', ')} not collected)` : ''}.`);
  }

  parts.push('This is a point-in-time posture snapshot, not a certification.');
  return parts.join(' ');
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
    ['Passed', s.pass], ['Failed', s.fail], ['Unknown', s.unknown], ['Not applicable', s.notApplicable],
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

  // --- Framework coverage ---
  const coverage = [
    ['Framework', 'Pass', 'Fail', 'Unknown', 'Scored', 'Pass rate', 'Failing controls'],
    ...report.frameworks.map(f => [
      f.label, f.pass, f.fail, f.unknown, f.scored,
      f.passRate === null ? 'n/a' : `${f.passRate}%`,
      f.failingControls.join(', ')
    ])
  ];
  const wsCoverage = X.utils.aoa_to_sheet(coverage);
  wsCoverage['!cols'] = [{ wch: 46 }, 6, 6, 8, 8, 10].map(w => (typeof w === 'number' ? { wch: w } : w)).concat([{ wch: 90 }]);
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

  const sevRow = SEVERITY_ORDER.slice(0, 4)
    .filter(k => s.failedBySeverity[k] > 0)
    .map(k => `<span class="pill ${k.toLowerCase()}">${s.failedBySeverity[k]} ${k}</span>`)
    .join(' ') || '<span class="pill none">No failures</span>';

  const row = (r) => `
    <tr class="s-${r.status.toLowerCase()}">
      <td><span class="status ${r.status.toLowerCase()}">${esc(r.status)}</span></td>
      <td><span class="sev ${esc(String(r.severity).toLowerCase())}">${esc(r.severity)}</span></td>
      <td><code>${esc(r.id)}</code><div class="nm">${esc(r.name)}</div></td>
      <td>${esc(r.detail)}
        ${r.status === 'Fail' && r.remediation?.portal ? `<div class="rem"><b>Fix:</b> ${esc(fixText(r.remediation.portal))}</div>` : ''}
        ${r.status === 'Fail' && r.remediation?.powershell ? `<div class="rem"><code>${esc(fixText(r.remediation.powershell))}</code></div>` : ''}
      </td>
      <td class="fw">${Object.entries(frameworksOf(r, r.inScope === false ? [] : report.frameworkFilter)).map(([, m]) => esc(m.controlId)).join('<br>')}</td>
    </tr>`;

  const sorted = sortResults(report.results);
  const findings = sorted.filter(r => r.inScope !== false).map(row).join('');
  const others = sorted.filter(r => r.inScope === false);
  const othersRows = others.map(row).join('');
  const othersSummary = summariseList(others);

  const priorities = (report.priorities || []).map((r, i) => `
    <li><b>${esc(r.name)}</b> <span class="sev ${esc(String(r.severity).toLowerCase())}">${esc(r.severity)}</span>
      <div class="muted">${esc(r.detail)}</div>
      ${r.remediation?.portal ? `<div class="rem"><b>Fix:</b> ${esc(fixText(r.remediation.portal))}</div>` : ''}
    </li>`).join('');

  const scope = scopeLabel(report);
  const sAll = report.summaryAll || s;
  const scopeNote = scope
    ? `${report.scope.inScopeCount} of ${report.results.length} checks map to ${scope}. Controls shown are for the selected framework${report.scope.frameworks.length === 1 ? '' : 's'} only.`
    : 'All frameworks. Controls shown are every mapping for each check.';

  const frameworks = report.frameworks.map(f => `
    <tr>
      <td>${esc(f.label)}</td>
      <td class="num">${f.pass}</td>
      <td class="num">${f.fail}</td>
      <td class="num">${f.passRate === null ? '—' : f.passRate + '%'}</td>
      <td class="fw">${esc(f.failingControls.slice(0, 12).join(', '))}${f.failingControls.length > 12 ? ` +${f.failingControls.length - 12} more` : ''}</td>
    </tr>`).join('');

  const unavailable = report.unavailable.length ? `
    <h2>Not collected</h2>
    <p class="muted">These areas could not be read, so the checks depending on them are reported as Unknown and excluded from the pass rate.</p>
    <table><thead><tr><th>Area</th><th>Reason</th></tr></thead><tbody>
    ${report.unavailable.map(u => `<tr><td>${esc(u.label)}</td><td>${esc(u.reason)}</td></tr>`).join('')}
    </tbody></table>` : '';

  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security assessment — ${esc(report.tenant?.name || 'tenant')}${scope ? ' — ' + esc(scope) : ''}</title>
<style>
:root{--ink:#0d1b2a;--muted:#5a6a7d;--rule:#dfe4ea;--bg:#f5f7fa}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.6 -apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif}
header{background:#080d1f;color:#fff;padding:36px 40px}
header h1{margin:0 0 6px;font-size:26px}header p{margin:0;color:#aab3c1;font-size:13px}
main{max-width:1180px;margin:0 auto;padding:32px 24px 64px}
h2{font-size:19px;margin:34px 0 12px;padding-bottom:7px;border-bottom:1px solid var(--rule)}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-top:20px}
.card{background:#fff;border:1px solid var(--rule);padding:16px;border-radius:3px}
.card b{display:block;font-size:28px;line-height:1.1}.card span{font-size:12px;color:var(--muted)}
.pill{display:inline-block;padding:3px 10px;border-radius:11px;font-size:12px;margin-right:5px}
.pill.critical{background:#4a0d18;color:#fff}.pill.high{background:#fde2e2;color:#8c1d1d}
.pill.medium{background:#fff3d6;color:#7a4f00}.pill.low{background:#e6eef7;color:#274b6d}.pill.none{background:#e5f5ee;color:#146c55}
table{width:100%;border-collapse:collapse;background:#fff;font-size:13px;margin-top:10px}
th{background:#eef1f5;text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}
th,td{padding:10px 12px;border-bottom:1px solid var(--rule);vertical-align:top}
td.num{text-align:right;font-variant-numeric:tabular-nums}
.status{font-size:11px;padding:2px 8px;border-radius:10px;white-space:nowrap}
.status.pass{background:#e5f5ee;color:#146c55}.status.fail{background:#fde2e2;color:#8c1d1d}
.status.unknown{background:#eceff3;color:#5a6a7d}.status.notapplicable{background:#f2f2f2;color:#888}
.sev{font-size:11px;white-space:nowrap}.sev.critical{color:#8c1d1d;font-weight:700}.sev.high{color:#b03030}
.sev.medium{color:#7a4f00}.sev.low{color:#4a6580}
code{font:12px ui-monospace,Consolas,monospace;background:#f0f2f5;padding:1px 4px;border-radius:2px}
.nm{margin-top:4px;color:var(--muted);font-size:12px}
.rem{margin-top:7px;padding-left:9px;border-left:2px solid var(--rule);font-size:12px;color:var(--muted)}
.fw{font-size:11px;color:var(--muted);max-width:230px;word-break:break-word}
.muted{color:var(--muted);font-size:13px}
tr.s-pass td{opacity:.72}
footer{margin-top:40px;padding-top:16px;border-top:1px solid var(--rule);font-size:11px;color:var(--muted)}
.lead{font-size:15px;line-height:1.7;max-width:900px}
.scope{display:inline-block;font-size:13px;font-weight:400;background:rgba(255,255,255,.12);padding:3px 10px;border-radius:11px;vertical-align:middle;margin-left:8px}
.priorities{padding-left:22px}.priorities li{margin-bottom:12px}.priorities li>b{font-size:14px}
@page{margin:14mm}
@media print{body{background:#fff;font-size:12px}header{background:#fff;color:#000;border-bottom:2px solid #000;padding:0 0 12px}header p{color:#444}main{padding:0;max-width:none}h2{break-after:avoid}tr{break-inside:avoid}table{font-size:11px}th,td{padding:6px 8px}.cards{grid-template-columns:repeat(5,1fr)}.card b{font-size:20px}tr.s-pass td{opacity:1}}
</style></head><body>
<header>
  <h1>Microsoft 365 security assessment${scope ? ` <span class="scope">${esc(scope)}</span>` : ''}</h1>
  <p>${esc(report.tenant?.name || 'Tenant')}${report.tenant?.id && report.tenant.id !== report.tenant.name ? ' &middot; ' + esc(report.tenant.id) : ''} &middot; ${esc(when)}${scope ? ` &middot; Scope: ${esc(scope)}` : ' &middot; All frameworks'}</p>
</header>
<main>
  <div class="cards">
    <div class="card"><b>${s.passRate === null ? '—' : s.passRate + '%'}</b><span>Pass rate${scope ? ' — ' + esc(scope) : ''}</span></div>
    <div class="card"><b>${s.pass}</b><span>Passed</span></div>
    <div class="card"><b>${s.fail}</b><span>Failed</span></div>
    <div class="card"><b>${s.unknown}</b><span>Unknown</span></div>
    <div class="card"><b>${s.notApplicable}</b><span>Not applicable</span></div>
  </div>
  <p style="margin-top:14px">${sevRow}</p>
  <p class="muted">${scope
    ? `Scored against the ${report.scope.inScopeCount} checks that map to ${esc(scope)}; ${s.scored} of those could be scored. Across all ${report.results.length} checks regardless of framework the pass rate is ${sAll.passRate === null ? 'n/a' : sAll.passRate + '%'} (${sAll.pass} of ${sAll.scored}).`
    : `Pass rate counts only the ${s.scored} checks that could be scored.`} Unknown and
  not-applicable results are excluded rather than counted as failures.</p>

  <h2>Executive summary</h2>
  <p class="lead">${esc(executiveSummary(report))}</p>

  ${priorities ? `<h2>Fix first</h2><ol class="priorities">${priorities}</ol>` : ''}

  <h2>Findings${scope ? ` — ${esc(scope)}` : ''}</h2>
  <p class="muted">${esc(scopeNote)}</p>
  <table><thead><tr><th>Status</th><th>Severity</th><th>Check</th><th>Detail</th><th>Controls</th></tr></thead>
  <tbody>${findings}</tbody></table>

  ${others.length ? `
  <h2>Other findings — not mapped to ${esc(scope)}</h2>
  <p class="muted">${others.length} check${others.length === 1 ? '' : 's'} were assessed but do not map to the selected
  framework${report.scope.frameworks.length === 1 ? '' : 's'}: ${othersSummary.pass} passed, ${othersSummary.fail} failed, ${othersSummary.other} other.
  They are excluded from the score above and listed here so nothing is hidden. Controls shown are all their mappings.</p>
  <table><thead><tr><th>Status</th><th>Severity</th><th>Check</th><th>Detail</th><th>Controls</th></tr></thead>
  <tbody>${othersRows}</tbody></table>` : ''}

  <h2>Compliance framework coverage</h2>
  <p class="muted">One technical condition maps to many frameworks. These figures reflect only the
  ${s.total} checks in this assessment, not each framework in full.</p>
  <table><thead><tr><th>Framework</th><th class="num">Pass</th><th class="num">Fail</th><th class="num">Rate</th><th>Failing controls</th></tr></thead>
  <tbody>${frameworks}</tbody></table>

  ${unavailable}

  <footer>
    Generated locally in the browser. No tenant data was transmitted to identityfrontline.com.<br>
    Control definitions and framework mappings from
    M365-Assess (&copy; Galvnyz, MIT licensed) &mdash; registry ${esc(report.catalog?.source?.registry?.dataVersion || 'n/a')}.<br>
    This is a posture snapshot and remediation guide, not a certification or formal audit opinion.<br>
    <strong>Confidential.</strong> Contains tenant configuration and administrator identities.
  </footer>
</main></body></html>`;
}
