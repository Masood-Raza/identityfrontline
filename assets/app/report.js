// Identity Frontline — results rendering and offline report generation.
//
// Everything here runs on data already in the browser. The downloadable HTML report is fully
// self-contained: no scripts, no external references, safe to open offline or attach to a
// remediation ticket.

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

export function downloadCsv(report) {
  const cols = ['CheckId', 'Name', 'Category', 'Severity', 'Status', 'Detail', 'Remediation', 'Frameworks'];
  const rows = sortResults(report.results).map(r => [
    r.id, r.name, r.category, r.severity, r.status, r.detail,
    r.remediation?.portal || r.remediation?.powershell || '',
    Object.entries(r.frameworks || {}).map(([k, m]) => `${k}:${m.controlId}`).join(' | ')
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

  const findings = sortResults(report.results).map(r => `
    <tr class="s-${r.status.toLowerCase()}">
      <td><span class="status ${r.status.toLowerCase()}">${esc(r.status)}</span></td>
      <td><span class="sev ${esc(String(r.severity).toLowerCase())}">${esc(r.severity)}</span></td>
      <td><code>${esc(r.id)}</code><div class="nm">${esc(r.name)}</div></td>
      <td>${esc(r.detail)}
        ${r.status === 'Fail' && r.remediation?.portal ? `<div class="rem"><b>Fix:</b> ${esc(r.remediation.portal)}</div>` : ''}
        ${r.status === 'Fail' && r.remediation?.powershell ? `<div class="rem"><code>${esc(r.remediation.powershell)}</code></div>` : ''}
      </td>
      <td class="fw">${Object.entries(r.frameworks || {}).map(([, m]) => esc(m.controlId)).join('<br>')}</td>
    </tr>`).join('');

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
<title>Security assessment — ${esc(report.tenant?.name || 'tenant')}</title>
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
@media print{body{background:#fff}header{background:#fff;color:#000;border-bottom:2px solid #000}header p{color:#444}}
</style></head><body>
<header>
  <h1>Microsoft 365 security assessment</h1>
  <p>${esc(report.tenant?.name || 'Tenant')}${report.tenant?.id ? ' &middot; ' + esc(report.tenant.id) : ''} &middot; ${esc(when)}</p>
</header>
<main>
  <div class="cards">
    <div class="card"><b>${s.passRate === null ? '—' : s.passRate + '%'}</b><span>Pass rate</span></div>
    <div class="card"><b>${s.pass}</b><span>Passed</span></div>
    <div class="card"><b>${s.fail}</b><span>Failed</span></div>
    <div class="card"><b>${s.unknown}</b><span>Unknown</span></div>
    <div class="card"><b>${s.notApplicable}</b><span>Not applicable</span></div>
  </div>
  <p style="margin-top:14px">${sevRow}</p>
  <p class="muted">Pass rate counts only the ${s.scored} checks that could be scored. Unknown and
  not-applicable results are excluded rather than counted as failures.</p>

  <h2>Findings</h2>
  <table><thead><tr><th>Status</th><th>Severity</th><th>Check</th><th>Detail</th><th>Controls</th></tr></thead>
  <tbody>${findings}</tbody></table>

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
