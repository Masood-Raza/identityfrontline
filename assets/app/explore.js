// Identity Frontline — findings explorer: search and filters over the results tables.
//
// `explorer` is embedded verbatim in the downloadable report (via Function.prototype.toString),
// so it must be self-contained: no imports, no references to anything outside its own body,
// and nothing newer than what a corporate browser from a few years back understands.
// The helpers below it run only on the page and may use the rest of the app.

export function explorer(root) {
  var bar = root.querySelector('.explorer');
  if (!bar) return;
  var search = bar.querySelector('.x-search');
  var chips = Array.prototype.slice.call(bar.querySelectorAll('.x-chip'));
  var count = bar.querySelector('.x-count');
  var clear = bar.querySelector('.x-clear');
  var bodies = Array.prototype.slice.call(root.querySelectorAll('tbody[data-explore]'));
  var rows = [];
  bodies.forEach(function (b) {
    Array.prototype.slice.call(b.querySelectorAll('tr[data-status]')).forEach(function (r) { rows.push(r); });
  });

  function matchesOne(r, key, value) {
    var v = r.getAttribute('data-' + key) || '';
    return v === value;
  }

  // Chip counts reflect the whole result set, so a reader can see what a filter would show.
  chips.forEach(function (c) {
    var key = c.getAttribute('data-key'), value = c.getAttribute('data-value');
    var n = rows.filter(function (r) { return matchesOne(r, key, value); }).length;
    var tag = c.querySelector('.x-n');
    if (tag) tag.textContent = String(n);
    if (!n) c.setAttribute('disabled', '');
  });

  function active(key) {
    return chips.filter(function (c) { return c.getAttribute('data-key') === key && c.classList.contains('on'); })
      .map(function (c) { return c.getAttribute('data-value'); });
  }

  function apply() {
    var q = (search ? search.value : '').trim().toLowerCase();
    var keys = ['status', 'sev', 'area', 'changed'];
    var sel = {};
    keys.forEach(function (k) { sel[k] = active(k); });
    var shown = 0;
    rows.forEach(function (r) {
      var ok = true;
      keys.forEach(function (k) {
        if (!ok || !sel[k].length) return;
        ok = sel[k].some(function (v) { return matchesOne(r, k, v); });
      });
      if (ok && q) ok = (r.getAttribute('data-text') || '').indexOf(q) !== -1;
      if (ok) { r.removeAttribute('hidden'); shown++; } else { r.setAttribute('hidden', ''); }
    });
    bodies.forEach(function (b) {
      var empty = b.querySelector('tr.x-empty');
      var any = Array.prototype.slice.call(b.querySelectorAll('tr[data-status]')).some(function (r) { return !r.hasAttribute('hidden'); });
      if (!any && !empty) {
        empty = b.ownerDocument.createElement('tr');
        empty.className = 'x-empty';
        var cols = b.parentNode.querySelectorAll('thead th').length || 5;
        empty.innerHTML = '<td colspan="' + cols + '">No findings match the current filters.</td>';
        b.appendChild(empty);
      } else if (any && empty) {
        b.removeChild(empty);
      }
    });
    if (count) count.textContent = shown === rows.length ? 'All ' + rows.length + ' findings' : shown + ' of ' + rows.length + ' findings';
    var filtering = q || keys.some(function (k) { return sel[k].length; });
    if (clear) { if (filtering) clear.removeAttribute('hidden'); else clear.setAttribute('hidden', ''); }
  }

  chips.forEach(function (c) {
    c.addEventListener('click', function () {
      if (c.hasAttribute('disabled')) return;
      c.classList.toggle('on');
      c.setAttribute('aria-pressed', c.classList.contains('on') ? 'true' : 'false');
      apply();
    });
  });
  if (search) search.addEventListener('input', apply);
  if (clear) clear.addEventListener('click', function () {
    if (search) search.value = '';
    chips.forEach(function (c) { c.classList.remove('on'); c.setAttribute('aria-pressed', 'false'); });
    apply();
  });
  // "/" jumps to the search box, as on most review tools.
  if (!root.__explorerKeys) {
    root.__explorerKeys = true;
    root.ownerDocument.addEventListener('keydown', function (e) {
      var t = e.target && e.target.tagName;
      if (e.key === '/' && t !== 'INPUT' && t !== 'TEXTAREA' && search && search.offsetParent !== null) {
        e.preventDefault(); search.focus();
      }
    });
  }
  apply();
}

// ---------------------------------------------------------------------------------------
// Page-side helpers (not embedded)
// ---------------------------------------------------------------------------------------
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, c =>
  ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

// Which drift bucket a result landed in, if any.
export function changeOf(r, drift) {
  if (!drift) return '';
  if (drift.regressed.some(x => x.id === r.id)) return 'regressed';
  if (drift.fixed.some(x => x.id === r.id)) return 'fixed';
  if (drift.added.some(x => x.id === r.id)) return 'new';
  if (drift.changed.some(x => x.id === r.id)) return 'changed';
  return '';
}

// data-* attributes the explorer filters on. `controls` is the text of the controls column so
// a search for a control ID finds the check.
export function rowAttrs(r, report, controls = '') {
  const text = [r.id, r.name, r.detail, r.category, r.status, r.severity, controls,
    r.remediation?.portal, r.remediation?.powershell].filter(Boolean).join(' ').toLowerCase();
  return `data-status="${esc(r.status.toLowerCase())}" data-sev="${esc(String(r.severity).toLowerCase())}" ` +
    `data-area="${esc(r.area || '')}" data-changed="${esc(changeOf(r, report.drift))}" data-text="${esc(text)}"`;
}

const chip = (key, value, label, cls = '') =>
  `<button type="button" class="x-chip ${cls}" data-key="${esc(key)}" data-value="${esc(value)}" aria-pressed="false">${esc(label)} <span class="x-n"></span></button>`;

export function explorerToolbar(report) {
  const areas = report.areas || [];
  return `
  <div class="explorer" role="search">
    <div class="x-row">
      <input class="x-search" type="search" placeholder="Search checks, details, controls…  (press / to focus)" aria-label="Search findings">
      <span class="x-count"></span>
      <button type="button" class="x-clear" hidden>Clear filters</button>
    </div>
    <div class="x-row"><span class="x-label">Status</span>
      ${chip('status', 'fail', 'Fail', 'c-fail')}${chip('status', 'warning', 'Partial', 'c-warning')}${chip('status', 'unknown', 'Unknown', 'c-unknown')}${chip('status', 'notapplicable', 'N/A', 'c-na')}${chip('status', 'pass', 'Pass', 'c-pass')}
    </div>
    <div class="x-row"><span class="x-label">Severity</span>
      ${chip('sev', 'critical', 'Critical', 'c-critical')}${chip('sev', 'high', 'High', 'c-high')}${chip('sev', 'medium', 'Medium', 'c-medium')}${chip('sev', 'low', 'Low', 'c-low')}
    </div>
    ${areas.length > 1 ? `<div class="x-row"><span class="x-label">Area</span>${areas.map(a => chip('area', a.id, a.label)).join('')}</div>` : ''}
    ${report.drift ? `<div class="x-row"><span class="x-label">Since last run</span>${chip('changed', 'regressed', 'Regressed', 'c-fail')}${chip('changed', 'fixed', 'Fixed', 'c-pass')}${chip('changed', 'changed', 'Detail changed', 'c-warning')}${chip('changed', 'new', 'New', 'c-unknown')}</div>` : ''}
  </div>`;
}

// Shared styles for the toolbar, used on the page and inlined into the report.
export const EXPLORER_CSS = `
.explorer{background:#fff;border:1px solid #dfe4ea;border-radius:3px;padding:12px 14px;margin:12px 0 10px}
.x-row{display:flex;flex-wrap:wrap;align-items:center;gap:6px;margin:4px 0}
.x-label{font-size:11px;letter-spacing:.06em;text-transform:uppercase;color:#5a6a7d;min-width:96px}
.x-search{flex:1 1 260px;font:inherit;font-size:13px;padding:7px 10px;border:1px solid #c9d1db;border-radius:3px;background:#fff;color:inherit}
.x-count{font-size:12px;color:#5a6a7d;white-space:nowrap}
.x-clear{font:inherit;font-size:12px;padding:5px 10px;border:1px solid #c9d1db;border-radius:3px;background:#f3f5f7;cursor:pointer;color:inherit}
.x-chip{font:inherit;font-size:12px;padding:3px 10px;border-radius:11px;border:1px solid #c9d1db;background:#f7f8fa;cursor:pointer;color:#0d1b2a;line-height:1.5}
.x-chip .x-n{opacity:.6;font-size:11px}
.x-chip[disabled]{opacity:.4;cursor:default}
.x-chip.on{border-color:transparent;font-weight:600;background:#0d1b2a;color:#fff}
.x-chip.on.c-fail,.x-chip.on.c-high{background:#fde2e2;color:#8c1d1d}.x-chip.on.c-critical{background:#4a0d18;color:#fff}
.x-chip.on.c-warning,.x-chip.on.c-medium{background:#fff3d6;color:#7a4f00}.x-chip.on.c-low{background:#e6eef7;color:#274b6d}
.x-chip.on.c-pass{background:#e5f5ee;color:#146c55}.x-chip.on.c-unknown,.x-chip.on.c-na{background:#eceff3;color:#5a6a7d}
tr.x-empty td{color:#5a6a7d;font-style:italic;text-align:center;padding:18px}
tr[hidden]{display:none}
@media print{.explorer{display:none}}`;
