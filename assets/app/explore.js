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
    var keys = ['status', 'sev', 'area', 'changed', 'effort'];
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
    var ev; try { ev = new root.ownerDocument.defaultView.Event('x-apply'); } catch (e) { ev = root.ownerDocument.createEvent('Event'); ev.initEvent('x-apply', false, false); }
    bar.dispatchEvent(ev);
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
  // Area cards double as filters: clicking one toggles that area's chip.
  Array.prototype.slice.call(root.querySelectorAll('[data-area-card]')).forEach(function (card) {
    card.addEventListener('click', function () {
      var chip = bar.querySelector('.x-chip[data-key="area"][data-value="' + card.getAttribute('data-area-card') + '"]');
      if (chip) chip.click();
    });
  });
  bar.addEventListener('x-apply', function () {
    Array.prototype.slice.call(root.querySelectorAll('[data-area-card]')).forEach(function (card) {
      var chip = bar.querySelector('.x-chip[data-key="area"][data-value="' + card.getAttribute('data-area-card') + '"]');
      if (chip) card.classList.toggle('on', chip.classList.contains('on'));
    });
  });

  // Copy as ticket: the Markdown lives on the button so it works with no app around it.
  function copyText(text, done) {
    var nav = root.ownerDocument.defaultView && root.ownerDocument.defaultView.navigator;
    if (nav && nav.clipboard && nav.clipboard.writeText) {
      nav.clipboard.writeText(text).then(function () { done(true); }, function () { done(fallback(text)); });
    } else {
      done(fallback(text));
    }
  }
  function fallback(text) {
    var doc = root.ownerDocument, ta = doc.createElement('textarea');
    ta.value = text; ta.setAttribute('readonly', ''); ta.style.position = 'fixed'; ta.style.left = '-9999px';
    doc.body.appendChild(ta); ta.select();
    var ok = false;
    try { ok = doc.execCommand && doc.execCommand('copy'); } catch (e) { ok = false; }
    doc.body.removeChild(ta);
    return ok;
  }
  Array.prototype.slice.call(root.querySelectorAll('.x-copy[data-ticket]')).forEach(function (btn) {
    btn.addEventListener('click', function () {
      var was = btn.textContent;
      copyText(btn.getAttribute('data-ticket'), function (ok) {
        btn.textContent = ok ? 'Copied' : 'Copy failed';
        btn.classList.toggle('done', ok);
        setTimeout(function () { btn.textContent = was; btn.classList.remove('done'); }, 1600);
      });
    });
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

// reportChrome wires up everything around the findings tables that is new in this layout:
// the theme toggle and print button (report only — the live page has neither), the sidebar's
// scrollspy, the framework picker's detail panel, and the critical-findings banner's "jump to
// filtered findings" links. Like explorer(), it is embedded verbatim via toString(), so it
// stays self-contained and tolerates running on the live page too, where most of these
// elements simply do not exist — every lookup is guarded.
export function reportChrome(root) {
  var doc = root.ownerDocument;
  var win = (doc.defaultView || window);
  var docEl = doc.documentElement;

  // Theme toggle. Report-only: the live page has its own theme and no [data-theme] attribute.
  // The button's own icon never changes — the whole page re-theming is the feedback — only
  // aria-pressed tracks state, for screen readers.
  var themeBtn = root.querySelector('.rc-theme');
  if (themeBtn) {
    themeBtn.addEventListener('click', function () {
      var goingLight = docEl.getAttribute('data-theme') !== 'light';
      docEl.setAttribute('data-theme', goingLight ? 'light' : 'dark');
      themeBtn.setAttribute('aria-pressed', goingLight ? 'true' : 'false');
    });
  }

  // Print. Report-only; the live page has its own Print / Save as PDF button already wired.
  var printBtn = root.querySelector('.rc-print');
  if (printBtn) printBtn.addEventListener('click', function () { win.print(); });

  // Scrollspy: the sidebar link for whichever section is currently in view gets .active.
  var navLinks = Array.prototype.slice.call(root.querySelectorAll('.rc-nav a[href^="#"]'));
  if (navLinks.length && 'IntersectionObserver' in win) {
    var byId = {};
    var sections = [];
    navLinks.forEach(function (a) {
      var id = a.getAttribute('href').slice(1);
      var el = doc.getElementById(id);
      if (el) { byId[id] = a; sections.push(el); }
    });
    var obs = new win.IntersectionObserver(function (entries) {
      entries.forEach(function (en) {
        if (!en.isIntersecting) return;
        navLinks.forEach(function (a) { a.classList.remove('active'); });
        var link = byId[en.target.id];
        if (link) link.classList.add('active');
      });
    }, { rootMargin: '-15% 0px -75% 0px' });
    sections.forEach(function (el) { obs.observe(el); });
  }

  // Framework picker: swap the detail panel's numbers when the selection changes. The stats
  // are pre-computed server-side (in the sense that this whole page was generated once, in the
  // browser, at report time) and shipped as a JSON data island, so no recomputation is needed.
  var fwSelect = root.querySelector('.rc-fw-select');
  if (fwSelect) {
    var dataEl = root.querySelector('.rc-fw-data');
    var stats = {};
    try { stats = JSON.parse(dataEl ? dataEl.textContent : '{}'); } catch (e) { stats = {}; }
    var panel = root.querySelector('.fw-panel');
    var renderFw = function (id) {
      var st = stats[id];
      if (!panel || !st) return;
      panel.innerHTML = '';
      var title = doc.createElement('b'); title.textContent = st.label; panel.appendChild(title);
      var rate = doc.createElement('span'); rate.className = 'fw-rate';
      rate.textContent = (st.passRate === null ? '—' : st.passRate + '%') + ' covered';
      panel.appendChild(rate);
      var bar = doc.createElement('div'); bar.className = 'fw-bar';
      var fill = doc.createElement('i'); fill.style.width = Math.max(0, Math.min(100, st.passRate || 0)) + '%';
      bar.appendChild(fill); panel.appendChild(bar);
      var meta = doc.createElement('small');
      meta.textContent = st.gaps + ' gap' + (st.gaps === 1 ? '' : 's') + ' of ' + st.checks + ' checks assessed';
      panel.appendChild(meta);
    };
    renderFw(fwSelect.value);
    fwSelect.addEventListener('change', function () { renderFw(fwSelect.value); });
  }

  // Jump links (the critical-findings banner, sidebar counts) also drive the explorer's own
  // filter chips, so "Review critical findings" both scrolls there and filters to them. This
  // must run after explorer() has attached the chips' own click listeners.
  Array.prototype.slice.call(root.querySelectorAll('[data-jump]')).forEach(function (a) {
    a.addEventListener('click', function () {
      var spec = a.getAttribute('data-jump');
      if (!spec) return;
      spec.split(',').forEach(function (pair) {
        var kv = pair.split(':');
        var chip = root.querySelector('.x-chip[data-key="' + kv[0] + '"][data-value="' + kv[1] + '"]');
        if (chip && !chip.classList.contains('on')) chip.click();
      });
    });
  });

  // A mobile sidebar is a <details> disclosure; close it once a link has been followed.
  var navToggle = root.querySelector('details.rc-nav-toggle');
  if (navToggle) {
    navLinks.forEach(function (a) { a.addEventListener('click', function () { navToggle.removeAttribute('open'); }); });
  }
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
    `data-area="${esc(r.area || '')}" data-effort="${esc(r.effort || '')}" data-changed="${esc(changeOf(r, report.drift))}" data-text="${esc(text)}"`;
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
    <div class="x-row"><span class="x-label">Effort</span>${chip('effort', 'quick', 'Quick win', 'c-pass')}${chip('effort', 'moderate', 'Moderate', 'c-low')}${chip('effort', 'review', 'Review with owners', 'c-warning')}${chip('effort', 'project', 'Project', 'c-unknown')}</div>
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
.effort{display:inline-block;font-size:10px;padding:1px 7px;border-radius:9px;margin-top:5px;white-space:nowrap;background:#eceff3;color:#5a6a7d}
.effort.quick{background:#e5f5ee;color:#146c55}.effort.moderate{background:#e6eef7;color:#274b6d}.effort.review{background:#fff3d6;color:#7a4f00}
.x-copy{font:inherit;font-size:11px;padding:2px 8px;border:1px solid #c9d1db;border-radius:3px;background:#fff;color:#274b6d;cursor:pointer;margin-top:7px}
.x-copy.done{background:#e5f5ee;border-color:#9fd3bd;color:#146c55}
.area-cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:10px;margin:14px 0 4px}
.area-card{background:#fff;border:1px solid #dfe4ea;border-radius:4px;padding:14px 15px;cursor:pointer;text-align:left;font:inherit;color:inherit;transition:border-color .12s,box-shadow .12s}
.area-card:hover{border-color:#b8c0cc}
.area-card b{display:block;font-size:24px;line-height:1.1;font-variant-numeric:tabular-nums}.area-card span{font-size:12.5px;color:#5a6a7d;display:block;font-weight:600}.area-card small{font-size:11px;color:#5a6a7d}
.area-card.on{border-color:#0d1b2a;box-shadow:inset 0 0 0 1px #0d1b2a}
.area-card .bar{height:5px;background:#eceff3;border-radius:2px;margin:9px 0 7px;overflow:hidden;display:flex}
.area-card .bar i{display:block;height:100%}
.area-card .bar i.seg-pass{background:#146c55}.area-card .bar i.seg-warn{background:#c98a00}.area-card .bar i.seg-fail{background:#b0263d}
@media print{.x-copy{display:none}}
tr[hidden]{display:none}
@media print{.explorer{display:none}}`;

// Styles for the hero score, stat tiles, critical-findings banner and framework picker.
// Shared between the live results page and the downloadable report, so every color here is a
// literal value rather than var(--x): the two documents carry different theme variables (the
// report's own dark override lives in report.js, scoped to [data-theme="dark"], and does not
// touch this file), and this stylesheet must read correctly against either one unstyled.
export const REPORT_CSS = `
.hero{display:flex;flex-wrap:wrap;gap:22px;align-items:stretch;margin:18px 0 16px}
.hero-score{flex:0 0 220px;background:#fff;border:1px solid #dfe4ea;border-radius:5px;padding:20px 22px;display:flex;flex-direction:column;justify-content:center}
.hero-label{font-size:11px;letter-spacing:.06em;text-transform:uppercase;color:#5a6a7d;font-weight:600}
.hero-score b{font-size:44px;line-height:1.05;margin:4px 0 10px;font-variant-numeric:tabular-nums}
.hero-bar{height:7px;background:#eceff3;border-radius:4px;overflow:hidden;margin-bottom:10px}
.hero-bar i{display:block;height:100%;background:linear-gradient(90deg,#8b0055,#c9366e)}
.hero-sub{font-size:12.5px;color:#5a6a7d;line-height:1.5}
.hero-delta{display:inline-block;margin-left:2px;font-weight:600}
.hero-delta.up{color:#146c55}.hero-delta.down{color:#b0263d}
.hero-tiles{flex:1 1 320px;display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:12px}
.tile{border:1px solid #dfe4ea;border-radius:5px;padding:14px 16px;background:#fff;border-left-width:4px}
.tile b{display:block;font-size:28px;line-height:1.05;font-variant-numeric:tabular-nums}
.tile span{display:block;font-size:12.5px;font-weight:600;margin-top:3px}
.tile small{display:block;font-size:11px;color:#5a6a7d;margin-top:2px}
.tile-critical{border-left-color:#4a0d18}.tile-critical b{color:#4a0d18}
.tile-fail{border-left-color:#b0263d}.tile-fail b{color:#b0263d}
.tile-warning{border-left-color:#c98a00}.tile-warning b{color:#c98a00}
.tile-pass{border-left-color:#146c55}.tile-pass b{color:#146c55}
.alert-banner{background:#3a0a14;color:#fde2e2;border-radius:5px;padding:14px 18px;margin:0 0 18px;font-size:13.5px;line-height:1.6}
.alert-banner b{color:#fff}
.alert-banner a{color:#ffb4c4;font-weight:600;text-decoration:none;white-space:nowrap;margin-left:4px}
.alert-banner a:hover{text-decoration:underline}
.fw-picker{background:#fff;border:1px solid #dfe4ea;border-radius:5px;padding:16px 18px;margin:14px 0 18px;display:flex;flex-wrap:wrap;gap:20px;align-items:center}
.fw-select-label{font-size:11px;letter-spacing:.06em;text-transform:uppercase;color:#5a6a7d;font-weight:600;display:flex;flex-direction:column;gap:6px}
.fw-select-label select{font:13px/1.4 inherit;padding:7px 9px;border:1px solid #c9d1db;border-radius:3px;background:#fff;color:#0d1b2a;text-transform:none;letter-spacing:normal}
.fw-panel{flex:1 1 220px;min-width:200px}
.fw-panel b{display:block;font-size:14px;margin-bottom:4px}
.fw-rate{font-size:12.5px;color:#5a6a7d}
.fw-bar{height:6px;background:#eceff3;border-radius:3px;overflow:hidden;margin:7px 0}
.fw-bar i{display:block;height:100%;background:#146c55}
.fw-panel small{font-size:11.5px;color:#5a6a7d}
@media print{.alert-banner{background:#fde2e2;color:#4a0d18;border:1px solid #b0263d}.alert-banner a{display:none}.fw-picker{break-inside:avoid}}
`;
