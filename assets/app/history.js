// Identity Frontline — run history and drift.
//
// Every completed run is remembered in this browser's localStorage, keyed by tenant, so the
// next run can say what changed. Only what drift needs is stored: check id, status, severity
// and the one-line detail. No token, no raw Graph data, and nothing is sent anywhere.
//
// Storage can be unavailable (private windows, blocked site data) or full; every call is
// guarded so history never breaks a run.

const PREFIX = 'iffl:runs:';
const MAX_RUNS = 12;

const tenantKey = (tenant) =>
  String(tenant?.id || tenant?.name || 'unknown').trim().toLowerCase();

let store = null;
export function useStorage(s) { store = s; }              // tests inject a fake
const storage = () => store || (typeof localStorage !== 'undefined' ? localStorage : null);

function read(key) {
  try { const raw = storage()?.getItem(PREFIX + key); return raw ? JSON.parse(raw) : []; }
  catch { return []; }
}
function write(key, runs) {
  try { storage()?.setItem(PREFIX + key, JSON.stringify(runs)); return true; }
  catch { return false; }
}

// A compact snapshot of a report: enough to diff, small enough to keep a dozen of.
export function snapshot(report) {
  return {
    started: report.started,
    areas: (report.areas || []).map(a => a.id),
    frameworkFilter: report.frameworkFilter || [],
    passRate: report.summaryAll?.passRate ?? report.summary?.passRate ?? null,
    results: report.results.map(r => ({ id: r.id, status: r.status, severity: r.severity, detail: r.detail }))
  };
}

export function list(tenant) {
  return read(tenantKey(tenant));
}

export function latest(tenant) {
  const runs = read(tenantKey(tenant));
  return runs.length ? runs[runs.length - 1] : null;
}

export function save(report) {
  const key = tenantKey(report.tenant);
  const runs = read(key);
  runs.push(snapshot(report));
  while (runs.length > MAX_RUNS) runs.shift();
  return write(key, runs);
}

export function forget(tenant) {
  try { storage()?.removeItem(PREFIX + tenantKey(tenant)); return true; }
  catch { return false; }
}

const isBad = (s) => s === 'Fail' || s === 'Warning';

// Compare a fresh report with a stored snapshot. Checks only in the new run are "new" (an area
// was added); checks only in the old run are counted but not judged (an area was dropped).
export function diff(report, previous) {
  if (!previous) return null;
  const before = new Map(previous.results.map(r => [r.id, r]));
  const fixed = [], regressed = [], changed = [], added = [];
  let unchanged = 0;

  for (const r of report.results) {
    const p = before.get(r.id);
    if (!p) { added.push(r); continue; }
    if (p.status === r.status) {
      if (p.detail !== r.detail && isBad(r.status)) changed.push({ ...r, previousDetail: p.detail });
      else unchanged++;
      continue;
    }
    if (isBad(p.status) && r.status === 'Pass') fixed.push({ ...r, previousStatus: p.status });
    else if (p.status === 'Pass' && isBad(r.status)) regressed.push({ ...r, previousStatus: p.status });
    else if (p.status === 'Fail' && r.status === 'Warning') fixed.push({ ...r, previousStatus: p.status, partial: true });
    else if (p.status === 'Warning' && r.status === 'Fail') regressed.push({ ...r, previousStatus: p.status });
    else changed.push({ ...r, previousStatus: p.status, previousDetail: p.detail });
  }
  const dropped = previous.results.filter(p => !report.results.some(r => r.id === p.id)).length;
  const now = report.summaryAll?.passRate ?? report.summary?.passRate ?? null;

  return {
    previousStarted: previous.started,
    previousPassRate: previous.passRate,
    passRate: now,
    delta: (now !== null && previous.passRate !== null) ? now - previous.passRate : null,
    fixed, regressed, changed, added, dropped, unchanged
  };
}

export const statusOf = (r) => ({ id: r.id, status: r.status });
