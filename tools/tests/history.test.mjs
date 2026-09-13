// History and drift. Runs are remembered per tenant in browser storage; the next run says
// what changed. Storage is injected so the tests never touch a real browser.
import * as h from '../../assets/app/history.js';

let fail = 0;
const ok = (name, cond, extra = '') => {
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${name}${!cond && extra ? ' -> ' + extra : ''}`);
  if (!cond) fail++;
};

const fakeStorage = () => { const m = new Map(); return {
  getItem: k => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: k => m.delete(k), size: () => m.size, raw: m
}; };

const report = (tenant, results, passRate, started = '2026-09-01T10:00:00Z', areas = ['identity']) => ({
  tenant, started, areas: areas.map(id => ({ id, label: id })), frameworkFilter: [],
  summaryAll: { passRate }, summary: { passRate },
  results: results.map(([id, status, detail = '', severity = 'High']) => ({ id, status, detail, severity, name: id }))
});

// ---- snapshot is compact and free of tenant data beyond results --------------------------
const s = fakeStorage(); h.useStorage(s);
const r1 = report({ id: 'tid', name: 'contoso' }, [['A', 'Pass'], ['B', 'Fail', 'x'], ['C', 'Warning', 'y'], ['D', 'Unknown']], 50);
const snap = h.snapshot(r1);
ok('snapshot keeps only id/status/severity/detail per result', Object.keys(snap.results[0]).sort().join() === 'detail,id,severity,status');
ok('snapshot carries no token or Graph payload', !JSON.stringify(snap).includes('token') && !('data' in snap));
ok('snapshot records areas and pass rate', snap.areas.join() === 'identity' && snap.passRate === 50);

// ---- save / latest / list / forget --------------------------------------------------------
ok('nothing remembered yet', h.latest(r1.tenant) === null && h.list(r1.tenant).length === 0);
ok('save succeeds', h.save(r1) === true);
ok('latest returns the saved run', h.latest(r1.tenant)?.started === r1.started);
ok('key is per tenant', h.latest({ id: 'other' }) === null);
ok('tenant key falls back to name when no id', (h.save(report({ name: 'Fabrikam' }, [['A', 'Pass']], 100)), h.latest({ name: 'fabrikam' }) !== null));
ok('forget removes the tenant history', (h.forget(r1.tenant), h.latest(r1.tenant) === null));

// ---- history is bounded -------------------------------------------------------------------
for (let i = 0; i < 20; i++) h.save(report({ id: 'cap' }, [['A', 'Pass']], i, `2026-01-${String(i + 1).padStart(2, '0')}T00:00:00Z`));
ok('history keeps at most 12 runs', h.list({ id: 'cap' }).length === 12);
ok('oldest runs are dropped first', h.list({ id: 'cap' })[0].passRate === 8 && h.latest({ id: 'cap' }).passRate === 19);

// ---- diff categories ----------------------------------------------------------------------
const prev = h.snapshot(report({ id: 't' }, [
  ['FIXED', 'Fail', 'was bad'], ['REGRESSED', 'Pass'], ['SAME', 'Pass'], ['SAMEBAD', 'Fail', 'still bad'],
  ['DETAIL', 'Fail', '5 admins'], ['DROPPED', 'Pass'], ['PARTIAL', 'Fail'], ['WORSE', 'Warning'], ['UNK', 'Unknown']
], 40));
const now = report({ id: 't' }, [
  ['FIXED', 'Pass'], ['REGRESSED', 'Fail', 'broke'], ['SAME', 'Pass'], ['SAMEBAD', 'Fail', 'still bad'],
  ['DETAIL', 'Fail', '7 admins'], ['NEW', 'Fail'], ['PARTIAL', 'Warning'], ['WORSE', 'Fail'], ['UNK', 'Pass']
], 55, '2026-09-02T10:00:00Z');
const d = h.diff(now, prev);
ok('diff against nothing is null', h.diff(now, null) === null);
ok('fixed: Fail -> Pass', d.fixed.some(r => r.id === 'FIXED' && r.previousStatus === 'Fail'));
ok('fixed (partial): Fail -> Warning is progress', d.fixed.some(r => r.id === 'PARTIAL' && r.partial));
ok('regressed: Pass -> Fail', d.regressed.some(r => r.id === 'REGRESSED' && r.previousStatus === 'Pass'));
ok('regressed: Warning -> Fail', d.regressed.some(r => r.id === 'WORSE'));
ok('detail changed while still failing is its own bucket', d.changed.some(r => r.id === 'DETAIL' && r.previousDetail === '5 admins'));
ok('unchanged pass is not listed', !d.fixed.concat(d.regressed, d.changed, d.added).some(r => r.id === 'SAME'));
ok('unchanged failure with same detail is not listed', !d.changed.some(r => r.id === 'SAMEBAD'));
ok('Unknown -> Pass is a change, not a fix', d.changed.some(r => r.id === 'UNK') && !d.fixed.some(r => r.id === 'UNK'));
ok('new checks are added, not regressed', d.added.some(r => r.id === 'NEW') && !d.regressed.some(r => r.id === 'NEW'));
ok('checks no longer assessed are counted as dropped', d.dropped === 1);
ok('pass rate delta computed', d.delta === 15 && d.previousPassRate === 40 && d.passRate === 55);
ok('unchanged count is right', d.unchanged === 2, String(d.unchanged));

// ---- storage failures never break a run ---------------------------------------------------
h.useStorage({ getItem: () => { throw new Error('blocked'); }, setItem: () => { throw new Error('blocked'); }, removeItem: () => { throw new Error('blocked'); } });
ok('blocked storage: latest is null, not a throw', h.latest({ id: 'x' }) === null);
ok('blocked storage: save reports false, not a throw', h.save(r1) === false);
ok('blocked storage: forget reports false, not a throw', h.forget({ id: 'x' }) === false);
h.useStorage(null);
ok('no storage at all: latest is null', h.latest({ id: 'x' }) === null);

console.log(`\n${fail === 0 ? 'all history checks passed' : fail + ' FAILED'}`);
process.exit(fail ? 1 : 0);
