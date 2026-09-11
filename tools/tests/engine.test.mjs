// Engine tests. Runs the real check predicates against mock Graph payloads, so the pass/fail
// logic is verified without a tenant. Two fixtures: a hardened tenant and a default one.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const catalog = JSON.parse(readFileSync(join(root, 'assets/catalog/checks.json'), 'utf8'));

let fail = 0;
const ok = (name, cond, extra = '') => {
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${name}${!cond && extra ? ' -> ' + extra : ''}`);
  if (!cond) fail++;
};

import { HARDENED, DEFAULTS, mockFetch } from './fixtures.mjs';

const { runAssessment, REQUIRED_SCOPES } = await import('../../assets/app/engine.js');

const run = async (fixture, opts) => {
  globalThis.fetch = mockFetch(fixture, opts);
  return runAssessment({ token: 'fake', catalog, tenant: { name: 'test' } });
};

// ---- scopes -----------------------------------------------------------------------------
ok('engine requires exactly 6 delegated scopes', REQUIRED_SCOPES.length === 6, REQUIRED_SCOPES.join(', '));
ok('no write scope is ever requested', !REQUIRED_SCOPES.some(s => /Write/i.test(s)), REQUIRED_SCOPES.join(', '));

// ---- hardened tenant --------------------------------------------------------------------
const good = await run(HARDENED);
const gFail = good.results.filter(r => r.status === 'Fail');
ok('hardened tenant: every check evaluated', good.results.length === catalog.checks.length,
  `${good.results.length} of ${catalog.checks.length}`);
ok('hardened tenant: no sources unavailable', good.unavailable.length === 0,
  good.unavailable.map(u => `${u.source}: ${u.reason}`).join('; '));
ok('hardened tenant: no failures', gFail.length === 0, gFail.map(r => `${r.id} (${r.detail})`).join(' | '));
ok('hardened tenant: pass rate is 100%', good.summary.passRate === 100, String(good.summary.passRate));
ok('hardened tenant: nothing left Unknown', good.summary.unknown === 0,
  good.results.filter(r => r.status === 'Unknown').map(r => r.id).join(', '));

// ---- default tenant ---------------------------------------------------------------------
const bad = await run(DEFAULTS);
const bFail = new Set(bad.results.filter(r => r.status === 'Fail').map(r => r.id));
ok('default tenant: pass rate is low', bad.summary.passRate !== null && bad.summary.passRate < 30,
  String(bad.summary.passRate));

for (const id of [
  'ENTRA-SECDEFAULT-001', 'CA-LEGACYAUTH-001', 'CA-MFA-ALL-001', 'ENTRA-CONSENT-001',
  'ENTRA-GUEST-001', 'ENTRA-GUEST-002', 'ENTRA-PASSWORD-001', 'ENTRA-AUTHMETHOD-001',
  'ENTRA-AUTHMETHOD-002', 'ENTRA-CLOUDADMIN-001', 'ENTRA-BREAKGLASS-001',
  'CA-NAMEDLOC-001', 'CA-REPORTONLY-001', 'ENTRA-ADMIN-001'
]) {
  ok(`default tenant flags ${id}`, bFail.has(id));
}
ok('default tenant: 7 synced admins is flagged, not 3',
  bad.results.find(r => r.id === 'ENTRA-ADMIN-001')?.detail.includes('7'));

// ---- degradation ------------------------------------------------------------------------
const denied = await run(HARDENED, { deny: ['/reports/authenticationMethods'] });
const mfaChecks = denied.results.filter(r => ['ENTRA-MFA-001', 'ENTRA-MFA-002'].includes(r.id));
ok('missing permission degrades to Unknown, never Fail',
  mfaChecks.every(r => r.status === 'Unknown'), mfaChecks.map(r => `${r.id}=${r.status}`).join(', '));
ok('the denial reason reaches the result',
  mfaChecks.every(r => /privileges|denied/i.test(r.detail)), mfaChecks.map(r => r.detail).join(' | '));
ok('unavailable source is reported', denied.unavailable.some(u => u.source === 'registrationDetails'));
ok('Unknown is excluded from the pass rate', denied.summary.passRate === 100, String(denied.summary.passRate));
ok('other checks still ran', denied.summary.pass === good.summary.pass - 2,
  `${denied.summary.pass} vs ${good.summary.pass}`);

// ---- security defaults path -------------------------------------------------------------
const sd = await run({ ...DEFAULTS, '/policies/identitySecurityDefaultsEnforcementPolicy': { isEnabled: true } });
ok('security defaults on: baseline check passes',
  sd.results.find(r => r.id === 'ENTRA-SECDEFAULT-001')?.status === 'Pass');
ok('security defaults on: MFA-for-all credited',
  sd.results.find(r => r.id === 'CA-MFA-ALL-001')?.status === 'Pass');
ok('security defaults on: CA gap analysis is NotApplicable',
  sd.results.find(r => r.id === 'ENTRA-SECDEFAULT-002')?.status === 'NotApplicable');

// ---- framework rollup -------------------------------------------------------------------
ok('framework rollup produced', bad.frameworks.length > 0, String(bad.frameworks.length));
ok('rollup names failing controls',
  bad.frameworks.some(f => f.failingControls.length > 0));
ok('rollup sorted worst-first',
  bad.frameworks.every((f, i, a) => i === 0 || (a[i - 1].passRate ?? 101) <= (f.passRate ?? 101)));

// ---- predicate robustness ---------------------------------------------------------------
const empty = await run({
  ...HARDENED,
  '/policies/authenticationMethodsPolicy': {},
  '/identity/conditionalAccess/policies': { value: [] },
  '/directoryRoles': { value: [] }
});
ok('empty payloads never throw', empty.results.length === catalog.checks.length);
ok('empty payloads produce no crash-Unknowns with stack traces',
  !empty.results.some(r => /could not be evaluated \(/.test(r.detail || '')),
  empty.results.filter(r => /could not be evaluated \(/.test(r.detail || '')).map(r => `${r.id}: ${r.detail}`).join(' | '));

console.log(`\n${fail === 0 ? 'all engine checks passed' : fail + ' FAILED'}`);
process.exit(fail ? 1 : 0);
