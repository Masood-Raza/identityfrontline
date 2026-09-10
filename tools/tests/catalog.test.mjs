import { readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { execFileSync } from 'node:child_process';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const html = readFileSync(`${root}/assessments.html`, 'utf8');
const cat = JSON.parse(readFileSync(join(root, 'assets/catalog/catalog.json'), 'utf8'));

let fail = 0;
const ok = (name, cond, extra = '') => {
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${name}${extra && !cond ? ' -> ' + extra : ''}`);
  if (!cond) fail++;
};

// --- 1. the wizard script parses -----------------------------------------------------------
const m = html.match(/<script>([\s\S]*?)<\/script>\s*<\/body>/);
ok('wizard script block found', !!m);
const tmp = join(tmpdir(), '_iffl_extracted.js');
writeFileSync(tmp, m[1]);
try {
  execFileSync('node', ['--check', tmp], { stdio: 'pipe' });
  ok('wizard script parses', true);
} catch (e) {
  ok('wizard script parses', false, String(e.stderr));
}

// --- 2. nothing about frameworks/scopes is hard-coded in the page ---------------------------
const forbidden = ['NIST CSF 2.0', 'Directory.Read.All', 'View-Only Organization Management', 'CIS Microsoft 365'];
for (const f of forbidden) ok(`page does not hard-code "${f}"`, !html.includes(f));

// --- 3. permission union matches the catalog for each wizard path ---------------------------
const scopesFor = sections =>
  cat.permissions.filter(p => p.sections.some(s => sections.includes(s))).map(p => p.name).sort();

const entra = scopesFor(['Tenant', 'Identity']);
const expectedEntra = [
  'Agreement.Read.All', 'Application.Read.All', 'AuditLog.Read.All', 'Directory.Read.All',
  'Domain.Read.All', 'Group.Read.All', 'Organization.Read.All', 'Policy.Read.All',
  'RoleManagement.Read.Directory', 'User.Read.All', 'UserAuthenticationMethod.Read.All'
].sort();
ok('Entra path requests exactly 11 scopes', entra.length === 11, `got ${entra.length}: ${entra}`);
ok('Entra scope set matches upstream Tenant+Identity',
  JSON.stringify(entra) === JSON.stringify(expectedEntra),
  `\n  got:      ${entra}\n  expected: ${expectedEntra}`);

const all = scopesFor(cat.profile.sections);
ok('full profile requests 17 scopes', all.length === 17, `got ${all.length}`);
ok('every profile scope is delegated + read-only',
  cat.permissions.every(p => p.type === 'Delegated' && p.access === 'Read-only'));
ok('no application permission appears anywhere',
  !cat.permissions.some(p => /application/i.test(p.type)));

// --- 4. every scope upstream declares for a profile section is present ----------------------
const declared = new Set();
for (const s of cat.sections.filter(s => s.inProfile)) s.scopes.forEach(x => declared.add(x));
const missing = [...declared].filter(x => !all.includes(x));
ok('catalog covers every upstream scope for profile sections', missing.length === 0, `missing: ${missing}`);

// --- 5. selecting a subset never leaks another section's permissions ------------------------
const intuneOnly = scopesFor(['Intune']);
ok('Intune alone yields only the two device scopes',
  JSON.stringify(intuneOnly) === JSON.stringify(
    ['DeviceManagementConfiguration.Read.All', 'DeviceManagementManagedDevices.Read.All']),
  `got ${intuneOnly}`);
ok('Intune alone does not leak Exchange or Purview', !intuneOnly.some(s => /Mailbox|Security/.test(s)));

// --- 6. excluded sections are disclosed, not silently dropped -------------------------------
const excluded = Object.keys(cat.profile.excluded);
ok('Email/Security/PowerBI are disclosed as excluded',
  ['Email', 'Security', 'PowerBI'].every(s => excluded.includes(s)), `got ${excluded}`);
ok('no excluded section is marked inProfile',
  !cat.sections.some(s => s.inProfile && excluded.includes(s.id)));

// --- 7. the ungranted-scope warning has something to fire on --------------------------------
const ungranted = cat.permissions.filter(p => !p.grantedByUpstreamConsentHelper).map(p => p.name);
ok('Agreement.Read.All flagged as not covered by standard consent',
  ungranted.includes('Agreement.Read.All'), `ungranted: ${ungranted}`);

// --- 8. attribution present ----------------------------------------------------------------
ok('page carries MIT attribution', html.includes('M365-Assess') && html.includes('MIT licensed'));
ok('catalog carries source ref + licence',
  cat.source.license === 'MIT' && /^[0-9a-f]{40}$/.test(cat.source.ref), `ref=${cat.source.ref}`);

console.log(`\n${fail === 0 ? 'all checks passed' : fail + ' FAILED'}`);
process.exit(fail ? 1 : 0);
