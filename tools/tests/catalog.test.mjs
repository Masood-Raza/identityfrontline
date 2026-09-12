// Catalog contract. checks.js decides which checks exist; checks.json (generated from the
// M365-Assess registry) supplies their metadata. These must never drift, and the page must
// never hard-code what the catalog provides.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const cat = JSON.parse(readFileSync(join(root, 'assets/catalog/checks.json'), 'utf8'));
const html = readFileSync(join(root, 'assessments.html'), 'utf8');
const { CHECKS, CHECK_IDS, SOURCES } = await import('../../assets/app/checks.js');
const { REQUIRED_SCOPES } = await import('../../assets/app/engine.js');

let fail = 0;
const ok = (name, cond, extra = '') => {
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${name}${!cond && extra ? ' -> ' + extra : ''}`);
  if (!cond) fail++;
};

// ---- checks.js <-> checks.json ---------------------------------------------------------------
const catIds = cat.checks.map(c => c.id);
ok('every implemented check has catalog metadata',
  CHECK_IDS.every(id => catIds.includes(id)), CHECK_IDS.filter(id => !catIds.includes(id)).join(', '));
ok('catalog carries no orphaned checks',
  catIds.every(id => CHECK_IDS.includes(id)), catIds.filter(id => !CHECK_IDS.includes(id)).join(', '));
ok('no duplicate check IDs', new Set(CHECK_IDS).size === CHECK_IDS.length);
ok('catalog count matches', cat.counts.implemented === CHECK_IDS.length);

// ---- metadata quality --------------------------------------------------------------------
ok('every check has a name', cat.checks.every(c => c.name && c.name.length > 10));
ok('every check has a valid severity',
  cat.checks.every(c => ['Critical', 'High', 'Medium', 'Low'].includes(c.severity)),
  cat.checks.filter(c => !['Critical', 'High', 'Medium', 'Low'].includes(c.severity)).map(c => `${c.id}=${c.severity}`).join(', '));
ok('every check has a rationale', cat.checks.every(c => c.rationale));
ok('every check maps to at least one framework', cat.checks.every(c => Object.keys(c.frameworks).length > 0),
  cat.checks.filter(c => !Object.keys(c.frameworks).length).map(c => c.id).join(', '));
ok('every framework mapping has a control ID',
  cat.checks.every(c => Object.values(c.frameworks).every(m => m.controlId && m.label)));
// Upstream has no remediation text for a handful of count-style checks; three quarters is the floor.
ok('three quarters of checks carry a remediation path',
  cat.checks.filter(c => c.remediation?.portal || c.remediation?.powershell).length >= cat.checks.length * 0.75);
ok('provenance recorded (git ref + registry version)',
  /^[0-9a-f]{40}$/.test(cat.source.ref) && cat.source.registry.dataVersion, cat.source.ref);
ok('MIT attribution recorded', cat.source.license === 'MIT');

// ---- check definitions -------------------------------------------------------------------
ok('every check declares data needs', CHECKS.every(c => Array.isArray(c.needs) && c.needs.length));
// A need prefixed with ? is optional; the source name follows.
const needName = (n) => n.replace(/^\?/, '');
ok('every need resolves to a source', CHECKS.every(c => c.needs.every(n => SOURCES[needName(n)])),
  [...new Set(CHECKS.flatMap(c => c.needs))].filter(n => !SOURCES[needName(n)]).join(', '));
ok('every check has an evaluate()', CHECKS.every(c => typeof c.evaluate === 'function'));
ok('every source declares scopes', Object.values(SOURCES).every(s => s.scopes?.length));
ok('every source has a user-facing label', Object.values(SOURCES).every(s => s.label));
ok('scopes are all read-only', REQUIRED_SCOPES.every(s => !/\.(Read)?Write|FullControl|AccessAsUser/i.test(s)), REQUIRED_SCOPES.join(', '));
ok('identity scope set is the expected six', REQUIRED_SCOPES.length === 6, REQUIRED_SCOPES.join(', '));
ok('every check belongs to a declared area', CHECKS.every(c => ['identity', 'sharepoint', 'teams', 'forms', 'intune'].includes(c.area)));

// ---- the page hard-codes nothing the catalog provides ------------------------------------
// The versioned labels come from the catalog; prose may still name a framework in passing.
for (const f of Object.values(cat.frameworks).map(f => f.label)) {
  ok(`page does not hard-code framework "${f}"`, !html.includes(f));
}
for (const s of REQUIRED_SCOPES) {
  ok(`page does not hard-code scope ${s}`, !html.includes(s));
}

// ---- hosting: IIS returns 404 for any extension without a MIME mapping -------------------
const webConfig = readFileSync(join(root, 'web.config'), 'utf8');
ok('web.config maps .json for IIS', /fileExtension="\.json" mimeType="application\/json/.test(webConfig));
ok('web.config maps .js for IIS', /fileExtension="\.js" mimeType="text\/javascript/.test(webConfig));

console.log(`\n${fail === 0 ? 'all catalog checks passed' : fail + ' FAILED'}`);
process.exit(fail ? 1 : 0);
