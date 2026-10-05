// Deep-link test: a page (the Zero Trust landing page) can send a visitor straight into the
// wizard with specific areas preselected via ?areas=a,b on the assessments.html URL.
import { JSDOM } from 'jsdom';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { HARDENED, mockFetch, DNS_HARDENED } from './fixtures.mjs';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const html = readFileSync(join(root, 'assessments.html'), 'utf8');
const checksJson = readFileSync(join(root, 'assets/catalog/checks.json'), 'utf8');

let fail = 0;
const ok = (name, cond, extra = '') => {
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${name}${!cond && extra ? ' -> ' + extra : ''}`);
  if (!cond) fail++;
};

// Each call imports a fresh instance of main.js (the query string busts Node's ESM module
// cache), so every boot gets its own module-level `state` rather than reusing one left over
// from a previous URL.
async function bootAt(url) {
  const dom = new JSDOM(html, { url, pretendToBeVisual: true });
  const { window } = dom;
  window.scrollTo = () => {};
  window.__IFFL_MANUAL_INIT = true;
  globalThis.window = window;
  globalThis.document = window.document;
  globalThis.HTMLElement = window.HTMLElement;

  const graph = mockFetch(HARDENED, { dns: DNS_HARDENED });
  globalThis.fetch = async (u, opts) => {
    if (opts?.method === 'HEAD') return { ok: true, status: 200, headers: { get: () => null } };
    if (String(u).includes('checks.json')) return { ok: true, status: 200, json: async () => JSON.parse(checksJson) };
    if (String(u).includes('app-tiers.json')) return { ok: true, status: 200, json: async () => JSON.parse(readFileSync(join(root, 'assets/catalog/app-tiers.json'), 'utf8')) };
    return graph(u, opts);
  };

  const main = await import(`../../assets/app/main.js?t=${encodeURIComponent(url)}`);
  await main.init();
  await new Promise(r => setTimeout(r, 0));
  return { window, main };
}

{
  const { main } = await bootAt('http://localhost:8080/assessments.html?areas=privileged,identity');
  ok('deep-linked areas are preselected', [...main.getState().areas].sort().join() === 'identity,privileged',
    [...main.getState().areas].join());
}
{
  const { main } = await bootAt('http://localhost:8080/assessments.html?areas=not-a-real-area,also-fake');
  ok('an areas param with no valid ids falls back to the default', [...main.getState().areas].join() === 'identity',
    [...main.getState().areas].join());
}
{
  const { main } = await bootAt('http://localhost:8080/assessments.html');
  ok('no areas param: default is unchanged', [...main.getState().areas].join() === 'identity');
}
{
  const { main } = await bootAt('http://localhost:8080/assessments.html?areas=privileged,bogus');
  ok('a mix of valid and invalid ids keeps only the valid ones', [...main.getState().areas].join() === 'privileged',
    [...main.getState().areas].join());
}

console.log(`\n${fail === 0 ? 'all deep-link checks passed' : fail + ' FAILED'}`);
process.exit(fail ? 1 : 0);
