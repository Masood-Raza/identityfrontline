// Identity Frontline — assessment engine.
//
// Fetches each Graph source once, then runs every check against the shared result. Runs
// entirely in the browser: tenant data goes Microsoft -> this page and nowhere else.
//
// Failure handling mirrors the upstream status model. A source that cannot be read (missing
// consent, unlicensed feature, transient error) is recorded as unavailable, and every check
// depending on it reports Unknown with the reason. Unknown and NotApplicable are excluded
// from the pass rate rather than counted as failures, so a partial run is still honest.

import { CHECKS, SOURCES, unknown } from './checks.js';

const GRAPH = 'https://graph.microsoft.com/v1.0';
const ROLE_GLOBAL_ADMIN = '62e90394-69f5-4237-9190-012177145e10';
const MAX_RETRIES = 4;

const sleep = ms => new Promise(r => setTimeout(r, ms));

class GraphError extends Error {
  constructor(message, status) { super(message); this.status = status; }
}

// ---------------------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------------------
async function graphFetch(token, url, { raw = false } = {}) {
  const full = url.startsWith('http') ? url : GRAPH + url;

  for (let attempt = 0; ; attempt++) {
    const res = await fetch(full, {
      headers: {
        Authorization: `Bearer ${token}`,
        // Required for $count and advanced query support.
        ConsistencyLevel: 'eventual'
      }
    });

    // Respect Graph throttling rather than hammering it.
    if ((res.status === 429 || res.status === 503) && attempt < MAX_RETRIES) {
      const retryAfter = parseInt(res.headers.get('Retry-After') || '', 10);
      const wait = Number.isFinite(retryAfter) ? retryAfter * 1000 : Math.min(2 ** attempt * 1000, 16000);
      await sleep(wait);
      continue;
    }

    if (!res.ok) {
      let detail = `HTTP ${res.status}`;
      try {
        const body = await res.json();
        if (body?.error?.message) detail = body.error.message;
      } catch { /* non-JSON error body */ }

      if (res.status === 403 || res.status === 401) {
        throw new GraphError(`Access denied. ${detail}`, res.status);
      }
      if (res.status === 404) {
        throw new GraphError(`Not available in this tenant. ${detail}`, 404);
      }
      throw new GraphError(detail, res.status);
    }

    return raw ? (await res.text()) : (await res.json());
  }
}

async function graphAll(token, url) {
  const items = [];
  let next = url;
  let pages = 0;
  while (next && pages < 50) {
    const page = await graphFetch(token, next);
    if (Array.isArray(page.value)) items.push(...page.value);
    next = page['@odata.nextLink'] || null;
    pages++;
  }
  return items;
}

// Global Administrator membership takes two hops: find the activated role, then list members.
async function fetchGlobalAdmins(token) {
  const roles = await graphFetch(token, `/directoryRoles?$filter=roleTemplateId eq '${ROLE_GLOBAL_ADMIN}'`);
  const role = (roles.value || [])[0];
  if (!role) return [];
  return graphAll(token,
    `/directoryRoles/${role.id}/members?$select=id,displayName,userPrincipalName,onPremisesSyncEnabled,accountEnabled`);
}

// ---------------------------------------------------------------------------------------
// Collection
// ---------------------------------------------------------------------------------------
export async function collect(token, sourceNames, onProgress = () => {}) {
  const data = {};
  const failures = {};
  const names = [...sourceNames];

  for (let i = 0; i < names.length; i++) {
    const name = names[i];
    const src = SOURCES[name];
    onProgress({ phase: 'collect', current: i + 1, total: names.length, label: src.label });

    try {
      if (src.derived === 'globalAdmins')  data[name] = await fetchGlobalAdmins(token);
      else if (src.count)                  data[name] = parseInt(await graphFetch(token, src.url, { raw: true }), 10);
      else if (src.collection)             data[name] = await graphAll(token, src.url);
      else                                 data[name] = await graphFetch(token, src.url);
    }
    catch (e) {
      data[name] = null;
      failures[name] = {
        label: src.label,
        reason: e.message,
        status: e.status ?? null,
        optional: !!src.optional
      };
    }
  }

  return { data, failures };
}

// ---------------------------------------------------------------------------------------
// Evaluation
// ---------------------------------------------------------------------------------------
export function evaluate(data, failures, catalog) {
  const meta = new Map(catalog.checks.map(c => [c.id, c]));

  return CHECKS.map(check => {
    const info = meta.get(check.id) || { id: check.id, name: check.id, severity: 'Unknown', frameworks: {} };

    // A check whose data never arrived is Unknown, never Fail.
    const missing = check.needs.filter(n => data[n] === null || data[n] === undefined);
    let verdict;
    if (missing.length) {
      const why = missing.map(n => failures[n]?.reason || 'not collected');
      verdict = unknown(`Could not evaluate: ${why[0]}`);
    } else {
      try {
        verdict = check.evaluate(data);
      } catch (e) {
        // A predicate bug must not take down the run or masquerade as a finding.
        verdict = unknown(`Check could not be evaluated (${e.message}).`);
      }
    }

    return {
      id: check.id,
      name: info.name,
      category: info.category,
      severity: info.severity,
      rationale: info.rationale,
      licensing: info.licensing,
      remediation: info.remediation,
      frameworks: info.frameworks,
      status: verdict.status,
      detail: verdict.detail
    };
  });
}

// ---------------------------------------------------------------------------------------
// Scoring
// ---------------------------------------------------------------------------------------
export function summarise(results) {
  const by = s => results.filter(r => r.status === s).length;
  const pass = by('Pass');
  const fail = by('Fail');
  const scored = pass + fail;

  const failedBySeverity = {};
  for (const s of ['Critical', 'High', 'Medium', 'Low']) {
    failedBySeverity[s] = results.filter(r => r.status === 'Fail' && r.severity === s).length;
  }

  return {
    total: results.length,
    pass,
    fail,
    unknown: by('Unknown'),
    notApplicable: by('NotApplicable'),
    scored,
    // Unknown and NotApplicable stay out of the denominator, so a partial run is not punished.
    passRate: scored ? Math.round((pass / scored) * 100) : null,
    failedBySeverity
  };
}

export function frameworkRollup(results) {
  const rollup = {};
  for (const r of results) {
    for (const [key, m] of Object.entries(r.frameworks || {})) {
      const e = rollup[key] || (rollup[key] = { label: m.label, pass: 0, fail: 0, unknown: 0, controls: new Set() });
      if (r.status === 'Pass') e.pass++;
      else if (r.status === 'Fail') { e.fail++; String(m.controlId).split(';').forEach(c => e.controls.add(c.trim())); }
      else if (r.status === 'Unknown') e.unknown++;
    }
  }
  return Object.entries(rollup)
    .map(([key, v]) => ({
      id: key,
      label: v.label,
      pass: v.pass,
      fail: v.fail,
      unknown: v.unknown,
      scored: v.pass + v.fail,
      passRate: (v.pass + v.fail) ? Math.round((v.pass / (v.pass + v.fail)) * 100) : null,
      failingControls: [...v.controls].sort()
    }))
    .sort((a, b) => (a.passRate ?? 101) - (b.passRate ?? 101));
}

// ---------------------------------------------------------------------------------------
// Orchestration
// ---------------------------------------------------------------------------------------
export async function runAssessment({ token, catalog, tenant, onProgress = () => {} }) {
  const needed = [...new Set(CHECKS.flatMap(c => c.needs))];
  const started = new Date();

  const { data, failures } = await collect(token, needed, onProgress);

  onProgress({ phase: 'evaluate', current: 0, total: CHECKS.length, label: 'Evaluating checks' });
  const results = evaluate(data, failures, catalog);
  onProgress({ phase: 'evaluate', current: CHECKS.length, total: CHECKS.length, label: 'Evaluating checks' });

  return {
    tenant,
    started: started.toISOString(),
    finished: new Date().toISOString(),
    durationMs: Date.now() - started.getTime(),
    catalog: {
      version: catalog.catalogVersion,
      source: catalog.source
    },
    summary: summarise(results),
    frameworks: frameworkRollup(results),
    unavailable: Object.entries(failures).map(([k, v]) => ({ source: k, ...v })),
    results
  };
}

export const REQUIRED_SCOPES = [...new Set(
  [...new Set(CHECKS.flatMap(c => c.needs))].flatMap(n => SOURCES[n].scopes)
)].sort();
