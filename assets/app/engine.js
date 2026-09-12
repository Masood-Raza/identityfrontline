// Identity Frontline — assessment engine.
//
// Fetches each Graph source once, then runs every check against the shared result. Runs
// entirely in the browser: tenant data goes Microsoft -> this page and nowhere else.
//
// Failure handling mirrors the upstream status model. A source that cannot be read (missing
// consent, unlicensed feature, transient error) is recorded as unavailable, and every check
// depending on it reports Unknown with the reason. Unknown and NotApplicable are excluded
// from the pass rate rather than counted as failures, so a partial run is still honest.

import { CHECKS, SOURCES, AREAS, unknown } from './checks.js';

// Which checks run for a set of selected areas. Empty selection means identity only.
export function checksFor(areas) {
  const set = new Set(areas && areas.length ? areas : ['identity']);
  return CHECKS.filter(c => set.has(c.area));
}

// A need written as '?name' is optional: it is fetched, but its absence does not make the
// check Unknown. Used where a secondary source merely adds evidence.
const needName = (n) => n.startsWith('?') ? n.slice(1) : n;
const isRequired = (n) => !n.startsWith('?');

export function scopesFor(areas) {
  const needs = new Set(checksFor(areas).flatMap(c => c.needs.map(needName)));
  return [...new Set([...needs].flatMap(n => SOURCES[n].scopes))].sort();
}

const GRAPH = 'https://graph.microsoft.com/v1.0';
const ROLE_GLOBAL_ADMIN = '62e90394-69f5-4237-9190-012177145e10';
const MAX_RETRIES = 4;

const sleep = ms => new Promise(r => setTimeout(r, ms));

// Graph's error strings are written for developers. Translate the ones users actually hit.
const FRIENDLY = [
  [/Request not applicable to target tenant/i, 'Intune is not licensed or provisioned in this tenant.'],
  [/not a B2C tenant and doesn't have premium license/i, 'Requires Entra ID P1 or P2; this tenant has neither.'],
  [/Resource not found for the segment/i, 'This setting is not exposed by Microsoft Graph.'],
  [/Insufficient privileges to complete the operation/i, 'The signed-in account or the granted consent does not include this permission.'],
  [/The tenant for tenant guid .* does not exist/i, 'The tenant was not found.']
];
export const friendly = (msg) => {
  for (const [re, text] of FRIENDLY) if (re.test(msg)) return text;
  return msg;
};

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
        if (body?.error?.message) detail = friendly(body.error.message);
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

// Application permissions are app roles on the Microsoft Graph service principal. Resolve its
// role catalogue, then list every principal assigned any of them, in two hops.
const GRAPH_APP_ID = '00000003-0000-0000-c000-000000000000';
async function fetchGraphAppRoles(token) {
  const res = await graphFetch(token, `/servicePrincipals?$filter=appId eq '${GRAPH_APP_ID}'&$select=id,appRoles`);
  const sp = (res.value || [])[0];
  if (!sp) return { names: {}, byPrincipal: {} };
  const names = {};
  for (const r of (sp.appRoles || [])) names[r.id] = r.value;
  const assigned = await graphAll(token, `/servicePrincipals/${sp.id}/appRoleAssignedTo?$top=999`);
  const byPrincipal = {};
  for (const a of assigned) (byPrincipal[a.principalId] = byPrincipal[a.principalId] || []).push(a.appRoleId);
  return { names, byPrincipal };
}

// Static data shipped with the site, fetched relative to the page without a token.
async function fetchLocal(path) {
  const res = await fetch(path, { cache: 'no-cache' });
  if (!res.ok) throw new GraphError(`Could not load ${path} (HTTP ${res.status}).`, res.status);
  return res.json();
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
      else if (src.derived === 'graphAppRoles') data[name] = await fetchGraphAppRoles(token);
      else if (src.local)                  data[name] = await fetchLocal(src.local);
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
export function evaluate(data, failures, catalog, checks = CHECKS) {
  const meta = new Map(catalog.checks.map(c => [c.id, c]));

  return checks.map(check => {
    const info = meta.get(check.id) || { id: check.id, name: check.id, severity: 'Unknown', frameworks: {} };

    // A check whose required data never arrived is Unknown, never Fail.
    const missing = check.needs.filter(isRequired).filter(n => data[n] === null || data[n] === undefined);
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
      area: check.area,
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
  const warning = by('Warning');
  // Warning is partial compliance: it is scored, and it does not count as a pass.
  const scored = pass + fail + warning;

  const failedBySeverity = {};
  for (const s of ['Critical', 'High', 'Medium', 'Low']) {
    failedBySeverity[s] = results.filter(r => r.status === 'Fail' && r.severity === s).length;
  }

  return {
    total: results.length,
    pass,
    fail,
    warning,
    unknown: by('Unknown'),
    notApplicable: by('NotApplicable'),
    scored,
    // Unknown and NotApplicable stay out of the denominator, so a partial run is not punished.
    passRate: scored ? Math.round((pass / scored) * 100) : null,
    failedBySeverity
  };
}

// The mappings a result should show under the user's framework selection. Empty = all.
export function frameworksOf(result, filter) {
  const all = result.frameworks || {};
  if (!filter || !filter.length) return all;
  return Object.fromEntries(Object.entries(all).filter(([k]) => filter.includes(k)));
}

// Failed checks in the order they should be fixed: severity first, then the ones with a
// concrete remediation path, then by category so related work sits together.
const SEV_RANK = { Critical: 0, High: 1, Medium: 2, Low: 3 };
const hasFix = r => (r.remediation?.portal || r.remediation?.powershell) ? 1 : 0;
export function prioritise(results, limit = 5) {
  return results
    .filter(r => r.status === 'Fail' || r.status === 'Warning')
    .sort((a, b) =>
      (a.status === 'Warning') - (b.status === 'Warning') ||
      (SEV_RANK[a.severity] ?? 9) - (SEV_RANK[b.severity] ?? 9) ||
      hasFix(b) - hasFix(a) ||
      String(a.category).localeCompare(String(b.category)) ||
      a.id.localeCompare(b.id))
    .slice(0, limit);
}

export function frameworkRollup(results, filter) {
  const rollup = {};
  for (const r of results) {
    for (const [key, m] of Object.entries(frameworksOf(r, filter))) {
      const e = rollup[key] || (rollup[key] = { label: m.label, pass: 0, fail: 0, warning: 0, unknown: 0, controls: new Set() });
      if (r.status === 'Pass') e.pass++;
      else if (r.status === 'Fail') { e.fail++; String(m.controlId).split(';').forEach(c => e.controls.add(c.trim())); }
      else if (r.status === 'Warning') { e.warning++; String(m.controlId).split(';').forEach(c => e.controls.add(c.trim())); }
      else if (r.status === 'Unknown') e.unknown++;
    }
  }
  return Object.entries(rollup)
    .map(([key, v]) => ({
      id: key,
      label: v.label,
      pass: v.pass,
      fail: v.fail,
      warning: v.warning,
      unknown: v.unknown,
      scored: v.pass + v.fail + v.warning,
      passRate: (v.pass + v.fail + v.warning) ? Math.round((v.pass / (v.pass + v.fail + v.warning)) * 100) : null,
      failingControls: [...v.controls].sort()
    }))
    .sort((a, b) => (a.passRate ?? 101) - (b.passRate ?? 101));
}

// ---------------------------------------------------------------------------------------
// Orchestration
// ---------------------------------------------------------------------------------------
export async function runAssessment({ token, catalog, tenant, frameworks = [], areas = ['identity'], onProgress = () => {} }) {
  const checks = checksFor(areas);
  const needed = [...new Set(checks.flatMap(c => c.needs.map(needName)))];
  const started = new Date();

  const { data, failures } = await collect(token, needed, onProgress);

  onProgress({ phase: 'evaluate', current: 0, total: checks.length, label: 'Evaluating checks' });
  const results = evaluate(data, failures, catalog, checks);
  onProgress({ phase: 'evaluate', current: checks.length, total: checks.length, label: 'Evaluating checks' });

  // Framework selection defines the SCOPE of the report. Every check is still assessed, but
  // the headline score, the priorities and the primary findings cover only the checks that
  // map to a selected framework. The rest are kept and reported separately, never hidden.
  const scopeIds = [...frameworks];
  for (const r of results) {
    r.inScope = scopeIds.length === 0 || scopeIds.some(id => r.frameworks && r.frameworks[id]);
  }
  const inScope = results.filter(r => r.inScope);
  const scope = {
    frameworks: scopeIds.map(id => ({ id, label: catalog.frameworks?.[id]?.label || id })),
    label: scopeIds.length ? scopeIds.map(id => catalog.frameworks?.[id]?.label || id).join(', ') : 'All frameworks',
    inScopeCount: inScope.length,
    outOfScopeCount: results.length - inScope.length
  };

  return {
    tenant,
    areas: [...new Set(areas && areas.length ? areas : ['identity'])].map(id => ({ id, label: AREAS.find(a => a.id === id)?.label || id })),
    started: started.toISOString(),
    finished: new Date().toISOString(),
    durationMs: Date.now() - started.getTime(),
    catalog: {
      version: catalog.catalogVersion,
      source: catalog.source
    },
    frameworkFilter: scopeIds,
    scope,
    // Headline numbers are for the selected scope; summaryAll is the unfiltered view.
    summary: summarise(inScope),
    summaryAll: summarise(results),
    frameworks: frameworkRollup(results, frameworks),
    priorities: prioritise(inScope),
    unavailable: Object.entries(failures).map(([k, v]) => ({ source: k, ...v })),
    results
  };
}

// Every scope any area could ask for: what the app registration must be configured with.
export const ALL_SCOPES = scopesFor(AREAS.map(a => a.id));
// Backwards-compatible default: identity only.
export const REQUIRED_SCOPES = scopesFor(['identity']);
