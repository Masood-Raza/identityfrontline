// Identity Frontline — browser-native check definitions.
//
// This file is the SOURCE OF TRUTH for which checks are implemented. Everything else about a
// check — its name, severity, rationale, remediation and framework mappings — comes from
// assets/catalog/checks.json, generated from the M365-Assess control registry by
// tools/Build-CheckCatalog.ps1. Keep the two in sync: `npm test` fails if they drift.
//
// Each check gets pre-fetched data and returns a verdict. Never throw from evaluate(); if the
// data needed is absent, return unknown() so the check is excluded from the pass rate rather
// than counted as a failure. This mirrors the upstream status model.

export const pass = (detail) => ({ status: 'Pass', detail });
export const fail = (detail) => ({ status: 'Fail', detail });
export const unknown = (detail) => ({ status: 'Unknown', detail });
export const na = (detail) => ({ status: 'NotApplicable', detail });
// Partial compliance: scored, and not a pass. Mirrors the upstream Warning status.
export const warn = (detail) => ({ status: 'Warning', detail });

// Assessment areas. Each check belongs to exactly one; the user picks which areas to run and
// only the permissions those areas need are requested.
export const AREAS = [
  { id: 'identity',      label: 'Identity & access', summary: 'Conditional Access, MFA, administrators, consent, guests, passwords and authentication methods.' },
  { id: 'collaboration', label: 'Collaboration',     summary: 'SharePoint and OneDrive sharing, sync and legacy authentication; Teams app consent; Microsoft Forms external access and phishing protection.' },
  { id: 'intune',        label: 'Intune & devices',  summary: 'Enrolment restrictions, compliance thresholds, encryption, removable media, VPN and Wi-Fi profiles.' },
  { id: 'privileged',    label: 'Applications & privileged access', summary: 'Enterprise apps and service principals: credentials, dangerous and Tier 0 permissions, owners, impersonation. PIM: eligibility, activation approval, MFA, duration, notifications. Access reviews.' },
  { id: 'signals',       label: 'Microsoft security signals', summary: 'Microsoft Secure Score, how fresh it is and its top improvement actions, plus open Defender alerts — Microsoft\'s own view of the tenant next to ours.' },
  { id: 'dns',           label: 'Email authentication (DNS)', summary: 'SPF, DKIM selectors, DMARC and MX for every verified domain.',
    note: 'Reads public DNS. Lookups go to a public resolver rather than to Microsoft — the only part of the assessment that contacts anything else. Domain names are already public; nothing else about the tenant is sent.' },
  { id: 'exchange',      label: 'Exchange & email security', summary: 'Modern auth, SMTP AUTH, forwarding, transport rules, connectors, mailbox auditing, anti-phishing, Safe Links, Safe Attachments and anti-spam policy.',
    note: 'Microsoft Graph does not expose any of this and the Exchange API refuses browser calls, so these checks read an evidence file produced by tools/Export-ExchangeEvidence.ps1. You pick the file on the run step; it is read in the browser and never uploaded.' }
];

// ---- Effort and ownership ----
// Every finding carries who fixes it and roughly how much work it is, so the Fix-first list
// can be ordered by impact per hour and the remediation plan can be handed out by team.
// A check may override either with its own `effort` or `owner` property.
export const EFFORT = {
  quick:    { rank: 0, label: 'Quick win',          hint: 'A setting in an admin portal; minutes, no design work.' },
  moderate: { rank: 1, label: 'Moderate',           hint: 'Needs a decision or a person: accounts to create, roles to remove, users to move.' },
  review:   { rank: 2, label: 'Review with owners', hint: 'Case by case with whoever owns the app or the integration.' },
  project:  { rank: 3, label: 'Project',            hint: 'Policy design, licensing or rollout planning before the switch is flipped.' }
};
export const OWNERS = {
  identity:   'Identity administrator',
  apps:       'Application owners',
  sharepoint: 'SharePoint administrator',
  teams:      'Teams administrator',
  m365:       'Microsoft 365 administrator',
  intune:     'Intune administrator',
  security:   'Security operations'
};
const EFFORT_RULES = [
  [/^CA-|^INTUNE-|^ENTRA-PIM-|^ENTRA-SECDEFAULT-002$/, 'project'],
  [/^ENTRA-ENTAPP-|^ENTRA-APPREG-00[234]$/, 'review'],
  [/^ENTRA-ADMIN-|^ENTRA-BREAKGLASS-|^ENTRA-CLOUDADMIN-|^ENTRA-MFA-|^ENTRA-SSPR-|^DEFENDER-/, 'moderate']
];
const OWNER_RULES = [
  [/^ENTRA-ENTAPP-|^ENTRA-APPREG-|^ENTRA-APPS-/, 'apps'],
  [/^SPO-/, 'sharepoint'], [/^TEAMS-/, 'teams'], [/^FORMS-/, 'm365'], [/^INTUNE-/, 'intune'], [/^DEFENDER-|^COMPLIANCE-/, 'security']
];
export const effortOf = (check) => check.effort || (EFFORT_RULES.find(([re]) => re.test(check.id)) || [, 'quick'])[1];
export const ownerOf = (check) => check.owner || (OWNER_RULES.find(([re]) => re.test(check.id)) || [, 'identity'])[1];

const SPO_SHARING = {
  disabled: 'disabled',
  existingExternalUserSharingOnly: 'existing guests only',
  externalUserSharingOnly: 'new and existing guests',
  externalUserAndGuestSharing: 'anyone, including anonymous links'
};
// SharePoint Online's first-party application ID, as it appears in Conditional Access.
const SPO_APP_ID = '00000003-0000-0ff1-ce00-000000000000';

// A boolean setting compared against its expected value.
const boolFlag = (obj, key, expected, okMsg, badMsg) => {
  if (!obj) return unknown('Setting not returned.');
  const v = obj[key];
  if (v === undefined || v === null) return unknown(`${key} was not returned for this tenant.`);
  return v === expected ? pass(okMsg) : fail(badMsg);
};

// ---- Email authentication helpers ----
const few = (items) => items.slice(0, 5).join(', ') + (items.length > 5 ? ` and ${items.length - 5} more` : '');
const resolvable = (d) => (d.dnsRecords?.domains || []).filter(x => !x.error);
// No routable domain at all is NotApplicable; domains that exist but would not resolve are
// Unknown with the resolver reason. Neither is a finding about the tenant.
const dnsGate = (d) => {
  const all = d.dnsRecords?.domains || [];
  if (!all.length) return na('No routable custom domains are verified on this tenant.');
  if (!all.some(x => !x.error)) return unknown(`DNS lookups did not complete: ${all[0].error}`);
  return null;
};
const domList = (doms) => few(doms.map(x => x.name));

// ---- Exchange evidence helpers ----
const first = (v) => (Array.isArray(v) ? v[0] : v);
const arr = (v) => (Array.isArray(v) ? v : (v === undefined || v === null ? [] : [v]));
// Evidence is collected one cmdlet at a time, and a cmdlet the tenant cannot run is recorded
// with its reason. Those checks report Unknown with that reason rather than a false failure.
const fromEvidence = (d, key, fn) => {
  const ev = d.exchangeEvidence;
  if (!ev) return unknown('Exchange evidence was not imported.');
  const why = ev.errors?.[key];
  if (why) return unknown(why);
  const v = ev.data?.[key];
  if (v === undefined || v === null) return unknown(`"${key}" was not present in the evidence file.`);
  return fn(v);
};

// ---- Applications & privileged access helpers ----
const GA_ROLE = '62e90394-69f5-4237-9190-012177145e10';
const redirectUris = (a, includePublic = true) => [
  ...(a.web?.redirectUris || []), ...(a.spa?.redirectUris || []),
  ...(includePublic ? (a.publicClient?.redirectUris || []) : [])];
const names = (arr) => arr.map(x => x.displayName).slice(0, 5).join(', ') + (arr.length > 5 ? ` and ${arr.length - 5} more` : '');
const list = (arr) => arr.slice(0, 5).join('; ') + (arr.length > 5 ? ` and ${arr.length - 5} more` : '');
const regularApps = d => (d.servicePrincipals || []).filter(sp => sp.servicePrincipalType !== 'ManagedIdentity');
const managedIdentities = d => (d.servicePrincipals || []).filter(sp => sp.servicePrincipalType === 'ManagedIdentity');
const hasCreds = sp => (sp.keyCredentials || []).length > 0 || (sp.passwordCredentials || []).length > 0;
const tenantId = d => (d.organization || [])[0]?.id;
// Microsoft's own multi-tenant apps are foreign by definition; they are expected, not findings.
const isFirstParty = (d, sp) => d.appTiers.firstPartyAppIds.includes(sp.appId) || d.appTiers.firstPartyTenantIds.includes(sp.appOwnerOrganizationId);
const thirdPartyForeign = d => {
  const tid = tenantId(d);
  return regularApps(d).filter(sp => sp.accountEnabled === true && sp.appOwnerOrganizationId && sp.appOwnerOrganizationId !== tid && !isFirstParty(d, sp));
};
// Application permissions (app roles on the Graph service principal) held by a principal, by name.
const appPerms = (d, sp) => (d.graphAppRoles?.byPrincipal?.[sp.id] || []).map(id => d.graphAppRoles.names[id]).filter(Boolean);
const appRoleCount = (d, id) => (d.graphAppRoles?.byPrincipal?.[id] || []).length;
const roleCount = (d, id) => (d.roleAssignments || []).filter(a => a.principalId === id).length;
const owners = (d, id) => (d.spOwners || []).find(s => s.id === id)?.owners || [];
const pimRule = (assignments, ruleId) => ((assignments || [])[0]?.policy?.rules || []).find(r => r.id === ruleId) || null;
// ISO 8601 duration to hours: PT8H, PT30M, P365D.
const isoHours = (iso) => {
  const m = /^P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?)?$/.exec(iso || '');
  if (!m) return null;
  return (+(m[1] || 0)) * 24 + (+(m[2] || 0)) + (+(m[3] || 0)) / 60;
};

// A configuration profile counts only if it exists AND is assigned to something.
const assignedProfile = (configs, match, okLabel, noneMsg) => {
  const hits = (configs || []).filter(match);
  if (!hits.length) return fail(noneMsg);
  const assigned = hits.filter(p => (p.assignments || []).length > 0);
  if (assigned.length) return pass(`${okLabel} by "${assigned[0].displayName}" (${assigned.length} assigned profile${assigned.length === 1 ? '' : 's'}).`);
  return fail(`${okLabel} by "${hits[0].displayName}", but the profile has no assignments so it is not applied.`);
};

// Well-known directory role template IDs (stable across every tenant).
const ROLE_GLOBAL_ADMIN = '62e90394-69f5-4237-9190-012177145e10';

// Well-known guest role template IDs from authorizationPolicy.guestUserRoleId.
const GUEST_ROLE = {
  '2af84b1e-32c8-42b7-82bc-daa82404023b': 'Restricted guest',
  '10dae51f-b6af-4016-8d66-8c2a99b929b3': 'Guest (default)',
  'a0b1b346-4d3e-4e8b-98f8-753987be4970': 'Same as member'
};

// ---------------------------------------------------------------------------------------
// Data sources. Fetched once, shared by every check that declares them in `needs`.
// `optional: true` means a failure degrades dependent checks to Unknown instead of erroring.
// ---------------------------------------------------------------------------------------
export const SOURCES = {
  organization: {
    url: '/organization?$select=id,displayName',
    scopes: ['Directory.Read.All'],
    collection: true,
    label: 'Tenant profile'
  },
  securityDefaults: {
    url: '/policies/identitySecurityDefaultsEnforcementPolicy',
    scopes: ['Policy.Read.All'],
    label: 'Security defaults'
  },
  authorizationPolicy: {
    url: '/policies/authorizationPolicy',
    scopes: ['Policy.Read.All'],
    label: 'Authorization policy'
  },
  adminConsentPolicy: {
    url: '/policies/adminConsentRequestPolicy',
    scopes: ['Policy.Read.All'],
    label: 'Admin consent workflow'
  },
  authMethodsPolicy: {
    url: '/policies/authenticationMethodsPolicy',
    scopes: ['Policy.Read.All'],
    label: 'Authentication methods policy'
  },
  authMethodsPolicyBeta: {
    // systemCredentialPreferences and reportSuspiciousActivitySettings are beta-only. Read
    // them from beta; everything else about the policy stays on v1.0.
    url: 'https://graph.microsoft.com/beta/policies/authenticationMethodsPolicy',
    scopes: ['Policy.Read.All'],
    optional: true,
    label: 'Authentication methods policy (extended settings)'
  },
  caPolicies: {
    url: '/identity/conditionalAccess/policies',
    scopes: ['Policy.Read.All'],
    collection: true,
    label: 'Conditional Access policies'
  },
  namedLocations: {
    url: '/identity/conditionalAccess/namedLocations',
    scopes: ['Policy.Read.All'],
    collection: true,
    label: 'Named locations'
  },
  domains: {
    url: '/domains',
    scopes: ['Domain.Read.All'],
    collection: true,
    label: 'Verified domains'
  },
  directoryRoles: {
    url: '/directoryRoles',
    scopes: ['Directory.Read.All', 'RoleManagement.Read.Directory'],
    collection: true,
    label: 'Activated directory roles'
  },
  globalAdmins: {
    // Resolved in two hops by the engine: find the Global Administrator role, list its members.
    derived: 'globalAdmins',
    scopes: ['Directory.Read.All', 'RoleManagement.Read.Directory'],
    label: 'Global Administrator members'
  },
  guestCount: {
    url: "/users/$count?$filter=userType eq 'Guest'",
    scopes: ['User.Read.All'],
    count: true,
    label: 'Guest user count'
  },
  // ---- SharePoint & OneDrive ----
  spoSettings: {
    url: '/admin/sharepoint/settings',
    scopes: ['SharePointTenantSettings.Read.All'],
    label: 'SharePoint tenant settings'
  },
  // ---- Teams ----
  // Meeting and external-access policies have no Graph endpoint (they need Teams PowerShell);
  // only the tenant-wide app settings are readable, and the consent flag lives on beta.
  teamsAppSettings: {
    url: 'https://graph.microsoft.com/beta/teamwork/teamsAppSettings',
    scopes: ['TeamworkAppSettings.Read.All'],
    label: 'Teams app settings'
  },
  // ---- Forms ----
  formsSettings: {
    url: 'https://graph.microsoft.com/beta/admin/forms/settings',
    scopes: ['OrgSettings-Forms.Read.All'],
    label: 'Forms settings'
  },
  // ---- Intune ----
  intuneSettings: {
    url: 'https://graph.microsoft.com/beta/deviceManagement/settings',
    scopes: ['DeviceManagementConfiguration.Read.All'],
    label: 'Intune tenant settings'
  },
  enrollmentConfigs: {
    url: 'https://graph.microsoft.com/beta/deviceManagement/deviceEnrollmentConfigurations',
    scopes: ['DeviceManagementServiceConfig.Read.All'],
    collection: true,
    label: 'Device enrolment configurations'
  },
  autopilotProfiles: {
    url: 'https://graph.microsoft.com/beta/deviceManagement/windowsAutopilotDeploymentProfiles',
    scopes: ['DeviceManagementServiceConfig.Read.All'],
    collection: true,
    optional: true,
    label: 'Autopilot deployment profiles'
  },
  managedDeviceOverview: {
    url: 'https://graph.microsoft.com/beta/deviceManagement/managedDeviceOverview',
    scopes: ['DeviceManagementManagedDevices.Read.All'],
    label: 'Managed device overview'
  },
  deviceCategories: {
    url: 'https://graph.microsoft.com/beta/deviceManagement/deviceCategories',
    scopes: ['DeviceManagementManagedDevices.Read.All'],
    collection: true,
    label: 'Device categories'
  },
  compliancePolicies: {
    url: 'https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies',
    scopes: ['DeviceManagementConfiguration.Read.All'],
    collection: true,
    label: 'Device compliance policies'
  },
  deviceConfigs: {
    url: 'https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations?$expand=assignments',
    scopes: ['DeviceManagementConfiguration.Read.All'],
    collection: true,
    label: 'Device configuration profiles'
  },
  // ---- Applications & privileged access ----
  applications: {
    url: '/applications?$select=id,appId,displayName,signInAudience,web,spa,publicClient&$top=999',
    scopes: ['Application.Read.All'],
    collection: true,
    label: 'App registrations'
  },
  servicePrincipals: {
    url: '/servicePrincipals?$select=id,appId,displayName,appOwnerOrganizationId,servicePrincipalType,keyCredentials,passwordCredentials,accountEnabled&$top=999',
    scopes: ['Application.Read.All'],
    collection: true,
    label: 'Enterprise applications'
  },
  spOwners: {
    url: '/servicePrincipals?$select=id&$expand=owners($select=id,displayName)&$top=999',
    scopes: ['Application.Read.All'],
    collection: true,
    optional: true,
    label: 'Application owners'
  },
  spSignIns: {
    // Entra ID P1. Absent otherwise; the two checks that need it go Unknown.
    url: 'https://graph.microsoft.com/beta/servicePrincipals?$select=id,signInActivity&$top=999',
    scopes: ['Application.Read.All', 'AuditLog.Read.All'],
    collection: true,
    optional: true,
    label: 'Application sign-in activity'
  },
  graphAppRoles: {
    // Two hops by the engine: the Graph service principal's app roles, then who holds them.
    derived: 'graphAppRoles',
    scopes: ['Application.Read.All'],
    label: 'Application permissions granted'
  },
  oauth2Grants: {
    url: '/oauth2PermissionGrants?$top=999',
    scopes: ['Directory.Read.All'],
    collection: true,
    label: 'Delegated permission grants'
  },
  roleAssignments: {
    url: '/roleManagement/directory/roleAssignments?$top=999',
    scopes: ['RoleManagement.Read.Directory'],
    collection: true,
    label: 'Directory role assignments'
  },
  appManagementPolicy: {
    url: '/policies/defaultAppManagementPolicy',
    scopes: ['Policy.Read.All'],
    label: 'Default app management policy'
  },
  appTiers: {
    // Static data shipped with the site: Tier 0/1 permission lists and Microsoft's first-party
    // app and tenant IDs, from the M365-Assess controls (MIT).
    local: 'assets/catalog/app-tiers.json',
    scopes: [],
    label: 'Permission tier data'
  },
  gaEligible: {
    // Entra ID P2. Without PIM, every Global Administrator is a permanent assignment.
    url: "/roleManagement/directory/roleEligibilityScheduleInstances?$filter=roleDefinitionId eq '62e90394-69f5-4237-9190-012177145e10'",
    scopes: ['RoleManagement.Read.Directory'],
    collection: true,
    optional: true,
    label: 'PIM-eligible Global Administrators'
  },
  accessReviews: {
    url: '/identityGovernance/accessReviews/definitions?$top=100',
    scopes: ['AccessReview.Read.All'],
    collection: true,
    label: 'Access review definitions'
  },
  pimPolicyGA: {
    url: "/policies/roleManagementPolicyAssignments?$filter=scopeId eq '/' and scopeType eq 'DirectoryRole' and roleDefinitionId eq '62e90394-69f5-4237-9190-012177145e10'&$expand=policy($expand=rules)",
    scopes: ['RoleManagement.Read.Directory'],
    collection: true,
    label: 'PIM policy: Global Administrator'
  },
  pimPolicyPRA: {
    url: "/policies/roleManagementPolicyAssignments?$filter=scopeId eq '/' and scopeType eq 'DirectoryRole' and roleDefinitionId eq 'e8611ab8-c189-46e8-94e1-60213ab1f814'&$expand=policy($expand=rules)",
    scopes: ['RoleManagement.Read.Directory'],
    collection: true,
    label: 'PIM policy: Privileged Role Administrator'
  },
  // ---- Microsoft security signals ----
  secureScores: {
    url: '/security/secureScores?$top=5',
    scopes: ['SecurityEvents.Read.All'],
    collection: true,
    label: 'Microsoft Secure Score'
  },
  secureScoreProfiles: {
    // Titles, maximum points and portal links for the improvement actions.
    url: '/security/secureScoreControlProfiles?$top=999',
    scopes: ['SecurityEvents.Read.All'],
    collection: true,
    optional: true,
    area: 'signals',
    label: 'Secure Score improvement actions'
  },
  defenderAlerts: {
    // Collected for the signals section, not for a check: there is no registry control for
    // "open alerts", and an alert is an event to triage rather than a setting to fix.
    url: '/security/alerts_v2?$top=200&$orderby=createdDateTime desc',
    scopes: ['SecurityAlert.Read.All'],
    collection: true,
    optional: true,
    area: 'signals',
    label: 'Defender alerts'
  },
  // ---- Email authentication and Exchange ----
  dnsRecords: {
    // Resolved over DNS-over-HTTPS from the browser. Needs the verified domain list, so it
    // carries the same scope the domains source does.
    derived: 'dnsRecords',
    scopes: ['Domain.Read.All'],
    label: 'Public DNS records'
  },
  exchangeEvidence: {
    // Not a Graph source at all: a JSON file the administrator produces with
    // tools/Export-ExchangeEvidence.ps1 and picks on the run step.
    imported: true,
    scopes: [],
    label: 'Exchange evidence file'
  },
  registrationDetails: {
    // Entra ID P1/P2. Absent on Business Basic/Standard tenants -> dependent checks go Unknown.
    url: '/reports/authenticationMethods/userRegistrationDetails',
    scopes: ['AuditLog.Read.All'],
    collection: true,
    optional: true,
    label: 'MFA registration report'
  }
};

// ---------------------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------------------
const enabledPolicies = (d) => (d.caPolicies || []).filter(p => p.state === 'enabled');

const methodState = (d, id) => {
  const cfg = (d.authMethodsPolicy?.authenticationMethodConfigurations || [])
    .find(m => (m.id || '').toLowerCase() === id.toLowerCase());
  return cfg ? cfg.state : null;
};
const methodConfig = (d, id) =>
  (d.authMethodsPolicy?.authenticationMethodConfigurations || [])
    .find(m => (m.id || '').toLowerCase() === id.toLowerCase()) || null;

// A policy targets everyone if it includes All users and excludes nothing beyond break-glass.
const targetsAllUsers = (p) => (p.conditions?.users?.includeUsers || []).includes('All');
const grants = (p, control) =>
  (p.grantControls?.builtInControls || []).map(c => c.toLowerCase()).includes(control);
const appliesToAllApps = (p) =>
  (p.conditions?.applications?.includeApplications || []).includes('All');

const pct = (n, total) => total ? Math.round((n / total) * 100) : 0;

// ---------------------------------------------------------------------------------------
// Checks
// ---------------------------------------------------------------------------------------
export const CHECKS = [
  // ---- Tenant baseline ----------------------------------------------------------------
  {
    id: 'ENTRA-SECDEFAULT-001',
    area: 'identity',
    needs: ['securityDefaults', 'caPolicies'],
    evaluate: (d) => {
      const on = d.securityDefaults?.isEnabled;
      if (on === undefined || on === null) return unknown('Could not read the security defaults policy.');
      const ca = enabledPolicies(d).length;
      if (on) return pass('Security defaults are enabled.');
      return ca > 0
        ? pass(`Security defaults are off, but ${ca} enabled Conditional Access ${ca === 1 ? 'policy provides' : 'policies provide'} equivalent or stronger control.`)
        : fail('Security defaults are disabled and no Conditional Access policy is enabled. The tenant has no baseline identity protection.');
    }
  },
  {
    id: 'ENTRA-SECDEFAULT-002',
    area: 'identity',
    needs: ['securityDefaults', 'caPolicies'],
    evaluate: (d) => {
      if (d.securityDefaults?.isEnabled) return na('Security defaults are enabled, so gap analysis against Conditional Access does not apply.');
      const pols = enabledPolicies(d);
      if (!pols.length) return fail('Security defaults are off and there are no enabled Conditional Access policies to replace them.');
      const gaps = [];
      if (!pols.some(p => grants(p, 'mfa') && targetsAllUsers(p))) gaps.push('MFA for all users');
      if (!pols.some(p => (p.conditions?.clientAppTypes || []).some(c => ['exchangeactivesync', 'other'].includes(c.toLowerCase())) && grants(p, 'block'))) gaps.push('legacy authentication block');
      return gaps.length
        ? fail(`Conditional Access does not cover what security defaults would enforce. Missing: ${gaps.join(', ')}.`)
        : pass('Conditional Access covers the protections security defaults would provide.');
    }
  },

  // ---- Consent and applications -------------------------------------------------------
  {
    id: 'ENTRA-CONSENT-001',
    area: 'identity',
    needs: ['authorizationPolicy'],
    evaluate: (d) => {
      const g = d.authorizationPolicy?.defaultUserRolePermissions?.permissionGrantPoliciesAssigned;
      if (!g) return unknown('Could not read the authorization policy consent settings.');
      return g.length === 0
        ? pass('Users cannot consent to applications accessing company data.')
        : fail(`Users can consent to applications (${g.length} grant ${g.length === 1 ? 'policy' : 'policies'} assigned).`);
    }
  },
  {
    id: 'ENTRA-CONSENT-003',
    area: 'identity',
    needs: ['authorizationPolicy'],
    evaluate: (d) => {
      const g = d.authorizationPolicy?.defaultUserRolePermissions?.permissionGrantPoliciesAssigned;
      if (!g) return unknown('Could not read the authorization policy consent settings.');
      if (g.length === 0) return na('User consent is disabled entirely, so publisher restrictions do not apply.');
      const low = g.some(p => p.includes('microsoft-user-default-low'));
      return low
        ? pass('User consent is limited to verified publishers and low-impact permissions.')
        : fail('User consent is not restricted to verified publishers.');
    }
  },
  {
    id: 'ENTRA-CONSENT-002',
    area: 'identity',
    needs: ['adminConsentPolicy'],
    evaluate: (d) => {
      const on = d.adminConsentPolicy?.isEnabled;
      if (on === undefined || on === null) return unknown('Could not read the admin consent request policy.');
      return on ? pass('The admin consent workflow is enabled.')
                : fail('The admin consent workflow is disabled, so users have no supported route to request app access.');
    }
  },
  {
    id: 'ENTRA-CONSENT-005',
    area: 'identity',
    needs: ['adminConsentPolicy'],
    evaluate: (d) => {
      if (!d.adminConsentPolicy?.isEnabled) return na('The admin consent workflow is disabled.');
      const n = (d.adminConsentPolicy.reviewers || []).length;
      return n > 0 ? pass(`${n} consent ${n === 1 ? 'reviewer is' : 'reviewers are'} designated.`)
                   : fail('No reviewers are designated, so consent requests fall to Global Administrators by default.');
    }
  },
  {
    id: 'ENTRA-CONSENT-006',
    area: 'identity',
    needs: ['adminConsentPolicy'],
    evaluate: (d) => {
      if (!d.adminConsentPolicy?.isEnabled) return na('The admin consent workflow is disabled.');
      return d.adminConsentPolicy.notifyReviewers
        ? pass('Reviewers are emailed when a consent request is raised.')
        : fail('Reviewers are not notified, so requests can sit unreviewed indefinitely.');
    }
  },

  // ---- Guests -------------------------------------------------------------------------
  {
    id: 'ENTRA-GUEST-001',
    area: 'identity',
    needs: ['authorizationPolicy'],
    evaluate: (d) => {
      const id = d.authorizationPolicy?.guestUserRoleId;
      if (!id) return unknown('Could not read the guest user role.');
      const label = GUEST_ROLE[id] || id;
      return id === '2af84b1e-32c8-42b7-82bc-daa82404023b'
        ? pass('Guest access is set to the most restrictive role.')
        : fail(`Guest access is set to "${label}". The restricted guest role is recommended.`);
    }
  },
  {
    id: 'ENTRA-GUEST-002',
    area: 'identity',
    needs: ['authorizationPolicy'],
    evaluate: (d) => {
      const v = d.authorizationPolicy?.allowInvitesFrom;
      if (!v) return unknown('Could not read the guest invitation setting.');
      return ['adminsAndGuestInviters', 'none'].includes(v)
        ? pass(`Guest invitations are limited (${v}).`)
        : fail(`Guest invitations are set to "${v}", allowing members to invite external users.`);
    }
  },
  {
    id: 'ENTRA-GUEST-003',
    area: 'identity',
    needs: ['guestCount'],
    evaluate: (d) => {
      const n = d.guestCount;
      if (n === null || n === undefined) return unknown('Could not count guest users.');
      return n === 0
        ? pass('No guest accounts exist in the tenant.')
        : pass(`${n} guest ${n === 1 ? 'account' : 'accounts'} present. Review that each is still required.`, n);
    }
  },

  // ---- Passwords ----------------------------------------------------------------------
  {
    id: 'ENTRA-PASSWORD-001',
    area: 'identity',
    needs: ['domains'],
    evaluate: (d) => {
      const verified = (d.domains || []).filter(x => x.isVerified);
      if (!verified.length) return unknown('No verified domains returned.');
      const expiring = verified.filter(x =>
        x.passwordValidityPeriodInDays !== undefined &&
        x.passwordValidityPeriodInDays !== null &&
        x.passwordValidityPeriodInDays !== 2147483647);
      return expiring.length === 0
        ? pass('Passwords are set never to expire on all verified domains.')
        : fail(`${expiring.length} of ${verified.length} verified domains expire passwords (${expiring.map(x => x.id).slice(0, 3).join(', ')}). Forced rotation encourages weaker passwords.`);
    }
  },

  // ---- Authentication methods ---------------------------------------------------------
  {
    id: 'ENTRA-AUTHMETHOD-001',
    area: 'identity',
    needs: ['authMethodsPolicy'],
    evaluate: (d) => {
      if (!d.authMethodsPolicy) return unknown('Could not read the authentication methods policy.');
      const weak = ['Sms', 'Voice'].filter(m => methodState(d, m) === 'enabled');
      return weak.length === 0
        ? pass('Phishable methods (SMS, voice) are disabled.')
        : fail(`Weak authentication methods are still enabled: ${weak.join(', ')}.`);
    }
  },
  {
    id: 'ENTRA-AUTHMETHOD-002',
    area: 'identity',
    needs: ['authMethodsPolicy'],
    evaluate: (d) => {
      const s = methodState(d, 'Email');
      if (s === null) return unknown('Email OTP configuration not present in the policy.');
      return s === 'disabled' ? pass('Email OTP is disabled.') : fail('Email OTP is enabled and can be used as an authentication method.');
    }
  },
  {
    id: 'ENTRA-AUTHMETHOD-003',
    area: 'identity',
    needs: ['authMethodsPolicy'],
    evaluate: (d) => {
      const cfg = methodConfig(d, 'MicrosoftAuthenticator');
      if (!cfg) return unknown('Microsoft Authenticator configuration not present in the policy.');
      if (cfg.state !== 'enabled') return na('Microsoft Authenticator is not enabled.');
      const f = cfg.featureSettings || {};
      const missing = [];
      if (f.numberMatchingRequiredState?.state !== 'enabled') missing.push('number matching');
      if (f.displayAppInformationRequiredState?.state !== 'enabled') missing.push('app context');
      if (f.displayLocationInformationRequiredState?.state !== 'enabled') missing.push('location context');
      return missing.length === 0
        ? pass('Authenticator is hardened against MFA fatigue (number matching and context shown).')
        : fail(`Authenticator is missing anti-fatigue protections: ${missing.join(', ')}.`);
    }
  },
  {
    id: 'ENTRA-AUTHMETHOD-004',
    area: 'identity',
    needs: ['authMethodsPolicyBeta'],
    evaluate: (d) => {
      const s = d.authMethodsPolicyBeta?.systemCredentialPreferences?.state;
      if (!s) return unknown('System-preferred MFA setting was not returned for this tenant.');
      return s === 'enabled'
        ? pass('System-preferred multifactor authentication is enabled.')
        : fail(`System-preferred MFA is "${s}", so users may default to a weaker method.`);
    }
  },
  {
    id: 'ENTRA-AUTHMETHOD-005',
    area: 'identity',
    needs: ['authMethodsPolicy'],
    evaluate: (d) => {
      const s = d.authMethodsPolicy?.policyMigrationState;
      if (!s) return unknown('Policy migration state not reported.');
      return s === 'migrationComplete'
        ? pass('Authentication methods are fully migrated to the converged policy.')
        : fail(`Migration state is "${s}". Legacy per-method policies still govern some users, causing configuration drift.`);
    }
  },
  {
    id: 'ENTRA-AUTHMETHOD-006',
    area: 'identity',
    needs: ['authMethodsPolicyBeta'],
    evaluate: (d) => {
      const s = d.authMethodsPolicyBeta?.reportSuspiciousActivitySettings?.state;
      if (!s) return unknown('Suspicious activity reporting setting was not returned for this tenant.');
      return s === 'enabled'
        ? pass('Users can report suspicious MFA prompts.')
        : fail('Suspicious activity reporting is off, so denied fraudulent prompts are never escalated.');
    }
  },
  {
    id: 'ENTRA-AUTHMETHOD-007',
    area: 'identity',
    needs: ['authMethodsPolicy'],
    evaluate: (d) => {
      const s = methodState(d, 'TemporaryAccessPass');
      if (s === null) return unknown('Temporary Access Pass configuration not present.');
      return s === 'enabled'
        ? pass('Temporary Access Pass is available for onboarding and recovery.')
        : fail('Temporary Access Pass is disabled, pushing account recovery toward weaker fallbacks.');
    }
  },
  {
    id: 'ENTRA-AUTHMETHOD-008',
    area: 'identity',
    needs: ['authMethodsPolicy'],
    evaluate: (d) => {
      const cfg = methodConfig(d, 'TemporaryAccessPass');
      if (!cfg) return unknown('Temporary Access Pass configuration not present.');
      if (cfg.state !== 'enabled') return na('Temporary Access Pass is disabled.');
      return cfg.isUsableOnce
        ? pass('Temporary Access Pass is single-use.')
        : fail('Temporary Access Pass is reusable, so an intercepted pass can be replayed until it expires.');
    }
  },
  {
    id: 'ENTRA-SSPR-001',
    area: 'identity',
    needs: ['authMethodsPolicy'],
    evaluate: (d) => {
      const c = d.authMethodsPolicy?.registrationEnforcement?.authenticationMethodsRegistrationCampaign;
      if (!c) return unknown('Registration campaign settings not present.');
      return c.state === 'enabled'
        ? pass('The MFA registration campaign is nudging users toward stronger methods.')
        : fail('The registration campaign is disabled, leaving users on phishable methods.');
    }
  },

  // ---- Conditional Access -------------------------------------------------------------
  {
    id: 'ENTRA-CA-002',
    area: 'identity',
    needs: ['caPolicies'],
    evaluate: (d) => {
      const n = (d.caPolicies || []).length;
      return n === 0
        ? fail('No Conditional Access policies exist.')
        : pass(`${n} Conditional Access ${n === 1 ? 'policy' : 'policies'} defined.`, n);
    }
  },
  {
    id: 'ENTRA-CA-003',
    area: 'identity',
    needs: ['caPolicies'],
    evaluate: (d) => {
      const all = (d.caPolicies || []).length;
      const on = enabledPolicies(d).length;
      if (all === 0) return fail('No Conditional Access policies exist.');
      return on > 0
        ? pass(`${on} of ${all} policies are enabled.`, on)
        : fail(`All ${all} Conditional Access policies are disabled or report-only. None are enforcing.`);
    }
  },
  {
    id: 'CA-LEGACYAUTH-001',
    area: 'identity',
    needs: ['caPolicies'],
    evaluate: (d) => {
      const hit = enabledPolicies(d).find(p =>
        (p.conditions?.clientAppTypes || []).some(c => ['exchangeactivesync', 'other'].includes(c.toLowerCase())) &&
        grants(p, 'block'));
      return hit
        ? pass(`Legacy authentication is blocked by "${hit.displayName}".`)
        : fail('No enabled policy blocks legacy authentication. Legacy protocols bypass MFA entirely.');
    }
  },
  {
    id: 'CA-MFA-ALL-001',
    area: 'identity',
    needs: ['caPolicies', 'securityDefaults'],
    evaluate: (d) => {
      if (d.securityDefaults?.isEnabled) return pass('Security defaults enforce MFA for all users.');
      const hit = enabledPolicies(d).find(p => targetsAllUsers(p) && appliesToAllApps(p) && grants(p, 'mfa'));
      return hit
        ? pass(`MFA is required for all users by "${hit.displayName}".`)
        : fail('No enabled policy requires MFA for all users across all applications.');
    }
  },
  {
    id: 'CA-MFA-ADMIN-001',
    area: 'identity',
    needs: ['caPolicies', 'securityDefaults'],
    evaluate: (d) => {
      if (d.securityDefaults?.isEnabled) return pass('Security defaults enforce MFA for administrators.');
      const hit = enabledPolicies(d).find(p =>
        grants(p, 'mfa') &&
        ((p.conditions?.users?.includeRoles || []).length > 0 || targetsAllUsers(p)));
      return hit
        ? pass(`Administrative roles require MFA via "${hit.displayName}".`)
        : fail('No enabled policy requires MFA for users in administrative roles.');
    }
  },
  {
    id: 'CA-DEVICECODE-001',
    area: 'identity',
    needs: ['caPolicies'],
    evaluate: (d) => {
      const hit = enabledPolicies(d).find(p =>
        (p.conditions?.authenticationFlows?.transferMethods || '').toLowerCase().includes('devicecodeflow') &&
        grants(p, 'block'));
      return hit
        ? pass(`Device code flow is blocked by "${hit.displayName}".`)
        : fail('Device code sign-in is not blocked. It is a common phishing vector for token theft.');
    }
  },
  {
    id: 'CA-REPORTONLY-001',
    area: 'identity',
    needs: ['caPolicies'],
    evaluate: (d) => {
      const ro = (d.caPolicies || []).filter(p => p.state === 'enabledForReportingButNotEnforced');
      return ro.length === 0
        ? pass('No policies are stuck in report-only mode.')
        : fail(`${ro.length} ${ro.length === 1 ? 'policy is' : 'policies are'} in report-only mode and not enforcing: ${ro.map(p => p.displayName).slice(0, 3).join(', ')}.`, ro.length);
    }
  },
  {
    id: 'ENTRA-CA-SESSIONFREQ-001',
    area: 'identity',
    needs: ['caPolicies'],
    evaluate: (d) => {
      const hit = enabledPolicies(d).find(p => p.sessionControls?.signInFrequency?.isEnabled);
      return hit
        ? pass(`Sign-in frequency is enforced by "${hit.displayName}".`)
        : fail('No enabled policy enforces sign-in frequency, so sessions can persist indefinitely.');
    }
  },
  {
    id: 'CA-SIGNINRISK-002',
    area: 'identity',
    needs: ['caPolicies'],
    evaluate: (d) => {
      const hit = enabledPolicies(d).find(p => {
        const levels = (p.conditions?.signInRiskLevels || []).map(x => x.toLowerCase());
        return levels.includes('high') && levels.includes('medium') && (grants(p, 'block') || grants(p, 'mfa'));
      });
      return hit
        ? pass(`Medium and high sign-in risk are handled by "${hit.displayName}".`)
        : fail('No enabled policy responds to medium and high sign-in risk. Requires Entra ID P2.');
    }
  },
  {
    id: 'CA-USERRISK-001',
    area: 'identity',
    needs: ['caPolicies'],
    evaluate: (d) => {
      const hit = enabledPolicies(d).find(p => (p.conditions?.userRiskLevels || []).length > 0);
      return hit
        ? pass(`User risk is handled by "${hit.displayName}".`)
        : fail('No enabled policy responds to user risk. Requires Entra ID P2.');
    }
  },
  {
    id: 'CA-NAMEDLOC-001',
    area: 'identity',
    needs: ['namedLocations'],
    evaluate: (d) => {
      const locs = d.namedLocations || [];
      const trustedIp = locs.filter(l =>
        (l['@odata.type'] || '').includes('ipNamedLocation') && l.isTrusted);
      return trustedIp.length === 0
        ? pass('No IP-based named locations are marked trusted.')
        : fail(`${trustedIp.length} IP named ${trustedIp.length === 1 ? 'location is' : 'locations are'} marked trusted (${trustedIp.map(l => l.displayName).slice(0, 3).join(', ')}). Source IP can be spoofed or proxied.`, trustedIp.length);
    }
  },

  // ---- Administrators -----------------------------------------------------------------
  {
    id: 'ENTRA-ADMIN-001',
    area: 'identity',
    needs: ['globalAdmins'],
    evaluate: (d) => {
      const admins = d.globalAdmins;
      if (!admins) return unknown('Could not enumerate Global Administrator membership.');
      const n = admins.length;
      if (n < 2) return fail(`Only ${n} Global Administrator. A single admin is a lockout risk.`, n);
      if (n > 4) return fail(`${n} Global Administrators. Between two and four is recommended.`, n);
      return pass(`${n} Global Administrators, within the recommended range of two to four.`, n);
    }
  },
  {
    id: 'ENTRA-ADMIN-003',
    area: 'identity',
    needs: ['globalAdmins'],
    evaluate: (d) => {
      const admins = d.globalAdmins;
      if (!admins) return unknown('Could not enumerate Global Administrator membership.');
      // Break-glass accounts are cloud-only, unlicensed and conventionally named.
      const candidates = admins.filter(a =>
        a.onPremisesSyncEnabled !== true &&
        /break.?glass|emergency|firecall|baa/i.test(`${a.displayName || ''} ${a.userPrincipalName || ''}`));
      return candidates.length >= 2
        ? pass(`${candidates.length} emergency access accounts identified.`, candidates.length)
        : fail(`${candidates.length} emergency access ${candidates.length === 1 ? 'account' : 'accounts'} identified by naming convention. Two are recommended so a Conditional Access misconfiguration cannot lock everyone out.`, candidates.length);
    }
  },
  {
    id: 'ENTRA-BREAKGLASS-001',
    area: 'identity',
    needs: ['globalAdmins'],
    evaluate: (d) => {
      const admins = d.globalAdmins;
      if (!admins) return unknown('Could not enumerate Global Administrator membership.');
      const found = admins.some(a =>
        a.onPremisesSyncEnabled !== true &&
        /break.?glass|emergency|firecall/i.test(`${a.displayName || ''} ${a.userPrincipalName || ''}`));
      return found
        ? pass('At least one break-glass emergency access account is present.')
        : fail('No break-glass account detected. Without one, a Conditional Access or MFA failure can lock every administrator out of the tenant.');
    }
  },
  {
    id: 'ENTRA-CLOUDADMIN-001',
    area: 'identity',
    needs: ['globalAdmins'],
    evaluate: (d) => {
      const admins = d.globalAdmins;
      if (!admins) return unknown('Could not enumerate Global Administrator membership.');
      const synced = admins.filter(a => a.onPremisesSyncEnabled === true);
      return synced.length === 0
        ? pass('All Global Administrators are cloud-only accounts.')
        : fail(`${synced.length} of ${admins.length} Global Administrators are synced from on-premises. A domain compromise would reach the tenant.`, synced.length);
    }
  },

  // ---- MFA registration ---------------------------------------------------------------
  {
    id: 'ENTRA-MFA-001',
    area: 'identity',
    needs: ['registrationDetails'],
    evaluate: (d) => {
      const rows = d.registrationDetails;
      if (!rows) return unknown('The MFA registration report is unavailable. It requires Entra ID P1 or later.');
      const members = rows.filter(r => (r.userType || '').toLowerCase() === 'member');
      if (!members.length) return unknown('No member accounts returned in the registration report.');
      const capable = members.filter(r => r.isMfaCapable);
      const p = pct(capable.length, members.length);
      return p === 100
        ? pass(`All ${members.length} member accounts are MFA capable.`, p)
        : fail(`${capable.length} of ${members.length} member accounts are MFA capable (${p}%).`, p);
    }
  },
  {
    id: 'ENTRA-MFA-002',
    area: 'identity',
    needs: ['registrationDetails'],
    evaluate: (d) => {
      const rows = d.registrationDetails;
      if (!rows) return unknown('The MFA registration report is unavailable. It requires Entra ID P1 or later.');
      const members = rows.filter(r => (r.userType || '').toLowerCase() === 'member');
      if (!members.length) return unknown('No member accounts returned in the registration report.');
      const without = members.filter(r => !r.isMfaRegistered);
      const p = pct(without.length, members.length);
      return without.length === 0
        ? pass('Every member account has an MFA method registered.', 0)
        : fail(`${without.length} of ${members.length} member accounts (${p}%) have no MFA method registered.`, p);
    }
  },
  // =====================================================================================
  // SharePoint & OneDrive — tenant sharing settings
  // =====================================================================================
  {
    id: 'SPO-SHARING-001',
    area: 'collaboration',
    needs: ['spoSettings'],
    evaluate: (d) => {
      const v = d.spoSettings?.sharingCapability;
      if (!v) return unknown('Sharing capability not returned.');
      const label = SPO_SHARING[v] || v;
      if (v === 'disabled' || v === 'existingExternalUserSharingOnly') return pass(`External sharing: ${label}.`);
      if (v === 'externalUserSharingOnly') return warn(`External sharing: ${label}. New guests can be invited; "existing guests only" is recommended.`);
      if (v === 'externalUserAndGuestSharing') return fail(`External sharing: ${label}. Anonymous "anyone" links are permitted tenant-wide.`);
      return unknown(`Unrecognised sharing capability "${v}".`);
    }
  },
  {
    id: 'SPO-SHARING-002',
    area: 'collaboration',
    needs: ['spoSettings'],
    evaluate: (d) => {
      const v = d.spoSettings?.isResharingByExternalUsersEnabled;
      if (v === undefined || v === null) return unknown('Resharing setting not returned.');
      return v ? warn('Guests can reshare items they do not own.') : pass('Guests cannot reshare items they do not own.');
    }
  },
  {
    id: 'SPO-SHARING-003',
    area: 'collaboration',
    needs: ['spoSettings'],
    evaluate: (d) => {
      const v = d.spoSettings?.sharingDomainRestrictionMode;
      if (!v) return unknown('Domain restriction mode not returned.');
      if (v === 'allowList' || v === 'blockList') return pass(`External sharing is restricted by ${v === 'allowList' ? 'an allow list' : 'a block list'} of domains.`);
      if (v === 'none') return warn('External sharing is not restricted by domain.');
      return unknown(`Unrecognised domain restriction mode "${v}".`);
    }
  },
  {
    id: 'SPO-SYNC-001',
    area: 'collaboration',
    needs: ['spoSettings'],
    evaluate: (d) => {
      const v = d.spoSettings?.isUnmanagedSyncAppForTenantRestricted;
      if (v === undefined || v === null) return unknown('Unmanaged sync restriction not returned.');
      return v ? pass('OneDrive sync is restricted to managed devices.') : warn('OneDrive sync is allowed from unmanaged devices.');
    }
  },
  {
    id: 'SPO-ACCESS-002',
    area: 'collaboration',
    needs: ['spoSettings'],
    evaluate: (d) => {
      const v = d.spoSettings?.isUnmanagedSyncAppForTenantRestricted;
      if (v === undefined || v === null) return unknown('Unmanaged sync restriction not returned.');
      return v ? pass('Sync from unmanaged devices is blocked.') : warn('Unmanaged devices can sync SharePoint and OneDrive content.');
    }
  },
  {
    id: 'SPO-SYNC-002',
    area: 'collaboration',
    needs: ['spoSettings'],
    evaluate: (d) => {
      const v = d.spoSettings?.isMacSyncAppEnabled;
      if (v === undefined || v === null) return unknown('Mac sync setting not returned.');
      return v ? warn('The Mac sync client is enabled. Confirm Mac devices are managed.') : pass('The Mac sync client is disabled.');
    }
  },
  {
    id: 'SPO-LOOP-001',
    area: 'collaboration',
    needs: ['spoSettings'],
    evaluate: (d) => {
      const v = d.spoSettings?.isLoopEnabled;
      if (v === undefined || v === null) return unknown('Loop setting not returned.');
      return v ? unknown('Loop components are enabled. Review whether Loop is sanctioned and covered by sharing controls.')
               : pass('Loop components are disabled.');
    }
  },
  {
    id: 'SPO-SESSION-001',
    area: 'collaboration',
    needs: ['spoSettings'],
    evaluate: (d) => {
      const i = d.spoSettings?.idleSessionSignOut;
      if (!i || i.isEnabled === undefined || i.isEnabled === null) return unknown('Idle session sign-out setting not returned.');
      if (!i.isEnabled) return fail('Idle session sign-out is disabled, so sessions on unmanaged devices never time out.');
      const hours = (i.signOutAfterInSeconds || 0) / 3600;
      return hours > 0 && hours <= 3
        ? pass(`Idle sessions are signed out after ${hours % 1 ? hours.toFixed(1) : hours} hour${hours === 1 ? '' : 's'}.`)
        : warn(`Idle session sign-out is enabled but set to ${hours % 1 ? hours.toFixed(1) : hours} hours; 3 or fewer is recommended.`);
    }
  },
  {
    id: 'SPO-AUTH-001',
    area: 'collaboration',
    needs: ['spoSettings'],
    evaluate: (d) => {
      const v = d.spoSettings?.isLegacyAuthProtocolsEnabled;
      if (v === undefined || v === null) return unknown('Legacy authentication setting not returned.');
      return v ? fail('Legacy authentication protocols are enabled for SharePoint. They bypass MFA.')
               : pass('Legacy authentication protocols are disabled for SharePoint.');
    }
  },
  {
    id: 'SPO-ACCESS-001',
    area: 'collaboration',
    needs: ['caPolicies'],
    evaluate: (d) => {
      const hit = enabledPolicies(d).find(p => {
        const apps = p.conditions?.applications?.includeApplications || [];
        return apps.includes('All') || apps.includes(SPO_APP_ID);
      });
      return hit ? pass(`SharePoint Online is covered by "${hit.displayName}".`)
                 : warn('No enabled Conditional Access policy targets SharePoint Online.');
    }
  },

  // =====================================================================================
  // Microsoft Teams
  // =====================================================================================
  {
    id: 'TEAMS-APPS-001',
    area: 'collaboration',
    needs: ['teamsAppSettings'],
    evaluate: (d) => {
      const v = d.teamsAppSettings?.isChatResourceSpecificConsentEnabled;
      if (v === undefined || v === null) return unknown('Chat resource-specific consent setting not returned.');
      return v ? unknown('Chat resource-specific consent is enabled. Review which apps users can grant chat access to.')
               : pass('Chat resource-specific consent is disabled.');
    }
  },
  // =====================================================================================
  // Microsoft Forms
  // =====================================================================================
  {
    id: 'FORMS-CONFIG-001',
    area: 'collaboration',
    needs: ['formsSettings'],
    evaluate: (d) => boolFlag(d.formsSettings, 'isExternalSendFormEnabled', false,
      'External users cannot respond to forms.', 'Forms can be sent to and answered by external users.')
  },
  {
    id: 'FORMS-CONFIG-002',
    area: 'collaboration',
    needs: ['formsSettings'],
    evaluate: (d) => boolFlag(d.formsSettings, 'isExternalShareCollaborationEnabled', false,
      'External users cannot collaborate on forms.', 'External users can be added as form collaborators.')
  },
  {
    id: 'FORMS-CONFIG-003',
    area: 'collaboration',
    needs: ['formsSettings'],
    evaluate: (d) => boolFlag(d.formsSettings, 'isExternalShareResultEnabled', false,
      'Form results cannot be shared externally.', 'Form results can be shared with external users.')
  },
  {
    id: 'FORMS-CONFIG-004',
    area: 'collaboration',
    needs: ['formsSettings'],
    evaluate: (d) => boolFlag(d.formsSettings, 'isInOrgFormsPhishingScanEnabled', true,
      'Phishing protection scanning is enabled for forms.', 'Phishing protection scanning is disabled for forms.')
  },
  {
    id: 'FORMS-CONFIG-005',
    area: 'collaboration',
    needs: ['formsSettings'],
    evaluate: (d) => {
      const v = d.formsSettings?.isRecordIdentityByDefaultEnabled;
      if (v === undefined || v === null) return unknown('Respondent identity setting not returned.');
      return v ? pass('Respondent identity is recorded by default.')
               : unknown('Respondent identity is not recorded by default. Review whether anonymous responses are intended.');
    }
  },
  {
    id: 'FORMS-CONFIG-006',
    area: 'collaboration',
    needs: ['formsSettings'],
    evaluate: (d) => {
      const v = d.formsSettings?.isBingImageSearchEnabled;
      if (v === undefined || v === null) return unknown('Bing search setting not returned.');
      return v ? unknown('Bing image search is enabled in Forms. Review against your data-handling policy.')
               : pass('Bing image search is disabled in Forms.');
    }
  },

  // =====================================================================================
  // Intune — enrolment, compliance and Windows configuration profiles
  // =====================================================================================
  {
    id: 'INTUNE-COMPLIANCE-001',
    area: 'intune',
    needs: ['intuneSettings'],
    evaluate: (d) => {
      const days = d.intuneSettings?.deviceComplianceCheckinThresholdDays;
      if (days === undefined || days === null) return unknown('Compliance check-in threshold not returned.');
      return days <= 30 ? pass(`Devices are marked non-compliant after ${days} days without check-in.`)
                        : warn(`Devices stay compliant for ${days} days without check-in; 30 or fewer is recommended.`);
    }
  },
  {
    id: 'INTUNE-ENROLL-001',
    area: 'intune',
    needs: ['enrollmentConfigs'],
    evaluate: (d) => {
      const restrictions = (d.enrollmentConfigs || []).filter(c =>
        (c['@odata.type'] || '') === '#microsoft.graph.deviceEnrollmentPlatformRestrictionsConfiguration');
      if (!restrictions.length) return fail('No enrolment platform restriction policy exists, so personal devices can enrol.');
      const open = [];
      for (const r of restrictions) {
        for (const p of ['iosRestriction', 'androidRestriction', 'windowsRestriction']) {
          if (r[p] && r[p].personalDeviceEnrollmentBlocked !== true) open.push(p.replace('Restriction', ''));
        }
      }
      const uniq = [...new Set(open)];
      return uniq.length ? fail(`Personal device enrolment is allowed on: ${uniq.join(', ')}.`)
                         : pass('Personal device enrolment is blocked on every platform.');
    }
  },
  {
    id: 'INTUNE-AUTODISC-001',
    area: 'intune',
    needs: ['enrollmentConfigs', '?autopilotProfiles'],
    evaluate: (d) => {
      const auto = (d.enrollmentConfigs || []).some(c => /deviceEnrollmentWindowsAutoEnrollment/i.test(c['@odata.type'] || ''));
      const ap = (d.autopilotProfiles || []).length;
      if (auto || ap) return pass(`${auto ? 'Windows automatic MDM enrolment is configured' : ''}${auto && ap ? '; ' : ''}${ap ? `${ap} Autopilot deployment profile${ap === 1 ? '' : 's'} defined` : ''}.`);
      return fail('Neither automatic MDM enrolment nor Autopilot is configured, so devices are not discovered and enrolled automatically.');
    }
  },
  {
    id: 'INTUNE-INVENTORY-001',
    area: 'intune',
    needs: ['managedDeviceOverview', 'deviceCategories'],
    evaluate: (d) => {
      const enrolled = d.managedDeviceOverview?.enrolledDeviceCount ?? 0;
      const cats = (d.deviceCategories || []).length;
      if (enrolled === 0) return fail('No devices are enrolled in Intune, so it cannot serve as the device inventory.');
      if (cats === 0) return warn(`${enrolled} devices enrolled but no device categories are defined.`);
      return pass(`${enrolled} devices enrolled across ${cats} device categor${cats === 1 ? 'y' : 'ies'}.`);
    }
  },
  {
    id: 'INTUNE-MOBILEENCRYPT-001',
    area: 'intune',
    needs: ['compliancePolicies'],
    evaluate: (d) => {
      const mobile = (d.compliancePolicies || []).filter(p => /iosCompliancePolicy|android(DeviceOwner|WorkProfile)?CompliancePolicy/i.test(p['@odata.type'] || ''));
      if (!mobile.length) return fail('No iOS or Android compliance policy exists, so mobile encryption is not enforced.');
      const weak = mobile.filter(p => p.storageRequireEncryption !== true);
      return weak.length ? fail(`${weak.length} of ${mobile.length} mobile compliance policies do not require encryption: ${weak.map(p => p.displayName).slice(0, 3).join(', ')}.`)
                         : pass(`All ${mobile.length} mobile compliance policies require device encryption.`);
    }
  },
  {
    id: 'INTUNE-REMOVABLEMEDIA-001',
    area: 'intune',
    needs: ['deviceConfigs'],
    evaluate: (d) => assignedProfile(d.deviceConfigs,
      p => /windows10GeneralConfiguration/i.test(p['@odata.type'] || '') && p.storageBlockRemovableStorage === true,
      'Removable storage is blocked', 'No profile blocks removable storage on managed Windows devices.')
  },
  {
    id: 'INTUNE-PORTSTORAGE-001',
    area: 'intune',
    needs: ['deviceConfigs'],
    evaluate: (d) => assignedProfile(d.deviceConfigs,
      p => /windows10GeneralConfiguration/i.test(p['@odata.type'] || '') && (p.usbBlocked === true || p.storageBlockRemovableStorage === true),
      'USB or removable storage is blocked', 'No profile blocks USB or removable storage on managed Windows devices.')
  },
  {
    id: 'INTUNE-FIPS-001',
    area: 'intune',
    needs: ['deviceConfigs'],
    evaluate: (d) => {
      const configs = d.deviceConfigs || [];
      let found = null, disabled = null, hinted = null;
      for (const c of configs) {
        const t = c['@odata.type'] || '';
        if (/windows10CustomConfiguration/i.test(t)) {
          for (const s of (c.omaSettings || [])) {
            if (/Cryptography\/AllowFipsAlgorithmPolicy/i.test(s.omaUri || '')) {
              const on = s.value === 1 || s.value === '1' || s.value === true;
              if (on) found = c; else disabled = c;
            }
          }
        } else if (/windows10EndpointProtectionConfiguration/i.test(t) && /FIPS|Cryptograph/i.test(c.displayName || '')) {
          hinted = c;
        }
      }
      if (found) return pass(`FIPS algorithm policy is enforced by "${found.displayName}".`);
      if (disabled) return fail(`"${disabled.displayName}" sets AllowFipsAlgorithmPolicy to 0.`);
      if (hinted) return warn(`"${hinted.displayName}" suggests FIPS but the OMA-URI setting could not be confirmed.`);
      return fail('No configuration profile enforces FIPS-validated cryptography.');
    }
  },
  {
    id: 'INTUNE-APPCONTROL-001',
    area: 'intune',
    needs: ['deviceConfigs'],
    evaluate: (d) => {
      const configs = d.deviceConfigs || [];
      const hits = configs.filter(c => {
        const t = c['@odata.type'] || '';
        if (/windows10CustomConfiguration/i.test(t)) return (c.omaSettings || []).some(s => /ApplicationControl|AppLocker|CodeIntegrity/i.test(s.omaUri || ''));
        if (/windows10EndpointProtectionConfiguration/i.test(t)) return !!(c.applicationGuardEnabled || c.smartScreenEnableInShell || c.defenderSecurityCenterDisableAppBrowserUI === false);
        return false;
      });
      return hits.length ? pass(`Application control is configured by ${hits.length} profile${hits.length === 1 ? '' : 's'}: ${hits.map(c => c.displayName).slice(0, 3).join(', ')}.`)
                         : fail('No configuration profile applies application control (AppLocker, WDAC or Code Integrity).');
    }
  },
  {
    id: 'INTUNE-REMOTEVPN-001',
    area: 'intune',
    needs: ['deviceConfigs'],
    evaluate: (d) => assignedProfile(d.deviceConfigs,
      p => /windows10VpnConfiguration/i.test(p['@odata.type'] || '') && p.alwaysOn === true && p.enableSplitTunneling === false,
      'Always-On VPN without split tunnelling is configured', 'No Always-On VPN profile (with split tunnelling disabled) is configured.')
  },
  {
    id: 'INTUNE-VPNCONFIG-001',
    area: 'intune',
    needs: ['deviceConfigs'],
    evaluate: (d) => assignedProfile(d.deviceConfigs,
      p => /windows10VpnConfiguration/i.test(p['@odata.type'] || '') && p.enableSplitTunneling === false,
      'VPN split tunnelling is prevented', 'No VPN profile disables split tunnelling.')
  },
  {
    id: 'INTUNE-WIFI-001',
    area: 'intune',
    needs: ['deviceConfigs'],
    evaluate: (d) => assignedProfile(d.deviceConfigs,
      p => /windowsWifiEnterpriseEAPConfiguration/i.test(p['@odata.type'] || '') && p.eapType === 'eapTls' && p.wifiSecurityType === 'wpa2Enterprise',
      'Enterprise Wi-Fi with EAP-TLS and WPA2-Enterprise is configured', 'No Wi-Fi profile enforces EAP-TLS with WPA2-Enterprise.')
  },
  // =====================================================================================
  // Applications & service principals
  // =====================================================================================
  {
    id: 'ENTRA-APPREG-001',
    area: 'privileged',
    needs: ['authorizationPolicy'],
    evaluate: (d) => {
      const v = d.authorizationPolicy?.defaultUserRolePermissions?.allowedToCreateApps;
      if (v === undefined || v === null) return unknown('App registration permission not returned.');
      return v ? fail('Any user can register applications.') : pass('Only administrators can register applications.');
    }
  },
  {
    id: 'ENTRA-APPS-001',
    area: 'privileged',
    needs: ['authorizationPolicy'],
    evaluate: (d) => {
      const v = d.authorizationPolicy?.defaultUserRolePermissions?.allowedToCreateApps;
      if (v === undefined || v === null) return unknown('App registration permission not returned.');
      return v ? fail('Users can integrate third-party applications by registering them.') : pass('Users cannot register third-party applications.');
    }
  },
  {
    id: 'ENTRA-APPREG-002',
    area: 'privileged',
    needs: ['applications'],
    evaluate: (d) => {
      const hits = (d.applications || []).filter(a => redirectUris(a).some(u => /localhost|127\.0\.0\.1|\[::1\]/i.test(u)));
      return hits.length ? warn(`${hits.length} app registration${hits.length === 1 ? ' has' : 's have'} localhost redirect URIs: ${names(hits)}.`)
                         : pass('No app registration has a localhost redirect URI.');
    }
  },
  {
    id: 'ENTRA-APPREG-003',
    area: 'privileged',
    needs: ['applications'],
    evaluate: (d) => {
      const hits = (d.applications || []).filter(a => redirectUris(a, false).some(u => /^http:\/\//i.test(u) && !/localhost|127\.0\.0\.1/i.test(u)));
      return hits.length ? fail(`${hits.length} app registration${hits.length === 1 ? ' has' : 's have'} plain-HTTP redirect URIs: ${names(hits)}.`)
                         : pass('No app registration uses a plain-HTTP redirect URI.');
    }
  },
  {
    id: 'ENTRA-APPREG-004',
    area: 'privileged',
    needs: ['applications'],
    evaluate: (d) => {
      const hits = (d.applications || []).filter(a => redirectUris(a, false).some(u => u.includes('*')));
      return hits.length ? fail(`${hits.length} app registration${hits.length === 1 ? ' has' : 's have'} wildcard redirect URIs: ${names(hits)}.`)
                         : pass('No app registration uses a wildcard redirect URI.');
    }
  },
  {
    id: 'ENTRA-ENTAPP-021',
    area: 'privileged',
    needs: ['applications'],
    evaluate: (d) => {
      const hits = (d.applications || []).filter(a => ['AzureADMultipleOrgs', 'AzureADandPersonalMicrosoftAccount'].includes(a.signInAudience));
      return hits.length ? unknown(`${hits.length} multi-tenant app registration${hits.length === 1 ? '' : 's'}: ${names(hits)}. Review that each is intended to be used from other tenants.`)
                         : pass('No app registration is multi-tenant.');
    }
  },
  {
    id: 'ENTRA-ENTAPP-001',
    area: 'privileged',
    needs: ['servicePrincipals'],
    evaluate: (d) => {
      const apps = regularApps(d).filter(sp => sp.accountEnabled === true && hasCreds(sp));
      if (!apps.length) return pass('No enabled application holds a secret or certificate.');
      return apps.length > 10
        ? warn(`${apps.length} enabled applications hold secrets or certificates. Review whether each still needs a credential.`)
        : pass(`${apps.length} enabled application${apps.length === 1 ? '' : 's'} hold${apps.length === 1 ? 's' : ''} a secret or certificate.`);
    }
  },
  {
    id: 'ENTRA-ENTAPP-002',
    area: 'privileged',
    needs: ['servicePrincipals', 'spSignIns'],
    evaluate: (d) => {
      const cutoff = Date.now() - 90 * 86400000;
      const seen = new Map((d.spSignIns || []).map(s => [s.id, s.signInActivity?.lastSignInDateTime]));
      const hits = regularApps(d).filter(sp => sp.accountEnabled === true && hasCreds(sp))
        .filter(sp => { const t = seen.get(sp.id); return !t || Date.parse(t) < cutoff; });
      return hits.length ? fail(`${hits.length} credentialed app${hits.length === 1 ? '' : 's'} with no sign-in in 90 days: ${names(hits)}. Unused credentials are pure exposure.`)
                         : pass('Every credentialed application has signed in within 90 days.');
    }
  },
  {
    id: 'ENTRA-ENTAPP-003',
    area: 'privileged',
    needs: ['servicePrincipals', 'graphAppRoles', 'organization', 'appTiers'],
    evaluate: (d) => {
      const hits = [];
      for (const sp of thirdPartyForeign(d)) for (const p of appPerms(d, sp)) if (d.appTiers.tier0.includes(p)) hits.push(`${sp.displayName}: ${p}`);
      return hits.length ? fail(`${hits.length} Tier 0 permission${hits.length === 1 ? '' : 's'} granted to third-party apps: ${list(hits)}.`)
                         : pass('No third-party application holds a Tier 0 application permission.');
    }
  },
  {
    id: 'ENTRA-ENTAPP-011',
    area: 'privileged',
    needs: ['servicePrincipals', 'graphAppRoles', 'organization', 'appTiers'],
    evaluate: (d) => {
      const hits = [];
      for (const sp of thirdPartyForeign(d)) for (const p of appPerms(d, sp)) if (d.appTiers.tier1.includes(p)) hits.push(`${sp.displayName}: ${p}`);
      return hits.length ? warn(`${hits.length} Tier 1 data-access permission${hits.length === 1 ? '' : 's'} granted to third-party apps: ${list(hits)}.`)
                         : pass('No third-party application holds Tier 1 mail, file or site permissions.');
    }
  },
  {
    id: 'ENTRA-ENTAPP-004',
    area: 'privileged',
    needs: ['servicePrincipals', 'oauth2Grants', 'organization', 'appTiers'],
    evaluate: (d) => {
      const dangerous = ['Directory.ReadWrite.All', 'RoleManagement.ReadWrite.Directory', 'Mail.ReadWrite', 'Files.ReadWrite.All', 'User.ReadWrite.All', 'AppRoleAssignment.ReadWrite.All'];
      const hits = [];
      for (const sp of thirdPartyForeign(d)) {
        for (const g of (d.oauth2Grants || []).filter(g => g.clientId === sp.id)) {
          for (const s of String(g.scope || '').split(/\s+/)) if (dangerous.includes(s)) hits.push(`${sp.displayName}: ${s}`);
        }
      }
      return hits.length ? fail(`${hits.length} dangerous delegated permission${hits.length === 1 ? '' : 's'} consented to third-party apps: ${list(hits)}.`)
                         : pass('No third-party application holds a dangerous delegated permission.');
    }
  },
  {
    id: 'ENTRA-ENTAPP-005',
    area: 'privileged',
    needs: ['servicePrincipals', 'roleAssignments', 'organization', 'appTiers'],
    evaluate: (d) => {
      const hits = thirdPartyForeign(d).filter(sp => roleCount(d, sp.id) > 0).map(sp => `${sp.displayName} (${roleCount(d, sp.id)} role${roleCount(d, sp.id) === 1 ? '' : 's'})`);
      return hits.length ? fail(`${hits.length} third-party app${hits.length === 1 ? '' : 's'} hold Entra directory roles: ${list(hits)}.`)
                         : pass('No third-party application holds an Entra directory role.');
    }
  },
  {
    id: 'ENTRA-ENTAPP-006',
    area: 'privileged',
    needs: ['servicePrincipals', 'graphAppRoles'],
    evaluate: (d) => {
      const hits = regularApps(d).filter(sp => sp.accountEnabled === true && appRoleCount(d, sp.id) > 10).map(sp => `${sp.displayName} (${appRoleCount(d, sp.id)})`);
      return hits.length ? warn(`${hits.length} app${hits.length === 1 ? '' : 's'} hold more than ten application permissions: ${list(hits)}.`)
                         : pass('No application holds more than ten application permissions.');
    }
  },
  {
    id: 'ENTRA-ENTAPP-007',
    area: 'privileged',
    needs: ['appManagementPolicy'],
    evaluate: (d) => {
      const on = d.appManagementPolicy?.isEnabled;
      if (on === undefined || on === null) return unknown('Default app management policy not returned.');
      return on ? pass('The default app management policy is enabled.') : warn('No default app management policy is enforced, so credential lifetime and property locks are not controlled.');
    }
  },
  {
    id: 'ENTRA-ENTAPP-008',
    area: 'privileged',
    needs: ['servicePrincipals', 'graphAppRoles', 'appTiers'],
    evaluate: (d) => {
      const all = [...d.appTiers.tier0, ...d.appTiers.tier1];
      const hits = [];
      for (const mi of managedIdentities(d)) for (const p of appPerms(d, mi)) if (all.includes(p)) hits.push(`${mi.displayName}: ${p}`);
      return hits.length ? fail(`${hits.length} dangerous permission${hits.length === 1 ? '' : 's'} on managed identities: ${list(hits)}.`)
                         : pass('No managed identity holds a dangerous application permission.');
    }
  },
  {
    id: 'ENTRA-ENTAPP-009',
    area: 'privileged',
    needs: ['servicePrincipals', 'roleAssignments'],
    evaluate: (d) => {
      const hits = managedIdentities(d).filter(mi => roleCount(d, mi.id) > 0).map(mi => `${mi.displayName} (${roleCount(d, mi.id)})`);
      return hits.length ? warn(`${hits.length} managed identit${hits.length === 1 ? 'y holds' : 'ies hold'} Entra directory roles: ${list(hits)}.`)
                         : pass('No managed identity holds an Entra directory role.');
    }
  },
  {
    id: 'ENTRA-ENTAPP-010',
    area: 'privileged',
    needs: ['servicePrincipals', 'graphAppRoles', 'organization', 'appTiers'],
    evaluate: (d) => {
      const tid = tenantId(d);
      const hits = [];
      for (const sp of (d.servicePrincipals || []).filter(sp => sp.appOwnerOrganizationId === tid && sp.servicePrincipalType !== 'ManagedIdentity')) {
        for (const p of appPerms(d, sp)) if (d.appTiers.tier0.includes(p)) hits.push(`${sp.displayName}: ${p}`);
      }
      return hits.length ? warn(`${hits.length} Tier 0 permission${hits.length === 1 ? '' : 's'} held by your own apps — each is a Global Administrator escalation path: ${list(hits)}.`)
                         : pass('No internal application holds a Tier 0 permission.');
    }
  },
  {
    id: 'ENTRA-ENTAPP-012',
    area: 'privileged',
    needs: ['servicePrincipals'],
    evaluate: (d) => {
      const hits = regularApps(d).filter(sp => sp.accountEnabled === true && (sp.passwordCredentials || []).length && !(sp.keyCredentials || []).length);
      return hits.length ? warn(`${hits.length} app${hits.length === 1 ? '' : 's'} authenticate with client secrets only: ${names(hits)}. Certificates are harder to leak.`)
                         : pass('No enabled application relies solely on a client secret.');
    }
  },
  {
    id: 'ENTRA-ENTAPP-013',
    area: 'privileged',
    needs: ['servicePrincipals'],
    evaluate: (d) => {
      const now = Date.now();
      const expired = c => c?.endDateTime && Date.parse(c.endDateTime) < now;
      const hits = regularApps(d).filter(sp => (sp.passwordCredentials || []).some(expired) || (sp.keyCredentials || []).some(expired));
      return hits.length ? warn(`${hits.length} app${hits.length === 1 ? '' : 's'} still carr${hits.length === 1 ? 'ies' : 'y'} expired credentials: ${names(hits)}.`)
                         : pass('No application carries an expired credential.');
    }
  },
  {
    id: 'ENTRA-ENTAPP-014',
    area: 'privileged',
    needs: ['servicePrincipals'],
    evaluate: (d) => {
      const hits = regularApps(d).filter(sp => (sp.passwordCredentials || []).length && (sp.keyCredentials || []).length);
      return hits.length ? warn(`${hits.length} app${hits.length === 1 ? '' : 's'} hold both a secret and a certificate: ${names(hits)}. Retire the secret.`)
                         : pass('No application holds both credential types.');
    }
  },
  {
    id: 'ENTRA-ENTAPP-015',
    area: 'privileged',
    needs: ['servicePrincipals', 'roleAssignments'],
    evaluate: (d) => {
      const hits = regularApps(d).filter(sp => (sp.passwordCredentials || []).length && roleCount(d, sp.id) > 0).map(sp => `${sp.displayName} (${roleCount(d, sp.id)} role${roleCount(d, sp.id) === 1 ? '' : 's'})`);
      return hits.length ? fail(`${hits.length} service principal${hits.length === 1 ? '' : 's'} combine a client secret with a permanent directory role: ${list(hits)}. A leaked secret is a leaked admin.`)
                         : pass('No service principal combines a client secret with a directory role.');
    }
  },
  {
    id: 'ENTRA-ENTAPP-016',
    area: 'privileged',
    needs: ['servicePrincipals', 'graphAppRoles', 'spOwners', 'appTiers'],
    evaluate: (d) => {
      const hits = regularApps(d).filter(sp => appPerms(d, sp).some(p => d.appTiers.tier0.includes(p)) && owners(d, sp.id).length)
        .map(sp => `${sp.displayName} (owners: ${owners(d, sp.id).map(o => o.displayName || o.id).join(', ')})`);
      return hits.length ? fail(`${hits.length} Tier 0 app${hits.length === 1 ? '' : 's'} have owners who can add credentials and impersonate them: ${list(hits)}.`)
                         : pass('No Tier 0 application has owners assigned.');
    }
  },
  {
    id: 'ENTRA-ENTAPP-017',
    area: 'privileged',
    needs: ['servicePrincipals', 'roleAssignments', 'spOwners'],
    evaluate: (d) => {
      const hits = regularApps(d).filter(sp => roleCount(d, sp.id) > 0 && owners(d, sp.id).length)
        .map(sp => `${sp.displayName} (owners: ${owners(d, sp.id).map(o => o.displayName || o.id).join(', ')})`);
      return hits.length ? warn(`${hits.length} role-holding app${hits.length === 1 ? '' : 's'} have owners: ${list(hits)}.`)
                         : pass('No application holding a directory role has owners assigned.');
    }
  },
  {
    id: 'ENTRA-ENTAPP-018',
    area: 'privileged',
    needs: ['servicePrincipals', 'spOwners'],
    evaluate: (d) => {
      const hits = regularApps(d).filter(sp => hasCreds(sp) && !owners(d, sp.id).length);
      return hits.length ? warn(`${hits.length} credentialed app${hits.length === 1 ? ' has' : 's have'} no owner: ${names(hits)}. Nobody is accountable for rotating them.`)
                         : pass('Every credentialed application has at least one owner.');
    }
  },
  {
    id: 'ENTRA-ENTAPP-019',
    area: 'privileged',
    needs: ['servicePrincipals', 'graphAppRoles', 'spSignIns', 'appTiers'],
    evaluate: (d) => {
      const seen = new Map((d.spSignIns || []).map(s => [s.id, s.signInActivity?.lastSignInDateTime]));
      // Microsoft's first-party apps hold Tier 0 permissions by design and their activity is not
      // yours to remove; only apps you could actually retire are findings here.
      const hits = regularApps(d).filter(sp => !isFirstParty(d, sp) && appPerms(d, sp).some(p => d.appTiers.tier0.includes(p)) && !seen.get(sp.id));
      return hits.length ? warn(`${hits.length} Tier 0 app${hits.length === 1 ? '' : 's'} show no sign-in activity: ${names(hits)}. Unused privilege should be removed.`)
                         : pass('Every Tier 0 application shows sign-in activity.');
    }
  },
  {
    id: 'ENTRA-ENTAPP-020',
    area: 'privileged',
    needs: ['servicePrincipals', 'organization', 'appTiers'],
    evaluate: (d) => {
      const ms = ['Microsoft Teams', 'Microsoft Graph', 'Microsoft Office', 'Microsoft Azure', 'Microsoft Intune', 'Microsoft Exchange', 'Microsoft SharePoint', 'Microsoft Outlook', 'Microsoft OneDrive', 'Microsoft Defender'];
      const hits = thirdPartyForeign(d).filter(sp => ms.some(n => sp.displayName === n || (sp.displayName || '').startsWith(n + ' ')));
      return hits.length ? fail(`${hits.length} third-party app${hits.length === 1 ? '' : 's'} use Microsoft product names: ${hits.map(sp => `${sp.displayName} (${sp.appId})`).slice(0, 3).join('; ')}. Classic consent-phishing lure.`)
                         : pass('No third-party application impersonates a Microsoft product name.');
    }
  },

  // =====================================================================================
  // Privileged Identity Management
  // =====================================================================================
  {
    id: 'ENTRA-PIM-001',
    area: 'privileged',
    needs: ['globalAdmins', 'gaEligible'],
    evaluate: (d) => {
      const eligible = new Set((d.gaEligible || []).map(e => e.principalId));
      const permanent = (d.globalAdmins || []).filter(m => !eligible.has(m.id));
      if (!permanent.length) return pass(`All ${(d.globalAdmins || []).length} Global Administrators are PIM-eligible rather than permanently assigned.`);
      return fail(`${permanent.length} permanent Global Administrator assignment${permanent.length === 1 ? '' : 's'}: ${permanent.map(m => m.userPrincipalName || m.displayName).slice(0, 5).join(', ')}. Use PIM eligibility so privilege is activated, not standing.`);
    }
  },
  {
    id: 'ENTRA-PIM-002',
    area: 'privileged',
    needs: ['accessReviews'],
    evaluate: (d) => {
      const hits = (d.accessReviews || []).filter(r => /guest/i.test(`${r.displayName} ${r.scope?.query || ''} ${r.scope?.queryType || ''}`) || /userType eq 'Guest'/i.test(r.scope?.query || ''));
      return hits.length ? pass(`${hits.length} access review${hits.length === 1 ? '' : 's'} cover guest users.`)
                         : fail('No access review targets guest users.');
    }
  },
  {
    id: 'ENTRA-PIM-003',
    area: 'privileged',
    needs: ['accessReviews'],
    evaluate: (d) => {
      const hits = (d.accessReviews || []).filter(r => /roleManagement|directoryRole/i.test(r.scope?.query || '') || /role/i.test(r.scope?.queryType || ''));
      return hits.length ? pass(`${hits.length} access review${hits.length === 1 ? '' : 's'} cover privileged roles.`)
                         : fail('No access review targets privileged directory roles.');
    }
  },
  {
    id: 'ENTRA-PIM-004',
    area: 'privileged',
    needs: ['pimPolicyGA'],
    evaluate: (d) => {
      const r = pimRule(d.pimPolicyGA, 'Approval_EndUser_Assignment');
      if (!r) return unknown('Global Administrator activation policy not returned. PIM requires Entra ID P2.');
      return r.setting?.isApprovalRequired ? pass('Global Administrator activation requires approval.') : fail('Global Administrator can be activated without approval.');
    }
  },
  {
    id: 'ENTRA-PIM-005',
    area: 'privileged',
    needs: ['pimPolicyPRA'],
    evaluate: (d) => {
      const r = pimRule(d.pimPolicyPRA, 'Approval_EndUser_Assignment');
      if (!r) return unknown('Privileged Role Administrator activation policy not returned. PIM requires Entra ID P2.');
      return r.setting?.isApprovalRequired ? pass('Privileged Role Administrator activation requires approval.') : fail('Privileged Role Administrator can be activated without approval.');
    }
  },
  {
    id: 'ENTRA-PIM-006',
    area: 'privileged',
    needs: ['pimPolicyGA'],
    evaluate: (d) => {
      const r = pimRule(d.pimPolicyGA, 'Expiration_EndUser_Assignment');
      if (!r) return unknown('Global Administrator activation policy not returned. PIM requires Entra ID P2.');
      const h = isoHours(r.maximumDuration);
      if (h === null) return unknown(`Activation duration "${r.maximumDuration}" could not be read.`);
      return h <= 4 ? pass(`Global Administrator activations last at most ${h} hours.`) : warn(`Global Administrator activations can last ${h} hours; 4 or fewer is recommended.`);
    }
  },
  {
    id: 'ENTRA-PIM-007',
    area: 'privileged',
    needs: ['pimPolicyGA'],
    evaluate: (d) => {
      const r = pimRule(d.pimPolicyGA, 'Enablement_EndUser_Assignment');
      if (!r) return unknown('Global Administrator activation policy not returned. PIM requires Entra ID P2.');
      return (r.enabledRules || []).includes('Justification') ? pass('Justification is required to activate Global Administrator.') : warn('Global Administrator can be activated without a justification.');
    }
  },
  {
    id: 'ENTRA-PIM-008',
    area: 'privileged',
    needs: ['pimPolicyGA'],
    evaluate: (d) => {
      const r = pimRule(d.pimPolicyGA, 'Enablement_EndUser_Assignment');
      if (!r) return unknown('Global Administrator activation policy not returned. PIM requires Entra ID P2.');
      return (r.enabledRules || []).includes('MultiFactorAuthentication') ? pass('MFA is required to activate Global Administrator.') : fail('Global Administrator can be activated without MFA.');
    }
  },
  {
    id: 'ENTRA-PIM-009',
    area: 'privileged',
    needs: ['pimPolicyGA'],
    evaluate: (d) => {
      const r = pimRule(d.pimPolicyGA, 'Expiration_Admin_Eligibility');
      if (!r) return unknown('Global Administrator assignment policy not returned. PIM requires Entra ID P2.');
      return r.isExpirationRequired ? pass(`Eligible Global Administrator assignments expire (maximum ${isoHours(r.maximumDuration) !== null ? Math.round(isoHours(r.maximumDuration) / 24) + ' days' : r.maximumDuration}).`)
                                    : fail('Eligible Global Administrator assignments can be permanent.');
    }
  },
  {
    id: 'ENTRA-PIM-010',
    area: 'privileged',
    needs: ['pimPolicyGA'],
    evaluate: (d) => {
      const r = pimRule(d.pimPolicyGA, 'Notification_Admin_EndUser_Assignment');
      if (!r) return unknown('Global Administrator notification policy not returned. PIM requires Entra ID P2.');
      const on = r.isDefaultRecipientsEnabled || (r.notificationRecipients || []).length > 0;
      return on ? pass('Administrators are notified when Global Administrator is activated.') : warn('Nobody is notified when Global Administrator is activated.');
    }
  }
,

  // =====================================================================================
  // Microsoft security signals
  // =====================================================================================
  {
    id: 'DEFENDER-SECUREMON-001',
    area: 'signals',
    needs: ['secureScores'],
    evaluate: (d) => {
      const latest = (d.secureScores || [])[0];
      if (!latest) return fail('No Secure Score has been computed for this tenant, so nothing is monitoring its posture.');
      const days = Math.floor((Date.now() - Date.parse(latest.createdDateTime)) / 86400000);
      const pct = latest.maxScore ? Math.round((latest.currentScore / latest.maxScore) * 100) : 0;
      return days <= 7
        ? pass(`Secure Score is ${pct}% and was updated ${days === 0 ? 'today' : days + ' day' + (days === 1 ? '' : 's') + ' ago'}.`)
        : warn(`Secure Score was last updated ${days} days ago; it should refresh within 7.`);
    }
  },
  {
    id: 'DEFENDER-SECURESCORE-001',
    area: 'signals',
    needs: ['secureScores'],
    evaluate: (d) => {
      const latest = (d.secureScores || [])[0];
      if (!latest || !latest.maxScore) return unknown('Secure Score not returned.');
      const pct = Math.round((latest.currentScore / latest.maxScore) * 100);
      const line = `Microsoft Secure Score is ${Math.round(latest.currentScore * 10) / 10} of ${latest.maxScore} (${pct}%).`;
      if (pct >= 70) return pass(line);
      if (pct >= 40) return warn(`${line} 70% or better is the common target.`);
      return fail(`${line} Below 40% leaves most of Microsoft\'s recommended controls unimplemented.`);
    }
  },
  // =====================================================================================
  // Email authentication in public DNS
  // =====================================================================================
  {
    id: 'DNS-SPF-001',
    area: 'dns',
    needs: ['dnsRecords'],
    evaluate: (d) => {
      const gate = dnsGate(d); if (gate) return gate;
      const doms = resolvable(d);
      const missing = doms.filter(x => !x.spf.found);
      if (missing.length) return fail(`${missing.length} of ${doms.length} domain${doms.length === 1 ? '' : 's'} publish no SPF record: ${domList(missing)}. Anyone can send mail claiming to be them.`);
      const permissive = doms.filter(x => /[?+]all\s*$/.test(x.spf.record || ''));
      if (permissive.length) return warn(`All ${doms.length} domains publish SPF, but ${domList(permissive)} end${permissive.length === 1 ? 's' : ''} in "?all" or "+all", which asks receivers to accept mail from anywhere.`);
      const soft = doms.filter(x => /~all\s*$/.test(x.spf.record || ''));
      return soft.length
        ? pass(`All ${doms.length} domain${doms.length === 1 ? '' : 's'} publish SPF; ${domList(soft)} use "~all" (soft fail) rather than "-all".`)
        : pass(`All ${doms.length} domain${doms.length === 1 ? '' : 's'} publish SPF ending in "-all".`);
    }
  },
  {
    id: 'DNS-DMARC-001',
    area: 'dns',
    needs: ['dnsRecords'],
    evaluate: (d) => {
      const gate = dnsGate(d); if (gate) return gate;
      const doms = resolvable(d);
      const missing = doms.filter(x => !x.dmarc.found);
      if (missing.length) return fail(`${missing.length} of ${doms.length} domain${doms.length === 1 ? '' : 's'} publish no DMARC record: ${domList(missing)}. Nothing tells receivers what to do with mail that fails authentication.`);
      const none = doms.filter(x => x.dmarc.policy === 'none');
      if (none.length) return warn(`All ${doms.length} domains publish DMARC, but ${domList(none)} use "p=none" — monitoring only, so spoofed mail is still delivered.`);
      const quarantine = doms.filter(x => x.dmarc.policy === 'quarantine');
      return quarantine.length
        ? pass(`All ${doms.length} domain${doms.length === 1 ? '' : 's'} enforce DMARC; ${domList(quarantine)} at "p=quarantine" rather than "p=reject".`)
        : pass(`All ${doms.length} domain${doms.length === 1 ? '' : 's'} enforce DMARC at "p=reject".`);
    }
  },
  {
    id: 'DNS-DKIM-001',
    area: 'dns',
    needs: ['dnsRecords'],
    evaluate: (d) => {
      const gate = dnsGate(d); if (gate) return gate;
      const doms = resolvable(d);
      const missing = doms.filter(x => !x.dkim.found);
      // Published selectors prove the DNS half. Whether Exchange actually signs with them is
      // EXO-DKIM-001, which needs the Exchange evidence file.
      return missing.length
        ? fail(`${missing.length} of ${doms.length} domain${doms.length === 1 ? '' : 's'} publish no DKIM selector records: ${domList(missing)}.`)
        : pass(`All ${doms.length} domain${doms.length === 1 ? '' : 's'} publish DKIM selector records. Whether signing is switched on in Exchange is reported separately.`);
    }
  },
  {
    id: 'DNS-MX-001',
    area: 'dns',
    needs: ['dnsRecords'],
    evaluate: (d) => {
      const gate = dnsGate(d); if (gate) return gate;
      const doms = resolvable(d);
      const missing = doms.filter(x => !x.mx.found);
      if (missing.length) return fail(`${missing.length} of ${doms.length} domain${doms.length === 1 ? '' : 's'} publish no MX record: ${domList(missing)}.`);
      const elsewhere = doms.filter(x => !x.mx.isExchangeOnline);
      return elsewhere.length
        ? unknown(`${domList(elsewhere)} route mail somewhere other than Exchange Online (${elsewhere[0].mx.hosts.slice(0, 2).join(', ')}). If that is a gateway in front of Exchange it is expected; confirm it is intended.`)
        : pass(`All ${doms.length} domain${doms.length === 1 ? '' : 's'} route mail to Exchange Online.`);
    }
  },

  // =====================================================================================
  // Exchange Online — from the evidence file
  // =====================================================================================
  {
    id: 'EXO-AUTH-001',
    area: 'exchange',
    needs: ['exchangeEvidence'],
    evaluate: (d) => fromEvidence(d, 'organizationConfig', (v) => {
      const on = first(v)?.OAuth2ClientProfileEnabled;
      if (on === undefined || on === null) return unknown('Modern authentication setting not returned.');
      return on ? pass('Modern authentication is enabled for Exchange Online.')
                : fail('Modern authentication is disabled, so Outlook can still fall back to basic authentication.');
    })
  },
  {
    id: 'EXO-AUTH-002',
    area: 'exchange',
    needs: ['exchangeEvidence'],
    evaluate: (d) => fromEvidence(d, 'transportConfig', (v) => {
      const off = first(v)?.SmtpClientAuthenticationDisabled;
      if (off === undefined || off === null) return unknown('SMTP AUTH setting not returned.');
      return off ? pass('SMTP AUTH is disabled tenant-wide.')
                 : fail('SMTP AUTH is enabled tenant-wide. It bypasses MFA and is a standard route for compromised-account mail.');
    })
  },
  {
    id: 'EXO-AUDIT-001',
    area: 'exchange',
    needs: ['exchangeEvidence'],
    evaluate: (d) => fromEvidence(d, 'organizationConfig', (v) => {
      const disabled = first(v)?.AuditDisabled;
      if (disabled === undefined || disabled === null) return unknown('Organisation audit setting not returned.');
      return disabled ? fail('Mailbox auditing is disabled for the organisation, so mailbox activity is not recorded.')
                      : pass('Mailbox auditing is enabled for the organisation.');
    })
  },
  {
    id: 'EXO-AUDIT-002',
    area: 'exchange',
    needs: ['exchangeEvidence'],
    evaluate: (d) => fromEvidence(d, 'mailboxAuditBypass', (v) => {
      const list = arr(v);
      return list.length
        ? fail(`${list.length} account${list.length === 1 ? ' bypasses' : 's bypass'} mailbox auditing: ${few(list.map(x => x.Name))}. Their activity is invisible to the audit log.`)
        : pass('No account bypasses mailbox auditing.');
    })
  },
  {
    id: 'EXO-AUDIT-003',
    area: 'exchange',
    needs: ['exchangeEvidence'],
    evaluate: (d) => fromEvidence(d, 'mailboxAuditSample', (v) => {
      const list = arr(v);
      if (!list.length) return unknown('No user mailboxes were returned.');
      const off = list.filter(m => m.AuditEnabled === false);
      return off.length
        ? fail(`${off.length} of ${list.length} sampled mailboxes have auditing switched off: ${few(off.map(m => m.UserPrincipalName))}.`)
        : pass(`All ${list.length} sampled mailboxes have auditing enabled.`);
    })
  },
  {
    id: 'EXO-LOCKBOX-001',
    area: 'exchange',
    needs: ['exchangeEvidence'],
    evaluate: (d) => fromEvidence(d, 'organizationConfig', (v) => {
      const on = first(v)?.CustomerLockBoxEnabled;
      if (on === undefined || on === null) return unknown('Customer Lockbox setting not returned.');
      return on ? pass('Customer Lockbox is enabled, so Microsoft engineers need explicit approval to access content.')
                : warn('Customer Lockbox is disabled. It requires E5 or the compliance add-on; if you hold that licence, enable it.');
    })
  },
  {
    id: 'EXO-MAILTIPS-001',
    area: 'exchange',
    needs: ['exchangeEvidence'],
    evaluate: (d) => fromEvidence(d, 'organizationConfig', (v) => {
      const c = first(v) || {};
      if (c.MailTipsAllTipsEnabled === undefined || c.MailTipsAllTipsEnabled === null) return unknown('MailTips settings not returned.');
      const off = [
        !c.MailTipsAllTipsEnabled && 'all tips',
        !c.MailTipsExternalRecipientsTipsEnabled && 'external recipient tips',
        !c.MailTipsGroupMetricsEnabled && 'group metrics'
      ].filter(Boolean);
      return off.length
        ? warn(`MailTips are partly off (${off.join(', ')}), so users get less warning before mailing outside the organisation.`)
        : pass('MailTips are enabled, including external recipient warnings.');
    })
  },
  {
    id: 'EXO-EXTTAG-001',
    area: 'exchange',
    needs: ['exchangeEvidence'],
    evaluate: (d) => fromEvidence(d, 'externalInOutlook', (v) => {
      const on = first(v)?.Enabled;
      if (on === undefined || on === null) return unknown('External sender identification setting not returned.');
      return on ? pass('Mail from outside the organisation is tagged as external in Outlook.')
                : warn('External senders are not tagged in Outlook, removing a visual cue users rely on to spot impersonation.');
    })
  },
  {
    id: 'EXO-FORWARD-001',
    area: 'exchange',
    needs: ['exchangeEvidence'],
    evaluate: (d) => fromEvidence(d, 'remoteDomains', (v) => {
      const def = arr(v).find(x => x.IsDefault) || first(v);
      if (!def || def.AutoForwardEnabled === undefined || def.AutoForwardEnabled === null) return unknown('Default remote domain not returned.');
      return def.AutoForwardEnabled
        ? fail('Automatic forwarding to external addresses is allowed on the default remote domain — the usual way data leaves after an account is compromised.')
        : pass('Automatic forwarding to external addresses is blocked on the default remote domain.');
    })
  },
  {
    id: 'EXO-OWA-001',
    area: 'exchange',
    needs: ['exchangeEvidence'],
    evaluate: (d) => fromEvidence(d, 'owaMailboxPolicies', (v) => {
      const list = arr(v);
      if (!list.length) return unknown('No Outlook on the web policies were returned.');
      const open = list.filter(p => p.AdditionalStorageProvidersAvailable);
      return open.length
        ? warn(`${open.length} of ${list.length} Outlook web polic${list.length === 1 ? 'y allows' : 'ies allow'} third-party storage providers (${few(open.map(p => p.Name))}), so attachments can be saved outside the tenant.`)
        : pass('Third-party storage providers are blocked in Outlook on the web.');
    })
  },
  {
    id: 'EXO-ADDINS-001',
    area: 'exchange',
    needs: ['exchangeEvidence'],
    evaluate: (d) => fromEvidence(d, 'roleAssignmentPolicies', (v) => {
      const def = arr(v).find(p => p.IsDefault) || first(v);
      if (!def) return unknown('No default role assignment policy was returned.');
      const roles = arr(def.AssignedRoles).map(String);
      const addin = roles.filter(r => /My (Marketplace|Custom|ReadWriteMailbox) Apps|MyBaseOptions/i.test(r));
      return addin.length
        ? warn(`Users can install their own Outlook add-ins (${addin.join(', ')}). An add-in can read mail as the user.`)
        : pass('Users cannot install their own Outlook add-ins.');
    })
  },
  {
    id: 'EXO-SHARING-001',
    area: 'exchange',
    needs: ['exchangeEvidence'],
    evaluate: (d) => fromEvidence(d, 'sharingPolicies', (v) => {
      const def = arr(v).find(p => p.Default) || first(v);
      if (!def) return unknown('No default sharing policy was returned.');
      const domains = arr(def.Domains).map(String);
      const anyone = domains.some(x => x.includes('*'));
      return anyone
        ? warn(`Calendar details can be shared with anyone (${domains.join(', ')}). Restrict sharing to named partner domains.`)
        : pass('Calendar sharing is restricted to named domains.');
    })
  },
  {
    id: 'EXO-CONNFILTER-001',
    area: 'exchange',
    needs: ['exchangeEvidence'],
    evaluate: (d) => fromEvidence(d, 'hostedConnectionFilterPolicies', (v) => {
      const def = arr(v).find(p => p.IsDefault) || first(v);
      if (!def) return unknown('No connection filter policy was returned.');
      const ips = arr(def.IPAllowList);
      return ips.length
        ? fail(`${ips.length} IP address${ips.length === 1 ? '' : 'es'} bypass spam filtering entirely: ${ips.slice(0, 5).join(', ')}${ips.length > 5 ? ` and ${ips.length - 5} more` : ''}.`)
        : pass('No IP addresses bypass spam filtering.');
    })
  },
  {
    id: 'EXO-CONNFILTER-002',
    area: 'exchange',
    needs: ['exchangeEvidence'],
    evaluate: (d) => fromEvidence(d, 'hostedConnectionFilterPolicies', (v) => {
      const def = arr(v).find(p => p.IsDefault) || first(v);
      if (!def || def.EnableSafeList === undefined || def.EnableSafeList === null) return unknown('Connection filter safe list setting not returned.');
      return def.EnableSafeList
        ? fail('The connection filter safe list is on, letting a third-party reputation list skip your filtering.')
        : pass('The connection filter safe list is off.');
    })
  },
  {
    id: 'EXO-TRANSPORT-001',
    area: 'exchange',
    needs: ['exchangeEvidence'],
    evaluate: (d) => fromEvidence(d, 'transportRules', (v) => {
      const hits = arr(v).filter(r => Number(r.SetSCL) === -1 && arr(r.SenderDomainIs).length);
      return hits.length
        ? fail(`${hits.length} transport rule${hits.length === 1 ? '' : 's'} skip spam filtering for whole sender domains: ${few(hits.map(r => r.Name))}. Anyone able to spoof those domains reaches the inbox.`)
        : pass('No transport rule whitelists a sender domain past spam filtering.');
    })
  },
  {
    id: 'EXO-TRANSPORT-002',
    area: 'exchange',
    needs: ['exchangeEvidence'],
    evaluate: (d) => fromEvidence(d, 'transportRules', (v) => {
      const targets = (r) => [...arr(r.RedirectMessageTo), ...arr(r.BlindCopyTo), ...arr(r.AddToRecipients), ...arr(r.CopyTo)].map(String);
      const doms = (d.exchangeEvidence?.tenant?.domains || []).map(x => String(x).toLowerCase());
      const external = (a) => a.includes('@') && !doms.some(dom => a.toLowerCase().endsWith('@' + dom));
      const hits = arr(v).filter(r => targets(r).some(external));
      return hits.length
        ? fail(`${hits.length} transport rule${hits.length === 1 ? '' : 's'} copy or redirect mail to addresses outside the tenant: ${few(hits.map(r => r.Name))}.`)
        : pass('No transport rule forwards mail outside the tenant.');
    })
  },
  {
    id: 'EXO-DIRECTSEND-001',
    area: 'exchange',
    needs: ['exchangeEvidence'],
    evaluate: (d) => fromEvidence(d, 'inboundConnectors', (v) => {
      const open = arr(v).filter(c => c.Enabled === true && c.RequireTls === false && c.RestrictDomainsToIPAddresses === false);
      return open.length
        ? fail(`${open.length} inbound connector${open.length === 1 ? '' : 's'} accept unauthenticated relay: ${few(open.map(c => c.Name))}. Anyone can send as your domain through them.`)
        : pass('No inbound connector accepts unauthenticated relay.');
    })
  },
  {
    id: 'EXO-HIDDEN-001',
    area: 'exchange',
    needs: ['exchangeEvidence'],
    evaluate: (d) => fromEvidence(d, 'hiddenMailboxes', (v) => {
      const list = arr(v);
      return list.length
        ? unknown(`${list.length} user mailbox${list.length === 1 ? ' is' : 'es are'} hidden from the address list: ${few(list.map(m => m.PrimarySmtpAddress || m.UserPrincipalName))}. Confirm each is intended.`)
        : pass('No user mailbox is hidden from the global address list.');
    })
  },
  {
    id: 'EXO-DKIM-001',
    area: 'exchange',
    needs: ['exchangeEvidence'],
    evaluate: (d) => fromEvidence(d, 'dkimSigningConfigs', (v) => {
      const list = arr(v).filter(c => !String(c.Domain || '').endsWith('.onmicrosoft.com'));
      if (!list.length) return na('No custom domain has a DKIM signing configuration.');
      const off = list.filter(c => !c.Enabled);
      return off.length
        ? fail(`DKIM signing is switched off for ${off.length} of ${list.length} domain${list.length === 1 ? '' : 's'}: ${few(off.map(c => c.Domain))}. Outbound mail is not signed.`)
        : pass(`DKIM signing is enabled for all ${list.length} custom domain${list.length === 1 ? '' : 's'}.`);
    })
  },

  // =====================================================================================
  // Defender for Office 365 and EOP — from the evidence file
  // =====================================================================================
  {
    id: 'EXO-ANTIPHISH-001',
    area: 'exchange',
    needs: ['exchangeEvidence'],
    evaluate: (d) => fromEvidence(d, 'antiPhishPolicies', (v) => {
      const p = arr(v).find(x => x.IsDefault) || first(v);
      if (!p) return fail('No anti-phishing policy exists.');
      const weak = [
        Number(p.PhishThresholdLevel) < 2 && `threshold is ${p.PhishThresholdLevel} (2 or higher recommended)`,
        !p.EnableSpoofIntelligence && 'spoof intelligence is off',
        !p.HonorDmarcPolicy && 'DMARC policy is not honoured',
        !p.EnableMailboxIntelligence && 'mailbox intelligence is off'
      ].filter(Boolean);
      return weak.length
        ? fail(`The anti-phishing policy "${p.Name}" is weakened: ${weak.join('; ')}.`)
        : pass(`The anti-phishing policy "${p.Name}" sets threshold ${p.PhishThresholdLevel} with spoof intelligence, DMARC honouring and mailbox intelligence on.`);
    })
  },
  {
    id: 'DEFENDER-ANTIPHISH-001',
    area: 'exchange',
    needs: ['exchangeEvidence'],
    evaluate: (d) => fromEvidence(d, 'antiPhishPolicies', (v) => {
      const list = arr(v).filter(p => p.Enabled !== false);
      return list.length
        ? pass(`${list.length} anti-phishing polic${list.length === 1 ? 'y is' : 'ies are'} in place.`)
        : fail('No enabled anti-phishing policy exists.');
    })
  },
  {
    id: 'DEFENDER-SAFELINKS-001',
    area: 'exchange',
    needs: ['exchangeEvidence'],
    evaluate: (d) => fromEvidence(d, 'safeLinksPolicies', (v) => {
      const list = arr(v);
      if (!list.length) return fail('No Safe Links policy exists, so URLs in mail and Office documents are not rewritten or checked at click time.');
      const on = list.filter(p => p.IsEnabled !== false);
      if (!on.length) return fail(`${list.length} Safe Links polic${list.length === 1 ? 'y exists but is' : 'ies exist but all are'} disabled.`);
      const gaps = on.filter(p => !p.EnableSafeLinksForEmail || !p.EnableSafeLinksForTeams || !p.EnableSafeLinksForOffice);
      return gaps.length
        ? warn(`${on.length} Safe Links polic${on.length === 1 ? 'y is' : 'ies are'} enabled, but ${few(gaps.map(p => p.Name))} do not cover email, Teams and Office together.`)
        : pass(`${on.length} Safe Links polic${on.length === 1 ? 'y covers' : 'ies cover'} email, Teams and Office.`);
    })
  },
  {
    id: 'DEFENDER-SAFEATTACH-001',
    area: 'exchange',
    needs: ['exchangeEvidence'],
    evaluate: (d) => fromEvidence(d, 'safeAttachmentPolicies', (v) => {
      const list = arr(v);
      if (!list.length) return fail('No Safe Attachments policy exists, so attachments are not detonated before delivery.');
      const on = list.filter(p => p.Enable !== false);
      if (!on.length) return fail(`${list.length} Safe Attachments polic${list.length === 1 ? 'y exists but is' : 'ies exist but all are'} disabled.`);
      const weak = on.filter(p => !['Block', 'Replace', 'DynamicDelivery'].includes(String(p.Action)));
      return weak.length
        ? warn(`${on.length} Safe Attachments polic${on.length === 1 ? 'y is' : 'ies are'} enabled, but ${few(weak.map(p => p.Name))} only monitor rather than block.`)
        : pass(`${on.length} Safe Attachments polic${on.length === 1 ? 'y blocks' : 'ies block'} or replaces malicious attachments.`);
    })
  },
  {
    id: 'DEFENDER-SAFEATTACH-002',
    area: 'exchange',
    needs: ['exchangeEvidence'],
    evaluate: (d) => fromEvidence(d, 'atpPolicyForO365', (v) => {
      const p = first(v);
      if (!p || p.EnableATPForSPOTeamsODB === undefined || p.EnableATPForSPOTeamsODB === null) return unknown('Safe Attachments for SharePoint, OneDrive and Teams setting not returned.');
      return p.EnableATPForSPOTeamsODB
        ? pass('Safe Attachments covers SharePoint, OneDrive and Teams.')
        : fail('Safe Attachments does not cover SharePoint, OneDrive or Teams, so a malicious file uploaded there is not detonated.');
    })
  },
  {
    id: 'DEFENDER-ZAP-001',
    area: 'exchange',
    needs: ['exchangeEvidence'],
    evaluate: (d) => fromEvidence(d, 'hostedContentFilterPolicies', (v) => {
      const p = arr(v).find(x => x.IsDefault) || first(v);
      if (!p) return unknown('No content filter policy was returned.');
      const off = [!p.SpamZapEnabled && 'spam', !p.PhishZapEnabled && 'phishing'].filter(Boolean);
      return off.length
        ? fail(`Zero-hour auto purge is off for ${off.join(' and ')}, so mail found malicious after delivery stays in the inbox.`)
        : pass('Zero-hour auto purge is on for spam and phishing.');
    })
  },
  {
    id: 'DEFENDER-ANTIMALWARE-001',
    area: 'exchange',
    needs: ['exchangeEvidence'],
    evaluate: (d) => fromEvidence(d, 'malwareFilterPolicies', (v) => {
      const p = arr(v).find(x => x.IsDefault) || first(v);
      if (!p) return unknown('No malware filter policy was returned.');
      if (!p.EnableFileFilter) return fail('The common attachment types filter is off, so executable attachments are not blocked by type.');
      const n = arr(p.FileTypes).length;
      return n >= 20
        ? pass(`The common attachment types filter is on, blocking ${n} file types.`)
        : warn(`The common attachment types filter is on but blocks only ${n} file types; the recommended list is longer.`);
    })
  },
  {
    id: 'DEFENDER-ANTIMALWARE-002',
    area: 'exchange',
    needs: ['exchangeEvidence'],
    evaluate: (d) => fromEvidence(d, 'malwareFilterPolicies', (v) => {
      const p = arr(v).find(x => x.IsDefault) || first(v);
      if (!p || p.EnableInternalSenderAdminNotifications === undefined || p.EnableInternalSenderAdminNotifications === null) return unknown('Internal sender notification setting not returned.');
      return p.EnableInternalSenderAdminNotifications
        ? pass('Administrators are notified when an internal user sends malware.')
        : warn('Nobody is notified when an internal user sends malware, so a compromised mailbox can go unnoticed.');
    })
  },
  {
    id: 'EXO-MALWARE-001',
    area: 'exchange',
    needs: ['exchangeEvidence'],
    evaluate: (d) => fromEvidence(d, 'malwareFilterPolicies', (v) => {
      const list = arr(v);
      if (!list.length) return fail('No malware filter policy exists.');
      const p = list.find(x => x.IsDefault) || list[0];
      const weak = [!p.EnableFileFilter && 'attachment type filter off', !p.ZapEnabled && 'zero-hour auto purge off'].filter(Boolean);
      return weak.length
        ? warn(`The malware filter policy "${p.Name}" is weakened: ${weak.join('; ')}.`)
        : pass(`The malware filter policy "${p.Name}" has attachment filtering and auto purge on.`);
    })
  },
  {
    id: 'EXO-ANTISPAM-001',
    area: 'exchange',
    needs: ['exchangeEvidence'],
    evaluate: (d) => fromEvidence(d, 'hostedContentFilterPolicies', (v) => {
      const p = arr(v).find(x => x.IsDefault) || first(v);
      if (!p) return fail('No anti-spam (content filter) policy exists.');
      const quarantines = (a) => ['Quarantine', 'MoveToJmf'].includes(String(a));
      const weak = [
        Number(p.BulkThreshold) > 6 && `bulk threshold is ${p.BulkThreshold} (6 or lower recommended)`,
        String(p.HighConfidencePhishAction) !== 'Quarantine' && `high-confidence phishing is "${p.HighConfidencePhishAction}" rather than quarantined`,
        !quarantines(p.SpamAction) && `spam action is "${p.SpamAction}"`
      ].filter(Boolean);
      return weak.length
        ? warn(`The anti-spam policy "${p.Name}" is weakened: ${weak.join('; ')}.`)
        : pass(`The anti-spam policy "${p.Name}" quarantines high-confidence phishing with a bulk threshold of ${p.BulkThreshold}.`);
    })
  },
  {
    id: 'DEFENDER-ANTISPAM-002',
    area: 'exchange',
    needs: ['exchangeEvidence'],
    evaluate: (d) => fromEvidence(d, 'hostedContentFilterPolicies', (v) => {
      const hits = arr(v).filter(p => arr(p.AllowedSenderDomains).length);
      if (!hits.length) return pass('No inbound anti-spam policy allow-lists a sender domain.');
      const total = hits.reduce((n, p) => n + arr(p.AllowedSenderDomains).length, 0);
      const doms = hits.flatMap(p => arr(p.AllowedSenderDomains).map(x => x.Domain || x));
      return fail(`${total} sender domain${total === 1 ? ' is' : 's are'} allow-listed past spam filtering: ${few(doms)}. Spoofing any of them reaches the inbox.`);
    })
  },
  {
    id: 'DEFENDER-ANTISPAM-001',
    area: 'exchange',
    needs: ['exchangeEvidence'],
    evaluate: (d) => fromEvidence(d, 'hostedOutboundSpamFilterPolicies', (v) => {
      const p = arr(v).find(x => x.IsDefault) || first(v);
      if (!p) return unknown('No outbound spam filter policy was returned.');
      const notify = p.NotifyOutboundSpam || arr(p.NotifyOutboundSpamRecipients).length || p.BccSuspiciousOutboundMail;
      return notify
        ? pass('Administrators are notified when a user sends outbound spam.')
        : warn('Nobody is notified when a user sends outbound spam, which is usually the first sign of a compromised mailbox.');
    })
  },
  {
    id: 'DEFENDER-OUTBOUND-001',
    area: 'exchange',
    needs: ['exchangeEvidence'],
    evaluate: (d) => fromEvidence(d, 'hostedOutboundSpamFilterPolicies', (v) => {
      const p = arr(v).find(x => x.IsDefault) || first(v);
      if (!p) return unknown('No outbound spam filter policy was returned.');
      const mode = String(p.AutoForwardingMode || '');
      const limits = [p.RecipientLimitExternalPerHour, p.RecipientLimitInternalPerHour, p.RecipientLimitPerDay].map(Number);
      if (mode !== 'Off') return fail(`Automatic external forwarding is "${mode}" rather than "Off", so a compromised mailbox can forward mail out silently.`);
      return limits.every(n => n > 0)
        ? pass(`External forwarding is off and outbound recipient limits are set (${limits[0]}/hour external, ${limits[2]}/day).`)
        : warn('External forwarding is off, but outbound recipient limits are not all set.');
    })
  }
];

export const CHECK_IDS = CHECKS.map(c => c.id);
