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
  { id: 'intune',        label: 'Intune & devices',  summary: 'Enrolment restrictions, compliance thresholds, encryption, removable media, VPN and Wi-Fi profiles.' }
];

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
    url: '/organization',
    scopes: ['Organization.Read.All'],
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
  }
];

export const CHECK_IDS = CHECKS.map(c => c.id);
