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
    needs: ['authMethodsPolicy'],
    evaluate: (d) => {
      const s = methodState(d, 'Email');
      if (s === null) return unknown('Email OTP configuration not present in the policy.');
      return s === 'disabled' ? pass('Email OTP is disabled.') : fail('Email OTP is enabled and can be used as an authentication method.');
    }
  },
  {
    id: 'ENTRA-AUTHMETHOD-003',
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
  }
];

export const CHECK_IDS = CHECKS.map(c => c.id);
