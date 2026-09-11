// Mock Graph payloads for two tenants: hardened and default. Shared by the engine and flow tests.

export const res = (body, { status = 200, text = null } = {}) => ({
  ok: status >= 200 && status < 300,
  status,
  headers: { get: () => null },
  json: async () => body,
  text: async () => (text ?? JSON.stringify(body))
});

export const CA = {
  legacyBlock: {
    displayName: 'Block legacy auth', state: 'enabled',
    conditions: { clientAppTypes: ['exchangeActiveSync', 'other'], users: { includeUsers: ['All'] }, applications: { includeApplications: ['All'] } },
    grantControls: { builtInControls: ['block'] }
  },
  mfaAll: {
    displayName: 'MFA for all', state: 'enabled',
    conditions: { clientAppTypes: ['all'], users: { includeUsers: ['All'] }, applications: { includeApplications: ['All'] } },
    grantControls: { builtInControls: ['mfa'] },
    sessionControls: { signInFrequency: { isEnabled: true, value: 12, type: 'hours' } }
  },
  deviceCode: {
    displayName: 'Block device code', state: 'enabled',
    conditions: { users: { includeUsers: ['All'] }, applications: { includeApplications: ['All'] }, authenticationFlows: { transferMethods: 'deviceCodeFlow' } },
    grantControls: { builtInControls: ['block'] }
  },
  signInRisk: {
    displayName: 'Sign-in risk', state: 'enabled',
    conditions: { users: { includeUsers: ['All'] }, applications: { includeApplications: ['All'] }, signInRiskLevels: ['high', 'medium'] },
    grantControls: { builtInControls: ['block'] }
  },
  userRisk: {
    displayName: 'User risk', state: 'enabled',
    conditions: { users: { includeUsers: ['All'] }, applications: { includeApplications: ['All'] }, userRiskLevels: ['high'] },
    grantControls: { builtInControls: ['mfa'] }
  },
  adminMfa: {
    displayName: 'Admin MFA', state: 'enabled',
    conditions: { users: { includeUsers: [], includeRoles: ['62e90394-69f5-4237-9190-012177145e10'] }, applications: { includeApplications: ['All'] } },
    grantControls: { builtInControls: ['mfa'] }
  },
  reportOnly: {
    displayName: 'Pilot policy', state: 'enabledForReportingButNotEnforced',
    conditions: { users: { includeUsers: ['All'] }, applications: { includeApplications: ['All'] } },
    grantControls: { builtInControls: ['mfa'] }
  }
};

export const authMethod = (id, state, extra = {}) => ({ id, state, ...extra });

export const HARDENED = {
  '/organization': { value: [{ displayName: 'Contoso', id: 't1' }] },
  '/policies/identitySecurityDefaultsEnforcementPolicy': { isEnabled: false },
  '/policies/authorizationPolicy': {
    guestUserRoleId: '2af84b1e-32c8-42b7-82bc-daa82404023b',
    allowInvitesFrom: 'adminsAndGuestInviters',
    defaultUserRolePermissions: { permissionGrantPoliciesAssigned: [] }
  },
  '/policies/adminConsentRequestPolicy': { isEnabled: true, notifyReviewers: true, reviewers: [{ query: 'x' }] },
  '/policies/authenticationMethodsPolicy': {
    policyMigrationState: 'migrationComplete',
    systemCredentialPreferences: { state: 'enabled' },
    reportSuspiciousActivitySettings: { state: 'enabled' },
    registrationEnforcement: { authenticationMethodsRegistrationCampaign: { state: 'enabled' } },
    authenticationMethodConfigurations: [
      authMethod('Email', 'disabled'), authMethod('Sms', 'disabled'), authMethod('Voice', 'disabled'),
      authMethod('TemporaryAccessPass', 'enabled', { isUsableOnce: true }),
      authMethod('MicrosoftAuthenticator', 'enabled', {
        featureSettings: {
          numberMatchingRequiredState: { state: 'enabled' },
          displayAppInformationRequiredState: { state: 'enabled' },
          displayLocationInformationRequiredState: { state: 'enabled' }
        }
      })
    ]
  },
  '/identity/conditionalAccess/policies': { value: [CA.legacyBlock, CA.mfaAll, CA.deviceCode, CA.signInRisk, CA.userRisk, CA.adminMfa] },
  '/identity/conditionalAccess/namedLocations': { value: [{ '@odata.type': '#microsoft.graph.countryNamedLocation', displayName: 'UK', isTrusted: false }] },
  '/domains': { value: [{ id: 'contoso.com', isVerified: true, passwordValidityPeriodInDays: 2147483647 }] },
  '/directoryRoles': { value: [{ id: 'role1', roleTemplateId: '62e90394-69f5-4237-9190-012177145e10' }] },
  '/directoryRoles/role1/members': {
    value: [
      { displayName: 'Alice Admin', userPrincipalName: 'alice@contoso.com', onPremisesSyncEnabled: false },
      { displayName: 'BreakGlass One', userPrincipalName: 'breakglass1@contoso.com', onPremisesSyncEnabled: false },
      { displayName: 'BreakGlass Two', userPrincipalName: 'breakglass2@contoso.com', onPremisesSyncEnabled: false }
    ]
  },
  '/users/$count': '0',
  '/reports/authenticationMethods/userRegistrationDetails': {
    value: [
      { userType: 'member', isMfaCapable: true, isMfaRegistered: true },
      { userType: 'member', isMfaCapable: true, isMfaRegistered: true }
    ]
  }
};

export const DEFAULTS = {
  '/organization': { value: [{ displayName: 'Fabrikam', id: 't2' }] },
  '/policies/identitySecurityDefaultsEnforcementPolicy': { isEnabled: false },
  '/policies/authorizationPolicy': {
    guestUserRoleId: '10dae51f-b6af-4016-8d66-8c2a99b929b3',
    allowInvitesFrom: 'everyone',
    defaultUserRolePermissions: { permissionGrantPoliciesAssigned: ['ManagePermissionGrantsForSelf.microsoft-user-default-legacy'] }
  },
  '/policies/adminConsentRequestPolicy': { isEnabled: false, notifyReviewers: false, reviewers: [] },
  '/policies/authenticationMethodsPolicy': {
    policyMigrationState: 'preMigration',
    systemCredentialPreferences: { state: 'disabled' },
    reportSuspiciousActivitySettings: { state: 'disabled' },
    registrationEnforcement: { authenticationMethodsRegistrationCampaign: { state: 'disabled' } },
    authenticationMethodConfigurations: [
      authMethod('Email', 'enabled'), authMethod('Sms', 'enabled'), authMethod('Voice', 'enabled'),
      authMethod('TemporaryAccessPass', 'disabled', { isUsableOnce: false }),
      authMethod('MicrosoftAuthenticator', 'enabled', { featureSettings: {} })
    ]
  },
  '/identity/conditionalAccess/policies': { value: [CA.reportOnly] },
  '/identity/conditionalAccess/namedLocations': { value: [{ '@odata.type': '#microsoft.graph.ipNamedLocation', displayName: 'HQ', isTrusted: true }] },
  '/domains': { value: [{ id: 'fabrikam.com', isVerified: true, passwordValidityPeriodInDays: 90 }] },
  '/directoryRoles': { value: [{ id: 'role1', roleTemplateId: '62e90394-69f5-4237-9190-012177145e10' }] },
  '/directoryRoles/role1/members': {
    value: Array.from({ length: 7 }, (_, i) => ({
      displayName: `Admin ${i}`, userPrincipalName: `admin${i}@fabrikam.com`, onPremisesSyncEnabled: true
    }))
  },
  '/users/$count': '42',
  '/reports/authenticationMethods/userRegistrationDetails': {
    value: [
      { userType: 'member', isMfaCapable: true, isMfaRegistered: true },
      { userType: 'member', isMfaCapable: false, isMfaRegistered: false }
    ]
  }
};

export function mockFetch(fixture, { deny = [] } = {}) {
  return async (url) => {
    // The same policy fixture serves both the v1.0 and beta reads of authenticationMethodsPolicy.
    const path = decodeURIComponent(String(url)).replace('https://graph.microsoft.com/v1.0', '').replace('https://graph.microsoft.com/beta', '').split('?')[0];
    if (deny.some(d => path.startsWith(d))) {
      return res({ error: { message: 'Insufficient privileges to complete the operation.' } }, { status: 403 });
    }
    const body = fixture[path];
    if (body === undefined) return res({ error: { message: `no fixture for ${path}` } }, { status: 404 });
    if (typeof body === 'string') return res(null, { text: body });
    return res(body);
  };
}
