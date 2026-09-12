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

// ---- Sprint 2 areas: SharePoint, Teams, Forms, Intune ------------------------------------
// One SharePoint fixture serves both the v1.0 and beta reads (the mock strips both prefixes).
const profile = (type, name, extra, assigned = true) =>
  ({ '@odata.type': `#microsoft.graph.${type}`, displayName: name, assignments: assigned ? [{ id: 'grp' }] : [], ...extra });

Object.assign(HARDENED, {
  '/admin/sharepoint/settings': {
    sharingCapability: 'existingExternalUserSharingOnly', isResharingByExternalUsersEnabled: false,
    sharingDomainRestrictionMode: 'allowList', defaultSharingLinkType: 'specificPeople',
    externalUserExpirationRequired: true, externalUserExpireInDays: 30,
    emailAttestationRequired: true, emailAttestationReAuthDays: 15, defaultLinkPermission: 'view',
    isUnmanagedSyncAppForTenantRestricted: true, isMacSyncAppEnabled: false, isLoopEnabled: false,
    oneDriveLoopSharingCapability: 'disabled', isLegacyAuthProtocolsEnabled: false,
    idleSessionSignOut: { isEnabled: true, warnAfterInSeconds: 600, signOutAfterInSeconds: 3600 }
  },
  '/policies/activityBasedTimeoutPolicies': { value: [{ id: 'idle-1' }] },
  '/teamwork/teamsAppSettings': { isChatResourceSpecificConsentEnabled: false },
  '/teamwork/teamsClientConfiguration': {
    allowTeamsConsumer: false, allowTeamsConsumerInbound: false, allowPublicUsers: false,
    allowDropBox: false, allowBox: false, allowGoogleDrive: false, allowShareFile: false, allowEgnyte: false,
    allowEmailIntoChannel: false, allowFederatedUsers: true, allowedDomains: ['partner.example']
  },
  '/teamwork/teamsMeetingPolicy': {
    allowAnonymousUsersToJoinMeeting: false, allowAnonymousUsersToStartMeeting: false,
    autoAdmittedUsers: 'EveryoneInCompanyExcludingGuests', allowPSTNUsersToBypassLobby: false,
    allowExternalParticipantGiveRequestControl: false, meetingChatEnabledType: 'EnabledExceptAnonymous',
    designatedPresenterRoleMode: 'OrganizerOnlyUserOverride', allowExternalNonTrustedMeetingChat: false,
    allowCloudRecording: false
  },
  '/admin/forms/settings': {
    isExternalSendFormEnabled: false, isExternalShareCollaborationEnabled: false, isExternalShareResultEnabled: false,
    isInOrgFormsPhishingScanEnabled: true, isRecordIdentityByDefaultEnabled: true, isBingImageSearchEnabled: false
  },
  '/deviceManagement/settings': { deviceComplianceCheckinThresholdDays: 30 },
  '/deviceManagement/deviceEnrollmentConfigurations': { value: [
    { '@odata.type': '#microsoft.graph.deviceEnrollmentPlatformRestrictionsConfiguration',
      iosRestriction: { personalDeviceEnrollmentBlocked: true }, androidRestriction: { personalDeviceEnrollmentBlocked: true }, windowsRestriction: { personalDeviceEnrollmentBlocked: true } },
    { '@odata.type': '#microsoft.graph.deviceEnrollmentWindowsAutoEnrollmentConfiguration' }
  ] },
  '/deviceManagement/windowsAutopilotDeploymentProfiles': { value: [{ displayName: 'Corporate Autopilot' }] },
  '/deviceManagement/managedDeviceOverview': { enrolledDeviceCount: 120 },
  '/deviceManagement/deviceCategories': { value: [{ displayName: 'Corporate' }] },
  '/deviceManagement/deviceCompliancePolicies': { value: [
    { '@odata.type': '#microsoft.graph.iosCompliancePolicy', displayName: 'iOS baseline', storageRequireEncryption: true },
    { '@odata.type': '#microsoft.graph.androidWorkProfileCompliancePolicy', displayName: 'Android baseline', storageRequireEncryption: true }
  ] },
  '/deviceManagement/deviceConfigurations': { value: [
    profile('windows10GeneralConfiguration', 'Device restrictions', { storageBlockRemovableStorage: true, usbBlocked: true }),
    profile('windows10CustomConfiguration', 'FIPS policy', { omaSettings: [{ omaUri: './Device/Vendor/MSFT/Policy/Config/Cryptography/AllowFipsAlgorithmPolicy', value: 1 }] }),
    profile('windows10CustomConfiguration', 'WDAC policy', { omaSettings: [{ omaUri: './Vendor/MSFT/ApplicationControl/Policies/x/Policy', value: 'x' }] }),
    profile('windows10VpnConfiguration', 'Always-On VPN', { alwaysOn: true, enableSplitTunneling: false }),
    profile('windowsWifiEnterpriseEAPConfiguration', 'Corp Wi-Fi', { eapType: 'eapTls', wifiSecurityType: 'wpa2Enterprise' })
  ] }
});

Object.assign(DEFAULTS, {
  '/admin/sharepoint/settings': {
    sharingCapability: 'externalUserAndGuestSharing', isResharingByExternalUsersEnabled: true,
    sharingDomainRestrictionMode: 'none', defaultSharingLinkType: 'anyone',
    externalUserExpirationRequired: true, externalUserExpireInDays: 90,
    emailAttestationRequired: false, defaultLinkPermission: 'edit',
    isUnmanagedSyncAppForTenantRestricted: false, isMacSyncAppEnabled: true, isLoopEnabled: true,
    oneDriveLoopSharingCapability: 'externalUserAndGuestSharing', isLegacyAuthProtocolsEnabled: true,
    idleSessionSignOut: { isEnabled: true, warnAfterInSeconds: 600, signOutAfterInSeconds: 43200 }
  },
  '/policies/activityBasedTimeoutPolicies': { value: [] },
  '/teamwork/teamsAppSettings': { isChatResourceSpecificConsentEnabled: true },
  '/teamwork/teamsClientConfiguration': {
    allowTeamsConsumer: true, allowTeamsConsumerInbound: true, allowPublicUsers: true,
    allowDropBox: true, allowBox: false, allowGoogleDrive: true, allowShareFile: false, allowEgnyte: false,
    allowEmailIntoChannel: true, allowFederatedUsers: true, allowedDomains: []
  },
  '/teamwork/teamsMeetingPolicy': {
    allowAnonymousUsersToJoinMeeting: true, allowAnonymousUsersToStartMeeting: true,
    autoAdmittedUsers: 'Everyone', allowPSTNUsersToBypassLobby: true,
    allowExternalParticipantGiveRequestControl: true, meetingChatEnabledType: 'Enabled',
    designatedPresenterRoleMode: 'EveryoneUserOverride', allowExternalNonTrustedMeetingChat: true,
    allowCloudRecording: true
  },
  '/admin/forms/settings': {
    isExternalSendFormEnabled: true, isExternalShareCollaborationEnabled: true, isExternalShareResultEnabled: true,
    isInOrgFormsPhishingScanEnabled: false, isRecordIdentityByDefaultEnabled: false, isBingImageSearchEnabled: true
  },
  '/deviceManagement/settings': { deviceComplianceCheckinThresholdDays: 90 },
  '/deviceManagement/deviceEnrollmentConfigurations': { value: [] },
  '/deviceManagement/windowsAutopilotDeploymentProfiles': { value: [] },
  '/deviceManagement/managedDeviceOverview': { enrolledDeviceCount: 0 },
  '/deviceManagement/deviceCategories': { value: [] },
  '/deviceManagement/deviceCompliancePolicies': { value: [
    { '@odata.type': '#microsoft.graph.iosCompliancePolicy', displayName: 'iOS default', storageRequireEncryption: false }
  ] },
  '/deviceManagement/deviceConfigurations': { value: [
    // Exists but is not assigned: must not count.
    profile('windows10GeneralConfiguration', 'Unassigned restrictions', { storageBlockRemovableStorage: true }, false)
  ] }
});
