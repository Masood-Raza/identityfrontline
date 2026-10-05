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
  },
  compliantDeviceAll: {
    displayName: 'Require compliant device', state: 'enabled',
    conditions: { users: { includeUsers: ['All'] }, applications: { includeApplications: ['All'] }, locations: { excludeLocations: ['AllTrusted'] } },
    grantControls: { builtInControls: ['compliantDevice'] }
  },
  compliantDeviceSecurityInfo: {
    displayName: 'Require compliant device to register security info', state: 'enabled',
    conditions: { users: { includeUsers: ['All'] }, applications: { includeUserActions: ['urn:user:registersecurityinfo'] } },
    grantControls: { builtInControls: ['compliantDevice'] }
  },
  intuneEnrollFreq: {
    displayName: 'Intune enrolment sign-in frequency', state: 'enabled',
    conditions: { users: { includeUsers: ['All'] }, applications: { includeApplications: ['d4ebce55-015a-49b5-a083-c84d1797ae8c'] } },
    sessionControls: { signInFrequency: { isEnabled: true, frequencyInterval: 'everyTime' } }
  },
  phishResistantAll: {
    displayName: 'Phishing-resistant MFA for admins', state: 'enabled',
    conditions: { users: { includeUsers: ['All'] }, applications: { includeApplications: ['All'] } },
    grantControls: { authenticationStrength: { displayName: 'Phishing-resistant MFA' } }
  }
};

export const authMethod = (id, state, extra = {}) => ({ id, state, ...extra });

export const HARDENED = {
  '/organization': { value: [{ displayName: 'Contoso', id: 't1' }] },
  '/policies/identitySecurityDefaultsEnforcementPolicy': { isEnabled: false },
  '/policies/authorizationPolicy': {
    guestUserRoleId: '2af84b1e-32c8-42b7-82bc-daa82404023b',
    allowInvitesFrom: 'adminsAndGuestInviters',
    defaultUserRolePermissions: {
      permissionGrantPoliciesAssigned: [], allowedToCreateApps: false,
      allowedToReadBitlockerKeysForOwnedDevice: false, allowedToCreateTenants: false
    }
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
  '/identity/conditionalAccess/policies': { value: [
    CA.legacyBlock, CA.mfaAll, CA.deviceCode, CA.signInRisk, CA.userRisk, CA.adminMfa,
    CA.compliantDeviceAll, CA.compliantDeviceSecurityInfo, CA.intuneEnrollFreq, CA.phishResistantAll
  ] },
  '/identity/conditionalAccess/namedLocations': { value: [{ '@odata.type': '#microsoft.graph.countryNamedLocation', displayName: 'UK', isTrusted: false }] },
  '/domains': { value: [{ id: 'contoso.com', isVerified: true, passwordValidityPeriodInDays: 2147483647 }] },
  '/directoryRoles': { value: [{ id: 'role1', roleTemplateId: '62e90394-69f5-4237-9190-012177145e10' }] },
  '/directoryRoles/role1/members': {
    value: [
      { id: 'u-alice', displayName: 'Alice Admin', userPrincipalName: 'alice@contoso.com', onPremisesSyncEnabled: false },
      { id: 'u-bg1', displayName: 'BreakGlass One', userPrincipalName: 'breakglass1@contoso.com', onPremisesSyncEnabled: false },
      { id: 'u-bg2', displayName: 'BreakGlass Two', userPrincipalName: 'breakglass2@contoso.com', onPremisesSyncEnabled: false }
    ]
  },
  '/users/$count': '0',
  '/reports/authenticationMethods/userRegistrationDetails': {
    value: [
      { userType: 'member', userPrincipalName: 'alice@contoso.com', isMfaCapable: true, isMfaRegistered: true, methodsRegistered: ['fido2'] },
      { userType: 'member', userPrincipalName: 'breakglass1@contoso.com', isMfaCapable: true, isMfaRegistered: true, methodsRegistered: ['windowsHelloForBusiness'] },
      { userType: 'member', userPrincipalName: 'breakglass2@contoso.com', isMfaCapable: true, isMfaRegistered: true, methodsRegistered: ['fido2'] }
    ]
  },
  '/policies/deviceRegistrationPolicy': {
    azureADJoin: {
      allowedToJoin: { '@odata.type': '#microsoft.graph.enumeratedDeviceRegistrationMembership' },
      localAdmins: {
        enableGlobalAdmins: false,
        registeringUsers: { '@odata.type': '#microsoft.graph.enumeratedDeviceRegistrationMembership' }
      }
    },
    localAdminPassword: { isEnabled: true },
    userDeviceQuota: 10
  },
  '/directory/onPremisesDirectorySynchronization': { features: { passwordHashSyncEnabled: true } },
  '/groups': { value: [] }
};

export const DEFAULTS = {
  '/organization': { value: [{ displayName: 'Fabrikam', id: 't2' }] },
  '/policies/identitySecurityDefaultsEnforcementPolicy': { isEnabled: false },
  '/policies/authorizationPolicy': {
    guestUserRoleId: '10dae51f-b6af-4016-8d66-8c2a99b929b3',
    allowInvitesFrom: 'everyone',
    defaultUserRolePermissions: {
      permissionGrantPoliciesAssigned: ['ManagePermissionGrantsForSelf.microsoft-user-default-legacy'], allowedToCreateApps: true,
      allowedToReadBitlockerKeysForOwnedDevice: true, allowedToCreateTenants: true
    }
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
      id: `u-admin${i}`, displayName: `Admin ${i}`, userPrincipalName: `admin${i}@fabrikam.com`, onPremisesSyncEnabled: true
    }))
  },
  '/users/$count': '42',
  '/reports/authenticationMethods/userRegistrationDetails': {
    value: [
      { userType: 'member', isMfaCapable: true, isMfaRegistered: true },
      { userType: 'member', isMfaCapable: false, isMfaRegistered: false }
    ]
  },
  '/policies/deviceRegistrationPolicy': {
    azureADJoin: {
      allowedToJoin: { '@odata.type': '#microsoft.graph.allDeviceRegistrationMembership' },
      localAdmins: {
        enableGlobalAdmins: true,
        registeringUsers: { '@odata.type': '#microsoft.graph.allDeviceRegistrationMembership' }
      }
    },
    localAdminPassword: { isEnabled: false },
    userDeviceQuota: 50
  },
  '/directory/onPremisesDirectorySynchronization': { features: { passwordHashSyncEnabled: false } },
  '/groups': { value: [] }
};

export function mockFetch(fixture, { deny = [], dns = null, dnsFail = false } = {}) {
  return async (url) => {
    // DNS-over-HTTPS: answered from the fixture's DNS map, not from Graph.
    const u = String(url);
    if (/dns-query|dns\.google/.test(u)) {
      if (dnsFail) return res({ error: 'resolver down' }, { status: 502 });
      const q = new URL(u);
      const key = `${q.searchParams.get('name')}|${q.searchParams.get('type')}`;
      const answers = (dns || {})[key];
      // Status 3 is NXDOMAIN: a real answer meaning "no such name", not a resolver failure.
      if (!answers) return res({ Status: 3, Answer: [] });
      const type = { TXT: 16, MX: 15, CNAME: 5 }[q.searchParams.get('type')];
      return res({ Status: 0, Answer: answers.map(data => ({ type, data })) });
    }
    // The same policy fixture serves both the v1.0 and beta reads of authenticationMethodsPolicy.
    const stripped = decodeURIComponent(String(url)).replace('https://graph.microsoft.com/v1.0', '').replace('https://graph.microsoft.com/beta', '');
    const path = stripped.split('?')[0];
    if (deny.some(d => path.startsWith(d))) {
      return res({ error: { message: 'Insufficient privileges to complete the operation.' } }, { status: 403 });
    }
    const body = fixture[stripped] !== undefined ? fixture[stripped] : fixture[path];
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

// ---- Sprint 3: applications & privileged access ------------------------------------------
import { readFileSync as _rf } from 'node:fs';
import { fileURLToPath as _fu } from 'node:url';
import { dirname as _dn, join as _jn } from 'node:path';
const APP_TIERS = JSON.parse(_rf(_jn(_dn(_fu(import.meta.url)), '..', '..', 'assets', 'catalog', 'app-tiers.json'), 'utf8'));

const GRAPH_SP = "/servicePrincipals?$filter=appId eq '00000003-0000-0000-c000-000000000000'&$select=id,appRoles";
const OWNERS = '/servicePrincipals?$select=id&$expand=owners($select=id,displayName)&$top=999';
const SIGNINS = '/servicePrincipals?$select=id,signInActivity&$top=999';
const PIM_GA = "/policies/roleManagementPolicyAssignments?$filter=scopeId eq '/' and scopeType eq 'DirectoryRole' and roleDefinitionId eq '62e90394-69f5-4237-9190-012177145e10'&$expand=policy($expand=rules)";
const PIM_PRA = "/policies/roleManagementPolicyAssignments?$filter=scopeId eq '/' and scopeType eq 'DirectoryRole' and roleDefinitionId eq 'e8611ab8-c189-46e8-94e1-60213ab1f814'&$expand=policy($expand=rules)";
const MS_TENANT = 'f8cdef31-a31e-4b4a-93e4-5f571e91255a';
const future = new Date(Date.now() + 180 * 86400000).toISOString();
const past = new Date(Date.now() - 30 * 86400000).toISOString();
const recent = new Date(Date.now() - 2 * 86400000).toISOString();
const graphRoles = { value: [{ id: 'graph-sp', appRoles: [
  { id: 'r-dirrw', value: 'Directory.ReadWrite.All' }, { id: 'r-mailrw', value: 'Mail.ReadWrite' }, { id: 'r-userread', value: 'User.Read.All' },
  ...Array.from({ length: 12 }, (_, i) => ({ id: `r-many${i}`, value: `Some.Read.${i}` }))
] }] };
const pimRules = (ok) => [{ policy: { rules: [
  { id: 'Approval_EndUser_Assignment', setting: { isApprovalRequired: ok } },
  { id: 'Expiration_EndUser_Assignment', maximumDuration: ok ? 'PT4H' : 'PT8H' },
  { id: 'Enablement_EndUser_Assignment', enabledRules: ok ? ['MultiFactorAuthentication', 'Justification'] : [] },
  { id: 'Expiration_Admin_Eligibility', isExpirationRequired: ok, maximumDuration: 'P365D' },
  { id: 'Notification_Admin_EndUser_Assignment', isDefaultRecipientsEnabled: ok, notificationRecipients: [] }
] } }];

Object.assign(HARDENED, {
  'assets/catalog/app-tiers.json': APP_TIERS,
  '/organization': { value: [{ id: 't1', displayName: 'Contoso' }] },
  '/applications': { value: [{ id: 'a1', appId: 'app-1', displayName: 'Line of business', signInAudience: 'AzureADMyOrg', web: { redirectUris: ['https://app.contoso.com/auth'] } }] },
  '/servicePrincipals': { value: [
    { id: 'sp1', appId: 'app-1', displayName: 'Line of business', appOwnerOrganizationId: 't1', servicePrincipalType: 'Application', accountEnabled: true, keyCredentials: [{ endDateTime: future }], passwordCredentials: [] },
    { id: 'sp-ms', appId: 'ms-1', displayName: 'Microsoft Graph Command Line Tools', appOwnerOrganizationId: MS_TENANT, servicePrincipalType: 'Application', accountEnabled: true, keyCredentials: [], passwordCredentials: [] },
    { id: 'mi1', appId: 'mi-1', displayName: 'func-identity', appOwnerOrganizationId: 't1', servicePrincipalType: 'ManagedIdentity', accountEnabled: true }
  ] },
  [GRAPH_SP]: graphRoles,
  '/servicePrincipals/graph-sp/appRoleAssignedTo': { value: [
    { principalId: 'sp1', appRoleId: 'r-userread' }, { principalId: 'sp-ms', appRoleId: 'r-dirrw' }, { principalId: 'mi1', appRoleId: 'r-userread' }
  ] },
  [OWNERS]: { value: [{ id: 'sp1', owners: [{ id: 'u-alice', displayName: 'Alice Admin' }] }, { id: 'sp-ms', owners: [] }, { id: 'mi1', owners: [] }] },
  [SIGNINS]: { value: [{ id: 'sp1', signInActivity: { lastSignInDateTime: recent } }] },
  '/oauth2PermissionGrants': { value: [] },
  '/roleManagement/directory/roleAssignments': { value: [] },
  '/policies/defaultAppManagementPolicy': { isEnabled: true },
  '/roleManagement/directory/roleEligibilityScheduleInstances': { value: [{ principalId: 'u-alice' }, { principalId: 'u-bg1' }, { principalId: 'u-bg2' }] },
  '/identityGovernance/accessReviews/definitions': { value: [
    { displayName: 'Quarterly guest review', scope: { query: "/users?$filter=(userType eq 'Guest')", queryType: 'MicrosoftGraph' } },
    { displayName: 'Global Administrator review', scope: { query: '/roleManagement/directory/roleDefinitions/62e90394-69f5-4237-9190-012177145e10', queryType: 'MicrosoftGraph' } }
  ] },
  [PIM_GA]: { value: pimRules(true) },
  [PIM_PRA]: { value: pimRules(true) }
});

Object.assign(DEFAULTS, {
  'assets/catalog/app-tiers.json': APP_TIERS,
  '/organization': { value: [{ id: 't2', displayName: 'Fabrikam' }] },
  '/applications': { value: [
    { id: 'a1', appId: 'app-1', displayName: 'Dev tool', signInAudience: 'AzureADMultipleOrgs', web: { redirectUris: ['http://localhost:3000/', 'http://prod.fabrikam.com/cb', 'https://*.fabrikam.com/cb'] } }
  ] },
  '/servicePrincipals': { value: [
    // Third-party, foreign, impersonating Microsoft, secret-only, expired, no owner, no sign-in, tier 0 + tier 1, holds a role.
    { id: 'sp-bad', appId: 'bad-1', displayName: 'Microsoft Teams Helper', appOwnerOrganizationId: 'evil-tenant', servicePrincipalType: 'Application', accountEnabled: true, keyCredentials: [], passwordCredentials: [{ endDateTime: past }] },
    // Internal app with a tier 0 permission, both credential types, and an owner.
    { id: 'sp-int', appId: 'int-1', displayName: 'Internal automation', appOwnerOrganizationId: 't2', servicePrincipalType: 'Application', accountEnabled: true, keyCredentials: [{ endDateTime: future }], passwordCredentials: [{ endDateTime: future }] },
    // Over-permissioned app.
    { id: 'sp-many', appId: 'many-1', displayName: 'Everything app', appOwnerOrganizationId: 't2', servicePrincipalType: 'Application', accountEnabled: true, keyCredentials: [], passwordCredentials: [] },
    // Managed identity with a dangerous permission and a directory role.
    { id: 'mi-bad', appId: 'mi-2', displayName: 'vm-identity', appOwnerOrganizationId: 't2', servicePrincipalType: 'ManagedIdentity', accountEnabled: true }
  ] },
  [GRAPH_SP]: graphRoles,
  '/servicePrincipals/graph-sp/appRoleAssignedTo': { value: [
    { principalId: 'sp-bad', appRoleId: 'r-dirrw' }, { principalId: 'sp-bad', appRoleId: 'r-mailrw' },
    { principalId: 'sp-int', appRoleId: 'r-dirrw' },
    { principalId: 'mi-bad', appRoleId: 'r-dirrw' },
    ...Array.from({ length: 12 }, (_, i) => ({ principalId: 'sp-many', appRoleId: `r-many${i}` }))
  ] },
  [OWNERS]: { value: [{ id: 'sp-bad', owners: [] }, { id: 'sp-int', owners: [{ id: 'u-admin0', displayName: 'Admin 0' }] }, { id: 'sp-many', owners: [] }, { id: 'mi-bad', owners: [] }] },
  [SIGNINS]: { value: [{ id: 'sp-int', signInActivity: { lastSignInDateTime: recent } }] },
  '/oauth2PermissionGrants': { value: [{ clientId: 'sp-bad', scope: 'User.Read Mail.ReadWrite' }] },
  '/roleManagement/directory/roleAssignments': { value: [{ principalId: 'sp-bad', roleDefinitionId: 'x' }, { principalId: 'sp-int', roleDefinitionId: 'x' }, { principalId: 'mi-bad', roleDefinitionId: 'x' }] },
  '/policies/defaultAppManagementPolicy': { isEnabled: false },
  '/roleManagement/directory/roleEligibilityScheduleInstances': { value: [] },
  '/identityGovernance/accessReviews/definitions': { value: [] },
  [PIM_GA]: { value: pimRules(false) },
  [PIM_PRA]: { value: pimRules(false) }
});

// ---- Microsoft security signals ----------------------------------------------------------
const daysAgo = (n) => new Date(Date.now() - n * 86400000).toISOString();
const PROFILES = { value: [
  { id: 'AdminMFAV2', title: 'Require MFA for administrative roles', maxScore: 10, controlCategory: 'Identity', implementationCost: 'Low', userImpact: 'Low', actionUrl: 'https://security.microsoft.com/securescore?viewid=actions' },
  { id: 'MFARegistrationV2', title: 'Ensure all users can complete MFA', maxScore: 9, controlCategory: 'Identity', implementationCost: 'Moderate', userImpact: 'Moderate', actionUrl: '' },
  { id: 'BlockLegacyAuthentication', title: 'Block legacy authentication', maxScore: 8, controlCategory: 'Identity', implementationCost: 'Low', userImpact: 'Low', actionUrl: '' },
  { id: 'SafeLinks', title: 'Turn on Safe Links', maxScore: 3, controlCategory: 'Apps', implementationCost: 'Low', userImpact: 'Low', actionUrl: '' }
] };
Object.assign(HARDENED, {
  '/security/secureScores': { value: [{ id: 's1', createdDateTime: daysAgo(1), currentScore: 78, maxScore: 100, controlScores: [
    { controlName: 'AdminMFAV2', score: 10, controlCategory: 'Identity' }, { controlName: 'MFARegistrationV2', score: 9, controlCategory: 'Identity' },
    { controlName: 'BlockLegacyAuthentication', score: 8, controlCategory: 'Identity' }, { controlName: 'SafeLinks', score: 0, controlCategory: 'Apps' } ] }] },
  '/security/secureScoreControlProfiles': PROFILES,
  '/security/alerts_v2': { value: [] }
});
Object.assign(DEFAULTS, {
  '/security/secureScores': { value: [{ id: 's2', createdDateTime: daysAgo(20), currentScore: 35, maxScore: 100, controlScores: [
    { controlName: 'AdminMFAV2', score: 0, controlCategory: 'Identity' }, { controlName: 'MFARegistrationV2', score: 2, controlCategory: 'Identity' },
    { controlName: 'BlockLegacyAuthentication', score: 0, controlCategory: 'Identity' }, { controlName: 'SafeLinks', score: 3, controlCategory: 'Apps' } ] }] },
  '/security/secureScoreControlProfiles': PROFILES,
  '/security/alerts_v2': { value: [
    { id: 'a1', title: 'Suspicious inbox forwarding rule', severity: 'medium', status: 'new', category: 'Exfiltration', createdDateTime: daysAgo(2), serviceSource: 'microsoftDefenderForOffice365' },
    { id: 'a2', title: 'Atypical travel sign-in', severity: 'high', status: 'inProgress', category: 'InitialAccess', createdDateTime: daysAgo(1), serviceSource: 'microsoftDefenderForIdentity' },
    { id: 'a3', title: 'Old resolved alert', severity: 'high', status: 'resolved', category: 'Malware', createdDateTime: daysAgo(30), serviceSource: 'microsoftDefenderForEndpoint' }
  ] }
});

// ---- Sprint 6: public DNS and the Exchange evidence file ----------------------------------
// Keys are "<name>|<type>"; a name that is absent resolves as NXDOMAIN, which is what a
// domain with no SPF or DMARC record actually looks like.
export const DNS_HARDENED = {
  'contoso.com|TXT': ['"v=spf1 include:spf.protection.outlook.com -all"'],
  '_dmarc.contoso.com|TXT': ['"v=DMARC1; p=reject; rua=mailto:dmarc@contoso.com"'],
  'contoso.com|MX': ['0 contoso-com.mail.protection.outlook.com.'],
  'selector1._domainkey.contoso.com|CNAME': ['selector1-contoso-com._domainkey.contoso.onmicrosoft.com.'],
  'selector2._domainkey.contoso.com|CNAME': ['selector2-contoso-com._domainkey.contoso.onmicrosoft.com.']
};

// A domain with a permissive SPF, monitor-only DMARC, no DKIM selectors and mail routed
// through a third-party gateway.
export const DNS_DEFAULT = {
  'fabrikam.com|TXT': ['"v=spf1 include:spf.protection.outlook.com ?all"'],
  '_dmarc.fabrikam.com|TXT': ['"v=DMARC1; p=none"'],
  'fabrikam.com|MX': ['10 mail.some-gateway.example.']
};

const EV_OK = {
  schemaVersion: 1,
  collectedUtc: new Date(Date.now() - 2 * 86400000).toISOString(),
  tool: { name: 'test', version: '1.0.0' },
  tenant: { name: 'contoso.onmicrosoft.com', domains: ['contoso.com', 'contoso.onmicrosoft.com'] },
  data: {
    organizationConfig: [{ Name: 'contoso', OAuth2ClientProfileEnabled: true, AuditDisabled: false, CustomerLockBoxEnabled: true,
      MailTipsAllTipsEnabled: true, MailTipsExternalRecipientsTipsEnabled: true, MailTipsGroupMetricsEnabled: true, MailTipsLargeAudienceThreshold: 25 }],
    transportConfig: [{ SmtpClientAuthenticationDisabled: true }],
    externalInOutlook: [{ Identity: 'x', Enabled: true, AllowList: [] }],
    remoteDomains: [{ Name: 'Default', DomainName: '*', IsDefault: true, AutoForwardEnabled: false }],
    owaMailboxPolicies: [{ Name: 'OwaMailboxPolicy-Default', IsDefault: true, AdditionalStorageProvidersAvailable: false }],
    roleAssignmentPolicies: [{ Name: 'Default Role Assignment Policy', IsDefault: true, AssignedRoles: ['MyContactInformation', 'MyVoiceMail'] }],
    sharingPolicies: [{ Name: 'Default Sharing Policy', Default: true, Enabled: true, Domains: ['partner.com: CalendarSharingFreeBusySimple'] }],
    transportRules: [],
    inboundConnectors: [{ Name: 'Partner', Enabled: true, RequireTls: true, RestrictDomainsToIPAddresses: true }],
    mailboxAuditBypass: [],
    dkimSigningConfigs: [{ Domain: 'contoso.com', Enabled: true, Status: 'Valid' }, { Domain: 'contoso.onmicrosoft.com', Enabled: true }],
    mailboxAuditSample: [{ UserPrincipalName: 'a@contoso.com', AuditEnabled: true }, { UserPrincipalName: 'b@contoso.com', AuditEnabled: true }],
    hiddenMailboxes: [],
    antiPhishPolicies: [{ Name: 'Office365 AntiPhish Default', Enabled: true, IsDefault: true, PhishThresholdLevel: 3,
      EnableMailboxIntelligence: true, EnableSpoofIntelligence: true, HonorDmarcPolicy: true, EnableFirstContactSafetyTips: true }],
    safeLinksPolicies: [{ Name: 'Standard', IsEnabled: true, EnableSafeLinksForEmail: true, EnableSafeLinksForTeams: true, EnableSafeLinksForOffice: true, ScanUrls: true, TrackClicks: true }],
    safeAttachmentPolicies: [{ Name: 'Standard', Enable: true, Action: 'Block', IsDefault: true }],
    atpPolicyForO365: [{ Name: 'Default', EnableATPForSPOTeamsODB: true, EnableSafeDocs: true }],
    malwareFilterPolicies: [{ Name: 'Default', IsDefault: true, EnableFileFilter: true, ZapEnabled: true,
      FileTypes: Array.from({ length: 30 }, (_, i) => 'ext' + i), EnableInternalSenderAdminNotifications: true }],
    hostedContentFilterPolicies: [{ Name: 'Default', IsDefault: true, AllowedSenderDomains: [], BulkThreshold: 5,
      SpamAction: 'MoveToJmf', HighConfidenceSpamAction: 'Quarantine', PhishSpamAction: 'Quarantine', HighConfidencePhishAction: 'Quarantine',
      ZapEnabled: true, SpamZapEnabled: true, PhishZapEnabled: true }],
    hostedOutboundSpamFilterPolicies: [{ Name: 'Default', IsDefault: true, AutoForwardingMode: 'Off', NotifyOutboundSpam: true,
      NotifyOutboundSpamRecipients: ['soc@contoso.com'], BccSuspiciousOutboundMail: true,
      RecipientLimitExternalPerHour: 400, RecipientLimitInternalPerHour: 800, RecipientLimitPerDay: 1000 }],
    hostedConnectionFilterPolicies: [{ Name: 'Default', IsDefault: true, IPAllowList: [], IPBlockList: [], EnableSafeList: false }],
    acceptedDomains: [{ Name: 'contoso.com', DomainName: 'contoso.com', DomainType: 'Authoritative', Default: true }]
  },
  errors: {}
};

const EV_BAD = {
  schemaVersion: 1,
  collectedUtc: new Date(Date.now() - 3 * 86400000).toISOString(),
  tool: { name: 'test', version: '1.0.0' },
  tenant: { name: 'fabrikam.onmicrosoft.com', domains: ['fabrikam.com', 'fabrikam.onmicrosoft.com'] },
  data: {
    organizationConfig: [{ Name: 'fabrikam', OAuth2ClientProfileEnabled: false, AuditDisabled: true, CustomerLockBoxEnabled: false,
      MailTipsAllTipsEnabled: false, MailTipsExternalRecipientsTipsEnabled: false, MailTipsGroupMetricsEnabled: false, MailTipsLargeAudienceThreshold: 50 }],
    transportConfig: [{ SmtpClientAuthenticationDisabled: false }],
    externalInOutlook: [{ Identity: 'x', Enabled: false, AllowList: [] }],
    remoteDomains: [{ Name: 'Default', DomainName: '*', IsDefault: true, AutoForwardEnabled: true }],
    owaMailboxPolicies: [{ Name: 'OwaMailboxPolicy-Default', IsDefault: true, AdditionalStorageProvidersAvailable: true }],
    roleAssignmentPolicies: [{ Name: 'Default Role Assignment Policy', IsDefault: true, AssignedRoles: ['My Marketplace Apps', 'My Custom Apps'] }],
    sharingPolicies: [{ Name: 'Default Sharing Policy', Default: true, Enabled: true, Domains: ['*: CalendarSharingFreeBusyReviewer'] }],
    transportRules: [
      { Name: 'Allow partner bulk', State: 'Enabled', SetSCL: -1, SenderDomainIs: ['partner.example'] },
      { Name: 'Journal to archive', State: 'Enabled', SetSCL: null, BlindCopyTo: ['archive@third-party.example'] }
    ],
    inboundConnectors: [{ Name: 'Legacy relay', Enabled: true, RequireTls: false, RestrictDomainsToIPAddresses: false }],
    mailboxAuditBypass: [{ Name: 'svc-scanner', AuditBypassEnabled: true }],
    dkimSigningConfigs: [{ Domain: 'fabrikam.com', Enabled: false, Status: 'CnameMissing' }],
    mailboxAuditSample: [{ UserPrincipalName: 'a@fabrikam.com', AuditEnabled: false }, { UserPrincipalName: 'b@fabrikam.com', AuditEnabled: true }],
    hiddenMailboxes: [{ UserPrincipalName: 'ghost@fabrikam.com', PrimarySmtpAddress: 'ghost@fabrikam.com' }],
    antiPhishPolicies: [{ Name: 'Office365 AntiPhish Default', Enabled: true, IsDefault: true, PhishThresholdLevel: 1,
      EnableMailboxIntelligence: false, EnableSpoofIntelligence: false, HonorDmarcPolicy: false }],
    safeLinksPolicies: [],
    safeAttachmentPolicies: [],
    atpPolicyForO365: [{ Name: 'Default', EnableATPForSPOTeamsODB: false }],
    malwareFilterPolicies: [{ Name: 'Default', IsDefault: true, EnableFileFilter: false, ZapEnabled: false,
      FileTypes: [], EnableInternalSenderAdminNotifications: false }],
    hostedContentFilterPolicies: [{ Name: 'Default', IsDefault: true, AllowedSenderDomains: [{ Domain: 'marketing.example' }],
      BulkThreshold: 8, SpamAction: 'NoAction', HighConfidenceSpamAction: 'MoveToJmf', PhishSpamAction: 'MoveToJmf', HighConfidencePhishAction: 'MoveToJmf',
      ZapEnabled: false, SpamZapEnabled: false, PhishZapEnabled: false }],
    hostedOutboundSpamFilterPolicies: [{ Name: 'Default', IsDefault: true, AutoForwardingMode: 'Automatic', NotifyOutboundSpam: false,
      NotifyOutboundSpamRecipients: [], BccSuspiciousOutboundMail: false,
      RecipientLimitExternalPerHour: 0, RecipientLimitInternalPerHour: 0, RecipientLimitPerDay: 0 }],
    hostedConnectionFilterPolicies: [{ Name: 'Default', IsDefault: true, IPAllowList: ['198.51.100.7', '203.0.113.0/24'], EnableSafeList: true }],
    acceptedDomains: [{ Name: 'fabrikam.com', DomainName: 'fabrikam.com', DomainType: 'Authoritative', Default: true }]
  },
  // One cmdlet the tenant could not run: its checks must report Unknown with this reason.
  errors: { safeLinksPolicies: 'Get-SafeLinksPolicy is not available in this tenant or to this account.' }
};

export const EVIDENCE_HARDENED = EV_OK;
export const EVIDENCE_DEFAULT = EV_BAD;
