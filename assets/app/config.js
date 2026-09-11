// Identity Frontline — deployment configuration.
//
// SETUP REQUIRED. Create an Entra app registration and paste its client ID below.
// The planner detects the placeholder and shows setup instructions instead of failing.
//
//   1. Entra admin center > App registrations > New registration
//        Name:                 Identity Frontline Assessment
//        Supported accounts:   Accounts in any organizational directory (multitenant)
//        Redirect URI:         Single-page application (SPA) -> https://<your-domain>/assessments.html
//                              Add http://localhost:8080/assessments.html for local testing.
//
//   2. API permissions > Add a permission > Microsoft Graph > Delegated:
//        AuditLog.Read.All, Directory.Read.All, Domain.Read.All,
//        Policy.Read.All, RoleManagement.Read.Directory, User.Read.All
//      Do NOT add application permissions. This app never runs unattended.
//
//   3. Overview > copy the Application (client) ID into clientId below.
//
//   4. Recommended: complete publisher verification so the consent screen shows a verified
//      publisher rather than an unverified-app warning.
//
// The app registration lives in YOUR tenant. Customers consent to it from theirs; their data
// is read by their browser using their token and never reaches this site.

export const CONFIG = {
  clientId: 'ca9c5d54-e77e-41c0-84a5-f903d5305bc8',

  // Where MSAL returns after sign-in. Defaults to this page, which must match a SPA redirect
  // URI registered on the app above.
  redirectUri: typeof window !== 'undefined'
    ? window.location.origin + window.location.pathname
    : '',

  // 'organizations' allows any work or school tenant, and blocks personal accounts.
  authority: 'https://login.microsoftonline.com/organizations',

  // Session storage keeps the token out of long-lived browser storage: closing the tab ends it.
  cacheLocation: 'sessionStorage'
};

export const isConfigured = () =>
  !!CONFIG.clientId && !CONFIG.clientId.startsWith('REPLACE_WITH');
