// Identity Frontline — Microsoft sign-in and admin consent.
//
// Uses MSAL.js authorization-code + PKCE, the supported pattern for single-page apps. The
// token stays in this tab's sessionStorage and is sent only to graph.microsoft.com. It is
// never transmitted to identityfrontline.com, logged, or persisted beyond the tab.

import { CONFIG } from './config.js';

let app = null;
let account = null;

const GRAPH_RESOURCE = 'https://graph.microsoft.com/';

function requireMsal() {
  if (typeof msal === 'undefined') {
    throw new Error('The Microsoft sign-in library did not load. Check your network or content blocker and reload.');
  }
}

// Resolve a tenant domain or GUID to an authority. A specific tenant gives the user a cleaner
// sign-in (no home-realm prompt) and makes admin consent land in the right directory.
export const authorityFor = (tenant) =>
  tenant ? `https://login.microsoftonline.com/${encodeURIComponent(tenant.trim())}` : CONFIG.authority;

export async function initAuth(tenant) {
  requireMsal();
  app = new msal.PublicClientApplication({
    auth: {
      clientId: CONFIG.clientId,
      authority: authorityFor(tenant),
      redirectUri: CONFIG.redirectUri,
      // A tenant-specific authority is still a valid issuer for the 'organizations' app.
      knownAuthorities: [],
      navigateToLoginRequestUrl: false
    },
    cache: {
      cacheLocation: CONFIG.cacheLocation,
      storeAuthStateInCookie: false
    },
    system: {
      loggerOptions: {
        // Never log tokens or claims.
        loggerCallback: () => {},
        piiLoggingEnabled: false
      }
    }
  });
  await app.initialize();
  return app;
}

export async function signIn(scopes, tenant) {
  if (!app) await initAuth(tenant);
  const result = await app.loginPopup({
    scopes,
    prompt: 'select_account'
  });
  account = result.account;
  app.setActiveAccount(account);
  return {
    account,
    tenantId: result.tenantId || account?.tenantId,
    username: account?.username,
    name: account?.name
  };
}

export async function getToken(scopes) {
  if (!app || !account) throw new Error('Not signed in.');
  try {
    const r = await app.acquireTokenSilent({ scopes, account });
    return { token: r.accessToken, grantedScopes: r.scopes || [] };
  } catch (e) {
    // Silent acquisition fails when consent is missing or the session expired. Both are
    // recoverable interactively.
    const r = await app.acquireTokenPopup({ scopes, account });
    return { token: r.accessToken, grantedScopes: r.scopes || [] };
  }
}

export function signOut() {
  account = null;
  try { app?.clearCache?.(); } catch { /* best effort */ }
}

// ---------------------------------------------------------------------------------------
// Admin consent
// ---------------------------------------------------------------------------------------
// Tenant-wide consent is a redirect an administrator completes, not something a token grants.
// Opening it in a popup keeps the wizard's state intact in the parent window.
export function adminConsentUrl(tenant, scopes) {
  const params = new URLSearchParams({
    client_id: CONFIG.clientId,
    scope: scopes.map(s => GRAPH_RESOURCE + s).join(' '),
    redirect_uri: CONFIG.redirectUri,
    state: 'iffl-consent'
  });
  return `https://login.microsoftonline.com/${encodeURIComponent(tenant.trim())}/v2.0/adminconsent?${params}`;
}

// Opens the consent screen and resolves when the popup closes. The popup lands back on our
// redirect URI, so we read the outcome from its query string while it is still same-origin.
export function requestAdminConsent(tenant, scopes) {
  return new Promise((resolve) => {
    const w = window.open(adminConsentUrl(tenant, scopes), 'iffl-consent',
      'width=620,height=740,menubar=no,toolbar=no');

    if (!w) {
      resolve({ completed: false, reason: 'popup-blocked' });
      return;
    }

    let outcome = null;
    const timer = setInterval(() => {
      try {
        // Throws while the popup is on login.microsoftonline.com (cross-origin) — expected.
        if (w.location.href.startsWith(CONFIG.redirectUri)) {
          const q = new URLSearchParams(w.location.search);
          outcome = {
            completed: q.get('admin_consent') === 'True',
            error: q.get('error'),
            errorDescription: q.get('error_description'),
            tenant: q.get('tenant')
          };
          w.close();
        }
      } catch { /* still cross-origin */ }

      if (w.closed) {
        clearInterval(timer);
        resolve(outcome || { completed: false, reason: 'closed' });
      }
    }, 400);
  });
}

// What the token actually carries, which is the only thing that matters at collection time.
export function missingScopes(required, granted) {
  const have = new Set(granted.map(s => s.toLowerCase().replace(GRAPH_RESOURCE, '')));
  return required.filter(s => !have.has(s.toLowerCase()));
}
