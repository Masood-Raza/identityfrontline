# Cloud assessment — architecture

The assessment runs **entirely in the visitor's browser**. The page signs the user in with
Microsoft, calls Microsoft Graph directly with their token, evaluates the checks in
JavaScript, and generates the reports client-side. Nothing about the tenant — no token, no
configuration, no report — is ever sent to identityfrontline.com. There is no server-side
component.

```
 assessments.html
   │
   ├─ assets/app/main.js      wizard: frameworks → scope → permissions → connect & run → results
   ├─ assets/app/auth.js      MSAL.js sign-in (auth code + PKCE), admin consent popup
   ├─ assets/app/engine.js    fetch Graph sources once, evaluate checks, score, roll up
   ├─ assets/app/checks.js    the checks: which Graph data each needs + a pass/fail predicate
   ├─ assets/app/report.js    on-page results, self-contained HTML / CSV / JSON downloads
   └─ assets/app/config.js    YOUR app registration client ID (see Setup)

 assets/catalog/checks.json   generated: name, severity, rationale, remediation and framework
                              mappings for every implemented check, from the M365-Assess registry
```

## Setup (one-time, only you can do this)

Sign-in needs an Entra app registration that customers consent to. It lives in your tenant.

1. **Entra admin center → App registrations → New registration**
   - Name: `Identity Frontline Assessment`
   - Supported account types: **Accounts in any organizational directory (multitenant)**
   - Redirect URI: platform **Single-page application**, value `https://<your-domain>/assessments.html`
   - Add a second SPA redirect `http://localhost:8080/assessments.html` for local testing
2. **API permissions → Add → Microsoft Graph → Delegated**, all read-only:
   - Identity: `AuditLog.Read.All`, `Directory.Read.All`, `Domain.Read.All`, `Policy.Read.All`,
     `RoleManagement.Read.Directory`, `User.Read.All`
   - SharePoint: `SharePointTenantSettings.Read.All`
   - Teams: `TeamSettings.Read.All`, `TeamworkAppSettings.Read.All`
   - Forms: `OrgSettings-Forms.Read.All`
   - Intune: `DeviceManagementConfiguration.Read.All`, `DeviceManagementServiceConfig.Read.All`,
     `DeviceManagementManagedDevices.Read.All`

   Only the scopes for the areas a user selects are requested at sign-in (identity alone is
   six), but the registration must carry all thirteen. Do **not** add application
   permissions — the app never runs unattended.
3. Copy the **Application (client) ID** into `assets/app/config.js`.
4. Recommended: [publisher verification](https://learn.microsoft.com/entra/identity-platform/publisher-verification-overview),
   so the consent screen shows a verified publisher instead of an "unverified" warning.

Until step 3 is done the page shows a setup notice and refuses to start sign-in.

## The user's journey

1. **Frameworks** — pick which to report against; the same findings map to each.
2. **Scope** — pick areas: identity & access (always on), SharePoint & OneDrive, Teams, Forms,
   Intune & devices. Each area adds only the permissions it needs. Exchange and Purview are
   listed as not assessable from the browser: they have no Graph API.
3. **Permissions** — the delegated read-only scopes the selected areas need (six for identity
   alone, thirteen for everything), each with its reason.
4. **Connect & run** — enter tenant, sign in with Microsoft. If a scope is missing, a
   *Grant admin consent* button opens Microsoft's consent page in a popup; the user can also
   run with reduced coverage. Progress is shown per data source.
5. **Results** — pass rate, failures by severity, an executive summary, the five findings to
   fix first, every finding with remediation, framework coverage, and what could not be
   collected. Download the HTML report, print it to PDF, or export an Excel workbook (summary,
   findings, a check-by-framework compliance matrix, coverage), CSV or JSON.

Framework selection in step 1 narrows what is *reported* — the coverage table, the mapping
column, the matrix columns — never what is assessed. Nothing selected means everything.

## Status model

Copied from M365-Assess so a partial run is honest rather than punitive:

| Situation | Status | Counts toward pass rate? |
|---|---|---|
| Condition met | Pass | yes |
| Condition not met | Fail | yes |
| Partially met (e.g. guest expiry on but set to 90 days) | Warning | yes — as not-passed |
| Source unreadable (missing consent, unlicensed, error) | Unknown | **no** |
| Check does not apply (e.g. security defaults on) | NotApplicable | **no** |

Unavailable sources are listed on the results page and in the report with the Graph error.

## Adding a check

1. Pick a `checkId` from the M365-Assess registry (`controls/registry.json`) — the framework
   mappings come from there and are the valuable part.
2. Add it to `CHECKS` in `assets/app/checks.js`: declare `needs` (existing or new `SOURCES`)
   and write `evaluate(d)` returning `pass()`, `fail()`, `warn()`, `unknown()` or `na()`. Set its
   `area`. Never throw.
3. Regenerate the catalog:
   ```powershell
   git clone https://github.com/Galvnyz/M365-Assess
   pwsh -File tools/Build-CheckCatalog.ps1 -SourcePath ./M365-Assess
   ```
   The build fails if the ID is not in the registry. `-Check` verifies without writing.
4. Add fixture data to `tools/tests/fixtures.mjs` and run the tests.

A new Graph scope must be added to the app registration too — existing customers are then
prompted for incremental consent on their next run.

## Continuous integration

`.github/workflows/tests.yml` runs the full suite on every pull request and on pushes to any
branch except `main`, plus a drift job that fetches M365-Assess at the commit recorded in
`checks.json` and runs `Build-CheckCatalog.ps1 -Check`. The deploy workflow runs the suite as
a gate before publishing `main`.

## Testing

```bash
cd tools/tests && npm install && npm test
```

- `catalog.test.mjs` — checks.js and checks.json agree; metadata is complete; the page
  hard-codes nothing the catalog supplies.
- `engine.test.mjs` — every predicate against a hardened tenant, a default tenant, a
  permission-denied source, and empty payloads.
- `wizard.test.mjs` — the real page and controller in jsdom, driven end to end with sign-in
  and Graph mocked: setup notice, all five steps, missing-scope → consent → run → downloads →
  restart, and a degraded run.

To try it in a browser: `pwsh -File tools/Serve-Site.ps1` (module scripts need http, not file://).

## Security properties

| Property | How |
|---|---|
| No credentials on this site | MSAL popup to login.microsoftonline.com; nothing typed here |
| Token never leaves the tab | `sessionStorage` cache, sent only to `graph.microsoft.com` |
| Read-only by construction | Only `*.Read.*` scopes exist in the code; tests assert it |
| No unattended use possible | No application permissions on the app registration |
| Throttling respected | 429/503 honour `Retry-After` with bounded backoff |
| Nothing logged | MSAL logger disabled, PII logging off |
| Reports are inert | Generated HTML has no scripts and no external references |

## Attribution

Check definitions, severities, remediation and framework mappings derive from
[M365-Assess](https://github.com/Galvnyz/M365-Assess), © Galvnyz, MIT — see
`assets/catalog/LICENSE-M365-Assess.txt`. The evaluation logic in `checks.js` is our own.

## Not done yet

- **Validated on one tenant.** Predicates are tested against mock Graph payloads that
  follow the documented schemas and have run clean on one real tenant; other tenants and
  licence tiers may still surface shape differences.
- **89 checks across five areas.** SharePoint, Teams, Forms and Intune have been validated
  against mock payloads only, not a real tenant. Secure Score and Defender alerts are
  reachable and not yet implemented. Exchange and Purview are not reachable through Graph.
- **Teams meeting policy, Forms settings and several Intune reads use Graph beta.** They
  are the same endpoints M365-Assess uses, but beta can change shape without notice.
- **No baseline or drift.** Each run stands alone; nothing is remembered between runs.
