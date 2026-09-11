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
2. **API permissions → Add → Microsoft Graph → Delegated**, exactly these six:
   `AuditLog.Read.All`, `Directory.Read.All`, `Domain.Read.All`, `Policy.Read.All`,
   `RoleManagement.Read.Directory`, `User.Read.All`.
   Do **not** add application permissions — the app never runs unattended.
3. Copy the **Application (client) ID** into `assets/app/config.js`.
4. Recommended: [publisher verification](https://learn.microsoft.com/entra/identity-platform/publisher-verification-overview),
   so the consent screen shows a verified publisher instead of an "unverified" warning.

Until step 3 is done the page shows a setup notice and refuses to start sign-in.

## The user's journey

1. **Frameworks** — pick which to report against; the same findings map to each.
2. **Scope** — identity & access in this release; other areas listed as coming.
3. **Permissions** — the six delegated read-only scopes, each with its reason.
4. **Connect & run** — enter tenant, sign in with Microsoft. If a scope is missing, a
   *Grant admin consent* button opens Microsoft's consent page in a popup; the user can also
   run with reduced coverage. Progress is shown per data source.
5. **Results** — pass rate, failures by severity, every finding with remediation, framework
   coverage, and what could not be collected. Download HTML, CSV or JSON.

## Status model

Copied from M365-Assess so a partial run is honest rather than punitive:

| Situation | Status | Counts toward pass rate? |
|---|---|---|
| Condition met | Pass | yes |
| Condition not met | Fail | yes |
| Source unreadable (missing consent, unlicensed, error) | Unknown | **no** |
| Check does not apply (e.g. security defaults on) | NotApplicable | **no** |

Unavailable sources are listed on the results page and in the report with the Graph error.

## Adding a check

1. Pick a `checkId` from the M365-Assess registry (`controls/registry.json`) — the framework
   mappings come from there and are the valuable part.
2. Add it to `CHECKS` in `assets/app/checks.js`: declare `needs` (existing or new `SOURCES`)
   and write `evaluate(d)` returning `pass()`, `fail()`, `unknown()` or `na()`. Never throw.
3. Regenerate the catalog:
   ```powershell
   git clone https://github.com/Galvnyz/M365-Assess
   pwsh -File tools/Build-CheckCatalog.ps1 -SourcePath ./M365-Assess
   ```
   The build fails if the ID is not in the registry. `-Check` verifies without writing.
4. Add fixture data to `tools/tests/fixtures.mjs` and run the tests.

A new Graph scope must be added to the app registration too — existing customers are then
prompted for incremental consent on their next run.

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

- **Never run against a real tenant.** Predicates are tested against mock Graph payloads
  that follow the documented schemas; real tenants will surface shape differences.
- **No app registration yet** — sign-in cannot work until Setup is done.
- **37 identity checks.** Exchange, Intune, SharePoint/Teams, Defender and Purview are not
  yet implemented; Exchange and Purview are not reachable through Graph alone.
- **No CI** calling `npm test` or `Build-CheckCatalog.ps1 -Check`.
