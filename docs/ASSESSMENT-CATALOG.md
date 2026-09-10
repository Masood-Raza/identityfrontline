# Local-first cloud assessments — architecture

The assessment experience has three moving parts and one rule: **no tenant data, report or
token ever reaches identityfrontline.com.** The website hands out a plan and a package; the
tenant is only ever contacted from the user's own machine.

```
 assessments.html  ──reads──▶  assets/catalog/catalog.json   (what can be assessed)
        │                      assets/catalog/manifest.json  (what to download, and its hash)
        │
        └──exports──▶ assessment-run-plan.json ──▶ runner/Invoke-IdentityFrontlineAssessment.ps1
                                                          │
                                                          ├─ interactive Microsoft sign-in
                                                          ├─ M365-Assess (local)
                                                          └─ HTML / XLSX / CSV, written locally
```

## The catalog is the single source of truth

`assets/catalog/catalog.json` is generated — never hand-edited — from a pinned M365-Assess
checkout:

```powershell
git clone https://github.com/Galvnyz/M365-Assess
pwsh -File tools/Build-AssessmentCatalog.ps1 -SourcePath ./M365-Assess
```

It carries the section list, the exact delegated Graph scope per section, framework
definitions with per-framework coverage, and the upstream commit it was built from.

The website reads it for the framework list, the scope tags and the permission preview.
The runner reads a bundled copy of the same file to decide what it is allowed to request.
Nothing about frameworks, sections or permissions is hard-coded in either — `tools/tests`
enforces this.

`-Check` mode fails if the committed catalog has drifted from the pinned source, so it can
gate CI:

```powershell
pwsh -File tools/Build-AssessmentCatalog.ps1 -SourcePath ./M365-Assess -Check
```

The generator **fails the build** rather than guessing when upstream changes shape:

- a registry collector it does not recognise (so check counts can never be silently wrong),
- a profile section upstream no longer defines,
- and it *warns* on a scope that `AssessmentMaps.ps1` requests at sign-in but
  `PermissionDefinitions.ps1` does not grant.

That last warning currently fires for `Agreement.Read.All`. It is a genuine upstream
inconsistency: sign-in asks for it, the standard consent grant does not include it, so the
Terms-of-Use checks report `Unknown` until an administrator consents separately. The catalog
records this per-scope as `grantedByUpstreamConsentHelper`, the planner shows it in step 4,
and the runner repeats it before sign-in.

## Why v1 is Graph-delegated only

The cost driver is **auth surfaces**, not service count. Each surface adds a module, a consent
path and its own partial-failure mode. Measured against the 291 implemented checks in registry
schema 3.4.0:

| Surface added | Checks | Coverage | CIS M365 v6 |
|---|---:|---:|---:|
| Identity only (Entra, Enterprise Apps, CA) | 126 | 43% | 34% |
| **All Graph-delegated** — the v1 profile | **196** | **67%** | **56%** |
| + Exchange Online (EXO RBAC role groups) | 223 | 77% | 71% |
| + Purview / Defender (directory roles) | 265 | 91% | 84% |
| + Power BI (`MicrosoftPowerBIMgmt`) | 291 | 100% | 100% |

Identity-only was rejected: it gives up 24 points of coverage while saving nothing, because
Intune, SharePoint, Teams and Forms ride the same interactive Graph sign-in and need only four
more scopes — no RBAC role groups, no directory roles, no second module.

**v1 profile `graph-delegated-v1`:** Tenant, Identity, Licensing, Intune, Collaboration,
Hybrid. One sign-in, 17 read-only delegated scopes, 196 checks.

Email, Security and PowerBI are *disclosed in the UI as excluded, with the reason* rather than
quietly omitted. They are the v1.1 candidates.

## Runner security model

Deliberate constraints, all enforced in code and covered by tests:

| Constraint | Why |
|---|---|
| Interactive delegated sign-in only | Client secrets, certificates, device code and managed identity are refused. A stolen package cannot run unattended. |
| Scopes recomputed from the catalog | The run plan's `scopes` array is advisory. A hand-edited plan asking for `Directory.ReadWrite.All` is ignored — verified by test. |
| Sections restricted to the profile | A plan naming an unsupported section is rejected with the reason, not silently skipped. |
| Auth type asserted post-connect | If `Get-MgContext` reports anything but `Delegated`, the runner disconnects and stops. |
| Granted scopes verified before collection | Missing scopes are listed with their reason and require explicit confirmation to continue. |
| Bounded retry | Only transient sign-in failures (429/503/throttling) retry, three times with exponential backoff. Consent refusals never loop. |
| No sensitive logging | `Connect-MgGraph -NoWelcome`; exception messages are surfaced without inner request/response payloads. |
| Always disconnects | `Disconnect-MgGraph` runs in `finally`, including on failure. |

## End-to-end test through the browser

The planner fetches the catalog at load, so opening `assessments.html` from disk fails
(`file://` origins are opaque) and the page shows its catalog error banner. Serve it instead:

```powershell
pwsh -File tools/Serve-Site.ps1          # http://localhost:8080/assessments.html
```

Then, in the browser: pick a type, choose frameworks, set scope, review the permissions, and
on step 5 download **both** the run plan and the runner. Step 5 also prints the exact
commands for what follows, filled in from the published manifest.

The runner finds the downloaded plan on its own — nearest location first (current directory,
then beside the script, then `~/Downloads`), newest only breaking ties within one folder. So
after unpacking beside the plan, `-RunPlan` is not needed.

### Two ways to rehearse without touching a tenant

```powershell
# 1. Plan validation only. Needs nothing installed, contacts nothing.
.\Invoke-IdentityFrontlineAssessment.ps1 -RunPlan .\assessment-run-plan.json -WhatIfPlan

# 2. Engine dry run. Installs/imports M365-Assess and lets the real engine resolve the
#    plan's sections, services, scopes and check counts. Still no sign-in, no tenant.
.\Invoke-IdentityFrontlineAssessment.ps1 -RunPlan .\assessment-run-plan.json -DryRun

# 3. The real thing. Opens a browser for interactive sign-in.
.\Invoke-IdentityFrontlineAssessment.ps1 -RunPlan .\assessment-run-plan.json -TenantId contoso.onmicrosoft.com
```

Steps 2 and 3 install the engine plus its eight Microsoft Graph dependencies (several hundred
MB, `CurrentUser` scope) if they are not already present, after asking.

### The catalog pin can be ahead of the gallery

The catalog records the module version from the git checkout it was built against, which can
be **newer than anything published**. At the time of writing the catalog pins `2.13.0` while
the newest PowerShell Gallery release is `2.12.0`, so a naive
`Install-Module -RequiredVersion 2.13.0` fails on a clean machine.

The runner resolves this: if the pinned version is not published it installs the newest
release at or below the pin and warns that check counts and framework mappings may differ
from the planner preview. Pin and installed version are compared on every run, not just on
first install.

## Building and publishing the runner

```powershell
pwsh -File tools/Build-RunnerPackage.ps1 -Version 1.0.0 -CertificateThumbprint <thumbprint>
```

Produces `assets/runner/identityfrontline-assessment-runner-<version>.zip` and writes
`assets/catalog/manifest.json` with the SHA256, size and signing state. The planner renders
the hash and the `Get-FileHash` command straight from the manifest, so a download can be
verified with or without a code-signing certificate.

Omitting `-CertificateThumbprint` produces an **unsigned** build; the planner labels it as
such on the page.

## Tests

```bash
cd tools/tests && npm install && npm test
```

`catalog.test.mjs` asserts the catalog's shape and that the page hard-codes nothing.
`wizard.test.mjs` loads the real page in jsdom against a live server and drives the wizard,
including regressions for the two bugs that shipped in the first version: the Continue button
dead-ending after Back from step 5, and hidden service scopes leaking into the permission
preview.

## Attribution

The assessment engine and control registry are
[M365-Assess](https://github.com/Galvnyz/M365-Assess), © Galvnyz, MIT licensed. The licence
text ships inside every runner package as `LICENSE-M365-Assess.txt` alongside a `NOTICE.txt`
recording the pinned engine version and catalog source ref.

## Not done yet

- **No test-tenant validation.** Nothing here has been run against a real tenant, and the
  engine has not been installed on a build machine either. Sign-in, consent, scope
  verification and partial-service degradation are implemented and unit-tested but unproven
  end to end. Start with `-DryRun`, which exercises the real engine without a tenant.
- **The runner prompts interactively.** Module install confirmation, tenant entry and the
  reduced-coverage confirmation all use `Read-Host`, and sign-in opens a browser. It has to
  be run from a real terminal; it cannot be driven from a non-interactive session.
- **Builds are unsigned.** The signing path exists; no certificate has been applied.
- **Throttling** beyond sign-in retry is left to M365-Assess's own Graph handling.
- **No CI wiring.** `Build-AssessmentCatalog.ps1 -Check` and `npm test` are ready to gate a
  workflow but are not yet called by one.
