<#
.SYNOPSIS
    Exports read-only Exchange Online and Defender for Office 365 configuration as a JSON
    evidence file for the Identity Frontline assessment.

.DESCRIPTION
    Exchange Online, Exchange Online Protection and Defender for Office 365 policy settings
    are not exposed by Microsoft Graph, and the Exchange REST endpoint sends no CORS headers,
    so a browser cannot read them at all. This script is the bridge: an administrator runs it,
    it reads configuration and writes a JSON file, and the assessment page imports that file
    from disk to evaluate the Exchange checks.

    The file is read by the browser locally. It is never uploaded, and this script sends
    nothing anywhere: it writes to the path you give it and exits.

    Every call is a Get-* cmdlet. There is no Set-, New-, Remove- or Enable- anywhere in this
    file, and the assessment only ever reads the result. The account you sign in with needs
    View-Only Configuration (the built-in "Global Reader" or "View-Only Organization
    Management" role is enough); it does not need write access to anything.

    A cmdlet that is unavailable -- not licensed, not present in your plan, blocked by role --
    is recorded in an "errors" map with its reason rather than failing the run. The checks
    that depend on it then report Unknown with that reason, never a false failure.

.PARAMETER OutputPath
    Where to write the JSON. Defaults to exchange-evidence-<tenant>-<date>.json in the
    current directory.

.PARAMETER UserPrincipalName
    Optional: the admin account to sign in as, passed to Connect-ExchangeOnline.

.PARAMETER SkipConnect
    Use an Exchange Online session you have already connected, instead of connecting here.

.EXAMPLE
    pwsh -File tools/Export-ExchangeEvidence.ps1

.EXAMPLE
    pwsh -File tools/Export-ExchangeEvidence.ps1 -UserPrincipalName admin@contoso.com -OutputPath C:\temp\evidence.json

.NOTES
    Requires the ExchangeOnlineManagement module:
        Install-Module ExchangeOnlineManagement -Scope CurrentUser

    Check definitions and framework mappings derive from M365-Assess
    (https://github.com/Galvnyz/M365-Assess), (c) Galvnyz, MIT licensed.
#>
[CmdletBinding()]
param(
    [string]$OutputPath,
    [string]$UserPrincipalName,
    [switch]$SkipConnect
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# The schema the assessment page expects. Bump only for a breaking change to the shape; the
# page refuses a file it does not understand rather than guessing.
$SCHEMA_VERSION = 1

# ------------------------------------------------------------------------------------------
# Connect
# ------------------------------------------------------------------------------------------
if (-not $SkipConnect) {
    if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
        throw "The ExchangeOnlineManagement module is not installed. Run: Install-Module ExchangeOnlineManagement -Scope CurrentUser"
    }
    Import-Module ExchangeOnlineManagement -ErrorAction Stop

    Write-Host 'Signing in to Exchange Online...' -ForegroundColor Cyan
    $connectParams = @{ ShowBanner = $false; ErrorAction = 'Stop' }
    if ($UserPrincipalName) { $connectParams['UserPrincipalName'] = $UserPrincipalName }
    Connect-ExchangeOnline @connectParams
}

# ------------------------------------------------------------------------------------------
# Collection
# ------------------------------------------------------------------------------------------
$data   = [ordered]@{}
$errors = [ordered]@{}

# Runs one read-only cmdlet, keeping the failure rather than throwing: an unlicensed or
# unavailable cmdlet must degrade one group of checks to Unknown, not abort the export.
function Get-Evidence {
    param(
        [Parameter(Mandatory)][string]$Key,
        [Parameter(Mandatory)][string]$Cmdlet,
        [Parameter(Mandatory)][scriptblock]$Script,
        [string[]]$Properties
    )
    if (-not (Get-Command -Name $Cmdlet -ErrorAction SilentlyContinue)) {
        $errors[$Key] = "$Cmdlet is not available in this tenant or to this account."
        Write-Host ("  {0,-34} unavailable" -f $Key) -ForegroundColor DarkYellow
        return
    }
    try {
        $raw = & $Script
        if ($null -eq $raw) { $data[$Key] = $null; Write-Host ("  {0,-34} empty" -f $Key) -ForegroundColor DarkGray; return }
        $value = if ($Properties) { $raw | Select-Object -Property $Properties } else { $raw }
        # Force a collection to stay a collection through ConvertTo-Json.
        $data[$Key] = @($value)
        Write-Host ("  {0,-34} {1}" -f $Key, @($value).Count) -ForegroundColor DarkGray
    }
    catch {
        $msg = $_.Exception.Message
        if ($msg.Length -gt 300) { $msg = $msg.Substring(0, 300) }
        $errors[$Key] = $msg
        Write-Host ("  {0,-34} failed: {1}" -f $Key, $msg) -ForegroundColor DarkYellow
    }
}

Write-Host ''
Write-Host 'Reading Exchange Online configuration (read-only)...' -ForegroundColor Cyan

Get-Evidence -Key 'organizationConfig' -Cmdlet 'Get-OrganizationConfig' -Script { Get-OrganizationConfig } -Properties `
    'Name', 'OAuth2ClientProfileEnabled', 'AuditDisabled', 'CustomerLockBoxEnabled',
    'MailTipsAllTipsEnabled', 'MailTipsExternalRecipientsTipsEnabled', 'MailTipsGroupMetricsEnabled',
    'MailTipsLargeAudienceThreshold', 'IsDehydrated'

Get-Evidence -Key 'transportConfig' -Cmdlet 'Get-TransportConfig' -Script { Get-TransportConfig } -Properties `
    'SmtpClientAuthenticationDisabled'

Get-Evidence -Key 'externalInOutlook' -Cmdlet 'Get-ExternalInOutlook' -Script { Get-ExternalInOutlook } -Properties `
    'Identity', 'Enabled', 'AllowList'

Get-Evidence -Key 'remoteDomains' -Cmdlet 'Get-RemoteDomain' -Script { Get-RemoteDomain } -Properties `
    'Name', 'DomainName', 'IsDefault', 'AutoForwardEnabled'

Get-Evidence -Key 'owaMailboxPolicies' -Cmdlet 'Get-OwaMailboxPolicy' -Script { Get-OwaMailboxPolicy -WarningAction SilentlyContinue } -Properties `
    'Name', 'IsDefault', 'AdditionalStorageProvidersAvailable'

Get-Evidence -Key 'roleAssignmentPolicies' -Cmdlet 'Get-RoleAssignmentPolicy' -Script { Get-RoleAssignmentPolicy } -Properties `
    'Name', 'IsDefault', 'AssignedRoles'

Get-Evidence -Key 'sharingPolicies' -Cmdlet 'Get-SharingPolicy' -Script { Get-SharingPolicy } -Properties `
    'Name', 'Default', 'Enabled', 'Domains'

Get-Evidence -Key 'transportRules' -Cmdlet 'Get-TransportRule' -Script { Get-TransportRule } -Properties `
    'Name', 'State', 'SetSCL', 'SenderDomainIs', 'RedirectMessageTo', 'BlindCopyTo', 'AddToRecipients', 'CopyTo'

Get-Evidence -Key 'inboundConnectors' -Cmdlet 'Get-InboundConnector' -Script { Get-InboundConnector } -Properties `
    'Name', 'Enabled', 'RequireTls', 'RestrictDomainsToIPAddresses', 'ConnectorType'

Get-Evidence -Key 'mailboxAuditBypass' -Cmdlet 'Get-MailboxAuditBypassAssociation' -Script {
    Get-MailboxAuditBypassAssociation -ResultSize Unlimited -WarningAction SilentlyContinue |
        Where-Object { $_.AuditBypassEnabled }
} -Properties 'Name', 'AuditBypassEnabled'

Get-Evidence -Key 'dkimSigningConfigs' -Cmdlet 'Get-DkimSigningConfig' -Script { Get-DkimSigningConfig } -Properties `
    'Domain', 'Enabled', 'Status', 'Selector1CNAME', 'Selector2CNAME'

Write-Host ''
Write-Host 'Reading mailbox samples...' -ForegroundColor Cyan

# A sample, not every mailbox: enough to show whether auditing is on as a rule, without
# pulling the whole directory into an evidence file.
Get-Evidence -Key 'mailboxAuditSample' -Cmdlet 'Get-EXOMailbox' -Script {
    Get-EXOMailbox -RecipientTypeDetails UserMailbox -ResultSize 200 -Properties AuditEnabled -WarningAction SilentlyContinue
} -Properties 'UserPrincipalName', 'AuditEnabled'

Get-Evidence -Key 'hiddenMailboxes' -Cmdlet 'Get-EXOMailbox' -Script {
    Get-EXOMailbox -RecipientTypeDetails UserMailbox -ResultSize Unlimited `
        -Filter 'HiddenFromAddressListsEnabled -eq $True' -Properties HiddenFromAddressListsEnabled -WarningAction SilentlyContinue
} -Properties 'UserPrincipalName', 'PrimarySmtpAddress'

Write-Host ''
Write-Host 'Reading Defender for Office 365 and EOP policies...' -ForegroundColor Cyan

Get-Evidence -Key 'antiPhishPolicies' -Cmdlet 'Get-AntiPhishPolicy' -Script { Get-AntiPhishPolicy } -Properties `
    'Name', 'Enabled', 'IsDefault', 'PhishThresholdLevel', 'EnableMailboxIntelligence',
    'EnableMailboxIntelligenceProtection', 'EnableTargetedUserProtection', 'EnableTargetedDomainsProtection',
    'EnableSpoofIntelligence', 'HonorDmarcPolicy', 'EnableFirstContactSafetyTips',
    'EnableUnauthenticatedSender', 'EnableViaTag'

Get-Evidence -Key 'safeLinksPolicies' -Cmdlet 'Get-SafeLinksPolicy' -Script { Get-SafeLinksPolicy } -Properties `
    'Name', 'IsEnabled', 'EnableSafeLinksForEmail', 'EnableSafeLinksForTeams', 'EnableSafeLinksForOffice',
    'ScanUrls', 'DeliverMessageAfterScan', 'EnableForInternalSenders', 'TrackClicks', 'AllowClickThrough'

Get-Evidence -Key 'safeAttachmentPolicies' -Cmdlet 'Get-SafeAttachmentPolicy' -Script { Get-SafeAttachmentPolicy } -Properties `
    'Name', 'Enable', 'Action', 'IsDefault', 'Redirect', 'QuarantineTag'

Get-Evidence -Key 'atpPolicyForO365' -Cmdlet 'Get-AtpPolicyForO365' -Script { Get-AtpPolicyForO365 } -Properties `
    'Name', 'EnableATPForSPOTeamsODB', 'EnableSafeDocs', 'AllowSafeDocsOpen'

Get-Evidence -Key 'malwareFilterPolicies' -Cmdlet 'Get-MalwareFilterPolicy' -Script { Get-MalwareFilterPolicy } -Properties `
    'Name', 'IsDefault', 'EnableFileFilter', 'FileTypes', 'ZapEnabled',
    'EnableInternalSenderAdminNotifications', 'InternalSenderAdminAddress'

Get-Evidence -Key 'hostedContentFilterPolicies' -Cmdlet 'Get-HostedContentFilterPolicy' -Script { Get-HostedContentFilterPolicy } -Properties `
    'Name', 'IsDefault', 'AllowedSenderDomains', 'AllowedSenders', 'BulkThreshold',
    'SpamAction', 'HighConfidenceSpamAction', 'PhishSpamAction', 'HighConfidencePhishAction',
    'BulkSpamAction', 'ZapEnabled', 'SpamZapEnabled', 'PhishZapEnabled'

Get-Evidence -Key 'hostedOutboundSpamFilterPolicies' -Cmdlet 'Get-HostedOutboundSpamFilterPolicy' -Script { Get-HostedOutboundSpamFilterPolicy } -Properties `
    'Name', 'IsDefault', 'AutoForwardingMode', 'NotifyOutboundSpam', 'NotifyOutboundSpamRecipients',
    'BccSuspiciousOutboundMail', 'RecipientLimitExternalPerHour', 'RecipientLimitInternalPerHour', 'RecipientLimitPerDay'

Get-Evidence -Key 'hostedConnectionFilterPolicies' -Cmdlet 'Get-HostedConnectionFilterPolicy' -Script { Get-HostedConnectionFilterPolicy } -Properties `
    'Name', 'IsDefault', 'IPAllowList', 'IPBlockList', 'EnableSafeList'

Get-Evidence -Key 'acceptedDomains' -Cmdlet 'Get-AcceptedDomain' -Script { Get-AcceptedDomain } -Properties `
    'Name', 'DomainName', 'DomainType', 'Default'

# ------------------------------------------------------------------------------------------
# Identify the tenant, so the page can warn if the evidence belongs to a different one
# ------------------------------------------------------------------------------------------
$tenantName = $null
$tenantDomains = @()
try {
    if ($data.Contains('acceptedDomains') -and $data['acceptedDomains']) {
        $tenantDomains = @($data['acceptedDomains'] | ForEach-Object { $_.DomainName })
        $initial = $data['acceptedDomains'] | Where-Object { $_.DomainName -like '*.onmicrosoft.com' } | Select-Object -First 1
        if ($initial) { $tenantName = $initial.DomainName }
    }
    if (-not $tenantName -and $data.Contains('organizationConfig') -and $data['organizationConfig']) {
        $tenantName = @($data['organizationConfig'])[0].Name
    }
}
catch { }

$out = [ordered]@{
    schemaVersion = $SCHEMA_VERSION
    collectedUtc  = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    tool          = [ordered]@{
        name    = 'Identity Frontline — Export-ExchangeEvidence.ps1'
        version = '1.0.0'
        host    = "PowerShell $($PSVersionTable.PSVersion)"
    }
    tenant        = [ordered]@{
        name    = $tenantName
        domains = $tenantDomains
    }
    data          = $data
    errors        = $errors
}

if (-not $OutputPath) {
    $slug = if ($tenantName) { ($tenantName -replace '[^a-zA-Z0-9]+', '-').ToLower() } else { 'tenant' }
    $OutputPath = Join-Path -Path (Get-Location) -ChildPath ("exchange-evidence-{0}-{1}.json" -f $slug, (Get-Date -Format 'yyyy-MM-dd'))
}

$out | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $OutputPath -Encoding UTF8

Write-Host ''
Write-Host "Evidence written to $OutputPath" -ForegroundColor Green
Write-Host ("  {0} groups collected, {1} unavailable" -f $data.Count, $errors.Count)
if ($errors.Count) {
    Write-Host '  Unavailable groups become Unknown in the report, with the reason shown:' -ForegroundColor DarkYellow
    foreach ($k in $errors.Keys) { Write-Host ("    {0}: {1}" -f $k, $errors[$k]) -ForegroundColor DarkYellow }
}
Write-Host ''
Write-Host 'Next: on the assessment page, select the Exchange & email security area and' -ForegroundColor Cyan
Write-Host 'choose this file under "Exchange evidence". It is read in your browser and not uploaded.' -ForegroundColor Cyan
Write-Host ''
Write-Host 'This file contains tenant configuration. Treat it as confidential.' -ForegroundColor Yellow
