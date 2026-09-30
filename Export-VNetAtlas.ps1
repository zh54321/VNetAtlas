<#
.SYNOPSIS
    Maps Azure virtual networks into a multi-page draw.io atlas.

.DESCRIPTION
    VNetAtlas inventories Azure networking resources through Azure Resource Graph and
    writes one .drawio file containing a network overview page grouped by subscription,
    one page per virtual network showing its subnets and the resources inside them,
    detail pages for each network security group and route table, and an Unmapped
    Resources page for anything that could not be placed.

    A resource is placed on a VNet page only where Resource Graph exposes a defensible
    subnet, NIC, backend, or peering relationship. Each subnet additionally reports what
    occupies it, read from its own ipConfigurations and serviceAssociationLinks, so a
    resource type the exporter does not query directly still appears rather than leaving
    the subnet looking empty.

    Output is deterministic. For unchanged input the generated file is byte-identical
    across repeat runs and across Windows PowerShell 5.1 and PowerShell 7, apart from the
    mxfile 'modified' timestamp.

    Firewall policy rules are not available through Resource Graph. They are read from
    Azure Resource Manager for each policy attached to a firewall and for the parent
    policies it inherits from, unless -SkipFirewallRules is set.

    The Az.Accounts and Az.ResourceGraph modules and at least Reader access to the
    queried subscriptions are required. Neither module is needed with -InputDataPath.

.PARAMETER SubscriptionId
    Subscriptions to query. Omit to use every enabled subscription in the tenant.

.PARAMETER TenantId
    Tenant to export. Triggers a new sign-in when the current Az context belongs to a
    different tenant. One Az context represents one tenant, so tenants are exported
    separately.

.PARAMETER InputDataPath
    Rebuild a diagram from JSON previously written by -ExportDataPath, without querying
    Azure. Required for the Input parameter set.

.PARAMETER ExportDataPath
    Also write the normalized query results to this path as JSON, so the same diagram can
    be regenerated offline.

.PARAMETER VnetName
    Only include virtual networks whose name matches. Wildcards are supported. Combines
    with the other scope filters using AND.

.PARAMETER ResourceGroup
    Only include virtual networks in these resource groups. Wildcards are supported.

.PARAMETER ExcludeSubscriptionId
    Drop virtual networks belonging to these subscriptions. Applied after -SubscriptionId.

.PARAMETER SkipRuleDetailPages
    Omit the per-NSG, per-route-table, and per-firewall-policy detail pages. Firewall
    policy rules are still collected, so -ExportDataPath keeps them.

.PARAMETER SkipFirewallRules
    Do not read firewall policy rules and omit the firewall policy detail pages. Rules
    are read from Azure Resource Manager with at least two requests per policy, so this
    switch removes those requests.

.PARAMETER SkipDefaultNsgRules
    Omit Azure's built-in default security rules from NSG detail pages, leaving only the
    custom rules.

.PARAMETER ResourcesPerRow
    How many resources may share a line inside a subnet, 1 to 4. Lower values make pages
    taller but reduce connector overlap. A NIC and its VM stay together where the value
    permits; a private endpoint always takes its own line.

.PARAMETER OutputPath
    Target .drawio file. Relative paths resolve against the current location. Defaults to
    a timestamped name such as 20260901_1025_Azure-Network.drawio.

.PARAMETER Quiet
    Suppress the banner and progress output. The summary line is still written to stdout.

.PARAMETER Version
    Print the exporter version and exit.

.PARAMETER Help
    Print usage and exit. Usage goes to stdout and the banner to the host stream, so
    redirecting stdout captures clean text.

.INPUTS
    None. This script does not accept pipeline input.

.OUTPUTS
    System.String. One summary line describing the file written and its page counts.
    Progress output goes to the host stream and is not part of this value.

.EXAMPLE
    .\Export-VNetAtlas.ps1

    Query every enabled subscription in the current tenant and write a timestamped
    diagram to the current location.

.EXAMPLE
    .\Export-VNetAtlas.ps1 -VnetName 'hub-*' -OutputPath .\hub.drawio

    Export only virtual networks whose name starts with "hub". The network overview and the
    NSG and route-table detail pages follow the same scope, and the Unmapped Resources page
    is suppressed because "unmapped" would otherwise mean "outside the selected VNets".

.EXAMPLE
    .\Export-VNetAtlas.ps1 -ExportDataPath .\network-data.json -OutputPath .\azure-network.drawio
    .\Export-VNetAtlas.ps1 -InputDataPath .\network-data.json -OutputPath .\offline.drawio

    Save the normalized query results, then rebuild the same diagram offline without
    contacting Azure.

.EXAMPLE
    $result = .\Export-VNetAtlas.ps1 -SubscriptionId '00000000-0000-0000-0000-000000000001' -Quiet

    Query one subscription with progress output suppressed. $result receives the summary
    line only.

.NOTES
    Runs on Windows PowerShell 5.1 and PowerShell 7 or later.

    Every generated file records its origin on the root mxfile element as
    host="VNetAtlas", agent="Export-VNetAtlas.ps1" and version="<exporter version>".

    Private DNS zones, VNet links, record sets and private-endpoint DNS zone groups are
    outside the current scope.

.LINK
    https://github.com/zh54321/VNetAtlas
#>

[CmdletBinding(DefaultParameterSetName = 'Azure')]
param(
    [Parameter(ParameterSetName = 'Azure')]
    [string[]]$SubscriptionId,

    [Parameter(ParameterSetName = 'Azure')]
    [string]$TenantId,

    [Parameter(Mandatory, ParameterSetName = 'Input')]
    [string]$InputDataPath,

    [Parameter(ParameterSetName = 'Azure')]
    [string]$ExportDataPath,

    # Scope filters. Name filters accept wildcards and are applied to the VNet
    # set before any page is built.
    [Parameter(ParameterSetName = 'Azure')]
    [Parameter(ParameterSetName = 'Input')]
    [string[]]$VnetName,

    [Parameter(ParameterSetName = 'Azure')]
    [Parameter(ParameterSetName = 'Input')]
    [string[]]$ResourceGroup,

    [Parameter(ParameterSetName = 'Azure')]
    [Parameter(ParameterSetName = 'Input')]
    [string[]]$ExcludeSubscriptionId,

    [Parameter(ParameterSetName = 'Azure')]
    [Parameter(ParameterSetName = 'Input')]
    [switch]$SkipRuleDetailPages,

    [Parameter(ParameterSetName = 'Azure')]
    [Parameter(ParameterSetName = 'Input')]
    [switch]$SkipFirewallRules,

    [Parameter(ParameterSetName = 'Azure')]
    [Parameter(ParameterSetName = 'Input')]
    [switch]$SkipDefaultNsgRules,

    [Parameter(ParameterSetName = 'Azure')]
    [Parameter(ParameterSetName = 'Input')]
    [ValidateRange(1,4)]
    [int]$ResourcesPerRow = 2,

    [Parameter(ParameterSetName = 'Azure')]
    [Parameter(ParameterSetName = 'Input')]
    [string]$OutputPath = ".\$(Get-Date -Format 'yyyyMMdd_HHmm')_Azure-Network.drawio",

    [Parameter(ParameterSetName = 'Azure')]
    [Parameter(ParameterSetName = 'Input')]
    [switch]$Quiet,

    [Parameter(Mandatory, ParameterSetName = 'Version')]
    [switch]$Version,

    [Parameter(Mandatory, ParameterSetName = 'Help')]
    [switch]$Help
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Date-based version of the exporter (VYYYYMMDD). Surfaced in the banner and
# stamped into the mxfile so a generated diagram records which build produced it.
$script:VNetAtlasVersion = 'V20260930'

# API version for every direct Azure Resource Manager read of firewall policy data.
$script:FirewallPolicyApiVersion = '2024-05-01'

# Progress goes to the host stream so the single stdout summary line stays the
# script's only pipeline output.
$script:ShowStatus = -not $Quiet.IsPresent

function Write-StatusMessage {
    param([string]$Message = '', [string]$Color = '')

    if (-not $script:ShowStatus) { return }
    if ($Color) {
        Write-Host $Message -ForegroundColor $Color
    } else {
        Write-Host $Message
    }
}

function Write-StatusBanner {
    if (-not $script:ShowStatus) { return }

    # Single-quoted here-string: the artwork contains backticks and backslashes
    # that PowerShell would otherwise treat as escapes.
    $banner = @'
 _    ___   __     __  ___   __  __          
| |  / / | / /__  / /_/   | / /_/ /___ ______
| | / /  |/ / _ \/ __/ /| |/ __/ / __ `/ ___/
| |/ / /|  /  __/ /_/ ___ / /_/ / /_/ (__  ) 
|___/_/ |_/\___/\__/_/  |_\__/_/\__,_/____/
'@
    foreach ($line in ($banner -split "`r?`n")) { Write-StatusMessage $line 'Cyan' }
    Write-StatusMessage "Azure network maps for draw.io   $script:VNetAtlasVersion" 'DarkGray'
    Write-StatusMessage ''
}

function Write-StatusStep {
    param([int]$Number, [int]$Total, [string]$Message)
    Write-StatusMessage "[$Number/$Total] $Message" 'Cyan'
}

function Write-StatusDetail {
    param([string]$Message)
    Write-StatusMessage "      $Message" 'DarkGray'
}

function Write-StatusProgress {
    param([string]$Activity, [string]$Status, [int]$Current, [int]$Total)

    if (-not $script:ShowStatus) { return }
    $percent = 0
    if ($Total -gt 0) { $percent = [int](($Current / $Total) * 100) }
    Write-Progress -Activity $Activity -Status $Status -PercentComplete ([math]::Min(100, [math]::Max(0, $percent)))
}

function Complete-StatusProgress {
    param([string]$Activity)
    if ($script:ShowStatus) { Write-Progress -Activity $Activity -Completed }
}

function Select-ScopedVnet {
    param(
        [object[]]$Vnets,
        [string[]]$VnetName,
        [string[]]$ResourceGroup,
        [string[]]$ExcludeSubscriptionId
    )

    $excluded = @()
    if ($ExcludeSubscriptionId) {
        $excluded = @($ExcludeSubscriptionId | ForEach-Object { ConvertTo-ResourceId $_ } | Where-Object { $_ })
    }
    return @($Vnets | Where-Object {
        $name = [string](Get-ObjectValue $_ 'name' '')
        $group = [string](Get-ObjectValue $_ 'resourceGroup' '')
        $subscription = ConvertTo-ResourceId (Get-ObjectValue $_ 'subscriptionId' '')
        $keep = $true
        if ($VnetName) { $keep = $keep -and (@($VnetName | Where-Object { $name -like $_ }).Count -gt 0) }
        if ($ResourceGroup) { $keep = $keep -and (@($ResourceGroup | Where-Object { $group -like $_ }).Count -gt 0) }
        if ($excluded.Count -gt 0) { $keep = $keep -and ($excluded -notcontains $subscription) }
        $keep
    })
}

function Show-VNetAtlasHelp {
    # Banner on the host stream, usage on stdout, so `-Help > usage.txt` captures
    # clean text while an interactive run still shows the artwork.
    Write-StatusBanner
    Write-Output @'
USAGE
  Export-VNetAtlas.ps1 [-SubscriptionId <ids>] [-TenantId <id>] [-ExportDataPath <file>] [options]
  Export-VNetAtlas.ps1 -InputDataPath <file> [options]
  Export-VNetAtlas.ps1 -Version
  Export-VNetAtlas.ps1 -Help

SOURCE (choose one)
  -SubscriptionId <string[]>     Subscriptions to query. Omit for every enabled subscription.
  -TenantId <string>             Tenant to export. Re-authenticates if the context differs.
  -InputDataPath <file>          Rebuild from exported JSON instead of querying Azure.

SCOPE
  -VnetName <string[]>           Only VNets matching these names. Wildcards allowed.
  -ResourceGroup <string[]>      Only VNets in these resource groups. Wildcards allowed.
  -ExcludeSubscriptionId <ids>   Drop VNets in these subscriptions. Applied after -SubscriptionId.

OUTPUT
  -OutputPath <file>             Target .drawio file. Default: .\<yyyyMMdd_HHmm>_Azure-Network.drawio
  -ExportDataPath <file>         Also save the normalized query results as JSON.
  -ResourcesPerRow <1-4>         Resources per line inside a subnet. Default: 2.
  -SkipRuleDetailPages           Omit the NSG, route-table, and firewall-policy detail pages.
  -SkipFirewallRules             Do not read firewall policy rules or build their pages.
  -SkipDefaultNsgRules           Omit Azure's built-in default rules from NSG pages.
  -Quiet                         Suppress the banner and progress output.

OTHER
  -Version                       Print the version and exit.
  -Help                          Print this help and exit.
  -Verbose                       Narrate the Azure query path.

NOTES
  Any scope filter suppresses the Unmapped Resources page, because "unmapped"
  would otherwise mean "outside the VNets you selected".
'@
}

function Format-ElapsedTime {
    param([TimeSpan]$Elapsed)

    if ($Elapsed.TotalMinutes -ge 1) {
        return '{0:0}m {1:00}s' -f [math]::Floor($Elapsed.TotalMinutes), $Elapsed.Seconds
    }
    return '{0:0.0}s' -f $Elapsed.TotalSeconds
}

function Format-FileSize {
    param([long]$Bytes)

    if ($Bytes -ge 1MB) { return '{0:0.0} MB' -f ($Bytes / 1MB) }
    if ($Bytes -ge 1KB) { return '{0:0} KB' -f ($Bytes / 1KB) }
    return "$Bytes B"
}

function Resolve-LocalFilePath {
    param([Parameter(Mandatory)][string]$Path)

    try {
        # Unlike [IO.Path]::GetFullPath(), this resolves relative paths against
        # PowerShell's current filesystem location ($PWD), not the process CWD.
        return $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
    }
    catch {
        throw "Unable to resolve '$Path' as a local filesystem path: $($_.Exception.Message)"
    }
}

function Get-ObjectValue {
    param(
        [AllowNull()][object]$Object,
        [Parameter(Mandatory)][string]$Name,
        [AllowNull()][object]$Default = $null
    )

    if ($null -eq $Object) { return $Default }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property -or $null -eq $property.Value) { return $Default }
    return $property.Value
}

function ConvertTo-ResourceId {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return '' }
    return ([string]$Value).Trim().ToLowerInvariant()
}

function Get-ResourceNameFromId {
    param([AllowNull()][string]$ResourceId)
    if ([string]::IsNullOrWhiteSpace($ResourceId)) { return '(unknown)' }
    return ($ResourceId.TrimEnd('/') -split '/')[-1]
}

function ConvertFrom-JsonCollection {
    param([AllowNull()][object]$Json)

    if ($null -eq $Json -or [string]::IsNullOrWhiteSpace([string]$Json) -or [string]$Json -eq '[]') {
        return @()
    }
    try {
        $parsed = [string]$Json | ConvertFrom-Json
        return @($parsed | ForEach-Object { $_ })
    }
    catch {
        return @()
    }
}

function ConvertTo-DisplayList {
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) { return '' }
    $text = [string]$Value
    if ([string]::IsNullOrWhiteSpace($text) -or $text -eq '[]') { return '' }
    if ($text.StartsWith('[')) {
        try { return (@(ConvertFrom-JsonCollection $text) -join ', ') } catch { return $text }
    }
    return $text
}

function Invoke-ResourceGraphPaged {
    param(
        [Parameter(Mandatory)][string]$Query,
        [string[]]$Subscriptions
    )

    $results = [System.Collections.Generic.List[object]]::new()
    $skip = 0
    do {
        $parameters = @{
            Query       = $Query
            First       = 1000
            ErrorAction = 'Stop'
        }
        if ($skip -gt 0) { $parameters.Skip = $skip }
        if ($Subscriptions -and $Subscriptions.Count -gt 0) {
            $parameters.Subscription = $Subscriptions
        }

        $response = Search-AzGraph @parameters
        $page = @()
        if ($null -ne $response) {
            $dataProperty = $response.PSObject.Properties['Data']
            if ($null -ne $dataProperty) {
                $page = @($dataProperty.Value)
            } else {
                $page = @($response)
            }
        }
        foreach ($item in $page) { $results.Add($item) }
        $skip += $page.Count
    } while ($page.Count -eq 1000)

    return $results.ToArray()
}

function Write-ExpandLimitWarning {
    param(
        [Parameter(Mandatory)][string]$QueryName,
        [object[]]$Rows,
        [Parameter(Mandatory)][string]$ParentProperty,
        [int]$RowLimit = 2000
    )

    # A resource whose expansion reached the mv-expand limit used in the queries
    # has most likely lost the entries beyond it.
    $rowCountByParentId = @{}
    foreach ($row in $Rows) {
        $parentId = [string](Get-ObjectValue $row $ParentProperty '')
        if (-not $parentId) { continue }
        $rowCountByParentId[$parentId] = 1 + [int]$rowCountByParentId[$parentId]
    }
    foreach ($parentId in @($rowCountByParentId.Keys | Sort-Object)) {
        if ($rowCountByParentId[$parentId] -ge $RowLimit) {
            Write-Warning "Resource Graph returned $($rowCountByParentId[$parentId]) '$QueryName' rows for $parentId, its per-resource expansion limit. Entries beyond $RowLimit may be missing from the diagram."
        }
    }
}

function Invoke-ArmGetRequest {
    param([Parameter(Mandatory)][string]$Target)

    # The only place this script reads Azure Resource Manager directly. Accepts a
    # resource path or an absolute nextLink. The returned error is short by
    # design: it never carries the response body, headers, or token material.
    $parameters = @{ Method = 'GET'; ErrorAction = 'Stop' }
    if ($Target -match '^https?://') {
        $parameters.Uri = $Target
    } else {
        $parameters.Path = $Target
    }
    try {
        $response = Invoke-AzRestMethod @parameters
    }
    catch {
        $reason = @(([string]$_.Exception.Message -split "`r?`n") | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        $text = 'Request failed'
        if ($reason.Count -gt 0) { $text = "Request failed: $($reason[0].Trim())" }
        if ($text.Length -gt 300) { $text = $text.Substring(0, 300) }
        return [pscustomobject]@{ Content = $null; Error = $text }
    }

    $statusCode = [int]$response.StatusCode
    $content = $null
    try { $content = [string]$response.Content | ConvertFrom-Json } catch { $content = $null }
    if ($statusCode -lt 200 -or $statusCode -ge 300) {
        $serviceError = Get-ObjectValue $content 'error' $null
        $detail = @(
            [string](Get-ObjectValue $serviceError 'code' ''),
            [string](Get-ObjectValue $serviceError 'message' '')
        ) | Where-Object { $_ }
        $text = "HTTP $statusCode"
        if (@($detail).Count -gt 0) { $text = "HTTP $statusCode - $(@($detail) -join ': ')" }
        if ($text.Length -gt 300) { $text = $text.Substring(0, 300) }
        return [pscustomobject]@{ Content = $null; Error = $text }
    }
    if ($null -eq $content) {
        return [pscustomobject]@{ Content = $null; Error = "HTTP $statusCode with unreadable content" }
    }
    return [pscustomobject]@{ Content = $content; Error = '' }
}

function Get-FirewallPolicyData {
    param([object[]]$FirewallRows)

    # Resource Graph does not return firewall policy rules, so every policy in
    # use, and every parent policy it inherits from, is read from ARM.
    $pending = [System.Collections.Generic.Queue[string]]::new()
    $visitedPolicyIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $attachedPolicyIds = @($FirewallRows | ForEach-Object { ConvertTo-ResourceId (Get-ObjectValue $_ 'firewallPolicyId' '') } |
        Where-Object { $_ } | Sort-Object -Unique)
    foreach ($policyId in $attachedPolicyIds) {
        if ($visitedPolicyIds.Add($policyId)) { $pending.Enqueue($policyId) }
    }

    $rows = [System.Collections.Generic.List[object]]::new()
    $requestCount = 0
    while ($pending.Count -gt 0) {
        $policyId = $pending.Dequeue()
        $policyName = Get-ResourceNameFromId $policyId
        Write-StatusProgress 'Reading firewall policies' $policyName $rows.Count $visitedPolicyIds.Count

        $metadataError = ''
        $policy = $null
        $metadata = Invoke-ArmGetRequest "${policyId}?api-version=$script:FirewallPolicyApiVersion"
        $requestCount++
        if ($metadata.Error) {
            $metadataError = $metadata.Error
            Write-Warning "Firewall policy '$policyName': settings could not be read ($metadataError)."
        } else {
            $policy = $metadata.Content
        }
        $properties = Get-ObjectValue $policy 'properties' $null
        $basePolicyId = ConvertTo-ResourceId (Get-ObjectValue (Get-ObjectValue $properties 'basePolicy' $null) 'id' '')
        if ($basePolicyId -and $visitedPolicyIds.Add($basePolicyId)) { $pending.Enqueue($basePolicyId) }

        # Rules are kept only when every page was read, so a partial result can
        # never be mistaken for the complete rule set.
        $groups = [System.Collections.Generic.List[object]]::new()
        $ruleError = ''
        $visitedLinks = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
        $target = "${policyId}/ruleCollectionGroups?api-version=$script:FirewallPolicyApiVersion"
        while ($target) {
            if (-not $visitedLinks.Add($target)) {
                $ruleError = 'Pagination returned a repeated link'
                break
            }
            $page = Invoke-ArmGetRequest $target
            $requestCount++
            if ($page.Error) {
                $ruleError = $page.Error
                break
            }
            foreach ($group in @(Get-ObjectValue $page.Content 'value' @())) {
                if ($null -ne $group) { $groups.Add($group) }
            }
            $target = [string](Get-ObjectValue $page.Content 'nextLink' '')
        }
        $ruleCollectionGroups = ''
        if ($ruleError) {
            Write-Warning "Firewall policy '$policyName': rules could not be read ($ruleError)."
        } else {
            # Groups and collections are sorted for stable output. Rule order
            # inside a collection is meaningful and kept as returned.
            $sortedGroups = @($groups | Sort-Object `
                @{Expression={ [int](Get-ObjectValue (Get-ObjectValue $_ 'properties' $null) 'priority' 0) }},
                @{Expression={ [string](Get-ObjectValue $_ 'name' '') }},
                @{Expression={ ConvertTo-ResourceId (Get-ObjectValue $_ 'id' '') }})
            $normalizedGroups = @(foreach ($group in $sortedGroups) {
                $groupProperties = Get-ObjectValue $group 'properties' $null
                $collections = @(@(Get-ObjectValue $groupProperties 'ruleCollections' @()) | Where-Object { $null -ne $_ } | Sort-Object `
                    @{Expression={ [int](Get-ObjectValue $_ 'priority' 0) }},
                    @{Expression={ [string](Get-ObjectValue $_ 'name' '') }})
                [pscustomobject][ordered]@{
                    id = ConvertTo-ResourceId (Get-ObjectValue $group 'id' '')
                    name = [string](Get-ObjectValue $group 'name' '')
                    priority = [int](Get-ObjectValue $groupProperties 'priority' 0)
                    ruleCollections = $collections
                }
            })
            $ruleCollectionGroups = ConvertTo-Json -InputObject $normalizedGroups -Depth 100 -Compress
        }

        # Inspection and DNS settings stay null when the policy could not be read,
        # so the page can tell "not reported" apart from "off" or "default".
        $dnsSettings = Get-ObjectValue $properties 'dnsSettings' $null
        $intrusionDetectionMode = $null
        $signatureOverrideCount = $null
        $bypassRuleCount = $null
        $tlsInspectionEnabled = $null
        $tlsCertificateName = ''
        $dnsServers = $null
        if ($null -ne $policy) {
            $intrusionDetection = Get-ObjectValue $properties 'intrusionDetection' $null
            $intrusionConfiguration = Get-ObjectValue $intrusionDetection 'configuration' $null
            $intrusionDetectionMode = [string](Get-ObjectValue $intrusionDetection 'mode' 'Off')
            $signatureOverrideCount = @(Get-ObjectValue $intrusionConfiguration 'signatureOverrides' @()).Count
            $bypassRuleCount = @(Get-ObjectValue $intrusionConfiguration 'bypassTrafficSettings' @()).Count
            $certificateAuthority = Get-ObjectValue (Get-ObjectValue $properties 'transportSecurity' $null) 'certificateAuthority' $null
            $tlsInspectionEnabled = $null -ne $certificateAuthority
            $tlsCertificateName = [string](Get-ObjectValue $certificateAuthority 'name' '')
            $dnsServerList = @(@(Get-ObjectValue $dnsSettings 'servers' @()) | ForEach-Object { [string]$_ } | Where-Object { $_ })
            $dnsServers = ConvertTo-Json -InputObject $dnsServerList -Compress
        }

        $subscriptionId = ''
        $resourceGroup = ''
        if ($policyId -match '^/subscriptions/([^/]+)/resourcegroups/([^/]+)/') {
            $subscriptionId = $Matches[1]
            $resourceGroup = $Matches[2]
        }
        $rows.Add([pscustomobject][ordered]@{
            id = $policyId
            name = [string](Get-ObjectValue $policy 'name' $policyName)
            resourceGroup = $resourceGroup
            subscriptionId = $subscriptionId
            location = [string](Get-ObjectValue $policy 'location' '')
            tier = [string](Get-ObjectValue (Get-ObjectValue $properties 'sku' $null) 'tier' '')
            threatIntelMode = [string](Get-ObjectValue $properties 'threatIntelMode' '')
            dnsProxyEnabled = Get-ObjectValue $dnsSettings 'enableProxy' $null
            dnsServers = $dnsServers
            intrusionDetectionMode = $intrusionDetectionMode
            intrusionDetectionSignatureOverrides = $signatureOverrideCount
            intrusionDetectionBypassRules = $bypassRuleCount
            tlsInspectionEnabled = $tlsInspectionEnabled
            tlsInspectionCertificateName = $tlsCertificateName
            basePolicyId = $basePolicyId
            provisioningState = [string](Get-ObjectValue $properties 'provisioningState' '')
            ruleCollectionGroups = $ruleCollectionGroups
            metadataError = $metadataError
            ruleError = $ruleError
        })
    }
    Complete-StatusProgress 'Reading firewall policies'
    return [pscustomobject]@{
        Rows = @($rows | Sort-Object @{Expression={ [string]$_.name }}, @{Expression={ [string]$_.id }})
        RequestCount = $requestCount
    }
}

function Get-AzureNetworkData {
    param([string[]]$Subscriptions, [string]$RequestedTenantId, [switch]$SkipFirewallRules)

    $requiredModules = @('Az.Accounts', 'Az.ResourceGraph')
    $missingModules = @($requiredModules | Where-Object { -not (Get-Module -ListAvailable -Name $_) })
    if ($missingModules.Count -gt 0) {
        $moduleList = ($missingModules | ForEach-Object { "  - $_" }) -join "`n"
        $installNames = $missingModules -join ', '
        throw "Required PowerShell modules are not installed:`n$moduleList`nInstall them with:`n  Install-Module -Name $installNames -Scope CurrentUser"
    }
    Import-Module Az.Accounts -ErrorAction Stop
    Import-Module Az.ResourceGraph -ErrorAction Stop

    $context = Get-AzContext -ErrorAction SilentlyContinue
    if ($null -eq $context -or ($RequestedTenantId -and $context.Tenant.Id -ne $RequestedTenantId)) {
        $connectParameters = @{}
        if ($RequestedTenantId) { $connectParameters.Tenant = $RequestedTenantId }
        $null = Connect-AzAccount @connectParameters
        $context = Get-AzContext -ErrorAction Stop
    }

    $tenantId = [string]$context.Tenant.Id
    $availableSubscriptions = @(Get-AzSubscription -TenantId $tenantId -ErrorAction Stop |
        Where-Object { -not $_.State -or $_.State -eq 'Enabled' })
    if (-not $Subscriptions -or $Subscriptions.Count -eq 0) {
        $Subscriptions = @($availableSubscriptions | ForEach-Object { [string]$_.Id } | Sort-Object -Unique)
        if ($Subscriptions.Count -eq 0) {
            throw "No enabled Azure subscriptions are available in tenant '$tenantId'."
        }
        Write-Verbose "No -SubscriptionId was supplied; querying all $($Subscriptions.Count) enabled subscription(s) in tenant '$tenantId'."
        $selectionNote = 'all enabled'
    } else {
        $Subscriptions = @($Subscriptions | ForEach-Object { ([string]$_).Trim().ToLowerInvariant() } |
            Where-Object { $_ } | Sort-Object -Unique)
        $availableIds = @($availableSubscriptions | ForEach-Object { ([string]$_.Id).ToLowerInvariant() })
        $unavailable = @($Subscriptions | Where-Object { $availableIds -notcontains $_ })
        if ($unavailable.Count -gt 0) {
            throw "The following subscription IDs are not enabled or accessible in tenant '$tenantId': $($unavailable -join ', ')"
        }
        Write-Verbose "Querying $($Subscriptions.Count) explicitly selected subscription(s) in tenant '$tenantId'."
        $selectionNote = 'explicitly selected'
    }
    Write-StatusDetail "Tenant $tenantId"
    Write-StatusDetail "$($Subscriptions.Count) subscription(s), $selectionNote"

    # Resource Graph expands only 128 array entries per resource unless mv-expand
    # sets a limit; 2,000 is the service maximum.
    $queries = @{
        subscriptions = @'
ResourceContainers
| where type =~ 'microsoft.resources/subscriptions'
| project subscriptionId=tolower(subscriptionId), subscriptionName=name
| order by subscriptionName asc
'@
        vnets = @'
Resources
| where type =~ 'microsoft.network/virtualnetworks'
| project id=tolower(id), name, resourceGroup, subscriptionId, location,
          addressPrefixes=tostring(properties.addressSpace.addressPrefixes)
| order by id asc
'@
        subnets = @'
Resources
| where type =~ 'microsoft.network/virtualnetworks'
| mv-expand subnet=properties.subnets limit 2000
| project id=tolower(tostring(subnet.id)), name=tostring(subnet.name), vnetId=tolower(id),
          addressPrefix=tostring(subnet.properties.addressPrefix),
          addressPrefixes=tostring(subnet.properties.addressPrefixes),
          nsgId=tolower(tostring(subnet.properties.networkSecurityGroup.id)),
          natGatewayId=tolower(tostring(subnet.properties.natGateway.id)),
          routeTableId=tolower(tostring(subnet.properties.routeTable.id)),
          delegations=tostring(subnet.properties.delegations),
          serviceEndpoints=tostring(subnet.properties.serviceEndpoints),
          privateEndpointNetworkPolicies=tostring(subnet.properties.privateEndpointNetworkPolicies),
          privateLinkServiceNetworkPolicies=tostring(subnet.properties.privateLinkServiceNetworkPolicies),
          ipConfigurations=tostring(subnet.properties.ipConfigurations),
          serviceAssociationLinks=tostring(subnet.properties.serviceAssociationLinks),
          resourceGroup, subscriptionId, location
| order by id asc
'@
        nics = @'
Resources
| where type =~ 'microsoft.network/networkinterfaces'
| extend nicId=tolower(id), nicName=name,
         nicNsgId=tolower(tostring(properties.networkSecurityGroup.id)),
         attachedResourceId=tolower(tostring(properties.virtualMachine.id))
| mv-expand ipConfig=properties.ipConfigurations limit 2000
| project nicId, nicName, resourceGroup, subscriptionId, location, attachedResourceId, nicNsgId,
          ipConfigurationName=tostring(ipConfig.name),
          privateIpAddress=tostring(ipConfig.properties.privateIPAddress),
          privateIpAllocationMethod=tostring(ipConfig.properties.privateIPAllocationMethod),
          subnetId=tolower(tostring(ipConfig.properties.subnet.id)),
          publicIpId=tolower(tostring(ipConfig.properties.publicIPAddress.id)),
          isPrimary=tobool(ipConfig.properties.primary)
| order by nicId asc, ipConfigurationName asc
'@
        publicIps = @'
Resources
| where type =~ 'microsoft.network/publicipaddresses'
| project id=tolower(id), name, resourceGroup, subscriptionId, location,
          ipAddress=tostring(properties.ipAddress),
          allocationMethod=tostring(properties.publicIPAllocationMethod),
          ipVersion=tostring(properties.publicIPAddressVersion),
          fqdn=tostring(properties.dnsSettings.fqdn), sku=tostring(sku.name),
          ipConfigurationId=tolower(tostring(properties.ipConfiguration.id)),
          natGatewayId=tolower(tostring(properties.natGateway.id))
| order by id asc
'@
        publicIpPrefixes = @'
Resources
| where type =~ 'microsoft.network/publicipprefixes'
| project id=tolower(id), name, resourceGroup, subscriptionId, location,
          ipPrefix=tostring(properties.ipPrefix),
          prefixLength=toint(properties.prefixLength),
          ipVersion=tostring(properties.publicIPAddressVersion), sku=tostring(sku.name)
| order by id asc
'@
        nsgs = @'
Resources
| where type =~ 'microsoft.network/networksecuritygroups'
| project id=tolower(id), name, resourceGroup, subscriptionId, location,
          securityRuleCount=array_length(properties.securityRules),
          defaultRuleCount=array_length(properties.defaultSecurityRules),
          securityRules=tostring(properties.securityRules),
          defaultSecurityRules=tostring(properties.defaultSecurityRules)
| order by id asc
'@
        natGateways = @'
Resources
| where type =~ 'microsoft.network/natgateways'
| project id=tolower(id), name, sku=tostring(sku.name),
          publicIpIds=tostring(properties.publicIpAddresses),
          publicIpIdsV6=tostring(properties.publicIpAddressesV6),
          publicIpPrefixIds=tostring(properties.publicIpPrefixes),
          publicIpPrefixIdsV6=tostring(properties.publicIpPrefixesV6),
          resourceGroup, subscriptionId, location
| order by id asc
'@
        virtualMachines = @'
Resources
| where type =~ 'microsoft.compute/virtualmachines'
| mv-expand nic=properties.networkProfile.networkInterfaces limit 2000
| project id=tolower(id), name, resourceGroup, subscriptionId, location,
          vmSize=tostring(properties.hardwareProfile.vmSize),
          osType=tostring(properties.storageProfile.osDisk.osType),
          nicId=tolower(tostring(nic.id))
| order by id asc, nicId asc
'@
        virtualMachineScaleSets = @'
Resources
| where type =~ 'microsoft.compute/virtualmachinescalesets'
| project id=tolower(id), name, resourceGroup, subscriptionId, location,
          sku=tostring(sku.name), capacity=toint(sku.capacity),
          orchestrationMode=tostring(properties.orchestrationMode),
          upgradeMode=tostring(properties.upgradePolicy.mode),
          networkInterfaceConfigurations=tostring(properties.virtualMachineProfile.networkProfile.networkInterfaceConfigurations)
| order by id asc
'@
        vnetPeerings = @'
Resources
| where type =~ 'microsoft.network/virtualnetworks'
| mv-expand peering=properties.virtualNetworkPeerings limit 2000
| project id=tolower(tostring(peering.id)), name=tostring(peering.name),
          vnetId=tolower(id), remoteVnetId=tolower(tostring(peering.properties.remoteVirtualNetwork.id)),
          state=tostring(peering.properties.peeringState),
          allowForwardedTraffic=tobool(peering.properties.allowForwardedTraffic),
          allowGatewayTransit=tobool(peering.properties.allowGatewayTransit),
          useRemoteGateways=tobool(peering.properties.useRemoteGateways),
          subscriptionId, resourceGroup
| order by vnetId asc, name asc
'@
        loadBalancers = @'
Resources
| where type =~ 'microsoft.network/loadbalancers'
| extend frontends=iff(array_length(properties.frontendIPConfigurations) > 0,
                       properties.frontendIPConfigurations, dynamic([{}]))
| mv-expand frontend=frontends limit 2000
| project id=tolower(id), name, resourceGroup, subscriptionId, location, sku=tostring(sku.name),
          frontendName=tostring(frontend.name),
          subnetId=tolower(tostring(frontend.properties.subnet.id)),
          publicIpId=tolower(tostring(frontend.properties.publicIPAddress.id)),
          backendPools=tostring(properties.backendAddressPools),
          ruleCount=array_length(properties.loadBalancingRules)
| order by id asc, frontendName asc
'@
        applicationGateways = @'
Resources
| where type =~ 'microsoft.network/applicationgateways'
| extend gatewayIpConfigurations=properties.gatewayIPConfigurations,
         frontendIpConfigurations=properties.frontendIPConfigurations
| project id=tolower(id), name, resourceGroup, subscriptionId, location,
          sku=tostring(properties.sku.name), tier=tostring(properties.sku.tier),
          subnetId=tolower(tostring(gatewayIpConfigurations[0].properties.subnet.id)),
          publicIpId=tolower(tostring(frontendIpConfigurations[0].properties.publicIPAddress.id)),
          frontendName=tostring(frontendIpConfigurations[0].name),
          gatewayIpConfigurations=tostring(gatewayIpConfigurations),
          frontendIpConfigurations=tostring(frontendIpConfigurations)
| order by id asc
'@
        firewalls = @'
Resources
| where type =~ 'microsoft.network/azurefirewalls'
| extend ipConfigurations=iff(array_length(properties.ipConfigurations) > 0,
                              properties.ipConfigurations, dynamic([{}]))
| mv-expand ipConfig=ipConfigurations limit 2000
| project id=tolower(id), name, resourceGroup, subscriptionId, location,
          sku=tostring(properties.sku.name), tier=tostring(properties.sku.tier),
          subnetId=tolower(tostring(ipConfig.properties.subnet.id)),
          privateIpAddress=tostring(ipConfig.properties.privateIPAddress),
          publicIpId=tolower(tostring(ipConfig.properties.publicIPAddress.id)),
          managementSubnetId=tolower(tostring(properties.managementIpConfiguration.properties.subnet.id)),
          managementPrivateIpAddress=tostring(properties.managementIpConfiguration.properties.privateIPAddress),
          managementPublicIpId=tolower(tostring(properties.managementIpConfiguration.properties.publicIPAddress.id)),
          managementIpConfigurationId=tolower(tostring(properties.managementIpConfiguration.id)),
          firewallPolicyId=tolower(tostring(properties.firewallPolicy.id)),
          threatIntelMode=tostring(properties.threatIntelMode),
          zones=tostring(zones),
          provisioningState=tostring(properties.provisioningState),
          virtualHubId=tolower(tostring(properties.virtualHub.id)),
          hubPrivateIpAddress=tostring(properties.hubIPAddresses.privateIPAddress),
          hubPublicIpAddresses=tostring(properties.hubIPAddresses.publicIPs.addresses)
| order by id asc
'@
        privateEndpoints = @'
Resources
| where type =~ 'microsoft.network/privateendpoints'
| extend automaticConnections=iff(isnull(properties.privateLinkServiceConnections),
                                  dynamic([]), properties.privateLinkServiceConnections),
         manualConnections=iff(isnull(properties.manualPrivateLinkServiceConnections),
                               dynamic([]), properties.manualPrivateLinkServiceConnections)
| extend connections=array_concat(automaticConnections, manualConnections)
| extend connections=iff(array_length(connections) > 0, connections, dynamic([{}]))
| mv-expand connection=connections limit 2000
| project id=tolower(id), name, resourceGroup, subscriptionId, location,
          subnetId=tolower(tostring(properties.subnet.id)),
          targetId=tolower(tostring(connection.properties.privateLinkServiceId)),
          groupIds=tostring(connection.properties.groupIds),
          connectionState=tostring(connection.properties.privateLinkServiceConnectionState.status),
          networkInterfaces=tostring(properties.networkInterfaces)
| order by id asc
'@
        routeTables = @'
Resources
| where type =~ 'microsoft.network/routetables'
| project id=tolower(id), name, resourceGroup, subscriptionId, location,
          routeCount=array_length(properties.routes),
          disableBgpRoutePropagation=tobool(properties.disableBgpRoutePropagation),
          routes=tostring(properties.routes)
| order by id asc
'@
        virtualNetworkGateways = @'
Resources
| where type =~ 'microsoft.network/virtualnetworkgateways'
| mv-expand ipConfig=properties.ipConfigurations limit 2000
| project id=tolower(id), name, resourceGroup, subscriptionId, location,
          gatewayType=tostring(properties.gatewayType), vpnType=tostring(properties.vpnType),
          sku=tostring(properties.sku.name), generation=tostring(properties.vpnGatewayGeneration),
          subnetId=tolower(tostring(ipConfig.properties.subnet.id)),
          privateIpAddress=tostring(ipConfig.properties.privateIPAddress),
          publicIpId=tolower(tostring(ipConfig.properties.publicIPAddress.id))
| order by id asc
'@
        bastionHosts = @'
Resources
| where type =~ 'microsoft.network/bastionhosts'
| extend ipConfigurations=iff(array_length(properties.ipConfigurations) > 0,
                              properties.ipConfigurations, dynamic([{}]))
| mv-expand ipConfig=ipConfigurations limit 2000
| project id=tolower(id), name, resourceGroup, subscriptionId, location,
          sku=tostring(sku.name), scaleUnits=toint(properties.scaleUnits),
          enableTunneling=tobool(properties.enableTunneling),
          enableIpConnect=tobool(properties.enableIpConnect),
          enableShareableLink=tobool(properties.enableShareableLink),
          enableKerberos=tobool(properties.enableKerberos),
          provisioningState=tostring(properties.provisioningState),
          subnetId=tolower(tostring(ipConfig.properties.subnet.id)),
          privateIpAddress=tostring(ipConfig.properties.privateIPAddress),
          publicIpId=tolower(tostring(ipConfig.properties.publicIPAddress.id))
| order by id asc
'@
        localNetworkGateways = @'
Resources
| where type =~ 'microsoft.network/localnetworkgateways'
| project id=tolower(id), name, resourceGroup, subscriptionId, location,
          gatewayIpAddress=tostring(properties.gatewayIpAddress),
          addressPrefixes=tostring(properties.localNetworkAddressSpace.addressPrefixes),
          bgpAsn=tostring(properties.bgpSettings.asn),
          bgpPeeringAddress=tostring(properties.bgpSettings.bgpPeeringAddress),
          provisioningState=tostring(properties.provisioningState)
| order by id asc
'@
        gatewayConnections = @'
Resources
| where type =~ 'microsoft.network/connections'
| project id=tolower(id), name, resourceGroup, subscriptionId, location,
          connectionType=tostring(properties.connectionType),
          connectionStatus=tostring(properties.connectionStatus),
          provisioningState=tostring(properties.provisioningState),
          routingWeight=toint(properties.routingWeight),
          enableBgp=tobool(properties.enableBgp),
          useLocalAzureIpAddress=tobool(properties.useLocalAzureIpAddress),
          vnetGateway1Id=tolower(tostring(properties.virtualNetworkGateway1.id)),
          vnetGateway2Id=tolower(tostring(properties.virtualNetworkGateway2.id)),
          localNetworkGateway2Id=tolower(tostring(properties.localNetworkGateway2.id)),
          expressRouteCircuitId=tolower(tostring(properties.peer.id))
| order by id asc
'@
        expressRouteCircuits = @'
Resources
| where type =~ 'microsoft.network/expressroutecircuits'
| project id=tolower(id), name, resourceGroup, subscriptionId, location,
          sku=tostring(sku.name), tier=tostring(sku.tier), family=tostring(sku.family),
          serviceProvider=tostring(properties.serviceProviderProperties.serviceProviderName),
          peeringLocation=tostring(properties.serviceProviderProperties.peeringLocation),
          bandwidthMbps=toint(properties.serviceProviderProperties.bandwidthInMbps),
          serviceProviderState=tostring(properties.serviceProviderProvisioningState),
          circuitState=tostring(properties.circuitProvisioningState),
          provisioningState=tostring(properties.provisioningState)
| order by id asc
'@
        expressRouteGateways = @'
Resources
| where type =~ 'microsoft.network/expressroutegateways'
| project id=tolower(id), name, resourceGroup, subscriptionId, location,
          virtualHubId=tolower(tostring(properties.virtualHub.id)),
          scaleUnits=toint(properties.autoScaleConfiguration.bounds.max)
| order by id asc
'@
        virtualHubs = @'
Resources
| where type =~ 'microsoft.network/virtualhubs'
| project id=tolower(id), name, resourceGroup, subscriptionId, location,
          addressPrefix=tostring(properties.addressPrefix),
          virtualRouterAsn=tostring(properties.virtualRouterAsn),
          virtualRouterIps=tostring(properties.virtualRouterIps),
          provisioningState=tostring(properties.provisioningState)
| order by id asc
'@
        hubVirtualNetworkConnections = @'
Resources
| where type =~ 'microsoft.network/virtualhubs/hubvirtualnetworkconnections'
| project id=tolower(id), name, resourceGroup, subscriptionId,
          virtualHubId=tolower(extract('(?i)(.*)/hubvirtualnetworkconnections/[^/]+$', 1, id)),
          remoteVnetId=tolower(tostring(properties.remoteVirtualNetwork.id)),
          provisioningState=tostring(properties.provisioningState),
          routingConfiguration=tostring(properties.routingConfiguration)
| order by id asc
'@
    }

    $queryNames = @(
        'subscriptions', 'vnets', 'subnets', 'nics', 'publicIps', 'publicIpPrefixes', 'nsgs', 'natGateways', 'virtualMachines',
        'virtualMachineScaleSets',
        'vnetPeerings', 'loadBalancers', 'applicationGateways', 'firewalls', 'privateEndpoints',
        'routeTables', 'virtualNetworkGateways', 'bastionHosts', 'localNetworkGateways',
        'gatewayConnections', 'expressRouteCircuits', 'expressRouteGateways', 'virtualHubs',
        'hubVirtualNetworkConnections'
    )
    # Column identifying the expanded resource in each query that uses mv-expand.
    $expandParentPropertyByQuery = @{
        subnets = 'vnetId'; nics = 'nicId'; virtualMachines = 'id'; vnetPeerings = 'vnetId'
        loadBalancers = 'id'; firewalls = 'id'; privateEndpoints = 'id'
        virtualNetworkGateways = 'id'; bastionHosts = 'id'
    }
    $data = [ordered]@{}
    $totalRows = 0
    $queryTimer = [System.Diagnostics.Stopwatch]::StartNew()
    for ($queryIndex = 0; $queryIndex -lt $queryNames.Count; $queryIndex++) {
        $name = $queryNames[$queryIndex]
        Write-StatusProgress 'Querying Azure Resource Graph' "$name ($($queryIndex + 1) of $($queryNames.Count))" $queryIndex $queryNames.Count
        Write-Verbose "Querying $name..."
        $rows = @(Invoke-ResourceGraphPaged -Query $queries[$name] -Subscriptions $Subscriptions)
        $data[$name] = $rows
        $totalRows += $rows.Count
        if ($expandParentPropertyByQuery.ContainsKey($name)) {
            Write-ExpandLimitWarning -QueryName $name -Rows $rows -ParentProperty $expandParentPropertyByQuery[$name]
        }
    }
    $queryTimer.Stop()
    Complete-StatusProgress 'Querying Azure Resource Graph'
    Write-StatusDetail "$($queryNames.Count) queries, $totalRows rows in $(Format-ElapsedTime $queryTimer.Elapsed)"
    if (-not $SkipFirewallRules) {
        $policyData = Get-FirewallPolicyData -FirewallRows $data['firewalls']
        $data['firewallPolicies'] = @($policyData.Rows)
        if ($policyData.RequestCount -gt 0) {
            Write-StatusDetail "$(@($policyData.Rows).Count) firewall policies, $($policyData.RequestCount) ARM requests"
        }
    }
    return [pscustomobject]$data
}

function Set-XmlAttribute {
    param([System.Xml.XmlElement]$Element, [string]$Name, [AllowNull()][object]$Value)
    $Element.SetAttribute($Name, [string]$Value)
}

function Get-ConnectorLayerDefinition {
    # Order here is the order draw.io lists in its Layers panel.
    return @(
        [pscustomobject]@{ Kind='Attachment';    Id='layer-attachment';    Name='Attachments and backends' },
        [pscustomobject]@{ Kind='Security';      Id='layer-security';      Name='Security (NSG)' },
        [pscustomobject]@{ Kind='Configuration'; Id='layer-configuration'; Name='Routing and NAT' },
        [pscustomobject]@{ Kind='Peering';       Id='layer-peering';       Name='VNet peering' },
        [pscustomobject]@{ Kind='Hybrid';        Id='layer-hybrid';        Name='Hybrid connectivity' }
    )
}

function Add-MxBaseCell {
    param([System.Xml.XmlDocument]$Document, [System.Xml.XmlElement]$Root)

    $baseCell = $null
    foreach ($baseId in @('0','1')) {
        $cell = $Document.CreateElement('mxCell')
        Set-XmlAttribute $cell 'id' $baseId
        if ($baseId -eq '1') {
            Set-XmlAttribute $cell 'value' 'Resources'
            Set-XmlAttribute $cell 'parent' '0'
            $baseCell = $cell
        }
        $null = $Root.AppendChild($cell)
    }
    return $baseCell
}

function Add-MxPageLayer {
    param(
        [System.Xml.XmlDocument]$Document,
        [System.Xml.XmlElement]$Root,
        [System.Xml.XmlElement]$BaseCell,
        [string[]]$Kinds
    )

    # Layer cells must be siblings of the base layer and precede the cells that
    # reference them, so insert rather than append. Only classes the page
    # actually draws get a layer, keeping the Layers panel free of empty rows.
    $layerIdByKind = @{}
    $reference = $BaseCell
    foreach ($definition in Get-ConnectorLayerDefinition) {
        if ($Kinds -notcontains $definition.Kind) { continue }
        $layer = $Document.CreateElement('mxCell')
        Set-XmlAttribute $layer 'id' $definition.Id
        Set-XmlAttribute $layer 'value' $definition.Name
        Set-XmlAttribute $layer 'parent' '0'
        $null = $Root.InsertAfter($layer, $reference)
        $reference = $layer
        $layerIdByKind[$definition.Kind] = $definition.Id
    }
    return $layerIdByKind
}

function Set-MxPageSize {
    param(
        [System.Xml.XmlElement]$Model,
        [double]$ContentRight,
        [double]$ContentBottom,
        [double]$Margin = 20
    )

    # draw.io paginates printing and PDF export on these values, so derive them
    # from the drawing instead of a fixed sheet that tall pages spill out of.
    Set-XmlAttribute $Model 'pageWidth'  ([int][math]::Max(850, [math]::Ceiling($ContentRight + $Margin)))
    Set-XmlAttribute $Model 'pageHeight' ([int][math]::Max(1100, [math]::Ceiling($ContentBottom + $Margin)))
}

function Add-MxVertex {
    param(
        [System.Xml.XmlDocument]$Document,
        [System.Xml.XmlElement]$Root,
        [string]$Id,
        [string]$Parent,
        [string]$Value,
        [string]$Style,
        [double]$X,
        [double]$Y,
        [double]$Width,
        [double]$Height,
        [string]$AzureId = '',
        [string]$ResourceType = '',
        [hashtable]$Attributes,
        [double]$CollapsedHeight = 0
    )

    $wrapCell=[bool]($AzureId -or $ResourceType -or ($Attributes -and $Attributes.Count -gt 0))
    $container=$null
    if($wrapCell){
        $container=$Document.CreateElement('object')
        Set-XmlAttribute $container 'id' $Id
        Set-XmlAttribute $container 'label' $Value
        if ($AzureId) { Set-XmlAttribute $container 'azureResourceId' $AzureId }
        if ($ResourceType) { Set-XmlAttribute $container 'azureResourceType' $ResourceType }
        if ($Attributes) {
            foreach ($entry in @($Attributes.GetEnumerator() | Sort-Object Key)) {
                if ($null -ne $entry.Value -and [string]$entry.Value -ne '') {
                    Set-XmlAttribute $container ([string]$entry.Key) $entry.Value
                }
            }
        }
    }
    $cell = $Document.CreateElement('mxCell')
    if(-not$wrapCell){Set-XmlAttribute $cell 'id' $Id;Set-XmlAttribute $cell 'value' $Value}
    Set-XmlAttribute $cell 'style' $Style
    Set-XmlAttribute $cell 'vertex' '1'
    Set-XmlAttribute $cell 'parent' $Parent

    $geometry = $Document.CreateElement('mxGeometry')
    Set-XmlAttribute $geometry 'x' $X
    Set-XmlAttribute $geometry 'y' $Y
    Set-XmlAttribute $geometry 'width' $Width
    Set-XmlAttribute $geometry 'height' $Height
    Set-XmlAttribute $geometry 'as' 'geometry'
    if ($CollapsedHeight -gt 0) {
        # Gives a folded container a controlled size instead of draw.io's
        # default, keeping the header readable when the shape is collapsed.
        $alternate = $Document.CreateElement('mxRectangle')
        Set-XmlAttribute $alternate 'width' $Width
        Set-XmlAttribute $alternate 'height' $CollapsedHeight
        Set-XmlAttribute $alternate 'as' 'alternateBounds'
        $null = $geometry.AppendChild($alternate)
    }
    $null = $cell.AppendChild($geometry)
    if($wrapCell){$null=$container.AppendChild($cell);$null=$Root.AppendChild($container)}else{$null=$Root.AppendChild($cell)}
}

function Add-MxEdge {
    param(
        [System.Xml.XmlDocument]$Document,
        [System.Xml.XmlElement]$Root,
        [string]$Id,
        [string]$Source,
        [string]$Target,
        [string]$Value,
        [string]$Style,
        [string]$AzureId = '',
        [string]$ResourceType = '',
        [hashtable]$Attributes,
        [string]$Parent = '1'
    )

    $wrapCell=[bool]($AzureId -or $ResourceType -or ($Attributes -and $Attributes.Count -gt 0))
    $container=$null
    if($wrapCell){
        $container=$Document.CreateElement('object')
        Set-XmlAttribute $container 'id' $Id
        Set-XmlAttribute $container 'label' $Value
        if ($AzureId) { Set-XmlAttribute $container 'azureResourceId' $AzureId }
        if ($ResourceType) { Set-XmlAttribute $container 'azureResourceType' $ResourceType }
        if ($Attributes) {
            foreach ($entry in @($Attributes.GetEnumerator() | Sort-Object Key)) {
                if ($null -ne $entry.Value -and [string]$entry.Value -ne '') {
                    Set-XmlAttribute $container ([string]$entry.Key) $entry.Value
                }
            }
        }
    }
    $cell = $Document.CreateElement('mxCell')
    if(-not$wrapCell){Set-XmlAttribute $cell 'id' $Id;Set-XmlAttribute $cell 'value' $Value}
    Set-XmlAttribute $cell 'style' $Style
    Set-XmlAttribute $cell 'edge' '1'
    Set-XmlAttribute $cell 'parent' $Parent
    Set-XmlAttribute $cell 'source' $Source
    Set-XmlAttribute $cell 'target' $Target
    $geometry = $Document.CreateElement('mxGeometry')
    Set-XmlAttribute $geometry 'relative' '1'
    Set-XmlAttribute $geometry 'as' 'geometry'
    $null = $cell.AppendChild($geometry)
    if($wrapCell){$null=$container.AppendChild($cell);$null=$Root.AppendChild($container)}else{$null=$Root.AppendChild($cell)}
}

#region Enhanced draw.io layout engine
function Get-DataRows {
    param([object]$Data, [string]$Name)
    return @((Get-ObjectValue -Object $Data -Name $Name -Default @()))
}

function Get-IdsFromJson {
    param([AllowNull()][object]$Json)

    if ($null -eq $Json -or [string]::IsNullOrWhiteSpace([string]$Json)) { return @() }
    try { $value = [string]$Json | ConvertFrom-Json } catch { return @() }
    $ids = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    function Add-ObjectId {
        param([AllowNull()][object]$Item)
        if ($null -eq $Item) { return }
        if ($Item -is [string] -or $Item -is [ValueType]) { return }
        if ($Item -is [System.Collections.IEnumerable] -and $Item -isnot [System.Collections.IDictionary] -and
            $Item -isnot [pscustomobject]) {
            foreach ($child in $Item) { Add-ObjectId $child }
            return
        }
        foreach ($property in $Item.PSObject.Properties) {
            if ($property.Name -eq 'id' -and $property.Value) {
                $null = $ids.Add((ConvertTo-ResourceId $property.Value))
            } else {
                Add-ObjectId $property.Value
            }
        }
    }

    Add-ObjectId $value
    return @($ids)
}

function Get-ResourceTypeFromId {
    param([AllowNull()][string]$ResourceId)

    $value = [string]$ResourceId
    if ([string]::IsNullOrWhiteSpace($value)) { return '' }
    $marker = '/providers/'
    $index = $value.LastIndexOf($marker, [System.StringComparison]::OrdinalIgnoreCase)
    if ($index -lt 0) { return '' }
    $segments = @($value.Substring($index + $marker.Length).Split('/') | Where-Object { $_ })
    if ($segments.Count -lt 2) { return '' }
    return "$($segments[0])/$($segments[1])"
}

function Get-SubnetOccupantId {
    param([AllowNull()][string]$ReferenceId)

    # A subnet references its consumers through child IDs. Trimming the child
    # segment yields the resource that actually occupies the address space,
    # whatever its type, without having to query that type separately.
    $value = [string]$ReferenceId
    if ([string]::IsNullOrWhiteSpace($value)) { return '' }
    # A scale-set instance NIC belongs to the scale set, not the instance.
    $vmssMatch = [regex]::Match($value, '(?i)^(.*?/providers/microsoft\.compute/virtualmachinescalesets/[^/]+)/virtualmachines/')
    if ($vmssMatch.Success) { return $vmssMatch.Groups[1].Value }
    foreach ($segment in @('/ipConfigurations/', '/bastionHostIpConfigurations/', '/frontendIPConfigurations/',
                           '/gatewayIPConfigurations/', '/azureFirewallIpConfigurations/',
                           '/ipConfigurationProfiles/')) {
        $index = $value.IndexOf($segment, [System.StringComparison]::OrdinalIgnoreCase)
        if ($index -gt 0) { return $value.Substring(0, $index) }
    }
    return $value
}

function Get-SubnetOccupant {
    param([AllowNull()][object]$Subnet)

    # Returns one entry per distinct resource occupying the subnet, keeping the
    # ARM casing for display and a normalized id for matching.
    $byId = @{}
    foreach ($reference in @(ConvertFrom-JsonCollection (Get-ObjectValue $Subnet 'ipConfigurations' ''))) {
        $ownerId = Get-SubnetOccupantId ([string](Get-ObjectValue $reference 'id' ''))
        if (-not $ownerId) { continue }
        $key = ConvertTo-ResourceId $ownerId
        if (-not $byId.ContainsKey($key)) {
            $byId[$key] = [pscustomobject]@{ Id=$key; DisplayId=$ownerId; ResourceType=(Get-ResourceTypeFromId $ownerId) }
        }
    }
    foreach ($link in @(ConvertFrom-JsonCollection (Get-ObjectValue $Subnet 'serviceAssociationLinks' ''))) {
        $properties = Get-ObjectValue $link 'properties' $link
        $ownerId = [string](Get-ObjectValue $properties 'link' '')
        if ([string]::IsNullOrWhiteSpace($ownerId) -or $ownerId -notlike '/subscriptions/*') { continue }
        $key = ConvertTo-ResourceId $ownerId
        if (-not $byId.ContainsKey($key)) {
            $linkedType = [string](Get-ObjectValue $properties 'linkedResourceType' '')
            if (-not $linkedType) { $linkedType = Get-ResourceTypeFromId $ownerId }
            $byId[$key] = [pscustomobject]@{ Id=$key; DisplayId=$ownerId; ResourceType=$linkedType }
        }
    }
    return @($byId.Values | Sort-Object Id)
}

function Get-NicIdFromIpConfigurationId {
    param([AllowNull()][string]$Id)
    $normalized = ConvertTo-ResourceId $Id
    if ($normalized -match '^(.*?/providers/microsoft\.network/networkinterfaces/[^/]+)/ipconfigurations/') {
        return $Matches[1]
    }
    return ''
}

function Add-IndexValue {
    param([hashtable]$Index,[string]$Key,[AllowNull()][object]$Value)
    if (-not $Key) { return }
    if (-not $Index.ContainsKey($Key)) {
        $Index[$Key] = [System.Collections.Generic.List[object]]::new()
    }
    $Index[$Key].Add($Value)
}

function New-ResourceMap {
    param([object[]]$Rows,[string]$IdProperty = 'id')
    $map = @{}
    foreach ($row in $Rows) {
        $id = ConvertTo-ResourceId (Get-ObjectValue $row $IdProperty)
        if ($id -and -not $map.ContainsKey($id)) { $map[$id] = $row }
    }
    return $map
}

function Get-VmssNetworkRelation {
    param([object]$ScaleSet)
    $subnetIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $nsgIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $backendPoolIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $subnetCandidates = [System.Collections.Generic.List[object]]::new()
    $nicConfigurations = @(ConvertFrom-JsonCollection (Get-ObjectValue $ScaleSet 'networkInterfaceConfigurations' ''))
    foreach ($nicConfiguration in $nicConfigurations) {
        $nicProperties = Get-ObjectValue $nicConfiguration 'properties' $null
        $nicIsPrimary = [bool](Get-ObjectValue $nicProperties 'primary' $false)
        $nsg = Get-ObjectValue $nicProperties 'networkSecurityGroup' $null
        $nsgId = ConvertTo-ResourceId (Get-ObjectValue $nsg 'id' '')
        if ($nsgId) { $null = $nsgIds.Add($nsgId) }
        foreach ($ipConfiguration in @((Get-ObjectValue $nicProperties 'ipConfigurations' @()) | ForEach-Object { $_ })) {
            $ipProperties = Get-ObjectValue $ipConfiguration 'properties' $null
            $subnet = Get-ObjectValue $ipProperties 'subnet' $null
            $subnetId = ConvertTo-ResourceId (Get-ObjectValue $subnet 'id' '')
            if ($subnetId) {
                $null = $subnetIds.Add($subnetId)
                $priority = 0
                if ($nicIsPrimary) { $priority += 1 }
                if ([bool](Get-ObjectValue $ipProperties 'primary' $false)) { $priority += 2 }
                $subnetCandidates.Add([pscustomobject]@{ SubnetId=$subnetId; Priority=$priority })
            }
            foreach ($pool in @((Get-ObjectValue $ipProperties 'loadBalancerBackendAddressPools' @()) | ForEach-Object { $_ })) {
                $poolId = ConvertTo-ResourceId (Get-ObjectValue $pool 'id' '')
                if ($poolId) { $null = $backendPoolIds.Add($poolId) }
            }
        }
    }
    $primarySubnetId = ''
    $primaryCandidate = $subnetCandidates | Sort-Object @{Expression='Priority';Descending=$true},SubnetId | Select-Object -First 1
    if ($null -ne $primaryCandidate) { $primarySubnetId = [string]$primaryCandidate.SubnetId }
    return [pscustomobject]@{
        ScaleSet=$ScaleSet
        SubnetIds=@($subnetIds | Sort-Object)
        PrimarySubnetId=$primarySubnetId
        NsgIds=@($nsgIds | Sort-Object)
        BackendPoolIds=@($backendPoolIds | Sort-Object)
    }
}

function Get-ApplicationGatewayRelation {
    param([object[]]$Rows)
    $deploymentSubnetIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $frontendSubnetIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $publicIpIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $privateIpAddresses = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $frontendNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($row in $Rows) {
        $legacySubnetId = ConvertTo-ResourceId (Get-ObjectValue $row 'subnetId' '')
        $legacyPublicIpId = ConvertTo-ResourceId (Get-ObjectValue $row 'publicIpId' '')
        $legacyFrontendName = [string](Get-ObjectValue $row 'frontendName' '')
        if ($legacySubnetId) { $null = $deploymentSubnetIds.Add($legacySubnetId) }
        if ($legacyPublicIpId) { $null = $publicIpIds.Add($legacyPublicIpId) }
        if ($legacyFrontendName) { $null = $frontendNames.Add($legacyFrontendName) }
        foreach ($configuration in @(ConvertFrom-JsonCollection (Get-ObjectValue $row 'gatewayIpConfigurations' ''))) {
            $properties = Get-ObjectValue $configuration 'properties' $null
            $subnet = Get-ObjectValue $properties 'subnet' $null
            $subnetId = ConvertTo-ResourceId (Get-ObjectValue $subnet 'id' '')
            if ($subnetId) { $null = $deploymentSubnetIds.Add($subnetId) }
        }
        foreach ($frontend in @(ConvertFrom-JsonCollection (Get-ObjectValue $row 'frontendIpConfigurations' ''))) {
            $frontendName = [string](Get-ObjectValue $frontend 'name' '')
            $properties = Get-ObjectValue $frontend 'properties' $null
            $publicIp = Get-ObjectValue $properties 'publicIPAddress' $null
            $subnet = Get-ObjectValue $properties 'subnet' $null
            $publicIpId = ConvertTo-ResourceId (Get-ObjectValue $publicIp 'id' '')
            $subnetId = ConvertTo-ResourceId (Get-ObjectValue $subnet 'id' '')
            $privateIpAddress = [string](Get-ObjectValue $properties 'privateIPAddress' '')
            if ($frontendName) { $null = $frontendNames.Add($frontendName) }
            if ($publicIpId) { $null = $publicIpIds.Add($publicIpId) }
            if ($subnetId) { $null = $frontendSubnetIds.Add($subnetId) }
            if ($privateIpAddress) { $null = $privateIpAddresses.Add($privateIpAddress) }
        }
    }
    $allSubnetIds = @(@($deploymentSubnetIds) + @($frontendSubnetIds) | Sort-Object -Unique)
    return [pscustomobject]@{
        Rows=$Rows
        SubnetIds=$allSubnetIds
        DeploymentSubnetIds=@($deploymentSubnetIds | Sort-Object)
        FrontendSubnetIds=@($frontendSubnetIds | Sort-Object)
        PublicIpIds=@($publicIpIds | Sort-Object)
        PrivateIpAddresses=@($privateIpAddresses | Sort-Object)
        FrontendNames=@($frontendNames | Sort-Object)
    }
}

function Get-ExpandedServiceRelation {
    param([object[]]$Rows)

    $subnetIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $publicIpIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $privateIpAddresses = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $managementSubnetIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $managementPublicIpIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $managementPrivateIpAddresses = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($row in $Rows) {
        $subnetId = ConvertTo-ResourceId (Get-ObjectValue $row 'subnetId' '')
        $publicIpId = ConvertTo-ResourceId (Get-ObjectValue $row 'publicIpId' '')
        $privateIpAddress = [string](Get-ObjectValue $row 'privateIpAddress' '')
        $managementSubnetId = ConvertTo-ResourceId (Get-ObjectValue $row 'managementSubnetId' '')
        $managementPublicIpId = ConvertTo-ResourceId (Get-ObjectValue $row 'managementPublicIpId' '')
        $managementPrivateIpAddress = [string](Get-ObjectValue $row 'managementPrivateIpAddress' '')
        if ($subnetId) { $null = $subnetIds.Add($subnetId) }
        if ($publicIpId) { $null = $publicIpIds.Add($publicIpId) }
        if ($privateIpAddress) { $null = $privateIpAddresses.Add($privateIpAddress) }
        if ($managementSubnetId) { $null = $managementSubnetIds.Add($managementSubnetId) }
        if ($managementPublicIpId) { $null = $managementPublicIpIds.Add($managementPublicIpId) }
        if ($managementPrivateIpAddress) { $null = $managementPrivateIpAddresses.Add($managementPrivateIpAddress) }
    }
    return [pscustomobject]@{
        Rows=$Rows
        SubnetIds=@($subnetIds | Sort-Object)
        PublicIpIds=@($publicIpIds | Sort-Object)
        PrivateIpAddresses=@($privateIpAddresses | Sort-Object)
        ManagementSubnetIds=@($managementSubnetIds | Sort-Object)
        ManagementPublicIpIds=@($managementPublicIpIds | Sort-Object)
        ManagementPrivateIpAddresses=@($managementPrivateIpAddresses | Sort-Object)
    }
}

function New-NetworkDataIndex {
    param([object]$Data)
    $index = [ordered]@{
        SubscriptionById=(New-ResourceMap (Get-DataRows $Data 'subscriptions') 'subscriptionId')
        VnetById=(New-ResourceMap (Get-DataRows $Data 'vnets'))
        SubnetById=(New-ResourceMap (Get-DataRows $Data 'subnets'))
        PublicIpById=(New-ResourceMap (Get-DataRows $Data 'publicIps'))
        PublicIpPrefixById=(New-ResourceMap (Get-DataRows $Data 'publicIpPrefixes'))
        NsgById=(New-ResourceMap (Get-DataRows $Data 'nsgs'))
        NatGatewayById=(New-ResourceMap (Get-DataRows $Data 'natGateways'))
        RouteTableById=(New-ResourceMap (Get-DataRows $Data 'routeTables'))
        GatewayById=(New-ResourceMap (Get-DataRows $Data 'virtualNetworkGateways'))
        LocalNetworkGatewayById=(New-ResourceMap (Get-DataRows $Data 'localNetworkGateways'))
        ExpressRouteCircuitById=(New-ResourceMap (Get-DataRows $Data 'expressRouteCircuits'))
        VirtualHubById=(New-ResourceMap (Get-DataRows $Data 'virtualHubs'))
        FirewallPolicyById=(New-ResourceMap (Get-DataRows $Data 'firewallPolicies'))
        FirewallIdsByPolicyId=@{}
        ChildPolicyIdsByBasePolicyId=@{}
        SubnetsByVnetId=@{}
        SubnetsByNsgId=@{}
        SubnetsByRouteTableId=@{}
        NicRowsBySubnetId=@{}
        NicRowsByNicId=@{}
        NicRowsByNsgId=@{}
        VmRowsByNicId=@{}
        PrivateEndpointRowsBySubnetId=@{}
        PeeringsByVnetId=@{}
        VmssRelationById=@{}
        VmssIdsBySubnetId=@{}
        VmssIdsByNsgId=@{}
        VmssIdsByBackendPoolId=@{}
        ApplicationGatewayRelationById=@{}
        ApplicationGatewayIdsBySubnetId=@{}
        LoadBalancerRelationById=@{}
        LoadBalancerIdsByVnetId=@{}
        HubConnectionsByVnetId=@{}
        ExpressRouteGatewaysByHubId=@{}
        PublicIpByIpConfigurationId=@{}
        SubnetReferencesByOccupantId=@{}
        FirewallRelationById=@{}
        FirewallIdsBySubnetId=@{}
        FirewallIdsByHubId=@{}
        GatewayRelationById=@{}
        GatewayIdsBySubnetId=@{}
        BastionRelationById=@{}
        BastionIdsBySubnetId=@{}
    }
    foreach ($publicIp in Get-DataRows $Data 'publicIps') {
        $ipConfigurationId = ConvertTo-ResourceId (Get-ObjectValue $publicIp 'ipConfigurationId' '')
        if ($ipConfigurationId) { $index.PublicIpByIpConfigurationId[$ipConfigurationId] = $publicIp }
    }
    foreach ($subnet in Get-DataRows $Data 'subnets') {
        $subnetId = ConvertTo-ResourceId (Get-ObjectValue $subnet 'id')
        Add-IndexValue $index.SubnetsByVnetId (ConvertTo-ResourceId (Get-ObjectValue $subnet 'vnetId')) $subnet
        Add-IndexValue $index.SubnetsByNsgId (ConvertTo-ResourceId (Get-ObjectValue $subnet 'nsgId')) $subnet
        Add-IndexValue $index.SubnetsByRouteTableId (ConvertTo-ResourceId (Get-ObjectValue $subnet 'routeTableId')) $subnet
        foreach ($reference in @(ConvertFrom-JsonCollection (Get-ObjectValue $subnet 'ipConfigurations' ''))) {
            $referenceId = ConvertTo-ResourceId (Get-ObjectValue $reference 'id' '')
            $occupantId = ConvertTo-ResourceId (Get-SubnetOccupantId $referenceId)
            if (-not $referenceId -or -not $occupantId) { continue }
            Add-IndexValue $index.SubnetReferencesByOccupantId $occupantId ([pscustomobject]@{
                SubnetId=$subnetId
                SubnetName=[string](Get-ObjectValue $subnet 'name' '')
                ReferenceId=$referenceId
            })
        }
    }
    foreach ($nic in Get-DataRows $Data 'nics') {
        Add-IndexValue $index.NicRowsBySubnetId (ConvertTo-ResourceId (Get-ObjectValue $nic 'subnetId')) $nic
        Add-IndexValue $index.NicRowsByNicId (ConvertTo-ResourceId (Get-ObjectValue $nic 'nicId')) $nic
        Add-IndexValue $index.NicRowsByNsgId (ConvertTo-ResourceId (Get-ObjectValue $nic 'nicNsgId')) $nic
    }
    foreach ($vm in Get-DataRows $Data 'virtualMachines') {
        Add-IndexValue $index.VmRowsByNicId (ConvertTo-ResourceId (Get-ObjectValue $vm 'nicId')) $vm
    }
    foreach ($endpoint in Get-DataRows $Data 'privateEndpoints') {
        Add-IndexValue $index.PrivateEndpointRowsBySubnetId (ConvertTo-ResourceId (Get-ObjectValue $endpoint 'subnetId')) $endpoint
    }
    foreach ($peering in Get-DataRows $Data 'vnetPeerings') {
        Add-IndexValue $index.PeeringsByVnetId (ConvertTo-ResourceId (Get-ObjectValue $peering 'vnetId')) $peering
    }
    foreach ($scaleSet in Get-DataRows $Data 'virtualMachineScaleSets') {
        $scaleSetId = ConvertTo-ResourceId (Get-ObjectValue $scaleSet 'id')
        $relation = Get-VmssNetworkRelation $scaleSet
        $index.VmssRelationById[$scaleSetId] = $relation
        foreach ($subnetId in $relation.SubnetIds) { Add-IndexValue $index.VmssIdsBySubnetId $subnetId $scaleSetId }
        foreach ($nsgId in $relation.NsgIds) { Add-IndexValue $index.VmssIdsByNsgId $nsgId $scaleSetId }
        foreach ($poolId in $relation.BackendPoolIds) { Add-IndexValue $index.VmssIdsByBackendPoolId $poolId $scaleSetId }
    }
    foreach ($group in @(Get-DataRows $Data 'applicationGateways' | Group-Object { ConvertTo-ResourceId (Get-ObjectValue $_ 'id') } | Sort-Object Name)) {
        $gatewayId = [string]$group.Name
        $relation = Get-ApplicationGatewayRelation @($group.Group)
        $index.ApplicationGatewayRelationById[$gatewayId] = $relation
        foreach ($subnetId in $relation.DeploymentSubnetIds) { Add-IndexValue $index.ApplicationGatewayIdsBySubnetId $subnetId $gatewayId }
    }
    foreach ($group in @(Get-DataRows $Data 'firewalls' | Group-Object { ConvertTo-ResourceId (Get-ObjectValue $_ 'id') } | Sort-Object Name)) {
        $firewallId = [string]$group.Name
        $baseRelation = Get-ExpandedServiceRelation @($group.Group)
        $dataSubnetIds = [System.Collections.Generic.HashSet[string]]::new([string[]]$baseRelation.SubnetIds,[System.StringComparer]::OrdinalIgnoreCase)
        $dataPublicIpIds = [System.Collections.Generic.HashSet[string]]::new([string[]]$baseRelation.PublicIpIds,[System.StringComparer]::OrdinalIgnoreCase)
        $managementSubnetIds = [System.Collections.Generic.HashSet[string]]::new([string[]]$baseRelation.ManagementSubnetIds,[System.StringComparer]::OrdinalIgnoreCase)
        $managementPublicIpIds = [System.Collections.Generic.HashSet[string]]::new([string[]]$baseRelation.ManagementPublicIpIds,[System.StringComparer]::OrdinalIgnoreCase)
        $managementConfigurationIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($row in $group.Group) {
            $configurationId = ConvertTo-ResourceId (Get-ObjectValue $row 'managementIpConfigurationId' '')
            if ($configurationId) { $null = $managementConfigurationIds.Add($configurationId) }
        }
        foreach ($reference in @($index.SubnetReferencesByOccupantId[$firewallId])) {
            if ($null -eq $reference) { continue }
            $isManagement = [string]$reference.SubnetName -ieq 'AzureFirewallManagementSubnet'
            if ($isManagement) {
                $null = $managementSubnetIds.Add([string]$reference.SubnetId)
                $null = $managementConfigurationIds.Add([string]$reference.ReferenceId)
            } else {
                $null = $dataSubnetIds.Add([string]$reference.SubnetId)
            }
            if ($index.PublicIpByIpConfigurationId.ContainsKey([string]$reference.ReferenceId)) {
                $publicIpId = ConvertTo-ResourceId (Get-ObjectValue $index.PublicIpByIpConfigurationId[[string]$reference.ReferenceId] 'id')
                if ($isManagement) {
                    $null = $managementPublicIpIds.Add($publicIpId)
                } else {
                    $null = $dataPublicIpIds.Add($publicIpId)
                }
            }
        }
        $relation = [pscustomobject]@{
            Rows=$baseRelation.Rows
            SubnetIds=@($dataSubnetIds | Sort-Object)
            PublicIpIds=@($dataPublicIpIds | Sort-Object)
            PrivateIpAddresses=$baseRelation.PrivateIpAddresses
            ManagementSubnetIds=@($managementSubnetIds | Sort-Object)
            ManagementPublicIpIds=@($managementPublicIpIds | Sort-Object)
            ManagementPrivateIpAddresses=$baseRelation.ManagementPrivateIpAddresses
            ManagementIpConfigurationIds=@($managementConfigurationIds | Sort-Object)
        }
        $index.FirewallRelationById[$firewallId] = $relation
        foreach ($subnetId in @($relation.SubnetIds) + @($relation.ManagementSubnetIds)) {
            Add-IndexValue $index.FirewallIdsBySubnetId $subnetId $firewallId
        }
        # A secured virtual hub firewall has no subnet and is reached through its hub.
        Add-IndexValue $index.FirewallIdsByHubId (ConvertTo-ResourceId (Get-ObjectValue $group.Group[0] 'virtualHubId' '')) $firewallId
        Add-IndexValue $index.FirewallIdsByPolicyId (ConvertTo-ResourceId (Get-ObjectValue $group.Group[0] 'firewallPolicyId' '')) $firewallId
    }
    foreach ($policyId in @($index.FirewallPolicyById.Keys | Sort-Object)) {
        $basePolicyId = ConvertTo-ResourceId (Get-ObjectValue $index.FirewallPolicyById[$policyId] 'basePolicyId' '')
        Add-IndexValue $index.ChildPolicyIdsByBasePolicyId $basePolicyId $policyId
    }
    foreach ($definition in @(
        @{Data='virtualNetworkGateways';Relations=$index.GatewayRelationById;BySubnet=$index.GatewayIdsBySubnetId},
        @{Data='bastionHosts';Relations=$index.BastionRelationById;BySubnet=$index.BastionIdsBySubnetId}
    )) {
        foreach ($group in @(Get-DataRows $Data $definition.Data | Group-Object { ConvertTo-ResourceId (Get-ObjectValue $_ 'id') } | Sort-Object Name)) {
            $id = [string]$group.Name
            $relation = Get-ExpandedServiceRelation @($group.Group)
            $definition.Relations[$id] = $relation
            foreach ($subnetId in $relation.SubnetIds) { Add-IndexValue $definition.BySubnet $subnetId $id }
        }
    }
    foreach ($connection in Get-DataRows $Data 'hubVirtualNetworkConnections') {
        Add-IndexValue $index.HubConnectionsByVnetId (ConvertTo-ResourceId (Get-ObjectValue $connection 'remoteVnetId')) $connection
    }
    foreach ($gateway in Get-DataRows $Data 'expressRouteGateways') {
        Add-IndexValue $index.ExpressRouteGatewaysByHubId (ConvertTo-ResourceId (Get-ObjectValue $gateway 'virtualHubId')) $gateway
    }
    foreach ($group in @(Get-DataRows $Data 'loadBalancers' | Group-Object { ConvertTo-ResourceId (Get-ObjectValue $_ 'id') } | Sort-Object Name)) {
        $loadBalancerId = [string]$group.Name
        $frontendSubnetIds = @($group.Group | ForEach-Object { ConvertTo-ResourceId (Get-ObjectValue $_ 'subnetId') } | Where-Object { $_ } | Sort-Object -Unique)
        $publicIpIds = @($group.Group | ForEach-Object { ConvertTo-ResourceId (Get-ObjectValue $_ 'publicIpId') } | Where-Object { $_ } | Sort-Object -Unique)
        $backendIds = @($group.Group | ForEach-Object { Get-IdsFromJson (Get-ObjectValue $_ 'backendPools' '') } | Sort-Object -Unique)
        $backendNicIds = @($backendIds | ForEach-Object { Get-NicIdFromIpConfigurationId $_ } | Where-Object { $_ } | Sort-Object -Unique)
        $backendVmssIds = @($backendIds | ForEach-Object {
            if ($index.VmssIdsByBackendPoolId.ContainsKey($_)) { $index.VmssIdsByBackendPoolId[$_] }
        } | ForEach-Object { $_ } | Sort-Object -Unique)
        $index.LoadBalancerRelationById[$loadBalancerId] = [pscustomobject]@{
            Rows=@($group.Group); FrontendSubnetIds=$frontendSubnetIds; PublicIpIds=$publicIpIds
            BackendNicIds=$backendNicIds; BackendVmssIds=$backendVmssIds
        }
        $relatedSubnetIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($subnetId in $frontendSubnetIds) { $null = $relatedSubnetIds.Add($subnetId) }
        foreach ($nicId in $backendNicIds) {
            if ($index.NicRowsByNicId.ContainsKey($nicId)) {
                foreach ($nicRow in $index.NicRowsByNicId[$nicId]) {
                    $subnetId = ConvertTo-ResourceId (Get-ObjectValue $nicRow 'subnetId')
                    if ($subnetId) { $null = $relatedSubnetIds.Add($subnetId) }
                }
            }
        }
        foreach ($scaleSetId in $backendVmssIds) {
            foreach ($subnetId in $index.VmssRelationById[$scaleSetId].SubnetIds) { $null = $relatedSubnetIds.Add($subnetId) }
        }
        foreach ($subnetId in $relatedSubnetIds) {
            if ($index.SubnetById.ContainsKey($subnetId)) {
                $vnetId = ConvertTo-ResourceId (Get-ObjectValue $index.SubnetById[$subnetId] 'vnetId')
                Add-IndexValue $index.LoadBalancerIdsByVnetId $vnetId $loadBalancerId
            }
        }
    }
    return [pscustomobject]$index
}

function Get-AzureIconPath {
    param([string]$Kind)
    $icons = @{
        VNet='networking/Virtual_Networks.svg'; Subnet='networking/Subnet.svg'
        NIC='networking/Network_Interfaces.svg'; PublicIP='networking/Public_IP_Addresses.svg'
        PublicIPPrefix='networking/Public_IP_Prefixes.svg'
        NSG='networking/Network_Security_Groups.svg'; VM='compute/Virtual_Machine.svg'
        VMSS='compute/VM_Scale_Sets.svg'; VirtualHub='networking/Virtual_WANs.svg'
        NAT='networking/NAT.svg'; LoadBalancer='networking/Load_Balancers.svg'
        ApplicationGateway='networking/Application_Gateways.svg'; Firewall='networking/Firewalls.svg'
        PrivateEndpoint='networking/Private_Endpoint.svg'; PrivateLinkTarget='networking/Private_Link.svg'
        RouteTable='networking/Route_Tables.svg'; Gateway='networking/Virtual_Network_Gateways.svg'
        ExpressRouteGateway='networking/ExpressRoute_Circuits.svg'; ExpressRouteCircuit='networking/ExpressRoute_Circuits.svg'
        Bastion='networking/Bastions.svg'; LocalNetworkGateway='networking/Local_Network_Gateways.svg'
        VPNConnection='networking/Connections.svg'; HubConnection='networking/Connections.svg'; RemoteGateway='networking/Virtual_Network_Gateways.svg'
        FirewallPolicy='networking/Azure_Firewall_Policy.svg'; FirewallManagementInterface='networking/Firewalls.svg'
        RemoteVNet='networking/Virtual_Networks.svg'; SubnetOccupant='general/All_Resources.svg'
    }
    if ($icons.ContainsKey($Kind)) { return "img/lib/azure2/$($icons[$Kind])" }
    return 'img/lib/azure2/general/All_Resources.svg'
}

function Get-AzureNodeStyle {
    param(
        [string]$Kind,
        [string]$FillColor = '#ffffff',
        [string]$StrokeColor = '#0078d4'
    )
    $icon = Get-AzureIconPath $Kind
    return "shape=label;rounded=1;whiteSpace=wrap;html=1;image=$icon;imageWidth=34;imageHeight=34;" +
           "imageAlign=left;imageVerticalAlign=middle;spacingLeft=44;align=left;verticalAlign=middle;" +
           "fillColor=$FillColor;strokeColor=$StrokeColor;fontSize=10;overflow=hidden;"
}

function Get-FriendlyResourceType {
    param([string]$Kind,[string]$ResourceType,[string]$ResourceId)
    $labels=@{
        NIC='Network interface';PublicIP='Public IP address';PublicIPPrefix='Public IP prefix';NSG='Network security group';VM='Virtual machine'
        VMSS='Virtual machine scale set';VirtualHub='Virtual Hub'
        NAT='NAT gateway';LoadBalancer='Load balancer';ApplicationGateway='Application gateway'
        Firewall='Azure Firewall';PrivateEndpoint='Private endpoint';RouteTable='Route table'
        Gateway='Virtual network gateway';RemoteGateway='Remote virtual network gateway'
        ExpressRouteGateway='ExpressRoute gateway';ExpressRouteCircuit='ExpressRoute circuit'
        Bastion='Azure Bastion';LocalNetworkGateway='Local network gateway';VPNConnection='Gateway connection'
        HubConnection='Virtual Hub connection';FirewallPolicy='Firewall policy';FirewallManagementInterface='Firewall management interface'
        RemoteVNet='Remote virtual network';GenericExternal='External endpoint'
    }
    if($Kind -eq 'PrivateLinkTarget'){
        $id=ConvertTo-ResourceId $ResourceId
        $targetTypes=@{
            'microsoft.storage/storageaccounts'='Storage account';'microsoft.keyvault/vaults'='Key vault'
            'microsoft.sql/servers'='Azure SQL server';'microsoft.web/sites'='App Service'
            'microsoft.containerregistry/registries'='Container registry';'microsoft.servicebus/namespaces'='Service Bus namespace'
            'microsoft.eventhub/namespaces'='Event Hubs namespace';'microsoft.documentdb/databaseaccounts'='Azure Cosmos DB account'
        }
        foreach($entry in $targetTypes.GetEnumerator()){if($id -like "*/providers/$($entry.Key)/*"){return [string]$entry.Value}}
        return 'Private Link target'
    }
    if($Kind -eq 'SubnetOccupant'){
        $injectedTypes=@{
            'microsoft.app/managedenvironments'='Container Apps environment'
            'microsoft.web/serverfarms'='App Service plan';'microsoft.web/sites'='App Service'
            'microsoft.dbforpostgresql/flexibleservers'='Azure Database for PostgreSQL flexible server'
            'microsoft.dbformysql/flexibleservers'='Azure Database for MySQL flexible server'
            'microsoft.apimanagement/service'='API Management service'
            'microsoft.containerinstance/containergroups'='Container instance group'
            'microsoft.databricks/workspaces'='Azure Databricks workspace'
            'microsoft.netapp/netappaccounts'='Azure NetApp Files account'
            'microsoft.containerservice/managedclusters'='AKS cluster'
            'microsoft.network/privatelinkservices'='Private Link service'
            'microsoft.network/dnsresolvers'='DNS Private Resolver'
            'microsoft.network/networkvirtualappliances'='Network virtual appliance'
            'microsoft.machinelearningservices/workspaces'='Azure Machine Learning workspace'
        }
        $normalizedType=([string]$ResourceType).ToLowerInvariant()
        if($injectedTypes.ContainsKey($normalizedType)){return [string]$injectedTypes[$normalizedType]}
        if($ResourceType){return $ResourceType}
        return 'Subnet occupant'
    }
    if($labels.ContainsKey($Kind)){return [string]$labels[$Kind]}
    if($ResourceType){return $ResourceType}
    return $Kind
}

function Add-ResourceTypeLine {
    param([string]$Label,[string]$Kind,[string]$ResourceType,[string]$ResourceId)
    $friendlyType=Get-FriendlyResourceType $Kind $ResourceType $ResourceId
    if(-not$friendlyType){return $Label}
    $marker="<br><font color='#777777'><i>$friendlyType</i></font>"
    $boldEnd=$Label.IndexOf('</b>',[System.StringComparison]::OrdinalIgnoreCase)
    if($boldEnd -lt 0){return "$Label$marker"}
    $insertAt=$boldEnd+4
    return $Label.Insert($insertAt,$marker)
}

function ConvertTo-TagToken {
    param([AllowNull()][string]$Value)

    # draw.io splits the tags attribute on whitespace, so each token must be
    # whitespace-free to stay a single filterable tag.
    $token = ([string]$Value).Trim().ToLowerInvariant()
    if (-not $token) { return '' }
    return ($token -replace '\s+', '-')
}

function Join-ShapeTag {
    param([string[]]$Tokens)

    $seen = [System.Collections.Generic.List[string]]::new()
    foreach ($token in $Tokens) {
        $normalized = ConvertTo-TagToken $token
        if ($normalized -and -not $seen.Contains($normalized)) { $seen.Add($normalized) }
    }
    return ($seen -join ' ')
}

function Add-GraphNode {
    param(
        [hashtable]$Nodes,
        [System.Collections.Generic.HashSet[string]]$UsedResourceIds,
        [string]$Id,
        [string]$Name,
        [string]$Kind,
        [string]$ResourceType,
        [string]$Label,
        [ValidateSet('Internal','Security','Connectivity','External')][string]$Lane,
        [string]$SubnetId = '',
        [hashtable]$Attributes
    )
    $resourceId = ConvertTo-ResourceId $Id
    if (-not $resourceId) { return }
    if (-not $Nodes.ContainsKey($resourceId)) {
        $displayLabel=Add-ResourceTypeLine $Label $Kind $ResourceType $resourceId
        # Copy rather than mutate: callers reuse their attribute hashtables.
        $shapeAttributes = @{}
        if ($Attributes) { foreach ($entry in $Attributes.GetEnumerator()) { $shapeAttributes[$entry.Key] = $entry.Value } }
        $normalizedSubnetId = ConvertTo-ResourceId $SubnetId
        $shapeAttributes.tags = Join-ShapeTag @($Kind, $Lane, $Name, $(if ($normalizedSubnetId) { Get-ResourceNameFromId $normalizedSubnetId }))
        # Every shape carries its resource ID on hover; a caller-supplied hint keeps precedence.
        if ($shapeAttributes.ContainsKey('tooltip') -and $shapeAttributes.tooltip) {
            $shapeAttributes.tooltip = "$($shapeAttributes.tooltip)`n$resourceId"
        } else {
            $shapeAttributes.tooltip = $resourceId
        }
        $Nodes[$resourceId] = [pscustomobject]@{
            Id=$resourceId; Name=$Name; Kind=$Kind; ResourceType=$ResourceType; Label=$displayLabel
            Lane=$Lane; SubnetId=$normalizedSubnetId; CellId=''; Attributes=$shapeAttributes
        }
    }
    $null = $UsedResourceIds.Add($resourceId)
}

function Add-GraphEdge {
    param(
        [System.Collections.Generic.List[object]]$Edges,
        [System.Collections.Generic.HashSet[string]]$EdgeKeys,
        [string]$SourceId,
        [string]$TargetId,
        [string]$Label,
        [ValidateSet('Attachment','Security','Configuration','Peering','Hybrid')][string]$Kind = 'Attachment',
        [string]$AzureId = '',
        [string]$ResourceType = '',
        [hashtable]$Attributes
    )
    $source = ConvertTo-ResourceId $SourceId
    $target = ConvertTo-ResourceId $TargetId
    if (-not $source -or -not $target) { return }
    $key = "$source|$target|$Label|$(ConvertTo-ResourceId $AzureId)"
    if ($EdgeKeys.Add($key)) {
        $normalizedAzureId = ConvertTo-ResourceId $AzureId
        # Connectors are filterable and hoverable on the same terms as shapes.
        $edgeAttributes = @{}
        if ($Attributes) { foreach ($entry in $Attributes.GetEnumerator()) { $edgeAttributes[$entry.Key] = $entry.Value } }
        $edgeAttributes.tags = Join-ShapeTag @('connector', $Kind, $Label)
        if ($normalizedAzureId) {
            if ($edgeAttributes.ContainsKey('tooltip') -and $edgeAttributes.tooltip) {
                $edgeAttributes.tooltip = "$($edgeAttributes.tooltip)`n$normalizedAzureId"
            } else {
                $edgeAttributes.tooltip = $normalizedAzureId
            }
        }
        $Edges.Add([pscustomobject]@{
            Source=$source; Target=$target; Label=$Label; Kind=$Kind
            AzureId=$normalizedAzureId; ResourceType=$ResourceType; Attributes=$edgeAttributes
        })
    }
}

function Get-PageConnectorStyle {
    param(
        [object]$Edge,
        [hashtable]$Nodes,
        [string[]]$SubnetIds,
        [string]$VnetId
    )
    $base = 'edgeStyle=orthogonalEdgeStyle;rounded=1;orthogonalLoop=1;jettySize=20;html=1;' +
            'jumpStyle=arc;jumpSize=8;labelBackgroundColor=#ffffff;sourcePerimeterSpacing=4;targetPerimeterSpacing=4;fontSize=9;'
    $base += switch ($Edge.Kind) {
        # NSG and routing links describe configuration, not traffic direction, so
        # they carry no arrowhead.
        'Security'      { 'dashed=1;dashPattern=6 4;strokeColor=#b8860b;endArrow=none;' }
        'Configuration' { 'dashed=1;dashPattern=6 4;strokeColor=#6c8ebf;endArrow=none;' }
        'Peering'       { 'dashed=1;dashPattern=8 4;strokeColor=#9673a6;strokeWidth=2;' }
        'Hybrid'        { 'strokeColor=#9673a6;strokeWidth=2;' }
        default         { 'strokeColor=#339966;' }
    }

    $sourceNode = if ($Nodes.ContainsKey($Edge.Source)) { $Nodes[$Edge.Source] } else { $null }
    $targetNode = if ($Nodes.ContainsKey($Edge.Target)) { $Nodes[$Edge.Target] } else { $null }
    $sourceLane = if ($sourceNode) { [string]$sourceNode.Lane } else { '' }
    $targetLane = if ($targetNode) { [string]$targetNode.Lane } else { '' }
    $sourceIsSubnet = $SubnetIds -contains $Edge.Source
    $targetIsSubnet = $SubnetIds -contains $Edge.Target

    if ($sourceLane -eq 'Security') {
        return $base + 'exitX=1;exitY=0.5;exitPerimeter=1;entryX=0;entryY=0.5;entryPerimeter=1;'
    }
    if ($targetLane -eq 'Security') {
        return $base + 'exitX=0;exitY=0.5;exitPerimeter=1;entryX=1;entryY=0.5;entryPerimeter=1;'
    }
    if ($sourceLane -eq 'Connectivity' -and ($targetLane -eq 'Internal' -or $targetIsSubnet)) {
        return $base + 'exitX=0;exitY=0.5;exitPerimeter=1;entryX=1;entryY=0.5;entryPerimeter=1;'
    }
    if (($sourceLane -eq 'Internal' -or $sourceIsSubnet) -and $targetLane -eq 'Connectivity') {
        return $base + 'exitX=1;exitY=0.5;exitPerimeter=1;entryX=0;entryY=0.5;entryPerimeter=1;'
    }
    if ($sourceLane -eq 'Connectivity' -and $targetLane -eq 'Connectivity') {
        # Keep service-to-service connectors outside the right-hand lane.
        return $base + 'exitX=1;exitY=0.35;exitPerimeter=1;entryX=1;entryY=0.65;entryPerimeter=1;'
    }
    if ($sourceLane -eq 'Connectivity' -and $targetLane -eq 'External') {
        return $base + 'exitX=1;exitY=0.5;exitPerimeter=1;entryX=0;entryY=0.5;entryPerimeter=1;'
    }
    if ($sourceLane -eq 'External' -and $targetLane -eq 'Connectivity') {
        return $base + 'exitX=0;exitY=0.5;exitPerimeter=1;entryX=1;entryY=0.5;entryPerimeter=1;'
    }
    if ($targetLane -eq 'External') {
        return $base + 'exitX=1;exitY=0.5;exitPerimeter=1;entryX=0;entryY=0.5;entryPerimeter=1;'
    }
    if ($sourceLane -eq 'Internal' -and $targetIsSubnet) {
        # Subnets are stacked vertically, so a contained resource reaches another
        # subnet through the border facing it instead of wrapping around its side.
        $targetIsAbove = [array]::IndexOf($SubnetIds, [string]$Edge.Target) -lt [array]::IndexOf($SubnetIds, [string]$sourceNode.SubnetId)
        $entryY = if ($targetIsAbove) { 1 } else { 0 }
        return $base + "exitX=1;exitY=0.5;exitPerimeter=1;entryX=0.5;entryY=$entryY;entryPerimeter=1;"
    }
    if ($sourceLane -eq 'Internal' -and $targetLane -eq 'Internal') {
        # Between resources in two stacked subnets, leave and enter on the right so
        # the line runs beside the subnet headers instead of across them.
        if ($sourceNode.SubnetId -and $targetNode.SubnetId -and $sourceNode.SubnetId -ne $targetNode.SubnetId) {
            return $base + 'exitX=1;exitY=0.5;exitPerimeter=1;entryX=1;entryY=0.5;entryPerimeter=1;'
        }
        if ($sourceNode.Kind -eq 'VM' -and $targetNode.Kind -eq 'NIC') {
            return $base + 'exitX=0;exitY=0.5;exitPerimeter=1;entryX=1;entryY=0.5;entryPerimeter=1;'
        }
        return $base + 'exitX=1;exitY=0.5;exitPerimeter=1;entryX=0;entryY=0.5;entryPerimeter=1;'
    }
    if ($Edge.Source -eq $VnetId -and $targetLane -eq 'Connectivity') {
        return $base + 'exitX=1;exitY=0.5;exitPerimeter=1;entryX=0;entryY=0.5;entryPerimeter=1;'
    }
    return $base + 'exitX=1;exitY=0.5;exitPerimeter=1;entryX=0;entryY=0.5;entryPerimeter=1;'
}

function Add-ReferencedPublicIp {
    param(
        [string]$PublicIpId,
        [hashtable]$Nodes,
        [hashtable]$PublicIpById,
        [System.Collections.Generic.HashSet[string]]$UsedResourceIds
    )
    $id = ConvertTo-ResourceId $PublicIpId
    if (-not $id) { return }
    $pip = if ($PublicIpById.ContainsKey($id)) { $PublicIpById[$id] } else { $null }
    $name = if ($pip) { [string](Get-ObjectValue $pip 'name' (Get-ResourceNameFromId $id)) } else { Get-ResourceNameFromId $id }
    $address = if ($pip) { [string](Get-ObjectValue $pip 'ipAddress' '') } else { '' }
    if (-not $address) { $address = 'not allocated' }
    $sku = if ($pip) { [string](Get-ObjectValue $pip 'sku' '') } else { '' }
    $version = if ($pip) { [string](Get-ObjectValue $pip 'ipVersion' '') } else { '' }
    $fqdn = if ($pip) { [string](Get-ObjectValue $pip 'fqdn' '') } else { '' }
    $detail = @($address, (($sku, $version | Where-Object { $_ }) -join ' / '), $fqdn) | Where-Object { $_ }
    Add-GraphNode -Nodes $Nodes -UsedResourceIds $UsedResourceIds -Id $id -Name $name -Kind 'PublicIP' `
        -ResourceType 'Microsoft.Network/publicIPAddresses' -Label "<b>$name</b><br>$($detail -join '<br>')" -Lane Connectivity
}

function Add-ReferencedPublicIpPrefix {
    param(
        [string]$PublicIpPrefixId,
        [hashtable]$Nodes,
        [hashtable]$PublicIpPrefixById,
        [System.Collections.Generic.HashSet[string]]$UsedResourceIds
    )
    $id = ConvertTo-ResourceId $PublicIpPrefixId
    if (-not $id) { return }
    $prefix = if ($PublicIpPrefixById.ContainsKey($id)) { $PublicIpPrefixById[$id] } else { $null }
    $name = if ($prefix) { [string](Get-ObjectValue $prefix 'name' (Get-ResourceNameFromId $id)) } else { Get-ResourceNameFromId $id }
    $address = if ($prefix) { [string](Get-ObjectValue $prefix 'ipPrefix' '') } else { '' }
    if (-not $address) {
        $length = if ($prefix) { [string](Get-ObjectValue $prefix 'prefixLength' '') } else { '' }
        $address = if ($length) { "Prefix length: /$length" } else { 'prefix not allocated' }
    }
    $sku = if ($prefix) { [string](Get-ObjectValue $prefix 'sku' '') } else { '' }
    $version = if ($prefix) { [string](Get-ObjectValue $prefix 'ipVersion' '') } else { '' }
    $detail = @($address, (($sku, $version | Where-Object { $_ }) -join ' / ')) | Where-Object { $_ }
    Add-GraphNode -Nodes $Nodes -UsedResourceIds $UsedResourceIds -Id $id -Name $name -Kind 'PublicIPPrefix' `
        -ResourceType 'Microsoft.Network/publicIPPrefixes' -Label "<b>$name</b><br>$($detail -join '<br>')" -Lane Connectivity
}

function Get-FirewallLabelDetail {
    param([object]$Item,[object]$Relation)

    # Returns the label lines shown below the firewall name. Related values
    # share a line so the label still fits the fixed node height.
    # The management IP is shown on the management interface shape instead.
    $addresses = @(@($Relation.PrivateIpAddresses) + @([string](Get-ObjectValue $Item 'hubPrivateIpAddress' '')) | Where-Object { $_ })
    $addressLine = @($addresses -join ', ') | Where-Object { $_ }

    # A policy-managed firewall takes its threat intelligence mode from the
    # policy, so the firewall's own value is only meaningful without one.
    $policyId = [string](Get-ObjectValue $Item 'firewallPolicyId' '')
    $threatIntelMode = [string](Get-ObjectValue $Item 'threatIntelMode' '')
    $policyLine = ''
    if ($policyId) {
        $policyLine = "Policy: $(Get-ResourceNameFromId $policyId)"
    } elseif ($threatIntelMode) {
        $policyLine = "Threat intel: $threatIntelMode"
    }

    $zones = ConvertTo-DisplayList (Get-ObjectValue $Item 'zones' '')
    $stateLine = @(
        $(if ($zones) { "Zones: $zones" }),
        [string](Get-ObjectValue $Item 'provisioningState' '')
    ) | Where-Object { $_ }
    $hubPublicIps = Get-JsonPropertyList (Get-ObjectValue $Item 'hubPublicIpAddresses' '') 'address'

    return @(
        ("$(Get-ObjectValue $Item 'sku' '') $(Get-ObjectValue $Item 'tier' '')").Trim(),
        ($addressLine -join ' | '),
        $policyLine,
        ($stateLine -join ' | '),
        $(if ($hubPublicIps) { "Public: $hubPublicIps" })
    ) | Where-Object { $_ }
}

function Get-FirewallPolicyLinkAttribute {
    param([object]$Item,[hashtable]$DetailPageIdByResourceId)

    # Shape attributes that open the firewall's policy page, when one is built.
    $attributes = @{}
    $policyId = ConvertTo-ResourceId (Get-ObjectValue $Item 'firewallPolicyId' '')
    if ($policyId -and $DetailPageIdByResourceId.ContainsKey($policyId)) {
        $attributes.link = "data:page/id,$($DetailPageIdByResourceId[$policyId])"
        $attributes.tooltip = 'Open firewall policy rules'
    }
    return $attributes
}

function Get-PrimaryLocalSubnetId {
    param(
        [string[]]$CandidateIds,
        [System.Collections.Generic.HashSet[string]]$LocalSubnetIds,
        [hashtable]$SubnetById,
        [string]$PreferredName = ''
    )

    $localCandidates = @($CandidateIds | ForEach-Object { ConvertTo-ResourceId $_ } |
        Where-Object { $_ -and $LocalSubnetIds.Contains($_) } | Sort-Object -Unique)
    if ($PreferredName) {
        foreach ($candidateId in $localCandidates) {
            if ($SubnetById.ContainsKey($candidateId) -and
                [string](Get-ObjectValue $SubnetById[$candidateId] 'name' '') -ieq $PreferredName) {
                return $candidateId
            }
        }
    }
    if ($localCandidates.Count -gt 0) { return [string]$localCandidates[0] }
    return ''
}

function Add-PageLegend {
    param([System.Xml.XmlDocument]$Document, [System.Xml.XmlElement]$Root, [double]$Y, [double]$Width = 1320)
    $value = "<b>Legend</b><br><font color='#0078d4'>Azure icon</font> = Azure resource &nbsp; | &nbsp; " +
             "Contained = VNet/subnet membership &nbsp; | &nbsp; Solid line = attachment/backend &nbsp; | &nbsp; " +
             "Dashed line = security/configuration/peering &nbsp; | &nbsp; Purple line = hybrid connectivity &nbsp; | &nbsp; Click a remote VNet to open its page"
    Add-MxVertex -Document $Document -Root $Root -Id 'legend' -Parent '1' -Value $value `
        -Style 'rounded=1;whiteSpace=wrap;html=1;fillColor=#f8f9fa;strokeColor=#adb5bd;fontSize=10;align=left;spacingLeft=10;' `
        -X 20 -Y $Y -Width $Width -Height 54
}

function New-EnhancedDrawIoPage {
    param(
        [System.Xml.XmlDocument]$Document,
        [System.Xml.XmlElement]$MxFile,
        [object]$Data,
        [object]$Index,
        [object]$Vnet,
        [hashtable]$PageIdByVnetId,
        [hashtable]$DetailPageIdByResourceId,
        [System.Collections.Generic.HashSet[string]]$UsedResourceIds,
        [ValidateRange(1,4)][int]$ResourcesPerRow
    )

    $vnetId = ConvertTo-ResourceId (Get-ObjectValue $Vnet 'id')
    $vnetName = [string](Get-ObjectValue $Vnet 'name' '(unnamed VNet)')
    $subscriptionId = [string](Get-ObjectValue $Vnet 'subscriptionId' '')
    $subscriptionName = ''
    $normalizedSubscriptionId = ConvertTo-ResourceId $subscriptionId
    if ($Index.SubscriptionById.ContainsKey($normalizedSubscriptionId)) {
        $subscriptionName = [string](Get-ObjectValue $Index.SubscriptionById[$normalizedSubscriptionId] 'subscriptionName' '')
    }
    $pageId = $PageIdByVnetId[$vnetId]
    $diagram = $Document.CreateElement('diagram')
    Set-XmlAttribute $diagram 'id' $pageId
    $pageName=if($subscriptionName){"$vnetName - $subscriptionName"}else{$vnetName}
    Set-XmlAttribute $diagram 'name' $(if ($pageName.Length -gt 80) { $pageName.Substring(0,80) } else { $pageName })
    Set-XmlAttribute $diagram 'azureSubscriptionId' $subscriptionId
    Set-XmlAttribute $diagram 'azureSubscriptionName' $subscriptionName
    $null = $MxFile.AppendChild($diagram)

    $model = $Document.CreateElement('mxGraphModel')
    foreach ($pair in ([ordered]@{dx='1422';dy='794';grid='1';gridSize='10';guides='1';tooltips='1';connect='1';arrows='1';fold='1';page='1';pageScale='1';pageWidth='2100';pageHeight='1200';math='0';shadow='0'}).GetEnumerator()) {
        Set-XmlAttribute $model $pair.Key $pair.Value
    }
    $null = $diagram.AppendChild($model)
    $root = $Document.CreateElement('root')
    $null = $model.AppendChild($root)
    $baseCell = Add-MxBaseCell $Document $root
    Add-MxVertex -Document $Document -Root $root -Id 'overview-link' -Parent '1' `
        -Value '&#8592; Network overview' `
        -Style 'rounded=1;whiteSpace=wrap;html=1;fillColor=#e6f2ff;strokeColor=#0078d4;fontColor=#0078d4;fontStyle=1;' `
        -X 20 -Y 15 -Width 220 -Height 30 -Attributes @{link='data:page/id,network-overview';tooltip='Open the network overview page'}

    $subnets = @($Index.SubnetsByVnetId[$vnetId] | ForEach-Object { $_ })
    $subnetIds = @($subnets | ForEach-Object { ConvertTo-ResourceId (Get-ObjectValue $_ 'id') })
    $subnetIdSet = [System.Collections.Generic.HashSet[string]]::new([string[]]$subnetIds,[System.StringComparer]::OrdinalIgnoreCase)
    $nicRows = @(foreach ($subnetId in $subnetIds) { $Index.NicRowsBySubnetId[$subnetId] | ForEach-Object { $_ } })
    $localNicIds = @($nicRows | ForEach-Object { ConvertTo-ResourceId (Get-ObjectValue $_ 'nicId') } | Sort-Object -Unique)
    $publicIpById = $Index.PublicIpById
    $publicIpPrefixById = $Index.PublicIpPrefixById
    $nsgById = $Index.NsgById

    $nodes = @{}
    $edges = [System.Collections.Generic.List[object]]::new()
    $edgeKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $null = $UsedResourceIds.Add($vnetId)
    foreach ($subnet in $subnets) { $null = $UsedResourceIds.Add((ConvertTo-ResourceId (Get-ObjectValue $subnet 'id'))) }

    foreach ($nicGroup in @($nicRows | Group-Object { ConvertTo-ResourceId (Get-ObjectValue $_ 'nicId') } | Sort-Object Name)) {
        $first = $nicGroup.Group[0]; $nicId = ConvertTo-ResourceId (Get-ObjectValue $first 'nicId')
        $ips = @($nicGroup.Group | ForEach-Object { [string](Get-ObjectValue $_ 'privateIpAddress' '') } | Where-Object { $_ } | Sort-Object -Unique)
        $allocation = @($nicGroup.Group | ForEach-Object { [string](Get-ObjectValue $_ 'privateIpAllocationMethod' '') } | Where-Object { $_ } | Sort-Object -Unique) -join ', '
        $nicName = [string](Get-ObjectValue $first 'nicName' (Get-ResourceNameFromId $nicId))
        Add-GraphNode $nodes $UsedResourceIds $nicId $nicName NIC 'Microsoft.Network/networkInterfaces' `
            "<b>$nicName</b><br>$($ips -join ', ')<br><font color='#666666'>$allocation</font>" Internal `
            (Get-ObjectValue $first 'subnetId' '')
        foreach ($pipId in @($nicGroup.Group | ForEach-Object { ConvertTo-ResourceId (Get-ObjectValue $_ 'publicIpId') } | Where-Object { $_ } | Sort-Object -Unique)) {
            Add-ReferencedPublicIp $pipId $nodes $publicIpById $UsedResourceIds
            Add-GraphEdge $edges $edgeKeys $pipId $nicId 'public IP' Attachment
        }
        $nsgId = ConvertTo-ResourceId (Get-ObjectValue $first 'nicNsgId')
        if ($nsgId) {
            $nsg = if ($nsgById.ContainsKey($nsgId)) { $nsgById[$nsgId] } else { $null }
            $name = if ($nsg) { [string](Get-ObjectValue $nsg 'name' (Get-ResourceNameFromId $nsgId)) } else { Get-ResourceNameFromId $nsgId }
            $count = if ($nsg) { [string](Get-ObjectValue $nsg 'securityRuleCount' '?') } else { '?' }
            $attributes = @{}
            if ($DetailPageIdByResourceId.ContainsKey($nsgId)) { $attributes.link = "data:page/id,$($DetailPageIdByResourceId[$nsgId])"; $attributes.tooltip = 'Open NSG rule details' }
            Add-GraphNode $nodes $UsedResourceIds $nsgId $name NSG 'Microsoft.Network/networkSecurityGroups' "<b>$name</b><br>Custom rules: $count<br><font color='#0078d4'>Open rules</font>" Security '' $attributes
            Add-GraphEdge $edges $edgeKeys $nsgId $nicId 'protects NIC' Security
        }
    }

    $localVmRows = @(foreach ($localNicId in $localNicIds) { $Index.VmRowsByNicId[$localNicId] | ForEach-Object { $_ } })
    foreach ($vmGroup in @($localVmRows | Group-Object { ConvertTo-ResourceId (Get-ObjectValue $_ 'id') } | Sort-Object Name)) {
        $localRows = @($vmGroup.Group)
        $vm = $localRows[0]; $vmId = ConvertTo-ResourceId (Get-ObjectValue $vm 'id'); $nicId = ConvertTo-ResourceId (Get-ObjectValue $localRows[0] 'nicId')
        $subnetId = ConvertTo-ResourceId (Get-ObjectValue @($Index.NicRowsByNicId[$nicId])[0] 'subnetId' '')
        $name=[string](Get-ObjectValue $vm 'name' (Get-ResourceNameFromId $vmId)); $size=[string](Get-ObjectValue $vm 'vmSize' ''); $os=[string](Get-ObjectValue $vm 'osType' '')
        Add-GraphNode $nodes $UsedResourceIds $vmId $name VM 'Microsoft.Compute/virtualMachines' "<b>$name</b><br>$size<br><font color='#666666'>$os</font>" Internal $subnetId
        foreach ($row in $localRows) { Add-GraphEdge $edges $edgeKeys $vmId (Get-ObjectValue $row 'nicId') 'uses NIC' Attachment }
    }

    $localVmssIds = @(@(foreach ($subnetId in $subnetIds) {
        $Index.VmssIdsBySubnetId[$subnetId] | ForEach-Object { $_ }
    }) | Sort-Object -Unique)
    foreach ($scaleSetId in $localVmssIds) {
        $relation = $Index.VmssRelationById[$scaleSetId]
        $scaleSet = $relation.ScaleSet
        $localSubnetIds = @($relation.SubnetIds | Where-Object { $subnetIdSet.Contains($_) })
        if ($localSubnetIds.Count -eq 0) { continue }
        $primarySubnetId = if ($subnetIdSet.Contains($relation.PrimarySubnetId)) { $relation.PrimarySubnetId } else { $localSubnetIds[0] }
        $name = [string](Get-ObjectValue $scaleSet 'name' (Get-ResourceNameFromId $scaleSetId))
        $sku = [string](Get-ObjectValue $scaleSet 'sku' '')
        $capacity = [string](Get-ObjectValue $scaleSet 'capacity' '')
        $orchestrationMode = [string](Get-ObjectValue $scaleSet 'orchestrationMode' '')
        $upgradeMode = [string](Get-ObjectValue $scaleSet 'upgradeMode' '')
        $details = @(
            $sku,
            $(if ($capacity) { "Instances: $capacity" }),
            $(if ($orchestrationMode) { "Orchestration: $orchestrationMode" }),
            $(if ($upgradeMode) { "Upgrade: $upgradeMode" })
        ) | Where-Object { $_ }
        Add-GraphNode $nodes $UsedResourceIds $scaleSetId $name VMSS 'Microsoft.Compute/virtualMachineScaleSets' `
            "<b>$name</b><br>$($details -join '<br>')" Internal $primarySubnetId
        foreach ($relatedSubnetId in $localSubnetIds) {
            if ($relatedSubnetId -ne $primarySubnetId) {
                Add-GraphEdge $edges $edgeKeys $scaleSetId $relatedSubnetId 'VMSS NIC subnet' Attachment
            }
        }
        foreach ($nsgId in $relation.NsgIds) {
            $nsg = if ($nsgById.ContainsKey($nsgId)) { $nsgById[$nsgId] } else { $null }
            $nsgName = if ($nsg) { [string](Get-ObjectValue $nsg 'name' (Get-ResourceNameFromId $nsgId)) } else { Get-ResourceNameFromId $nsgId }
            $count = if ($nsg) { [string](Get-ObjectValue $nsg 'securityRuleCount' '?') } else { '?' }
            $attributes = @{}
            if ($DetailPageIdByResourceId.ContainsKey($nsgId)) {
                $attributes.link = "data:page/id,$($DetailPageIdByResourceId[$nsgId])"
                $attributes.tooltip = 'Open NSG rule details'
            }
            Add-GraphNode $nodes $UsedResourceIds $nsgId $nsgName NSG 'Microsoft.Network/networkSecurityGroups' `
                "<b>$nsgName</b><br>Custom rules: $count<br><font color='#0078d4'>Open rules</font>" Security '' $attributes
            Add-GraphEdge $edges $edgeKeys $nsgId $scaleSetId 'protects VMSS' Security
        }
    }

    $localPrivateEndpointRows = @(foreach ($subnetId in $subnetIds) { $Index.PrivateEndpointRowsBySubnetId[$subnetId] | ForEach-Object { $_ } })
    foreach ($peGroup in @($localPrivateEndpointRows | Group-Object { ConvertTo-ResourceId (Get-ObjectValue $_ 'id') } | Sort-Object Name)) {
        $pe=$peGroup.Group[0]; $id=ConvertTo-ResourceId (Get-ObjectValue $pe 'id'); $name=[string](Get-ObjectValue $pe 'name' (Get-ResourceNameFromId $id)); $subnetId=ConvertTo-ResourceId (Get-ObjectValue $pe 'subnetId')
        $targets=@($peGroup.Group | ForEach-Object { ConvertTo-ResourceId (Get-ObjectValue $_ 'targetId') } | Where-Object { $_ } | Sort-Object -Unique)
        $groups=ConvertTo-DisplayList (Get-ObjectValue $pe 'groupIds' '')
        Add-GraphNode $nodes $UsedResourceIds $id $name PrivateEndpoint 'Microsoft.Network/privateEndpoints' "<b>$name</b><br>$groups<br><font color='#666666'>$(Get-ObjectValue $pe 'connectionState' '')</font>" Internal $subnetId
        foreach ($target in $targets) {
            $targetName=Get-ResourceNameFromId $target
            Add-GraphNode $nodes $UsedResourceIds $target $targetName PrivateLinkTarget 'Azure linked resource' "<b>$targetName</b><br><font color='#666666'>Private Link target</font>" Connectivity
            Add-GraphEdge $edges $edgeKeys $id $target 'private link' Attachment
        }
    }

    foreach ($subnet in $subnets) {
        $subnetId=ConvertTo-ResourceId (Get-ObjectValue $subnet 'id')
        $nsgId=ConvertTo-ResourceId (Get-ObjectValue $subnet 'nsgId')
        if ($nsgId) {
            $nsg=if($nsgById.ContainsKey($nsgId)){$nsgById[$nsgId]}else{$null}; $name=if($nsg){[string](Get-ObjectValue $nsg 'name' (Get-ResourceNameFromId $nsgId))}else{Get-ResourceNameFromId $nsgId}; $count=if($nsg){[string](Get-ObjectValue $nsg 'securityRuleCount' '?')}else{'?'}
            $attributes=@{};if($DetailPageIdByResourceId.ContainsKey($nsgId)){$attributes.link="data:page/id,$($DetailPageIdByResourceId[$nsgId])";$attributes.tooltip='Open NSG rule details'}
            Add-GraphNode $nodes $UsedResourceIds $nsgId $name NSG 'Microsoft.Network/networkSecurityGroups' "<b>$name</b><br>Custom rules: $count<br><font color='#0078d4'>Open rules</font>" Security '' $attributes
            Add-GraphEdge $edges $edgeKeys $nsgId $subnetId 'protects subnet' Security
        }
        $routeId=ConvertTo-ResourceId (Get-ObjectValue $subnet 'routeTableId')
        if ($routeId) {
            $route=if($Index.RouteTableById.ContainsKey($routeId)){$Index.RouteTableById[$routeId]}else{$null}
            $name=if($route){[string](Get-ObjectValue $route 'name' (Get-ResourceNameFromId $routeId))}else{Get-ResourceNameFromId $routeId}; $count=if($route){[string](Get-ObjectValue $route 'routeCount' '?')}else{'?'}
            $attributes=@{};if($DetailPageIdByResourceId.ContainsKey($routeId)){$attributes.link="data:page/id,$($DetailPageIdByResourceId[$routeId])";$attributes.tooltip='Open route details'}
            Add-GraphNode $nodes $UsedResourceIds $routeId $name RouteTable 'Microsoft.Network/routeTables' "<b>$name</b><br>Routes: $count<br><font color='#0078d4'>Open routes</font>" Security '' $attributes
            Add-GraphEdge $edges $edgeKeys $routeId $subnetId 'routes subnet' Configuration
        }
        $natId=ConvertTo-ResourceId (Get-ObjectValue $subnet 'natGatewayId')
        if ($natId) {
            $nat=if($Index.NatGatewayById.ContainsKey($natId)){$Index.NatGatewayById[$natId]}else{$null}
            $name=if($nat){[string](Get-ObjectValue $nat 'name' (Get-ResourceNameFromId $natId))}else{Get-ResourceNameFromId $natId}; $sku=if($nat){[string](Get-ObjectValue $nat 'sku' '')}else{''}
            Add-GraphNode $nodes $UsedResourceIds $natId $name NAT 'Microsoft.Network/natGateways' "<b>$name</b><br>$sku" Connectivity
            Add-GraphEdge $edges $edgeKeys $natId $subnetId 'outbound NAT' Configuration
            if ($nat) {
                $pipIds=@(
                    Get-IdsFromJson (Get-ObjectValue $nat 'publicIpIds' '')
                    Get-IdsFromJson (Get-ObjectValue $nat 'publicIpIdsV6' '')
                )
                $legacy=ConvertTo-ResourceId (Get-ObjectValue $nat 'publicIpId' ''); if($legacy){$pipIds+= $legacy}
                foreach($pipId in @($pipIds|Sort-Object -Unique)){ Add-ReferencedPublicIp $pipId $nodes $publicIpById $UsedResourceIds; Add-GraphEdge $edges $edgeKeys $pipId $natId 'NAT public IP' Attachment }
                $prefixIds=@(
                    Get-IdsFromJson (Get-ObjectValue $nat 'publicIpPrefixIds' '')
                    Get-IdsFromJson (Get-ObjectValue $nat 'publicIpPrefixIdsV6' '')
                )
                foreach($prefixId in @($prefixIds|Sort-Object -Unique)){
                    Add-ReferencedPublicIpPrefix $prefixId $nodes $publicIpPrefixById $UsedResourceIds
                    Add-GraphEdge $edges $edgeKeys $prefixId $natId 'NAT public IP prefix' Attachment
                }
            }
        }
    }

    $localLoadBalancerIds = @($Index.LoadBalancerIdsByVnetId[$vnetId] | ForEach-Object { $_ } | Sort-Object -Unique)
    foreach ($id in $localLoadBalancerIds) {
        $relation = $Index.LoadBalancerRelationById[$id]
        $lb = $relation.Rows[0]
        $name=[string](Get-ObjectValue $lb 'name' (Get-ResourceNameFromId $id)); $sku=[string](Get-ObjectValue $lb 'sku' ''); $rules=[string](Get-ObjectValue $lb 'ruleCount' '0')
        Add-GraphNode $nodes $UsedResourceIds $id $name LoadBalancer 'Microsoft.Network/loadBalancers' "<b>$name</b><br>$sku<br>Rules: $rules" Connectivity
        foreach ($sid in @($relation.FrontendSubnetIds | Where-Object { $subnetIdSet.Contains($_) })) {
            Add-GraphEdge $edges $edgeKeys $id $sid 'frontend subnet' Attachment
        }
        foreach ($pipId in $relation.PublicIpIds) {
            Add-ReferencedPublicIp $pipId $nodes $publicIpById $UsedResourceIds
            Add-GraphEdge $edges $edgeKeys $pipId $id 'frontend IP' Attachment
        }
        foreach ($nicId in @($relation.BackendNicIds | Where-Object { $localNicIds -contains $_ })) {
            Add-GraphEdge $edges $edgeKeys $id $nicId 'backend' Attachment
        }
        foreach ($scaleSetId in @($relation.BackendVmssIds | Where-Object { $localVmssIds -contains $_ })) {
            Add-GraphEdge $edges $edgeKeys $id $scaleSetId 'backend' Attachment
        }
    }

    $localApplicationGatewayIds = @(@(foreach ($subnetId in $subnetIds) {
        $Index.ApplicationGatewayIdsBySubnetId[$subnetId] | ForEach-Object { $_ }
    }) | Sort-Object -Unique)
    foreach ($id in $localApplicationGatewayIds) {
        $relation = $Index.ApplicationGatewayRelationById[$id]
        $item = $relation.Rows[0]
        $name = [string](Get-ObjectValue $item 'name' (Get-ResourceNameFromId $id))
        $sku = [string](Get-ObjectValue $item 'sku' '')
        $tier = [string](Get-ObjectValue $item 'tier' '')
        $privateIps = @($relation.PrivateIpAddresses)
        $details = @($sku,$tier,$(if ($privateIps.Count -gt 0) { "Private IPs: $($privateIps -join ', ')" })) | Where-Object { $_ }
        $primarySubnetId = Get-PrimaryLocalSubnetId $relation.DeploymentSubnetIds $subnetIdSet $Index.SubnetById
        $lane = if ($primarySubnetId) { 'Internal' } else { 'Connectivity' }
        Add-GraphNode $nodes $UsedResourceIds $id $name ApplicationGateway 'Microsoft.Network/applicationGateways' `
            "<b>$name</b><br>$($details -join '<br>')" $lane $primarySubnetId
        foreach ($sid in @($relation.DeploymentSubnetIds | Where-Object { $subnetIdSet.Contains($_) -and $_ -ne $primarySubnetId })) {
            Add-GraphEdge $edges $edgeKeys $id $sid 'additional gateway subnet' Attachment
        }
        foreach ($sid in @($relation.FrontendSubnetIds | Where-Object { $subnetIdSet.Contains($_) -and $_ -ne $primarySubnetId })) {
            Add-GraphEdge $edges $edgeKeys $id $sid 'frontend subnet' Attachment
        }
        foreach ($pipId in $relation.PublicIpIds) {
            Add-ReferencedPublicIp $pipId $nodes $publicIpById $UsedResourceIds
            Add-GraphEdge $edges $edgeKeys $pipId $id 'frontend IP' Attachment
        }
    }

    $localFirewallIds = @(@(foreach ($subnetId in $subnetIds) {
        $Index.FirewallIdsBySubnetId[$subnetId] | ForEach-Object { $_ }
    }) | Sort-Object -Unique)
    foreach ($id in $localFirewallIds) {
        $relation = $Index.FirewallRelationById[$id]
        $item = $relation.Rows[0]
        $name = [string](Get-ObjectValue $item 'name' (Get-ResourceNameFromId $id))
        $details = @(Get-FirewallLabelDetail $item $relation)
        $primarySubnetId = Get-PrimaryLocalSubnetId $relation.SubnetIds $subnetIdSet $Index.SubnetById 'AzureFirewallSubnet'
        $lane = if ($primarySubnetId) { 'Internal' } else { 'Connectivity' }
        Add-GraphNode $nodes $UsedResourceIds $id $name Firewall 'Microsoft.Network/azureFirewalls' `
            "<b>$name</b><br>$($details -join '<br>')" $lane $primarySubnetId `
            (Get-FirewallPolicyLinkAttribute $item $DetailPageIdByResourceId)
        foreach ($sid in @($relation.SubnetIds | Where-Object { $subnetIdSet.Contains($_) -and $_ -ne $primarySubnetId })) {
            Add-GraphEdge $edges $edgeKeys $id $sid 'additional firewall subnet' Attachment
        }
        foreach ($pipId in $relation.PublicIpIds) {
            Add-ReferencedPublicIp $pipId $nodes $publicIpById $UsedResourceIds
            Add-GraphEdge $edges $edgeKeys $pipId $id 'public IP' Attachment
        }
        # The firewall's second interface sits in the management subnet. Drawing it
        # there shows that placement directly, and the management public IP
        # belongs to that interface rather than to the data-plane firewall shape.
        $managementSubnetId = @($relation.ManagementSubnetIds | Where-Object { $subnetIdSet.Contains($_) } | Select-Object -First 1)
        $managementTargetId = $id
        if ($managementSubnetId.Count -gt 0) {
            $managementTargetId = "$id/managementipconfiguration"
            if (@($relation.ManagementIpConfigurationIds).Count -gt 0) { $managementTargetId = [string]@($relation.ManagementIpConfigurationIds)[0] }
            $managementAddresses = @($relation.ManagementPrivateIpAddresses | Where-Object { $_ })
            $managementAddressText = if ($managementAddresses.Count -gt 0) { $managementAddresses -join ', ' } else { "<font color='#666666'>Private IP not reported</font>" }
            Add-GraphNode $nodes $UsedResourceIds $managementTargetId $name FirewallManagementInterface `
                'Microsoft.Network/azureFirewalls/azureFirewallIpConfigurations' "<b>$name</b><br>$managementAddressText" `
                Internal ([string]$managementSubnetId[0]) @{ tooltip = "Management interface of Azure Firewall $name" }
            Add-GraphEdge $edges $edgeKeys $id $managementTargetId 'management interface' Attachment
        }
        foreach ($pipId in $relation.ManagementPublicIpIds) {
            Add-ReferencedPublicIp $pipId $nodes $publicIpById $UsedResourceIds
            Add-GraphEdge $edges $edgeKeys $pipId $managementTargetId 'management public IP' Attachment
        }
    }

    $localGatewayIds = @(@(foreach ($subnetId in $subnetIds) {
        $Index.GatewayIdsBySubnetId[$subnetId] | ForEach-Object { $_ }
    }) | Sort-Object -Unique)
    foreach ($id in $localGatewayIds) {
        $relation = $Index.GatewayRelationById[$id]
        $item = $relation.Rows[0]
        $name = [string](Get-ObjectValue $item 'name' (Get-ResourceNameFromId $id))
        $details = @(
            (Get-ObjectValue $item 'sku' ''),
            (Get-ObjectValue $item 'gatewayType' ''),
            $(if ($relation.PrivateIpAddresses.Count -gt 0) { $relation.PrivateIpAddresses -join ', ' })
        ) | Where-Object { $_ }
        $primarySubnetId = Get-PrimaryLocalSubnetId $relation.SubnetIds $subnetIdSet $Index.SubnetById 'GatewaySubnet'
        $lane = if ($primarySubnetId) { 'Internal' } else { 'Connectivity' }
        Add-GraphNode $nodes $UsedResourceIds $id $name Gateway 'Microsoft.Network/virtualNetworkGateways' `
            "<b>$name</b><br>$($details -join '<br>')" $lane $primarySubnetId
        foreach ($sid in @($relation.SubnetIds | Where-Object { $subnetIdSet.Contains($_) -and $_ -ne $primarySubnetId })) {
            Add-GraphEdge $edges $edgeKeys $id $sid 'additional gateway subnet' Attachment
        }
        foreach ($pipId in $relation.PublicIpIds) {
            Add-ReferencedPublicIp $pipId $nodes $publicIpById $UsedResourceIds
            Add-GraphEdge $edges $edgeKeys $pipId $id 'public IP' Attachment
        }
    }

    $localBastionIds = @(@(foreach ($subnetId in $subnetIds) {
        $Index.BastionIdsBySubnetId[$subnetId] | ForEach-Object { $_ }
    }) | Sort-Object -Unique)
    foreach ($id in $localBastionIds) {
        $relation = $Index.BastionRelationById[$id]
        $item = $relation.Rows[0]
        $name = [string](Get-ObjectValue $item 'name' (Get-ResourceNameFromId $id))
        $sku = [string](Get-ObjectValue $item 'sku' ''); $scale = [string](Get-ObjectValue $item 'scaleUnits' ''); $state = [string](Get-ObjectValue $item 'provisioningState' '')
        $features=@();if((Get-ObjectValue $item 'enableTunneling' $false)){$features+='Tunneling'};if((Get-ObjectValue $item 'enableIpConnect' $false)){$features+='IP Connect'};if((Get-ObjectValue $item 'enableShareableLink' $false)){$features+='Shareable Link'};if((Get-ObjectValue $item 'enableKerberos' $false)){$features+='Kerberos'}
        $details=@($sku,$(if($scale){"Scale units: $scale"}),$state,$(if($features.Count -gt 0){$features -join ', '}),$(if($relation.PrivateIpAddresses.Count -gt 0){$relation.PrivateIpAddresses -join ', '}))|Where-Object{$_}
        $primarySubnetId = Get-PrimaryLocalSubnetId $relation.SubnetIds $subnetIdSet $Index.SubnetById 'AzureBastionSubnet'
        $lane = if ($primarySubnetId) { 'Internal' } else { 'Connectivity' }
        Add-GraphNode $nodes $UsedResourceIds $id $name Bastion 'Microsoft.Network/bastionHosts' "<b>$name</b><br>$($details -join '<br>')" $lane $primarySubnetId
        foreach ($sid in @($relation.SubnetIds | Where-Object { $subnetIdSet.Contains($_) -and $_ -ne $primarySubnetId })) {
            Add-GraphEdge $edges $edgeKeys $id $sid 'additional Bastion subnet' Attachment
        }
        foreach ($pipId in $relation.PublicIpIds) {
            Add-ReferencedPublicIp $pipId $nodes $publicIpById $UsedResourceIds
            Add-GraphEdge $edges $edgeKeys $pipId $id 'Bastion public IP' Attachment
        }
    }

    $localGatewayIds=@($nodes.Values|Where-Object Kind -eq 'Gateway'|ForEach-Object{$_.Id})
    $gatewayById=$Index.GatewayById
    $localNetworkGatewayById=$Index.LocalNetworkGatewayById
    $circuitById=$Index.ExpressRouteCircuitById
    $renderedConnectionIds=[System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach($connection in @(Get-DataRows $Data 'gatewayConnections'|Where-Object{
        $gateway1=ConvertTo-ResourceId(Get-ObjectValue $_ 'vnetGateway1Id');$gateway2=ConvertTo-ResourceId(Get-ObjectValue $_ 'vnetGateway2Id')
        ($localGatewayIds -contains $gateway1)-or($localGatewayIds -contains $gateway2)
    })){
        $connectionId=ConvertTo-ResourceId(Get-ObjectValue $connection 'id')
        $connectionName=[string](Get-ObjectValue $connection 'name' (Get-ResourceNameFromId $connectionId))
        $connectionType=[string](Get-ObjectValue $connection 'connectionType' '')
        $connectionState=[string](Get-ObjectValue $connection 'connectionStatus' '')
        if(-not$connectionState){$connectionState=[string](Get-ObjectValue $connection 'provisioningState' '')}
        $bgpEnabled=[bool](Get-ObjectValue $connection 'enableBgp' $false)
        $connectionParts=@($connectionType,$connectionState,$(if($bgpEnabled){'BGP'}))|Where-Object{$_}
        $connectionLabel="<b>$connectionName</b><br>$($connectionParts -join ' | ')"
        $connectionTooltip="Connection: $connectionName`nType: $connectionType`nStatus: $connectionState`nBGP enabled: $bgpEnabled"
        $gateway1=ConvertTo-ResourceId(Get-ObjectValue $connection 'vnetGateway1Id')
        $gateway2=ConvertTo-ResourceId(Get-ObjectValue $connection 'vnetGateway2Id')
        $localGatewayId=@($gateway1,$gateway2|Where-Object{$localGatewayIds -contains $_}|Select-Object -First 1)
        if($localGatewayId.Count -eq 0){continue}
        $localGatewayId=[string]$localGatewayId[0]
        $endpointIds=[System.Collections.Generic.List[string]]::new()

        $remoteGatewayId=@($gateway1,$gateway2|Where-Object{$_ -and $_ -ne $localGatewayId}|Select-Object -First 1)
        if($remoteGatewayId.Count -gt 0){
            $remoteGatewayId=[string]$remoteGatewayId[0]
            $remote=if($gatewayById.ContainsKey($remoteGatewayId)){$gatewayById[$remoteGatewayId]}else{$null}
            $remoteName=if($remote){[string](Get-ObjectValue $remote 'name' (Get-ResourceNameFromId $remoteGatewayId))}else{Get-ResourceNameFromId $remoteGatewayId}
            $remoteDetails=if($remote){@((Get-ObjectValue $remote 'gatewayType' ''),(Get-ObjectValue $remote 'sku' ''))|Where-Object{$_}}else{@('Remote virtual network gateway')}
            Add-GraphNode $nodes $UsedResourceIds $remoteGatewayId $remoteName RemoteGateway 'Microsoft.Network/virtualNetworkGateways' "<b>$remoteName</b><br>$($remoteDetails -join '<br>')" External
            $endpointIds.Add($remoteGatewayId)
        }

        $lngId=ConvertTo-ResourceId(Get-ObjectValue $connection 'localNetworkGateway2Id')
        if($lngId){
            $lng=if($localNetworkGatewayById.ContainsKey($lngId)){$localNetworkGatewayById[$lngId]}else{$null}
            $lngName=if($lng){[string](Get-ObjectValue $lng 'name' (Get-ResourceNameFromId $lngId))}else{Get-ResourceNameFromId $lngId}
            $lngDetails=if($lng){@((Get-ObjectValue $lng 'gatewayIpAddress' ''),(ConvertTo-DisplayList(Get-ObjectValue $lng 'addressPrefixes' '')),$(if((Get-ObjectValue $lng 'bgpAsn' '')){"BGP ASN: $(Get-ObjectValue $lng 'bgpAsn' '')"}))|Where-Object{$_}}else{@()}
            Add-GraphNode $nodes $UsedResourceIds $lngId $lngName LocalNetworkGateway 'Microsoft.Network/localNetworkGateways' "<b>$lngName</b><br>$($lngDetails -join '<br>')" External
            $endpointIds.Add($lngId)
        }

        $circuitId=ConvertTo-ResourceId(Get-ObjectValue $connection 'expressRouteCircuitId')
        if($circuitId){
            $circuit=if($circuitById.ContainsKey($circuitId)){$circuitById[$circuitId]}else{$null}
            $circuitName=if($circuit){[string](Get-ObjectValue $circuit 'name' (Get-ResourceNameFromId $circuitId))}else{Get-ResourceNameFromId $circuitId}
            $circuitDetails=if($circuit){@((Get-ObjectValue $circuit 'serviceProvider' ''),(Get-ObjectValue $circuit 'peeringLocation' ''),$(if((Get-ObjectValue $circuit 'bandwidthMbps' '')){"$(Get-ObjectValue $circuit 'bandwidthMbps' '') Mbps"}),(Get-ObjectValue $circuit 'circuitState' ''))|Where-Object{$_}}else{@()}
            Add-GraphNode $nodes $UsedResourceIds $circuitId $circuitName ExpressRouteCircuit 'Microsoft.Network/expressRouteCircuits' "<b>$circuitName</b><br>$($circuitDetails -join '<br>')" External
            $endpointIds.Add($circuitId)
        }

        if($endpointIds.Count -eq 0){
            $unresolvedId="$connectionId/unresolved-remote-endpoint"
            Add-GraphNode $nodes $UsedResourceIds $unresolvedId 'Unresolved remote endpoint' GenericExternal '' '<b>Unresolved remote endpoint</b><br><font color=''#666666''>Endpoint ID was not returned</font>' External
            $endpointIds.Add($unresolvedId)
        }
        foreach($endpointId in $endpointIds){
            Add-GraphEdge $edges $edgeKeys $localGatewayId $endpointId $connectionLabel Hybrid $connectionId 'Microsoft.Network/connections' @{tooltip=$connectionTooltip}
        }
        $null=$renderedConnectionIds.Add($connectionId)
        $null=$UsedResourceIds.Add($connectionId)
    }

    foreach ($hubConnection in @($Index.HubConnectionsByVnetId[$vnetId] | ForEach-Object { $_ })) {
        $connectionId = ConvertTo-ResourceId (Get-ObjectValue $hubConnection 'id')
        $hubId = ConvertTo-ResourceId (Get-ObjectValue $hubConnection 'virtualHubId')
        if (-not $hubId) { continue }
        $hub = if ($Index.VirtualHubById.ContainsKey($hubId)) { $Index.VirtualHubById[$hubId] } else { $null }
        $hubName = if ($hub) { [string](Get-ObjectValue $hub 'name' (Get-ResourceNameFromId $hubId)) } else { Get-ResourceNameFromId $hubId }
        $hubDetails = @()
        if ($hub) {
            $hubDetails = @(
                (Get-ObjectValue $hub 'addressPrefix' ''),
                $(if ((Get-ObjectValue $hub 'virtualRouterAsn' '')) { "ASN: $(Get-ObjectValue $hub 'virtualRouterAsn' '')" }),
                (Get-ObjectValue $hub 'provisioningState' '')
            ) | Where-Object { $_ }
        }
        Add-GraphNode $nodes $UsedResourceIds $hubId $hubName VirtualHub 'Microsoft.Network/virtualHubs' `
            "<b>$hubName</b><br>$($hubDetails -join '<br>')" External
        $connectionName = [string](Get-ObjectValue $hubConnection 'name' 'Virtual WAN connection')
        $connectionState = [string](Get-ObjectValue $hubConnection 'provisioningState' '')
        $connectionLabel = if ($connectionState) { "$connectionName | $connectionState" } else { $connectionName }
        Add-GraphEdge $edges $edgeKeys $vnetId $hubId $connectionLabel Hybrid $connectionId `
            'Microsoft.Network/virtualHubs/hubVirtualNetworkConnections'
        if ($connectionId) {
            $null = $renderedConnectionIds.Add($connectionId)
            $null = $UsedResourceIds.Add($connectionId)
        }
        foreach ($expressRouteGateway in @($Index.ExpressRouteGatewaysByHubId[$hubId] | ForEach-Object { $_ })) {
            $gatewayId = ConvertTo-ResourceId (Get-ObjectValue $expressRouteGateway 'id')
            $gatewayName = [string](Get-ObjectValue $expressRouteGateway 'name' (Get-ResourceNameFromId $gatewayId))
            $scaleUnits = [string](Get-ObjectValue $expressRouteGateway 'scaleUnits' '')
            $gatewayDetails = if ($scaleUnits) { "Scale units: $scaleUnits" } else { '' }
            Add-GraphNode $nodes $UsedResourceIds $gatewayId $gatewayName ExpressRouteGateway `
                'Microsoft.Network/expressRouteGateways' "<b>$gatewayName</b><br>$gatewayDetails" External
            Add-GraphEdge $edges $edgeKeys $hubId $gatewayId 'ExpressRoute gateway' Hybrid
        }
        foreach ($firewallId in @($Index.FirewallIdsByHubId[$hubId] | ForEach-Object { $_ })) {
            if (-not $firewallId) { continue }
            $firewallRelation = $Index.FirewallRelationById[$firewallId]
            $firewallItem = $firewallRelation.Rows[0]
            $firewallName = [string](Get-ObjectValue $firewallItem 'name' (Get-ResourceNameFromId $firewallId))
            $firewallDetails = @(Get-FirewallLabelDetail $firewallItem $firewallRelation)
            Add-GraphNode $nodes $UsedResourceIds $firewallId $firewallName Firewall 'Microsoft.Network/azureFirewalls' `
                "<b>$firewallName</b><br>$($firewallDetails -join '<br>')" External '' `
                (Get-FirewallPolicyLinkAttribute $firewallItem $DetailPageIdByResourceId)
            Add-GraphEdge $edges $edgeKeys $hubId $firewallId 'hub firewall' Hybrid
        }
    }

    foreach($peering in @($Index.PeeringsByVnetId[$vnetId] | ForEach-Object { $_ })){
        $remoteId=ConvertTo-ResourceId (Get-ObjectValue $peering 'remoteVnetId');if(-not $remoteId){continue};$remoteVnet=if($Index.VnetById.ContainsKey($remoteId)){$Index.VnetById[$remoteId]}else{$null};$remoteName=if($remoteVnet){[string](Get-ObjectValue $remoteVnet 'name' (Get-ResourceNameFromId $remoteId))}else{Get-ResourceNameFromId $remoteId};$state=[string](Get-ObjectValue $peering 'state' '')
        $attributes=@{tooltip="Remote VNet: $remoteName`nState: $state"};if($PageIdByVnetId.ContainsKey($remoteId)){$attributes.link="data:page/id,$($PageIdByVnetId[$remoteId])"}
        Add-GraphNode $nodes $UsedResourceIds $remoteId $remoteName RemoteVNet 'Microsoft.Network/virtualNetworks' "<b>$remoteName</b><br>Peering: $state<br><font color='#0078d4'>Open VNet page</font>" External '' $attributes
        Add-GraphEdge $edges $edgeKeys $vnetId $remoteId ([string](Get-ObjectValue $peering 'name' 'peering')) Peering
    }

    # The subnet's own ipConfigurations and service association links name every
    # resource consuming its address space. Anything not already drawn from a
    # queried resource type is placed from that reference alone, so a subnet is
    # never shown as empty when something is actually using it.
    $occupantsBySubnetId = @{}
    foreach ($subnet in $subnets) {
        $subnetId = ConvertTo-ResourceId (Get-ObjectValue $subnet 'id')
        $occupants = @(Get-SubnetOccupant $subnet)
        $occupantsBySubnetId[$subnetId] = $occupants
        foreach ($occupant in $occupants) {
            if ($nodes.ContainsKey($occupant.Id)) { continue }
            $occupantName = Get-ResourceNameFromId $occupant.DisplayId
            $label = "<b>$occupantName</b><br><font color='#666666'>Detected from subnet reference</font>"
            Add-GraphNode $nodes $UsedResourceIds $occupant.Id $occupantName SubnetOccupant $occupant.ResourceType `
                $label Internal $subnetId @{ tooltip = $occupant.DisplayId }
        }
    }

    # Propagate subnet anchors across relationships. This aligns security and
    # connectivity resources with the subnet row they are closest to. A subnet
    # and the resources it contains keep their own anchor, so an edge to a
    # second subnet cannot pull their attachments into that subnet's row.
    $anchorCandidates = @{}
    $fixedAnchorIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($sid in $subnetIds) {
        $anchorCandidates[$sid] = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $null = $anchorCandidates[$sid].Add($sid)
        $null = $fixedAnchorIds.Add($sid)
    }
    foreach ($node in $nodes.Values) {
        if ($node.SubnetId) {
            $anchorCandidates[$node.Id] = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            $null = $anchorCandidates[$node.Id].Add($node.SubnetId)
            $null = $fixedAnchorIds.Add($node.Id)
        }
    }
    for ($pass = 0; $pass -lt 4; $pass++) {
        foreach ($edge in $edges) {
            foreach ($direction in @(@($edge.Source, $edge.Target), @($edge.Target, $edge.Source))) {
                $from = $direction[0]; $to = $direction[1]
                if (-not $anchorCandidates.ContainsKey($from) -or $fixedAnchorIds.Contains($to)) { continue }
                if (-not $anchorCandidates.ContainsKey($to)) {
                    $anchorCandidates[$to] = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                }
                foreach ($candidate in $anchorCandidates[$from]) { $null = $anchorCandidates[$to].Add($candidate) }
            }
        }
    }

    $subnetOrder = @{}
    for ($i = 0; $i -lt $subnetIds.Count; $i++) { $subnetOrder[$subnetIds[$i]] = $i }
    $anchorByNodeId = @{}
    foreach ($node in $nodes.Values) {
        if (-not $anchorCandidates.ContainsKey($node.Id)) { continue }
        $selected = @($anchorCandidates[$node.Id] | Sort-Object { $subnetOrder[$_] } | Select-Object -First 1)
        if ($selected.Count -gt 0) { $anchorByNodeId[$node.Id] = $selected[0] }
    }

    $securityNodes = @($nodes.Values | Where-Object { $_.Lane -eq 'Security' } | Sort-Object Kind, Name)
    $connectivityNodes = @($nodes.Values | Where-Object { $_.Lane -eq 'Connectivity' } | Sort-Object Kind, Name)
    $externalNodes = @($nodes.Values | Where-Object { $_.Lane -eq 'External' } | Sort-Object Kind, Name)

    # Build explicit resource rows. A NIC and its VM are treated as a unit when
    # space permits; private endpoints always receive a dedicated row.
    $internalRowsBySubnetId = @{}
    $internalRowIndexByNodeId = @{}
    foreach ($subnet in $subnets) {
        $sid = ConvertTo-ResourceId (Get-ObjectValue $subnet 'id')
        $internal = @($nodes.Values | Where-Object { $_.Lane -eq 'Internal' -and $_.SubnetId -eq $sid })
        $usedInternalIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $units = [System.Collections.Generic.List[object]]::new()

        foreach ($nic in @($internal | Where-Object Kind -eq 'NIC' | Sort-Object Name)) {
            $items = [System.Collections.Generic.List[object]]::new()
            $items.Add($nic); $null = $usedInternalIds.Add($nic.Id)
            foreach ($vm in @($internal | Where-Object Kind -eq 'VM' | Where-Object {
                $vmId = $_.Id
                @($edges | Where-Object { ($_.Source -eq $vmId -and $_.Target -eq $nic.Id) -or ($_.Target -eq $vmId -and $_.Source -eq $nic.Id) }).Count -gt 0
            } | Sort-Object Name)) {
                if ($usedInternalIds.Add($vm.Id)) { $items.Add($vm) }
            }
            $units.Add([pscustomobject]@{Items=@($items);OwnRow=$false})
        }
        foreach ($gateway in @($internal | Where-Object Kind -eq 'Gateway' | Sort-Object Name)) {
            if ($usedInternalIds.Add($gateway.Id)) {
                $units.Add([pscustomobject]@{Items=@($gateway);OwnRow=$true})
            }
        }
        foreach ($endpoint in @($internal | Where-Object Kind -eq 'PrivateEndpoint' | Sort-Object Name)) {
            if ($usedInternalIds.Add($endpoint.Id)) {
                $units.Add([pscustomobject]@{Items=@($endpoint);OwnRow=$true})
            }
        }
        foreach ($node in @($internal | Sort-Object Kind, Name)) {
            if ($usedInternalIds.Add($node.Id)) {
                $units.Add([pscustomobject]@{Items=@($node);OwnRow=$false})
            }
        }

        $rows = [System.Collections.Generic.List[object]]::new()
        $currentItems = [System.Collections.Generic.List[object]]::new()
        foreach ($unit in $units) {
            $unitItems = @($unit.Items)
            if ($unit.OwnRow) {
                if ($currentItems.Count -gt 0) {
                    $rows.Add([pscustomobject]@{Items=@($currentItems)})
                    $currentItems = [System.Collections.Generic.List[object]]::new()
                }
                $rows.Add([pscustomobject]@{Items=$unitItems})
                continue
            }
            if ($currentItems.Count -gt 0 -and ($currentItems.Count + $unitItems.Count) -gt $ResourcesPerRow) {
                $rows.Add([pscustomobject]@{Items=@($currentItems)})
                $currentItems = [System.Collections.Generic.List[object]]::new()
            }
            foreach ($item in $unitItems) {
                if ($currentItems.Count -ge $ResourcesPerRow) {
                    $rows.Add([pscustomobject]@{Items=@($currentItems)})
                    $currentItems = [System.Collections.Generic.List[object]]::new()
                }
                $currentItems.Add($item)
            }
        }
        if ($currentItems.Count -gt 0) { $rows.Add([pscustomobject]@{Items=@($currentItems)}) }
        $internalRowsBySubnetId[$sid] = @($rows)
        for ($rowIndex = 0; $rowIndex -lt $rows.Count; $rowIndex++) {
            foreach ($node in @($rows[$rowIndex].Items)) { $internalRowIndexByNodeId[$node.Id] = $rowIndex }
        }
    }

    # Find the nearest internal resource row for each side-lane node. This lets
    # an NSG, public IP, load balancer, and similar resource sit on the same
    # horizontal line as the NIC/resource it is connected to.
    $adjacentNodeIds = @{}
    foreach ($edge in $edges) {
        foreach ($pair in @(@($edge.Source,$edge.Target),@($edge.Target,$edge.Source))) {
            if (-not $adjacentNodeIds.ContainsKey($pair[0])) { $adjacentNodeIds[$pair[0]] = [System.Collections.Generic.List[string]]::new() }
            if (-not $adjacentNodeIds[$pair[0]].Contains($pair[1])) { $adjacentNodeIds[$pair[0]].Add($pair[1]) }
        }
    }
    $preferredRowByNodeId = @{}
    foreach ($sideNode in @($securityNodes + $connectivityNodes + $externalNodes)) {
        if (-not $anchorByNodeId.ContainsKey($sideNode.Id)) { continue }
        $anchor = $anchorByNodeId[$sideNode.Id]
        $visited = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $frontier = [System.Collections.Generic.List[string]]::new(); $frontier.Add($sideNode.Id); $null = $visited.Add($sideNode.Id)
        $matchedRows = [System.Collections.Generic.List[int]]::new()
        for ($depth = 0; $depth -lt 5 -and $frontier.Count -gt 0 -and $matchedRows.Count -eq 0; $depth++) {
            $next = [System.Collections.Generic.List[string]]::new()
            foreach ($candidateId in $frontier) {
                if ($internalRowIndexByNodeId.ContainsKey($candidateId) -and $nodes.ContainsKey($candidateId) -and $nodes[$candidateId].SubnetId -eq $anchor) {
                    $matchedRows.Add([int]$internalRowIndexByNodeId[$candidateId])
                }
                if ($adjacentNodeIds.ContainsKey($candidateId)) {
                    foreach ($neighborId in $adjacentNodeIds[$candidateId]) {
                        if ($visited.Add($neighborId)) { $next.Add($neighborId) }
                    }
                }
            }
            $frontier = $next
        }
        $preferredRowByNodeId[$sideNode.Id] = if ($matchedRows.Count -gt 0) { ($matchedRows | Measure-Object -Minimum).Minimum } else { 0 }
    }

    # Gateways connect from inside GatewaySubnet to nodes in the remote lane.
    # Reserve every row their orthogonal connectors can cross before placing
    # public IPs or other nodes in the intervening connectivity lane.
    $gatewayTransitSlotsBySubnetId = @{}
    $preassignedExternalSlotByNodeId = @{}
    $preassignedExternalSlotsBySubnetId = @{}
    foreach ($sid in $subnetIds) {
        $transitSlots = [System.Collections.Generic.HashSet[int]]::new()
        $externalSlots = [System.Collections.Generic.HashSet[int]]::new()
        $gateways = @($nodes.Values | Where-Object {
            $_.Kind -eq 'Gateway' -and $_.Lane -eq 'Internal' -and $_.SubnetId -eq $sid
        } | Sort-Object @{Expression={ [int]$internalRowIndexByNodeId[$_.Id] }}, Name, Id)
        foreach ($gateway in $gateways) {
            $gatewayRow = [int]$internalRowIndexByNodeId[$gateway.Id]
            $null = $transitSlots.Add($gatewayRow)
            $endpointIds = @($edges | Where-Object {
                $_.Kind -eq 'Hybrid' -and ($_.Source -eq $gateway.Id -or $_.Target -eq $gateway.Id)
            } | ForEach-Object {
                if ($_.Source -eq $gateway.Id) { $_.Target } else { $_.Source }
            } | Where-Object {
                $nodes.ContainsKey($_) -and $nodes[$_].Lane -eq 'External' -and $anchorByNodeId[$_] -eq $sid
            } | Sort-Object -Unique)
            $endpoints = @($endpointIds | ForEach-Object { $nodes[$_] } | Sort-Object Kind, Name, Id)
            foreach ($endpoint in $endpoints) {
                if ($preassignedExternalSlotByNodeId.ContainsKey($endpoint.Id)) {
                    $endpointSlot = [int]$preassignedExternalSlotByNodeId[$endpoint.Id]
                } else {
                    $endpointSlot = $gatewayRow
                    while ($externalSlots.Contains($endpointSlot)) { $endpointSlot++ }
                    $preassignedExternalSlotByNodeId[$endpoint.Id] = $endpointSlot
                    $null = $externalSlots.Add($endpointSlot)
                }
                $firstTransitSlot = [math]::Min($gatewayRow, $endpointSlot)
                $lastTransitSlot = [math]::Max($gatewayRow, $endpointSlot)
                for ($slot = $firstTransitSlot; $slot -le $lastTransitSlot; $slot++) {
                    $null = $transitSlots.Add($slot)
                }
            }
        }
        $gatewayTransitSlotsBySubnetId[$sid] = $transitSlots
        $preassignedExternalSlotsBySubnetId[$sid] = $externalSlots
    }

    $securityPlacementsBySubnetId = @{}; $connectivityPlacementsBySubnetId = @{}; $externalPlacementsBySubnetId = @{}
    foreach ($sid in $subnetIds) {
        foreach ($placementDefinition in @(
            @{Nodes=$securityNodes;Target=$securityPlacementsBySubnetId;Reserved=@()},
            @{Nodes=$connectivityNodes;Target=$connectivityPlacementsBySubnetId;Reserved=@($gatewayTransitSlotsBySubnetId[$sid])}
        )) {
            $placements = [System.Collections.Generic.List[object]]::new()
            $occupiedSlots = [System.Collections.Generic.HashSet[int]]::new()
            foreach ($reservedSlot in $placementDefinition.Reserved) { $null = $occupiedSlots.Add([int]$reservedSlot) }
            $anchoredNodes = @($placementDefinition.Nodes | Where-Object { $anchorByNodeId[$_.Id] -eq $sid } | Sort-Object @{Expression={ if ($preferredRowByNodeId.ContainsKey($_.Id)) { $preferredRowByNodeId[$_.Id] } else { 0 } }}, Kind, Name)
            foreach ($node in $anchoredNodes) {
                $slot = if ($preferredRowByNodeId.ContainsKey($node.Id)) { [int]$preferredRowByNodeId[$node.Id] } else { 0 }
                while ($occupiedSlots.Contains($slot)) { $slot++ }
                $null = $occupiedSlots.Add($slot)
                $placements.Add([pscustomobject]@{Node=$node;Slot=$slot})
            }
            $placementDefinition.Target[$sid] = @($placements)
        }
    }
    $connectivitySlotByNodeId=@{}
    foreach($sid in $subnetIds){foreach($placement in @($connectivityPlacementsBySubnetId[$sid])){$connectivitySlotByNodeId[$placement.Node.Id]=[int]$placement.Slot}}
    foreach($sid in $subnetIds){
        $placements=[System.Collections.Generic.List[object]]::new()
        $occupiedSlots=[System.Collections.Generic.HashSet[int]]::new()
        foreach($reservedSlot in @($preassignedExternalSlotsBySubnetId[$sid])){$null=$occupiedSlots.Add([int]$reservedSlot)}
        $anchoredNodes=@($externalNodes|Where-Object{$anchorByNodeId[$_.Id] -eq $sid}|Sort-Object Kind,Name)
        foreach($node in @($anchoredNodes|Where-Object{$preassignedExternalSlotByNodeId.ContainsKey($_.Id)}|Sort-Object @{Expression={$preassignedExternalSlotByNodeId[$_.Id]}},Kind,Name)){
            $placements.Add([pscustomobject]@{Node=$node;Slot=[int]$preassignedExternalSlotByNodeId[$node.Id]})
        }
        foreach($node in @($anchoredNodes|Where-Object{-not $preassignedExternalSlotByNodeId.ContainsKey($_.Id)})){
            $connectedSlots=@()
            if($adjacentNodeIds.ContainsKey($node.Id)){$connectedSlots=@($adjacentNodeIds[$node.Id]|Where-Object{$connectivitySlotByNodeId.ContainsKey($_)}|ForEach-Object{$connectivitySlotByNodeId[$_]})}
            $slot=if($connectedSlots.Count -gt 0){[int](($connectedSlots|Measure-Object -Minimum).Minimum)}elseif($preferredRowByNodeId.ContainsKey($node.Id)){[int]$preferredRowByNodeId[$node.Id]}else{0}
            while($occupiedSlots.Contains($slot)){$slot++}
            $null=$occupiedSlots.Add($slot)
            $placements.Add([pscustomobject]@{Node=$node;Slot=$slot})
        }
        $externalPlacementsBySubnetId[$sid]=@($placements)
    }

    $layouts = [System.Collections.Generic.List[object]]::new()
    $resourceNodeHeight=90
    $resourceRowPitch=106
    $subnetHeaderHeight = 116
    $subnetWidth = 900
    $currentY = 90
    foreach ($subnet in $subnets) {
        $sid = ConvertTo-ResourceId (Get-ObjectValue $subnet 'id')
        $internalRowCount = @($internalRowsBySubnetId[$sid]).Count
        $securitySlots = @($securityPlacementsBySubnetId[$sid] | ForEach-Object { $_.Slot })
        $connectivitySlots = @($connectivityPlacementsBySubnetId[$sid] | ForEach-Object { $_.Slot })
        $externalSlots = @($externalPlacementsBySubnetId[$sid] | ForEach-Object { $_.Slot })
        $lastSideSlot = -1
        if (($securitySlots + $connectivitySlots + $externalSlots).Count -gt 0) { $lastSideSlot = [int](($securitySlots + $connectivitySlots + $externalSlots | Measure-Object -Maximum).Maximum) }
        $internalHeight = $subnetHeaderHeight + 10 + ($internalRowCount * $resourceRowPitch)
        $sideHeight = $subnetHeaderHeight + 10 + (($lastSideSlot + 1) * $resourceRowPitch)
        $rowHeight = [math]::Max(220, [math]::Max($internalHeight, $sideHeight))
        $layouts.Add([pscustomobject]@{Subnet=$subnet;Id=$sid;X=25;Y=$currentY;Width=$subnetWidth;Height=$rowHeight})
        $currentY += $rowHeight + 25
    }

    $unanchoredSecurity = @($securityNodes | Where-Object { -not $anchorByNodeId.ContainsKey($_.Id) })
    $unanchoredConnectivity = @($connectivityNodes | Where-Object { -not $anchorByNodeId.ContainsKey($_.Id) })
    $unanchoredExternal = @($externalNodes | Where-Object { -not $anchorByNodeId.ContainsKey($_.Id) })
    $maximumUnanchoredCount=[math]::Max($unanchoredSecurity.Count,[math]::Max($unanchoredConnectivity.Count,$unanchoredExternal.Count))
    $unanchoredHeight = if ($maximumUnanchoredCount -gt 0) {
        55 + ($maximumUnanchoredCount * $resourceRowPitch)
    } else { 0 }
    $vnetX = 280; $vnetY = 60; $vnetWidth = 950
    $vnetHeight = [math]::Max(250, $currentY + 5)
    $laneHeight = $vnetHeight + $unanchoredHeight

    $attachedResourceCount=@($nodes.Values|Where-Object{$_.Kind -notin @('RemoteVNet','PrivateLinkTarget')}).Count
    $publicIpCount=@($nodes.Values|Where-Object Kind -eq 'PublicIP').Count
    $nsgCount=@($nodes.Values|Where-Object Kind -eq 'NSG').Count
    # A VNet without peerings has no index entry, and @($null) would count as one.
    $peeringCount=@($Index.PeeringsByVnetId[$vnetId] | Where-Object { $_ -and (Get-ObjectValue $_ 'remoteVnetId' '') }).Count
    $hybridResourceIds=[System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach($node in $nodes.Values|Where-Object{$_.Kind -in @('Gateway','RemoteGateway','LocalNetworkGateway','ExpressRouteCircuit','ExpressRouteGateway','VirtualHub')}){$null=$hybridResourceIds.Add($node.Id)}
    foreach($connectionId in $renderedConnectionIds){$null=$hybridResourceIds.Add($connectionId)}
    $hybridCount=$hybridResourceIds.Count
    $bastionCount=@($nodes.Values|Where-Object Kind -eq 'Bastion').Count
    $summary="<b>VNet inventory</b> &nbsp; Subnets: $($subnets.Count) &nbsp; | &nbsp; Attached resources: $attachedResourceCount &nbsp; | &nbsp; Public IPs: $publicIpCount &nbsp; | &nbsp; NSGs: $nsgCount &nbsp; | &nbsp; Peerings: $peeringCount &nbsp; | &nbsp; Hybrid: $hybridCount &nbsp; | &nbsp; Bastion: $bastionCount"
    Add-MxVertex $Document $root 'vnet-summary' '1' $summary `
        'rounded=1;whiteSpace=wrap;html=1;fillColor=#f8f9fa;strokeColor=#adb5bd;fontSize=10;align=left;spacingLeft=10;' `
        260 15 1580 30

    Add-MxVertex $Document $root 'security-lane' '1' '<b>Security &amp; routing</b>' `
        'swimlane;html=1;rounded=1;startSize=38;fillColor=#fffaf0;strokeColor=#d6b656;fontSize=12;' `
        20 $vnetY 220 $laneHeight
    $address = ConvertTo-DisplayList (Get-ObjectValue $Vnet 'addressPrefixes' '')
    $subscriptionLabel=if($subscriptionName){"$subscriptionName ($subscriptionId)"}else{$subscriptionId}
    $vnetLabel = "<b>$vnetName</b><br><font color='#777777'><i>Virtual network</i></font><br>$address<br><font color='#555555'>Subscription: $subscriptionLabel</font><br><font color='#666666'>RG: $(Get-ObjectValue $Vnet 'resourceGroup' '') | $(Get-ObjectValue $Vnet 'location' '')</font>"
    Add-MxVertex $Document $root 'vnet' '1' $vnetLabel `
        'swimlane;html=1;rounded=1;startSize=90;fillColor=#e6f2ff;strokeColor=#0078d4;strokeWidth=2;fontSize=12;' `
        $vnetX $vnetY $vnetWidth $vnetHeight $vnetId 'Microsoft.Network/virtualNetworks' `
        @{ tags = (Join-ShapeTag @('vnet', $vnetName)); tooltip = $vnetId }
    $connectionX = $vnetX + $vnetWidth + 40
    Add-MxVertex $Document $root 'connectivity-lane' '1' '<b>Azure connectivity</b>' `
        'swimlane;html=1;rounded=1;startSize=38;fillColor=#f2fbf5;strokeColor=#82b366;fontSize=12;' `
        $connectionX $vnetY 250 $laneHeight
    $externalX=$connectionX+290
    Add-MxVertex $Document $root 'external-lane' '1' '<b>Remote &amp; hybrid</b>' `
        'swimlane;html=1;rounded=1;startSize=38;fillColor=#f8f3fc;strokeColor=#9673a6;fontSize=12;' `
        $externalX $vnetY 280 $laneHeight

    $subnetCellById = @{}
    $resourceNumber = 0
    for ($subnetIndex = 0; $subnetIndex -lt $layouts.Count; $subnetIndex++) {
        $layout = $layouts[$subnetIndex]; $subnet = $layout.Subnet; $sid = $layout.Id
        $cell = "subnet-$($subnetIndex + 1)"; $subnetCellById[$sid] = $cell
        $prefix = ConvertTo-DisplayList (Get-ObjectValue $subnet 'addressPrefixes' '')
        if (-not $prefix) { $prefix = [string](Get-ObjectValue $subnet 'addressPrefix' '') }
        $nsgResourceId = ConvertTo-ResourceId (Get-ObjectValue $subnet 'nsgId' '')
        $routeTableResourceId = ConvertTo-ResourceId (Get-ObjectValue $subnet 'routeTableId' '')
        $natGatewayResourceId = ConvertTo-ResourceId (Get-ObjectValue $subnet 'natGatewayId' '')
        $nsgName = if($nsgResourceId){Get-ResourceNameFromId $nsgResourceId}else{'None'}
        $routeTableName = if($routeTableResourceId){Get-ResourceNameFromId $routeTableResourceId}else{'None'}
        $natGatewayName = if($natGatewayResourceId){Get-ResourceNameFromId $natGatewayResourceId}else{'None'}
        $delegationNames = Get-JsonPropertyList (Get-ObjectValue $subnet 'delegations' '') 'properties.serviceName'
        $serviceEndpointNames = Get-JsonPropertyList (Get-ObjectValue $subnet 'serviceEndpoints' '') 'service'
        if(-not$delegationNames){$delegationNames='None'};if(-not$serviceEndpointNames){$serviceEndpointNames='None'}
        # Stated positively so an empty subnet is distinguishable from a gap in
        # what the exporter enumerates.
        $occupants = @($occupantsBySubnetId[$sid])
        $occupancyReported = $null -ne (Get-ObjectValue $subnet 'ipConfigurations' $null)
        if (-not $occupancyReported) {
            # Data exported before subnet references were collected.
            $occupancyText = 'not reported'
            $occupancyColor = '#999999'
        } elseif ($occupants.Count -eq 0) {
            $occupancyText = 'none - no resource references this subnet'
            $occupancyColor = '#107c10'
        } else {
            $occupancyText = "$($occupants.Count) resource(s) referencing this subnet"
            $occupancyColor = '#666666'
        }
        $pePolicies = [string](Get-ObjectValue $subnet 'privateEndpointNetworkPolicies' 'Not reported')
        $plsPolicies = [string](Get-ObjectValue $subnet 'privateLinkServiceNetworkPolicies' 'Not reported')
        if([string]::IsNullOrWhiteSpace($pePolicies)){$pePolicies='Not reported'};if([string]::IsNullOrWhiteSpace($plsPolicies)){$plsPolicies='Not reported'}
        $label = "<b>$(Get-ObjectValue $subnet 'name' '(unnamed subnet)')</b><br><font color='#777777'><i>Subnet</i></font> &nbsp; <font color='#555555'>$prefix</font>" +
                 "<br><font color='#444444'><b>NSG:</b> $nsgName &nbsp; | &nbsp; <b>UDR:</b> $routeTableName &nbsp; | &nbsp; <b>NAT:</b> $natGatewayName</font>" +
                 "<br><font color='#555555'><b>Delegation:</b> $delegationNames &nbsp; | &nbsp; <b>Service endpoints:</b> $serviceEndpointNames</font>" +
                 "<br><font color='#666666'><b>PE policies:</b> $pePolicies &nbsp; | &nbsp; <b>PLS policies:</b> $plsPolicies</font>" +
                 "<br><font color='$occupancyColor'><b>Occupants:</b> $occupancyText</font>"
        Add-MxVertex $Document $root $cell 'vnet' $label `
            "swimlane;html=1;rounded=1;collapsible=1;startSize=$subnetHeaderHeight;fillColor=#f8fbff;strokeColor=#6c8ebf;fontSize=10;align=left;spacingLeft=8;" `
            $layout.X $layout.Y $layout.Width $layout.Height $sid 'Microsoft.Network/virtualNetworks/subnets' `
            @{ tags = (Join-ShapeTag @('subnet', (Get-ObjectValue $subnet 'name' ''))); tooltip = $sid } `
            -CollapsedHeight $subnetHeaderHeight

        $rowGap = 20; $rowLeft = 18
        $resourceWidth = [math]::Floor(($layout.Width - ($rowLeft * 2) - (($ResourcesPerRow - 1) * $rowGap)) / $ResourcesPerRow)
        $internalRows = @($internalRowsBySubnetId[$sid])
        for ($rowIndex = 0; $rowIndex -lt $internalRows.Count; $rowIndex++) {
            $rowItems = @($internalRows[$rowIndex].Items)
            for ($columnIndex = 0; $columnIndex -lt $rowItems.Count; $columnIndex++) {
                $node = $rowItems[$columnIndex]; $resourceNumber++; $node.CellId = "resource-$resourceNumber"
                $x = $rowLeft + ($columnIndex * ($resourceWidth + $rowGap)); $y = $subnetHeaderHeight + 10 + ($rowIndex * $resourceRowPitch)
                Add-MxVertex $Document $root $node.CellId $cell $node.Label (Get-AzureNodeStyle $node.Kind) `
                    $x $y $resourceWidth $resourceNodeHeight $node.Id $node.ResourceType $node.Attributes
            }
        }
    }

    # Place side-lane nodes inside the vertical band of their related subnet.
    $securityNumber = 0; $connectivityNumber = 0; $externalNumber = 0
    foreach ($layout in $layouts) {
        $sideY = $layout.Y + $subnetHeaderHeight + 10
        foreach ($placement in @($securityPlacementsBySubnetId[$layout.Id])) {
            $node = $placement.Node
            $securityNumber++; $node.CellId = "security-$securityNumber"
            Add-MxVertex $Document $root $node.CellId 'security-lane' $node.Label `
                (Get-AzureNodeStyle $node.Kind '#ffffff' '#d6b656') 12 ($sideY + ($placement.Slot * $resourceRowPitch)) 196 $resourceNodeHeight `
                $node.Id $node.ResourceType $node.Attributes
        }
        foreach ($placement in @($connectivityPlacementsBySubnetId[$layout.Id])) {
            $node = $placement.Node
            $connectivityNumber++; $node.CellId = "connectivity-$connectivityNumber"
            Add-MxVertex $Document $root $node.CellId 'connectivity-lane' $node.Label `
                (Get-AzureNodeStyle $node.Kind '#ffffff' '#82b366') 12 ($sideY + ($placement.Slot * $resourceRowPitch)) 226 $resourceNodeHeight `
                $node.Id $node.ResourceType $node.Attributes
        }
        foreach ($placement in @($externalPlacementsBySubnetId[$layout.Id])) {
            $node = $placement.Node
            $externalNumber++; $node.CellId = "external-$externalNumber"
            Add-MxVertex $Document $root $node.CellId 'external-lane' $node.Label `
                (Get-AzureNodeStyle $node.Kind '#ffffff' '#9673a6') 12 ($sideY + ($placement.Slot * $resourceRowPitch)) 256 $resourceNodeHeight `
                $node.Id $node.ResourceType $node.Attributes
        }
    }
    $unanchoredY = $vnetHeight + 45
    $i = 0
    foreach ($node in $unanchoredSecurity) {
        $securityNumber++; $node.CellId = "security-$securityNumber"
        Add-MxVertex $Document $root $node.CellId 'security-lane' $node.Label `
            (Get-AzureNodeStyle $node.Kind '#ffffff' '#d6b656') 12 ($unanchoredY + ($i * $resourceRowPitch)) 196 $resourceNodeHeight `
            $node.Id $node.ResourceType $node.Attributes
        $i++
    }
    $i = 0
    foreach ($node in $unanchoredConnectivity) {
        $connectivityNumber++; $node.CellId = "connectivity-$connectivityNumber"
        Add-MxVertex $Document $root $node.CellId 'connectivity-lane' $node.Label `
            (Get-AzureNodeStyle $node.Kind '#ffffff' '#82b366') 12 ($unanchoredY + ($i * $resourceRowPitch)) 226 $resourceNodeHeight `
            $node.Id $node.ResourceType $node.Attributes
        $i++
    }
    $i = 0
    foreach ($node in $unanchoredExternal) {
        $externalNumber++; $node.CellId = "external-$externalNumber"
        Add-MxVertex $Document $root $node.CellId 'external-lane' $node.Label `
            (Get-AzureNodeStyle $node.Kind '#ffffff' '#9673a6') 12 ($unanchoredY + ($i * $resourceRowPitch)) 256 $resourceNodeHeight `
            $node.Id $node.ResourceType $node.Attributes
        $i++
    }

    $cellById = @{$vnetId='vnet'}
    foreach ($sid in $subnetCellById.Keys) { $cellById[$sid] = $subnetCellById[$sid] }
    foreach ($node in $nodes.Values) { if ($node.CellId) { $cellById[$node.Id] = $node.CellId } }
    $renderableEdges = @($edges | Where-Object { $cellById.ContainsKey($_.Source) -and $cellById.ContainsKey($_.Target) })
    $layerIdByKind = Add-MxPageLayer $Document $root $baseCell `
        @($renderableEdges | ForEach-Object { [string]$_.Kind } | Sort-Object -Unique)
    $edgeNumber = 0; $connectorUseCount = @{}
    foreach ($edge in $renderableEdges) {
        $edgeNumber++
        $style = Get-PageConnectorStyle -Edge $edge -Nodes $nodes -SubnetIds $subnetIds -VnetId $vnetId
        $channelKey = "$($edge.Source)|$($edge.Kind)"
        $channelNumber = if ($connectorUseCount.ContainsKey($channelKey)) { [int]$connectorUseCount[$channelKey] } else { 0 }
        $connectorUseCount[$channelKey] = $channelNumber + 1
        $style += "jettySize=$([math]::Min(84, 20 + ($channelNumber * 8)));"
        # A label cannot fit cleanly in the small gap between a paired VM and
        # NIC. Their placement and connector already make the relationship
        # clear, so keep this short attachment line intentionally unlabeled.
        $displayLabel = if ($edge.Label -eq 'uses NIC') { '' } else { $edge.Label }
        $layerId = if ($layerIdByKind.ContainsKey($edge.Kind)) { [string]$layerIdByKind[$edge.Kind] } else { '1' }
        Add-MxEdge $Document $root "edge-$edgeNumber" $cellById[$edge.Source] $cellById[$edge.Target] $displayLabel $style $edge.AzureId $edge.ResourceType $edge.Attributes `
            -Parent $layerId
    }
    $legendY = $vnetY + $laneHeight + 25
    Add-PageLegend $Document $root $legendY 1820
    Set-MxPageSize $model ([math]::Max(1840, $externalX + 280)) ($legendY + 54)
}

function Get-UnmappedResources {
    param([object]$Data,[System.Collections.Generic.HashSet[string]]$UsedResourceIds)
    $definitions=@(
        @{Data='nics';Id='nicId';Name='nicName';Kind='NIC';Type='Microsoft.Network/networkInterfaces'},@{Data='virtualMachines';Id='id';Name='name';Kind='VM';Type='Microsoft.Compute/virtualMachines'},
        @{Data='virtualMachineScaleSets';Id='id';Name='name';Kind='VMSS';Type='Microsoft.Compute/virtualMachineScaleSets'},
        @{Data='publicIps';Id='id';Name='name';Kind='PublicIP';Type='Microsoft.Network/publicIPAddresses'},@{Data='publicIpPrefixes';Id='id';Name='name';Kind='PublicIPPrefix';Type='Microsoft.Network/publicIPPrefixes'},@{Data='nsgs';Id='id';Name='name';Kind='NSG';Type='Microsoft.Network/networkSecurityGroups'},
        @{Data='natGateways';Id='id';Name='name';Kind='NAT';Type='Microsoft.Network/natGateways'},@{Data='loadBalancers';Id='id';Name='name';Kind='LoadBalancer';Type='Microsoft.Network/loadBalancers'},
        @{Data='applicationGateways';Id='id';Name='name';Kind='ApplicationGateway';Type='Microsoft.Network/applicationGateways'},@{Data='firewalls';Id='id';Name='name';Kind='Firewall';Type='Microsoft.Network/azureFirewalls'},
        @{Data='privateEndpoints';Id='id';Name='name';Kind='PrivateEndpoint';Type='Microsoft.Network/privateEndpoints'},@{Data='routeTables';Id='id';Name='name';Kind='RouteTable';Type='Microsoft.Network/routeTables'},
        @{Data='virtualNetworkGateways';Id='id';Name='name';Kind='Gateway';Type='Microsoft.Network/virtualNetworkGateways'},@{Data='bastionHosts';Id='id';Name='name';Kind='Bastion';Type='Microsoft.Network/bastionHosts'},
        @{Data='localNetworkGateways';Id='id';Name='name';Kind='LocalNetworkGateway';Type='Microsoft.Network/localNetworkGateways'},@{Data='gatewayConnections';Id='id';Name='name';Kind='VPNConnection';Type='Microsoft.Network/connections'},
        @{Data='expressRouteCircuits';Id='id';Name='name';Kind='ExpressRouteCircuit';Type='Microsoft.Network/expressRouteCircuits'},@{Data='expressRouteGateways';Id='id';Name='name';Kind='ExpressRouteGateway';Type='Microsoft.Network/expressRouteGateways'},
        @{Data='virtualHubs';Id='id';Name='name';Kind='VirtualHub';Type='Microsoft.Network/virtualHubs'},@{Data='hubVirtualNetworkConnections';Id='id';Name='name';Kind='HubConnection';Type='Microsoft.Network/virtualHubs/hubVirtualNetworkConnections'}
    )
    $result=@{};foreach($definition in $definitions){foreach($row in Get-DataRows $Data $definition.Data){$id=ConvertTo-ResourceId(Get-ObjectValue $row $definition.Id);if(-not$id-or$UsedResourceIds.Contains($id)-or$result.ContainsKey($id)){continue};$name=[string](Get-ObjectValue $row $definition.Name (Get-ResourceNameFromId $id));$result[$id]=[pscustomobject]@{Id=$id;Name=$name;Kind=$definition.Kind;Type=$definition.Type;Location=[string](Get-ObjectValue $row 'location' '');ResourceGroup=[string](Get-ObjectValue $row 'resourceGroup' '')}}};return @($result.Values|Sort-Object Kind,Name)
}

function New-UnmappedDrawIoPage {
    param([System.Xml.XmlDocument]$Document,[System.Xml.XmlElement]$MxFile,[object[]]$Resources,[hashtable]$DetailPageIdByResourceId)
    if($Resources.Count-eq0){return $false};$diagram=$Document.CreateElement('diagram');Set-XmlAttribute $diagram 'id' 'unmapped-resources';Set-XmlAttribute $diagram 'name' 'Unmapped Resources';$null=$MxFile.AppendChild($diagram);$model=$Document.CreateElement('mxGraphModel');foreach($pair in ([ordered]@{dx='1422';dy='794';grid='1';gridSize='10';guides='1';tooltips='1';connect='1';arrows='1';fold='1';page='1';pageScale='1';pageWidth='1800';pageHeight='1200';math='0';shadow='0'}).GetEnumerator()){Set-XmlAttribute $model $pair.Key $pair.Value};$null=$diagram.AppendChild($model);$root=$Document.CreateElement('root');$null=$model.AppendChild($root);$null=Add-MxBaseCell $Document $root
    Add-MxVertex $Document $root 'title' '1' '<b>Unmapped Resources</b><br><font color=''#666666''>Resources that could not be associated with a VNet from Azure Resource Graph relationships.</font>' 'rounded=1;whiteSpace=wrap;html=1;fillColor=#fff2cc;strokeColor=#d6b656;fontSize=14;align=left;spacingLeft=12;' 20 20 1320 60
    $columns=4;$width=290;$height=76;$gapX=25;$gapY=20;$index=0;foreach($resource in $Resources){$x=20+(($index%$columns)*($width+$gapX));$y=110+([math]::Floor($index/$columns)*($height+$gapY));$friendlyType=Get-FriendlyResourceType $resource.Kind $resource.Type $resource.Id;$label="<b>$($resource.Name)</b><br><font color='#777777'><i>$friendlyType</i></font><br><font color='#666666'>$($resource.ResourceGroup) | $($resource.Location)</font>";$attributes=@{tooltip=$resource.Id;tags=(Join-ShapeTag @('unmapped',$resource.Kind,$resource.Name))};if($DetailPageIdByResourceId.ContainsKey($resource.Id)){$attributes.link="data:page/id,$($DetailPageIdByResourceId[$resource.Id])"};Add-MxVertex $Document $root "unmapped-$($index+1)" '1' $label (Get-AzureNodeStyle $resource.Kind '#fffdf5' '#d6b656') $x $y $width $height $resource.Id $resource.Type $attributes;$index++};$legendY=130+([math]::Ceiling($Resources.Count/[double]$columns)*($height+$gapY));Add-PageLegend $Document $root $legendY;Set-MxPageSize $model 1340 ($legendY+54);return $true
}

function New-DrawIoPageRoot {
    param(
        [System.Xml.XmlDocument]$Document,
        [System.Xml.XmlElement]$MxFile,
        [string]$Id,
        [string]$Name,
        [int]$PageWidth = 1800,
        [int]$PageHeight = 1200
    )
    $diagram=$Document.CreateElement('diagram');Set-XmlAttribute $diagram 'id' $Id;Set-XmlAttribute $diagram 'name' $Name;$null=$MxFile.AppendChild($diagram)
    $model=$Document.CreateElement('mxGraphModel')
    foreach($pair in ([ordered]@{dx='1422';dy='794';grid='1';gridSize='10';guides='1';tooltips='1';connect='1';arrows='1';fold='1';page='1';pageScale='1';pageWidth=[string]$PageWidth;pageHeight=[string]$PageHeight;math='0';shadow='0'}).GetEnumerator()){Set-XmlAttribute $model $pair.Key $pair.Value}
    $null=$diagram.AppendChild($model);$root=$Document.CreateElement('root');$null=$model.AppendChild($root)
    $baseCell=Add-MxBaseCell $Document $root
    return [pscustomobject]@{Diagram=$diagram;Model=$model;Root=$root;BaseCell=$baseCell}
}

function New-NetworkOverviewPage {
    param(
        [System.Xml.XmlDocument]$Document,
        [System.Xml.XmlElement]$MxFile,
        [object]$Data,
        [object[]]$Vnets,
        [hashtable]$PageIdByVnetId
    )
    $page=New-DrawIoPageRoot $Document $MxFile 'network-overview' 'Network Overview' 1800 1200;$root=$page.Root
    Add-MxVertex $Document $root 'overview-title' '1' '<b>Azure Network Overview</b><br><font color=''#666666''>Subscriptions, virtual networks, address spaces, regions, and peerings. Click a VNet to open its detailed page.</font>' 'rounded=1;whiteSpace=wrap;html=1;fillColor=#e6f2ff;strokeColor=#0078d4;strokeWidth=2;fontSize=15;align=left;spacingLeft=12;' 20 20 1440 65
    $subscriptionNames=@{};foreach($subscription in Get-DataRows $Data 'subscriptions'){$subscriptionNames[(ConvertTo-ResourceId(Get-ObjectValue $subscription 'subscriptionId'))]=[string](Get-ObjectValue $subscription 'subscriptionName' '')}
    $groups=@($Vnets|Sort-Object subscriptionId,name|Group-Object{ConvertTo-ResourceId(Get-ObjectValue $_ 'subscriptionId')}|Sort-Object Name);$vnetCellById=@{};$vnetPositionById=@{};$currentY=110;$subscriptionIndex=0
    foreach($group in $groups){$subscriptionIndex++;$subscriptionId=[string]$group.Name;$subscriptionName=if($subscriptionNames.ContainsKey($subscriptionId)){$subscriptionNames[$subscriptionId]}else{''};$heading=if($subscriptionName){"<b>$subscriptionName</b><br><font color='#666666'>$subscriptionId</font>"}else{"<b>Subscription</b><br><font color='#666666'>$subscriptionId</font>"};$columns=4;$rows=[math]::Ceiling($group.Count/[double]$columns);$laneHeight=65+($rows*105);$laneId="subscription-$subscriptionIndex";Add-MxVertex $Document $root $laneId '1' $heading 'swimlane;html=1;rounded=1;startSize=48;fillColor=#f8fbff;strokeColor=#6c8ebf;fontSize=11;align=left;' 20 $currentY 1440 $laneHeight '' 'Microsoft.Resources/subscriptions' @{azureSubscriptionId=$subscriptionId;tags=(Join-ShapeTag @('subscription',$subscriptionName));tooltip=$(if($subscriptionName){"$subscriptionName`n$subscriptionId"}else{$subscriptionId})}
        $i=0;foreach($vnet in @($group.Group|Sort-Object name)){$vnetId=ConvertTo-ResourceId(Get-ObjectValue $vnet 'id');$name=[string](Get-ObjectValue $vnet 'name' '(unnamed VNet)');$address=ConvertTo-DisplayList(Get-ObjectValue $vnet 'addressPrefixes' '');$location=[string](Get-ObjectValue $vnet 'location' '');$resourceGroup=[string](Get-ObjectValue $vnet 'resourceGroup' '');$cellId="overview-vnet-$subscriptionIndex-$($i+1)";$vnetCellById[$vnetId]=$cellId;$x=20+(($i%$columns)*350);$y=58+([math]::Floor($i/$columns)*105);$vnetPositionById[$vnetId]=[pscustomobject]@{X=20+$x+162;Y=$currentY+$y+41};$attributes=@{tooltip=$vnetId;tags=(Join-ShapeTag @('vnet',$name,$location))};if($PageIdByVnetId.ContainsKey($vnetId)){$attributes.link="data:page/id,$($PageIdByVnetId[$vnetId])"};$label="<b>$name</b><br><font color='#777777'><i>Virtual network</i></font><br>$address<br><font color='#666666'>$location | $resourceGroup</font>";Add-MxVertex $Document $root $cellId $laneId $label (Get-AzureNodeStyle 'VNet' '#ffffff' '#0078d4') $x $y 325 82 $vnetId 'Microsoft.Network/virtualNetworks' $attributes;$i++};$currentY+=$laneHeight+25
    }
    # Resolve which peerings actually render before drawing, so the layer that
    # holds them can be created ahead of the edges that reference it.
    $peeringPairs=[System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $renderablePeerings=[System.Collections.Generic.List[object]]::new()
    foreach($peering in Get-DataRows $Data 'vnetPeerings'){
        $source=ConvertTo-ResourceId(Get-ObjectValue $peering 'vnetId');$target=ConvertTo-ResourceId(Get-ObjectValue $peering 'remoteVnetId')
        if(-not$vnetCellById.ContainsKey($source)-or-not$vnetCellById.ContainsKey($target)){continue}
        $ordered=@($source,$target)|Sort-Object;$key="$($ordered[0])|$($ordered[1])";if(-not$peeringPairs.Add($key)){continue}
        $renderablePeerings.Add([pscustomobject]@{Peering=$peering;Source=$source;Target=$target})
    }
    $peeringKinds=@();if($renderablePeerings.Count -gt 0){$peeringKinds=@('Peering')}
    $layerIdByKind=Add-MxPageLayer $Document $root $page.BaseCell $peeringKinds
    $peeringLayerId=if($layerIdByKind.ContainsKey('Peering')){[string]$layerIdByKind['Peering']}else{'1'}
    $edgeNumber=0
    foreach($renderable in $renderablePeerings){
        $peering=$renderable.Peering;$source=$renderable.Source;$target=$renderable.Target
        $edgeNumber++;$state=[string](Get-ObjectValue $peering 'state' '')
        $sourcePosition=$vnetPositionById[$source];$targetPosition=$vnetPositionById[$target]
        $style='edgeStyle=orthogonalEdgeStyle;rounded=1;orthogonalLoop=1;jettySize=20;html=1;dashed=1;dashPattern=8 4;strokeColor=#9673a6;strokeWidth=2;fontSize=9;jumpStyle=arc;jumpSize=8;labelBackgroundColor=#ffffff;sourcePerimeterSpacing=4;targetPerimeterSpacing=4;'
        if([math]::Abs($targetPosition.X-$sourcePosition.X)-ge[math]::Abs($targetPosition.Y-$sourcePosition.Y)){
            if($targetPosition.X-ge$sourcePosition.X){$style+='exitX=1;exitY=0.5;entryX=0;entryY=0.5;'}else{$style+='exitX=0;exitY=0.5;entryX=1;entryY=0.5;'}
        }else{
            if($targetPosition.Y-ge$sourcePosition.Y){$style+='exitX=0.5;exitY=1;entryX=0.5;entryY=0;'}else{$style+='exitX=0.5;exitY=0;entryX=0.5;entryY=1;'}
        }
        $style+='exitPerimeter=1;entryPerimeter=1;'
        Add-MxEdge $Document $root "overview-peering-$edgeNumber" $vnetCellById[$source] $vnetCellById[$target] "VNet peering $state" $style -Parent $peeringLayerId
    }
    Add-MxVertex $Document $root 'overview-legend' '1' '<b>Overview legend</b><br>Click a VNet card for details. Dashed purple lines represent VNet peerings.' 'rounded=1;whiteSpace=wrap;html=1;fillColor=#f8f9fa;strokeColor=#adb5bd;fontSize=10;align=left;spacingLeft=10;' 20 ($currentY+5) 1440 48
    Set-MxPageSize $page.Model 1460 ($currentY+53)
}

function Get-JsonPropertyList {
    param([AllowNull()][object]$Json,[Parameter(Mandatory)][string]$PropertyPath)
    if($null-eq$Json-or[string]::IsNullOrWhiteSpace([string]$Json)-or[string]$Json-eq'[]'){return ''}
    $items=@(ConvertFrom-JsonCollection $Json)
    $values=[System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach($item in $items){
        $value=$item
        foreach($part in $PropertyPath.Split('.')){$value=Get-ObjectValue $value $part $null;if($null-eq$value){break}}
        foreach($entry in @($value)){if(-not[string]::IsNullOrWhiteSpace([string]$entry)){$null=$values.Add([string]$entry)}}
    }
    return (@($values|Sort-Object)-join', ')
}

function Get-CombinedPropertyValue {
    param([object]$Object,[string]$SingleName,[string]$PluralName)
    $plural=Get-ObjectValue $Object $PluralName $null
    if($null-ne$plural){$values=@($plural|ForEach-Object{[string]$_}|Where-Object{$_});if($values.Count-gt0){return $values-join', '}}
    return [string](Get-ObjectValue $Object $SingleName '')
}

function Get-SecurityRuleEndpointValue {
    param(
        [object]$Properties,
        [string]$SinglePrefixName,
        [string]$PluralPrefixName,
        [string]$ApplicationSecurityGroupName
    )

    $values = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $prefixes = Get-CombinedPropertyValue $Properties $SinglePrefixName $PluralPrefixName
    if (-not [string]::IsNullOrWhiteSpace($prefixes)) { $null = $values.Add($prefixes) }
    foreach ($applicationSecurityGroup in @((Get-ObjectValue $Properties $ApplicationSecurityGroupName @()) | ForEach-Object { $_ })) {
        $id = if ($applicationSecurityGroup -is [string]) {
            [string]$applicationSecurityGroup
        } else {
            [string](Get-ObjectValue $applicationSecurityGroup 'id' '')
        }
        if (-not [string]::IsNullOrWhiteSpace($id)) {
            $null = $values.Add("ASG: $(Get-ResourceNameFromId $id)")
        }
    }
    return ConvertTo-SecurityRuleDisplayValue (@($values | Sort-Object) -join ', ')
}

function ConvertTo-SecurityRuleDisplayValue {
    param([AllowNull()][object]$Value)

    $text = [string]$Value
    if ([string]::IsNullOrWhiteSpace($text)) { return 'Not specified' }
    if ($text -eq '*') { return 'Any' }
    return $text
}

function Add-DetailTableCell {
    param([System.Xml.XmlDocument]$Document,[System.Xml.XmlElement]$Root,[string]$Id,[string]$Value,[double]$X,[double]$Y,[double]$Width,[double]$Height,[switch]$Header,[string]$StyleOverride='',[hashtable]$Attributes)
    $style=if($StyleOverride){$StyleOverride}elseif($Header){'rounded=0;whiteSpace=wrap;html=1;fillColor=#0078d4;strokeColor=#005a9e;fontColor=#ffffff;fontStyle=1;fontSize=10;align=left;spacingLeft=6;'}else{'rounded=0;whiteSpace=wrap;html=1;fillColor=#ffffff;strokeColor=#b3b3b3;fontSize=9;align=left;spacingLeft=6;overflow=hidden;'}
    Add-MxVertex -Document $Document -Root $Root -Id $Id -Parent '1' -Value $Value -Style $style `
        -X $X -Y $Y -Width $Width -Height $Height -Attributes $Attributes
}

function Add-DetailNavigation {
    param([System.Xml.XmlDocument]$Document,[System.Xml.XmlElement]$Root)
    Add-MxVertex -Document $Document -Root $Root -Id 'overview-link' -Parent '1' -Value '&#8592; Network overview' -Style 'rounded=1;whiteSpace=wrap;html=1;fillColor=#e6f2ff;strokeColor=#0078d4;fontColor=#0078d4;fontStyle=1;' -X 20 -Y 15 -Width 220 -Height 30 -Attributes @{link='data:page/id,network-overview';tooltip='Open the network overview page'}
}

function Add-NsgRuleTable {
    param(
        [System.Xml.XmlDocument]$Document,
        [System.Xml.XmlElement]$Root,
        [object[]]$Rules,
        [string]$Direction,
        [string]$IdPrefix,
        [double]$StartY
    )
    # Match the Azure portal's scanning order while keeping both halves of the
    # source-to-destination port relationship visible.
    $columns=@(
        @{Name='Priority';Width=75},@{Name='Name';Width=210},
        @{Name='Source port';Width=110},@{Name='Destination port';Width=125},
        @{Name='Protocol';Width=85},@{Name='Source';Width=350},
        @{Name='Destination';Width=375},@{Name='Action';Width=110}
    )
    $tableWidth=0;foreach($column in $columns){$tableWidth+=$column.Width}
    $headingColor=if($Direction-eq'Inbound'){'#e6f2ff'}else{'#f3e8ff'}
    $headingStroke=if($Direction-eq'Inbound'){'#0078d4'}else{'#9673a6'}
    $customCount=@($Rules|Where-Object{-not[bool](Get-ObjectValue $_ '_isDefault' $false)}).Count
    $defaultCount=@($Rules|Where-Object{[bool](Get-ObjectValue $_ '_isDefault' $false)}).Count
    Add-MxVertex $Document $Root "$IdPrefix-heading" '1' "<b>$Direction rules</b> ($customCount custom, $defaultCount default)" "rounded=1;whiteSpace=wrap;html=1;fillColor=$headingColor;strokeColor=$headingStroke;fontSize=12;align=left;spacingLeft=8;" 20 $StartY $tableWidth 34
    $headerY=$StartY+40;$x=20;$columnX=@()
    for($i=0;$i-lt$columns.Count;$i++){$columnX+=$x;Add-DetailTableCell $Document $Root "$IdPrefix-header-$i" $columns[$i].Name $x $headerY $columns[$i].Width 34 -Header;$x+=$columns[$i].Width}
    if($Rules.Count-eq0){Add-MxVertex $Document $Root "$IdPrefix-empty" '1' "No $($Direction.ToLowerInvariant()) rules were returned." 'rounded=0;whiteSpace=wrap;html=1;fillColor=#ffffff;strokeColor=#b3b3b3;fontSize=10;' 20 ($headerY+34) $tableWidth 45;return ($headerY+99)}
    $row=0
    foreach($rule in @($Rules|Sort-Object @{Expression={[int](Get-ObjectValue (Get-ObjectValue $_ 'properties' $_) 'priority' 65000)}}, @{Expression={[string](Get-ObjectValue $_ 'name' '')}})){
        $properties=Get-ObjectValue $rule 'properties' $rule
        $access=[string](Get-ObjectValue $properties 'access' '')
        $isDefault=[bool](Get-ObjectValue $rule '_isDefault' $false)
        $ruleName=[string](Get-ObjectValue $rule 'name' '')
        if ([string]::IsNullOrWhiteSpace($ruleName)) { $ruleName = '(unnamed rule)' }
        if($isDefault){$ruleName+="<br><font color='#666666'>Default rule</font>"}
        $description = [string](Get-ObjectValue $properties 'description' '')
        $ruleAttributes = @{}
        if (-not [string]::IsNullOrWhiteSpace($description)) { $ruleAttributes.tooltip = $description }
        $values=@(
            (ConvertTo-SecurityRuleDisplayValue (Get-ObjectValue $properties 'priority' '')),$ruleName,
            (ConvertTo-SecurityRuleDisplayValue (Get-CombinedPropertyValue $properties 'sourcePortRange' 'sourcePortRanges')),
            (ConvertTo-SecurityRuleDisplayValue (Get-CombinedPropertyValue $properties 'destinationPortRange' 'destinationPortRanges')),
            (ConvertTo-SecurityRuleDisplayValue (Get-ObjectValue $properties 'protocol' '')),
            (Get-SecurityRuleEndpointValue $properties 'sourceAddressPrefix' 'sourceAddressPrefixes' 'sourceApplicationSecurityGroups'),
            (Get-SecurityRuleEndpointValue $properties 'destinationAddressPrefix' 'destinationAddressPrefixes' 'destinationApplicationSecurityGroups'),
            $(if($access-ieq'Allow'){"$([char]0x2713) ALLOW"}elseif($access-ieq'Deny'){"$([char]0x2715) DENY"}else{ConvertTo-SecurityRuleDisplayValue $access})
        )
        $y=$headerY+34+($row*54)
        for($i=0;$i-lt$columns.Count;$i++){
            if($i-eq($columns.Count-1)){
                $actionStyle=if($access-ieq'Allow'){'rounded=0;whiteSpace=wrap;html=1;fillColor=#d5e8d4;strokeColor=#82b366;fontColor=#107c10;fontStyle=1;fontSize=10;align=center;'}elseif($access-ieq'Deny'){'rounded=0;whiteSpace=wrap;html=1;fillColor=#f8cecc;strokeColor=#b85450;fontColor=#b91c1c;fontStyle=1;fontSize=10;align=center;'}else{'rounded=0;whiteSpace=wrap;html=1;fillColor=#fff2cc;strokeColor=#d6b656;fontStyle=1;fontSize=10;align=center;'}
                Add-DetailTableCell $Document $Root "$IdPrefix-rule-$row-$i" $values[$i] $columnX[$i] $y $columns[$i].Width 54 -StyleOverride $actionStyle -Attributes $ruleAttributes
            }elseif($isDefault){
                Add-DetailTableCell $Document $Root "$IdPrefix-rule-$row-$i" $values[$i] $columnX[$i] $y $columns[$i].Width 54 -StyleOverride 'rounded=0;whiteSpace=wrap;html=1;fillColor=#f2f2f2;strokeColor=#b3b3b3;fontColor=#555555;fontSize=9;align=left;spacingLeft=6;overflow=hidden;' -Attributes $ruleAttributes
            }else{
                Add-DetailTableCell $Document $Root "$IdPrefix-rule-$row-$i" $values[$i] $columnX[$i] $y $columns[$i].Width 54 -Attributes $ruleAttributes
            }
        }
        $row++
    }
    return ($headerY+34+($row*54)+20)
}

function New-NsgDetailPage {
    param([System.Xml.XmlDocument]$Document,[System.Xml.XmlElement]$MxFile,[object]$Index,[object]$Nsg,[string]$PageId,[bool]$IncludeDefaultRules = $true)
    $id=ConvertTo-ResourceId(Get-ObjectValue $Nsg 'id');$name=[string](Get-ObjectValue $Nsg 'name' (Get-ResourceNameFromId $id));$page=New-DrawIoPageRoot $Document $MxFile $PageId "NSG - $name" 1800 1200;$root=$page.Root;Add-DetailNavigation $Document $root
    $customRules=@(ConvertFrom-JsonCollection(Get-ObjectValue $Nsg 'securityRules' ''));foreach($rule in $customRules){$rule|Add-Member -NotePropertyName '_isDefault' -NotePropertyValue $false -Force}
    $defaultRules=@()
    if($IncludeDefaultRules){$defaultRules=@(ConvertFrom-JsonCollection(Get-ObjectValue $Nsg 'defaultSecurityRules' ''));foreach($rule in $defaultRules){$rule|Add-Member -NotePropertyName '_isDefault' -NotePropertyValue $true -Force}}
    $rules=@($customRules+$defaultRules)
    # A missing index entry pipes a single $null, which would render as an empty association.
    $subnetNames=@($Index.SubnetsByNsgId[$id]|Where-Object{$null-ne$_}|ForEach-Object{"Subnet: $(Get-ObjectValue $_ 'name' '')"}|Sort-Object -Unique)
    $nicNames=@($Index.NicRowsByNsgId[$id]|Where-Object{$null-ne$_}|ForEach-Object{"NIC: $(Get-ObjectValue $_ 'nicName' '')"}|Sort-Object -Unique)
    $vmssNames = @()
    if ($Index.VmssIdsByNsgId.ContainsKey($id)) {
        $vmssNames = @(@(foreach ($scaleSetIdValue in $Index.VmssIdsByNsgId[$id]) {
            $scaleSetId = [string]$scaleSetIdValue
            if ($Index.VmssRelationById.ContainsKey($scaleSetId)) {
                $vmssRelation = $Index.VmssRelationById[$scaleSetId]
                "VMSS: $(Get-ObjectValue $vmssRelation.ScaleSet 'name' '')"
            }
        }) | Sort-Object -Unique)
    }
    $associations=@($subnetNames+$nicNames+$vmssNames);if($associations.Count-eq0){$associations=@('No NIC, VMSS, or subnet associations found')}
    $title="<b>$name</b><br><font color='#666666'>Network Security Group | $(Get-ObjectValue $Nsg 'resourceGroup' '') | $(Get-ObjectValue $Nsg 'location' '')</font>";Add-MxVertex $Document $root 'detail-title' '1' $title (Get-AzureNodeStyle 'NSG' '#fffaf0' '#d6b656') 270 15 720 62 $id 'Microsoft.Network/networkSecurityGroups' @{tooltip=$id;tags=(Join-ShapeTag @('nsg','detail',$name))}
    Add-MxVertex $Document $root 'associations' '1' "<b>Associations</b><br>$($associations-join'<br>')" 'rounded=1;whiteSpace=wrap;html=1;fillColor=#f8f9fa;strokeColor=#adb5bd;fontSize=10;align=left;spacingLeft=8;verticalAlign=top;' 20 100 1440 ([math]::Max(65,35+($associations.Count*18)))
    $tableY=190+([math]::Max(0,($associations.Count-1)*18))
    $inboundRules=@($rules|Where-Object{[string](Get-ObjectValue (Get-ObjectValue $_ 'properties' $_) 'direction' '')-ieq'Inbound'})
    $outboundRules=@($rules|Where-Object{[string](Get-ObjectValue (Get-ObjectValue $_ 'properties' $_) 'direction' '')-ieq'Outbound'})
    $nextY=Add-NsgRuleTable -Document $Document -Root $root -Rules $inboundRules -Direction 'Inbound' -IdPrefix 'inbound' -StartY $tableY
    $bottomY=Add-NsgRuleTable -Document $Document -Root $root -Rules $outboundRules -Direction 'Outbound' -IdPrefix 'outbound' -StartY $nextY
    Set-MxPageSize $page.Model 1460 $bottomY
}

function New-RouteTableDetailPage {
    param([System.Xml.XmlDocument]$Document,[System.Xml.XmlElement]$MxFile,[object]$Index,[object]$RouteTable,[string]$PageId)
    # A missing index entry pipes a single $null, and single-prefix subnets report an empty
    # addressPrefixes string rather than null, so fall back to addressPrefix explicitly.
    $id=ConvertTo-ResourceId(Get-ObjectValue $RouteTable 'id');$name=[string](Get-ObjectValue $RouteTable 'name' (Get-ResourceNameFromId $id));$page=New-DrawIoPageRoot $Document $MxFile $PageId "Routes - $name" 1800 1200;$root=$page.Root;Add-DetailNavigation $Document $root;$routes=@(ConvertFrom-JsonCollection(Get-ObjectValue $RouteTable 'routes' ''))
    $associations=@($Index.SubnetsByRouteTableId[$id]|Where-Object{$null-ne$_}|ForEach-Object{
        $subnetPrefix=ConvertTo-DisplayList (Get-ObjectValue $_ 'addressPrefixes' '')
        if(-not$subnetPrefix){$subnetPrefix=[string](Get-ObjectValue $_ 'addressPrefix' '')}
        if($subnetPrefix){"Subnet: $(Get-ObjectValue $_ 'name' '') ($subnetPrefix)"}else{"Subnet: $(Get-ObjectValue $_ 'name' '')"}
    }|Sort-Object -Unique);if($associations.Count-eq0){$associations=@('No subnet associations found')}
    $title="<b>$name</b><br><font color='#666666'>Route table | $(Get-ObjectValue $RouteTable 'resourceGroup' '') | BGP propagation disabled: $(Get-ObjectValue $RouteTable 'disableBgpRoutePropagation' $false)</font>";Add-MxVertex $Document $root 'detail-title' '1' $title (Get-AzureNodeStyle 'RouteTable' '#fffaf0' '#d6b656') 270 15 720 62 $id 'Microsoft.Network/routeTables' @{tooltip=$id;tags=(Join-ShapeTag @('routetable','detail',$name))};Add-MxVertex $Document $root 'associations' '1' "<b>Associations</b><br>$($associations-join'<br>')" 'rounded=1;whiteSpace=wrap;html=1;fillColor=#f8f9fa;strokeColor=#adb5bd;fontSize=10;align=left;spacingLeft=8;verticalAlign=top;' 20 100 1200 ([math]::Max(65,35+($associations.Count*18)))
    $columns=@(@{Name='Route name';Width=340},@{Name='Address prefix';Width=300},@{Name='Next hop type';Width=260},@{Name='Next hop IP address';Width=300});$tableY=190+([math]::Max(0,($associations.Count-1)*18));$x=20;$columnX=@();for($i=0;$i-lt$columns.Count;$i++){$columnX+=$x;Add-DetailTableCell $Document $root "header-$i" $columns[$i].Name $x $tableY $columns[$i].Width 34 -Header;$x+=$columns[$i].Width}
    if($routes.Count-eq0){Add-MxVertex $Document $root 'no-routes' '1' 'No custom routes.' 'rounded=0;whiteSpace=wrap;html=1;fillColor=#ffffff;strokeColor=#b3b3b3;fontSize=10;' 20 ($tableY+34) ($x-20) 45;Set-MxPageSize $page.Model 1220 ($tableY+79);return}
    $row=0;foreach($route in @($routes|Sort-Object name)){$properties=Get-ObjectValue $route 'properties' $route;$values=@([string](Get-ObjectValue $route 'name' ''),[string](Get-ObjectValue $properties 'addressPrefix' ''),[string](Get-ObjectValue $properties 'nextHopType' ''),[string](Get-ObjectValue $properties 'nextHopIpAddress' ''));$y=$tableY+34+($row*48);for($i=0;$i-lt$columns.Count;$i++){Add-DetailTableCell $Document $root "route-$row-$i" $values[$i] $columnX[$i] $y $columns[$i].Width 48};$row++}
    Set-MxPageSize $page.Model 1220 ($tableY+34+($row*48))
}

function Get-ReachableFirewallPolicy {
    param([object]$Index,[string[]]$FirewallIds)

    # Returns the policies attached to the given firewalls plus every parent
    # policy they inherit from. Policy rows nothing refers to are ignored.
    $visited = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $pending = [System.Collections.Generic.Queue[string]]::new()
    foreach ($firewallId in @($FirewallIds | Where-Object { $_ } | Sort-Object)) {
        if (-not $Index.FirewallRelationById.ContainsKey($firewallId)) { continue }
        $policyId = ConvertTo-ResourceId (Get-ObjectValue $Index.FirewallRelationById[$firewallId].Rows[0] 'firewallPolicyId' '')
        if ($policyId -and $visited.Add($policyId)) { $pending.Enqueue($policyId) }
    }
    $policies = [System.Collections.Generic.List[object]]::new()
    while ($pending.Count -gt 0) {
        $policyId = $pending.Dequeue()
        if (-not $Index.FirewallPolicyById.ContainsKey($policyId)) { continue }
        $policy = $Index.FirewallPolicyById[$policyId]
        $policies.Add($policy)
        $basePolicyId = ConvertTo-ResourceId (Get-ObjectValue $policy 'basePolicyId' '')
        if ($basePolicyId -and $visited.Add($basePolicyId)) { $pending.Enqueue($basePolicyId) }
    }
    return @($policies | Sort-Object `
        @{Expression={ [string](Get-ObjectValue $_ 'name' '') }},
        @{Expression={ ConvertTo-ResourceId (Get-ObjectValue $_ 'id' '') }})
}

function Get-FirewallRuleEndpointItem {
    param([object]$Rule,[string[]]$ValueNames,[string]$IpGroupName)

    # Returns the individual endpoint values of a rule, IP groups by name.
    $values = [System.Collections.Generic.List[string]]::new()
    foreach ($valueName in $ValueNames) {
        foreach ($entry in @(Get-ObjectValue $Rule $valueName @())) {
            if (-not [string]::IsNullOrWhiteSpace([string]$entry)) { $values.Add([string]$entry) }
        }
    }
    foreach ($groupId in @(Get-ObjectValue $Rule $IpGroupName @())) {
        if (-not [string]::IsNullOrWhiteSpace([string]$groupId)) { $values.Add("IP group: $(Get-ResourceNameFromId ([string]$groupId))") }
    }
    return $values.ToArray()
}

function Format-DetailCellList {
    param([string[]]$Items,[double]$Width,[int]$ReservedLines = 0)

    # A detail cell has a fixed height and hides overflow. A list that would not
    # fit is cut after the last whole item that does, with the number left out
    # stated in the cell and the complete list returned for the tooltip.
    $entries = @($Items | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $fullText = $entries -join ', '
    if ($entries.Count -eq 0) {
        return [pscustomobject]@{ Text = 'Not specified'; FullText = ''; Truncated = $false }
    }
    if ($entries.Count -eq 1 -and $entries[0] -eq '*') {
        return [pscustomobject]@{ Text = 'Any'; FullText = ''; Truncated = $false }
    }
    $charactersPerLine = [math]::Max(8, [math]::Floor(($Width - 12) / 5.4))
    $capacity = [int]($charactersPerLine * [math]::Max(1, 4 - $ReservedLines) * 0.8)
    if ($fullText.Length -le $capacity) {
        return [pscustomobject]@{ Text = $fullText; FullText = $fullText; Truncated = $false }
    }
    # Room is kept for the "(+N more)" hint. The first item is always shown.
    $budget = $capacity - 12
    $shown = [System.Collections.Generic.List[string]]::new()
    $length = 0
    foreach ($entry in $entries) {
        $added = $entry.Length
        if ($shown.Count -gt 0) { $added += 2 }
        if ($shown.Count -gt 0 -and ($length + $added) -gt $budget) { break }
        $shown.Add($entry)
        $length += $added
    }
    $text = $shown -join ', '
    $hidden = $entries.Count - $shown.Count
    if ($hidden -gt 0) { $text += " (+$hidden more)" }
    return [pscustomobject]@{ Text = $text; FullText = $fullText; Truncated = $true }
}

function Add-FirewallRuleSection {
    param(
        [System.Xml.XmlDocument]$Document,
        [System.Xml.XmlElement]$Root,
        [string]$Title,
        [object[]]$Entries,
        [string]$IdPrefix,
        [double]$StartY
    )
    # Same column order as the NSG rule tables. Firewall rules have no source
    # port, and the priority shown is the collection's, within its group.
    $columns=@(
        @{Name='Priority';Width=75},@{Name='Collection';Width=170},@{Name='Name';Width=210},
        @{Name='Destination port';Width=125},@{Name='Protocol';Width=100},
        @{Name='Source';Width=290},@{Name='Destination';Width=360},@{Name='Action';Width=110}
    )
    $tableWidth=0;foreach($column in $columns){$tableWidth+=$column.Width}
    $ruleCount=@($Entries|Where-Object{$null-ne$_.Rule}).Count
    $inheritedCount=@($Entries|Where-Object{$null-ne$_.Rule-and$_.InheritedFrom}).Count
    $countText="$ruleCount";if($inheritedCount-gt0){$countText="$ruleCount, $inheritedCount inherited"}
    $inheritedCellStyle='rounded=0;whiteSpace=wrap;html=1;fillColor=#f2f2f2;strokeColor=#b3b3b3;fontColor=#555555;fontSize=9;align=left;spacingLeft=6;overflow=hidden;'
    Add-MxVertex $Document $Root "$IdPrefix-heading" '1' "<b>$Title</b> ($countText)"'rounded=1;whiteSpace=wrap;html=1;fillColor=#e6f2ff;strokeColor=#0078d4;fontSize=12;align=left;spacingLeft=8;' 20 $StartY $tableWidth 34
    $headerY=$StartY+40;$x=20;$columnX=@()
    for($i=0;$i-lt$columns.Count;$i++){$columnX+=$x;Add-DetailTableCell $Document $Root "$IdPrefix-header-$i" $columns[$i].Name $x $headerY $columns[$i].Width 34 -Header;$x+=$columns[$i].Width}
    $y=$headerY+34
    $row=0;$groupNumber=0;$currentGroupKey=$null
    foreach($entry in $Entries){
        # Rows arrive in evaluation order; a band marks each change of group.
        if($entry.GroupKey-ne$currentGroupKey){
            $currentGroupKey=$entry.GroupKey;$groupNumber++
            $groupOrigin='';if($entry.InheritedFrom){$groupOrigin=" &nbsp; | &nbsp; <b>Inherited from $($entry.InheritedFrom)</b>, evaluated before this policy's own rules"}
            Add-MxVertex $Document $Root "$IdPrefix-group-$groupNumber" '1' "<b>$($entry.GroupName)</b> &nbsp; <font color='#666666'>Rule collection group, priority $($entry.GroupPriority)$groupOrigin</font>"'rounded=0;whiteSpace=wrap;html=1;fillColor=#f2f2f2;strokeColor=#b3b3b3;fontSize=10;align=left;spacingLeft=6;' 20 $y $tableWidth 26
            $y+=26
        }
        $collection=$entry.Collection;$rule=$entry.Rule
        $ruleType=[string](Get-ObjectValue $rule 'ruleType' '')
        $action=[string](Get-ObjectValue (Get-ObjectValue $collection 'action' $null) 'type' '')
        $collectionPriority=ConvertTo-SecurityRuleDisplayValue (Get-ObjectValue $collection 'priority' '')
        $collectionName=[string](Get-ObjectValue $collection 'name' '(unnamed collection)')
        $ruleName=[string](Get-ObjectValue $rule 'name' '')
        if($null-eq$rule){$ruleName='(no rules)'}elseif([string]::IsNullOrWhiteSpace($ruleName)){$ruleName='(unnamed rule)'}
        # TLS inspection is switched on per application rule, so it is stated per rule.
        $terminateTls=Get-ObjectValue $rule 'terminateTLS' $null
        if($ruleType-eq'ApplicationRule'-and$null-ne$terminateTls){
            $ruleName+="<br><font color='#666666'>TLS inspection: $(if([bool]$terminateTls){'on'}else{'off'})</font>"
        }
        $source=Format-DetailCellList (Get-FirewallRuleEndpointItem $rule @('sourceAddresses') 'sourceIpGroups') $columns[5].Width
        $isDnat=$ruleType-eq'NatRule'
        $destinationReservedLines=0;if($isDnat){$destinationReservedLines=1}
        if($ruleType-eq'ApplicationRule'){
            $applicationProtocols=@(@(Get-ObjectValue $rule 'protocols' @())|Where-Object{$null-ne$_})
            $protocol=Format-DetailCellList @($applicationProtocols|ForEach-Object{[string](Get-ObjectValue $_ 'protocolType' '')}) $columns[4].Width
            $ports=Format-DetailCellList @($applicationProtocols|ForEach-Object{[string](Get-ObjectValue $_ 'port' '')}) $columns[3].Width
            $destination=Format-DetailCellList (Get-FirewallRuleEndpointItem $rule @('targetFqdns','fqdnTags','webCategories','targetUrls','destinationAddresses') 'destinationIpGroups') $columns[6].Width
        }else{
            $protocol=Format-DetailCellList @(Get-ObjectValue $rule 'ipProtocols' @()|ForEach-Object{[string]$_}) $columns[4].Width
            $ports=Format-DetailCellList @(Get-ObjectValue $rule 'destinationPorts' @()|ForEach-Object{[string]$_}) $columns[3].Width
            $destination=Format-DetailCellList (Get-FirewallRuleEndpointItem $rule @('destinationAddresses','destinationFqdns') 'destinationIpGroups') $columns[6].Width $destinationReservedLines
        }
        $destinationText=$destination.Text
        if($isDnat){
            $translatedTarget=[string](Get-ObjectValue $rule 'translatedAddress' '')
            if(-not$translatedTarget){$translatedTarget=[string](Get-ObjectValue $rule 'translatedFqdn' '')}
            $destinationText+="<br>&#8594; $(ConvertTo-SecurityRuleDisplayValue $translatedTarget):$(ConvertTo-SecurityRuleDisplayValue (Get-ObjectValue $rule 'translatedPort' ''))"
        }
        $actionLabel=if($action-ieq'Allow'){"$([char]0x2713) ALLOW"}elseif($action-ieq'Deny'){"$([char]0x2715) DENY"}else{(ConvertTo-SecurityRuleDisplayValue $action).ToUpperInvariant()}
        $actionStyle=if($action-ieq'Allow'){'rounded=0;whiteSpace=wrap;html=1;fillColor=#d5e8d4;strokeColor=#82b366;fontColor=#107c10;fontStyle=1;fontSize=10;align=center;'}elseif($action-ieq'Deny'){'rounded=0;whiteSpace=wrap;html=1;fillColor=#f8cecc;strokeColor=#b85450;fontColor=#b91c1c;fontStyle=1;fontSize=10;align=center;'}else{'rounded=0;whiteSpace=wrap;html=1;fillColor=#fff2cc;strokeColor=#d6b656;fontStyle=1;fontSize=10;align=center;'}
        $values=@($collectionPriority,$collectionName,$ruleName,$ports.Text,$protocol.Text,$source.Text,$destinationText,$actionLabel)
        # A shortened cell carries its complete list on hover; other cells keep the rule description.
        $fullTextByColumn=@{3=$ports;4=$protocol;5=$source;6=$destination}
        $description=[string](Get-ObjectValue $rule 'description' '')
        for($i=0;$i-lt$columns.Count;$i++){
            $cellAttributes=@{}
            if(-not[string]::IsNullOrWhiteSpace($description)){$cellAttributes.tooltip=$description}
            if($fullTextByColumn.ContainsKey($i)-and$fullTextByColumn[$i].Truncated){$cellAttributes.tooltip=$fullTextByColumn[$i].FullText}
            if($i-eq($columns.Count-1)){
                Add-DetailTableCell $Document $Root "$IdPrefix-rule-$row-$i" $values[$i] $columnX[$i] $y $columns[$i].Width 54 -StyleOverride $actionStyle -Attributes $cellAttributes
            }elseif($entry.InheritedFrom){
                Add-DetailTableCell $Document $Root "$IdPrefix-rule-$row-$i" $values[$i] $columnX[$i] $y $columns[$i].Width 54 -StyleOverride $inheritedCellStyle -Attributes $cellAttributes
            }else{
                Add-DetailTableCell $Document $Root "$IdPrefix-rule-$row-$i" $values[$i] $columnX[$i] $y $columns[$i].Width 54 -Attributes $cellAttributes
            }
        }
        $y+=54;$row++
    }
    return ($y+20)
}

function Get-FirewallPolicyRuleEntry {
    param([object]$Policy,[string]$KeyPrefix,[string]$InheritedFrom)

    # Returns one entry per rule of a policy, in group, collection, and rule
    # order. InheritedFrom names the parent policy when the entries are listed
    # on a child policy's page.
    $entries=[System.Collections.Generic.List[object]]::new()
    $groups=@(ConvertFrom-JsonCollection(Get-ObjectValue $Policy 'ruleCollectionGroups' '')|Sort-Object @{Expression={[int](Get-ObjectValue $_ 'priority' 0)}},@{Expression={[string](Get-ObjectValue $_ 'name' '')}})
    for($groupIndex=0;$groupIndex-lt$groups.Count;$groupIndex++){
        $group=$groups[$groupIndex]
        $collections=@(@(Get-ObjectValue $group 'ruleCollections' @())|Where-Object{$null-ne$_}|Sort-Object @{Expression={[int](Get-ObjectValue $_ 'priority' 0)}},@{Expression={[string](Get-ObjectValue $_ 'name' '')}})
        foreach($collection in $collections){
            $rules=@(@(Get-ObjectValue $collection 'rules' @())|Where-Object{$null-ne$_})
            # A collection without rules still gets an entry, so it is not silently absent.
            if($rules.Count-eq0){$rules=@($null)}
            foreach($rule in $rules){
                $ruleType=[string](Get-ObjectValue $rule 'ruleType' '')
                if(-not$ruleType-and[string](Get-ObjectValue $collection 'ruleCollectionType' '')-ieq'FirewallPolicyNatRuleCollection'){$ruleType='NatRule'}
                $entries.Add([pscustomobject]@{
                    Type=$ruleType;GroupKey="$KeyPrefix-group-$groupIndex"
                    GroupName=[string](Get-ObjectValue $group 'name' '(unnamed group)')
                    GroupPriority=[string](Get-ObjectValue $group 'priority' 'not set')
                    Collection=$collection;Rule=$rule;InheritedFrom=$InheritedFrom
                })
            }
        }
    }
    return $entries.ToArray()
}

function New-FirewallPolicyDetailPage {
    param([System.Xml.XmlDocument]$Document,[System.Xml.XmlElement]$MxFile,[object]$Index,[object]$Policy,[string]$PageId,[hashtable]$DetailPageIdByResourceId)
    $id=ConvertTo-ResourceId(Get-ObjectValue $Policy 'id');$name=[string](Get-ObjectValue $Policy 'name' (Get-ResourceNameFromId $id))
    $page=New-DrawIoPageRoot $Document $MxFile $PageId "Firewall policy - $name" 1800 1200;$root=$page.Root;Add-DetailNavigation $Document $root
    $pageWidth=1440
    $warningStyle='rounded=1;whiteSpace=wrap;html=1;fillColor=#fff2cc;strokeColor=#d6b656;fontColor=#7a4f01;fontSize=10;align=left;spacingLeft=8;'
    $title="<b>$name</b><br><font color='#666666'>Firewall policy | $(Get-ObjectValue $Policy 'resourceGroup' '') | $(Get-ObjectValue $Policy 'location' '')</font>"
    Add-MxVertex $Document $root 'detail-title' '1' $title (Get-AzureNodeStyle 'FirewallPolicy' '#fffaf0' '#d6b656') 270 15 720 62 $id 'Microsoft.Network/firewallPolicies' @{tooltip=$id;tags=(Join-ShapeTag @('firewallpolicy','detail',$name))}

    # Settings that were not returned are stated as such, never shown as a default.
    $notReported='Not reported'
    $tier=[string](Get-ObjectValue $Policy 'tier' '');if(-not$tier){$tier=$notReported}
    $threatIntelMode=[string](Get-ObjectValue $Policy 'threatIntelMode' '');if(-not$threatIntelMode){$threatIntelMode=$notReported}
    $state=[string](Get-ObjectValue $Policy 'provisioningState' '');if(-not$state){$state=$notReported}
    $dnsProxyValue=Get-ObjectValue $Policy 'dnsProxyEnabled' $null
    $dnsProxy=$notReported
    if($null-ne$dnsProxyValue){$dnsProxy=if([bool]$dnsProxyValue){'Enabled'}else{'Disabled'}}
    $firewallNames=@($Index.FirewallIdsByPolicyId[$id]|Where-Object{$_}|ForEach-Object{
        $firewallItem=$Index.FirewallRelationById[[string]$_].Rows[0]
        [string](Get-ObjectValue $firewallItem 'name' (Get-ResourceNameFromId ([string]$_)))
    }|Sort-Object -Unique)
    $childPolicyIds=@($Index.ChildPolicyIdsByBasePolicyId[$id]|Where-Object{$_}|ForEach-Object{[string]$_}|Sort-Object -Unique)
    $childNames=@($childPolicyIds|ForEach-Object{[string](Get-ObjectValue $Index.FirewallPolicyById[$_] 'name' (Get-ResourceNameFromId $_))})
    $basePolicyId=ConvertTo-ResourceId(Get-ObjectValue $Policy 'basePolicyId' '')
    $basePolicyName=''
    if($basePolicyId){
        $basePolicyName=Get-ResourceNameFromId $basePolicyId
        if($Index.FirewallPolicyById.ContainsKey($basePolicyId)){$basePolicyName=[string](Get-ObjectValue $Index.FirewallPolicyById[$basePolicyId] 'name' $basePolicyName)}
    }
    $dnsServersValue=Get-ObjectValue $Policy 'dnsServers' $null
    $dnsServers=$notReported
    if($null-ne$dnsServersValue){$dnsServers=ConvertTo-DisplayList $dnsServersValue;if(-not$dnsServers){$dnsServers='Azure default'}}
    $inspectionParts=@("DNS servers: $dnsServers")
    # Intrusion detection and TLS inspection exist only on Premium policies. They are
    # also listed when the tier itself is unknown, so a failed read stays visible.
    if($tier-ieq'Premium'-or$tier-eq$notReported){
        $intrusionMode=[string](Get-ObjectValue $Policy 'intrusionDetectionMode' '')
        $intrusionDetection=$notReported
        if($intrusionMode){
            $intrusionDetection=if($intrusionMode-ieq'Deny'){'Alert and deny'}else{$intrusionMode}
            $overrideCount=[int](Get-ObjectValue $Policy 'intrusionDetectionSignatureOverrides' 0)
            $bypassCount=[int](Get-ObjectValue $Policy 'intrusionDetectionBypassRules' 0)
            $intrusionExtras=@(
                $(if($overrideCount-gt0){"$overrideCount signature override(s)"}),
                $(if($bypassCount-gt0){"$bypassCount bypass rule(s)"})
            )|Where-Object{$_}
            if(@($intrusionExtras).Count-gt0){$intrusionDetection+=" ($(@($intrusionExtras)-join', '))"}
        }
        $tlsValue=Get-ObjectValue $Policy 'tlsInspectionEnabled' $null
        $tlsInspection=$notReported
        if($null-ne$tlsValue){
            $tlsInspection='Disabled'
            if([bool]$tlsValue){
                $tlsInspection='Enabled'
                $certificateName=[string](Get-ObjectValue $Policy 'tlsInspectionCertificateName' '')
                if($certificateName){$tlsInspection="Enabled (CA: $certificateName)"}
            }
        }
        $inspectionParts+="IDPS: $intrusionDetection"
        $inspectionParts+="TLS inspection: $tlsInspection"
    }else{
        $inspectionParts+="IDPS and TLS inspection: not available on the $tier tier"
    }
    $infoLines=@(
        "Tier: $tier &nbsp; | &nbsp; Threat intelligence: $threatIntelMode &nbsp; | &nbsp; DNS proxy: $dnsProxy &nbsp; | &nbsp; State: $state",
        ($inspectionParts-join' &nbsp; | &nbsp; '),
        "Directly used by firewalls: $(if($firewallNames.Count-gt0){$firewallNames-join', '}else{'none'})",
        "Inherited by policies: $(if($childNames.Count-gt0){$childNames-join', '}else{'none'})",
        "Parent policy: $(if($basePolicyName){$basePolicyName}else{'none'})"
    )
    $metadataError=[string](Get-ObjectValue $Policy 'metadataError' '')
    if($metadataError){$infoLines+="<font color='#b91c1c'><b>Policy settings could not be read:</b> $([System.Net.WebUtility]::HtmlEncode($metadataError))</font>"}
    $infoHeight=35+($infoLines.Count*18)
    Add-MxVertex $Document $root 'policy-info' '1' "<b>Policy</b><br>$($infoLines-join'<br>')" 'rounded=1;whiteSpace=wrap;html=1;fillColor=#f8f9fa;strokeColor=#adb5bd;fontSize=10;align=left;spacingLeft=8;verticalAlign=top;' 20 100 $pageWidth $infoHeight
    $nextY=100+$infoHeight+12

    # Related policies get their own link shapes, because a shape has one link.
    $relatedPolicies=@()
    if($basePolicyId-and$DetailPageIdByResourceId.ContainsKey($basePolicyId)){$relatedPolicies+=@{Label="Parent policy: $basePolicyName";Id=$basePolicyId}}
    for($i=0;$i-lt$childPolicyIds.Count;$i++){
        if($DetailPageIdByResourceId.ContainsKey($childPolicyIds[$i])){$relatedPolicies+=@{Label="Child policy: $($childNames[$i])";Id=$childPolicyIds[$i]}}
    }
    for($i=0;$i-lt$relatedPolicies.Count;$i++){
        $linkX=20+(($i%4)*355);$linkY=$nextY+([math]::Floor($i/4)*38)
        Add-MxVertex $Document $root "policy-link-$($i+1)" '1' $relatedPolicies[$i].Label 'rounded=1;whiteSpace=wrap;html=1;fillColor=#e6f2ff;strokeColor=#0078d4;fontColor=#0078d4;fontStyle=1;fontSize=10;' $linkX $linkY 340 30 '' '' @{link="data:page/id,$($DetailPageIdByResourceId[$relatedPolicies[$i].Id])";tooltip='Open firewall policy rules'}
    }
    if($relatedPolicies.Count-gt0){$nextY+=([math]::Ceiling($relatedPolicies.Count/4.0)*38)+6}

    $evaluationNote='<b>Evaluation order</b>' +
        '<br>Rules are listed as evaluated: DNAT, then network, then application, each by group and collection priority.'
    # The inheritance line only applies to a policy that has a parent.
    if($basePolicyId){$evaluationNote+='<br>Rules inherited from a parent policy come first. DNAT rules are not inherited.'}
    $evaluationNote+='<br>Traffic matching no rule is denied, except to the platform FQDNs in Azure''s built-in infrastructure rule collection. Neither is a rule in the policy.'
    Add-MxVertex $Document $root 'evaluation-note' '1' $evaluationNote 'rounded=1;whiteSpace=wrap;html=1;fillColor=#f8f9fa;strokeColor=#adb5bd;fontSize=10;align=left;spacingLeft=8;verticalAlign=top;' 20 $nextY $pageWidth 72
    $nextY+=84

    # Parent policies, topmost first, which is the order their rules are evaluated in.
    $ancestors=[System.Collections.Generic.List[object]]::new()
    $inheritanceWarnings=[System.Collections.Generic.List[string]]::new()
    $visitedPolicyIds=[System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $null=$visitedPolicyIds.Add($id)
    $ancestorId=$basePolicyId
    while($ancestorId-and$visitedPolicyIds.Add($ancestorId)){
        if(-not$Index.FirewallPolicyById.ContainsKey($ancestorId)){
            $inheritanceWarnings.Add("parent policy $(Get-ResourceNameFromId $ancestorId) is not in the collected data")
            break
        }
        $ancestor=$Index.FirewallPolicyById[$ancestorId]
        $ancestors.Insert(0,$ancestor)
        $ancestorId=ConvertTo-ResourceId(Get-ObjectValue $ancestor 'basePolicyId' '')
    }

    # One entry per rule. Inherited network and application rules come first;
    # DNAT collections are not inherited. Splitting the entries by rule type
    # afterwards keeps this order inside each section.
    $entries=[System.Collections.Generic.List[object]]::new()
    for($ancestorIndex=0;$ancestorIndex-lt$ancestors.Count;$ancestorIndex++){
        $ancestor=$ancestors[$ancestorIndex]
        $ancestorName=[string](Get-ObjectValue $ancestor 'name' (Get-ResourceNameFromId (ConvertTo-ResourceId(Get-ObjectValue $ancestor 'id' ''))))
        if([string](Get-ObjectValue $ancestor 'ruleError' '')){
            $inheritanceWarnings.Add("the rules of parent policy $ancestorName could not be read")
            continue
        }
        foreach($entry in @(Get-FirewallPolicyRuleEntry -Policy $ancestor -KeyPrefix "inherited-$ancestorIndex" -InheritedFrom $ancestorName)){
            if(@('NetworkRule','ApplicationRule')-contains$entry.Type){$entries.Add($entry)}
        }
    }
    if($inheritanceWarnings.Count-gt0){
        Add-MxVertex $Document $root 'inheritance-warning' '1' "<b>Inherited rules are incomplete:</b> $([System.Net.WebUtility]::HtmlEncode(($inheritanceWarnings-join'; ')))." $warningStyle 20 $nextY $pageWidth 45
        $nextY+=57
    }
    $ruleError=[string](Get-ObjectValue $Policy 'ruleError' '')
    $ownEntries=@()
    if($ruleError){
        Add-MxVertex $Document $root 'rule-error' '1' "<b>Rules could not be read:</b> $([System.Net.WebUtility]::HtmlEncode($ruleError))" $warningStyle 20 $nextY $pageWidth 45
        $nextY+=57
    }else{
        $ownEntries=@(Get-FirewallPolicyRuleEntry -Policy $Policy -KeyPrefix 'own' -InheritedFrom '')
        foreach($entry in $ownEntries){$entries.Add($entry)}
    }
    if(-not$ruleError-and$ownEntries.Count-eq0){
        Add-MxVertex $Document $root 'no-rules' '1' 'This policy defines no rule collections of its own.' 'rounded=0;whiteSpace=wrap;html=1;fillColor=#ffffff;strokeColor=#b3b3b3;fontSize=10;' 20 $nextY $pageWidth 45
        $nextY+=57
    }

    $sections=@(
        @{Types=@('NatRule');Title='DNAT rules';Id='section-dnat'},
        @{Types=@('NetworkRule');Title='Network rules';Id='section-network'},
        @{Types=@('ApplicationRule');Title='Application rules';Id='section-application'}
    )
    $knownTypes=@($sections|ForEach-Object{$_.Types})
    foreach($section in $sections){
        $sectionEntries=@($entries|Where-Object{$section.Types-contains$_.Type})
        if($sectionEntries.Count-eq0){continue}
        $nextY=Add-FirewallRuleSection -Document $Document -Root $root -Title $section.Title -Entries $sectionEntries -IdPrefix $section.Id -StartY $nextY
    }
    # Empty filter collections and rule types this page does not know have no
    # place in the evaluation order, so they are listed last rather than dropped.
    $otherEntries=@($entries|Where-Object{$knownTypes-notcontains$_.Type})
    if($otherEntries.Count-gt0){
        $nextY=Add-FirewallRuleSection -Document $Document -Root $root -Title 'Other collections' -Entries $otherEntries -IdPrefix 'section-other' -StartY $nextY
    }
    Set-MxPageSize $page.Model 1460 $nextY
}

#endregion Enhanced draw.io layout engine

function Export-DrawIoDocument {
    param(
        [object]$Data,
        [string]$Path,
        [bool]$IncludeRuleDetailPages = $true,
        [bool]$IncludeDefaultNsgRules = $true,
        [bool]$IncludeFirewallRules = $true,
        [ValidateRange(1,4)][int]$ResourcesPerRow = 2,
        [string[]]$VnetName,
        [string[]]$ResourceGroup,
        [string[]]$ExcludeSubscriptionId
    )

    $vnets = @((Get-ObjectValue $Data 'vnets' @()))
    if ($vnets.Count -eq 0) { throw 'No virtual networks were found in the supplied data.' }
    $isScoped = [bool]($VnetName -or $ResourceGroup -or $ExcludeSubscriptionId)
    if ($isScoped) {
        $availableVnetCount = $vnets.Count
        $vnets = @(Select-ScopedVnet -Vnets $vnets -VnetName $VnetName -ResourceGroup $ResourceGroup -ExcludeSubscriptionId $ExcludeSubscriptionId)
        if ($vnets.Count -eq 0) {
            throw 'No virtual networks matched the supplied -VnetName, -ResourceGroup, or -ExcludeSubscriptionId filters.'
        }
        Write-StatusDetail "Scope filters kept $($vnets.Count) of $availableVnetCount VNet(s)"
    }
    $networkIndex = New-NetworkDataIndex $Data
    $document = [System.Xml.XmlDocument]::new()
    $declaration = $document.CreateXmlDeclaration('1.0', 'UTF-8', $null)
    $null = $document.AppendChild($declaration)
    $mxFile = $document.CreateElement('mxfile')
    Set-XmlAttribute $mxFile 'host' 'VNetAtlas'
    Set-XmlAttribute $mxFile 'modified' ([DateTime]::UtcNow.ToString('o'))
    Set-XmlAttribute $mxFile 'agent' 'Export-VNetAtlas.ps1'
    Set-XmlAttribute $mxFile 'version' $script:VNetAtlasVersion
    Set-XmlAttribute $mxFile 'type' 'device'
    $null = $document.AppendChild($mxFile)

    $sortedVnets = @($vnets | Sort-Object subscriptionId, name)
    $pageIdByVnetId = @{}
    for ($index = 0; $index -lt $sortedVnets.Count; $index++) {
        $pageIdByVnetId[(ConvertTo-ResourceId (Get-ObjectValue $sortedVnets[$index] 'id'))] = "vnet-page-$($index + 1)"
    }
    $detailPageIdByResourceId = @{}
    $nsgs = @(Get-DataRows $Data 'nsgs' | Sort-Object name)
    $routeTables = @(Get-DataRows $Data 'routeTables' | Sort-Object name)
    $policyFirewallIds = @($networkIndex.FirewallRelationById.Keys)
    if ($isScoped) {
        # A narrowed VNet set should not still emit a detail page for every NSG,
        # route table, and firewall policy in the tenant, so keep only those the
        # scope reaches.
        $reachableIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $scopedFirewallIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($vnet in $sortedVnets) {
            $scopedVnetId = ConvertTo-ResourceId (Get-ObjectValue $vnet 'id')
            # Secured-hub firewalls have no subnet and are reached through the hub.
            foreach ($hubConnection in @($networkIndex.HubConnectionsByVnetId[$scopedVnetId])) {
                if ($null -eq $hubConnection) { continue }
                $hubId = ConvertTo-ResourceId (Get-ObjectValue $hubConnection 'virtualHubId')
                foreach ($firewallId in @($networkIndex.FirewallIdsByHubId[$hubId])) {
                    if ($firewallId) { $null = $scopedFirewallIds.Add([string]$firewallId) }
                }
            }
            foreach ($subnet in @($networkIndex.SubnetsByVnetId[$scopedVnetId])) {
                if ($null -eq $subnet) { continue }
                $subnetId = ConvertTo-ResourceId (Get-ObjectValue $subnet 'id')
                foreach ($firewallId in @($networkIndex.FirewallIdsBySubnetId[$subnetId])) {
                    if ($firewallId) { $null = $scopedFirewallIds.Add([string]$firewallId) }
                }
                $null = $reachableIds.Add((ConvertTo-ResourceId (Get-ObjectValue $subnet 'nsgId')))
                $null = $reachableIds.Add((ConvertTo-ResourceId (Get-ObjectValue $subnet 'routeTableId')))
                foreach ($nic in @($networkIndex.NicRowsBySubnetId[$subnetId])) {
                    if ($null -eq $nic) { continue }
                    $null = $reachableIds.Add((ConvertTo-ResourceId (Get-ObjectValue $nic 'nicNsgId')))
                }
                foreach ($scaleSetIdValue in @($networkIndex.VmssIdsBySubnetId[$subnetId])) {
                    $scaleSetId = [string]$scaleSetIdValue
                    if (-not $networkIndex.VmssRelationById.ContainsKey($scaleSetId)) { continue }
                    foreach ($nsgId in $networkIndex.VmssRelationById[$scaleSetId].NsgIds) { $null = $reachableIds.Add($nsgId) }
                }
            }
        }
        $nsgs = @($nsgs | Where-Object { $reachableIds.Contains((ConvertTo-ResourceId (Get-ObjectValue $_ 'id'))) })
        $routeTables = @($routeTables | Where-Object { $reachableIds.Contains((ConvertTo-ResourceId (Get-ObjectValue $_ 'id'))) })
        $policyFirewallIds = @($scopedFirewallIds)
    }
    $firewallPolicies = @()
    if ($IncludeFirewallRules) {
        $firewallPolicies = @(Get-ReachableFirewallPolicy -Index $networkIndex -FirewallIds $policyFirewallIds)
    }
    if ($IncludeRuleDetailPages) {
        for ($index = 0; $index -lt $firewallPolicies.Count; $index++) {
            $detailPageIdByResourceId[(ConvertTo-ResourceId (Get-ObjectValue $firewallPolicies[$index] 'id'))] = "fwpolicy-detail-$($index + 1)"
        }
        for ($index = 0; $index -lt $nsgs.Count; $index++) {
            $detailPageIdByResourceId[(ConvertTo-ResourceId (Get-ObjectValue $nsgs[$index] 'id'))] = "nsg-detail-$($index + 1)"
        }
        for ($index = 0; $index -lt $routeTables.Count; $index++) {
            $detailPageIdByResourceId[(ConvertTo-ResourceId (Get-ObjectValue $routeTables[$index] 'id'))] = "route-detail-$($index + 1)"
        }
    }
    $plannedDetailPages = 0
    if ($IncludeRuleDetailPages) { $plannedDetailPages = $nsgs.Count + $routeTables.Count + $firewallPolicies.Count }
    $plannedPages = 1 + $sortedVnets.Count + $plannedDetailPages
    $builtPages = 0
    Write-StatusProgress 'Building diagram pages' 'Network overview' $builtPages $plannedPages
    # The overview follows the scope filters so it never lists VNets without a page.
    New-NetworkOverviewPage -Document $document -MxFile $mxFile -Data $Data -Vnets $sortedVnets -PageIdByVnetId $pageIdByVnetId
    $builtPages++
    $usedResourceIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $page = 0
    foreach ($vnet in $sortedVnets) {
        $page++
        Write-StatusProgress 'Building diagram pages' "VNet $page of $($sortedVnets.Count): $(Get-ObjectValue $vnet 'name' '')" $builtPages $plannedPages
        $builtPages++
        New-EnhancedDrawIoPage -Document $document -MxFile $mxFile -Data $Data -Index $networkIndex -Vnet $vnet `
            -PageIdByVnetId $pageIdByVnetId -DetailPageIdByResourceId $detailPageIdByResourceId `
            -UsedResourceIds $usedResourceIds -ResourcesPerRow $ResourcesPerRow
    }
    $detailPages = 0
    if ($IncludeRuleDetailPages) {
        foreach ($nsg in $nsgs) {
            $id = ConvertTo-ResourceId (Get-ObjectValue $nsg 'id')
            Write-StatusProgress 'Building diagram pages' "NSG detail: $(Get-ObjectValue $nsg 'name' '')" $builtPages $plannedPages
            New-NsgDetailPage -Document $document -MxFile $mxFile -Index $networkIndex -Nsg $nsg -PageId $detailPageIdByResourceId[$id] -IncludeDefaultRules $IncludeDefaultNsgRules
            $detailPages++; $builtPages++
        }
        foreach ($routeTable in $routeTables) {
            $id = ConvertTo-ResourceId (Get-ObjectValue $routeTable 'id')
            Write-StatusProgress 'Building diagram pages' "Route table detail: $(Get-ObjectValue $routeTable 'name' '')" $builtPages $plannedPages
            New-RouteTableDetailPage -Document $document -MxFile $mxFile -Index $networkIndex -RouteTable $routeTable -PageId $detailPageIdByResourceId[$id]
            $detailPages++; $builtPages++
        }
        foreach ($firewallPolicy in $firewallPolicies) {
            $id = ConvertTo-ResourceId (Get-ObjectValue $firewallPolicy 'id')
            Write-StatusProgress 'Building diagram pages' "Firewall policy detail: $(Get-ObjectValue $firewallPolicy 'name' '')" $builtPages $plannedPages
            New-FirewallPolicyDetailPage -Document $document -MxFile $mxFile -Index $networkIndex -Policy $firewallPolicy `
                -PageId $detailPageIdByResourceId[$id] -DetailPageIdByResourceId $detailPageIdByResourceId
            $detailPages++; $builtPages++
        }
    }
    # With a scope filter active, "unmapped" would read as "outside the VNets you
    # selected", which is not what the page means. Skip it rather than mislead.
    $unmappedResources = @()
    if (-not $isScoped) { $unmappedResources = @(Get-UnmappedResources -Data $Data -UsedResourceIds $usedResourceIds) }
    $hasUnmappedPage = New-UnmappedDrawIoPage -Document $document -MxFile $mxFile -Resources $unmappedResources -DetailPageIdByResourceId $detailPageIdByResourceId
    $totalPages = 1 + $page + $detailPages + $(if ($hasUnmappedPage) { 1 } else { 0 })

    $resolvedPath = Resolve-LocalFilePath $Path
    $directory = [System.IO.Path]::GetDirectoryName($resolvedPath)
    if (-not [System.IO.Directory]::Exists($directory)) {
        $null = [System.IO.Directory]::CreateDirectory($directory)
    }
    $settings = [System.Xml.XmlWriterSettings]::new()
    $settings.Indent = $true
    $settings.Encoding = [System.Text.UTF8Encoding]::new($false)
    Complete-StatusProgress 'Building diagram pages'
    $pageBreakdown = "1 overview + $page VNet + $detailPages detail"
    if ($hasUnmappedPage) { $pageBreakdown += ' + 1 unmapped' }
    Write-StatusDetail "$pageBreakdown = $totalPages pages"

    Write-StatusStep 3 3 "Writing $([System.IO.Path]::GetFileName($resolvedPath))"
    $writer = [System.Xml.XmlWriter]::Create($resolvedPath, $settings)
    try { $document.Save($writer) } finally { $writer.Dispose() }
    Write-StatusDetail "$totalPages pages, $(Format-FileSize ([System.IO.FileInfo]::new($resolvedPath).Length))"
    return [pscustomobject]@{
        Path=$resolvedPath; Subscriptions=@(Get-DataRows $Data 'subscriptions').Count; VnetPages=$page; DetailPages=$detailPages; TotalPages=$totalPages; UnmappedResources=$unmappedResources.Count
    }
}

if ($PSCmdlet.ParameterSetName -eq 'Version') {
    Write-Output "VNetAtlas $script:VNetAtlasVersion"
    return
}
if ($PSCmdlet.ParameterSetName -eq 'Help') {
    Show-VNetAtlasHelp
    return
}

$runTimer = [System.Diagnostics.Stopwatch]::StartNew()
Write-StatusMessage ''
Write-StatusBanner

try {
    if ($PSCmdlet.ParameterSetName -eq 'Input') {
        Write-StatusStep 1 3 'Reading exported network data'
        $resolvedInput = (Resolve-Path -LiteralPath $InputDataPath).Path
        $networkData = Get-Content -LiteralPath $resolvedInput -Raw | ConvertFrom-Json
        Write-StatusDetail $resolvedInput
    } else {
        Write-StatusStep 1 3 'Querying Azure Resource Graph'
        $networkData = Get-AzureNetworkData -Subscriptions $SubscriptionId -RequestedTenantId $TenantId `
            -SkipFirewallRules:$SkipFirewallRules
        if ($ExportDataPath) {
            $resolvedExport = Resolve-LocalFilePath $ExportDataPath
            $exportDirectory = [System.IO.Path]::GetDirectoryName($resolvedExport)
            if (-not [System.IO.Directory]::Exists($exportDirectory)) {
                $null = [System.IO.Directory]::CreateDirectory($exportDirectory)
            }
            $json = $networkData | ConvertTo-Json -Depth 12
            [System.IO.File]::WriteAllText($resolvedExport, $json, [System.Text.UTF8Encoding]::new($false))
            Write-Verbose "Exported normalized Azure data to $resolvedExport"
            Write-StatusDetail "Exported query data to $resolvedExport"
        }
    }

    Write-StatusStep 2 3 'Building diagram pages'
    $result = Export-DrawIoDocument -Data $networkData -Path $OutputPath `
        -IncludeRuleDetailPages (-not $SkipRuleDetailPages.IsPresent) `
        -IncludeDefaultNsgRules (-not $SkipDefaultNsgRules.IsPresent) `
        -IncludeFirewallRules (-not $SkipFirewallRules.IsPresent) `
        -ResourcesPerRow $ResourcesPerRow `
        -VnetName $VnetName -ResourceGroup $ResourceGroup -ExcludeSubscriptionId $ExcludeSubscriptionId
    $runTimer.Stop()
    Write-StatusMessage ''
    Write-StatusMessage "Done in $(Format-ElapsedTime $runTimer.Elapsed)" 'Green'
    Write-StatusMessage ''
    Write-Output "Created $($result.Path) from $($result.Subscriptions) subscription(s), with 1 overview, $($result.VnetPages) VNet page(s), $($result.DetailPages) detail page(s), $($result.UnmappedResources) unmapped resource(s), and $($result.TotalPages) total page(s)."
}
catch {
    Complete-StatusProgress 'Querying Azure Resource Graph'
    Complete-StatusProgress 'Reading firewall policies'
    Complete-StatusProgress 'Building diagram pages'
    if ($runTimer.IsRunning) { $runTimer.Stop() }

    $errorLines = @(([string]$_.Exception.Message -split "`r?`n") | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($errorLines.Count -eq 0) { $errorLines = @('An unexpected error occurred.') }
    [Console]::Error.WriteLine("ERROR: $($errorLines[0])")
    for ($lineIndex = 1; $lineIndex -lt $errorLines.Count; $lineIndex++) {
        [Console]::Error.WriteLine("       $($errorLines[$lineIndex])")
    }
    exit 1
}
