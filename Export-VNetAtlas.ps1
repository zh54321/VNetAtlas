<#
.SYNOPSIS
    Maps Azure virtual networks into a multi-page draw.io atlas.

.DESCRIPTION
    VNetAtlas inventories Azure networking resources through Azure Resource Graph and
    writes one .drawio file containing a network overview page grouped by subscription,
    a Network Ranges page listing public IP addresses, connected ranges, and subnet
    prefixes, one page per virtual network showing its subnets and the resources inside
    them, detail pages for each network security group and route table, and an Unmapped
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
    Azure. Required for the Input parameter set. The diagram shows when that data was
    collected, not when it was rebuilt.

.PARAMETER ExportDataPath
    Also write the normalized query results to this path as JSON, so the same diagram can
    be regenerated offline. The JSON records when the data was collected.

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

.PARAMETER SkipNetworkRanges
    Omit the Network Ranges page and its link on the network overview. -ExportRangesPath
    still writes the ranges as CSV.

.PARAMETER SkipUnmappedResources
    Omit the Unmapped Resources page.

.PARAMETER SkipCredit
    Omit the "Created with VNetAtlas" line from the network overview legend.

.PARAMETER ResourcesPerRow
    How many resources may share a line inside a subnet, 1 to 4. Lower values make pages
    taller but reduce connector overlap. A NIC and its VM stay together where the value
    permits; a private endpoint always takes its own line.

.PARAMETER OutputPath
    Target .drawio file. Relative paths resolve against the current location. Defaults to
    a timestamped name such as 20260901_1025_Azure-Network.drawio.

.PARAMETER ExportRangesPath
    Also write the Network Ranges tables to this path as CSV, one row per prefix or
    address, for use as a scan scope. The rows follow the same scope filters as the page.

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
    .\Export-VNetAtlas.ps1 -ExportRangesPath .\ranges.csv
    Import-Csv .\ranges.csv | Where-Object Category -eq 'Subnet' | ForEach-Object Range

    Also write the Network Ranges tables as CSV, then list the subnet prefixes in use,
    one per line, as input for a scanner.

.EXAMPLE
    $result = .\Export-VNetAtlas.ps1 -SubscriptionId '00000000-0000-0000-0000-000000000001' -Quiet

    Query one subscription with progress output suppressed. $result receives the summary
    line only.

.NOTES
    Runs on Windows PowerShell 5.1 and PowerShell 7 or later.

    Every generated file records its origin on the root mxfile element as
    host="VNetAtlas", agent="Export-VNetAtlas.ps1" and version="<exporter version>".
    draw.io replaces these attributes when it saves the file, so the Network Overview
    page also shows the tool name, version, and project link in its legend, unless
    -SkipCredit is used.

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
    [switch]$SkipNetworkRanges,

    [Parameter(ParameterSetName = 'Azure')]
    [Parameter(ParameterSetName = 'Input')]
    [switch]$SkipUnmappedResources,

    [Parameter(ParameterSetName = 'Azure')]
    [Parameter(ParameterSetName = 'Input')]
    [switch]$SkipCredit,

    [Parameter(ParameterSetName = 'Azure')]
    [Parameter(ParameterSetName = 'Input')]
    [ValidateRange(1,4)]
    [int]$ResourcesPerRow = 2,

    [Parameter(ParameterSetName = 'Azure')]
    [Parameter(ParameterSetName = 'Input')]
    [string]$OutputPath = ".\$(Get-Date -Format 'yyyyMMdd_HHmm')_Azure-Network.drawio",

    [Parameter(ParameterSetName = 'Azure')]
    [Parameter(ParameterSetName = 'Input')]
    [string]$ExportRangesPath,

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
$script:VNetAtlasVersion = 'V20261026'

# Linked from the credit on the Network Overview page.
$script:VNetAtlasProjectUrl = 'https://github.com/zh54321/VNetAtlas'

# API version for every direct Azure Resource Manager read of firewall policy data.
$script:FirewallPolicyApiVersion = '2024-05-01'

# API version for the direct Azure Resource Manager read of Virtual WAN hub connections.
$script:VirtualHubApiVersion = '2024-05-01'

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
  -ExportRangesPath <file>       Also save the Network Ranges tables as CSV.
  -ResourcesPerRow <1-4>         Resources per line inside a subnet. Default: 2.
  -SkipRuleDetailPages           Omit the NSG, route-table, and firewall-policy detail pages.
  -SkipFirewallRules             Do not read firewall policy rules or build their pages.
  -SkipDefaultNsgRules           Omit Azure's built-in default rules from NSG pages.
  -SkipNetworkRanges             Omit the Network Ranges page. -ExportRangesPath still works.
  -SkipUnmappedResources         Omit the Unmapped Resources page.
  -SkipCredit                    Omit the "Created with VNetAtlas" line from the overview.
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

function Format-InvariantNumber {
    param([double]$Value, [string]$Format = 'N0')

    # Diagram text must not depend on the current culture, or output would differ
    # between machines.
    return $Value.ToString($Format, [System.Globalization.CultureInfo]::InvariantCulture)
}

function Get-AddressPrefixInfo {
    param([AllowNull()][string]$Prefix)

    # Accepts a CIDR prefix or a bare address. Start orders IPv4 ranges numerically;
    # IPv6 is recognized but not sized, because no table reports IPv6 address counts.
    $text = ([string]$Prefix).Trim()
    $info = [pscustomobject]@{ Text=$text; IsValid=$false; IsIPv4=$false; IpVersion=''; Start=[long]0; Length=-1; Size=[long]0 }
    if (-not $text) { return $info }
    $parts = $text.Split('/')
    if ($parts.Count -gt 2) { return $info }
    $length = -1
    if ($parts.Count -eq 2) {
        $parsedLength = 0
        if (-not [int]::TryParse($parts[1], [ref]$parsedLength) -or $parsedLength -lt 0) { return $info }
        $length = $parsedLength
    }
    $address = $null
    if ($parts[0] -match '^\d{1,3}(\.\d{1,3}){3}$') {
        if (-not [System.Net.IPAddress]::TryParse($parts[0], [ref]$address)) { return $info }
        if ($length -lt 0) { $length = 32 }
        if ($length -gt 32) { return $info }
        $bytes = $address.GetAddressBytes()
        $info.Start = ([long]$bytes[0] -shl 24) + ([long]$bytes[1] -shl 16) + ([long]$bytes[2] -shl 8) + [long]$bytes[3]
        $info.Size = [long]1 -shl (32 - $length)
        $info.IsIPv4 = $true
        $info.IpVersion = 'IPv4'
    } elseif ($parts[0].Contains(':')) {
        if (-not [System.Net.IPAddress]::TryParse($parts[0], [ref]$address)) { return $info }
        if ($length -lt 0) { $length = 128 }
        if ($length -gt 128) { return $info }
        $info.IpVersion = 'IPv6'
    } else {
        return $info
    }
    $info.IsValid = $true
    $info.Length = $length
    return $info
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

function Format-CollectedAt {
    param([AllowNull()][object]$Value)

    # Windows PowerShell reads the ISO timestamp from JSON as text, PowerShell 7 as a
    # DateTime, so both are accepted and rendered the same way. Returns '' for data
    # exported before the collection time was recorded.
    if ($null -eq $Value) { return '' }
    if ($Value -is [datetime]) {
        $moment = if ($Value.Kind -eq [System.DateTimeKind]::Local) { $Value.ToUniversalTime() } else { $Value }
    } else {
        $moment = [datetime]::MinValue
        $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
        if (-not [datetime]::TryParse([string]$Value, [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$moment)) { return '' }
    }
    return $moment.ToString('yyyy-MM-dd HH:mm', [System.Globalization.CultureInfo]::InvariantCulture) + ' UTC'
}

function ConvertTo-NullableBoolean {
    param([AllowNull()][object]$Value)

    # Resource Graph returns tobool() columns as 1 or 0, while the sample data and
    # hand-edited JSON use true or false. Returns $null when the value is missing or
    # not recognized, so callers can tell "off" from "not collected".
    if ($null -eq $Value) { return $null }
    if ($Value -is [bool]) { return $Value }
    $text = ([string]$Value).Trim()
    if ($text -eq 'true' -or $text -eq '1') { return $true }
    if ($text -eq 'false' -or $text -eq '0') { return $false }
    return $null
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

function Get-HubConnectionData {
    param([object[]]$HubRows)

    # Resource Graph does not index a Virtual WAN hub's VNet connections, so each hub's list
    # is read from ARM and shaped like the other query rows. A hub whose list cannot be read
    # is reported and contributes no connections.
    $rows = [System.Collections.Generic.List[object]]::new()
    $requestCount = 0
    $hubIds = @($HubRows | ForEach-Object { ConvertTo-ResourceId (Get-ObjectValue $_ 'id' '') } | Where-Object { $_ } | Sort-Object -Unique)
    for ($hubIndex = 0; $hubIndex -lt $hubIds.Count; $hubIndex++) {
        $hubId = $hubIds[$hubIndex]
        $hubName = Get-ResourceNameFromId $hubId
        Write-StatusProgress 'Reading Virtual WAN hub connections' $hubName $hubIndex $hubIds.Count
        $connections = [System.Collections.Generic.List[object]]::new()
        $readError = ''
        $visitedLinks = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
        $target = "${hubId}/hubVirtualNetworkConnections?api-version=$script:VirtualHubApiVersion"
        while ($target) {
            if (-not $visitedLinks.Add($target)) {
                $readError = 'Pagination returned a repeated link'
                break
            }
            $page = Invoke-ArmGetRequest $target
            $requestCount++
            if ($page.Error) {
                $readError = $page.Error
                break
            }
            foreach ($connection in @(Get-ObjectValue $page.Content 'value' @())) {
                if ($null -ne $connection) { $connections.Add($connection) }
            }
            $target = [string](Get-ObjectValue $page.Content 'nextLink' '')
        }
        if ($readError) {
            Write-Warning "Virtual WAN hub '$hubName': VNet connections could not be read ($readError)."
            continue
        }
        foreach ($connection in $connections) {
            $rawId = [string](Get-ObjectValue $connection 'id' '')
            $properties = Get-ObjectValue $connection 'properties' $null
            $routing = Get-ObjectValue $properties 'routingConfiguration' $null
            $rows.Add([pscustomobject]@{
                id = ConvertTo-ResourceId $rawId
                name = [string](Get-ObjectValue $connection 'name' (Get-ResourceNameFromId $rawId))
                resourceGroup = $(if ($rawId -match '/resourceGroups/([^/]+)/') { $Matches[1] } else { '' })
                subscriptionId = $(if ($rawId -match '^/subscriptions/([^/]+)/') { $Matches[1] } else { '' })
                virtualHubId = $hubId
                remoteVnetId = ConvertTo-ResourceId (Get-ObjectValue (Get-ObjectValue $properties 'remoteVirtualNetwork' $null) 'id' '')
                provisioningState = [string](Get-ObjectValue $properties 'provisioningState' '')
                routingConfiguration = $(if ($null -ne $routing) { $routing | ConvertTo-Json -Depth 20 -Compress } else { '' })
            })
        }
    }
    Complete-StatusProgress 'Reading Virtual WAN hub connections'
    return [pscustomobject]@{ Rows = $rows.ToArray(); RequestCount = $requestCount }
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

function Get-EnabledAzSubscription {
    param([string]$TenantId)

    # An expired or MFA-blocked sign-in does not fail here: Az writes a warning and
    # returns no subscriptions, which would otherwise read as an empty tenant.
    $azWarnings = $null
    $subscriptions = @(Get-AzSubscription -TenantId $TenantId -ErrorAction Stop -WarningAction SilentlyContinue -WarningVariable azWarnings |
        Where-Object { -not $_.State -or $_.State -eq 'Enabled' })
    foreach ($warning in @($azWarnings)) { Write-Verbose "Get-AzSubscription: $warning" }
    $signInFailed = $subscriptions.Count -eq 0 -and
        @($azWarnings | Where-Object { [string]$_ -match 'acquire token|interaction is required|Authentication failed|AADSTS' }).Count -gt 0
    return [pscustomobject]@{ Subscriptions=$subscriptions; SignInFailed=$signInFailed }
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
    $subscriptionLookup = Get-EnabledAzSubscription -TenantId $tenantId
    if ($subscriptionLookup.SignInFailed) {
        # Renew the sign-in once, the same way a run without any sign-in starts.
        Write-StatusDetail "Azure sign-in for tenant $tenantId expired or needs MFA; signing in again"
        $null = Connect-AzAccount -Tenant $tenantId
        $subscriptionLookup = Get-EnabledAzSubscription -TenantId $tenantId
        if ($subscriptionLookup.SignInFailed) {
            throw "Azure sign-in for tenant '$tenantId' failed, so no subscriptions could be read.`nRun 'Connect-AzAccount -TenantId $tenantId' and try again. Use -Verbose to see the message from Azure."
        }
    }
    $availableSubscriptions = @($subscriptionLookup.Subscriptions)
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
          allowVirtualNetworkAccess=tobool(peering.properties.allowVirtualNetworkAccess),
          allowForwardedTraffic=tobool(peering.properties.allowForwardedTraffic),
          allowGatewayTransit=tobool(peering.properties.allowGatewayTransit),
          useRemoteGateways=tobool(peering.properties.useRemoteGateways),
          peerCompleteVnets=tobool(peering.properties.peerCompleteVnets),
          localSubnetNames=tostring(peering.properties.localSubnetNames),
          remoteSubnetNames=tostring(peering.properties.remoteSubnetNames),
          peeringSyncLevel=tostring(peering.properties.peeringSyncLevel),
          localPeeredAddressPrefixes=tostring(peering.properties.localAddressSpace.addressPrefixes),
          peeredAddressPrefixes=tostring(peering.properties.remoteAddressSpace.addressPrefixes),
          remoteAddressPrefixes=tostring(peering.properties.remoteVirtualNetworkAddressSpace.addressPrefixes),
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
          privateIpAddress=tostring(frontend.properties.privateIPAddress),
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
          vpnClientAddressPrefixes=tostring(properties.vpnClientConfiguration.vpnClientAddressPool.addressPrefixes),
          vpnClientConnectionConfigurations=tostring(properties.vpnClientConfiguration.vngClientConnectionConfigurations),
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
        # Only the circuit reference and state are read from each connection, so its
        # authorization key is never part of the result.
        expressRouteGateways = @'
Resources
| where type =~ 'microsoft.network/expressroutegateways'
| extend gatewayConnections=iff(array_length(properties.expressRouteConnections) > 0,
                                properties.expressRouteConnections, dynamic([{}]))
| mv-expand connection=gatewayConnections limit 2000
| project id=tolower(id), name, resourceGroup, subscriptionId, location,
          virtualHubId=tolower(tostring(properties.virtualHub.id)),
          scaleUnits=toint(properties.autoScaleConfiguration.bounds.max),
          connectionName=tostring(connection.name),
          circuitPeeringId=tolower(tostring(connection.properties.expressRouteCircuitPeering.id)),
          connectionState=tostring(connection.properties.provisioningState)
| order by id asc, connectionName asc
'@
        virtualHubs = @'
Resources
| where type =~ 'microsoft.network/virtualhubs'
| project id=tolower(id), name, resourceGroup, subscriptionId, location,
          virtualWanId=tolower(tostring(properties.virtualWan.id)),
          addressPrefix=tostring(properties.addressPrefix),
          virtualRouterAsn=tostring(properties.virtualRouterAsn),
          virtualRouterIps=tostring(properties.virtualRouterIps),
          provisioningState=tostring(properties.provisioningState)
| order by id asc
'@
        p2sVpnGateways = @'
Resources
| where type =~ 'microsoft.network/p2svpngateways'
| project id=tolower(id), name, resourceGroup, subscriptionId, location,
          virtualHubId=tolower(tostring(properties.virtualHub.id)),
          connectionConfigurations=tostring(properties.p2SConnectionConfigurations),
          scaleUnits=toint(properties.vpnGatewayScaleUnit),
          provisioningState=tostring(properties.provisioningState)
| order by id asc
'@
        vpnSites = @'
Resources
| where type =~ 'microsoft.network/vpnsites'
| project id=tolower(id), name, resourceGroup, subscriptionId, location,
          virtualWanId=tolower(tostring(properties.virtualWan.id)),
          addressPrefixes=tostring(properties.addressSpace.addressPrefixes),
          ipAddress=tostring(properties.ipAddress),
          bgpAsn=tostring(properties.bgpProperties.asn),
          bgpPeeringAddress=tostring(properties.bgpProperties.bgpPeeringAddress),
          siteLinks=tostring(properties.vpnSiteLinks),
          deviceVendor=tostring(properties.deviceProperties.deviceVendor),
          provisioningState=tostring(properties.provisioningState)
| order by id asc
'@
        # Only the site reference is read from each connection, so connection
        # secrets are never part of the result.
        vpnGateways = @'
Resources
| where type =~ 'microsoft.network/vpngateways'
| extend gatewayConnections=iff(array_length(properties.connections) > 0,
                                properties.connections, dynamic([{}]))
| mv-expand connection=gatewayConnections limit 2000
| project id=tolower(id), name, resourceGroup, subscriptionId, location,
          virtualHubId=tolower(tostring(properties.virtualHub.id)),
          ipConfigurations=tostring(properties.ipConfigurations),
          bgpAsn=tostring(properties.bgpSettings.asn),
          scaleUnits=toint(properties.vpnGatewayScaleUnit),
          connectionName=tostring(connection.name),
          remoteVpnSiteId=tolower(tostring(connection.properties.remoteVpnSite.id)),
          connectionStatus=tostring(connection.properties.connectionStatus),
          provisioningState=tostring(properties.provisioningState)
| order by id asc, connectionName asc
'@
    }

    $queryNames = @(
        'subscriptions', 'vnets', 'subnets', 'nics', 'publicIps', 'publicIpPrefixes', 'nsgs', 'natGateways', 'virtualMachines',
        'virtualMachineScaleSets',
        'vnetPeerings', 'loadBalancers', 'applicationGateways', 'firewalls', 'privateEndpoints',
        'routeTables', 'virtualNetworkGateways', 'bastionHosts', 'localNetworkGateways',
        'gatewayConnections', 'expressRouteCircuits', 'expressRouteGateways', 'virtualHubs',
        'p2sVpnGateways', 'vpnSites', 'vpnGateways'
    )
    # Column identifying the expanded resource in each query that uses mv-expand.
    $expandParentPropertyByQuery = @{
        subnets = 'vnetId'; nics = 'nicId'; virtualMachines = 'id'; vnetPeerings = 'vnetId'
        loadBalancers = 'id'; firewalls = 'id'; privateEndpoints = 'id'; vpnGateways = 'id'; expressRouteGateways = 'id'
        virtualNetworkGateways = 'id'; bastionHosts = 'id'
    }
    $data = [ordered]@{}
    # When the data was read. A diagram rebuilt later from the exported JSON shows this
    # time, not the time it was drawn.
    $data['collectedAt'] = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture)
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
    $hubConnectionData = Get-HubConnectionData -HubRows $data['virtualHubs']
    $data['hubVirtualNetworkConnections'] = @($hubConnectionData.Rows)
    if ($hubConnectionData.RequestCount -gt 0) {
        Write-StatusDetail "$(@($hubConnectionData.Rows).Count) Virtual WAN hub connections, $($hubConnectionData.RequestCount) ARM requests"
    }
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

# Dark counterparts for the light colors written in styles, keyed by style
# property. draw.io's automatic inversion leaves pure white text on black and
# turns the table headers bright, so the dark theme is set explicitly instead.
$script:DarkPageBackground = '#1e1f22'
$script:DarkDefaultFontColor = '#dcdde0'
$script:DarkThemeColors = @{
    fillColor = @{
        '#ffffff' = '#2b2d31'; '#fffdf5' = '#2d2b26'; '#f8f9fa' = '#26282c'; '#f2f2f2' = '#232427'
        '#e6f2ff' = '#1d2d40'; '#f8fbff' = '#22272e'; '#fffaf0' = '#2e2a1f'; '#f2fbf5' = '#1f2b23'
        '#f8f3fc' = '#2a2433'; '#f3e8ff' = '#2d2340'; '#fff2cc' = '#3a321c'; '#d5e8d4' = '#1f3324'
        '#f8cecc' = '#3d2326'; '#0078d4' = '#1f4e79'
    }
    strokeColor = @{
        '#0078d4' = '#4a9be0'; '#005a9e' = '#2f6aa0'; '#b3b3b3' = '#3e4148'; '#adb5bd' = '#4a4f57'
        '#d6b656' = '#a88f3f'; '#82b366' = '#5e9a55'; '#9673a6' = '#9c84c4'; '#6c8ebf' = '#5f7fae'
        '#b85450' = '#a8504c'; '#339966' = '#4caf7d'; '#b8860b' = '#c9a227'
    }
    fontColor = @{
        '#ffffff' = '#f0f3f6'; '#0078d4' = '#6cb6ff'; '#107c10' = '#7fd18b'; '#b91c1c' = '#ff8f8f'
        '#555555' = '#a0a4aa'; '#7a4f01' = '#e8c872'
    }
    labelBackgroundColor = @{ '#ffffff' = $script:DarkPageBackground }
}

function ConvertTo-AdaptiveStyle {
    param([string]$Style)

    # Colors inside HTML labels are left as written: draw.io ignores light-dark()
    # there and inverts plain colors on its own, which reads well for the greys.
    $hasFontColor = $false
    $parts = foreach ($part in $Style.Split(';')) {
        $separator = $part.IndexOf('=')
        if ($separator -gt 0) {
            $key = $part.Substring(0, $separator)
            $value = $part.Substring($separator + 1)
            if ($key -eq 'fontColor') { $hasFontColor = $true }
            $darkColors = $script:DarkThemeColors[$key]
            if ($darkColors -and $darkColors.ContainsKey($value)) {
                $part = "$key=light-dark($value,$($darkColors[$value]))"
            }
        }
        $part
    }
    $adaptiveStyle = $parts -join ';'
    if (-not $hasFontColor) {
        if ($adaptiveStyle -and -not $adaptiveStyle.EndsWith(';')) { $adaptiveStyle += ';' }
        $adaptiveStyle += "fontColor=light-dark(#000000,$script:DarkDefaultFontColor);"
    }
    return $adaptiveStyle
}

function Set-MxPageTheme {
    param([System.Xml.XmlElement]$Model)
    Set-XmlAttribute $Model 'background' "light-dark(#ffffff,$script:DarkPageBackground)"
}

function Get-ConnectorLayerDefinition {
    # Order here is the order draw.io lists in its Layers panel.
    return @(
        [pscustomobject]@{ Kind='Attachment';    Id='layer-attachment';    Name='Attachments and backends' },
        [pscustomobject]@{ Kind='Security';      Id='layer-security';      Name='Security (NSG)' },
        [pscustomobject]@{ Kind='Configuration'; Id='layer-configuration'; Name='Routing and NAT' },
        [pscustomobject]@{ Kind='Peering';       Id='layer-peering';       Name='VNet peering' },
        [pscustomobject]@{ Kind='Hybrid';        Id='layer-hybrid';        Name='Gateway connections' }
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
    # from the drawing alone: content larger than the page spills onto extra sheets,
    # and a fixed minimum would pad small pages with blank space.
    Set-XmlAttribute $Model 'pageWidth'  ([int][math]::Ceiling($ContentRight + $Margin))
    Set-XmlAttribute $Model 'pageHeight' ([int][math]::Ceiling($ContentBottom + $Margin))
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
    Set-XmlAttribute $cell 'style' (ConvertTo-AdaptiveStyle $Style)
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
        [string]$Parent = '1',
        # Waypoints in the edge parent's coordinates, as objects with X and Y.
        [object[]]$Points = @()
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
    Set-XmlAttribute $cell 'style' (ConvertTo-AdaptiveStyle $Style)
    Set-XmlAttribute $cell 'edge' '1'
    Set-XmlAttribute $cell 'parent' $Parent
    Set-XmlAttribute $cell 'source' $Source
    Set-XmlAttribute $cell 'target' $Target
    $geometry = $Document.CreateElement('mxGeometry')
    Set-XmlAttribute $geometry 'relative' '1'
    Set-XmlAttribute $geometry 'as' 'geometry'
    if ($Points.Count -gt 0) {
        $pointArray = $Document.CreateElement('Array')
        Set-XmlAttribute $pointArray 'as' 'points'
        foreach ($point in $Points) {
            $mxPoint = $Document.CreateElement('mxPoint')
            Set-XmlAttribute $mxPoint 'x' $point.X
            Set-XmlAttribute $mxPoint 'y' $point.Y
            $null = $pointArray.AppendChild($mxPoint)
        }
        $null = $geometry.AppendChild($pointArray)
    }
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
        VpnSiteById=(New-ResourceMap (Get-DataRows $Data 'vpnSites'))
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
        HubConnections=[System.Collections.Generic.List[object]]::new()
        ExpressRouteGatewaysByHubId=@{}
        ExpressRouteConnectionsByGatewayId=@{}
        VpnGatewaysByHubId=@{}
        P2sVpnGatewaysByHubId=@{}
        PublicIpByIpConfigurationId=@{}
        SubnetReferencesByOccupantId=@{}
        FirewallRelationById=@{}
        FirewallIdsBySubnetId=@{}
        FirewallIdsByHubId=@{}
        GatewayRelationById=@{}
        GatewayIdsBySubnetId=@{}
        BastionRelationById=@{}
        BastionIdsBySubnetId=@{}
        PrivateIpOwners=@{}
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
    # Resources holding a private IP that a route or a DNAT rule can point to, with their
    # VNet: firewalls, VM and private endpoint NICs, and the private frontends of load
    # balancers and application gateways. See Resolve-PrivateIpOwner.
    $privateEndpointNameByNicId = @{}
    foreach ($endpoint in Get-DataRows $Data 'privateEndpoints') {
        foreach ($endpointNicId in @(Get-IdsFromJson (Get-ObjectValue $endpoint 'networkInterfaces' ''))) {
            $privateEndpointNameByNicId[$endpointNicId] = [string](Get-ObjectValue $endpoint 'name' '')
        }
    }
    $ipOwners = @(
        foreach ($firewall in Get-DataRows $Data 'firewalls') {
            $firewallName = [string](Get-ObjectValue $firewall 'name' '')
            [pscustomobject]@{ Ip=[string](Get-ObjectValue $firewall 'privateIpAddress' ''); Name=$firewallName; SubnetId=[string](Get-ObjectValue $firewall 'subnetId' '') }
            [pscustomobject]@{ Ip=[string](Get-ObjectValue $firewall 'hubPrivateIpAddress' ''); Name=$firewallName; SubnetId='' }
        }
        foreach ($nic in Get-DataRows $Data 'nics') {
            $nicId = ConvertTo-ResourceId (Get-ObjectValue $nic 'nicId' '')
            $vmId = [string](Get-ObjectValue $nic 'attachedResourceId' '')
            $nicOwner = if ($vmId) { Get-ResourceNameFromId $vmId } elseif ($privateEndpointNameByNicId.ContainsKey($nicId)) { $privateEndpointNameByNicId[$nicId] } else { [string](Get-ObjectValue $nic 'nicName' '') }
            [pscustomobject]@{ Ip=[string](Get-ObjectValue $nic 'privateIpAddress' ''); Name=$nicOwner; SubnetId=[string](Get-ObjectValue $nic 'subnetId' '') }
        }
        foreach ($loadBalancer in Get-DataRows $Data 'loadBalancers') {
            [pscustomobject]@{ Ip=[string](Get-ObjectValue $loadBalancer 'privateIpAddress' ''); Name=[string](Get-ObjectValue $loadBalancer 'name' ''); SubnetId=[string](Get-ObjectValue $loadBalancer 'subnetId' '') }
        }
        foreach ($applicationGateway in Get-DataRows $Data 'applicationGateways') {
            foreach ($frontend in @(ConvertFrom-JsonCollection (Get-ObjectValue $applicationGateway 'frontendIpConfigurations' ''))) {
                $frontendProperties = Get-ObjectValue $frontend 'properties' $frontend
                $frontendSubnet = Get-ObjectValue $frontendProperties 'subnet' $null
                $frontendSubnetId = if ($frontendSubnet) { [string](Get-ObjectValue $frontendSubnet 'id' '') } else { [string](Get-ObjectValue $applicationGateway 'subnetId' '') }
                [pscustomobject]@{ Ip=[string](Get-ObjectValue $frontendProperties 'privateIPAddress' ''); Name=[string](Get-ObjectValue $applicationGateway 'name' ''); SubnetId=$frontendSubnetId }
            }
        }
    )
    foreach ($owner in $ipOwners) {
        if (-not $owner.Ip -or -not $owner.Name) { continue }
        $ownerVnetId = if ([string]$owner.SubnetId -match '^(.*/virtualnetworks/[^/]+)/subnets/') { ConvertTo-ResourceId $Matches[1] } else { '' }
        if (-not $index.PrivateIpOwners.ContainsKey($owner.Ip)) { $index.PrivateIpOwners[$owner.Ip] = @{} }
        if (-not $index.PrivateIpOwners[$owner.Ip].ContainsKey($owner.Name)) { $index.PrivateIpOwners[$owner.Ip][$owner.Name] = $ownerVnetId }
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
        $index.HubConnections.Add($connection)
    }
    # Connecting a VNet to a Virtual WAN hub also peers it with the hub's Microsoft-managed
    # VNet, named HV_<hub>_<guid>. Where the connection itself is missing, for example when
    # the hub's connections could not be read, that peering stands in for it, provided
    # exactly one hub in the export has that name.
    $hubIdsByName = @{}
    foreach ($hub in Get-DataRows $Data 'virtualHubs') {
        Add-IndexValue $hubIdsByName ([string](Get-ObjectValue $hub 'name' '')).ToLowerInvariant() (ConvertTo-ResourceId (Get-ObjectValue $hub 'id'))
    }
    foreach ($peering in Get-DataRows $Data 'vnetPeerings') {
        $remoteName = Get-ResourceNameFromId (ConvertTo-ResourceId (Get-ObjectValue $peering 'remoteVnetId' ''))
        if (-not ($remoteName -match '^hv_(.+)_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')) { continue }
        $hubIds = @($hubIdsByName[$Matches[1].ToLowerInvariant()] | Where-Object { $_ })
        if ($hubIds.Count -ne 1) { continue }
        $vnetId = ConvertTo-ResourceId (Get-ObjectValue $peering 'vnetId' '')
        $known = @($index.HubConnectionsByVnetId[$vnetId] | Where-Object { $null -ne $_ -and (ConvertTo-ResourceId (Get-ObjectValue $_ 'virtualHubId' '')) -eq $hubIds[0] })
        if ($known.Count -gt 0) { continue }
        $peeringState = [string](Get-ObjectValue $peering 'state' '')
        $inferred = [pscustomobject]@{
            id = ''; name = 'from managed peering'; virtualHubId = $hubIds[0]; remoteVnetId = $vnetId
            provisioningState = $(if ($peeringState -eq 'Connected') { 'Succeeded' } else { $peeringState })
        }
        Add-IndexValue $index.HubConnectionsByVnetId $vnetId $inferred
        $index.HubConnections.Add($inferred)
    }
    # The ExpressRoute gateway query returns one row per connection.
    foreach ($group in @(Get-DataRows $Data 'expressRouteGateways' | Group-Object { ConvertTo-ResourceId (Get-ObjectValue $_ 'id') } | Sort-Object Name)) {
        if (-not $group.Name) { continue }
        Add-IndexValue $index.ExpressRouteGatewaysByHubId (ConvertTo-ResourceId (Get-ObjectValue $group.Group[0] 'virtualHubId')) $group.Group[0]
        $index.ExpressRouteConnectionsByGatewayId[[string]$group.Name] = @($group.Group | Where-Object { Get-ObjectValue $_ 'circuitPeeringId' '' })
    }
    # The VPN gateway query returns one row per connection.
    foreach ($group in @(Get-DataRows $Data 'vpnGateways' | Group-Object { ConvertTo-ResourceId (Get-ObjectValue $_ 'id') } | Sort-Object Name)) {
        if (-not $group.Name) { continue }
        Add-IndexValue $index.VpnGatewaysByHubId (ConvertTo-ResourceId (Get-ObjectValue $group.Group[0] 'virtualHubId' '')) `
            ([pscustomobject]@{ Id=[string]$group.Name; Rows=@($group.Group) })
    }
    foreach ($gateway in Get-DataRows $Data 'p2sVpnGateways') {
        Add-IndexValue $index.P2sVpnGatewaysByHubId (ConvertTo-ResourceId (Get-ObjectValue $gateway 'virtualHubId' '')) $gateway
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

function Get-ServiceTypeInfo {
    param([AllowNull()][string]$ResourceType)

    # Services known only from a reference: private endpoint targets and resources
    # deployed into a subnet. Each type maps to a display name and, where draw.io's
    # Azure library has a matching shape, an icon path below img/lib/azure2. A new
    # non-square icon also needs its proportions in Get-AzureIconSize.
    $serviceTypes = @{
        'microsoft.storage/storageaccounts' = @('Storage account', 'storage/Storage_Accounts.svg')
        'microsoft.storagesync/storagesyncservices' = @('Storage Sync Service', 'storage/Storage_Sync_Services.svg')
        'microsoft.compute/diskaccesses' = @('Disk access', 'compute/Disks.svg')
        'microsoft.netapp/netappaccounts' = @('Azure NetApp Files account', 'storage/Azure_NetApp_Files.svg')
        'microsoft.keyvault/vaults' = @('Key vault', 'security/Key_Vaults.svg')
        'microsoft.keyvault/managedhsms' = @('Managed HSM', 'security/Key_Vaults.svg')
        'microsoft.sql/servers' = @('Azure SQL server', 'databases/SQL_Server.svg')
        'microsoft.sql/managedinstances' = @('SQL Managed Instance', 'databases/SQL_Managed_Instance.svg')
        'microsoft.dbforpostgresql/flexibleservers' = @('Azure Database for PostgreSQL flexible server', 'databases/Azure_Database_PostgreSQL_Server.svg')
        'microsoft.dbformysql/flexibleservers' = @('Azure Database for MySQL flexible server', 'databases/Azure_Database_MySQL_Server.svg')
        'microsoft.documentdb/databaseaccounts' = @('Azure Cosmos DB account', 'databases/Azure_Cosmos_DB.svg')
        'microsoft.cache/redis' = @('Azure Cache for Redis', 'databases/Cache_Redis.svg')
        'microsoft.cache/redisenterprise' = @('Azure Managed Redis', 'databases/Azure_Managed_Redis.svg')
        'microsoft.synapse/workspaces' = @('Synapse workspace', 'analytics/Azure_Synapse_Analytics.svg')
        'microsoft.kusto/clusters' = @('Azure Data Explorer cluster', 'databases/Azure_Data_Explorer_Clusters.svg')
        'microsoft.datafactory/factories' = @('Data Factory', 'databases/Data_Factory.svg')
        'microsoft.databricks/workspaces' = @('Azure Databricks workspace', 'analytics/Azure_Databricks.svg')
        'microsoft.purview/accounts' = @('Microsoft Purview account', 'databases/Azure_Purview_Accounts.svg')
        'microsoft.cognitiveservices/accounts' = @('Azure AI services account', 'ai_machine_learning/Cognitive_Services.svg')
        'microsoft.search/searchservices' = @('AI Search service', 'app_services/Search_Services.svg')
        'microsoft.machinelearningservices/workspaces' = @('Azure Machine Learning workspace', 'ai_machine_learning/Machine_Learning.svg')
        'microsoft.web/sites' = @('App Service', 'app_services/App_Services.svg')
        'microsoft.web/serverfarms' = @('App Service plan', 'app_services/App_Service_Plans.svg')
        'microsoft.web/staticsites' = @('Static Web App', 'preview/Static_Apps.svg')
        'microsoft.app/managedenvironments' = @('Container Apps environment', 'other/Container_App_Environments.svg')
        'microsoft.containerservice/managedclusters' = @('AKS cluster', 'containers/Kubernetes_Services.svg')
        'microsoft.containerregistry/registries' = @('Container registry', 'containers/Container_Registries.svg')
        'microsoft.containerinstance/containergroups' = @('Container instance group', 'containers/Container_Instances.svg')
        'microsoft.apimanagement/service' = @('API Management service', 'app_services/API_Management_Services.svg')
        'microsoft.appconfiguration/configurationstores' = @('App Configuration store', 'integration/App_Configuration.svg')
        'microsoft.servicebus/namespaces' = @('Service Bus namespace', 'integration/Service_Bus.svg')
        'microsoft.eventhub/namespaces' = @('Event Hubs namespace', 'analytics/Event_Hubs.svg')
        'microsoft.eventgrid/topics' = @('Event Grid topic', 'integration/Event_Grid_Topics.svg')
        'microsoft.eventgrid/domains' = @('Event Grid domain', 'integration/Event_Grid_Domains.svg')
        'microsoft.eventgrid/namespaces' = @('Event Grid namespace', 'integration/Event_Grid_Topics.svg')
        'microsoft.relay/namespaces' = @('Relay namespace', 'integration/Relays.svg')
        'microsoft.devices/iothubs' = @('IoT Hub', 'iot/IoT_Hub.svg')
        'microsoft.signalrservice/signalr' = @('SignalR Service', 'web/SignalR.svg')
        'microsoft.signalrservice/webpubsub' = @('Web PubSub', 'integration/Azure_PubSub.svg')
        'microsoft.insights/privatelinkscopes' = @('Azure Monitor Private Link Scope', 'management_governance/Monitor.svg')
        'microsoft.hybridcompute/privatelinkscopes' = @('Azure Arc Private Link Scope', 'management_governance/Azure_Arc.svg')
        'microsoft.recoveryservices/vaults' = @('Recovery Services vault', 'management_governance/Recovery_Services_Vaults.svg')
        'microsoft.automation/automationaccounts' = @('Automation account', 'management_governance/Automation_Accounts.svg')
        'microsoft.desktopvirtualization/hostpools' = @('Azure Virtual Desktop host pool', 'compute/Host_Pools.svg')
        'microsoft.desktopvirtualization/workspaces' = @('Azure Virtual Desktop workspace', 'compute/Workspaces.svg')
        'microsoft.dashboard/grafana' = @('Azure Managed Grafana', 'other/Grafana.svg')
        'microsoft.network/privatelinkservices' = @('Private Link service', 'networking/Private_Link_Service.svg')
        'microsoft.network/applicationgateways' = @('Application gateway', 'networking/Application_Gateways.svg')
        'microsoft.network/dnsresolvers' = @('DNS Private Resolver', 'networking/DNS_Private_Resolver.svg')
        'microsoft.network/networkvirtualappliances' = @('Network virtual appliance', '')
    }
    $key = ([string]$ResourceType).ToLowerInvariant()
    if (-not $serviceTypes.ContainsKey($key)) { return $null }
    return [pscustomobject]@{ Name = $serviceTypes[$key][0]; Icon = $serviceTypes[$key][1] }
}

function Get-AzureIconPath {
    param([string]$Kind, [string]$ResourceType = '', [string]$ResourceId = '')
    # Private endpoint targets and subnet services take their own type's icon where
    # one exists; a target's type is known only from its ID.
    if ($Kind -eq 'PrivateLinkTarget') { $ResourceType = Get-ResourceTypeFromId $ResourceId }
    if ($Kind -eq 'PrivateLinkTarget' -or $Kind -eq 'SubnetOccupant') {
        $service = Get-ServiceTypeInfo $ResourceType
        if ($service -and $service.Icon) { return "img/lib/azure2/$($service.Icon)" }
    }
    # A new non-square icon also needs its proportions in Get-AzureIconSize.
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
        VpnGateway='networking/Virtual_Network_Gateways.svg'; P2SVpnGateway='networking/Virtual_Network_Gateways.svg'
        VpnSite='networking/Local_Network_Gateways.svg'
    }
    if ($icons.ContainsKey($Kind)) { return "img/lib/azure2/$($icons[$Kind])" }
    return 'img/lib/azure2/general/All_Resources.svg'
}

function Get-AzureIconSize {
    param([string]$IconPath, [int]$BoxSize = 34)

    # draw.io's label shape stretches its image to imageWidth x imageHeight, so each icon
    # is fitted into the box at its own proportions. The width/height ratios were measured
    # from draw.io's azure2 library; icons within 2% of square are omitted. A new icon that
    # is missing here is drawn square, which distorts it but breaks nothing.
    $aspectByIcon = @{
        'ai_machine_learning/Cognitive_Services.svg' = 1.41
        'ai_machine_learning/Machine_Learning.svg' = 0.93
        'analytics/Azure_Databricks.svg' = 0.92
        'analytics/Azure_Synapse_Analytics.svg' = 0.87
        'analytics/Event_Hubs.svg' = 1.12
        'app_services/API_Management_Services.svg' = 1.09
        'app_services/Search_Services.svg' = 1.37
        'compute/Disks.svg' = 1.03
        'compute/Virtual_Machine.svg' = 1.08
        'compute/Workspaces.svg' = 1.16
        'containers/Container_Instances.svg' = 0.94
        'containers/Container_Registries.svg' = 1.12
        'containers/Kubernetes_Services.svg' = 1.14
        'databases/Azure_Database_MySQL_Server.svg' = 0.75
        'databases/Azure_Database_PostgreSQL_Server.svg' = 0.75
        'databases/Azure_Purview_Accounts.svg' = 1.6
        'databases/Cache_Redis.svg' = 1.23
        'integration/App_Configuration.svg' = 0.93
        'integration/Event_Grid_Domains.svg' = 1.12
        'integration/Event_Grid_Topics.svg' = 1.12
        'integration/Relays.svg' = 1.12
        'integration/Service_Bus.svg' = 1.12
        'management_governance/Azure_Arc.svg' = 1.34
        'management_governance/Recovery_Services_Vaults.svg' = 1.15
        'networking/Azure_Firewall_Policy.svg' = 1.38
        'networking/Bastions.svg' = 0.86
        'networking/DNS_Private_Resolver.svg' = 1.14
        'networking/ExpressRoute_Circuits.svg' = 1.09
        'networking/Firewalls.svg' = 1.18
        'networking/Network_Interfaces.svg' = 1.13
        'networking/Network_Security_Groups.svg' = 0.82
        'networking/Private_Endpoint.svg' = 1.09
        'networking/Private_Link_Service.svg' = 1.73
        'networking/Private_Link.svg' = 1.08
        'networking/Public_IP_Addresses.svg' = 1.24
        'networking/Public_IP_Prefixes.svg' = 1.29
        'networking/Route_Tables.svg' = 1.04
        'networking/Subnet.svg' = 1.67
        'networking/Virtual_Network_Gateways.svg' = 0.75
        'networking/Virtual_Networks.svg' = 1.67
        'other/Grafana.svg' = 1.29
        'preview/Static_Apps.svg' = 1.24
        'storage/Azure_NetApp_Files.svg' = 1.24
        'storage/Storage_Accounts.svg' = 1.24
        'storage/Storage_Sync_Services.svg' = 1.2
    }
    $key = $IconPath -replace '^img/lib/azure2/', ''
    $aspect = if ($aspectByIcon.ContainsKey($key)) { [double]$aspectByIcon[$key] } else { 1.0 }
    if ($aspect -ge 1) {
        return [pscustomobject]@{ Width = $BoxSize; Height = [int][math]::Round($BoxSize / $aspect) }
    }
    return [pscustomobject]@{ Width = [int][math]::Round($BoxSize * $aspect); Height = $BoxSize }
}

function Get-AzureNodeStyle {
    param(
        [string]$Kind,
        [string]$FillColor = '#ffffff',
        [string]$StrokeColor = '#0078d4',
        [string]$ResourceType = '',
        [string]$ResourceId = ''
    )
    $icon = Get-AzureIconPath $Kind $ResourceType $ResourceId
    $iconSize = Get-AzureIconSize $icon
    return "shape=label;rounded=1;whiteSpace=wrap;html=1;image=$icon;imageWidth=$($iconSize.Width);imageHeight=$($iconSize.Height);" +
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
        VpnSite='VPN site';VpnGateway='Virtual WAN VPN gateway';P2SVpnGateway='Point-to-site VPN gateway'
    }
    # Types not known to Get-ServiceTypeInfo fall back to the raw resource type.
    if($Kind -eq 'PrivateLinkTarget'){
        $targetType=(Get-ResourceTypeFromId (ConvertTo-ResourceId $ResourceId)).ToLowerInvariant()
        $service=Get-ServiceTypeInfo $targetType
        if($service){return [string]$service.Name}
        if($targetType){return $targetType}
        return 'Private Link target'
    }
    if($Kind -eq 'SubnetOccupant'){
        $service=Get-ServiceTypeInfo $ResourceType
        if($service){return [string]$service.Name}
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
        [hashtable]$Attributes,
        # Replaces the line and arrowhead style of the kind, such as a peering's arrowheads.
        [string]$KindStyle = ''
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
            AzureId=$normalizedAzureId; ResourceType=$ResourceType; Attributes=$edgeAttributes; KindStyle=$KindStyle
        })
    }
}

function Get-ExternalLaneOrder {
    param([object[]]$Nodes,[System.Collections.Generic.List[object]]$Edges)

    # Each Virtual Hub is followed directly by what sits behind it, so its connectors
    # stay short; the other remote resources keep their order above the hubs.
    $nodeById = @{}
    foreach ($node in $Nodes) { $nodeById[$node.Id] = $node }
    $childIdsByParentId = @{}
    foreach ($edge in $Edges) {
        if ($edge.Kind -eq 'Hybrid' -and $nodeById.ContainsKey($edge.Source) -and $nodeById.ContainsKey($edge.Target)) {
            Add-IndexValue $childIdsByParentId $edge.Source $edge.Target
        }
    }
    $rankByKind = @{ ExpressRouteGateway=0; Firewall=1; P2SVpnGateway=2; VpnGateway=3; VpnSite=4 }
    $placedIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $hubChains = [System.Collections.Generic.List[object]]::new()
    foreach ($hub in @($Nodes | Where-Object Kind -eq 'VirtualHub' | Sort-Object Name, Id)) {
        $pending = [System.Collections.Generic.Stack[string]]::new()
        $pending.Push($hub.Id)
        while ($pending.Count -gt 0) {
            $id = $pending.Pop()
            if (-not $placedIds.Add($id)) { continue }
            $hubChains.Add($nodeById[$id])
            $children = @($childIdsByParentId[$id] | Where-Object { $_ -and -not $placedIds.Contains($_) } | ForEach-Object { $nodeById[$_] } |
                Sort-Object @{Expression={ if ($rankByKind.ContainsKey($_.Kind)) { $rankByKind[$_.Kind] } else { 9 } }}, Name, Id)
            # Pushed in reverse so the first child is placed next.
            for ($index = $children.Count - 1; $index -ge 0; $index--) { $pending.Push($children[$index].Id) }
        }
    }
    return @(@($Nodes | Where-Object { -not $placedIds.Contains($_.Id) }) + @($hubChains))
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
    if ($Edge.KindStyle) {
        $base += $Edge.KindStyle
    } else {
        $base += switch ($Edge.Kind) {
            # NSG and routing links describe configuration, not traffic direction, so
            # they carry no arrowhead.
            'Security'      { 'dashed=1;dashPattern=6 4;strokeColor=#b8860b;endArrow=none;' }
            'Configuration' { 'dashed=1;dashPattern=6 4;strokeColor=#6c8ebf;endArrow=none;' }
            'Peering'       { 'dashed=1;dashPattern=8 4;strokeColor=#9673a6;strokeWidth=2;' }
            'Hybrid'        { 'strokeColor=#9673a6;strokeWidth=2;' }
            default         { 'strokeColor=#339966;' }
        }
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
    if ($sourceLane -eq 'External' -and $targetLane -eq 'External') {
        # Stacked in the same lane: run along its right edge instead of wrapping
        # around to the left side across the nodes in between.
        return $base + 'exitX=1;exitY=0.35;exitPerimeter=1;entryX=1;entryY=0.65;entryPerimeter=1;'
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
        if (@('VM', 'PrivateEndpoint') -contains $sourceNode.Kind -and $targetNode.Kind -eq 'NIC') {
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
             "Dashed line = security/configuration/peering &nbsp; | &nbsp; Purple line = peering or gateway connection &nbsp; | &nbsp; Click a remote VNet to open its page" +
             "<br>Arrowheads on peerings and connections = directions traffic may flow, detailed on the remote VNet for peerings; NSGs, routes, and firewalls are not evaluated &nbsp; | &nbsp; Red = not connected &nbsp; | &nbsp; No arrowheads = configuration, parts of a Virtual WAN hub, or state not reported"
    Add-MxVertex -Document $Document -Root $Root -Id 'legend' -Parent '1' -Value $value `
        -Style 'rounded=1;whiteSpace=wrap;html=1;fillColor=#f8f9fa;strokeColor=#adb5bd;fontSize=10;align=left;spacingLeft=10;' `
        -X 20 -Y $Y -Width $Width -Height 54
}

function Get-ExpressRouteCircuitDetail {
    param([AllowNull()][object]$Circuit)

    # Provider, location, bandwidth, and state, for the circuit's card.
    if ($null -eq $Circuit) { return @() }
    $bandwidth = [string](Get-ObjectValue $Circuit 'bandwidthMbps' '')
    return @(
        (Get-ObjectValue $Circuit 'serviceProvider' ''),
        (Get-ObjectValue $Circuit 'peeringLocation' ''),
        $(if ($bandwidth) { "$bandwidth Mbps" }),
        (Get-ObjectValue $Circuit 'circuitState' '')
    ) | Where-Object { $_ }
}

function Resolve-PrivateIpOwner {
    param([object]$Index, [string]$Ip)

    # Overlapping VNets can reuse an address, so an IP is only attributed when exactly one
    # resource in the export holds it. Returns $null otherwise.
    if (-not $Ip -or -not $Index.PrivateIpOwners.ContainsKey($Ip)) { return $null }
    $owners = $Index.PrivateIpOwners[$Ip]
    if ($owners.Count -ne 1) { return $null }
    $ownerName = @($owners.Keys)[0]
    return [pscustomobject]@{ Name = $ownerName; VnetId = [string]$owners[$ownerName] }
}

function Get-RouteDescription {
    param([object]$Route, [object]$Index)

    # Names the next hop the way a reader thinks of it. An appliance IP becomes the name of
    # the resource holding it when that is unambiguous, otherwise it stays an IP.
    $properties = Get-ObjectValue $Route 'properties' $Route
    $prefix = [string](Get-ObjectValue $properties 'addressPrefix' '')
    $type = [string](Get-ObjectValue $properties 'nextHopType' '')
    $ip = [string](Get-ObjectValue $properties 'nextHopIpAddress' '')
    $hop = switch ($type) {
        'VirtualAppliance' {
            $hopOwner = Resolve-PrivateIpOwner $Index $ip
            if ($hopOwner) { $hopOwner.Name } elseif ($ip) { $ip } else { 'appliance' }
        }
        'VirtualNetworkGateway' { 'gateway' }
        'VnetLocal' { 'VNet local' }
        'Internet' { 'Internet' }
        'None' { 'dropped' }
        default { $type }
    }
    $technical = if ($ip) { "$type $ip" } else { $type }
    return [pscustomobject]@{
        Card = "$prefix &#8594; $hop"
        Tooltip = "$([string](Get-ObjectValue $Route 'name' '')): $prefix $([char]0x2192) $hop ($technical)"
    }
}

function Get-PeeringFlow {
    param([object]$Index, [object]$Peering)

    # Each side of a peering is its own resource with its own state and VNet access
    # setting, and a side's setting governs traffic leaving its VNet. The way back needs
    # the remote VNet's own peering, known only when that VNet is part of the export.
    # Exports made before VNet access was collected count as allowed, Azure's default.
    $localId = ConvertTo-ResourceId (Get-ObjectValue $Peering 'vnetId' '')
    $remoteId = ConvertTo-ResourceId (Get-ObjectValue $Peering 'remoteVnetId' '')
    $reverse = $null
    foreach ($candidate in @($Index.PeeringsByVnetId[$remoteId] | Where-Object { $null -ne $_ })) {
        if ((ConvertTo-ResourceId (Get-ObjectValue $candidate 'remoteVnetId' '')) -eq $localId) { $reverse = $candidate; break }
    }
    $localState = [string](Get-ObjectValue $Peering 'state' '')
    $remoteState = if ($reverse) { [string](Get-ObjectValue $reverse 'state' '') } else { '' }
    $connected = ($localState -eq 'Connected') -and ((-not $reverse) -or $remoteState -eq 'Connected')
    $localAccess = ConvertTo-NullableBoolean (Get-ObjectValue $Peering 'allowVirtualNetworkAccess')
    $remoteAccess = if ($reverse) { ConvertTo-NullableBoolean (Get-ObjectValue $reverse 'allowVirtualNetworkAccess') } else { $null }
    $inbound = $false
    if ($connected) { $inbound = if ($reverse) { $remoteAccess -ne $false } else { $null } }
    $names = foreach ($id in @($localId, $remoteId)) {
        if ($Index.VnetById.ContainsKey($id)) { [string](Get-ObjectValue $Index.VnetById[$id] 'name' (Get-ResourceNameFromId $id)) } else { Get-ResourceNameFromId $id }
    }
    $syncLevel = [string](Get-ObjectValue $Peering 'peeringSyncLevel' '')
    return [pscustomobject]@{
        LocalId = $localId; RemoteId = $remoteId; LocalName = $names[0]; RemoteName = $names[1]
        HasReverse = $null -ne $reverse; RemoteInExport = $Index.VnetById.ContainsKey($remoteId)
        LocalPeeringName = [string](Get-ObjectValue $Peering 'name' '')
        RemotePeeringName = $(if ($reverse) { [string](Get-ObjectValue $reverse 'name' '') } else { '' })
        LocalState = $localState; RemoteState = $remoteState; Connected = $connected
        LocalAccess = $localAccess; RemoteAccess = $remoteAccess
        Outbound = $connected -and $localAccess -ne $false; Inbound = $inbound
        IsSubnetPeering = (ConvertTo-NullableBoolean (Get-ObjectValue $Peering 'peerCompleteVnets')) -eq $false
        LocalSubnets = @(ConvertFrom-JsonCollection (Get-ObjectValue $Peering 'localSubnetNames' '') | ForEach-Object { [string]$_ } | Where-Object { $_ })
        RemoteSubnets = @(ConvertFrom-JsonCollection (Get-ObjectValue $Peering 'remoteSubnetNames' '') | ForEach-Object { [string]$_ } | Where-Object { $_ })
        LocalPrefixes = @(Get-PrefixList (Get-ObjectValue $Peering 'localPeeredAddressPrefixes' ''))
        RemotePrefixes = @(Get-PrefixList (Get-ObjectValue $Peering 'peeredAddressPrefixes' ''))
        SyncLevel = $syncLevel; IsOutOfSync = [bool]($syncLevel -and $syncLevel -ne 'FullyInSync')
    }
}

function Get-PeeringFlowDescription {
    param([object]$Flow)

    # Plain-text lines for tooltips, naming both VNets so they read the same on the
    # overview and on either VNet's page.
    $arrow = [char]0x2192
    $directions = @(
        @{ Allowed = $Flow.Outbound; Access = $Flow.LocalAccess; From = $Flow.LocalName; To = $Flow.RemoteName },
        @{ Allowed = $Flow.Inbound; Access = $Flow.RemoteAccess; From = $Flow.RemoteName; To = $Flow.LocalName }
    )
    $lines = @(foreach ($direction in $directions) {
        $status = if (-not $Flow.Connected) {
            'none, the peering is not connected'
        } elseif ($null -eq $direction.Allowed) {
            "not known, $($direction.From)'s side of the peering is not in this export"
        } elseif ($direction.Allowed) {
            if ($null -eq $direction.Access) { 'allowed (VNet access not collected)' } else { 'allowed' }
        } else {
            "blocked, VNet access is off on $($direction.From)'s side"
        }
        "Traffic $($direction.From) $arrow $($direction.To): $status"
    })
    $remoteSide = if ($Flow.HasReverse) { $Flow.RemoteState } elseif ($Flow.RemoteInExport) { 'no peering back' } else { 'not in this export' }
    $lines += "State: $($Flow.LocalName) side $($Flow.LocalState), $($Flow.RemoteName) side $remoteSide"
    # Each side names its own peering resource, and the two names are often unrelated.
    $lines += "Peering name on $($Flow.LocalName)'s side: $($Flow.LocalPeeringName)"
    if ($Flow.HasReverse) { $lines += "Peering name on $($Flow.RemoteName)'s side: $($Flow.RemotePeeringName)" }
    if ($Flow.IsSubnetPeering) {
        foreach ($side in @(@{ Name = $Flow.LocalName; Subnets = $Flow.LocalSubnets; Prefixes = $Flow.LocalPrefixes },
                            @{ Name = $Flow.RemoteName; Subnets = $Flow.RemoteSubnets; Prefixes = $Flow.RemotePrefixes })) {
            $subnets = if (@($side.Subnets).Count -gt 0) { @($side.Subnets) -join ', ' } else { 'not reported' }
            $prefixes = if (@($side.Prefixes).Count -gt 0) { " ($(@($side.Prefixes) -join ', '))" } else { '' }
            $lines += "Subnet peering, $($side.Name): $subnets$prefixes"
        }
    }
    if ($Flow.IsOutOfSync) {
        $lines += "Not in sync ($($Flow.SyncLevel)): an address space changed since the peering was last synced"
    }
    return $lines
}

function Get-PeeringLineStyle {
    param([object]$Flow)

    # Arrowheads point where the peering lets traffic go: at the target for traffic from
    # the source VNet, at the source for traffic back. A peering that is not connected
    # carries no traffic and is drawn red without arrowheads.
    if (-not $Flow.Connected) {
        return 'dashed=1;dashPattern=8 4;strokeColor=#b85450;strokeWidth=2;startArrow=none;endArrow=none;'
    }
    $start = if ($Flow.Inbound -eq $true) { 'startArrow=classic;startFill=1;' } else { 'startArrow=none;' }
    $end = if ($Flow.Outbound) { 'endArrow=classic;endFill=1;' } else { 'endArrow=none;' }
    return "dashed=1;dashPattern=8 4;strokeColor=#9673a6;strokeWidth=2;$start$end"
}

function Get-PeeringTrafficSummary {
    param([object]$Flow)

    # One card line, seen from the VNet whose page it is on. The tooltip names the VNets.
    if (-not $Flow.Connected) { return "<font color='#b91c1c'>Traffic: none, not connected</font>" }
    if ($Flow.Outbound -and $Flow.Inbound -eq $true) { return 'Traffic: both ways' }
    if ($Flow.Outbound -and $Flow.Inbound -eq $false) { return 'Traffic: outbound only' }
    if ($Flow.Outbound) { return 'Traffic: outbound, inbound unknown' }
    if ($Flow.Inbound -eq $true) { return 'Traffic: inbound only' }
    if ($Flow.Inbound -eq $false) { return "<font color='#b91c1c'>Traffic: none, access blocked</font>" }
    return 'Traffic: outbound blocked, inbound unknown'
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
        [ValidateRange(1,4)][int]$ResourcesPerRow,
        [hashtable]$PlacedVnetIdsByResourceId,
        [string]$CollectedAt = ''
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
    foreach ($pair in ([ordered]@{dx='1422';dy='794';grid='0';gridSize='10';guides='1';tooltips='1';connect='1';arrows='1';fold='1';page='1';pageScale='1';pageWidth='2100';pageHeight='1200';math='0';shadow='0'}).GetEnumerator()) {
        Set-XmlAttribute $model $pair.Key $pair.Value
    }
    Set-MxPageTheme $model
    $null = $diagram.AppendChild($model)
    $root = $Document.CreateElement('root')
    $null = $model.AppendChild($root)
    $baseCell = Add-MxBaseCell $Document $root
    Add-MxVertex -Document $Document -Root $root -Id 'overview-link' -Parent '1' `
        -Value '&#8592; Network overview' `
        -Style 'rounded=1;whiteSpace=wrap;html=1;fillColor=#e6f2ff;strokeColor=#0078d4;fontColor=#0078d4;fontStyle=1;' `
        -X 20 -Y 15 -Width 220 -Height 30 -Attributes @{link='data:page/id,network-overview';tooltip='Open the network overview page'}

    # A VNet without subnets has no index entry, and piping that $null would draw one empty subnet.
    $subnets = @($Index.SubnetsByVnetId[$vnetId] | Where-Object { $null -ne $_ })
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
        $connectionState=[string](Get-ObjectValue $pe 'connectionState' '')
        # Captioned because a bare "blob" or "Approved" does not say what it is: the target
        # sub-resource (groupIds) and the state of the connection to the target.
        $peLines=@("<b>$name</b>")
        if($groups){$peLines+="$(if($groups -like '*,*'){'Sub-resources'}else{'Sub-resource'}): $groups"}
        if($connectionState){$peLines+="<font color='#666666'>Connection: $connectionState</font>"}
        Add-GraphNode $nodes $UsedResourceIds $id $name PrivateEndpoint 'Microsoft.Network/privateEndpoints' ($peLines -join '<br>') Internal $subnetId
        foreach ($nicId in @(Get-IdsFromJson (Get-ObjectValue $pe 'networkInterfaces' ''))) {
            Add-GraphEdge $edges $edgeKeys $id $nicId 'uses NIC' Attachment
        }
        foreach ($target in $targets) {
            $targetName=Get-ResourceNameFromId $target
            # The target is not queried, so where it lives is read from its ID; the
            # subscription is named when it is part of this export. A bare subscription ID
            # does not fit the node, and the full resource ID is in the tooltip anyway.
            $targetScope=''
            if ($target -match '^/subscriptions/([^/]+)/resourcegroups/([^/]+)/') {
                $targetResourceGroup=$Matches[2]; $targetSubscriptionId=ConvertTo-ResourceId $Matches[1]; $targetSubscription='other subscription'
                if ($Index.SubscriptionById.ContainsKey($targetSubscriptionId)) {
                    $knownName=[string](Get-ObjectValue $Index.SubscriptionById[$targetSubscriptionId] 'subscriptionName' '')
                    $targetSubscription=if ($knownName) { $knownName } else { $targetSubscriptionId }
                }
                $targetScope="<br><font color='#666666'>RG: $targetResourceGroup | $targetSubscription</font>"
            }
            Add-GraphNode $nodes $UsedResourceIds $target $targetName PrivateLinkTarget 'Azure linked resource' "<b>$targetName</b>$targetScope" Connectivity
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
            # One or two routes, the common case, are spelled out on the card; longer tables
            # keep the count. The hover text lists every route either way.
            $routeDescriptions=@();if($route){$routeDescriptions=@(ConvertFrom-JsonCollection (Get-ObjectValue $route 'routes' '') | ForEach-Object { Get-RouteDescription $_ $Index })}
            $routeSummary=if($routeDescriptions.Count -ge 1 -and $routeDescriptions.Count -le 2){($routeDescriptions|ForEach-Object{$_.Card}) -join '<br>'}else{"Routes: $count"}
            if($route){
                $shownRoutes=@($routeDescriptions|Select-Object -First 25|ForEach-Object{$_.Tooltip})
                if($routeDescriptions.Count -gt 25){$shownRoutes+="... $($routeDescriptions.Count - 25) more on the route table page"}
                $bgp=if((ConvertTo-NullableBoolean (Get-ObjectValue $route 'disableBgpRoutePropagation')) -eq $true){'off'}else{'on'}
                $routeTooltip=@('Routes configured in this table, not the effective routes Azure applies:')+$shownRoutes+"BGP route propagation: $bgp"
                $attributes.tooltip=(@(@($attributes['tooltip'])|Where-Object{$_})+$routeTooltip) -join "`n"
            }
            Add-GraphNode $nodes $UsedResourceIds $routeId $name RouteTable 'Microsoft.Network/routeTables' "<b>$name</b><br>$routeSummary<br><font color='#0078d4'>Open routes</font>" Security '' $attributes
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
            $circuitDetails=@(Get-ExpressRouteCircuitDetail $circuit)
            Add-GraphNode $nodes $UsedResourceIds $circuitId $circuitName ExpressRouteCircuit 'Microsoft.Network/expressRouteCircuits' "<b>$circuitName</b><br>$($circuitDetails -join '<br>')" External
            $endpointIds.Add($circuitId)
        }

        if($endpointIds.Count -eq 0){
            $unresolvedId="$connectionId/unresolved-remote-endpoint"
            Add-GraphNode $nodes $UsedResourceIds $unresolvedId 'Unresolved remote endpoint' GenericExternal '' '<b>Unresolved remote endpoint</b><br><font color=''#666666''>Endpoint ID was not returned</font>' External
            $endpointIds.Add($unresolvedId)
        }
        foreach($endpointId in $endpointIds){
            Add-GraphEdge $edges $edgeKeys $localGatewayId $endpointId $connectionLabel Hybrid $connectionId 'Microsoft.Network/connections' @{tooltip=$connectionTooltip} `
                -KindStyle (Get-ConnectionLineStyle -Established (Test-ConnectionEstablished $connectionState))
        }
        $null=$renderedConnectionIds.Add($connectionId)
        $null=$UsedResourceIds.Add($connectionId)
    }

    # Above this many sites behind one VPN gateway, one summary node replaces them, since
    # every spoke connected to the hub would otherwise repeat every branch.
    $maximumDrawnVpnSites = 5
    $vpnSiteIdsByCollapsedNodeId = @{}
    # Gateways and firewalls are parts of the hub rather than paths with a direction, so
    # their lines carry no arrowheads.
    $hubComponentStyle = 'strokeColor=#9673a6;strokeWidth=2;startArrow=none;endArrow=none;'
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
        $connectionName = [string](Get-ObjectValue $hubConnection 'name' 'Virtual WAN connection')
        $connectionState = [string](Get-ObjectValue $hubConnection 'provisioningState' '')
        $connectionLabel = if ($connectionState) { "$connectionName | $connectionState" } else { $connectionName }
        # The connection is named on the hub, not on its connector: connectors from the
        # VNet share one trunk, where labels would pile up.
        Add-GraphNode $nodes $UsedResourceIds $hubId $hubName VirtualHub 'Microsoft.Network/virtualHubs' `
            "<b>$hubName</b><br>$((@($hubDetails) + "<font color='#666666'>Connection: $connectionLabel</font>") -join '<br>')" External
        Add-GraphEdge $edges $edgeKeys $vnetId $hubId $connectionLabel Hybrid $connectionId `
            'Microsoft.Network/virtualHubs/hubVirtualNetworkConnections' -KindStyle (Get-ConnectionLineStyle -Established (Test-ConnectionEstablished $connectionState))
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
            Add-GraphEdge $edges $edgeKeys $hubId $gatewayId 'ExpressRoute gateway' Hybrid -KindStyle $hubComponentStyle
            # Each connection reaches a circuit through one of its peerings.
            foreach ($expressRouteConnection in @($Index.ExpressRouteConnectionsByGatewayId[$gatewayId] | Where-Object { $null -ne $_ })) {
                $circuitId = ConvertTo-ResourceId ([string](Get-ObjectValue $expressRouteConnection 'circuitPeeringId' '') -replace '/peerings/[^/]+$', '')
                if (-not $circuitId) { continue }
                $circuit = if ($Index.ExpressRouteCircuitById.ContainsKey($circuitId)) { $Index.ExpressRouteCircuitById[$circuitId] } else { $null }
                $circuitName = if ($circuit) { [string](Get-ObjectValue $circuit 'name' (Get-ResourceNameFromId $circuitId)) } else { Get-ResourceNameFromId $circuitId }
                $circuitDetails = @(Get-ExpressRouteCircuitDetail $circuit)
                if (-not $circuit) { $circuitDetails = @("<font color='#666666'>Circuit not in this export</font>") }
                Add-GraphNode $nodes $UsedResourceIds $circuitId $circuitName ExpressRouteCircuit 'Microsoft.Network/expressRouteCircuits' `
                    "<b>$circuitName</b><br>$($circuitDetails -join '<br>')" External
                $expressRouteConnectionName = [string](Get-ObjectValue $expressRouteConnection 'connectionName' 'ExpressRoute connection')
                $expressRouteConnectionState = [string](Get-ObjectValue $expressRouteConnection 'connectionState' '')
                $peeringName = [string](Get-ObjectValue $expressRouteConnection 'circuitPeeringId' '') -replace '^.*/peerings/', ''
                $expressRouteConnectionLabel = if ($expressRouteConnectionState) { "$expressRouteConnectionName | $expressRouteConnectionState" } else { $expressRouteConnectionName }
                Add-GraphEdge $edges $edgeKeys $gatewayId $circuitId $expressRouteConnectionLabel Hybrid "$gatewayId/expressrouteconnections/$(([string]$expressRouteConnectionName).ToLowerInvariant())" `
                    'Microsoft.Network/expressRouteGateways/expressRouteConnections' @{ tooltip = "Connection: $expressRouteConnectionName`nCircuit peering: $peeringName`nState: $expressRouteConnectionState" } `
                    -KindStyle (Get-ConnectionLineStyle -Established (Test-ConnectionEstablished $expressRouteConnectionState))
            }
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
            Add-GraphEdge $edges $edgeKeys $hubId $firewallId 'hub firewall' Hybrid -KindStyle $hubComponentStyle
        }
        foreach ($p2sGateway in @($Index.P2sVpnGatewaysByHubId[$hubId] | Where-Object { $null -ne $_ })) {
            $p2sGatewayId = ConvertTo-ResourceId (Get-ObjectValue $p2sGateway 'id')
            if (-not $p2sGatewayId) { continue }
            $p2sGatewayName = [string](Get-ObjectValue $p2sGateway 'name' (Get-ResourceNameFromId $p2sGatewayId))
            $configurations = @(ConvertFrom-JsonCollection (Get-ObjectValue $p2sGateway 'connectionConfigurations' ''))
            $clientPools = @(Select-UniqueValue @(Get-ClientPoolPrefix $configurations))
            $configurationNames = @(Select-UniqueValue @($configurations | ForEach-Object { Get-ObjectValue $_ 'name' '' }))
            $p2sDetails = @(
                $(if ($clientPools.Count -gt 0) { "Clients: $($clientPools -join ', ')" }),
                $(if ($configurationNames.Count -gt 0) { "Configurations: $($configurationNames -join ', ')" })
            ) | Where-Object { $_ }
            Add-GraphNode $nodes $UsedResourceIds $p2sGatewayId $p2sGatewayName P2SVpnGateway 'Microsoft.Network/p2sVpnGateways' `
                "<b>$p2sGatewayName</b><br>$(@($p2sDetails) -join '<br>')" External
            Add-GraphEdge $edges $edgeKeys $hubId $p2sGatewayId 'point-to-site gateway' Hybrid -KindStyle $hubComponentStyle
        }
        foreach ($vpnGateway in @($Index.VpnGatewaysByHubId[$hubId] | Where-Object { $null -ne $_ })) {
            $vpnGatewayId = [string]$vpnGateway.Id
            $vpnGatewayItem = $vpnGateway.Rows[0]
            $vpnGatewayName = [string](Get-ObjectValue $vpnGatewayItem 'name' (Get-ResourceNameFromId $vpnGatewayId))
            $gatewayAddresses = @(Select-UniqueValue @(ConvertFrom-JsonCollection (Get-ObjectValue $vpnGatewayItem 'ipConfigurations' '') |
                ForEach-Object { Get-ObjectValue $_ 'publicIpAddress' '' }))
            $scaleUnits = [string](Get-ObjectValue $vpnGatewayItem 'scaleUnits' '')
            $gatewayAsn = [string](Get-ObjectValue $vpnGatewayItem 'bgpAsn' '')
            $vpnGatewayDetails = @(
                $(if ($gatewayAddresses.Count -gt 0) { "Public: $($gatewayAddresses -join ', ')" }),
                ((@($(if ($scaleUnits) { "Scale units: $scaleUnits" }), $(if ($gatewayAsn) { "BGP ASN: $gatewayAsn" })) | Where-Object { $_ }) -join ' | ')
            ) | Where-Object { $_ }
            Add-GraphNode $nodes $UsedResourceIds $vpnGatewayId $vpnGatewayName VpnGateway 'Microsoft.Network/vpnGateways' `
                "<b>$vpnGatewayName</b><br>$(@($vpnGatewayDetails) -join '<br>')" External
            Add-GraphEdge $edges $edgeKeys $hubId $vpnGatewayId 'VPN gateway' Hybrid -KindStyle $hubComponentStyle

            $vpnConnections = @($vpnGateway.Rows | Where-Object { ConvertTo-ResourceId (Get-ObjectValue $_ 'remoteVpnSiteId' '') })
            $siteIds = @($vpnConnections | ForEach-Object { ConvertTo-ResourceId (Get-ObjectValue $_ 'remoteVpnSiteId' '') } | Sort-Object -Unique)
            if ($siteIds.Count -gt $maximumDrawnVpnSites) {
                $siteNames = @($siteIds | ForEach-Object {
                    if ($Index.VpnSiteById.ContainsKey($_)) { [string](Get-ObjectValue $Index.VpnSiteById[$_] 'name' (Get-ResourceNameFromId $_)) } else { Get-ResourceNameFromId $_ }
                } | Sort-Object)
                $siteLines = @(foreach ($siteId in $siteIds) {
                    $siteSummary = Get-VpnSiteSummary $Index.VpnSiteById[$siteId]
                    "$(Get-ResourceNameFromId $siteId): $(if ($siteSummary.Prefixes.Count -gt 0) { $siteSummary.Prefixes -join ', ' } else { 'no static prefixes' })"
                })
                $shownNames = (@($siteNames | Select-Object -First 3) -join ', ') + $(if ($siteNames.Count -gt 3) { ', &#8230;' } else { '' })
                $collapsedId = "$vpnGatewayId/vpn-sites"
                Add-GraphNode $nodes $UsedResourceIds $collapsedId "$($siteIds.Count) VPN sites" VpnSite 'Microsoft.Network/vpnSites' `
                    "<b>$($siteIds.Count) VPN sites</b><br>$shownNames<br><font color='#666666'>Prefixes on the Network Ranges page</font>" External '' `
                    @{ tooltip = ($siteLines -join "`n") }
                # One line stands for several connections: arrowheads when all are established,
                # red when none is, and neither, with counts in the label, for any mix.
                $results = @($vpnConnections | ForEach-Object { Test-ConnectionEstablished ([string](Get-ObjectValue $_ 'connectionStatus' '')) })
                $downCount = @($results | Where-Object { $_ -eq $false }).Count
                $unknownCount = @($results | Where-Object { $null -eq $_ }).Count
                $summaryLabel = "$($vpnConnections.Count) connections"
                if ($downCount -eq 0 -and $unknownCount -eq 0) {
                    $summaryStyle = Get-ConnectionLineStyle -Established $true
                } elseif ($downCount -eq $vpnConnections.Count) {
                    $summaryStyle = Get-ConnectionLineStyle -Established $false
                    $summaryLabel += ', none connected'
                } else {
                    $summaryStyle = Get-ConnectionLineStyle -Established $null
                    if ($downCount -gt 0) { $summaryLabel += ", $downCount not connected" }
                    if ($unknownCount -gt 0) { $summaryLabel += ", $unknownCount status not reported" }
                }
                Add-GraphEdge $edges $edgeKeys $vpnGatewayId $collapsedId $summaryLabel Hybrid -KindStyle $summaryStyle
                $vpnSiteIdsByCollapsedNodeId[$collapsedId] = $siteIds
                foreach ($siteId in $siteIds) { $null = $UsedResourceIds.Add($siteId) }
                continue
            }
            foreach ($vpnConnection in $vpnConnections) {
                $siteId = ConvertTo-ResourceId (Get-ObjectValue $vpnConnection 'remoteVpnSiteId' '')
                $site = if ($Index.VpnSiteById.ContainsKey($siteId)) { $Index.VpnSiteById[$siteId] } else { $null }
                $siteName = if ($site) { [string](Get-ObjectValue $site 'name' (Get-ResourceNameFromId $siteId)) } else { Get-ResourceNameFromId $siteId }
                if ($site) {
                    $siteSummary = Get-VpnSiteSummary $site
                    $siteDetails = @(
                        $(if ($siteSummary.Prefixes.Count -gt 0) { $siteSummary.Prefixes -join ', ' }),
                        ((@($(if ($siteSummary.Endpoints.Count -gt 0) { "Link: $($siteSummary.Endpoints -join ', ')" }),
                            $(if ($siteSummary.Asns.Count -gt 0) { "BGP ASN: $($siteSummary.Asns -join ', ')" })) | Where-Object { $_ }) -join ' | ')
                    ) | Where-Object { $_ }
                } else {
                    $siteDetails = @("<font color='#666666'>Site details not returned</font>")
                }
                Add-GraphNode $nodes $UsedResourceIds $siteId $siteName VpnSite 'Microsoft.Network/vpnSites' `
                    "<b>$siteName</b><br>$(@($siteDetails) -join '<br>')" External
                $vpnConnectionName = [string](Get-ObjectValue $vpnConnection 'connectionName' '')
                if (-not $vpnConnectionName) { $vpnConnectionName = 'VPN connection' }
                $vpnConnectionStatus = [string](Get-ObjectValue $vpnConnection 'connectionStatus' '')
                $vpnConnectionStatusText = if ($vpnConnectionStatus) { $vpnConnectionStatus } else { 'status not reported' }
                $vpnConnectionLabel = "$vpnConnectionName | $vpnConnectionStatusText"
                Add-GraphEdge $edges $edgeKeys $vpnGatewayId $siteId $vpnConnectionLabel Hybrid '' '' `
                    @{ tooltip = "Connection: $vpnConnectionName`nStatus: $(if ($vpnConnectionStatus) { $vpnConnectionStatus } else { 'not reported by Azure for this connection' })" } `
                    -KindStyle (Get-ConnectionLineStyle -Established (Test-ConnectionEstablished $vpnConnectionStatus))
            }
        }
    }

    # Local subnets taking part in a subnet peering, named in their subnet header.
    $subnetPeeringsBySubnetName = @{}
    foreach($peering in @($Index.PeeringsByVnetId[$vnetId] | ForEach-Object { $_ })){
        $remoteId=ConvertTo-ResourceId (Get-ObjectValue $peering 'remoteVnetId');if(-not $remoteId){continue}
        # The peering to a Virtual WAN hub's managed VNet is the hub connection drawn above.
        if(Test-HubManagedPeering $Index $peering){continue}
        $flow=Get-PeeringFlow $Index $peering;$remoteName=$flow.RemoteName
        # Each side of a peering has its own settings; these are this VNet's side, so the
        # card says so rather than suggest they belong to the remote VNet it is drawn on.
        $forwarded=(ConvertTo-NullableBoolean (Get-ObjectValue $peering 'allowForwardedTraffic')) -eq $true
        $gatewayTransit=(ConvertTo-NullableBoolean (Get-ObjectValue $peering 'allowGatewayTransit')) -eq $true
        $useRemoteGateways=(ConvertTo-NullableBoolean (Get-ObjectValue $peering 'useRemoteGateways')) -eq $true
        $settings=@()
        # Short words keep the line from wrapping; gateway transit and remote gateway use
        # never occur on the same side. The tooltip spells the settings out.
        if($forwarded){$settings+='forwarding'}
        if($gatewayTransit){$settings+='gateway transit'}
        if($useRemoteGateways){$settings+='remote gateway'}
        $settingsLine=if($settings.Count -gt 0){"This side: $($settings -join ' &#183; ')"}else{'This side: no forwarding or gateway'}
        $accessText=if($flow.LocalAccess -eq $false){'no'}elseif($flow.LocalAccess -eq $true){'yes'}else{'not collected'}
        $settingsTooltip=@("Settings on $($flow.LocalName)'s side:","VNet access: $accessText","Forwarded traffic: $(if($forwarded){'yes'}else{'no'})","Gateway transit: $(if($gatewayTransit){'yes'}else{'no'})","Uses remote gateway: $(if($useRemoteGateways){'yes'}else{'no'})")
        $peeringName=[string](Get-ObjectValue $peering 'name' 'peering')
        $flowLines=@(Get-PeeringFlowDescription $flow)
        $attributes=@{tooltip=(@("Remote VNet: $remoteName")+$flowLines+$settingsTooltip) -join "`n"};if($PageIdByVnetId.ContainsKey($remoteId)){$attributes.link="data:page/id,$($PageIdByVnetId[$remoteId])"}
        # The card has room for one line of name; a longer one is cut, and the tooltip has it in full.
        $cardPeeringName=if($peeringName.Length -gt 24){"$($peeringName.Substring(0,23))&#8230;"}else{$peeringName}
        $stateText=if($flow.Connected){'Connected'}elseif($flow.HasReverse -and $flow.RemoteState -ne $flow.LocalState){"$($flow.LocalState) / $($flow.RemoteState)"}else{$flow.LocalState}
        if($flow.IsSubnetPeering){$stateText+=' (subnet)'}
        $peeringLine="Peering: $stateText";if($flow.IsOutOfSync){$peeringLine+=" &#183; <font color='#b91c1c'>not in sync</font>"}
        $pageHint=if($attributes.ContainsKey('link')){"<br><font color='#0078d4'>Open VNet page</font>"}else{''}
        Add-GraphNode $nodes $UsedResourceIds $remoteId $remoteName RemoteVNet 'Microsoft.Network/virtualNetworks' "<b>$remoteName</b><br>$peeringLine<br><font color='#666666'>Peering name: $cardPeeringName</font><br>$(Get-PeeringTrafficSummary $flow)<br>$settingsLine$pageHint" External '' $attributes
        Add-GraphEdge -Edges $edges -EdgeKeys $edgeKeys -SourceId $vnetId -TargetId $remoteId -Label $peeringName -Kind Peering `
            -Attributes @{tooltip=($flowLines -join "`n")} -KindStyle (Get-PeeringLineStyle $flow)
        if($flow.IsSubnetPeering){
            $remoteSubnets=if(@($flow.RemoteSubnets).Count -gt 0){" ($(@($flow.RemoteSubnets) -join ', '))"}else{''}
            foreach($subnetName in $flow.LocalSubnets){Add-IndexValue $subnetPeeringsBySubnetName $subnetName "$remoteName$remoteSubnets"}
        }
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
    # space permits; private endpoints always receive a dedicated row, shared
    # with their NIC.
    $internalRowsBySubnetId = @{}
    $internalRowIndexByNodeId = @{}
    foreach ($subnet in $subnets) {
        $sid = ConvertTo-ResourceId (Get-ObjectValue $subnet 'id')
        $internal = @($nodes.Values | Where-Object { $_.Lane -eq 'Internal' -and $_.SubnetId -eq $sid })
        $usedInternalIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $units = [System.Collections.Generic.List[object]]::new()

        $nicNodesByEndpointId = @{}
        $endpointNicIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($edge in @($edges | Where-Object Label -eq 'uses NIC')) {
            $sourceNode = $nodes[$edge.Source]; $targetNode = $nodes[$edge.Target]
            if ($sourceNode -and $targetNode -and $sourceNode.Kind -eq 'PrivateEndpoint' -and $targetNode.Kind -eq 'NIC' -and
                $sourceNode.SubnetId -eq $sid -and $targetNode.SubnetId -eq $sid) {
                Add-IndexValue $nicNodesByEndpointId $sourceNode.Id $targetNode
                $null = $endpointNicIds.Add($targetNode.Id)
            }
        }

        foreach ($nic in @($internal | Where-Object Kind -eq 'NIC' | Sort-Object Name)) {
            if ($endpointNicIds.Contains($nic.Id)) { continue }
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
                # The NIC goes first so the private link connector leaves the
                # endpoint toward the connectivity lane without crossing the NIC.
                $items = [System.Collections.Generic.List[object]]::new()
                if ($nicNodesByEndpointId.ContainsKey($endpoint.Id)) {
                    foreach ($nic in @($nicNodesByEndpointId[$endpoint.Id] | Sort-Object Name)) {
                        if ($usedInternalIds.Add($nic.Id)) { $items.Add($nic) }
                    }
                }
                $items.Add($endpoint)
                $units.Add([pscustomobject]@{Items=@($items);OwnRow=$true})
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
                # A dedicated unit wider than -ResourcesPerRow continues on the next row.
                for ($start = 0; $start -lt $unitItems.Count; $start += $ResourcesPerRow) {
                    $end = [math]::Min($start + $ResourcesPerRow, $unitItems.Count) - 1
                    $rows.Add([pscustomobject]@{Items=@($unitItems[$start..$end])})
                }
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
    $preferredRowByNodeId = @{}; $placementRankByNodeId = @{}
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
        # Nodes claim rows closest link first: one linked directly to a single row, such as a
        # private endpoint's target or a NIC's public IP, before one linked to several rows,
        # one reached only through other nodes, and one tied to the whole subnet.
        $placementRankByNodeId[$sideNode.Id] = if ($matchedRows.Count -gt 0) { (($depth - 1) * 1000) + @($matchedRows | Sort-Object -Unique).Count } else { [int]::MaxValue }
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
            $anchoredNodes = @($placementDefinition.Nodes | Where-Object { $anchorByNodeId[$_.Id] -eq $sid } |
                Sort-Object @{Expression={ if ($placementRankByNodeId.ContainsKey($_.Id)) { $placementRankByNodeId[$_.Id] } else { [int]::MaxValue } }},
                    @{Expression={ if ($preferredRowByNodeId.ContainsKey($_.Id)) { $preferredRowByNodeId[$_.Id] } else { 0 } }}, Kind, Name)
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
    $unanchoredExternal = @(Get-ExternalLaneOrder -Nodes @($externalNodes | Where-Object { -not $anchorByNodeId.ContainsKey($_.Id) }) -Edges $edges)
    $vnetX = 280; $vnetY = 60; $vnetWidth = 950
    $vnetHeight = [math]::Max(250, $currentY + 5)

    # Remote and hybrid resources not tied to a subnet first fill the free rows of their
    # lane beside the VNet, top down and around the rows subnet-bound nodes occupy, so a
    # large VNet does not also grow a long tail below it. Only what does not fit continues
    # below the VNet. Values are lane-relative y.
    $occupiedExternalRows = @(foreach ($layout in $layouts) {
        foreach ($placement in @($externalPlacementsBySubnetId[$layout.Id])) {
            $layout.Y + $subnetHeaderHeight + 10 + ($placement.Slot * $resourceRowPitch)
        }
    })
    $besideExternalYById = @{}
    $belowExternal = [System.Collections.Generic.List[object]]::new()
    $candidateY = 48
    foreach ($node in $unanchoredExternal) {
        if ($belowExternal.Count -eq 0) {
            do {
                $overlaps = @($occupiedExternalRows | Where-Object { $candidateY -lt $_ + $resourceRowPitch -and $_ -lt $candidateY + $resourceRowPitch })
                if ($overlaps.Count -gt 0) { $candidateY = ($overlaps | Measure-Object -Maximum).Maximum + $resourceRowPitch }
            } while ($overlaps.Count -gt 0)
            if ($candidateY + $resourceNodeHeight -le $vnetHeight) {
                $besideExternalYById[$node.Id] = $candidateY
                $candidateY += $resourceRowPitch
                continue
            }
        }
        $belowExternal.Add($node)
    }
    $maximumUnanchoredCount=[math]::Max($unanchoredSecurity.Count,[math]::Max($unanchoredConnectivity.Count,$belowExternal.Count))
    $unanchoredHeight = if ($maximumUnanchoredCount -gt 0) {
        55 + ($maximumUnanchoredCount * $resourceRowPitch)
    } else { 0 }
    $laneHeight = $vnetHeight + $unanchoredHeight

    $attachedResourceCount=@($nodes.Values|Where-Object{$_.Kind -notin @('RemoteVNet','PrivateLinkTarget')}).Count
    $publicIpCount=@($nodes.Values|Where-Object Kind -eq 'PublicIP').Count
    $nsgCount=@($nodes.Values|Where-Object Kind -eq 'NSG').Count
    # A VNet without peerings has no index entry, and @($null) would count as one.
    $peeringCount=@($Index.PeeringsByVnetId[$vnetId] | Where-Object { $_ -and (Get-ObjectValue $_ 'remoteVnetId' '') -and -not (Test-HubManagedPeering $Index $_) }).Count
    $hybridResourceIds=[System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach($node in $nodes.Values|Where-Object{$_.Kind -in @('Gateway','RemoteGateway','LocalNetworkGateway','ExpressRouteCircuit','ExpressRouteGateway','VirtualHub','VpnGateway','P2SVpnGateway','VpnSite')}){
        # A summary node stands for several VPN sites, so count the sites it replaces.
        if($vpnSiteIdsByCollapsedNodeId.ContainsKey($node.Id)){foreach($siteId in $vpnSiteIdsByCollapsedNodeId[$node.Id]){$null=$hybridResourceIds.Add($siteId)}}else{$null=$hybridResourceIds.Add($node.Id)}
    }
    foreach($connectionId in $renderedConnectionIds){$null=$hybridResourceIds.Add($connectionId)}
    $hybridCount=$hybridResourceIds.Count
    $bastionCount=@($nodes.Values|Where-Object Kind -eq 'Bastion').Count
    $summary="<b>VNet inventory</b> &nbsp; Subnets: $($subnets.Count) &nbsp; | &nbsp; Attached resources: $attachedResourceCount &nbsp; | &nbsp; Public IPs: $publicIpCount &nbsp; | &nbsp; NSGs: $nsgCount &nbsp; | &nbsp; Peerings: $peeringCount &nbsp; | &nbsp; Gateways &amp; connections: $hybridCount &nbsp; | &nbsp; Bastion: $bastionCount"
    # Repeated from the overview so a single page exported on its own still carries the date.
    if($CollectedAt){$summary+=" &nbsp; | &nbsp; Data collected $CollectedAt"}
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
    Add-MxVertex $Document $root 'external-lane' '1' '<b>Peerings &amp; gateway connections</b>' `
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
        $isDelegated = [bool]$delegationNames
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
        } elseif ($occupants.Count -eq 0 -and $isDelegated) {
            # A delegated service such as AKS virtual nodes or Application Gateway for
            # Containers can use the subnet without the subnet referencing it, so "none"
            # would wrongly suggest an unused subnet. Matches "Service-managed" on the
            # Network Ranges page.
            $occupancyText = 'service-managed (delegated) - Azure reports no resource here'
            $occupancyColor = '#666666'
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
        # A subnet peering reaches only the subnets it names, so they are marked here.
        $subnetName = [string](Get-ObjectValue $subnet 'name' '')
        if ($subnetName -and $subnetPeeringsBySubnetName.ContainsKey($subnetName)) {
            $label += "<br><font color='#666666'><b>Subnet peering:</b> $(@($subnetPeeringsBySubnetName[$subnetName]) -join ', ')</font>"
        }
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
                Add-MxVertex $Document $root $node.CellId $cell $node.Label (Get-AzureNodeStyle $node.Kind -ResourceType $node.ResourceType -ResourceId $node.Id) `
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
                (Get-AzureNodeStyle $node.Kind '#ffffff' '#82b366' $node.ResourceType $node.Id) 12 ($sideY + ($placement.Slot * $resourceRowPitch)) 226 $resourceNodeHeight `
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
            (Get-AzureNodeStyle $node.Kind '#ffffff' '#82b366' $node.ResourceType $node.Id) 12 ($unanchoredY + ($i * $resourceRowPitch)) 226 $resourceNodeHeight `
            $node.Id $node.ResourceType $node.Attributes
        $i++
    }
    $i = 0
    $unanchoredExternalCenterYById = @{}
    foreach ($node in $unanchoredExternal) {
        $externalNumber++; $node.CellId = "external-$externalNumber"
        if ($besideExternalYById.ContainsKey($node.Id)) {
            $nodeY = $besideExternalYById[$node.Id]
        } else {
            $nodeY = $unanchoredY + ($i * $resourceRowPitch); $i++
        }
        Add-MxVertex $Document $root $node.CellId 'external-lane' $node.Label `
            (Get-AzureNodeStyle $node.Kind '#ffffff' '#9673a6') 12 $nodeY 256 $resourceNodeHeight `
            $node.Id $node.ResourceType $node.Attributes
        $unanchoredExternalCenterYById[$node.Id] = $vnetY + $nodeY + ($resourceNodeHeight / 2)
    }

    $cellById = @{$vnetId='vnet'}
    foreach ($sid in $subnetCellById.Keys) { $cellById[$sid] = $subnetCellById[$sid] }
    foreach ($node in $nodes.Values) { if ($node.CellId) { $cellById[$node.Id] = $node.CellId } }
    $renderableEdges = @($edges | Where-Object { $cellById.ContainsKey($_.Source) -and $cellById.ContainsKey($_.Target) })
    $layerIdByKind = Add-MxPageLayer $Document $root $baseCell `
        @($renderableEdges | ForEach-Object { [string]$_.Kind } | Sort-Object -Unique)
    $edgeNumber = 0; $connectorUseCount = @{}; $externalOverhang = 0
    foreach ($edge in $renderableEdges) {
        $edgeNumber++
        $style = Get-PageConnectorStyle -Edge $edge -Nodes $nodes -SubnetIds $subnetIds -VnetId $vnetId
        $channelKey = "$($edge.Source)|$($edge.Kind)"
        $channelNumber = if ($connectorUseCount.ContainsKey($channelKey)) { [int]$connectorUseCount[$channelKey] } else { 0 }
        $connectorUseCount[$channelKey] = $channelNumber + 1
        $jettySize = [math]::Min(84, 20 + ($channelNumber * 8))
        $style += "jettySize=$jettySize;"
        # A label cannot fit cleanly in the small gap between a NIC and its paired
        # VM or private endpoint. Their placement and connector already make the
        # relationship clear, so keep this short attachment line intentionally unlabeled.
        # Peerings and hub connections from the VNet are named on their target node.
        $fromVnetToRemote = $edge.Source -eq $vnetId -and $nodes.ContainsKey($edge.Target) -and $nodes[$edge.Target].Lane -eq 'External'
        $displayLabel = if ($edge.Label -eq 'uses NIC' -or $fromVnetToRemote) { '' } else { $edge.Label }
        $points = @()
        if ($fromVnetToRemote -and $unanchoredExternalCenterYById.ContainsKey($edge.Target)) {
            # Leave through the VNet's right edge near the top, where the connectivity lane is
            # always empty (below its header, above the first subnet's rows at 216), cross
            # it there, and run down the gap between the connectivity and remote lanes to the
            # target, whether beside the VNet or below it. Connectors of one kind share this
            # trunk, so it stays clear of every node however many targets there are.
            $trunk = if ($edge.Kind -eq 'Hybrid') { 1 } else { 0 }
            $bandY = $vnetY + 58 + ($trunk * 12)
            $gapX = $externalX - 14 - ($trunk * 12)
            $style = ($style -replace 'edgeStyle=orthogonalEdgeStyle;', 'edgeStyle=none;') `
                -replace 'exitX=[^;]*;exitY=[^;]*;', "exitX=1;exitY=$([math]::Round(($bandY - $vnetY) / $vnetHeight, 4));"
            $points = @(
                [pscustomobject]@{ X = $gapX; Y = $bandY },
                [pscustomobject]@{ X = $gapX; Y = $unanchoredExternalCenterYById[$edge.Target] }
            )
        }
        # Connectors between two remote/hybrid nodes run beyond the nodes' right edge,
        # with their label centred on that run; the page must be wide enough for both.
        if ($nodes.ContainsKey($edge.Source) -and $nodes.ContainsKey($edge.Target) -and
            $nodes[$edge.Source].Lane -eq 'External' -and $nodes[$edge.Target].Lane -eq 'External') {
            $externalOverhang = [math]::Max($externalOverhang, $jettySize + 8 + ([string]$displayLabel).Length * 3)
        }
        $layerId = if ($layerIdByKind.ContainsKey($edge.Kind)) { [string]$layerIdByKind[$edge.Kind] } else { '1' }
        Add-MxEdge $Document $root "edge-$edgeNumber" $cellById[$edge.Source] $cellById[$edge.Target] $displayLabel $style $edge.AzureId $edge.ResourceType $edge.Attributes `
            -Parent $layerId -Points $points
    }
    $legendY = $vnetY + $laneHeight + 25
    Add-PageLegend $Document $root $legendY 1820
    # Remote/hybrid nodes end 268 px into their 280 px lane.
    $contentRight = [math]::Max(1840, [math]::Max($externalX + 280, $externalX + 268 + $externalOverhang))
    Set-MxPageSize $model $contentRight ($legendY + 54)

    # Lets the Network Ranges page name the VNet a resource belongs to from what this
    # page actually drew, instead of re-deriving the relationships.
    if ($null -ne $PlacedVnetIdsByResourceId) {
        foreach ($node in $nodes.Values) {
            if ($node.CellId) { Add-IndexValue $PlacedVnetIdsByResourceId $node.Id $vnetId }
        }
    }
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
        @{Data='virtualHubs';Id='id';Name='name';Kind='VirtualHub';Type='Microsoft.Network/virtualHubs'},@{Data='hubVirtualNetworkConnections';Id='id';Name='name';Kind='HubConnection';Type='Microsoft.Network/virtualHubs/hubVirtualNetworkConnections'},
        @{Data='vpnGateways';Id='id';Name='name';Kind='VpnGateway';Type='Microsoft.Network/vpnGateways'},@{Data='p2sVpnGateways';Id='id';Name='name';Kind='P2SVpnGateway';Type='Microsoft.Network/p2sVpnGateways'},
        @{Data='vpnSites';Id='id';Name='name';Kind='VpnSite';Type='Microsoft.Network/vpnSites'}
    )
    $result=@{};foreach($definition in $definitions){foreach($row in Get-DataRows $Data $definition.Data){$id=ConvertTo-ResourceId(Get-ObjectValue $row $definition.Id);if(-not$id-or$UsedResourceIds.Contains($id)-or$result.ContainsKey($id)){continue};$name=[string](Get-ObjectValue $row $definition.Name (Get-ResourceNameFromId $id));$result[$id]=[pscustomobject]@{Id=$id;Name=$name;Kind=$definition.Kind;Type=$definition.Type;Location=[string](Get-ObjectValue $row 'location' '');ResourceGroup=[string](Get-ObjectValue $row 'resourceGroup' '')}}};return @($result.Values|Sort-Object Kind,Name)
}

function New-UnmappedDrawIoPage {
    param([System.Xml.XmlDocument]$Document,[System.Xml.XmlElement]$MxFile,[object[]]$Resources,[hashtable]$DetailPageIdByResourceId)
    if($Resources.Count-eq0){return $false};$diagram=$Document.CreateElement('diagram');Set-XmlAttribute $diagram 'id' 'unmapped-resources';Set-XmlAttribute $diagram 'name' 'Unmapped Resources';$null=$MxFile.AppendChild($diagram);$model=$Document.CreateElement('mxGraphModel');foreach($pair in ([ordered]@{dx='1422';dy='794';grid='0';gridSize='10';guides='1';tooltips='1';connect='1';arrows='1';fold='1';page='1';pageScale='1';pageWidth='1800';pageHeight='1200';math='0';shadow='0'}).GetEnumerator()){Set-XmlAttribute $model $pair.Key $pair.Value};Set-MxPageTheme $model;$null=$diagram.AppendChild($model);$root=$Document.CreateElement('root');$null=$model.AppendChild($root);$null=Add-MxBaseCell $Document $root
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
    foreach($pair in ([ordered]@{dx='1422';dy='794';grid='0';gridSize='10';guides='1';tooltips='1';connect='1';arrows='1';fold='1';page='1';pageScale='1';pageWidth=[string]$PageWidth;pageHeight=[string]$PageHeight;math='0';shadow='0'}).GetEnumerator()){Set-XmlAttribute $model $pair.Key $pair.Value}
    Set-MxPageTheme $model
    $null=$diagram.AppendChild($model);$root=$Document.CreateElement('root');$null=$model.AppendChild($root)
    $baseCell=Add-MxBaseCell $Document $root
    return [pscustomobject]@{Diagram=$diagram;Model=$model;Root=$root;BaseCell=$baseCell}
}

function Test-HubManagedPeering {
    param([object]$Index, [object]$Peering)

    # A Virtual WAN connection can also appear as a peering from the spoke to the hub's
    # Microsoft-managed VNet, named HV_<hub>_<id>. Where the VNet has a hub connection, that
    # peering is the same link, so it is not drawn or counted a second time.
    $remoteName = Get-ResourceNameFromId (ConvertTo-ResourceId (Get-ObjectValue $Peering 'remoteVnetId' ''))
    if ($remoteName -notlike 'HV_*') { return $false }
    $localId = ConvertTo-ResourceId (Get-ObjectValue $Peering 'vnetId' '')
    return @($Index.HubConnectionsByVnetId[$localId] | Where-Object { $null -ne $_ }).Count -gt 0
}

function Get-GatewayVnetId {
    param([object]$Index, [string]$GatewayId)

    # A virtual network gateway belongs to the VNet of its GatewaySubnet. Returns '' for a
    # gateway that is not in the export.
    $id = ConvertTo-ResourceId $GatewayId
    if (-not $id -or -not $Index.GatewayRelationById.ContainsKey($id)) { return '' }
    foreach ($subnetId in @($Index.GatewayRelationById[$id].SubnetIds)) {
        if ([string]$subnetId -match '^(.*/virtualnetworks/[^/]+)/subnets/') { return (ConvertTo-ResourceId $Matches[1]) }
    }
    return ''
}

function Get-OverviewConnection {
    param([object]$Data, [object]$Index, [System.Collections.Generic.HashSet[string]]$ShownIds)

    # Every link that touches a card on the overview: peerings, Virtual WAN hub connections,
    # and VNet-to-VNet VPN connections, one entry per pair. The source is on the overview
    # wherever one side is, so a line to the outside section starts at its card. A VPN
    # connection whose far gateway is not in the export has no card to reach; it is
    # returned per VNet for that VNet's tooltip.
    $connections = [System.Collections.Generic.List[object]]::new()
    $pairKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $rows = @(Get-DataRows $Data 'vnetPeerings')
    $rows = @($rows | Where-Object { $ShownIds.Contains((ConvertTo-ResourceId (Get-ObjectValue $_ 'vnetId' ''))) }) +
        @($rows | Where-Object { -not $ShownIds.Contains((ConvertTo-ResourceId (Get-ObjectValue $_ 'vnetId' ''))) })
    foreach ($peering in $rows) {
        $localId = ConvertTo-ResourceId (Get-ObjectValue $peering 'vnetId' '')
        $remoteId = ConvertTo-ResourceId (Get-ObjectValue $peering 'remoteVnetId' '')
        if (-not $localId -or -not $remoteId) { continue }
        if (-not $ShownIds.Contains($localId) -and -not $ShownIds.Contains($remoteId)) { continue }
        if (Test-HubManagedPeering $Index $peering) { continue }
        if (-not $pairKeys.Add("peering|$(@($localId, $remoteId | Sort-Object) -join '|')")) { continue }
        $flow = Get-PeeringFlow $Index $peering
        $connections.Add([pscustomobject]@{
            Kind = 'Peering'; SourceId = $localId; TargetId = $remoteId; Established = $flow.Connected
            Flow = $flow; Row = $peering; Names = @($flow.LocalPeeringName); States = @($flow.LocalState)
        })
    }
    foreach ($hubConnection in $Index.HubConnections) {
        $vnetId = ConvertTo-ResourceId (Get-ObjectValue $hubConnection 'remoteVnetId' '')
        $hubId = ConvertTo-ResourceId (Get-ObjectValue $hubConnection 'virtualHubId' '')
        if (-not $vnetId -or -not $hubId) { continue }
        if (-not $ShownIds.Contains($vnetId) -and -not $ShownIds.Contains($hubId)) { continue }
        $state = [string](Get-ObjectValue $hubConnection 'provisioningState' '')
        $sourceId, $targetId = if ($ShownIds.Contains($vnetId)) { $vnetId, $hubId } else { $hubId, $vnetId }
        $connections.Add([pscustomobject]@{
            Kind = 'Hub'; SourceId = $sourceId; TargetId = $targetId; Established = (Test-ConnectionEstablished $state)
            Flow = $null; Row = $hubConnection; Names = @([string](Get-ObjectValue $hubConnection 'name' '')); States = @($state)
        })
    }
    # Each side of a VNet-to-VNet VPN is its own connection resource; the two become one line.
    $vpnByKey = [ordered]@{}
    $unresolvedVpnByVnetId = @{}
    foreach ($gatewayConnection in Get-DataRows $Data 'gatewayConnections') {
        if ([string](Get-ObjectValue $gatewayConnection 'connectionType' '') -ne 'Vnet2Vnet') { continue }
        $gateway1 = ConvertTo-ResourceId (Get-ObjectValue $gatewayConnection 'vnetGateway1Id' '')
        $gateway2 = ConvertTo-ResourceId (Get-ObjectValue $gatewayConnection 'vnetGateway2Id' '')
        $vnet1 = Get-GatewayVnetId $Index $gateway1
        $vnet2 = Get-GatewayVnetId $Index $gateway2
        $name = [string](Get-ObjectValue $gatewayConnection 'name' '')
        $state = [string](Get-ObjectValue $gatewayConnection 'connectionStatus' '')
        if (-not $state) { $state = [string](Get-ObjectValue $gatewayConnection 'provisioningState' '') }
        if ($vnet1 -and $vnet2) {
            if ($vnet1 -eq $vnet2 -or (-not $ShownIds.Contains($vnet1) -and -not $ShownIds.Contains($vnet2))) { continue }
            $key = "vpn|$(@($vnet1, $vnet2 | Sort-Object) -join '|')"
            if (-not $vpnByKey.Contains($key)) {
                $sourceId, $targetId = if ($ShownIds.Contains($vnet1)) { $vnet1, $vnet2 } else { $vnet2, $vnet1 }
                $vpnByKey[$key] = [pscustomobject]@{
                    Kind = 'Vpn'; SourceId = $sourceId; TargetId = $targetId; Established = $true; Flow = $null; Row = $gatewayConnection
                    Names = [System.Collections.Generic.List[string]]::new(); States = [System.Collections.Generic.List[string]]::new()
                }
            }
            $vpn = $vpnByKey[$key]
            $vpn.Names.Add($name); $vpn.States.Add($state)
            # One side down makes the pair down; otherwise one side without a state leaves it unknown.
            $sideEstablished = Test-ConnectionEstablished $state
            if ($sideEstablished -eq $false) { $vpn.Established = $false } elseif ($null -eq $sideEstablished -and $vpn.Established -eq $true) { $vpn.Established = $null }
        } else {
            $knownVnetId = if ($vnet1) { $vnet1 } else { $vnet2 }
            $farGatewayId = if ($vnet1) { $gateway2 } else { $gateway1 }
            if (-not $knownVnetId -or -not $ShownIds.Contains($knownVnetId)) { continue }
            Add-IndexValue $unresolvedVpnByVnetId $knownVnetId "$name to gateway $(Get-ResourceNameFromId $farGatewayId), not in this export: $state"
        }
    }
    foreach ($vpn in $vpnByKey.Values) { $connections.Add($vpn) }
    return [pscustomobject]@{ Connections = $connections.ToArray(); UnresolvedVpnByVnetId = $unresolvedVpnByVnetId }
}

function Test-ConnectionEstablished {
    param([AllowEmptyString()][string]$State)

    # $true when Azure reports a connection Connected or Succeeded, $false for any other
    # state, and $null when it reports none: a Virtual WAN VPN connection, for one, carries
    # no status of its own, and that says nothing either way.
    if (-not $State) { return $null }
    return ($State -eq 'Connected' -or $State -eq 'Succeeded')
}

function Get-ConnectionLineStyle {
    param([AllowNull()][object]$Established)

    # Virtual WAN and VPN links have no per-direction access setting, so an established one
    # carries both arrowheads, one that is not established is drawn red without any, and one
    # of unknown state has neither arrowheads nor red.
    if ($null -eq $Established) { return 'strokeColor=#9673a6;strokeWidth=2;startArrow=none;endArrow=none;' }
    if (-not $Established) { return 'strokeColor=#b85450;strokeWidth=2;startArrow=none;endArrow=none;' }
    return 'strokeColor=#9673a6;strokeWidth=2;startArrow=classic;startFill=1;endArrow=classic;endFill=1;'
}

function Get-OrderPermutation {
    param([string[]]$Ids)

    # Every ordering of a few IDs, the given order first (Heap's algorithm).
    $current = [string[]]$Ids.Clone()
    $permutations = [System.Collections.Generic.List[object]]::new()
    $permutations.Add([string[]]$current.Clone())
    $counters = New-Object 'int[]' $current.Length
    $i = 0
    while ($i -lt $current.Length) {
        if ($counters[$i] -lt $i) {
            $swapWith = if ($i % 2 -eq 0) { 0 } else { $counters[$i] }
            $held = $current[$swapWith]; $current[$swapWith] = $current[$i]; $current[$i] = $held
            $permutations.Add([string[]]$current.Clone())
            $counters[$i]++; $i = 0
        } else {
            $counters[$i] = 0; $i++
        }
    }
    return $permutations.ToArray()
}

function Get-OverviewSlot {
    param([object[]]$Items, [object[]]$Connections, [int]$Columns = 4)

    # Connected cards are placed next to each other so their lines stay short. Groups of
    # cards linked by peerings, hub connections, or VPN come first, largest first; each
    # starts with its most-connected member, usually a hub, followed outward by its
    # neighbours. Hubs of the same Virtual WAN are connected through the WAN, so they count
    # as linked although no line joins them. Cards linked only to cards elsewhere follow,
    # then unlinked ones, each by name. Returns one slot per grid cell in reading order; a
    # slot without an item is an empty cell.
    $sorted = @($Items | Sort-Object Name, Id)
    $itemById = @{}; $nameRank = @{}; $neighbours = @{}
    for ($i = 0; $i -lt $sorted.Count; $i++) {
        $id = $sorted[$i].Id
        $itemById[$id] = $sorted[$i]; $nameRank[$id] = $i
        $neighbours[$id] = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    }
    $linked = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($connection in $Connections) {
        $sourceId = $connection.SourceId; $targetId = $connection.TargetId
        foreach ($end in @($sourceId, $targetId)) { if ($itemById.ContainsKey($end)) { $null = $linked.Add($end) } }
        if ($sourceId -ne $targetId -and $itemById.ContainsKey($sourceId) -and $itemById.ContainsKey($targetId)) {
            $null = $neighbours[$sourceId].Add($targetId); $null = $neighbours[$targetId].Add($sourceId)
        }
    }
    $hubIdsByWanId = @{}
    foreach ($item in $sorted) { if ($item.Kind -eq 'Hub' -and $item.WanId) { Add-IndexValue $hubIdsByWanId $item.WanId $item.Id } }
    foreach ($hubIds in $hubIdsByWanId.Values) {
        foreach ($hubId in $hubIds) {
            foreach ($otherHubId in $hubIds) {
                if ($hubId -ne $otherHubId) { $null = $neighbours[$hubId].Add($otherHubId); $null = $linked.Add($hubId) }
            }
        }
    }
    $byPriority = @(@{ Expression = { $neighbours[$_].Count }; Descending = $true }, @{ Expression = { $nameRank[$_] } })
    $visited = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $groups = [System.Collections.Generic.List[object]]::new()
    foreach ($id in @($sorted | ForEach-Object { $_.Id })) {
        if ($visited.Contains($id) -or $neighbours[$id].Count -eq 0) { continue }
        $members = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $pending = [System.Collections.Generic.Stack[string]]::new(); $pending.Push($id)
        while ($pending.Count -gt 0) {
            $current = $pending.Pop()
            if ($members.Add($current)) { foreach ($next in $neighbours[$current]) { $pending.Push($next) } }
        }
        # Walk the group breadth-first from its most-connected member.
        $order = [System.Collections.Generic.List[string]]::new()
        $queue = [System.Collections.Generic.Queue[string]]::new()
        $start = @($members | Sort-Object $byPriority)[0]
        $queue.Enqueue($start); $null = $visited.Add($start)
        while ($queue.Count -gt 0) {
            $current = $queue.Dequeue(); $order.Add($current)
            foreach ($next in @($neighbours[$current] | Sort-Object $byPriority)) {
                if ($visited.Add($next)) { $queue.Enqueue($next) }
            }
        }
        # A group that fits in one row takes the ordering whose lines pass the fewest other
        # cards, such as a VNet between the two it links to; the walk order wins ties.
        if ($order.Count -ge 3 -and $order.Count -le $Columns) {
            $best = $null; $bestCost = [int]::MaxValue
            foreach ($candidate in @(Get-OrderPermutation $order.ToArray())) {
                $position = @{}
                for ($p = 0; $p -lt $candidate.Count; $p++) { $position[$candidate[$p]] = $p }
                $cost = 0
                foreach ($memberId in $candidate) {
                    foreach ($otherId in $neighbours[$memberId]) {
                        if ($position[$memberId] -lt $position[$otherId]) { $cost += $position[$otherId] - $position[$memberId] - 1 }
                    }
                }
                if ($cost -lt $bestCost) { $best = $candidate; $bestCost = $cost }
            }
            $order = [System.Collections.Generic.List[string]]::new([string[]]$best)
        }
        $groups.Add([pscustomobject]@{ Ids = $order.ToArray(); Count = $order.Count; FirstRank = $nameRank[$order[0]] })
    }
    $singles = [System.Collections.Generic.Queue[object]]::new()
    foreach ($item in $sorted) { if ($neighbours[$item.Id].Count -eq 0 -and $linked.Contains($item.Id)) { $singles.Enqueue($item) } }
    foreach ($item in $sorted) { if (-not $linked.Contains($item.Id)) { $singles.Enqueue($item) } }
    $slots = [System.Collections.Generic.List[object]]::new()
    foreach ($group in @($groups | Sort-Object @{ Expression = 'Count'; Descending = $true }, FirstRank)) {
        # A group that does not fit in the rest of the current row starts on a new one, so
        # no line has to run from a row's end back to the start of the next. Cards without
        # lines between them fill the cells left over.
        $used = $slots.Count % $Columns
        if ($used -gt 0 -and $used + $group.Count -gt $Columns) {
            while ($slots.Count % $Columns -ne 0) {
                $filler = if ($singles.Count -gt 0) { $singles.Dequeue() } else { $null }
                $slots.Add([pscustomobject]@{ Item = $filler })
            }
        }
        foreach ($id in $group.Ids) { $slots.Add([pscustomobject]@{ Item = $itemById[$id] }) }
    }
    while ($singles.Count -gt 0) { $slots.Add([pscustomobject]@{ Item = $singles.Dequeue() }) }
    return $slots.ToArray()
}

function Get-OverviewVnetSummary {
    param(
        [object]$Index,
        [string]$VnetId,
        [System.Collections.Generic.HashSet[string]]$ShownIds,
        [hashtable]$OneSidedByRemoteId,
        [object[]]$Connections,
        [hashtable]$UnresolvedVpnByVnetId
    )

    # The number of this VNet's peerings for its card, and its tooltip: one line per
    # peering, including peerings to VNets outside this overview and peerings another VNet
    # created toward this one without a peering back, then its Virtual WAN hub and VPN
    # connections.
    $entries = @(
        foreach ($peering in @($Index.PeeringsByVnetId[$VnetId] | Where-Object { $null -ne $_ -and (Get-ObjectValue $_ 'remoteVnetId' '') })) {
            if (Test-HubManagedPeering $Index $peering) { continue }
            $flow = Get-PeeringFlow $Index $peering
            $notes = @($(if ($flow.Connected) { 'connected' } else { $flow.LocalState.ToLowerInvariant() }))
            if ($flow.IsSubnetPeering) { $notes += 'subnet peering' }
            if ($flow.IsOutOfSync) { $notes += 'not in sync' }
            if (-not $ShownIds.Contains($flow.RemoteId)) { $notes += 'outside this overview' }
            [pscustomobject]@{ Name = $flow.RemoteName; Text = "$($flow.RemoteName): $($notes -join ', ')" }
        }
        foreach ($flow in @($OneSidedByRemoteId[$VnetId] | Where-Object { $null -ne $_ })) {
            $notes = @("$($flow.LocalState.ToLowerInvariant()) on $($flow.LocalName)'s side only, no peering back")
            if (-not $ShownIds.Contains($flow.LocalId)) { $notes += 'outside this overview' }
            [pscustomobject]@{ Name = $flow.LocalName; Text = "$($flow.LocalName): $($notes -join ', ')" }
        }
    )
    $tooltip = @()
    if ($entries.Count -gt 0) { $tooltip += 'Peered with:'; $tooltip += @($entries | Sort-Object Name | ForEach-Object { $_.Text }) }
    $hubLines = @(); $vpnLines = @()
    foreach ($connection in @($Connections | Where-Object { $_.Kind -ne 'Peering' -and ($_.SourceId -eq $VnetId -or $_.TargetId -eq $VnetId) })) {
        $otherId = if ($connection.SourceId -eq $VnetId) { $connection.TargetId } else { $connection.SourceId }
        if ($connection.Kind -eq 'Hub') {
            $hubName = if ($Index.VirtualHubById.ContainsKey($otherId)) { [string](Get-ObjectValue $Index.VirtualHubById[$otherId] 'name' (Get-ResourceNameFromId $otherId)) } else { Get-ResourceNameFromId $otherId }
            $hubLines += "$($hubName): $(if ($connection.Established) { 'connected' } elseif ($null -eq $connection.Established) { 'state not reported' } else { ([string]$connection.States[0]).ToLowerInvariant() })"
        } else {
            $otherName = if ($Index.VnetById.ContainsKey($otherId)) { [string](Get-ObjectValue $Index.VnetById[$otherId] 'name' (Get-ResourceNameFromId $otherId)) } else { Get-ResourceNameFromId $otherId }
            $vpnLines += "$($otherName): $(@($connection.States | Select-Object -Unique) -join ' / ')"
        }
    }
    $vpnLines += @($UnresolvedVpnByVnetId[$VnetId] | Where-Object { $_ })
    if ($hubLines.Count -gt 0) { $tooltip += 'Virtual WAN hub:'; $tooltip += $hubLines }
    if ($vpnLines.Count -gt 0) { $tooltip += 'VNet-to-VNet VPN:'; $tooltip += $vpnLines }
    return [pscustomobject]@{ Count = $entries.Count; Tooltip = $tooltip }
}

function Get-OverviewHubCard {
    param([object]$Index, [object]$Hub, [object[]]$Connections)

    # A Virtual WAN hub has no page of its own, so its card names the WAN and its tooltip
    # lists the gateways on the hub and the VNets connected to it.
    $hubId = ConvertTo-ResourceId (Get-ObjectValue $Hub 'id')
    $name = [string](Get-ObjectValue $Hub 'name' (Get-ResourceNameFromId $hubId))
    $wanId = ConvertTo-ResourceId (Get-ObjectValue $Hub 'virtualWanId' '')
    $wanName = if ($wanId) { Get-ResourceNameFromId $wanId } else { '' }
    $hubConnections = @($Connections | Where-Object { $_.Kind -eq 'Hub' -and ($_.SourceId -eq $hubId -or $_.TargetId -eq $hubId) })
    $gateways = @(
        @($Index.ExpressRouteGatewaysByHubId[$hubId] | Where-Object { $null -ne $_ } | ForEach-Object {
            $circuitNames = @($Index.ExpressRouteConnectionsByGatewayId[(ConvertTo-ResourceId (Get-ObjectValue $_ 'id' ''))] | Where-Object { $null -ne $_ } |
                ForEach-Object { Get-ResourceNameFromId ([string](Get-ObjectValue $_ 'circuitPeeringId' '') -replace '/peerings/[^/]+$', '') } | Select-Object -Unique)
            "ExpressRoute $(Get-ObjectValue $_ 'name' '')$(if ($circuitNames.Count -gt 0) { " (circuits: $($circuitNames -join ', '))" })"
        })
        @($Index.VpnGatewaysByHubId[$hubId] | Where-Object { $null -ne $_ } | ForEach-Object { "VPN $(Get-ObjectValue @($_.Rows)[0] 'name' '')" })
        @($Index.P2sVpnGatewaysByHubId[$hubId] | Where-Object { $null -ne $_ } | ForEach-Object { "Point-to-site $(Get-ObjectValue $_ 'name' '')" })
        @($Index.FirewallIdsByHubId[$hubId] | Where-Object { $_ } | ForEach-Object { "Firewall $(Get-ObjectValue @($Index.FirewallRelationById[[string]$_].Rows)[0] 'name' (Get-ResourceNameFromId $_))" })
    )
    $connectedLines = @($hubConnections | ForEach-Object {
        $vnetId = if ($_.SourceId -eq $hubId) { $_.TargetId } else { $_.SourceId }
        $vnetName = if ($Index.VnetById.ContainsKey($vnetId)) { [string](Get-ObjectValue $Index.VnetById[$vnetId] 'name' (Get-ResourceNameFromId $vnetId)) } else { Get-ResourceNameFromId $vnetId }
        "$($vnetName): $(if ($_.Established) { 'connected' } elseif ($null -eq $_.Established) { 'state not reported' } else { ([string]$_.States[0]).ToLowerInvariant() })"
    } | Sort-Object)
    $tooltip = @(
        "Virtual WAN hub $name"
        "Virtual WAN: $(if ($wanName) { $wanName } else { 'not reported' })"
        "Gateways: $(if ($gateways.Count -gt 0) { $gateways -join '; ' } else { 'none' })"
    )
    if ($connectedLines.Count -gt 0) { $tooltip += 'Connected VNets:'; $tooltip += $connectedLines }
    $tooltip += "Whether these VNets reach each other depends on the hub's routing, which is not evaluated."
    $tooltip += $hubId
    $countLine = "Connections: $($hubConnections.Count)"
    if ($wanName) { $countLine = "WAN: $wanName &#183; $countLine" }
    $label = "<b>$name</b><br><font color='#777777'><i>Virtual WAN hub</i></font><br>$(Get-ObjectValue $Hub 'addressPrefix' '')" +
        "<br><font color='#666666'>$(Get-ObjectValue $Hub 'location' '') | $(Get-ObjectValue $Hub 'resourceGroup' '')</font><br>$countLine"
    return [pscustomobject]@{ Label = $label; Tooltip = ($tooltip -join "`n") }
}

function Get-OverviewStatistic {
    param([object[]]$Items, [object]$Index, [object[]]$Connections)

    # Counts for the overview header and each subscription lane, over the cards in the lanes.
    # A peering or VPN counts once per pair: once in the total, and once in each
    # subscription it touches, so one between two subscriptions appears in both lanes.
    $newCounter = {
        [pscustomobject]@{
            Subscriptions = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            Vnets = 0; Subnets = 0; Hubs = 0
            Regions = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            Peerings = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            Vpns = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        }
    }
    $total = & $newCounter
    $bySubscription = @{}
    $subscriptionById = @{}
    foreach ($item in $Items) {
        $subscriptionById[$item.Id] = $item.SubscriptionId
        if (-not $bySubscription.ContainsKey($item.SubscriptionId)) { $bySubscription[$item.SubscriptionId] = & $newCounter }
        $subnetCount = if ($item.Kind -eq 'VNet') { @($Index.SubnetsByVnetId[$item.Id] | Where-Object { $null -ne $_ }).Count } else { 0 }
        $location = [string](Get-ObjectValue $item.Row 'location' '')
        foreach ($counter in @($total, $bySubscription[$item.SubscriptionId])) {
            $null = $counter.Subscriptions.Add($item.SubscriptionId)
            if ($item.Kind -eq 'Hub') { $counter.Hubs++ } else { $counter.Vnets++; $counter.Subnets += $subnetCount }
            if ($location) { $null = $counter.Regions.Add($location) }
        }
    }
    foreach ($connection in $Connections) {
        $property = switch ($connection.Kind) { 'Peering' { 'Peerings' } 'Vpn' { 'Vpns' } default { '' } }
        if (-not $property) { continue }
        $pairKey = @($connection.SourceId, $connection.TargetId | Sort-Object) -join '|'
        $null = $total.$property.Add($pairKey)
        foreach ($end in @($connection.SourceId, $connection.TargetId)) {
            if ($subscriptionById.ContainsKey($end)) { $null = $bySubscription[$subscriptionById[$end]].$property.Add($pairKey) }
        }
    }
    return [pscustomobject]@{ Total = $total; BySubscription = $bySubscription }
}

function Format-OverviewStatistic {
    param([object]$Counter, [switch]$IncludeSubscriptions)

    # Hubs and VPNs are mentioned only where there are any. The header spells them out; a
    # lane's narrower text uses short words.
    $parts = [System.Collections.Generic.List[string]]::new()
    $add = { param($Count, $Singular, $Plural) $parts.Add($(if ($Count -eq 1) { "1 $Singular" } else { "$Count $Plural" })) }
    if ($IncludeSubscriptions) { & $add $Counter.Subscriptions.Count 'subscription' 'subscriptions' }
    & $add $Counter.Vnets 'VNet' 'VNets'
    if ($Counter.Hubs -gt 0) {
        if ($IncludeSubscriptions) { & $add $Counter.Hubs 'Virtual WAN hub' 'Virtual WAN hubs' } else { & $add $Counter.Hubs 'hub' 'hubs' }
    }
    & $add $Counter.Subnets 'subnet' 'subnets'
    & $add $Counter.Peerings.Count 'peering' 'peerings'
    if ($Counter.Vpns.Count -gt 0) {
        if ($IncludeSubscriptions) { & $add $Counter.Vpns.Count 'VNet-to-VNet VPN' 'VNet-to-VNet VPNs' } else { & $add $Counter.Vpns.Count 'VPN' 'VPNs' }
    }
    & $add $Counter.Regions.Count 'region' 'regions'
    return ($parts -join ' &#183; ')
}

function Get-OverviewOutsideItem {
    param(
        [object]$Index,
        [object[]]$Connections,
        [System.Collections.Generic.HashSet[string]]$ShownIds,
        [hashtable]$NameById
    )

    # Connected VNets without a card of their own, outside the export or left out by a scope
    # filter, are known only from the links that point to them. Returns a card item for each,
    # in the order the links first name them, carrying what those links reveal.
    $externals = [ordered]@{}
    foreach ($connection in $Connections) {
        $sourceShown = $ShownIds.Contains($connection.SourceId)
        if ($sourceShown -eq $ShownIds.Contains($connection.TargetId)) { continue }
        $externalId = if ($sourceShown) { $connection.TargetId } else { $connection.SourceId }
        $peerId = if ($sourceShown) { $connection.SourceId } else { $connection.TargetId }
        if (-not $externals.Contains($externalId)) {
            $vnet = if ($Index.VnetById.ContainsKey($externalId)) { $Index.VnetById[$externalId] } else { $null }
            $name = if ($vnet) { [string](Get-ObjectValue $vnet 'name' (Get-ResourceNameFromId $externalId)) } else { Get-ResourceNameFromId $externalId }
            $externals[$externalId] = [pscustomobject]@{
                Id = $externalId; Vnet = $vnet; Name = $name
                # A hub's managed VNet, reached by a peering while the hub itself is not in the export.
                IsLikelyHub = ($null -eq $vnet -and $name -like 'HV_*')
                PeerIds = [System.Collections.Generic.List[string]]::new(); Descriptions = [System.Collections.Generic.List[object]]::new()
                Prefixes = [System.Collections.Generic.List[string]]::new(); PeeredPrefixes = [System.Collections.Generic.List[string]]::new()
            }
        }
        $external = $externals[$externalId]
        if (-not $external.PeerIds.Contains($peerId)) { $external.PeerIds.Add($peerId) }
        $peerName = [string]$NameById[$peerId]
        if ($connection.Kind -eq 'Peering') {
            $flow = $connection.Flow
            $external.Descriptions.Add(@("Peering $($flow.LocalName) $([char]0x2194) $($flow.RemoteName)") + @(Get-PeeringFlowDescription $flow))
            # The card's side of the peering records the remote VNet's address space and the
            # part of it that is peered.
            if ((ConvertTo-ResourceId (Get-ObjectValue $connection.Row 'vnetId' '')) -eq $peerId) {
                foreach ($entry in @(@{ List = $external.Prefixes; Property = 'remoteAddressPrefixes' }, @{ List = $external.PeeredPrefixes; Property = 'peeredAddressPrefixes' })) {
                    foreach ($prefix in @(Get-PrefixList (Get-ObjectValue $connection.Row $entry.Property ''))) {
                        if (-not $entry.List.Contains($prefix)) { $entry.List.Add($prefix) }
                    }
                }
            }
        } elseif ($connection.Kind -eq 'Vpn') {
            $lines = @("VNet-to-VNet VPN $peerName $([char]0x2194) $($external.Name)")
            for ($i = 0; $i -lt $connection.Names.Count; $i++) { $lines += "Connection $($connection.Names[$i]): $($connection.States[$i])" }
            $external.Descriptions.Add($lines)
        } else {
            $external.Descriptions.Add(@("Virtual WAN connection $($connection.Names[0]) to $peerName", "State: $($connection.States[0])"))
        }
    }
    return @($externals.Values | ForEach-Object { [pscustomobject]@{ Id = $_.Id; Name = $_.Name; Kind = 'Outside'; Row = $null; SubscriptionId = ''; WanId = ''; External = $_ } })
}

function Get-OverviewOutsideCard {
    param([object]$External, [hashtable]$SubscriptionNames, [hashtable]$NameById)

    # The label and tooltip of a card outside the overview: where the VNet is, its address
    # space or at least the peered part of it, and the cards it is connected to.
    $id = $External.Id
    $subscriptionId = ''; $resourceGroup = ''
    if ($id -match '^/subscriptions/([^/]+)/resourcegroups/([^/]+)/') { $subscriptionId = $Matches[1]; $resourceGroup = $Matches[2] }
    if ($External.Vnet) { $resourceGroup = [string](Get-ObjectValue $External.Vnet 'resourceGroup' $resourceGroup) }
    $scope = if ($External.Vnet) { 'Outside the selected VNets' } elseif ($External.IsLikelyHub) { 'Likely a Virtual WAN hub' } else { 'Not in this export' }
    $prefixes = if ($External.Vnet) { ConvertTo-DisplayList (Get-ObjectValue $External.Vnet 'addressPrefixes' '') } else { @($External.Prefixes) -join ', ' }
    # Without the address space, the peered part is shown, marked so it does not read as
    # the whole VNet.
    if (-not $prefixes -and $External.PeeredPrefixes.Count -gt 0) { $prefixes = "Peered: $(@($External.PeeredPrefixes) -join ', ')" }
    if (-not $prefixes) { $prefixes = "<font color='#666666'>Address space not reported</font>" }
    $subscriptionName = if ($SubscriptionNames.ContainsKey($subscriptionId)) { [string]$SubscriptionNames[$subscriptionId] } else { '' }
    $subscriptionText = if ($subscriptionName) { $subscriptionName } elseif ($subscriptionId.Length -gt 13) { "Sub $($subscriptionId.Substring(0, 8))&#8230;" } else { "Sub $subscriptionId" }
    $peerNames = @($External.PeerIds | ForEach-Object { [string]$NameById[$_] } | Sort-Object)
    $peerText = $peerNames[0] + $(if ($peerNames.Count -gt 1) { " +$($peerNames.Count - 1)" } else { '' })
    $tooltip = @("$($External.Name): $scope", "Subscription: $subscriptionId$(if ($subscriptionName) { " ($subscriptionName)" })", "Resource group: $resourceGroup")
    foreach ($description in $External.Descriptions) { $tooltip += ''; $tooltip += @($description) }
    $tooltip += ''; $tooltip += $id
    $label = "<b>$($External.Name)</b><br><font color='#777777'><i>$scope</i></font><br>$prefixes<br><font color='#666666'>$subscriptionText | $resourceGroup</font><br>Connected to: $peerText"
    $kind = if ($External.IsLikelyHub) { 'VirtualHub' } else { 'VNet' }
    return [pscustomobject]@{ Label = $label; Tooltip = ($tooltip -join "`n"); Kind = $kind }
}

function Get-OverviewPlacement {
    param([object[]]$Lanes, [object[]]$Connections, [int]$Columns = 4)

    # Linked cards go close together, so their lines stay short. A hub, a Virtual WAN hub or
    # any card with three or more lines, takes an inner column of its lane's first row,
    # where its partners fit on both sides, and subscriptions with a hub come first. Every
    # card linked to a placed card then goes to the free cell nearest it, in the same column
    # when that card is in another lane. A group not yet linked to anything placed starts in
    # the first row with room for all of it, in the order Get-OverviewSlot gives, which keeps
    # its members side by side. Cards outside the overview form the last lane. Returns the
    # lanes in display order, each with its cards in reading order and its row count, and
    # the cell of every card by ID.
    $laneOfId = @{}
    foreach ($lane in $Lanes) { foreach ($item in $lane.Items) { $laneOfId[$item.Id] = $lane } }
    $neighbours = @{}; $degree = @{}
    foreach ($id in $laneOfId.Keys) { $neighbours[$id] = [System.Collections.Generic.List[string]]::new(); $degree[$id] = 0 }
    foreach ($connection in $Connections) {
        $sourceId = $connection.SourceId; $targetId = $connection.TargetId
        if ($sourceId -eq $targetId -or -not $laneOfId.ContainsKey($sourceId) -or -not $laneOfId.ContainsKey($targetId)) { continue }
        $degree[$sourceId]++; $degree[$targetId]++
        if (-not $neighbours[$sourceId].Contains($targetId)) { $neighbours[$sourceId].Add($targetId); $neighbours[$targetId].Add($sourceId) }
    }
    $isHub = { param($Item) $Item.Kind -eq 'Hub' -or $degree[$Item.Id] -ge 3 }
    $ordered = @(
        @($Lanes | Where-Object { -not $_.IsOutside -and @($_.Items | Where-Object { & $isHub $_ }).Count -gt 0 })
        @($Lanes | Where-Object { -not $_.IsOutside -and @($_.Items | Where-Object { & $isHub $_ }).Count -eq 0 })
        @($Lanes | Where-Object { $_.IsOutside })
    )

    $cellById = @{}
    $placedLanes = [System.Collections.Generic.List[object]]::new()
    for ($laneIndex = 0; $laneIndex -lt $ordered.Count; $laneIndex++) {
        $lane = $ordered[$laneIndex]
        $rank = @{}
        foreach ($slot in @(Get-OverviewSlot -Items @($lane.Items) -Connections $Connections -Columns $Columns)) {
            if ($null -ne $slot.Item) { $rank[$slot.Item.Id] = $rank.Count }
        }
        $pending = [System.Collections.Generic.List[object]]::new()
        foreach ($item in @($lane.Items | Sort-Object { $rank[$_.Id] })) { $pending.Add($item) }
        $occupied = @{}; $rowCount = 0
        $cards = [System.Collections.Generic.List[object]]::new()
        $place = {
            param($Item, [int]$Row, [int]$Column)
            $occupied["$Row|$Column"] = $true
            $cellById[$Item.Id] = [pscustomobject]@{ Lane = $laneIndex; Row = $Row; Column = $Column }
            $cards.Add([pscustomobject]@{ Item = $Item; Row = $Row; Column = $Column })
            $null = $pending.Remove($Item)
        }
        if (-not $lane.IsOutside) {
            foreach ($hub in @($pending | Where-Object { & $isHub $_ } | Sort-Object @{ Expression = { $degree[$_.Id] }; Descending = $true }, Name, Id)) {
                $cell = $null
                for ($row = 0; $null -eq $cell; $row++) {
                    foreach ($column in @(1, 2, 0, 3)) {
                        if ($column -lt $Columns -and $null -eq $cell -and -not $occupied.ContainsKey("$row|$column")) { $cell = @($row, $column) }
                    }
                }
                & $place $hub $cell[0] $cell[1]
                $rowCount = [math]::Max($rowCount, $cell[0] + 1)
            }
        }
        while ($pending.Count -gt 0) {
            $next = $null; $nextPartners = @()
            foreach ($item in $pending) {
                $partners = @($neighbours[$item.Id] | Where-Object { $cellById.ContainsKey($_) })
                if ($partners.Count -gt $nextPartners.Count) { $next = $item; $nextPartners = $partners }
            }
            if ($null -ne $next) {
                $anchor = @($nextPartners | ForEach-Object { $cellById[$_] } | Sort-Object Lane, Row, Column)[0]
                $best = $null; $bestScore = [double]::MaxValue
                for ($row = 0; $row -le $rowCount; $row++) {
                    for ($column = 0; $column -lt $Columns; $column++) {
                        if ($occupied.ContainsKey("$row|$column")) { continue }
                        # Within a lane the same row wins over the one above, so linked cards end
                        # up side by side; across lanes the same column wins.
                        $score = if ($anchor.Lane -eq $laneIndex) {
                            (([math]::Abs($column - $anchor.Column) + [math]::Abs($row - $anchor.Row)) * 10) + $(if ($row -ne $anchor.Row) { 5 } else { 0 }) + $row
                        } else {
                            ([math]::Abs($column - $anchor.Column) * 10) + ($row * 15)
                        }
                        if ($score -lt $bestScore) { $bestScore = $score; $best = @($row, $column) }
                    }
                }
            } else {
                # The group of the first card left, among the cards still to place in this lane.
                $next = $pending[0]
                $group = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                $walk = [System.Collections.Generic.Stack[string]]::new(); $walk.Push($next.Id)
                while ($walk.Count -gt 0) {
                    $current = $walk.Pop()
                    if ($group.Add($current)) { foreach ($other in $neighbours[$current]) { if ([object]::ReferenceEquals($laneOfId[$other], $lane) -and -not $cellById.ContainsKey($other)) { $walk.Push($other) } } }
                }
                $width = [math]::Min($group.Count, $Columns)
                $best = $null
                for ($row = 0; $null -eq $best; $row++) {
                    for ($column = 0; $column -le $Columns - $width -and $null -eq $best; $column++) {
                        $free = $true
                        for ($offset = 0; $offset -lt $width; $offset++) { if ($occupied.ContainsKey("$row|$($column + $offset)")) { $free = $false } }
                        if ($free) { $best = @($row, $column) }
                    }
                }
            }
            & $place $next $best[0] $best[1]
            $rowCount = [math]::Max($rowCount, $best[0] + 1)
        }
        $placedLanes.Add([pscustomobject]@{ Lane = $lane; Cards = @($cards | Sort-Object Row, Column); Rows = $rowCount })
    }
    return [pscustomobject]@{ Lanes = $placedLanes.ToArray(); CellById = $cellById }
}

function Get-ReversedLineStyle {
    param([string]$Style)

    # The same line drawn from its other end: the start and end arrowheads trade places.
    $parts = foreach ($part in ($Style -split ';')) {
        if ($part -match '^(start|end)(Arrow|Fill)=(.*)$') { "$(if ($Matches[1] -eq 'start') { 'end' } else { 'start' })$($Matches[2])=$($Matches[3])" } else { $part }
    }
    return ($parts -join ';')
}

function Get-OverviewRoutePlan {
    param([object]$Placement, [object[]]$Lines, [int]$Columns = 4)

    # Each line's way through the gaps between cards, planned before any position is known
    # so every gap can be sized to the lines it carries. Gap "lane|r" lies above row r of its
    # lane; gutter g runs between columns g-1 and g. Neighbours in a row are joined side to
    # side, and cards in one column with nothing between them straight down. Other lines
    # leave the upper card's bottom into the gap below it, run down an inner gutter when
    # they have to reach another row, and enter the lower card through the gap above it.
    # Lines between subscriptions stay in the inner columns and gutters, clear of the text
    # in the lane headers.
    $cells = $Placement.CellById
    $isBefore = { param($First, $Second) ($First.Lane -lt $Second.Lane) -or ($First.Lane -eq $Second.Lane -and ($First.Row -lt $Second.Row -or ($First.Row -eq $Second.Row -and $First.Column -lt $Second.Column))) }
    $lineCountByPair = @{}
    foreach ($line in $Lines) { $pairKey = @($line.SourceId, $line.TargetId | Sort-Object) -join '|'; $lineCountByPair[$pairKey] = 1 + [int]$lineCountByPair[$pairKey] }

    # A card with more than four lines that look alike, leading below it or elsewhere in its
    # row, gets one trunk for them: they leave it together and share their tracks until each
    # branches off to its card. Labelled lines and lines that look different, such as red
    # ones, keep a way of their own, so a trunk never hides an exception.
    $candidatesByHub = @{}
    for ($i = 0; $i -lt $Lines.Count; $i++) {
        $line = $Lines[$i]
        if ($line.Label) { continue }
        foreach ($hubId in @($line.SourceId, $line.TargetId)) {
            $spokeId = if ($hubId -eq $line.SourceId) { $line.TargetId } else { $line.SourceId }
            $hub = $cells[$hubId]; $spoke = $cells[$spokeId]
            $isLower = $spoke.Lane -gt $hub.Lane -or ($spoke.Lane -eq $hub.Lane -and $spoke.Row -ge $hub.Row)
            $isBeside = $spoke.Lane -eq $hub.Lane -and $spoke.Row -eq $hub.Row -and [math]::Abs($spoke.Column - $hub.Column) -le 1
            if (-not $isLower -or $isBeside) { continue }
            $style = if ($hubId -eq $line.SourceId) { $line.LineStyle } else { Get-ReversedLineStyle $line.LineStyle }
            if (-not $candidatesByHub.ContainsKey($hubId)) { $candidatesByHub[$hubId] = [System.Collections.Generic.List[object]]::new() }
            $candidatesByHub[$hubId].Add([pscustomobject]@{ Index = $i; Look = (@($style -split ';' | Where-Object { $_ } | Sort-Object) -join ';') })
        }
    }
    $trunkHubByLine = @{}
    foreach ($hubId in @($candidatesByHub.Keys | Sort-Object @{ Expression = { $candidatesByHub[$_].Count }; Descending = $true }, @{ Expression = { $_ } })) {
        $looks = @($candidatesByHub[$hubId] | Where-Object { -not $trunkHubByLine.ContainsKey($_.Index) } | Group-Object Look |
            Sort-Object @{ Expression = 'Count'; Descending = $true }, @{ Expression = { ($_.Group | Measure-Object Index -Minimum).Minimum } })
        if ($looks.Count -gt 0 -and $looks[0].Count -gt 4) { foreach ($candidate in $looks[0].Group) { $trunkHubByLine[$candidate.Index] = $hubId } }
    }
    $trunkHubs = [System.Collections.Generic.HashSet[string]]::new([string[]]@($trunkHubByLine.Values), [System.StringComparer]::OrdinalIgnoreCase)
    # The trunk runs down the inner gutter beside its hub on the side where most of its
    # distant cards are.
    $farColumnsByHub = @{}
    foreach ($index in $trunkHubByLine.Keys) {
        $hubId = $trunkHubByLine[$index]; $line = $Lines[$index]
        $spoke = $cells[$(if ($line.SourceId -eq $hubId) { $line.TargetId } else { $line.SourceId })]; $hub = $cells[$hubId]
        if ($spoke.Lane -ne $hub.Lane -or $spoke.Row -gt $hub.Row + 1) { Add-IndexValue $farColumnsByHub $hubId $spoke.Column }
    }
    $busByHub = @{}
    foreach ($hubId in $farColumnsByHub.Keys) {
        $hubColumn = $cells[$hubId].Column
        $averageColumn = (@($farColumnsByHub[$hubId]) | Measure-Object -Average).Average
        $busByHub[$hubId] = [math]::Min($Columns - 1, [math]::Max(1, $(if ($averageColumn -le $hubColumn) { $hubColumn } else { $hubColumn + 1 })))
    }

    $plans = [System.Collections.Generic.List[object]]::new()
    $horizontalTracks = @{}; $verticalTracks = @{}; $sharedTracks = @{}
    for ($i = 0; $i -lt $Lines.Count; $i++) {
        $line = $Lines[$i]
        $plan = [pscustomobject]@{ Index = $i; Line = $line; Kind = ''; Upper = $line.SourceId; Lower = $line.TargetId; Below = ''; Above = ''; Gutter = 0; Trunk = ''; Reverse = $false }
        if ($trunkHubByLine.ContainsKey($i)) {
            # Trunk lines are drawn from the hub, so the dashes of the shared stretch line up.
            $hubId = $trunkHubByLine[$i]
            $plan.Trunk = $hubId; $plan.Upper = $hubId; $plan.Lower = $(if ($line.SourceId -eq $hubId) { $line.TargetId } else { $line.SourceId }); $plan.Reverse = $line.SourceId -ne $hubId
            $hub = $cells[$hubId]; $spoke = $cells[$plan.Lower]
            $plan.Below = "$($hub.Lane)|$($hub.Row + 1)"
            if ($spoke.Lane -eq $hub.Lane -and $spoke.Row -eq $hub.Row) { $plan.Kind = 'TrunkSameRow' }
            elseif ($spoke.Lane -eq $hub.Lane -and $spoke.Row -eq $hub.Row + 1) { $plan.Kind = 'TrunkNextRow' }
            else { $plan.Kind = 'Trunk'; $plan.Above = "$($spoke.Lane)|$($spoke.Row)"; $plan.Gutter = $busByHub[$hubId] }
            foreach ($gap in @($plan.Below, $plan.Above)) {
                if ($gap -and -not $sharedTracks.ContainsKey("$hubId|$gap")) { $sharedTracks["$hubId|$gap"] = $true; $horizontalTracks[$gap] = 1 + [int]$horizontalTracks[$gap] }
            }
            if ($plan.Gutter -gt 0 -and -not $sharedTracks.ContainsKey("$hubId|gutter")) { $sharedTracks["$hubId|gutter"] = $true; $verticalTracks[$plan.Gutter] = 1 + [int]$verticalTracks[$plan.Gutter] }
            $plans.Add($plan)
            continue
        }
        if (& $isBefore $cells[$plan.Lower] $cells[$plan.Upper]) { $plan.Upper = $line.TargetId; $plan.Lower = $line.SourceId }
        $upper = $cells[$plan.Upper]; $lower = $cells[$plan.Lower]
        $sameLane = $upper.Lane -eq $lower.Lane
        if ($sameLane -and $upper.Row -eq $lower.Row -and [math]::Abs($upper.Column - $lower.Column) -eq 1) {
            $plan.Kind = 'Side'
        } else {
            # The centre of a trunk hub's bottom belongs to its trunk.
            $straight = $upper.Column -eq $lower.Column -and $lineCountByPair[(@($plan.Upper, $plan.Lower | Sort-Object) -join '|')] -eq 1 -and
                ($sameLane -or ($upper.Column -ge 1 -and $upper.Column -le $Columns - 2)) -and -not $trunkHubs.Contains($plan.Upper)
            if ($straight) {
                foreach ($cell in $cells.Values) {
                    if ($cell.Column -eq $upper.Column -and (& $isBefore $upper $cell) -and (& $isBefore $cell $lower)) { $straight = $false; break }
                }
            }
            if ($straight) {
                $plan.Kind = 'Straight'
            } elseif ($sameLane -and $upper.Row -eq $lower.Row) {
                $plan.Kind = 'SameRow'; $plan.Below = "$($upper.Lane)|$($upper.Row + 1)"
            } elseif ($sameLane -and $lower.Row -eq $upper.Row + 1) {
                $plan.Kind = 'NextRow'; $plan.Below = "$($upper.Lane)|$($lower.Row)"
            } else {
                $plan.Kind = 'Gutter'; $plan.Below = "$($upper.Lane)|$($upper.Row + 1)"; $plan.Above = "$($lower.Lane)|$($lower.Row)"
                # The inner gutter beside the lower card that is nearest both cards.
                $plan.Gutter = @(@($lower.Column, ($lower.Column + 1)) | Where-Object { $_ -ge 1 -and $_ -le $Columns - 1 } |
                    Sort-Object { [math]::Abs($_ - ($upper.Column + 0.5)) + [math]::Abs($_ - ($lower.Column + 0.5)) }, { $_ })[0]
            }
        }
        foreach ($gap in @($plan.Below, $plan.Above)) { if ($gap) { $horizontalTracks[$gap] = 1 + [int]$horizontalTracks[$gap] } }
        if ($plan.Gutter -gt 0) { $verticalTracks[$plan.Gutter] = 1 + [int]$verticalTracks[$plan.Gutter] }
        $plans.Add($plan)
    }
    return [pscustomobject]@{ Plans = $plans.ToArray(); HorizontalTracks = $horizontalTracks; VerticalTracks = $verticalTracks }
}

function Get-OverviewLayout {
    param([object]$Placement, [hashtable]$HorizontalTracks = @{}, [hashtable]$VerticalTracks = @{})

    # Card positions and lane sizes, relative to each lane. Gap "lane|r" lies above row r and
    # gap "lane|rows" below the last row. A gap with lines is tall enough for one track
    # every 12 px, and never smaller than without lines; the gutters between columns widen
    # the same way when one has to carry more than eight lines.
    $cardWidth = 290; $cardHeight = 82; $margin = 50
    $mostVertical = [int](@(@($VerticalTracks.Values) + 0) | Measure-Object -Maximum).Maximum
    $pitch = $cardWidth + [math]::Max(110, 16 + (12 * $mostVertical))
    $laneTop = @{}; $laneHeight = @{}; $gapTop = @{}; $gapHeight = @{}; $rowTop = @{}
    $y = 110
    for ($laneIndex = 0; $laneIndex -lt $Placement.Lanes.Count; $laneIndex++) {
        $rows = $Placement.Lanes[$laneIndex].Rows
        $laneTop[$laneIndex] = $y
        $cursor = 48
        for ($row = 0; $row -le $rows; $row++) {
            $key = "$laneIndex|$row"
            $height = if ($row -eq 0) { 10 } elseif ($row -eq $rows) { 30 } else { 23 }
            $tracks = [int]$HorizontalTracks[$key]
            if ($tracks -gt 0) { $height = [math]::Max($height, 16 + (12 * $tracks)) }
            $gapTop[$key] = $cursor; $gapHeight[$key] = $height; $cursor += $height
            if ($row -lt $rows) { $rowTop[$key] = $cursor; $cursor += $cardHeight }
        }
        $laneHeight[$laneIndex] = $cursor
        $y += $cursor + 25
    }
    return [pscustomobject]@{
        CardWidth = $cardWidth; CardHeight = $cardHeight; Margin = $margin; Pitch = $pitch
        LaneWidth = (2 * $margin) + (3 * $pitch) + $cardWidth
        LaneTop = $laneTop; LaneHeight = $laneHeight; GapTop = $gapTop; GapHeight = $gapHeight; RowTop = $rowTop; Bottom = $y
    }
}

function Get-OverviewRoute {
    param([object[]]$Plans, [object]$Placement, [object]$Layout)

    # The ports and bend points of every planned line, in page coordinates and oriented from
    # the line's source to its target, or from the hub for a trunk line. Lines on one side
    # of a card are spread along it in the order they head off, so they leave it without
    # crossing; a straight line or a trunk keeps the centre of its side, and the others
    # share the halves beside it. Each line takes the next free track, 12 px apart, in every
    # gap and gutter it runs through; the lines of a trunk share one.
    $cells = $Placement.CellById
    $boxById = @{}
    foreach ($id in $cells.Keys) {
        $cell = $cells[$id]
        $boxById[$id] = [pscustomobject]@{ Left = 20 + $Layout.Margin + ($cell.Column * $Layout.Pitch); Top = $Layout.LaneTop[$cell.Lane] + $Layout.RowTop["$($cell.Lane)|$($cell.Row)"] }
    }
    $width = $Layout.CardWidth; $height = $Layout.CardHeight
    $gutterLeft = { param([int]$Gutter) 20 + $Layout.Margin + (($Gutter - 1) * $Layout.Pitch) + $width }
    $gapTop = { param([string]$Gap) $Layout.LaneTop[[int]($Gap -split '\|')[0]] + $Layout.GapTop[$Gap] }

    $endsBySide = [ordered]@{}
    $addEnd = {
        param($Plan, [string]$Role, [string]$Side, [double]$Heading, [bool]$Centre)
        $cardId = if ($Role -eq 'Upper') { $Plan.Upper } else { $Plan.Lower }
        $key = "$cardId|$Side"
        if (-not $endsBySide.Contains($key)) { $endsBySide[$key] = [System.Collections.Generic.List[object]]::new() }
        $endsBySide[$key].Add([pscustomobject]@{ Plan = $Plan; Role = $Role; Side = $Side; Heading = $Heading; Centre = $Centre; Order = $endsBySide[$key].Count; Offset = 0 })
    }
    foreach ($plan in $Plans) {
        $upper = $boxById[$plan.Upper]; $lower = $boxById[$plan.Lower]
        $upperCentre = $upper.Left + ($width / 2); $lowerCentre = $lower.Left + ($width / 2)
        switch ($plan.Kind) {
            'Side' {
                $upperSide = if ($upper.Left -lt $lower.Left) { 'right' } else { 'left' }
                $lowerSide = if ($upperSide -eq 'right') { 'left' } else { 'right' }
                & $addEnd $plan 'Upper' $upperSide 0 $false; & $addEnd $plan 'Lower' $lowerSide 0 $false
            }
            'Straight' { & $addEnd $plan 'Upper' 'bottom' $upperCentre $true; & $addEnd $plan 'Lower' 'top' $lowerCentre $true }
            'SameRow' { & $addEnd $plan 'Upper' 'bottom' $lowerCentre $false; & $addEnd $plan 'Lower' 'bottom' $upperCentre $false }
            'NextRow' { & $addEnd $plan 'Upper' 'bottom' $lowerCentre $false; & $addEnd $plan 'Lower' 'top' $upperCentre $false }
            'Gutter' {
                $gutterCentre = (& $gutterLeft $plan.Gutter) + (($Layout.Pitch - $width) / 2)
                & $addEnd $plan 'Upper' 'bottom' $gutterCentre $false; & $addEnd $plan 'Lower' 'top' $gutterCentre $false
            }
            'TrunkSameRow' { & $addEnd $plan 'Upper' 'bottom' $upperCentre $true; & $addEnd $plan 'Lower' 'bottom' $upperCentre $false }
            'TrunkNextRow' { & $addEnd $plan 'Upper' 'bottom' $upperCentre $true; & $addEnd $plan 'Lower' 'top' $upperCentre $false }
            'Trunk' {
                $busCentre = (& $gutterLeft $plan.Gutter) + (($Layout.Pitch - $width) / 2)
                & $addEnd $plan 'Upper' 'bottom' $upperCentre $true; & $addEnd $plan 'Lower' 'top' $busCentre $false
            }
        }
    }
    $offsetByEnd = @{}
    foreach ($key in $endsBySide.Keys) {
        $ends = @($endsBySide[$key])
        $side = $ends[0].Side
        if ($side -eq 'left' -or $side -eq 'right') {
            # Lines between the same two neighbours are listed in the same order on both cards.
            for ($i = 0; $i -lt $ends.Count; $i++) { $ends[$i].Offset = [math]::Round($height * ($i + 1) / ($ends.Count + 1)) }
        } else {
            $cardId = ($key -split '\|')[0]
            $centre = $boxById[$cardId].Left + ($width / 2)
            $spread = @($ends | Where-Object { -not $_.Centre } | Sort-Object Heading, Order)
            if (@($ends | Where-Object { $_.Centre }).Count -gt 0) {
                foreach ($end in @($ends | Where-Object { $_.Centre })) { $end.Offset = $width / 2 }
                $leftEnds = @($spread | Where-Object { $_.Heading -lt $centre }); $rightEnds = @($spread | Where-Object { $_.Heading -ge $centre })
                for ($i = 0; $i -lt $leftEnds.Count; $i++) { $leftEnds[$i].Offset = [math]::Round(($width / 2) * ($i + 1) / ($leftEnds.Count + 1)) }
                for ($i = 0; $i -lt $rightEnds.Count; $i++) { $rightEnds[$i].Offset = [math]::Round(($width / 2) + (($width / 2) * ($i + 1) / ($rightEnds.Count + 1))) }
            } else {
                for ($i = 0; $i -lt $spread.Count; $i++) { $spread[$i].Offset = [math]::Round($width * ($i + 1) / ($spread.Count + 1)) }
            }
        }
        foreach ($end in $ends) { $offsetByEnd["$($end.Plan.Index)|$($end.Role)"] = $end }
    }

    $horizontalUsed = @{}; $verticalUsed = @{}
    $nextTrack = { param([hashtable]$Used, [string]$Key) $Used[$Key] = 1 + [int]$Used[$Key]; 4 + (12 * $Used[$Key]) }
    $sharedTrack = @{}
    $trunkTrack = {
        param([hashtable]$Used, [string]$Key, [string]$Shared)
        if (-not $sharedTrack.ContainsKey($Shared)) { $sharedTrack[$Shared] = & $nextTrack $Used $Key }
        $sharedTrack[$Shared]
    }
    $routes = foreach ($plan in $Plans) {
        $upperEnd = $offsetByEnd["$($plan.Index)|Upper"]; $lowerEnd = $offsetByEnd["$($plan.Index)|Lower"]
        $upper = $boxById[$plan.Upper]; $lower = $boxById[$plan.Lower]
        $anchor = @{}
        foreach ($end in @($upperEnd, $lowerEnd)) {
            $box = if ($end.Role -eq 'Upper') { $upper } else { $lower }
            $anchor[$end.Role] = switch ($end.Side) {
                'top' { [pscustomobject]@{ FractionX = $end.Offset / $width; FractionY = 0; X = $box.Left + $end.Offset; Y = $box.Top } }
                'bottom' { [pscustomobject]@{ FractionX = $end.Offset / $width; FractionY = 1; X = $box.Left + $end.Offset; Y = $box.Top + $height } }
                'left' { [pscustomobject]@{ FractionX = 0; FractionY = $end.Offset / $height; X = $box.Left; Y = $box.Top + $end.Offset } }
                'right' { [pscustomobject]@{ FractionX = 1; FractionY = $end.Offset / $height; X = $box.Left + $width; Y = $box.Top + $end.Offset } }
            }
        }
        $upperX = $anchor['Upper'].X; $lowerX = $anchor['Lower'].X
        $points = @()
        if ($plan.Kind -eq 'SameRow' -or $plan.Kind -eq 'NextRow') {
            $trackY = (& $gapTop $plan.Below) + (& $nextTrack $horizontalUsed $plan.Below)
            $points = @(@($upperX, $trackY), @($lowerX, $trackY))
        } elseif ($plan.Kind -eq 'Gutter') {
            $belowY = (& $gapTop $plan.Below) + (& $nextTrack $horizontalUsed $plan.Below)
            $gutterX = (& $gutterLeft $plan.Gutter) + (& $nextTrack $verticalUsed ([string]$plan.Gutter))
            $aboveY = (& $gapTop $plan.Above) + (& $nextTrack $horizontalUsed $plan.Above)
            $points = @(@($upperX, $belowY), @($gutterX, $belowY), @($gutterX, $aboveY), @($lowerX, $aboveY))
        } elseif ($plan.Kind -like 'Trunk*') {
            # Every line of a trunk follows the same points until it branches off to its card.
            $belowY = (& $gapTop $plan.Below) + (& $trunkTrack $horizontalUsed $plan.Below "$($plan.Trunk)|$($plan.Below)")
            if ($plan.Kind -eq 'Trunk') {
                $busX = (& $gutterLeft $plan.Gutter) + (& $trunkTrack $verticalUsed ([string]$plan.Gutter) "$($plan.Trunk)|gutter")
                $branchY = (& $gapTop $plan.Above) + (& $trunkTrack $horizontalUsed $plan.Above "$($plan.Trunk)|$($plan.Above)")
                $points = @(@($upperX, $belowY), @($busX, $belowY), @($busX, $branchY), @($lowerX, $branchY))
            } else {
                $points = @(@($upperX, $belowY), @($lowerX, $belowY))
            }
        }
        # Points that repeat the one before or lie on a straight run add no bend; a card right
        # below its hub, for one, is reached in a single straight run.
        $path = @(, @($anchor['Upper'].X, $anchor['Upper'].Y)) + $points + @(, @($anchor['Lower'].X, $anchor['Lower'].Y))
        $kept = [System.Collections.Generic.List[object]]::new(); $kept.Add($path[0])
        for ($k = 1; $k -lt $path.Count - 1; $k++) {
            $previous = $kept[$kept.Count - 1]; $current = $path[$k]; $following = $path[$k + 1]
            $repeats = $current[0] -eq $previous[0] -and $current[1] -eq $previous[1]
            $straight = ($previous[0] -eq $current[0] -and $current[0] -eq $following[0]) -or ($previous[1] -eq $current[1] -and $current[1] -eq $following[1])
            if (-not $repeats -and -not $straight) { $kept.Add($current) }
        }
        $points = @(for ($k = 1; $k -lt $kept.Count; $k++) { , $kept[$k] })
        # A trunk line always runs from its hub; the caller swaps its arrowheads to match.
        $sourceRole = 'Upper'; $targetRole = 'Lower'
        if ($plan.Line.SourceId -ne $plan.Upper -and -not $plan.Reverse) {
            $sourceRole = 'Lower'; $targetRole = 'Upper'
            [array]::Reverse($points)
        }
        [pscustomobject]@{
            Plan = $plan; Exit = $anchor[$sourceRole]; Entry = $anchor[$targetRole]
            Points = @($points | ForEach-Object { [pscustomobject]@{ X = $_[0]; Y = $_[1] } })
        }
    }
    return @($routes)
}

function Get-OverviewLine {
    param([object]$Connection, [hashtable]$NameById)

    # The label, tooltip, and style of one overview line.
    $sourceName = [string]$NameById[$Connection.SourceId]; $targetName = [string]$NameById[$Connection.TargetId]
    if ($Connection.Kind -eq 'Peering') {
        # The line carries an arrowhead for each direction the peering allows. Toward a VNet
        # outside the export only this side is known, so the way back stays without one.
        $flow = $Connection.Flow
        # A connected VNet peering is the normal case and goes unlabelled; a label marks
        # anything else. One short line each, because neighbouring cards leave only a narrow gap.
        $labelLines = @()
        if (-not $flow.Connected) { $labelLines += $(if ($flow.HasReverse -and $flow.RemoteState -ne $flow.LocalState) { "$($flow.LocalState) /<br>$($flow.RemoteState)" } else { $flow.LocalState }) }
        if ($flow.IsSubnetPeering) { $labelLines += 'subnet<br>peering' }
        if ($flow.IsOutOfSync) { $labelLines += 'not in sync' }
        $label = $labelLines -join '<br>'
        $tooltip = (@("Peering $($flow.LocalName) $([char]0x2194) $($flow.RemoteName)") + @(Get-PeeringFlowDescription $flow)) -join "`n"
        $lineStyle = Get-PeeringLineStyle $flow
        $layerKind = 'Peering'
    } else {
        $states = @($Connection.States | Where-Object { $_ } | Select-Object -Unique)
        if ($Connection.Kind -eq 'Vpn') {
            # Always labelled: a solid line between two VNets would otherwise read as a hub connection.
            $label = 'VPN' + $(if ($Connection.Established -eq $false) { "<br>$($states -join ' / ')" } elseif ($null -eq $Connection.Established) { '<br>status not reported' } else { '' })
            $tooltip = @("VNet-to-VNet VPN $sourceName $([char]0x2194) $targetName")
            for ($nameIndex = 0; $nameIndex -lt $Connection.Names.Count; $nameIndex++) { $tooltip += "Connection $($Connection.Names[$nameIndex]): $($Connection.States[$nameIndex])" }
            $tooltip = $tooltip -join "`n"
        } else {
            $label = if ($Connection.Established -eq $false) { $states -join ' / ' } elseif ($null -eq $Connection.Established) { 'state not reported' } else { '' }
            $tooltip = @("Virtual WAN connection $($Connection.Names[0])", "$sourceName $([char]0x2194) $targetName", "State: $($Connection.States[0])") -join "`n"
        }
        $lineStyle = Get-ConnectionLineStyle -Established $Connection.Established
        $layerKind = 'Hybrid'
    }
    return [pscustomobject]@{
        Connection = $Connection; SourceId = $Connection.SourceId; TargetId = $Connection.TargetId
        Label = $label; Tooltip = $tooltip; LineStyle = $lineStyle; LayerKind = $layerKind
    }
}

function New-NetworkOverviewPage {
    param(
        [System.Xml.XmlDocument]$Document,
        [System.Xml.XmlElement]$MxFile,
        [object]$Data,
        [object]$Index,
        [object[]]$Vnets,
        [hashtable]$PageIdByVnetId,
        [bool]$IncludeRangesLink = $true,
        [bool]$IncludeCredit = $true,
        [string]$CollectedAt = '',
        [bool]$IsScoped = $false
    )
    $page=New-DrawIoPageRoot $Document $MxFile 'network-overview' 'Network Overview' 1800 1200;$root=$page.Root

    # The cards: every VNet shown, and the Virtual WAN hubs, all of them in a full export but
    # only those connected to a selected VNet in a filtered one.
    $items=[System.Collections.Generic.List[object]]::new()
    $vnetIds=[System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach($vnet in $Vnets){
        $vnetId=ConvertTo-ResourceId(Get-ObjectValue $vnet 'id');$null=$vnetIds.Add($vnetId)
        $items.Add([pscustomobject]@{Id=$vnetId;Name=[string](Get-ObjectValue $vnet 'name' '(unnamed VNet)');Kind='VNet';Row=$vnet;SubscriptionId=ConvertTo-ResourceId(Get-ObjectValue $vnet 'subscriptionId' '');WanId=''})
    }
    $connectedHubIds=[System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach($hubConnection in $Index.HubConnections){if($vnetIds.Contains((ConvertTo-ResourceId(Get-ObjectValue $hubConnection 'remoteVnetId' '')))){$null=$connectedHubIds.Add((ConvertTo-ResourceId(Get-ObjectValue $hubConnection 'virtualHubId' '')))}}
    foreach($hub in Get-DataRows $Data 'virtualHubs'){
        $hubId=ConvertTo-ResourceId(Get-ObjectValue $hub 'id');if(-not $hubId -or ($IsScoped -and -not $connectedHubIds.Contains($hubId))){continue}
        $items.Add([pscustomobject]@{Id=$hubId;Name=[string](Get-ObjectValue $hub 'name' (Get-ResourceNameFromId $hubId));Kind='Hub';Row=$hub;SubscriptionId=ConvertTo-ResourceId(Get-ObjectValue $hub 'subscriptionId' '');WanId=ConvertTo-ResourceId(Get-ObjectValue $hub 'virtualWanId' '')})
    }
    $shownIds=[System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach($item in $items){$null=$shownIds.Add($item.Id)}
    $connectionData=Get-OverviewConnection -Data $Data -Index $Index -ShownIds $shownIds
    $connections=@($connectionData.Connections)
    $statistics=Get-OverviewStatistic -Items $items -Index $Index -Connections $connections
    $subscriptionNames=@{};foreach($subscription in Get-DataRows $Data 'subscriptions'){$subscriptionNames[(ConvertTo-ResourceId(Get-ObjectValue $subscription 'subscriptionId'))]=[string](Get-ObjectValue $subscription 'subscriptionName' '')}
    $oneSidedByRemoteId=@{}
    foreach($peering in Get-DataRows $Data 'vnetPeerings'){$flow=Get-PeeringFlow $Index $peering;if(-not $flow.HasReverse){Add-IndexValue $oneSidedByRemoteId $flow.RemoteId $flow}}

    # One lane per subscription, then a last one for the connected VNets that have no card of
    # their own. Every card is placed and every line planned before anything is drawn, since
    # the lanes are sized to the lines that run through them.
    $nameById=@{};foreach($item in $items){$nameById[$item.Id]=$item.Name}
    $outsideItems=@(Get-OverviewOutsideItem -Index $Index -Connections $connections -ShownIds $shownIds -NameById $nameById)
    foreach($item in $outsideItems){$nameById[$item.Id]=$item.Name}
    $lanes=@(foreach($group in @($items|Sort-Object SubscriptionId,Name|Group-Object SubscriptionId|Sort-Object Name)){[pscustomobject]@{SubscriptionId=[string]$group.Name;IsOutside=$false;Items=@($group.Group)}})
    if($outsideItems.Count -gt 0){$lanes+=[pscustomobject]@{SubscriptionId='';IsOutside=$true;Items=$outsideItems}}
    $lines=@($connections|Where-Object{$nameById.ContainsKey($_.SourceId) -and $nameById.ContainsKey($_.TargetId)}|ForEach-Object{Get-OverviewLine -Connection $_ -NameById $nameById})
    $placement=Get-OverviewPlacement -Lanes $lanes -Connections $connections -Columns 4
    $routePlan=Get-OverviewRoutePlan -Placement $placement -Lines $lines -Columns 4
    $layout=Get-OverviewLayout -Placement $placement -HorizontalTracks $routePlan.HorizontalTracks -VerticalTracks $routePlan.VerticalTracks
    $routes=@(Get-OverviewRoute -Plans $routePlan.Plans -Placement $placement -Layout $layout)
    $laneWidth=$layout.LaneWidth

    # Without a Network Ranges page there is nothing to link to, so the title takes the full width.
    $titleWidth=if($IncludeRangesLink){$laneWidth-250}else{$laneWidth}
    $collectedNote=if($CollectedAt){" &nbsp;&#183;&nbsp; Data collected $CollectedAt"}else{''}
    Add-MxVertex $Document $root 'overview-title' '1' "<b>Azure Network Overview</b><br><font color='#666666'>$(Format-OverviewStatistic $statistics.Total -IncludeSubscriptions)$collectedNote</font>" 'rounded=1;whiteSpace=wrap;html=1;fillColor=#e6f2ff;strokeColor=#0078d4;strokeWidth=2;fontSize=15;align=left;spacingLeft=12;' 20 20 $titleWidth 65
    if($IncludeRangesLink){Add-MxVertex $Document $root 'ranges-link' '1' 'Network ranges &#8594;' 'rounded=1;whiteSpace=wrap;html=1;fillColor=#e6f2ff;strokeColor=#0078d4;fontColor=#0078d4;fontStyle=1;fontSize=13;' ($laneWidth-210) 20 230 65 '' '' @{link='data:page/id,network-ranges';tooltip='Open the Network Ranges page: public IP addresses, connected ranges, and subnet prefixes'}}

    $cardCellById=@{};$laneNumber=0;$outsideNumber=0
    for($laneIndex=0;$laneIndex -lt $placement.Lanes.Count;$laneIndex++){
        $placedLane=$placement.Lanes[$laneIndex];$laneY=$layout.LaneTop[$laneIndex];$laneHeight=$layout.LaneHeight[$laneIndex]
        if($placedLane.Lane.IsOutside){
            $laneId='outside-lane'
            $subscriptionIds=@($placedLane.Lane.Items|ForEach-Object{if($_.Id -match '^/subscriptions/([^/]+)/'){$Matches[1]}}|Sort-Object -Unique)
            Add-MxVertex $Document $root $laneId '1' "<b>Connected VNets outside this overview</b><br><font color='#666666'>Known only from their connections</font>" `
                'swimlane;html=1;rounded=1;startSize=48;fillColor=#f8f9fa;strokeColor=#adb5bd;dashed=1;fontSize=11;align=left;spacingLeft=20;' 20 $laneY $laneWidth $laneHeight '' '' @{tags='outside'}
            $vnetCount=if($placedLane.Lane.Items.Count -eq 1){'1 VNet'}else{"$($placedLane.Lane.Items.Count) VNets"}
            $subscriptionCount=if($subscriptionIds.Count -eq 1){'1 subscription'}else{"$($subscriptionIds.Count) subscriptions"}
            Add-MxVertex $Document $root "$laneId-counts" $laneId "$vnetCount &#183; $subscriptionCount" 'text;html=1;align=right;verticalAlign=middle;fontSize=11;fontColor=#555555;' ($laneWidth-460) 7 440 20
        }else{
            $laneNumber++;$laneId="subscription-$laneNumber";$subscriptionId=$placedLane.Lane.SubscriptionId
            $subscriptionName=if($subscriptionNames.ContainsKey($subscriptionId)){$subscriptionNames[$subscriptionId]}else{''}
            $heading=if($subscriptionName){"<b>$subscriptionName</b><br><font color='#666666'>$subscriptionId</font>"}else{"<b>Subscription</b><br><font color='#666666'>$subscriptionId</font>"}
            Add-MxVertex $Document $root $laneId '1' $heading 'swimlane;html=1;rounded=1;startSize=48;fillColor=#f8fbff;strokeColor=#6c8ebf;fontSize=11;align=left;spacingLeft=20;' 20 $laneY $laneWidth $laneHeight '' 'Microsoft.Resources/subscriptions' @{azureSubscriptionId=$subscriptionId;tags=(Join-ShapeTag @('subscription',$subscriptionName));tooltip=$(if($subscriptionName){"$subscriptionName`n$subscriptionId"}else{$subscriptionId})}
            # The lane's counts sit right-aligned in its header. Lines between lanes cross
            # headers only in the inner gutters and columns, well left of the text.
            Add-MxVertex $Document $root "$laneId-counts" $laneId (Format-OverviewStatistic $statistics.BySubscription[$subscriptionId]) 'text;html=1;align=right;verticalAlign=middle;fontSize=11;fontColor=#555555;' ($laneWidth-460) 7 440 20
        }
        foreach($card in $placedLane.Cards){
            $item=$card.Item
            $x=$layout.Margin+($card.Column*$layout.Pitch);$y=$layout.RowTop["$laneIndex|$($card.Row)"];$slotNumber=($card.Row*4)+$card.Column+1
            $location=[string](Get-ObjectValue $item.Row 'location' '');$resourceGroup=[string](Get-ObjectValue $item.Row 'resourceGroup' '')
            if($item.Kind -eq 'Outside'){
                $outsideNumber++;$cellId="overview-outside-$outsideNumber"
                $outsideCard=Get-OverviewOutsideCard -External $item.External -SubscriptionNames $subscriptionNames -NameById $nameById
                Add-MxVertex $Document $root $cellId $laneId $outsideCard.Label ((Get-AzureNodeStyle $outsideCard.Kind '#ffffff' '#adb5bd')+'dashed=1;') $x $y 290 82 $item.Id 'Microsoft.Network/virtualNetworks' `
                    @{tooltip=$outsideCard.Tooltip;tags=(Join-ShapeTag @('vnet','outside',$item.Name))}
            }elseif($item.Kind -eq 'Hub'){
                $cellId="overview-hub-$laneNumber-$slotNumber"
                $hubCard=Get-OverviewHubCard -Index $Index -Hub $item.Row -Connections $connections
                Add-MxVertex $Document $root $cellId $laneId $hubCard.Label (Get-AzureNodeStyle 'VirtualHub' '#ffffff' '#9673a6') $x $y 290 82 $item.Id 'Microsoft.Network/virtualHubs' @{tooltip=$hubCard.Tooltip;tags=(Join-ShapeTag @('hub',$item.Name,$location))}
            }else{
                $cellId="overview-vnet-$laneNumber-$slotNumber"
                $summary=Get-OverviewVnetSummary -Index $Index -VnetId $item.Id -ShownIds $shownIds -OneSidedByRemoteId $oneSidedByRemoteId -Connections $connections -UnresolvedVpnByVnetId $connectionData.UnresolvedVpnByVnetId
                $subnetCount=@($Index.SubnetsByVnetId[$item.Id]|Where-Object{$null -ne $_}).Count
                $address=ConvertTo-DisplayList(Get-ObjectValue $item.Row 'addressPrefixes' '')
                $attributes=@{tooltip=((@($summary.Tooltip)+$item.Id) -join "`n");tags=(Join-ShapeTag @('vnet',$item.Name,$location))}
                if($PageIdByVnetId.ContainsKey($item.Id)){$attributes.link="data:page/id,$($PageIdByVnetId[$item.Id])"}
                $label="<b>$($item.Name)</b><br><font color='#777777'><i>Virtual network</i></font><br>$address<br><font color='#666666'>$location | $resourceGroup</font><br>Subnets: $subnetCount &#183; Peerings: $($summary.Count)"
                Add-MxVertex $Document $root $cellId $laneId $label (Get-AzureNodeStyle 'VNet' '#ffffff' '#0078d4') $x $y 290 82 $item.Id 'Microsoft.Network/virtualNetworks' $attributes
            }
            $cardCellById[$item.Id]=$cellId
        }
    }

    # The layers that hold the lines must exist before the lines that reference them.
    $layerKinds=@($lines|ForEach-Object{$_.LayerKind}|Sort-Object -Unique)
    $layerIdByKind=Add-MxPageLayer $Document $root $page.BaseCell $layerKinds
    $peeringNumber=0;$connectionNumber=0
    foreach($route in $routes){
        $line=$route.Plan.Line
        if($line.LayerKind -eq 'Peering'){$peeringNumber++;$edgeId="overview-peering-$peeringNumber"}else{$connectionNumber++;$edgeId="overview-connection-$connectionNumber"}
        $layerId=if($layerIdByKind.ContainsKey($line.LayerKind)){[string]$layerIdByKind[$line.LayerKind]}else{'1'}
        $anchor="exitX=$([math]::Round($route.Exit.FractionX,6));exitY=$([math]::Round($route.Exit.FractionY,6));entryX=$([math]::Round($route.Entry.FractionX,6));entryY=$([math]::Round($route.Entry.FractionY,6));exitPerimeter=0;entryPerimeter=0;"
        # A trunk line drawn from its hub carries its arrowheads swapped to match, and no jump
        # arcs, which would mark every point where the trunk's lines part.
        $sourceId=$line.SourceId;$targetId=$line.TargetId;$lineStyle=$line.LineStyle;$jumps='jumpStyle=arc;jumpSize=8;'
        if($route.Plan.Reverse){$sourceId=$line.TargetId;$targetId=$line.SourceId;$lineStyle=Get-ReversedLineStyle $line.LineStyle}
        if($route.Plan.Trunk){$jumps=''}
        # draw.io follows the bend points exactly, and Clear Waypoints hands a line back to its
        # own orthogonal routing, for instance after cards were moved.
        $style="edgeStyle=orthogonalEdgeStyle;rounded=1;html=1;$($lineStyle)fontSize=9;$($jumps)labelBackgroundColor=#ffffff;$anchor"
        Add-MxEdge $Document $root $edgeId $cardCellById[$sourceId] $cardCellById[$targetId] $line.Label $style '' '' @{tooltip=$line.Tooltip} -Parent $layerId -Points $route.Points
    }
    # Each sentence stays short of the credit, which sits right-aligned on the same lines.
    $currentY=$layout.Bottom
    Add-MxVertex $Document $root 'overview-legend' '1' ('<b>Overview legend</b><br>Click a VNet card for details. Dashed purple lines are VNet peerings; solid purple lines are Virtual WAN hub connections and VNet-to-VNet VPNs. A hub''s many lines share one trunk that branches off to each VNet.' +
        '<br>Arrowheads show the directions traffic may flow; red lines are not connected. Labels mark subnet peerings and other exceptions. NSGs, routes, and firewalls are not evaluated.') 'rounded=1;whiteSpace=wrap;html=1;fillColor=#f8f9fa;strokeColor=#adb5bd;fontSize=10;align=left;spacingLeft=10;' 20 ($currentY+5) $laneWidth 62
    # draw.io replaces the mxfile origin attributes when it saves, so the tool also
    # names itself visibly, right-aligned inside the legend.
    if($IncludeCredit){
        $credit="Created with <b>VNetAtlas</b> $script:VNetAtlasVersion &nbsp;&#183;&nbsp; $($script:VNetAtlasProjectUrl -replace '^https://','')"
        Add-MxVertex $Document $root 'vnetatlas-credit' '1' $credit 'text;html=1;align=right;verticalAlign=middle;fontSize=10;fontColor=#555555;' ($laneWidth-400) ($currentY+26) 410 20 '' '' @{link=$script:VNetAtlasProjectUrl;tooltip='Open the VNetAtlas project page'}
    }
    Set-MxPageSize $page.Model (20+$laneWidth) ($currentY+67)
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

function Add-DetailAssociationList {
    param(
        [System.Xml.XmlDocument]$Document,
        [System.Xml.XmlElement]$Root,
        [object]$Index,
        [hashtable]$PageIdByVnetId,
        [object[]]$Associations,
        [string]$EmptyText,
        [double]$Width
    )

    # Associations are grouped by the VNet of their subnet, because subnet names
    # such as "default" repeat across VNets. Each group links back to its VNet page.
    # Returns the bottom edge of the list.
    $boxStyle = 'rounded=1;whiteSpace=wrap;html=1;fillColor=#f8f9fa;strokeColor=#adb5bd;fontSize=10;align=left;spacingLeft=8;verticalAlign=top;'
    if ($Associations.Count -eq 0) {
        Add-MxVertex $Document $Root 'associations' '1' "<b>Associations</b><br>$EmptyText" $boxStyle 20 100 $Width 65
        return 165
    }
    $groups = @(foreach ($group in @($Associations | Group-Object {
        if ([string]$_.SubnetId -match '^(.*/virtualnetworks/[^/]+)/subnets/') { ConvertTo-ResourceId $Matches[1] } else { '' }
    })) {
        $vnetId = [string]$group.Name
        $vnetName = 'Unknown VNet'
        if ($Index.VnetById.ContainsKey($vnetId)) {
            $vnetName = [string](Get-ObjectValue $Index.VnetById[$vnetId] 'name' (Get-ResourceNameFromId $vnetId))
        } elseif ($vnetId) {
            $vnetName = Get-ResourceNameFromId $vnetId
        }
        $lines = @($group.Group | ForEach-Object { [string]$_.Text } | Select-Object -Unique)
        [pscustomobject]@{ VnetId = $vnetId; Name = $vnetName; Lines = $lines; Height = 12 + (16 * (1 + $lines.Count)) }
    })
    $groups = @($groups | Sort-Object Name)
    $boxHeight = 34 + (($groups | Measure-Object Height -Sum).Sum) + (6 * $groups.Count)
    Add-MxVertex $Document $Root 'associations' '1' '<b>Associations</b>' $boxStyle 20 100 $Width $boxHeight

    $rowStyle = 'rounded=1;whiteSpace=wrap;html=1;fillColor=#ffffff;strokeColor=#adb5bd;fontSize=10;align=left;spacingLeft=8;verticalAlign=top;'
    $y = 128
    for ($groupIndex = 0; $groupIndex -lt $groups.Count; $groupIndex++) {
        $group = $groups[$groupIndex]
        if ($PageIdByVnetId.ContainsKey($group.VnetId)) {
            $heading = "<font color='#0078d4'><b>$($group.Name)</b> &#8594;</font>"
            $attributes = @{ link = "data:page/id,$($PageIdByVnetId[$group.VnetId])"; tooltip = 'Open the VNet page' }
        } else {
            $heading = "<b>$($group.Name)</b> <font color='#666666'>(no VNet page in this diagram)</font>"
            $attributes = @{ tooltip = $group.VnetId }
        }
        Add-MxVertex -Document $Document -Root $Root -Id "association-vnet-$($groupIndex + 1)" -Parent '1' `
            -Value "$heading<br>$($group.Lines -join '<br>')" -Style $rowStyle `
            -X 30 -Y $y -Width ($Width - 20) -Height $group.Height -Attributes $attributes
        $y += $group.Height + 6
    }
    return 100 + $boxHeight
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
    param([System.Xml.XmlDocument]$Document,[System.Xml.XmlElement]$MxFile,[object]$Index,[object]$Nsg,[string]$PageId,[bool]$IncludeDefaultRules = $true,[hashtable]$PageIdByVnetId = @{})
    $id=ConvertTo-ResourceId(Get-ObjectValue $Nsg 'id');$name=[string](Get-ObjectValue $Nsg 'name' (Get-ResourceNameFromId $id));$page=New-DrawIoPageRoot $Document $MxFile $PageId "NSG - $name" 1800 1200;$root=$page.Root;Add-DetailNavigation $Document $root
    $customRules=@(ConvertFrom-JsonCollection(Get-ObjectValue $Nsg 'securityRules' ''));foreach($rule in $customRules){$rule|Add-Member -NotePropertyName '_isDefault' -NotePropertyValue $false -Force}
    $defaultRules=@()
    if($IncludeDefaultRules){$defaultRules=@(ConvertFrom-JsonCollection(Get-ObjectValue $Nsg 'defaultSecurityRules' ''));foreach($rule in $defaultRules){$rule|Add-Member -NotePropertyName '_isDefault' -NotePropertyValue $true -Force}}
    $rules=@($customRules+$defaultRules)
    # A missing index entry pipes a single $null, which would render as an empty association.
    $subnetAssociations=@($Index.SubnetsByNsgId[$id]|Where-Object{$null-ne$_}|ForEach-Object{[pscustomobject]@{SubnetId=[string](Get-ObjectValue $_ 'id' '');Text="Subnet: $(Get-ObjectValue $_ 'name' '')"}}|Sort-Object Text)
    $nicAssociations=@($Index.NicRowsByNsgId[$id]|Where-Object{$null-ne$_}|ForEach-Object{[pscustomobject]@{SubnetId=[string](Get-ObjectValue $_ 'subnetId' '');Text="NIC: $(Get-ObjectValue $_ 'nicName' '')"}}|Sort-Object Text)
    $vmssAssociations = @()
    if ($Index.VmssIdsByNsgId.ContainsKey($id)) {
        # A scale set spanning several subnets is listed under each of their VNets.
        $vmssAssociations = @(@(foreach ($scaleSetIdValue in $Index.VmssIdsByNsgId[$id]) {
            $scaleSetId = [string]$scaleSetIdValue
            if ($Index.VmssRelationById.ContainsKey($scaleSetId)) {
                $vmssRelation = $Index.VmssRelationById[$scaleSetId]
                foreach ($subnetId in @($vmssRelation.SubnetIds)) {
                    [pscustomobject]@{SubnetId=[string]$subnetId;Text="VMSS: $(Get-ObjectValue $vmssRelation.ScaleSet 'name' '')"}
                }
            }
        }) | Sort-Object Text)
    }
    $title="<b>$name</b><br><font color='#666666'>Network Security Group | $(Get-ObjectValue $Nsg 'resourceGroup' '') | $(Get-ObjectValue $Nsg 'location' '')</font>";Add-MxVertex $Document $root 'detail-title' '1' $title (Get-AzureNodeStyle 'NSG' '#fffaf0' '#d6b656') 270 15 720 62 $id 'Microsoft.Network/networkSecurityGroups' @{tooltip=$id;tags=(Join-ShapeTag @('nsg','detail',$name))}
    $associationsBottom=Add-DetailAssociationList -Document $Document -Root $root -Index $Index -PageIdByVnetId $PageIdByVnetId `
        -Associations @($subnetAssociations+$nicAssociations+$vmssAssociations) -EmptyText 'No NIC, VMSS, or subnet associations found' -Width 1440
    $tableY=$associationsBottom+25
    $inboundRules=@($rules|Where-Object{[string](Get-ObjectValue (Get-ObjectValue $_ 'properties' $_) 'direction' '')-ieq'Inbound'})
    $outboundRules=@($rules|Where-Object{[string](Get-ObjectValue (Get-ObjectValue $_ 'properties' $_) 'direction' '')-ieq'Outbound'})
    $nextY=Add-NsgRuleTable -Document $Document -Root $root -Rules $inboundRules -Direction 'Inbound' -IdPrefix 'inbound' -StartY $tableY
    $bottomY=Add-NsgRuleTable -Document $Document -Root $root -Rules $outboundRules -Direction 'Outbound' -IdPrefix 'outbound' -StartY $nextY
    Set-MxPageSize $page.Model 1460 $bottomY
}

function New-RouteTableDetailPage {
    param([System.Xml.XmlDocument]$Document,[System.Xml.XmlElement]$MxFile,[object]$Index,[object]$RouteTable,[string]$PageId,[hashtable]$PageIdByVnetId = @{})
    # A missing index entry pipes a single $null, and single-prefix subnets report an empty
    # addressPrefixes string rather than null, so fall back to addressPrefix explicitly.
    $id=ConvertTo-ResourceId(Get-ObjectValue $RouteTable 'id');$name=[string](Get-ObjectValue $RouteTable 'name' (Get-ResourceNameFromId $id));$page=New-DrawIoPageRoot $Document $MxFile $PageId "Routes - $name" 1800 1200;$root=$page.Root;Add-DetailNavigation $Document $root;$routes=@(ConvertFrom-JsonCollection(Get-ObjectValue $RouteTable 'routes' ''))
    $associations=@($Index.SubnetsByRouteTableId[$id]|Where-Object{$null-ne$_}|ForEach-Object{
        $subnetPrefix=ConvertTo-DisplayList (Get-ObjectValue $_ 'addressPrefixes' '')
        if(-not$subnetPrefix){$subnetPrefix=[string](Get-ObjectValue $_ 'addressPrefix' '')}
        $text=if($subnetPrefix){"Subnet: $(Get-ObjectValue $_ 'name' '') ($subnetPrefix)"}else{"Subnet: $(Get-ObjectValue $_ 'name' '')"}
        [pscustomobject]@{SubnetId=[string](Get-ObjectValue $_ 'id' '');Text=$text}
    }|Sort-Object Text)
    $title="<b>$name</b><br><font color='#666666'>Route table | $(Get-ObjectValue $RouteTable 'resourceGroup' '') | BGP propagation disabled: $(if((ConvertTo-NullableBoolean (Get-ObjectValue $RouteTable 'disableBgpRoutePropagation')) -eq $true){'True'}else{'False'})</font>";Add-MxVertex $Document $root 'detail-title' '1' $title (Get-AzureNodeStyle 'RouteTable' '#fffaf0' '#d6b656') 270 15 720 62 $id 'Microsoft.Network/routeTables' @{tooltip=$id;tags=(Join-ShapeTag @('routetable','detail',$name))}
    $associationsBottom=Add-DetailAssociationList -Document $Document -Root $root -Index $Index -PageIdByVnetId $PageIdByVnetId `
        -Associations $associations -EmptyText 'No subnet associations found' -Width 1200
    $columns=@(@{Name='Route name';Width=340},@{Name='Address prefix';Width=300},@{Name='Next hop type';Width=260},@{Name='Next hop IP address';Width=300});$tableY=$associationsBottom+25;$x=20;$columnX=@();for($i=0;$i-lt$columns.Count;$i++){$columnX+=$x;Add-DetailTableCell $Document $root "header-$i" $columns[$i].Name $x $tableY $columns[$i].Width 34 -Header;$x+=$columns[$i].Width}
    if($routes.Count-eq0){Add-MxVertex $Document $root 'no-routes' '1' 'No custom routes.' 'rounded=0;whiteSpace=wrap;html=1;fillColor=#ffffff;strokeColor=#b3b3b3;fontSize=10;' 20 ($tableY+34) ($x-20) 45;Set-MxPageSize $page.Model 1220 ($tableY+79);return}
    $row=0;foreach($route in @($routes|Sort-Object name)){$properties=Get-ObjectValue $route 'properties' $route;$values=@([string](Get-ObjectValue $route 'name' ''),[string](Get-ObjectValue $properties 'addressPrefix' ''),[string](Get-ObjectValue $properties 'nextHopType' ''),[string](Get-ObjectValue $properties 'nextHopIpAddress' ''));$y=$tableY+34+($row*48);for($i=0;$i-lt$columns.Count;$i++){Add-DetailTableCell $Document $root "route-$row-$i" $values[$i] $columnX[$i] $y $columns[$i].Width 48};$row++}
    Set-MxPageSize $page.Model 1220 ($tableY+34+($row*48))
}

function Get-PrefixList {
    param([AllowNull()][object]$Value)

    # Resource Graph returns prefix arrays as JSON text and single prefixes as plain text.
    $text = ([string]$Value).Trim()
    if (-not $text -or $text -eq '[]') { return @() }
    if ($text.StartsWith('[')) {
        return @(ConvertFrom-JsonCollection $text | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ })
    }
    return @($text)
}

function Get-RangePlacement {
    param([hashtable]$PlacedVnetIdsByResourceId,[hashtable]$VnetById,[string[]]$ResourceId)

    # Several IDs combine, for a resource reached through more than one drawn resource.
    $placedIds = foreach ($id in @($ResourceId | Where-Object { $_ })) {
        if ($PlacedVnetIdsByResourceId.ContainsKey($id)) { $PlacedVnetIdsByResourceId[$id] }
    }
    return ConvertTo-RangePlacement -VnetIds @($placedIds | ForEach-Object { [string]$_ }) -VnetById $VnetById
}

function ConvertTo-RangePlacement {
    param([string[]]$VnetIds,[hashtable]$VnetById)

    $vnetIds = @($VnetIds | Where-Object { $_ } | Sort-Object -Unique)
    $vnetNames = @($vnetIds | ForEach-Object {
        if ($VnetById.ContainsKey($_)) {
            [string](Get-ObjectValue $VnetById[$_] 'name' (Get-ResourceNameFromId $_))
        } else {
            Get-ResourceNameFromId $_
        }
    } | Sort-Object -Unique)
    return [pscustomobject]@{ VnetIds=$vnetIds; VnetNames=$vnetNames }
}

function Get-PublicAddressOwnerMap {
    param([object]$Data,[object]$Index)

    # Built from the same references the VNet pages draw, so a public IP is listed as
    # attached to the resource its VNet page shows it attached to.
    $owners = @{}
    foreach ($nic in Get-DataRows $Data 'nics') {
        $publicIpId = ConvertTo-ResourceId (Get-ObjectValue $nic 'publicIpId' '')
        if (-not $publicIpId) { continue }
        $nicId = ConvertTo-ResourceId (Get-ObjectValue $nic 'nicId' '')
        $nicName = [string](Get-ObjectValue $nic 'nicName' (Get-ResourceNameFromId $nicId))
        $vmRows = @($Index.VmRowsByNicId[$nicId] | Where-Object { $null -ne $_ })
        if ($vmRows.Count -gt 0) {
            $owner = "$(Get-FriendlyResourceType 'VM' '' ''): $(Get-ObjectValue $vmRows[0] 'name' '') (NIC $nicName)"
        } else {
            $owner = "$(Get-FriendlyResourceType 'NIC' '' ''): $nicName"
        }
        Add-IndexValue $owners $publicIpId $owner
    }
    foreach ($definition in @(
        @{Relations=$Index.LoadBalancerRelationById;Kind='LoadBalancer';Property='PublicIpIds';Suffix=''},
        @{Relations=$Index.ApplicationGatewayRelationById;Kind='ApplicationGateway';Property='PublicIpIds';Suffix=''},
        @{Relations=$Index.FirewallRelationById;Kind='Firewall';Property='PublicIpIds';Suffix=''},
        @{Relations=$Index.FirewallRelationById;Kind='Firewall';Property='ManagementPublicIpIds';Suffix=' (management)'},
        @{Relations=$Index.GatewayRelationById;Kind='Gateway';Property='PublicIpIds';Suffix=''},
        @{Relations=$Index.BastionRelationById;Kind='Bastion';Property='PublicIpIds';Suffix=''}
    )) {
        foreach ($ownerId in @($definition.Relations.Keys | Sort-Object)) {
            $relation = $definition.Relations[$ownerId]
            $ownerName = [string](Get-ObjectValue @($relation.Rows)[0] 'name' (Get-ResourceNameFromId $ownerId))
            $owner = "$(Get-FriendlyResourceType $definition.Kind '' ''): $ownerName$($definition.Suffix)"
            foreach ($publicIpId in @($relation.($definition.Property))) {
                if ($publicIpId) { Add-IndexValue $owners ([string]$publicIpId) $owner }
            }
        }
    }
    foreach ($natGateway in Get-DataRows $Data 'natGateways') {
        $natGatewayId = ConvertTo-ResourceId (Get-ObjectValue $natGateway 'id')
        $owner = "$(Get-FriendlyResourceType 'NAT' '' ''): $(Get-ObjectValue $natGateway 'name' (Get-ResourceNameFromId $natGatewayId))"
        foreach ($property in @('publicIpIds', 'publicIpIdsV6', 'publicIpPrefixIds', 'publicIpPrefixIdsV6')) {
            foreach ($referencedId in @(Get-IdsFromJson (Get-ObjectValue $natGateway $property ''))) {
                if ($referencedId) { Add-IndexValue $owners ([string]$referencedId) $owner }
            }
        }
    }
    return $owners
}

function New-PublicAddressRow {
    param(
        [string]$Category,
        [string]$Range,
        [string]$IpVersion,
        [string]$Name,
        [string]$Detail,
        [string]$Fqdn,
        [string[]]$Owners,
        [object]$Placement,
        [object]$Source,
        [string]$ResourceId
    )

    $info = Get-AddressPrefixInfo $Range
    if (-not $IpVersion) { $IpVersion = $info.IpVersion }
    # Unallocated addresses sort last, after IPv4 and IPv6.
    $sortGroup = 2
    if ($info.IsIPv4) { $sortGroup = 0 } elseif ($info.IsValid) { $sortGroup = 1 }
    return [pscustomobject]@{
        Category=$Category; Range=$Range; IpVersion=$IpVersion; Name=$Name; Detail=$Detail; Fqdn=$Fqdn
        Owners=@($Owners | Where-Object { $_ }); VnetIds=$Placement.VnetIds; VnetNames=$Placement.VnetNames
        SubscriptionId=[string](Get-ObjectValue $Source 'subscriptionId' '')
        ResourceGroup=[string](Get-ObjectValue $Source 'resourceGroup' '')
        Location=[string](Get-ObjectValue $Source 'location' '')
        ResourceId=$ResourceId; SortGroup=$sortGroup; SortStart=$info.Start
    }
}

function New-ConnectedRangeRow {
    param(
        [string]$Category,
        [string]$Type,
        [string]$Name,
        [string[]]$Prefixes,
        [string[]]$Detail,
        [object]$Placement,
        [object]$Source,
        [string]$ResourceId,
        [string]$EmptyText = 'None'
    )

    return [pscustomobject]@{
        Category=$Category; Type=$Type; Name=$Name; Prefixes=@($Prefixes | Where-Object { $_ })
        Detail=(@($Detail | Where-Object { $_ }) -join ' | '); EmptyText=$EmptyText
        VnetIds=$Placement.VnetIds; VnetNames=$Placement.VnetNames
        SubscriptionId=[string](Get-ObjectValue $Source 'subscriptionId' '')
        ResourceGroup=[string](Get-ObjectValue $Source 'resourceGroup' '')
        Location=[string](Get-ObjectValue $Source 'location' ''); ResourceId=$ResourceId
    }
}

function Select-UniqueValue {
    param([object[]]$Values)

    # Keeps the first occurrence of each non-empty value, in its original order.
    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($value in $Values) {
        $text = ([string]$value).Trim()
        if ($text -and $seen.Add($text)) { $text }
    }
}

function Get-ClientPoolPrefix {
    param([object[]]$Configurations)

    # Classic gateway user-group configurations and Virtual WAN point-to-site
    # configurations share this shape.
    foreach ($configuration in $Configurations) {
        $pool = Get-ObjectValue (Get-ObjectValue $configuration 'properties' $null) 'vpnClientAddressPool' $null
        foreach ($prefix in @(Get-ObjectValue $pool 'addressPrefixes' @())) { [string]$prefix }
    }
}

function Get-VpnSiteSummary {
    param([AllowNull()][object]$Site)

    # A site lists its device address either once for the site or per link.
    $linkProperties = @(ConvertFrom-JsonCollection (Get-ObjectValue $Site 'siteLinks' '') | ForEach-Object { Get-ObjectValue $_ 'properties' $_ })
    $endpoints = @(Select-UniqueValue (@(Get-ObjectValue $Site 'ipAddress' '') + @($linkProperties | ForEach-Object {
        $endpoint = [string](Get-ObjectValue $_ 'ipAddress' '')
        if (-not $endpoint) { $endpoint = [string](Get-ObjectValue $_ 'fqdn' '') }
        $endpoint
    })))
    $asns = @(Select-UniqueValue (@(Get-ObjectValue $Site 'bgpAsn' '') + @($linkProperties | ForEach-Object {
        Get-ObjectValue (Get-ObjectValue $_ 'bgpProperties' $null) 'asn' ''
    })) | Where-Object { $_ -ne '0' })
    return [pscustomobject]@{
        Prefixes=@(Get-PrefixList (Get-ObjectValue $Site 'addressPrefixes' '')); Endpoints=$endpoints; Asns=$asns
    }
}

function New-SubnetRangeRow {
    param([object]$Subnet)

    $prefixes = @(Get-PrefixList (Get-ObjectValue $Subnet 'addressPrefixes' ''))
    if ($prefixes.Count -eq 0) { $prefixes = @(Get-PrefixList (Get-ObjectValue $Subnet 'addressPrefix' '')) }
    $prefixInfos = @($prefixes | ForEach-Object { Get-AddressPrefixInfo $_ })
    $usable = [long]0
    $hasIPv4 = $false
    $hasIPv6 = $false
    foreach ($info in $prefixInfos) {
        if ($info.IsIPv4) {
            $hasIPv4 = $true
            # Azure reserves the first four addresses and the last one in every subnet.
            if ($info.Size -gt 5) { $usable += $info.Size - 5 }
        } elseif ($info.IsValid) {
            $hasIPv6 = $true
        }
    }
    $usableText = ''
    if ($hasIPv4) { $usableText = Format-InvariantNumber $usable }
    if ($hasIPv6) {
        if ($usableText) { $usableText += ' + IPv6' } else { $usableText = 'IPv6' }
    }

    # Each IP configuration holds one address. Delegated and service-linked subnets
    # are run by the service, which does not report its addresses here.
    $delegation = Get-JsonPropertyList (Get-ObjectValue $Subnet 'delegations' '') 'properties.serviceName'
    $ipConfigurations = Get-ObjectValue $Subnet 'ipConfigurations' $null
    $serviceLinkCount = @(ConvertFrom-JsonCollection (Get-ObjectValue $Subnet 'serviceAssociationLinks' '')).Count
    if ($null -eq $ipConfigurations) {
        $occupancyState = 'NotReported'
        $occupancyText = 'Not reported'
    } else {
        $configurationCount = @(ConvertFrom-JsonCollection $ipConfigurations).Count
        if ($configurationCount -gt 0) {
            $occupancyState = 'InUse'
            $occupancyText = if ($configurationCount -eq 1) { '1 IP config' } else { "$configurationCount IP configs" }
        } elseif ($delegation -or $serviceLinkCount -gt 0) {
            $occupancyState = 'ServiceManaged'
            $occupancyText = 'Service-managed'
        } else {
            $occupancyState = 'Empty'
            $occupancyText = 'Empty'
        }
    }

    $nsgId = ConvertTo-ResourceId (Get-ObjectValue $Subnet 'nsgId' '')
    $routeTableId = ConvertTo-ResourceId (Get-ObjectValue $Subnet 'routeTableId' '')
    $sortGroup = 1
    $sortStart = [long]0
    if ($prefixInfos.Count -gt 0 -and $prefixInfos[0].IsIPv4) {
        $sortGroup = 0
        $sortStart = $prefixInfos[0].Start
    }
    return [pscustomobject]@{
        Name=[string](Get-ObjectValue $Subnet 'name' '(unnamed subnet)')
        SubnetId=(ConvertTo-ResourceId (Get-ObjectValue $Subnet 'id'))
        Prefixes=$prefixInfos; Usable=$usableText; OccupancyState=$occupancyState; Occupancy=$occupancyText
        NsgId=$nsgId; NsgName=$(if ($nsgId) { Get-ResourceNameFromId $nsgId } else { '' })
        RouteTableId=$routeTableId; RouteTableName=$(if ($routeTableId) { Get-ResourceNameFromId $routeTableId } else { '' })
        Delegation=$delegation
        SubscriptionId=[string](Get-ObjectValue $Subnet 'subscriptionId' '')
        ResourceGroup=[string](Get-ObjectValue $Subnet 'resourceGroup' '')
        Location=[string](Get-ObjectValue $Subnet 'location' '')
        SortGroup=$sortGroup; SortStart=$sortStart
    }
}

function Get-NetworkRangeData {
    param(
        [object]$Data,
        [object]$Index,
        [object[]]$Vnets,
        [hashtable]$PlacedVnetIdsByResourceId,
        [bool]$IsScoped
    )

    # A filtered run keeps only resources drawn on a selected VNet page, the same
    # reasoning that suppresses the Unmapped Resources page.
    $ownersById = Get-PublicAddressOwnerMap -Data $Data -Index $Index
    $pagedVnetIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($vnet in $Vnets) { $null = $pagedVnetIds.Add((ConvertTo-ResourceId (Get-ObjectValue $vnet 'id'))) }
    $kindByType = @{
        'microsoft.network/networkinterfaces'='NIC'; 'microsoft.network/loadbalancers'='LoadBalancer'
        'microsoft.network/applicationgateways'='ApplicationGateway'; 'microsoft.network/azurefirewalls'='Firewall'
        'microsoft.network/virtualnetworkgateways'='Gateway'; 'microsoft.network/bastionhosts'='Bastion'
        'microsoft.network/natgateways'='NAT'
    }

    $publicAddresses = [System.Collections.Generic.List[object]]::new()
    foreach ($publicIp in Get-DataRows $Data 'publicIps') {
        $id = ConvertTo-ResourceId (Get-ObjectValue $publicIp 'id')
        if (-not $id) { continue }
        $placement = Get-RangePlacement $PlacedVnetIdsByResourceId $Index.VnetById $id
        if ($IsScoped -and $placement.VnetIds.Count -eq 0) { continue }
        $owners = @($ownersById[$id] | Where-Object { $_ } | Sort-Object -Unique)
        if ($owners.Count -eq 0) {
            # Owner types the exporter does not query are still named from the public
            # IP's own reference.
            $ownerId = ConvertTo-ResourceId (Get-ObjectValue $publicIp 'natGatewayId' '')
            $configurationId = ConvertTo-ResourceId (Get-ObjectValue $publicIp 'ipConfigurationId' '')
            if ($configurationId) { $ownerId = ConvertTo-ResourceId (Get-SubnetOccupantId $configurationId) }
            if ($ownerId) {
                $ownerType = (Get-ResourceTypeFromId $ownerId).ToLowerInvariant()
                $ownerKind = if ($kindByType.ContainsKey($ownerType)) { [string]$kindByType[$ownerType] } else { '' }
                $owners = @("$(Get-FriendlyResourceType $ownerKind $ownerType $ownerId): $(Get-ResourceNameFromId $ownerId)")
            }
        }
        $ipVersion = [string](Get-ObjectValue $publicIp 'ipVersion' '')
        $detail = @((Get-ObjectValue $publicIp 'sku' ''), $ipVersion, (Get-ObjectValue $publicIp 'allocationMethod' '')) | Where-Object { $_ }
        $publicAddresses.Add((New-PublicAddressRow -Category 'PublicIp' -Range ([string](Get-ObjectValue $publicIp 'ipAddress' '')) `
            -IpVersion $ipVersion -Name ([string](Get-ObjectValue $publicIp 'name' (Get-ResourceNameFromId $id))) `
            -Detail ($detail -join ' / ') -Fqdn ([string](Get-ObjectValue $publicIp 'fqdn' '')) -Owners $owners `
            -Placement $placement -Source $publicIp -ResourceId $id))
    }
    foreach ($prefix in Get-DataRows $Data 'publicIpPrefixes') {
        $id = ConvertTo-ResourceId (Get-ObjectValue $prefix 'id')
        if (-not $id) { continue }
        $placement = Get-RangePlacement $PlacedVnetIdsByResourceId $Index.VnetById $id
        if ($IsScoped -and $placement.VnetIds.Count -eq 0) { continue }
        $ipVersion = [string](Get-ObjectValue $prefix 'ipVersion' '')
        $prefixLength = [string](Get-ObjectValue $prefix 'prefixLength' '')
        $prefixLabel = if ($prefixLength) { "Prefix /$prefixLength" } else { 'Prefix' }
        $detail = @((Get-ObjectValue $prefix 'sku' ''), $ipVersion, $prefixLabel) | Where-Object { $_ }
        $publicAddresses.Add((New-PublicAddressRow -Category 'PublicIpPrefix' -Range ([string](Get-ObjectValue $prefix 'ipPrefix' '')) `
            -IpVersion $ipVersion -Name ([string](Get-ObjectValue $prefix 'name' (Get-ResourceNameFromId $id))) `
            -Detail ($detail -join ' / ') -Fqdn '' -Owners @($ownersById[$id] | Where-Object { $_ } | Sort-Object -Unique) `
            -Placement $placement -Source $prefix -ResourceId $id))
    }
    # Secured-hub firewalls get Azure-managed public addresses that are not public IP resources.
    foreach ($firewallId in @($Index.FirewallRelationById.Keys | Sort-Object)) {
        $firewall = @($Index.FirewallRelationById[$firewallId].Rows)[0]
        $hubAddresses = @(ConvertFrom-JsonCollection (Get-ObjectValue $firewall 'hubPublicIpAddresses' '') |
            ForEach-Object { [string](Get-ObjectValue $_ 'address' '') } | Where-Object { $_ })
        if ($hubAddresses.Count -eq 0) { continue }
        $placement = Get-RangePlacement $PlacedVnetIdsByResourceId $Index.VnetById $firewallId
        if ($IsScoped -and $placement.VnetIds.Count -eq 0) { continue }
        $name = [string](Get-ObjectValue $firewall 'name' (Get-ResourceNameFromId $firewallId))
        $owner = "$(Get-FriendlyResourceType 'Firewall' '' ''): $name"
        $hubId = ConvertTo-ResourceId (Get-ObjectValue $firewall 'virtualHubId' '')
        if ($hubId) { $owner += " (secured hub $(Get-ResourceNameFromId $hubId))" }
        $detail = @((Get-ObjectValue $firewall 'sku' ''), (Get-ObjectValue $firewall 'tier' '')) | Where-Object { $_ }
        foreach ($address in $hubAddresses) {
            $publicAddresses.Add((New-PublicAddressRow -Category 'FirewallHubPublicIp' -Range $address -IpVersion '' -Name $name `
                -Detail ($detail -join ' / ') -Fqdn '' -Owners @($owner) -Placement $placement -Source $firewall -ResourceId $firewallId))
        }
    }
    # Virtual WAN VPN gateways and point-to-site gateways are not drawn on VNet pages.
    # They belong to a hub, so they reach the VNets whose pages drew that hub.
    $vpnGatewayGroups = @(Get-DataRows $Data 'vpnGateways' | Group-Object { ConvertTo-ResourceId (Get-ObjectValue $_ 'id') } | Sort-Object Name)
    $hubIdsBySiteId = @{}
    foreach ($group in $vpnGatewayGroups) {
        $gatewayId = [string]$group.Name
        if (-not $gatewayId) { continue }
        $gateway = $group.Group[0]
        $hubId = ConvertTo-ResourceId (Get-ObjectValue $gateway 'virtualHubId' '')
        foreach ($row in $group.Group) {
            $siteId = ConvertTo-ResourceId (Get-ObjectValue $row 'remoteVpnSiteId' '')
            if ($siteId -and $hubId) { Add-IndexValue $hubIdsBySiteId $siteId $hubId }
        }
        $addresses = @(Select-UniqueValue @(ConvertFrom-JsonCollection (Get-ObjectValue $gateway 'ipConfigurations' '') |
            ForEach-Object { Get-ObjectValue $_ 'publicIpAddress' '' }))
        if ($addresses.Count -eq 0) { continue }
        $placement = Get-RangePlacement $PlacedVnetIdsByResourceId $Index.VnetById $hubId
        if ($IsScoped -and $placement.VnetIds.Count -eq 0) { continue }
        $name = [string](Get-ObjectValue $gateway 'name' (Get-ResourceNameFromId $gatewayId))
        $owner = "$(Get-FriendlyResourceType 'VpnGateway' '' ''): $name"
        if ($hubId) { $owner += " (hub $(Get-ResourceNameFromId $hubId))" }
        $scaleUnits = [string](Get-ObjectValue $gateway 'scaleUnits' '')
        $detail = if ($scaleUnits) { "Scale units $scaleUnits" } else { '' }
        foreach ($address in $addresses) {
            $publicAddresses.Add((New-PublicAddressRow -Category 'VpnGatewayPublicIp' -Range $address -IpVersion '' -Name $name `
                -Detail $detail -Fqdn '' -Owners @($owner) -Placement $placement -Source $gateway -ResourceId $gatewayId))
        }
    }

    $connectedRanges = [System.Collections.Generic.List[object]]::new()
    foreach ($gateway in Get-DataRows $Data 'localNetworkGateways') {
        $id = ConvertTo-ResourceId (Get-ObjectValue $gateway 'id')
        if (-not $id) { continue }
        $placement = Get-RangePlacement $PlacedVnetIdsByResourceId $Index.VnetById $id
        if ($IsScoped -and $placement.VnetIds.Count -eq 0) { continue }
        $gatewayIp = [string](Get-ObjectValue $gateway 'gatewayIpAddress' '')
        $bgpAsn = [string](Get-ObjectValue $gateway 'bgpAsn' '')
        $bgpPeer = [string](Get-ObjectValue $gateway 'bgpPeeringAddress' '')
        $connectedRanges.Add((New-ConnectedRangeRow -Category 'LocalNetworkGateway' -Type (Get-FriendlyResourceType 'LocalNetworkGateway' '' '') `
            -Name ([string](Get-ObjectValue $gateway 'name' (Get-ResourceNameFromId $id))) `
            -Prefixes @(Get-PrefixList (Get-ObjectValue $gateway 'addressPrefixes' '')) `
            -Detail @($(if ($gatewayIp) { "Gateway IP $gatewayIp" }), $(if ($bgpAsn) { "BGP ASN $bgpAsn" }), $(if ($bgpPeer) { "BGP peer $bgpPeer" })) `
            -Placement $placement -Source $gateway -ResourceId $id))
    }
    foreach ($site in Get-DataRows $Data 'vpnSites') {
        $id = ConvertTo-ResourceId (Get-ObjectValue $site 'id')
        if (-not $id) { continue }
        $hubIds = @($hubIdsBySiteId[$id] | Where-Object { $_ } | Sort-Object -Unique)
        $placement = Get-RangePlacement $PlacedVnetIdsByResourceId $Index.VnetById $hubIds
        if ($IsScoped -and $placement.VnetIds.Count -eq 0) { continue }
        $siteSummary = Get-VpnSiteSummary $site
        $hubNames = @($hubIds | ForEach-Object { Get-ResourceNameFromId $_ })
        $connectedRanges.Add((New-ConnectedRangeRow -Category 'VpnSite' -Type (Get-FriendlyResourceType 'VpnSite' '' '') `
            -Name ([string](Get-ObjectValue $site 'name' (Get-ResourceNameFromId $id))) -Prefixes $siteSummary.Prefixes `
            -Detail @($(if ($siteSummary.Endpoints.Count -gt 0) { "Link IP $($siteSummary.Endpoints -join ', ')" }),
                $(if ($siteSummary.Asns.Count -gt 0) { "BGP ASN $($siteSummary.Asns -join ', ')" }),
                $(if ($hubNames.Count -gt 0) { "Hub $($hubNames -join ', ')" } else { 'Not connected to a hub' })) `
            -Placement $placement -Source $site -ResourceId $id))
    }
    foreach ($gatewayId in @($Index.GatewayRelationById.Keys | Sort-Object)) {
        $relation = $Index.GatewayRelationById[$gatewayId]
        $gateway = @($relation.Rows)[0]
        $configurations = @(ConvertFrom-JsonCollection (Get-ObjectValue $gateway 'vpnClientConnectionConfigurations' ''))
        $prefixes = @(Select-UniqueValue (@(Get-PrefixList (Get-ObjectValue $gateway 'vpnClientAddressPrefixes' '')) + @(Get-ClientPoolPrefix $configurations)))
        if ($prefixes.Count -eq 0) { continue }
        # A gateway is also drawn as the remote end of VNet-to-VNet connections, so
        # its own VNet comes from its subnet rather than from where it was drawn.
        $gatewayVnetIds = @($relation.SubnetIds | ForEach-Object {
            if ($Index.SubnetById.ContainsKey($_)) { ConvertTo-ResourceId (Get-ObjectValue $Index.SubnetById[$_] 'vnetId') }
        } | Where-Object { $pagedVnetIds.Contains($_) })
        $placement = ConvertTo-RangePlacement -VnetIds $gatewayVnetIds -VnetById $Index.VnetById
        if ($IsScoped -and $placement.VnetIds.Count -eq 0) { continue }
        $configurationNames = @(Select-UniqueValue @($configurations | ForEach-Object { Get-ObjectValue $_ 'name' '' }))
        $connectedRanges.Add((New-ConnectedRangeRow -Category 'VpnClientPool' -Type 'VPN client pool' `
            -Name ([string](Get-ObjectValue $gateway 'name' (Get-ResourceNameFromId $gatewayId))) -Prefixes $prefixes `
            -Detail @((Get-FriendlyResourceType 'Gateway' '' ''), $(if ($configurationNames.Count -gt 0) { "Configurations $($configurationNames -join ', ')" })) `
            -Placement $placement -Source $gateway -ResourceId $gatewayId))
    }
    foreach ($gateway in Get-DataRows $Data 'p2sVpnGateways') {
        $id = ConvertTo-ResourceId (Get-ObjectValue $gateway 'id')
        if (-not $id) { continue }
        $configurations = @(ConvertFrom-JsonCollection (Get-ObjectValue $gateway 'connectionConfigurations' ''))
        $prefixes = @(Select-UniqueValue @(Get-ClientPoolPrefix $configurations))
        if ($prefixes.Count -eq 0) { continue }
        $hubId = ConvertTo-ResourceId (Get-ObjectValue $gateway 'virtualHubId' '')
        $placement = Get-RangePlacement $PlacedVnetIdsByResourceId $Index.VnetById $hubId
        if ($IsScoped -and $placement.VnetIds.Count -eq 0) { continue }
        $configurationNames = @(Select-UniqueValue @($configurations | ForEach-Object { Get-ObjectValue $_ 'name' '' }))
        $connectedRanges.Add((New-ConnectedRangeRow -Category 'VpnClientPool' -Type 'VPN client pool' `
            -Name ([string](Get-ObjectValue $gateway 'name' (Get-ResourceNameFromId $id))) -Prefixes $prefixes `
            -Detail @((Get-FriendlyResourceType 'P2SVpnGateway' '' ''), $(if ($hubId) { "Hub $(Get-ResourceNameFromId $hubId)" }),
                $(if ($configurationNames.Count -gt 0) { "Configurations $($configurationNames -join ', ')" })) `
            -Placement $placement -Source $gateway -ResourceId $id))
    }
    # Peered VNets without a page here, outside the export or outside the selected
    # VNets, are still reachable from the VNets that are listed.
    $peeringsByRemoteId = @{}
    foreach ($peering in Get-DataRows $Data 'vnetPeerings') {
        $localId = ConvertTo-ResourceId (Get-ObjectValue $peering 'vnetId' '')
        $remoteId = ConvertTo-ResourceId (Get-ObjectValue $peering 'remoteVnetId' '')
        if (-not $remoteId -or -not $pagedVnetIds.Contains($localId) -or $pagedVnetIds.Contains($remoteId)) { continue }
        Add-IndexValue $peeringsByRemoteId $remoteId $peering
    }
    foreach ($remoteId in @($peeringsByRemoteId.Keys | Sort-Object)) {
        $peerings = @($peeringsByRemoteId[$remoteId])
        # The peered space is what is reachable; subnet peering can make it smaller
        # than the remote VNet's own address space.
        $prefixes = @(Select-UniqueValue @(foreach ($peering in $peerings) {
            $peered = @(Get-PrefixList (Get-ObjectValue $peering 'peeredAddressPrefixes' ''))
            if ($peered.Count -eq 0) { $peered = @(Get-PrefixList (Get-ObjectValue $peering 'remoteAddressPrefixes' '')) }
            $peered
        }))
        $remoteVnet = if ($Index.VnetById.ContainsKey($remoteId)) { $Index.VnetById[$remoteId] } else { $null }
        if ($prefixes.Count -eq 0 -and $null -ne $remoteVnet) { $prefixes = @(Get-PrefixList (Get-ObjectValue $remoteVnet 'addressPrefixes' '')) }
        $source = $remoteVnet
        if ($null -eq $source -and $remoteId -match '^/subscriptions/([^/]+)/resourcegroups/([^/]+)/') {
            $source = [pscustomobject]@{ subscriptionId=$Matches[1]; resourceGroup=$Matches[2]; location='' }
        }
        $states = @(Select-UniqueValue @($peerings | ForEach-Object { Get-ObjectValue $_ 'state' '' }))
        $isSubnetPeering = @($peerings | Where-Object { (ConvertTo-NullableBoolean (Get-ObjectValue $_ 'peerCompleteVnets')) -eq $false }).Count -gt 0
        $scopeNote = if ($null -ne $remoteVnet) { 'Outside the selected VNets' } else { 'Not in this export' }
        $remoteSubscriptionId = [string](Get-ObjectValue $source 'subscriptionId' '')
        $placement = ConvertTo-RangePlacement -VnetIds @($peerings | ForEach-Object { ConvertTo-ResourceId (Get-ObjectValue $_ 'vnetId' '') }) `
            -VnetById $Index.VnetById
        $connectedRanges.Add((New-ConnectedRangeRow -Category 'PeeredVnet' -Type (Get-FriendlyResourceType 'RemoteVNet' '' '') `
            -Name ([string](Get-ObjectValue $remoteVnet 'name' (Get-ResourceNameFromId $remoteId))) -Prefixes $prefixes `
            -Detail @($(if ($states.Count -gt 0) { "Peering $($states -join ', ')" }), $(if ($isSubnetPeering) { 'Subnet peering' }), $scopeNote,
                $(if ($remoteSubscriptionId) { "Subscription $remoteSubscriptionId" })) `
            -Placement $placement -Source $source -ResourceId $remoteId -EmptyText 'Not reported'))
    }
    foreach ($hub in Get-DataRows $Data 'virtualHubs') {
        $id = ConvertTo-ResourceId (Get-ObjectValue $hub 'id')
        if (-not $id) { continue }
        $placement = Get-RangePlacement $PlacedVnetIdsByResourceId $Index.VnetById $id
        if ($IsScoped -and $placement.VnetIds.Count -eq 0) { continue }
        $routerAsn = [string](Get-ObjectValue $hub 'virtualRouterAsn' '')
        $routerIps = ConvertTo-DisplayList (Get-ObjectValue $hub 'virtualRouterIps' '')
        $connectedRanges.Add((New-ConnectedRangeRow -Category 'VirtualHub' -Type (Get-FriendlyResourceType 'VirtualHub' '' '') `
            -Name ([string](Get-ObjectValue $hub 'name' (Get-ResourceNameFromId $id))) `
            -Prefixes @(Get-PrefixList (Get-ObjectValue $hub 'addressPrefix' '')) `
            -Detail @($(if ($routerAsn) { "ASN $routerAsn" }), $(if ($routerIps) { "Router IPs $routerIps" })) `
            -Placement $placement -Source $hub -ResourceId $id))
    }

    $vnetGroups = [System.Collections.Generic.List[object]]::new()
    foreach ($vnet in $Vnets) {
        $vnetId = ConvertTo-ResourceId (Get-ObjectValue $vnet 'id')
        $subscriptionId = [string](Get-ObjectValue $vnet 'subscriptionId' '')
        $subscriptionName = ''
        $normalizedSubscriptionId = ConvertTo-ResourceId $subscriptionId
        if ($Index.SubscriptionById.ContainsKey($normalizedSubscriptionId)) {
            $subscriptionName = [string](Get-ObjectValue $Index.SubscriptionById[$normalizedSubscriptionId] 'subscriptionName' '')
        }
        $spaceInfos = @(Get-PrefixList (Get-ObjectValue $vnet 'addressPrefixes' '') | ForEach-Object { Get-AddressPrefixInfo $_ })
        $spaceSize = [long]0
        foreach ($info in $spaceInfos) { if ($info.IsIPv4) { $spaceSize += $info.Size } }
        $subnetRows = @($Index.SubnetsByVnetId[$vnetId] | Where-Object { $null -ne $_ } | ForEach-Object { New-SubnetRangeRow $_ })
        $coveredSize = [long]0
        foreach ($subnetRow in $subnetRows) {
            foreach ($info in $subnetRow.Prefixes) { if ($info.IsIPv4) { $coveredSize += $info.Size } }
        }
        $coverage = if ($subnetRows.Count -eq 1) { '1 subnet' } else { "$($subnetRows.Count) subnets" }
        if ($spaceSize -gt 0) {
            $percent = 100.0 * $coveredSize / $spaceSize
            $percentText = if ($percent -gt 0 -and $percent -lt 0.1) { '<0.1%' } else { "$(Format-InvariantNumber $percent '0.0')%" }
            $verb = if ($subnetRows.Count -eq 1) { 'covers' } else { 'cover' }
            $coverage = "$coverage $verb $(Format-InvariantNumber $coveredSize) of $(Format-InvariantNumber $spaceSize) IPv4 addresses ($percentText)"
        }
        $vnetGroups.Add([pscustomobject]@{
            VnetId=$vnetId; Name=[string](Get-ObjectValue $vnet 'name' '(unnamed VNet)')
            SubscriptionId=$subscriptionId; SubscriptionName=$subscriptionName
            ResourceGroup=[string](Get-ObjectValue $vnet 'resourceGroup' ''); Location=[string](Get-ObjectValue $vnet 'location' '')
            AddressSpace=$spaceInfos; Coverage=$coverage
            Subnets=@($subnetRows | Sort-Object SortGroup, SortStart, Name, SubnetId)
        })
    }

    return [pscustomobject]@{
        IsScoped=$IsScoped
        PublicAddresses=@($publicAddresses | Sort-Object SortGroup, SortStart, Range, Name, ResourceId)
        ConnectedRanges=@($connectedRanges | Sort-Object Type, Name, ResourceId)
        VnetGroups=@($vnetGroups)
    }
}

function Get-RangeCellStyle {
    param([string]$Kind = 'Default')

    # An empty style lets Add-DetailTableCell apply its default body style.
    $base = 'rounded=0;whiteSpace=wrap;html=1;fontSize=9;align=left;spacingLeft=6;overflow=hidden;'
    switch ($Kind) {
        'Muted'   { return $base + 'fillColor=#ffffff;strokeColor=#b3b3b3;fontColor=#555555;' }
        'Link'    { return $base + 'fillColor=#ffffff;strokeColor=#b3b3b3;fontColor=#0078d4;' }
        'Empty'   { return $base + 'fillColor=#d5e8d4;strokeColor=#82b366;fontColor=#107c10;fontStyle=1;' }
        'Warning' { return $base + 'fillColor=#fff2cc;strokeColor=#d6b656;' }
        'Service' { return $base + 'fillColor=#f2f2f2;strokeColor=#b3b3b3;fontColor=#555555;' }
        'Group'   { return 'rounded=0;whiteSpace=wrap;html=1;fontSize=10;align=left;spacingLeft=8;overflow=hidden;fillColor=#f8fbff;strokeColor=#6c8ebf;' }
        default   { return '' }
    }
}

function New-RangeCell {
    param([AllowNull()][string]$Value,[string]$Kind = 'Default',[hashtable]$Attributes)
    return @{ Value=[string]$Value; Style=(Get-RangeCellStyle $Kind); Attributes=$Attributes }
}

function New-RangeVnetCell {
    param([object]$Row,[hashtable]$PageIdByVnetId)

    $names = @($Row.VnetNames)
    $ids = @($Row.VnetIds)
    if ($names.Count -eq 0) { return New-RangeCell 'Not on a VNet page' 'Muted' }
    if ($ids.Count -eq 1 -and $PageIdByVnetId.ContainsKey([string]$ids[0])) {
        return New-RangeCell ([string]$names[0]) 'Link' @{ link="data:page/id,$($PageIdByVnetId[[string]$ids[0]])"; tooltip='Open the VNet page' }
    }
    return New-RangeCell ($names -join '<br>')
}

function New-RangeResourceCell {
    param([string]$ResourceId,[string]$Name,[hashtable]$DetailPageIdByResourceId)

    if (-not $ResourceId) { return New-RangeCell 'None' 'Muted' }
    if ($DetailPageIdByResourceId.ContainsKey($ResourceId)) {
        return New-RangeCell $Name 'Link' @{ link="data:page/id,$($DetailPageIdByResourceId[$ResourceId])"; tooltip=$ResourceId }
    }
    return New-RangeCell $Name 'Default' @{ tooltip=$ResourceId }
}

function Add-RangeTableHeading {
    param(
        [System.Xml.XmlDocument]$Document,
        [System.Xml.XmlElement]$Root,
        [string]$IdPrefix,
        [string]$Title,
        [int]$Count,
        [string]$Note,
        [object[]]$Columns,
        [double]$Y
    )

    $tableWidth = 0
    foreach ($column in $Columns) { $tableWidth += $column.Width }
    $label = "<b>$Title</b> ($Count)"
    if ($Note) { $label += " &nbsp; <font color='#666666'>$Note</font>" }
    Add-MxVertex $Document $Root "$IdPrefix-heading" '1' $label 'rounded=1;whiteSpace=wrap;html=1;fillColor=#e6f2ff;strokeColor=#0078d4;fontSize=12;align=left;spacingLeft=8;' 20 $Y $tableWidth 34
    $headerY = $Y + 40
    $x = 20
    for ($i = 0; $i -lt $Columns.Count; $i++) {
        $attributes = @{}
        if ($Columns[$i].ContainsKey('Tooltip')) { $attributes.tooltip = $Columns[$i].Tooltip }
        Add-DetailTableCell $Document $Root "$IdPrefix-header-$i" $Columns[$i].Name $x $headerY $Columns[$i].Width 34 -Header -Attributes $attributes
        $x += $Columns[$i].Width
    }
    return $headerY + 34
}

function Add-RangeTableRow {
    param(
        [System.Xml.XmlDocument]$Document,
        [System.Xml.XmlElement]$Root,
        [string]$IdPrefix,
        [object[]]$Columns,
        [object[]]$Cells,
        [double]$Y
    )

    $lineCount = 1
    foreach ($cell in $Cells) {
        $lines = ([regex]::Matches([string]$cell.Value, '<br>')).Count + 1
        if ($lines -gt $lineCount) { $lineCount = $lines }
    }
    $height = [math]::Max(30, 12 + (14 * $lineCount))
    $x = 20
    for ($i = 0; $i -lt $Columns.Count; $i++) {
        $cell = $Cells[$i]
        Add-DetailTableCell $Document $Root "$IdPrefix-$i" $cell.Value $x $Y $Columns[$i].Width $height `
            -StyleOverride $cell.Style -Attributes $cell.Attributes
        $x += $Columns[$i].Width
    }
    return $Y + $height
}

function New-NetworkRangesPage {
    param(
        [System.Xml.XmlDocument]$Document,
        [object]$Page,
        [object]$Ranges,
        [hashtable]$PageIdByVnetId,
        [hashtable]$DetailPageIdByResourceId
    )

    # Short tables come first so they stay visible above a long subnet list.
    $root = $Page.Root
    Add-DetailNavigation $Document $root
    $description = 'Public IP addresses, connected on-premises and Virtual WAN ranges, and subnet prefixes. ' +
                   'Subnet prefixes are the ranges in use; a VNet address space is only reserved.'
    if ($Ranges.IsScoped) { $description += ' Filtered to the selected VNets; unattached public IPs are omitted.' }
    Add-MxVertex $Document $root 'ranges-title' '1' "<b>Network Ranges</b><br><font color='#666666'>$description</font>" `
        'rounded=1;whiteSpace=wrap;html=1;fillColor=#e6f2ff;strokeColor=#0078d4;strokeWidth=2;fontSize=13;align=left;spacingLeft=12;' `
        260 15 1200 62
    $fullWidth = @(@{Width=1440})

    $publicColumns = @(
        @{Name='Address';Width=160},@{Name='Name';Width=220},@{Name='SKU / version / allocation';Width=190},
        @{Name='FQDN';Width=280},@{Name='Attached to';Width=350},@{Name='VNet';Width=240}
    )
    $y = Add-RangeTableHeading -Document $Document -Root $root -IdPrefix 'public' -Title 'Public IP addresses' `
        -Count $Ranges.PublicAddresses.Count -Note ('Azure public IP resources plus the addresses of secured-hub firewalls and Virtual WAN VPN gateways. ' +
            'PaaS public endpoints are not listed.') `
        -Columns $publicColumns -Y 100
    if ($Ranges.PublicAddresses.Count -eq 0) {
        $y = Add-RangeTableRow -Document $Document -Root $root -IdPrefix 'public-empty' -Columns $fullWidth -Cells @((New-RangeCell 'None found.' 'Muted')) -Y $y
    }
    $rowNumber = 0
    foreach ($address in $Ranges.PublicAddresses) {
        $addressCell = if ($address.Range) { New-RangeCell $address.Range } else { New-RangeCell 'not allocated' 'Muted' }
        $ownerCell = if (@($address.Owners).Count -gt 0) { New-RangeCell (@($address.Owners) -join '<br>') } else { New-RangeCell 'Not attached' 'Warning' }
        $cells = @(
            $addressCell,
            (New-RangeCell $address.Name 'Default' @{ tooltip=$address.ResourceId }),
            (New-RangeCell $address.Detail),
            (New-RangeCell $address.Fqdn),
            $ownerCell,
            (New-RangeVnetCell $address $PageIdByVnetId)
        )
        $y = Add-RangeTableRow -Document $Document -Root $root -IdPrefix "public-row-$rowNumber" -Columns $publicColumns -Cells $cells -Y $y
        $rowNumber++
    }

    $connectedColumns = @(
        @{Name='Range';Width=260},@{Name='Type';Width=200},@{Name='Name';Width=240},
        @{Name='Detail';Width=440},@{Name='VNet';Width=300}
    )
    $y = Add-RangeTableHeading -Document $Document -Root $root -IdPrefix 'connected' -Title 'Connected ranges' `
        -Count $Ranges.ConnectedRanges.Count -Note ('Static on-premises prefixes, VPN client pools, Virtual WAN hubs, and peered VNets without a page here. ' +
            'Ranges learned over BGP, such as through ExpressRoute, are not visible.') `
        -Columns $connectedColumns -Y ($y + 30)
    if ($Ranges.ConnectedRanges.Count -eq 0) {
        $y = Add-RangeTableRow -Document $Document -Root $root -IdPrefix 'connected-empty' -Columns $fullWidth -Cells @((New-RangeCell 'None found.' 'Muted')) -Y $y
    }
    $rowNumber = 0
    foreach ($range in $Ranges.ConnectedRanges) {
        $prefixes = @($range.Prefixes)
        $rangeCell = if ($prefixes.Count -gt 0) { New-RangeCell ($prefixes -join '<br>') } else { New-RangeCell $range.EmptyText 'Muted' }
        $cells = @(
            $rangeCell,
            (New-RangeCell $range.Type),
            (New-RangeCell $range.Name 'Default' @{ tooltip=$range.ResourceId }),
            (New-RangeCell $range.Detail),
            (New-RangeVnetCell $range $PageIdByVnetId)
        )
        $y = Add-RangeTableRow -Document $Document -Root $root -IdPrefix "connected-row-$rowNumber" -Columns $connectedColumns -Cells $cells -Y $y
        $rowNumber++
    }

    $subnetColumns = @(
        @{Name='Subnet';Width=260},@{Name='Prefix';Width=220},@{Name='Usable';Width=110},
        @{Name='Occupancy';Width=190;Tooltip=("IP configurations Azure reports on the subnet, one address each. Scaled services such as " +
            "Application Gateway, Azure Firewall, and VPN gateways can use more addresses than they report. " +
            "Service-managed: a delegated or service-linked subnet whose addresses Azure does not report here.")},
        @{Name='NSG';Width=220},@{Name='Route table';Width=220},@{Name='Delegation';Width=220}
    )
    $subnetCount = 0
    foreach ($group in $Ranges.VnetGroups) { $subnetCount += @($group.Subnets).Count }
    $y = Add-RangeTableHeading -Document $Document -Root $root -IdPrefix 'subnets' -Title 'Subnets' -Count $subnetCount `
        -Note 'Grouped by VNet and ordered by address. Usable excludes the 5 addresses Azure reserves in each subnet.' `
        -Columns $subnetColumns -Y ($y + 30)
    $groupNumber = 0
    foreach ($group in $Ranges.VnetGroups) {
        $groupNumber++
        $space = @($group.AddressSpace | ForEach-Object { $_.Text }) -join ', '
        $subscription = if ($group.SubscriptionName) { $group.SubscriptionName } else { $group.SubscriptionId }
        $groupLabel = "<b>$($group.Name)</b> &nbsp; $space &nbsp; | &nbsp; $subscription &nbsp; | &nbsp; $($group.Coverage)"
        $groupAttributes = @{ tooltip=$group.VnetId }
        if ($PageIdByVnetId.ContainsKey($group.VnetId)) { $groupAttributes.link = "data:page/id,$($PageIdByVnetId[$group.VnetId])" }
        $y = Add-RangeTableRow -Document $Document -Root $root -IdPrefix "subnets-group-$groupNumber" -Columns $fullWidth `
            -Cells @((New-RangeCell $groupLabel 'Group' $groupAttributes)) -Y $y
        if (@($group.Subnets).Count -eq 0) {
            $y = Add-RangeTableRow -Document $Document -Root $root -IdPrefix "subnets-group-$groupNumber-empty" -Columns $fullWidth `
                -Cells @((New-RangeCell 'No subnets.' 'Muted')) -Y $y
        }
        $rowNumber = 0
        foreach ($subnet in $group.Subnets) {
            $occupancyKind = switch ($subnet.OccupancyState) {
                'Empty' { 'Empty' }
                'ServiceManaged' { 'Service' }
                'NotReported' { 'Muted' }
                default { 'Default' }
            }
            $delegationCell = if ($subnet.Delegation) { New-RangeCell $subnet.Delegation } else { New-RangeCell 'None' 'Muted' }
            $cells = @(
                (New-RangeCell $subnet.Name 'Default' @{ tooltip=$subnet.SubnetId }),
                (New-RangeCell (@($subnet.Prefixes | ForEach-Object { $_.Text }) -join '<br>')),
                (New-RangeCell $subnet.Usable),
                (New-RangeCell $subnet.Occupancy $occupancyKind),
                (New-RangeResourceCell $subnet.NsgId $subnet.NsgName $DetailPageIdByResourceId),
                (New-RangeResourceCell $subnet.RouteTableId $subnet.RouteTableName $DetailPageIdByResourceId),
                $delegationCell
            )
            $y = Add-RangeTableRow -Document $Document -Root $root -IdPrefix "subnets-group-$groupNumber-row-$rowNumber" `
                -Columns $subnetColumns -Cells $cells -Y $y
            $rowNumber++
        }
        $y += 10
    }
    Set-MxPageSize $Page.Model 1460 $y
}

function New-NetworkRangeCsvRow {
    param(
        [string]$Category,
        [string]$Range = '',
        [string]$IpVersion = '',
        [string]$Name = '',
        [string]$Vnet = '',
        [string]$Subnet = '',
        [string]$Usable = '',
        [string]$Occupancy = '',
        [string]$AttachedTo = '',
        [string]$Fqdn = '',
        [string]$Detail = '',
        [string]$SubscriptionId = '',
        [string]$ResourceGroup = '',
        [string]$Location = '',
        [string]$ResourceId = ''
    )

    return [pscustomobject]@{
        Category=$Category; Range=$Range; IpVersion=$IpVersion; Name=$Name; Vnet=$Vnet; Subnet=$Subnet
        Usable=$Usable; Occupancy=$Occupancy; AttachedTo=$AttachedTo; Fqdn=$Fqdn; Detail=$Detail
        SubscriptionId=$SubscriptionId; ResourceGroup=$ResourceGroup; Location=$Location; ResourceId=$ResourceId
    }
}

function ConvertTo-NetworkRangeCsvRow {
    param([object]$Ranges)

    # One row per prefix or address, so the Range column filters straight into a
    # scanner target list.
    foreach ($address in $Ranges.PublicAddresses) {
        $attachedTo = if (@($address.Owners).Count -gt 0) { @($address.Owners) -join '; ' } else { 'Not attached' }
        New-NetworkRangeCsvRow -Category $address.Category -Range $address.Range -IpVersion $address.IpVersion `
            -Name $address.Name -Vnet (@($address.VnetNames) -join '; ') -AttachedTo $attachedTo -Fqdn $address.Fqdn `
            -Detail $address.Detail -SubscriptionId $address.SubscriptionId -ResourceGroup $address.ResourceGroup `
            -Location $address.Location -ResourceId $address.ResourceId
    }
    foreach ($range in $Ranges.ConnectedRanges) {
        $prefixes = @($range.Prefixes)
        if ($prefixes.Count -eq 0) { $prefixes = @('') }
        foreach ($prefix in $prefixes) {
            $info = Get-AddressPrefixInfo $prefix
            New-NetworkRangeCsvRow -Category $range.Category -Range $prefix -IpVersion $info.IpVersion -Name $range.Name `
                -Vnet (@($range.VnetNames) -join '; ') -Detail $range.Detail -SubscriptionId $range.SubscriptionId `
                -ResourceGroup $range.ResourceGroup -Location $range.Location -ResourceId $range.ResourceId
        }
    }
    foreach ($group in $Ranges.VnetGroups) {
        foreach ($info in $group.AddressSpace) {
            New-NetworkRangeCsvRow -Category 'VnetAddressSpace' -Range $info.Text -IpVersion $info.IpVersion -Name $group.Name `
                -Vnet $group.Name -Detail $group.Coverage -SubscriptionId $group.SubscriptionId -ResourceGroup $group.ResourceGroup `
                -Location $group.Location -ResourceId $group.VnetId
        }
        foreach ($subnet in $group.Subnets) {
            $nsgName = if ($subnet.NsgName) { $subnet.NsgName } else { 'None' }
            $routeTableName = if ($subnet.RouteTableName) { $subnet.RouteTableName } else { 'None' }
            $delegation = if ($subnet.Delegation) { $subnet.Delegation } else { 'None' }
            $detail = "NSG: $nsgName; Route table: $routeTableName; Delegation: $delegation"
            $prefixInfos = @($subnet.Prefixes)
            if ($prefixInfos.Count -eq 0) { $prefixInfos = @(Get-AddressPrefixInfo '') }
            foreach ($info in $prefixInfos) {
                $usable = ''
                if ($info.IsIPv4) {
                    $usableCount = $info.Size - 5
                    if ($usableCount -lt 0) { $usableCount = 0 }
                    $usable = $usableCount.ToString([System.Globalization.CultureInfo]::InvariantCulture)
                }
                New-NetworkRangeCsvRow -Category 'Subnet' -Range $info.Text -IpVersion $info.IpVersion -Name $subnet.Name `
                    -Vnet $group.Name -Subnet $subnet.Name -Usable $usable -Occupancy $subnet.Occupancy -Detail $detail `
                    -SubscriptionId $subnet.SubscriptionId -ResourceGroup $subnet.ResourceGroup -Location $subnet.Location `
                    -ResourceId $subnet.SubnetId
            }
        }
    }
}

function Export-NetworkRangeCsv {
    param([object]$Ranges,[string]$Path)

    $rows = @(ConvertTo-NetworkRangeCsvRow -Ranges $Ranges)
    if ($rows.Count -gt 0) {
        $lines = @($rows | ConvertTo-Csv -NoTypeInformation)
    } else {
        # ConvertTo-Csv writes nothing for no input; a header keeps the file importable.
        $lines = @((@((New-NetworkRangeCsvRow -Category '').PSObject.Properties.Name) | ForEach-Object { '"' + $_ + '"' }) -join ',')
    }
    [System.IO.File]::WriteAllLines($Path, [string[]]$lines, [System.Text.UTF8Encoding]::new($false))
    return $rows.Count
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
        [double]$StartY,
        [object]$Index,
        [hashtable]$PageIdByVnetId = @{}
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
        $destinationReservedLines=0;$translatedLine='';$targetOwner=$null;$targetOwnerText='';$targetPageId=''
        if($isDnat){
            $translatedAddress=[string](Get-ObjectValue $rule 'translatedAddress' '')
            $translatedTarget=if($translatedAddress){$translatedAddress}else{[string](Get-ObjectValue $rule 'translatedFqdn' '')}
            $translatedLine="&#8594; $(ConvertTo-SecurityRuleDisplayValue $translatedTarget):$(ConvertTo-SecurityRuleDisplayValue (Get-ObjectValue $rule 'translatedPort' ''))"
            # The translated IP is named after the resource holding it, so a service
            # published through the firewall can be traced to its VNet page.
            if($Index -and $translatedAddress){$targetOwner=Resolve-PrivateIpOwner $Index $translatedAddress}
            if($targetOwner){
                $targetOwnerText=$targetOwner.Name
                if($targetOwner.VnetId){
                    $targetVnetName=if($Index.VnetById.ContainsKey($targetOwner.VnetId)){[string](Get-ObjectValue $Index.VnetById[$targetOwner.VnetId] 'name' (Get-ResourceNameFromId $targetOwner.VnetId))}else{Get-ResourceNameFromId $targetOwner.VnetId}
                    $targetOwnerText+=" in $targetVnetName"
                    if($PageIdByVnetId.ContainsKey($targetOwner.VnetId)){$targetPageId=$PageIdByVnetId[$targetOwner.VnetId]}
                }
                $ownerMarkup=if($targetPageId){"<font color='#0078d4'>$targetOwnerText</font>"}else{$targetOwnerText}
                $translatedLine+=" ($ownerMarkup)"
            }
            # The translated line takes one line of the fixed-height cell, two when a long
            # owner name makes it wrap.
            $plainTranslatedLength=($translatedLine -replace '<[^>]+>','' -replace '&#8594;','>').Length
            $destinationReservedLines=if($plainTranslatedLength -gt [math]::Floor(($columns[6].Width - 12) / 5.4)){2}else{1}
        }
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
        if($isDnat){$destinationText+="<br>$translatedLine"}
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
            if($i-eq6-and$targetOwner){
                $ownerNote="$translatedAddress is $targetOwnerText"
                if($targetPageId){$cellAttributes.link="data:page/id,$targetPageId";$ownerNote+=". Click to open its VNet page."}
                $cellAttributes.tooltip=if($cellAttributes.ContainsKey('tooltip')){"$($cellAttributes.tooltip)`n$ownerNote"}else{$ownerNote}
            }
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
    param([System.Xml.XmlDocument]$Document,[System.Xml.XmlElement]$MxFile,[object]$Index,[object]$Policy,[string]$PageId,[hashtable]$DetailPageIdByResourceId,[hashtable]$PageIdByVnetId = @{})
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
        $nextY=Add-FirewallRuleSection -Document $Document -Root $root -Title $section.Title -Entries $sectionEntries -IdPrefix $section.Id -StartY $nextY -Index $Index -PageIdByVnetId $PageIdByVnetId
    }
    # Empty filter collections and rule types this page does not know have no
    # place in the evaluation order, so they are listed last rather than dropped.
    $otherEntries=@($entries|Where-Object{$knownTypes-notcontains$_.Type})
    if($otherEntries.Count-gt0){
        $nextY=Add-FirewallRuleSection -Document $Document -Root $root -Title 'Other collections' -Entries $otherEntries -IdPrefix 'section-other' -StartY $nextY -Index $Index -PageIdByVnetId $PageIdByVnetId
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
        [bool]$IncludeNetworkRangesPage = $true,
        [bool]$IncludeUnmappedPage = $true,
        [bool]$IncludeCredit = $true,
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
    $rangesPageCount = if ($IncludeNetworkRangesPage) { 1 } else { 0 }
    $plannedPages = 1 + $rangesPageCount + $sortedVnets.Count + $plannedDetailPages
    $builtPages = 0
    Write-StatusProgress 'Building diagram pages' 'Network overview' $builtPages $plannedPages
    # The overview follows the scope filters so it never lists VNets without a page.
    $collectedAt = Format-CollectedAt (Get-ObjectValue $Data 'collectedAt' $null)
    New-NetworkOverviewPage -Document $document -MxFile $mxFile -Data $Data -Index $networkIndex -Vnets $sortedVnets -PageIdByVnetId $pageIdByVnetId `
        -IncludeRangesLink $IncludeNetworkRangesPage -IncludeCredit $IncludeCredit -CollectedAt $collectedAt -IsScoped $isScoped
    $builtPages++
    # Created now to keep it second in the file, filled once the VNet pages have
    # recorded which resources they drew.
    $rangesPage = $null
    if ($IncludeNetworkRangesPage) { $rangesPage = New-DrawIoPageRoot $document $mxFile 'network-ranges' 'Network Ranges' }
    $placedVnetIdsByResourceId = @{}
    $usedResourceIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $page = 0
    foreach ($vnet in $sortedVnets) {
        $page++
        Write-StatusProgress 'Building diagram pages' "VNet $page of $($sortedVnets.Count): $(Get-ObjectValue $vnet 'name' '')" $builtPages $plannedPages
        $builtPages++
        New-EnhancedDrawIoPage -Document $document -MxFile $mxFile -Data $Data -Index $networkIndex -Vnet $vnet `
            -PageIdByVnetId $pageIdByVnetId -DetailPageIdByResourceId $detailPageIdByResourceId `
            -UsedResourceIds $usedResourceIds -ResourcesPerRow $ResourcesPerRow `
            -PlacedVnetIdsByResourceId $placedVnetIdsByResourceId -CollectedAt $collectedAt
    }
    # The ranges are still collected without their page, because -ExportRangesPath writes them as CSV.
    $networkRanges = Get-NetworkRangeData -Data $Data -Index $networkIndex -Vnets $sortedVnets `
        -PlacedVnetIdsByResourceId $placedVnetIdsByResourceId -IsScoped $isScoped
    if ($IncludeNetworkRangesPage) {
        Write-StatusProgress 'Building diagram pages' 'Network ranges' $builtPages $plannedPages
        New-NetworkRangesPage -Document $document -Page $rangesPage -Ranges $networkRanges `
            -PageIdByVnetId $pageIdByVnetId -DetailPageIdByResourceId $detailPageIdByResourceId
        $builtPages++
    }
    $detailPages = 0
    if ($IncludeRuleDetailPages) {
        foreach ($nsg in $nsgs) {
            $id = ConvertTo-ResourceId (Get-ObjectValue $nsg 'id')
            Write-StatusProgress 'Building diagram pages' "NSG detail: $(Get-ObjectValue $nsg 'name' '')" $builtPages $plannedPages
            New-NsgDetailPage -Document $document -MxFile $mxFile -Index $networkIndex -Nsg $nsg -PageId $detailPageIdByResourceId[$id] -IncludeDefaultRules $IncludeDefaultNsgRules `
                -PageIdByVnetId $pageIdByVnetId
            $detailPages++; $builtPages++
        }
        foreach ($routeTable in $routeTables) {
            $id = ConvertTo-ResourceId (Get-ObjectValue $routeTable 'id')
            Write-StatusProgress 'Building diagram pages' "Route table detail: $(Get-ObjectValue $routeTable 'name' '')" $builtPages $plannedPages
            New-RouteTableDetailPage -Document $document -MxFile $mxFile -Index $networkIndex -RouteTable $routeTable -PageId $detailPageIdByResourceId[$id] `
                -PageIdByVnetId $pageIdByVnetId
            $detailPages++; $builtPages++
        }
        foreach ($firewallPolicy in $firewallPolicies) {
            $id = ConvertTo-ResourceId (Get-ObjectValue $firewallPolicy 'id')
            Write-StatusProgress 'Building diagram pages' "Firewall policy detail: $(Get-ObjectValue $firewallPolicy 'name' '')" $builtPages $plannedPages
            New-FirewallPolicyDetailPage -Document $document -MxFile $mxFile -Index $networkIndex -Policy $firewallPolicy `
                -PageId $detailPageIdByResourceId[$id] -DetailPageIdByResourceId $detailPageIdByResourceId -PageIdByVnetId $pageIdByVnetId
            $detailPages++; $builtPages++
        }
    }
    # With a scope filter active, "unmapped" would read as "outside the VNets you
    # selected", which is not what the page means. Skip it rather than mislead.
    $unmappedResources = @()
    if (-not $isScoped -and $IncludeUnmappedPage) { $unmappedResources = @(Get-UnmappedResources -Data $Data -UsedResourceIds $usedResourceIds) }
    $hasUnmappedPage = New-UnmappedDrawIoPage -Document $document -MxFile $mxFile -Resources $unmappedResources -DetailPageIdByResourceId $detailPageIdByResourceId
    $totalPages = 1 + $rangesPageCount + $page + $detailPages + $(if ($hasUnmappedPage) { 1 } else { 0 })

    $resolvedPath = Resolve-LocalFilePath $Path
    $directory = [System.IO.Path]::GetDirectoryName($resolvedPath)
    if (-not [System.IO.Directory]::Exists($directory)) {
        $null = [System.IO.Directory]::CreateDirectory($directory)
    }
    $settings = [System.Xml.XmlWriterSettings]::new()
    $settings.Indent = $true
    $settings.Encoding = [System.Text.UTF8Encoding]::new($false)
    Complete-StatusProgress 'Building diagram pages'
    $pageBreakdown = "1 overview$(if ($IncludeNetworkRangesPage) { ' + 1 ranges' }) + $page VNet + $detailPages detail"
    if ($hasUnmappedPage) { $pageBreakdown += ' + 1 unmapped' }
    Write-StatusDetail "$pageBreakdown = $totalPages pages"

    Write-StatusStep 3 3 "Writing $([System.IO.Path]::GetFileName($resolvedPath))"
    $writer = [System.Xml.XmlWriter]::Create($resolvedPath, $settings)
    try { $document.Save($writer) } finally { $writer.Dispose() }
    Write-StatusDetail "$totalPages pages, $(Format-FileSize ([System.IO.FileInfo]::new($resolvedPath).Length))"
    return [pscustomobject]@{
        Path=$resolvedPath; Subscriptions=@(Get-DataRows $Data 'subscriptions').Count; VnetPages=$page; DetailPages=$detailPages; TotalPages=$totalPages; UnmappedResources=$unmappedResources.Count
        Ranges=$networkRanges
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
        -IncludeNetworkRangesPage (-not $SkipNetworkRanges.IsPresent) `
        -IncludeUnmappedPage (-not $SkipUnmappedResources.IsPresent) `
        -IncludeCredit (-not $SkipCredit.IsPresent) `
        -ResourcesPerRow $ResourcesPerRow `
        -VnetName $VnetName -ResourceGroup $ResourceGroup -ExcludeSubscriptionId $ExcludeSubscriptionId
    if ($ExportRangesPath) {
        $resolvedRanges = Resolve-LocalFilePath $ExportRangesPath
        $rangesDirectory = [System.IO.Path]::GetDirectoryName($resolvedRanges)
        if (-not [System.IO.Directory]::Exists($rangesDirectory)) {
            $null = [System.IO.Directory]::CreateDirectory($rangesDirectory)
        }
        $rangeRowCount = Export-NetworkRangeCsv -Ranges $result.Ranges -Path $resolvedRanges
        Write-StatusDetail "Exported $rangeRowCount network range row(s) to $resolvedRanges"
    }
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
