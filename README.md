# VNetAtlas

**Map your Azure networks into an editable draw.io atlas without clicking through the portal.**

## Why VNetAtlas

As a security analyst, I've always found Azure network reviews tedious. In environments
without consistent naming or structure, things get chaotic quickly, and working out how a
network actually fits together can take a million clicks in the portal. More often than
not, I ended up drawing the network in draw.io by hand.

draw.io files are just XML, so I wondered how much of that drawing I could automate.
VNetAtlas is the answer. It signs in with the Az PowerShell modules, runs a set of KQL
queries against Azure Resource Graph, and writes the diagram I used to draw by hand:
VNets, subnets, peerings, the resources inside them, and everything attached to them, from
gateways and public IPs to NSGs with their full rule sets.

## A tour of the atlas

One command produces a single `.drawio` file that reads like an atlas: start with the big
picture and click your way down to the details.

**1. Network overview.** Every VNet, grouped by subscription, with its address space,
region, and subnet and peering counts. Click a VNet to open its page. Lines show peerings,
Virtual WAN hub connections, and VNet-to-VNet VPNs, with arrowheads for the directions
traffic may flow; anything unusual is labelled or drawn in red. Connected VNets outside the
export get a section of their own, and the header shows when the data was read from Azure.

![VNetAtlas Network Overview](assets/vnet_overview.png)
*Network overview with VNets grouped by subscription and their peerings.*

**2. Network ranges.** The address ranges actually in use, often far smaller than the VNet
address spaces suggest: public IPs and what they are attached to, connected ranges such as
on-premises prefixes, VPN client pools and peered VNets, and every subnet grouped by VNet.
Add `-ExportRangesPath` to get the same rows as CSV for a scan scope.

![VNetAtlas Network Ranges](assets/networkranges.png)
*Network Ranges page with public IP addresses, connected ranges, and subnet prefixes.*

**3. One page per VNet.** Each subnet is a container holding what runs in it: VMs, scale
sets, private endpoints, and services such as Application Gateway, Azure Firewall,
gateways, Bastion, or Container Apps. Three lanes around the VNet show what it connects to:

- **Security & routing:** NSGs and route tables
- **Azure connectivity:** public IPs, NAT gateways, load balancers, and private endpoint
  targets
- **Peerings & gateway connections:** peered VNets, and the far ends of VPN, ExpressRoute,
  and Virtual WAN hub connections

Labels carry what you would otherwise look up blade by blade, such as VM sizes, private
IPs, routes, and each peering's state and allowed directions. Hover over a shape for its
resource ID.

![VNetAtlas VNet View](assets/vnet.png)
*VNet page showing subnet containment and connected Azure resources.*

**4. NSG and route-table pages.** Click an NSG to see its rules laid out the way the portal
lists them: inbound and outbound, custom and default, with application security groups
resolved and each rule's description shown on hover. Route tables get the same treatment.
On both pages the associations are grouped by VNet, and each VNet links back to its page.

![VNetAtlas NSG View](assets/nsg.png)
*NSG detail page with its associations and inbound and outbound security rules.*

Click an Azure Firewall to open its firewall policy page, with every rule collection group,
collection, and rule. DNAT rules name the resource behind each translated address, such as
an application gateway or VM, and link to its VNet page.

![VNetAtlas Firewall Policy View](assets/azure_firewall.png)
*Firewall policy page with DNAT, network, and application rules, including rules inherited
from a parent policy.*

**5. Unmapped Resources.** Anything VNetAtlas found but could not tie to a VNet through a
relationship Azure actually reports, such as a public IP or an NSG that is not attached to
anything. VNetAtlas lists these instead of guessing where they belong, and they are often
worth a second look in a review.

The output is plain, uncompressed draw.io XML, so the atlas is a starting point rather than
a finished picture. Move shapes around, annotate your findings, or hide connector types
with draw.io layers.

## Made for reviews

- **Read-only.** VNetAtlas runs Resource Graph queries, plus read-only (`GET`) Azure
  Resource Manager requests for firewall policy rules and Virtual WAN hub connections.
  Reader access is enough.
- **Focus on what matters.** Narrow large tenants with `-VnetName`, `-ResourceGroup`, or
  `-ExcludeSubscriptionId`.

## Quick start

VNetAtlas requires Windows PowerShell 5.1 or PowerShell 7+, the `Az.Accounts` and
`Az.ResourceGraph` modules, and at least Reader access to the subscriptions being queried.

```powershell
Install-Module -Name Az.Accounts, Az.ResourceGraph -Scope CurrentUser
Connect-AzAccount
.\Export-VNetAtlas.ps1
```

The command queries every enabled subscription available in the current tenant and creates
a timestamped `*_Azure-Network.drawio` file in the current directory. Open it in the draw.io
desktop application or at [app.diagrams.net](https://app.diagrams.net/); both include the
Azure icons it uses.

## Parameters

The script has four mutually exclusive parameter sets. `Azure` is the default and queries
live; `Input` regenerates a diagram from exported JSON; `Version` and `Help` print and exit.

| Parameter | Type | Set | Description |
| --- | --- | --- | --- |
| `-SubscriptionId` | `string[]` | Azure | Subscriptions to query. Omit to use every enabled subscription in the tenant. |
| `-TenantId` | `string` | Azure | Tenant to export. Forces a new sign-in when the current Az context uses another tenant. |
| `-ExportDataPath` | `string` | Azure | Also write normalized query results as JSON for offline reruns. |
| `-VnetName` | `string[]` | both | Include only matching VNet names. Wildcards are supported (`hub-*`). |
| `-ResourceGroup` | `string[]` | both | Include only VNets in matching resource groups. Wildcards are supported. |
| `-ExcludeSubscriptionId` | `string[]` | both | Exclude VNets in these subscriptions after applying `-SubscriptionId`. |
| `-InputDataPath` | `string` | Input (**required**) | Build from exported JSON instead of querying Azure. |
| `-OutputPath` | `string` | both | Target `.drawio` file. Defaults to `.\<yyyyMMdd_HHmm>_Azure-Network.drawio`. |
| `-ExportRangesPath` | `string` | both | Also write the Network Ranges tables as CSV, one row per prefix or address. |
| `-ResourcesPerRow` | `int` | both | Resources per subnet row, from 1 to 4. Default: `2`. |
| `-SkipRuleDetailPages` | `switch` | both | Omit NSG, route-table, and firewall-policy detail pages. Firewall policy rules are still collected. |
| `-SkipFirewallRules` | `switch` | both | Do not read firewall policy rules and omit the firewall-policy detail pages. |
| `-SkipDefaultNsgRules` | `switch` | both | Omit Azure's built-in rules from NSG detail pages. |
| `-SkipNetworkRanges` | `switch` | both | Omit the Network Ranges page and its link on the overview. `-ExportRangesPath` still writes the CSV. |
| `-SkipUnmappedResources` | `switch` | both | Omit the Unmapped Resources page. |
| `-SkipCredit` | `switch` | both | Omit the "Created with VNetAtlas" line from the network overview. |
| `-Quiet` | `switch` | both | Suppress the banner and progress output. The summary line and warnings are still written. |
| `-Verbose` | `switch` | Azure | Narrate subscription selection and each Resource Graph query. |
| `-Version` | `switch` | Version | Print `VNetAtlas <version>` and exit. |
| `-Help` | `switch` | Help | Print compact usage and exit. |

For full command help, run:

```powershell
Get-Help .\Export-VNetAtlas.ps1 -Full
```

## Examples

Export selected subscriptions:

```powershell
.\Export-VNetAtlas.ps1 `
    -SubscriptionId '00000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000002' `
    -OutputPath .\azure-network.drawio
```

Export only matching VNets:

```powershell
.\Export-VNetAtlas.ps1 `
    -VnetName 'hub-*' `
    -OutputPath .\hub.drawio
```

Save the query results as JSON, so you can later rebuild the atlas with different options
(for example a single VNet or no default NSG rules) without querying Azure again. The
rebuilt atlas still shows when the data was originally collected:

```powershell
.\Export-VNetAtlas.ps1 `
    -ExportDataPath .\network-data.json `
    -OutputPath .\azure-network.drawio

.\Export-VNetAtlas.ps1 `
    -InputDataPath .\network-data.json `
    -OutputPath .\azure-network-offline.drawio
```

Write the Network Ranges tables as CSV and list the subnet prefixes in use, one per line,
as input for a scanner:

```powershell
.\Export-VNetAtlas.ps1 -ExportRangesPath .\ranges.csv

Import-Csv .\ranges.csv | Where-Object Category -eq 'Subnet' | ForEach-Object Range
```

Relative output and data paths are resolved against PowerShell's current location. Use
`-TenantId` to select another tenant; different tenants must be exported separately.

## Supported resources and relationships

VNetAtlas currently queries and relates:

- Virtual networks, subnets, and VNet peerings, including subnet peerings
- VMs, VM scale sets, and network interfaces
- Public IP addresses and prefixes, NSGs, route tables, and NAT gateways with their IPv4 and
  IPv6 public IPs and prefixes
- Load balancers and application gateways, including frontend and backend relationships
- Azure Firewalls and their firewall policies, including parent policies
- Private endpoints, their NICs, and their target resources
- VPN/ExpressRoute gateways, connections, local gateways, and ExpressRoute circuits
- Azure Bastion hosts
- Virtual Hubs, hub VNet connections, and associated ExpressRoute gateways, with the
  circuits connected to them, and secured-hub firewalls
- Virtual WAN VPN gateways and their connections, VPN sites, and point-to-site VPN gateways
- VPN client address pools on virtual network gateways (Network Ranges page only)

A resource appears on a VNet page only when Azure Resource Graph exposes a subnet, NIC,
backend, peering, gateway connection, or Virtual WAN hub connection relationship. Other
supported resources appear on the `Unmapped Resources` page instead of being assigned by
inference.

Subnet references also identify VNet-injected services that are not queried directly, such
as Container Apps environments, App Service integration, flexible database servers, and
Private Link services. These shapes are labelled `Detected from subnet reference`.

### Firewall policy rules

Resource Graph does not return firewall policy rules, so VNetAtlas reads them with read-only
Azure Resource Manager requests: at least two per policy, including parent policies.
`-ExportDataPath` saves them for offline reruns, and `-SkipFirewallRules` skips them. If a
policy cannot be read, its page says so and the export continues.

Not shown: classic rules on firewalls without a policy, the addresses inside IP groups, and
policies that no firewall uses.

### Scope and limitations

- Filters (`-VnetName`, `-ResourceGroup`, `-ExcludeSubscriptionId`) combine with AND. The
  overview then shows only the selected VNets, detail pages only what those VNets reach,
  and the `Unmapped Resources` page is left out; if nothing matches, no diagram is written.
- Private DNS zones, VNet links, record sets, and private-endpoint DNS zone groups are not
  collected.
- Route tables show the routes configured in them, not the effective routes Azure applies:
  system routes and routes learned through BGP are not included.
- Arrowheads show what a peering or connection allows, not whether traffic arrives: NSGs,
  routes, firewalls, and Virtual WAN hub routing are not evaluated.
- A VNet outside the export is known only from its connections, so a VNet in another tenant
  and one in a subscription that was not queried look the same.
- The peering a Virtual WAN hub creates to its managed `HV_` VNet is shown as the hub
  connection, not as a second peering.
- Overview lines keep their bend points when cards are moved in draw.io; Arrange > Clear
  Waypoints (Alt+Shift+R) routes them again.
- Azure Resource Graph expands at most 2,000 subnets, peerings, or IP configurations per
  resource. The script warns when a resource reaches that limit.

## Diagram conventions

- Containment represents VNet, subnet, and subnet-resource membership.
- Solid green connectors represent attachments, public IPs, and load-balancer backends.
- Dashed gold connectors represent NSG associations.
- Dashed blue connectors represent routing and NAT configuration.
- Purple connectors represent peerings (dashed) and VPN, ExpressRoute, and Virtual WAN hub
  connections (solid). Arrowheads show the directions traffic may flow, red means not
  connected, and no arrowheads mean Azure reports no state or, from a hub to its gateways,
  a part of the hub rather than a path.
- On VNet pages, peering arrowheads at the VNet overlap; each peered VNet's card states the
  directions in words.
- Connector classes use separate draw.io layers. Open **View > Layers** (`Ctrl+Shift+L`) to
  show or hide them.
- Subnets are collapsible, and **View > Tags** can filter shapes by kind, lane, name, or
  subnet.
- Behind a Virtual WAN VPN gateway, more than five VPN sites are drawn as one summary node
  that lists them on hover; the Network Ranges page lists each site's prefixes.
- The atlas follows draw.io's light and dark mode.

## Disclaimer

VNetAtlas was developed with AI assistance and may contain errors, omissions, or incomplete
mappings. It is intended as a supporting tool for security reviews and is not an
authoritative source of truth or a substitute for manual validation and professional
judgement.
