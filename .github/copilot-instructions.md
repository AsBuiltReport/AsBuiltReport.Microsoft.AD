# Copilot Instructions for AsBuiltReport.Microsoft.AD

## What This Project Does

A PowerShell module that generates As-Built documentation reports for Microsoft Active Directory environments (Forest, Domains, Domain Controllers, DNS, PKI/CA). It produces HTML/Word/Text output via the **PScribo** library, with optional network topology diagrams via **Diagrammer.Core**.

## Runtime Requirements

- **Must run as Administrator** — `#Requires -RunAsAdministrator` is enforced in the entry point.
- **Target must be an FQDN** — IP addresses are explicitly rejected; always pass a fully-qualified domain name for `-Target`.
- **Cannot run in PowerShell ISE** — detected and blocked at startup; use the PowerShell console or terminal.
- **PowerShell 7+ recommended** — required for tests; the module itself targets Windows PowerShell 5.1+ on Windows only.
- **Reporting machine must be domain-joined** — required for the PKI/CA section (`Get-ComputerADDomain` check).
- **WinRM must be enabled on DCs** — all remote data collection goes through WinRM; CIMSession is supplementary.

## Testing

Run all Pester tests (requires PowerShell 7+, Windows):
```powershell
cd Tests
.\Invoke-Tests.ps1
```

Run with code coverage:
```powershell
.\Invoke-Tests.ps1 -CodeCoverage
```

Run a single test file directly:
```powershell
Invoke-Pester -Path .\Tests\AsBuiltReport.Microsoft.AD.Tests.ps1 -Output Detailed
```

Run PSScriptAnalyzer lint locally:
```powershell
Invoke-ScriptAnalyzer -Path .\AsBuiltReport.Microsoft.AD\Src -Settings .\.github\workflows\PSScriptAnalyzerSettings.psd1 -Recurse
```

PSScriptAnalyzer enforces: `UseCorrectCasing`, `PSUseConsistentWhitespace`, `PSAvoidUsingCmdletAliases`, `AvoidUsingDoubleQuotesForConstantString`, `PSAvoidExclaimOperator`. Errors fail CI; warnings do not.

## Architecture

### Module Layout

```
AsBuiltReport.Microsoft.AD/
  AsBuiltReport.Microsoft.AD.psm1   # Dot-sources all Src/Public and Src/Private *.ps1 files
  AsBuiltReport.Microsoft.AD.json   # Default report config (InfoLevel, HealthCheck, Options)
  AsBuiltReport.Microsoft.AD.psd1   # Module manifest
  AsBuiltReport.Microsoft.AD.Style.ps1  # PScribo document styling
  Src/
    Public/
      Invoke-AsBuiltReport.Microsoft.AD.ps1  # Entry point; sets up sessions, calls Section functions
    Private/
      Get-Abr*Section.ps1   # Top-level section orchestrators
      Get-AbrAD*.ps1        # Report content generators (one per AD topic)
      Get-AbrDiag*.ps1      # Diagram generators
      ConvertTo-*.ps1       # Data conversion helpers
      Get-Valid*.ps1        # Session/DC validation helpers
  Language/
    en-US/MicrosoftAD.psd1  # English string resources
    es-ES/MicrosoftAD.psd1  # Spanish string resources
```

### Data Flow

1. `Invoke-AsBuiltReport.Microsoft.AD` (Public) connects via PSSession/CIMSession to a target DC, discovers the forest/domain topology, then calls each `Get-Abr*Section` function.
2. Section functions (e.g., `Get-AbrDomainSection`, `Get-AbrForestSection`, `Get-AbrDNSSection`, `Get-AbrPKISection`) gate execution with `$InfoLevel.*` checks and iterate over domains/DCs.
3. Content functions (e.g., `Get-AbrADDomain`, `Get-AbrADDomainController`) collect AD data via `Invoke-CommandWithTimeout` (remote PSSession) and write output using PScribo DSL (`Section`, `Table`, `Paragraph`, `BlankLine`).
4. The PScribo document is assembled in memory and exported to the requested format by the AsBuiltReport.Core framework.

### Key Script-Scoped Variables

These are set by `Invoke-AsBuiltReport.Microsoft.AD` and used across all Private functions:

| Variable | Purpose |
|---|---|
| `$script:TempPssSession` | Primary PSSession to initial target DC |
| `$script:TempCIMSession` | CIMSession to initial DC |
| `$script:InfoLevel` | Hash from JSON config — controls section depth (0–3) |
| `$script:Options` | Hash from JSON config — WinRM, exclusions, diagram settings |
| `$script:ADSystem` | `Get-ADForest` result for the target forest |
| `$script:ForestInfo` | Root domain FQDN (uppercased) |
| `$script:OrderedDomains` | Root domain first, then child domains |
| `$script:DCStatus` | ArrayList tracking reachability status per DC |
| `$reportTranslate` | Localized string resources loaded from `Language/` |

## Key Conventions

### Function Naming

- `Get-AbrAD*` — collects and renders a specific AD topic (domain info, DC info, GPO, trust, etc.)
- `Get-Abr*Section` — top-level orchestrators that call multiple `Get-AbrAD*` functions inside `Section {}` blocks
- `Get-AbrDiag*` — generate infrastructure diagrams
- `ConvertTo-*` — data transformation helpers (e.g., `ConvertTo-TextYN`, `ConvertTo-HashToYN`, `ConvertTo-FileSizeString`)
- `Get-Valid*` — session/connectivity helpers (`Get-ValidDCfromDomain`, `Get-ValidPSSession`, `Get-ValidCIMSession`)

### Building Report Tables

Every content function uses this pattern:
```powershell
$OutObj = [System.Collections.ArrayList]::new()
$inObj = [ordered] @{
    $reportTranslate.FunctionName.FieldKey = $value
    # ...
}
$OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null

$TableParams = @{
    Name = "Table Title - $Domain"
    List = $true          # or $false for horizontal tables
    ColumnWidths = 40, 60
}
if ($Report.ShowTableCaptions) {
    $TableParams['Caption'] = "- $($TableParams.Name)"
}
$OutObj | Table @TableParams
```

### Localized Strings

All user-visible strings — table column headers, section headings, paragraph text, health check messages — must come from `$reportTranslate.<FunctionName>.<Key>`. Add new strings to both `Language/en-US/MicrosoftAD.psd1` and `Language/es-ES/MicrosoftAD.psd1`. String keys use PascalCase and match the function name as a top-level key.

### InfoLevel and HealthCheck Gating

- `$InfoLevel.Domain` (0=Disabled, 1=Enabled, 2=Adv Summary, 3=Detailed) controls whether a section runs and how much detail it shows.
- `$HealthCheck.Domain.BestPractice` (boolean) controls whether health check styling/paragraphs are added to existing tables.
- Pattern for health checks:
```powershell
if ($HealthCheck.Domain.BestPractice) {
    $OutObj | Set-Style -Style Warning -Property $reportTranslate.FunctionName.FieldKey
}
```

### Remote Execution

Always use `Invoke-CommandWithTimeout` (not `Invoke-Command` directly) for remote PSSession calls. This respects `$Options.JobsTimeOut`:
```powershell
$Result = Invoke-CommandWithTimeout -Session $TempPssSession -ScriptBlock {
    Get-ADDomain -Identity $using:Domain
}
```

### Error Handling Pattern

```powershell
begin {
    Write-PScriboMessage -Message ($reportTranslate.FunctionName.Collecting -f $Domain)
    Show-AbrDebugExecutionTime -Start -TitleMessage 'Section Title'
}
process {
    try {
        # ... collect and render ...
    } catch {
        Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Context Description)"
    }
}
end {
    Show-AbrDebugExecutionTime -End -TitleMessage 'Section Title'
}
```

Use `Write-PScriboMessage` (not `Write-Host`) for module logging. `Write-Host` is only allowed in the Public entry point (`Invoke-AsBuiltReport.Microsoft.AD.ps1`) for top-level user-facing progress messages.

### DC Connectivity Check

Before running per-DC logic, always check WinRM reachability:
```powershell
if (Get-DCWinRMState -ComputerName $DC -DCStatus ([ref]$DCStatus)) {
    # ... per-DC work ...
}
```

### Configuration JSON

`AsBuiltReport.Microsoft.AD.json` defines defaults for `Report`, `Options`, `InfoLevel`, and `HealthCheck`. New configurable options must be added here with sensible defaults.

---

## Session Management

### Three Parallel Session Tables

All remote connectivity is tracked in three `[System.Collections.ArrayList]` caches (passed as `[ref]` throughout):

| Variable | Cache Contents | Helper |
|---|---|---|
| `$DCStatus` | WinRM reachability per DC | `Get-DCWinRMState` |
| `$PSSTable` | PSSession objects per DC | `Get-ValidPSSession` |
| `$CIMTable` | CIMSession objects per DC | `Get-ValidCIMSession` |

Each entry in these lists is a hashtable with at minimum: `DCName`, `Status` (`Online`/`Offline`), `Protocol`, and `Id`.

### `Get-DCWinRMState` — Reachability Gate

Always called **before** establishing a PSSession or CIMSession. It:
1. Checks `$DCStatus` cache first (avoids repeated Test-WSMan calls).
2. Falls back to `Test-WSMan` if not cached, respecting `$Options.WinRMSSL`, `$Options.WinRMSSLPort`, and `$Options.WinRMFallbackToNoSSL`.
3. Records result in `$DCStatus` and returns `$true`/`$false`.
4. Ping count controlled by `$Options.DCStatusPingCount` (default: 2).

```powershell
# Always gate DC-specific work:
if (Get-DCWinRMState -ComputerName $DC -DCStatus ([ref]$DCStatus)) {
    # safe to proceed
}
```

### `Get-ValidPSSession` — PSSession Pool

Manages a pool of reusable PSSessions. Behaviour:
- If a cached `Online` session exists for the DC, returns it immediately without creating a new one.
- If `$Options.WinRMSSL` is set, tries SSL first (`$Options.WinRMSSLPort`); if it fails and `$Options.WinRMFallbackToNoSSL` is `$true`, retries on plain WinRM (`$Options.WinRMPort`).
- For the **initial forest connection** (`-InitialForrestConnection $true`), failure throws a terminating error. For per-DC connections, failure is non-terminating (logged as a warning).
- Authentication method is `$Options.PSDefaultAuthentication` (default: `Negotiate`).

```powershell
$DCPssSession = Get-ValidPSSession -ComputerName $DC -SessionName $DC -PSSTable ([ref]$PSSTable)
```

### `Get-ValidCIMSession` — CIMSession Pool

Mirrors `Get-ValidPSSession` but for CIM. SSL uses `New-CimSessionOption -UseSsl`; plain uses `New-CimSession` with `$Options.PSDefaultAuthentication`. CIMSession entries carry an additional `InstanceId` field.

### `Get-ValidDCfromDomain` — Domain DC Discovery

Queries `Get-ADDomain` (via the primary `$TempPssSession`) to get `ReplicaDirectoryServers`, then iterates them through `Get-DCWinRMState` and returns the first reachable DC's FQDN. Used at the start of each domain loop to obtain the `$ValidDC` variable passed to all content functions.

```powershell
if ($ValidDC = Get-ValidDCfromDomain -Domain $Domain -DCStatus ([ref]$DCStatus)) {
    # use $ValidDC as the -Server parameter for AD cmdlets
}
```

---

## Diagram Generation

### Overview

Diagrams are generated via the **Diagrammer.Core** / **Diagrammer.Microsoft.AD** ecosystem (PSGraph + Graphviz). The pipeline is:

```
Get-AbrDiagrammer          # thin wrapper, reads $Options, calls New-AbrADDiagram
  └─ New-AbrADDiagram      # builds Graphviz DOT graph, exports to file or base64
       └─ Get-AbrDiag*     # per-diagram-type data collectors (called inside New-AbrADDiagram)
```

### Diagram Types

Six types are supported (controlled by `$Options.DiagramType.*` booleans in the JSON config):

| Type | JSON Key | What it shows |
|---|---|---|
| `Forest` | `DiagramType.Forest` | Forest topology with domains |
| `Sites` | `DiagramType.Sites` | AD site links and connections |
| `SitesInventory` | `DiagramType.SitesInventory` | Sites with DC inventory per site |
| `Trusts` | `DiagramType.Trusts` | Domain trust relationships |
| `CertificateAuthority` | `DiagramType.CertificateAuthority` | PKI CA hierarchy |
| `Replication` | `DiagramType.Replication` | DC replication topology |

### How `Get-AbrDiagrammer` Works

1. Reads `$Options.DiagramTheme` (`White`/`Black`/`Neon`) and `$Options.ExportDiagramsFormat` (array: `pdf`, `png`, `svg`, `jpg`, `base64`).
2. Passes an existing `$TempPssSession` as `-PSSessionObject` (no credential re-prompt).
3. For `base64` format: returns the base64 string directly (used to embed diagrams inline in HTML reports).
4. For file formats: saves to `$OutputFolderPath` as `AsBuiltReport.Microsoft.AD-(<DiagramType>).<ext>` and returns the file path when `-ExportPath` is set.
5. Optional features toggled via `$Options`: `EnableDiagramDebug` (red edge/subgraph outlines), `EnableDiagramSignature` (footer with `SignatureAuthorName`/`SignatureCompanyName`), `DiagramWaterMark`.

### Embedding a Diagram in the Report

The typical pattern in a Section function:
```powershell
if ($Options.EnableDiagrams -and $Options.DiagramType.Forest) {
    $DiagramFile = Get-AbrDiagrammer -DiagramType 'Forest' -DiagramOutput 'base64' -PSSessionObject $TempPssSession
    if ($DiagramFile) {
        Image -Base64 $DiagramFile -Text 'Forest Diagram' -Percent 100 -Align 'Center'
        BlankLine
    }
}
```

### `New-AbrADDiagram` Internals

- Requires **admin** privileges (checks `WindowsPrincipal` role).
- Builds a `Graph {}` block (PSGraph DSL) with node/edge default styles derived from `$DiagramTheme`.
- Icon images are loaded from `AsBuiltReport.Microsoft.AD/icons/` via `$script:IconPath`.
- The `$reportTranslate.NewADDiagram.*` keys supply graph label strings (supports `en-US`/`es-ES`).
- `$Options.DiagramObjDebug` enables verbose object-level debug output.
- Does **not** use `$TempPssSession` directly — it creates its own internal `$DiagramTempPssSession` or accepts one via `-PSSessionObject`.

### Adding a New Diagram Type

1. Add a new `Get-AbrDiag<Type>.ps1` in `Src/Private/` following the existing `Get-AbrDiagForest.ps1` / `Get-AbrDiagSite.ps1` pattern.
2. Add the type string to the `ValidateSet` in both `Get-AbrDiagrammer` and `New-AbrADDiagram`.
3. Add a `$MainGraphLabel` switch case in `New-AbrADDiagram`'s `begin` block.
4. Add the corresponding boolean key to `Options.DiagramType` in `AsBuiltReport.Microsoft.AD.json`.
5. Add localized label strings to both `Language/` psd1 files under the `NewADDiagram` key.

---

## PKI / Certificate Authority Section

### Prerequisites

The PKI section only runs when **all** of the following are true:
- `$InfoLevel.CA -ge 1`
- The machine running the report is joined to a domain that is **part of the target forest** (`Get-ComputerADDomain` result must be in `$ADSystem.Domains`)
- `Get-CertificationAuthority -Enterprise` returns at least one CA (uses the **PSPKI** module)

If the reporting machine's domain is not in the forest, a warning is logged and the section is skipped entirely.

### CA Data Source

The PKI section does **not** use PSSession/CIMSession for CA data. It uses **PSPKI** module cmdlets directly on the machine running the report:
- `Get-CertificationAuthority -Enterprise` — discovers all enterprise CAs
- `Get-CertificationAuthority -Enterprise -ComputerName $CA` — per-CA object
- `Get-CACryptographyConfig -CertificationAuthority $CA`
- `Get-CATemplate`, `Get-CARoleServiceStatus`, `Get-CRLDistributionPoint`, `Get-AuthorityInformationAccess`

The `$script:CAs` variable is set in `Get-AbrPKISection` and used by all CA sub-functions.

### Section Structure (`Get-AbrPKISection`)

```
PKI (Heading1)                       ← only when $InfoLevel.CA -ge 1
  Get-AbrADCASummary                 ← always (CA name, server, type, service status)
  Get-AbrADCARoot                    ← InfoLevel.CA -ge 2
  Get-AbrADCASubordinate             ← InfoLevel.CA -ge 2
  foreach accessible CA:
    <CA DisplayName> Details (Heading2)
      Get-AbrADCASecurity            ← always
      Get-AbrADCACryptographyConfig  ← always
      Get-AbrADCAAIA                 ← InfoLevel.CA -ge 2
      Get-AbrADCACRLSetting          ← InfoLevel.CA -ge 2
      Get-AbrADCATemplate            ← InfoLevel.CA -ge 2
      Get-AbrADCAKeyRecoveryAgent    ← always
```

### HealthCheck Styles for CA

| Check | Config Key | Style Applied |
|---|---|---|
| CA service not Running | `HealthCheck.CA.Status` | `Critical` on Status column |
| CA statistics thresholds | `HealthCheck.CA.Statistics` | `Warning` |
| Best practice settings | `HealthCheck.CA.BestPractice` | `Warning` |

Style values are `Warning` (yellow), `Critical` (red), and `Info` (blue) — passed to `Set-Style -Style <value> -Property <translated-key>`.

### Adding New CA Content

CA functions receive `$CA` (a PSPKI `CertificationAuthority` object) as their only parameter. The `$ForestInfo` script variable provides the forest name for table naming. Follow the same `$inObj` → `ConvertTo-HashToYN` → `Table` pattern as all other content functions.
