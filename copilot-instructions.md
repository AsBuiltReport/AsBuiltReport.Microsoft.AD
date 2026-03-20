# AsBuiltReport.Microsoft.AD - Copilot Instructions

**Project Overview:** AsBuiltReport.Microsoft.AD is a PowerShell module that generates comprehensive as-built documentation for Microsoft Active Directory (AD) infrastructure in Word/HTML/Text formats. It's part of the larger AsBuiltReport ecosystem and works in conjunction with AsBuiltReport.Core.

---

## 1. PROJECT STRUCTURE

### Top-Level Directory Layout
```
AsBuiltReport.Microsoft.AD/
├── .github/                          # CI/CD workflows and PR templates
│   ├── workflows/                    # GitHub Actions workflows
│   │   ├── Pester.yml               # Unit testing pipeline
│   │   ├── PSScriptAnalyzer.yml     # Linting/code analysis
│   │   ├── CodeQL.yml               # Security scanning
│   │   ├── Release.yml              # Publishing to PSGallery + social media
│   │   └── Stale.yml                # Issue/PR housekeeping
│   └── PULL_REQUEST_TEMPLATE.md
├── .vscode/                          # VS Code settings for PowerShell formatting
│   └── settings.json                # Formatting rules, rulers @ 115 chars
├── AsBuiltReport.Microsoft.AD/       # MAIN MODULE DIRECTORY
│   ├── AsBuiltReport.Microsoft.AD.psm1        # Module manifest (14 lines - loads all functions)
│   ├── AsBuiltReport.Microsoft.AD.psd1        # Module declaration (v0.9.11)
│   ├── AsBuiltReport.Microsoft.AD.json        # Default report config (InfoLevels, HealthChecks)
│   ├── AsBuiltReport.Microsoft.AD.Style.ps1  # Document styling (20.8 KB)
│   ├── Src/
│   │   ├── Public/
│   │   │   └── Invoke-AsBuiltReport.Microsoft.AD.ps1  # ENTRY POINT (291 lines)
│   │   └── Private/
│   │       ├── Get-Abr*.ps1         # 52x data gathering functions
│   │       ├── ConvertTo-*.ps1      # Format/conversion helpers
│   │       ├── Convert-*.ps1        # Data transformation utilities
│   │       ├── Get-*Diagram.ps1     # Visualization generation
│   │       └── Utility functions    # Session management, timeout handling, etc.
│   ├── Language/                    # Localization files
│   │   ├── en-US/MicrosoftAD.psd1  # English strings (hash of all messages)
│   │   └── es-ES/MicrosoftAD.psd1  # Spanish localization
│   └── icons/                       # Image assets for reports
├── Tests/
│   ├── Invoke-Tests.ps1             # Test runner script (204 lines)
│   ├── AsBuiltReport.Microsoft.AD.Tests.ps1  # Pester unit tests
│   ├── LocalizationData.Tests.ps1   # Localization validation
│   └── README.md
├── Samples/                         # Example HTML reports
├── README.md                        # Project documentation
├── CONTRIBUTING.md                  # Contribution guidelines
├── CODE_OF_CONDUCT.md              # Community standards
├── LICENSE                         # License file
├── CHANGELOG.md                    # Version history
├── SECURITY.md                     # Security policy
└── Todo.md                         # Development roadmap
```

### Key Directories
- **Src/Public**: Only `Invoke-AsBuiltReport.Microsoft.AD` - the single exported public function
- **Src/Private**: 88 total functions (52 Get-Abr* for data gathering, rest are utilities)
- **Language**: Localization for multi-language support (en-US, es-ES)
- **Tests**: Pester tests + custom test runner supporting code coverage

### File Count Summary
- **Total .ps1 files**: 94
- **Public functions**: 1 (exported)
- **Private functions**: ~88 + utilities
- **Data gathering functions (Get-Abr*)**: 52

---

## 2. BUILD, TEST, LINT COMMANDS

### Test Execution

**Local Test Execution:**
```powershell
.\Tests\Invoke-Tests.ps1                              # Basic run
.\Tests\Invoke-Tests.ps1 -CodeCoverage -OutputFormat NUnitXml  # With coverage
```

**Test Runner Details** (`Tests/Invoke-Tests.ps1`):
- Uses **Pester 5.0.0+** for testing framework
- Supports output formats: Console, NUnitXml, JUnitXml
- Includes code coverage analysis (JaCoCo format)
- Code coverage threshold: 50% minimum (warning at <50%)
- Coverage files tracked: `*.psm1`, `Src/Public/*.ps1`, `Src/Private/*.ps1`
- Test results: `Tests/testResults.xml`
- Coverage output: `Tests/coverage.xml`

### Code Analysis

**PSScriptAnalyzer** (`PSScriptAnalyzerSettings.psd1`):
- Linting tool configured in CI/CD
- Custom rules enforced:
  - `PSAvoidExclaimOperator` - no `!` operator
  - `AvoidUsingDoubleQuotesForConstantString` - use single quotes for constants
  - `UseCorrectCasing` - enforce proper case
  - `PSAvoidUsingCmdletAliases` - no aliases
  - `PSUseConsistentWhitespace` - whitespace consistency
- Excluded rules:
  - `PSUseToExportFieldsInManifest`
  - `PSAvoidUsingWriteHost` (needed for reports)

### CI/CD Pipelines

**Pester Tests Workflow** (`.github/workflows/Pester.yml`):
- Triggers: push (main/dev/master), PR, manual
- Runs on: Windows (pwsh + powershell 5.1)
- Auto-installs: Pester 5.0.0+, PScribo 0.11.1+, PSScriptAnalyzer 1.0.0+, AsBuiltReport.Core 1.6.2+
- Uploads test results as artifacts
- Uploads code coverage to Codecov

**PSScriptAnalyzer Workflow** (`.github/workflows/PSScriptAnalyzer.yml`):
- Uses external action: `alagoutte/github-action-psscriptanalyzer@master`
- Fails on errors, comments inline
- Settings: `.github/workflows/PSScriptAnalyzerSettings.psd1`

**CodeQL Workflow** (`.github/workflows/CodeQL.yml`):
- Security scanning for PowerShell

**Release Workflow** (`.github/workflows/Release.yml`):
- Triggers on release published
- Tests module manifest
- Publishes to PowerShell Gallery (`Publish-Module`)
- Posts release announcements to Twitter & Bluesky

**No Build/Invoke-Build found**: This is a pure PowerShell module (no compilation).

---

## 3. ARCHITECTURE

### High-Level Data Flow

```
Invoke-AsBuiltReport.Microsoft.AD (Entry Point)
    ↓
    [Input: Target DC, Credentials]
    ↓
    [Validate: Requirements, Features, Modules]
    ↓
    [Connection: PSSession + CIMSession to DC]
    ↓
    [Process Per Forest/Domain]
    ├── Get-AbrForestSection (Forest-level data)
    ├── Get-AbrDomainSection (Per-domain data)
    ├── Get-AbrDnsSection (DNS configuration)
    └── Get-AbrPKISection (Certificate Authority)
    ↓
    [Diagram Generation: Forest, Replication, Trusts, Sites, CA]
    ↓
    [Session Cleanup: Remove PSSession, CIMSession]
    ↓
    [Output: HTML/Word/Text Report]
```

### Main Entry Point

**File**: `AsBuiltReport.Microsoft.AD/Src/Public/Invoke-AsBuiltReport.Microsoft.AD.ps1` (291 lines)

**Signature**:
```powershell
function Invoke-AsBuiltReport.Microsoft.AD {
    [CmdletBinding()]
    param (
        [String[]] $Target,              # Domain controller(s) FQDN
        [PSCredential] $Credential       # Credentials for remote session
    )
    #Requires -RunAsAdministrator
}
```

**Key Responsibilities**:
1. Validate prerequisites (Windows PS >= 5.1, admin rights, not ISE)
2. Check installed modules & warn on outdated versions
3. Validate OS features (RSAT tools on workstation, features on server)
4. Load report config (JSON), InfoLevels, HealthChecks, Options
5. Establish PSSession + CIMSession to DC via WinRM
6. Collect forest/domain/DNS/PKI data via section functions
7. Generate diagrams (if enabled)
8. Build report using PScribo
9. Cleanup sessions

**Critical Design Pattern**:
- **$Target** must be FQDN (not IP) - WinRM limitation
- Must run **-RunAsAdministrator**
- Must run from PowerShell 7+, **NOT** PowerShell ISE
- WinRM must be enabled on DC
- Uses **$Options** hash from config for behavior control

### Core Section Builders

These functions call data gatherers and structure output via PScribo's **Section** cmdlet:

1. **Get-AbrForestSection**: Forest topology, schema, tombstone lifetime, global catalogs
2. **Get-AbrDomainSection**: Per-domain configuration, trusts, replication, GPOs, OUs
3. **Get-AbrDnsSection**: DNS zones, scavenging, delegation
4. **Get-AbrPKISection**: Certificate authorities, templates, security

### Data Gathering Functions (Get-Abr*)

**Pattern**: Each function collects specific AD object data via remote PSSession:

Example: `Get-AbrADForest` (80 lines)
- Uses `Invoke-CommandWithTimeout` to run remote cmdlets
- Parses schema version to determine Windows Server version
- Detects anonymous access via dsHeuristics
- Returns object with translated property names
- Applies HealthCheck styling if enabled

**All 52 Get-Abr* functions follow this pattern:**
- Accept parameters (Domain, ValidDcFromDomain, etc.)
- Start: Log collection message, start timing
- Process: Remote invocation via session, data transformation
- Output: `[System.Collections.ArrayList]` of objects
- HealthCheck: Conditionally apply styling (Warning/Critical)
- Return: Table/list output via PScribo's **Table** cmdlet

### InfoLevel Architecture

**Default Config** (`AsBuiltReport.Microsoft.AD.json`):
```json
"InfoLevel": {
    "_comment_": "0 = Disabled, 1 = Enabled, 2 = Adv Summary, 3 = Detailed",
    "Forest": 2,
    "Domain": 2,
    "DNS": 1,
    "CA": 0
}
```

**Usage Pattern**:
```powershell
if ($InfoLevel.Forest -ge 1) { ... show basic info }
if ($InfoLevel.Forest -ge 2) { ... show advanced details }
if ($InfoLevel.Forest -ge 3) { ... show comprehensive tables }
```

Enables **progressive disclosure** - users control report verbosity.

### HealthCheck Architecture

**Default Config**:
```json
"HealthCheck": {
    "Domain": {
        "GMSA": true,           # Group Managed Service Accounts
        "GPO": true,            # Group Policy Objects
        "Backup": true,         # Domain backup status
        "DFS": true,            # DFS health
        "SPN": true,            # Service Principal Names
        "DuplicateObject": true,
        "Security": true,
        "BestPractice": true
    },
    "DomainController": { ... },
    "Site": { ... },
    "DNS": { ... },
    "CA": { ... }
}
```

**Styling Application**:
```powershell
if ($HealthCheck.Domain.Security) {
    $OutObj | Where-Object { $_.AnonymousAccess -eq 'Enabled' } | 
        Set-Style -Style Critical -Property AnonymousAccess
    $OutObj | Where-Object { $_.TombstoneLifetime -lt 180 } | 
        Set-Style -Style Warning -Property TombstoneLifetime
}
```

Objects marked as Warning/Critical get colored highlighting in reports.

### Connection Management

**Session Establishment** (in main entry point):
```powershell
$TempPssSession = Get-ValidPSSession -ComputerName $System -SessionName $System
$TempCIMSession = Get-ValidCIMSession -ComputerName $System -SessionName $System
```

**Remote Command Execution**:
```powershell
Invoke-CommandWithTimeout -Session $TempPssSession -ScriptBlock { Get-ADForest }
```

**Cleanup**:
```powershell
foreach ($PSSession in $PSSTable | Where { $_.Status -ne 'Offline' }) {
    Remove-PSSession -Id $PSSession.id
}
```

### Diagram Generation

**Diagrammer Integration**:
- Uses `Diagrammer.Core` module for topology visualization
- Types: Forest, Replication, Sites, SitesInventory, Trusts, CertificateAuthority
- Controlled by `$Options.EnableDiagrams`, `$Options.DiagramType.*`
- Outputs: PDF/PNG (configurable via `$Options.ExportDiagramsFormat`)
- Theme: White/Dark (via `$Options.DiagramTheme`)

---

## 4. KEY CONVENTIONS AND PATTERNS

### Function Naming Convention

**Public Functions**:
- `Invoke-AsBuiltReport.Microsoft.AD` - single entry point (uses dot notation)

**Private Functions** - Three categories:

1. **Data Gatherers** (`Get-Abr*`):
   - `Get-AbrADForest` - retrieves Forest info
   - `Get-AbrADDomain` - retrieves Domain info
   - `Get-AbrADDomainController` - DC inventory
   - `Get-AbrADCA*` - CA-specific data
   - Pattern: Get-Abr[Section][Subsection]

2. **Section Builders** (`Get-Abr*Section`):
   - `Get-AbrForestSection` - orchestrates Forest section
   - `Get-AbrDomainSection` - orchestrates Domain section
   - `Get-AbrDnsSection` - orchestrates DNS section
   - `Get-AbrPKISection` - orchestrates PKI section
   - Pattern: Get-Abr[Section]Section

3. **Diagram Builders** (`Get-AbrDiag*`):
   - `Get-AbrDiagrammer` - main diagram orchestration
   - `Get-AbrDiagForest`, `Get-AbrDiagReplication`, etc.
   - Pattern: Get-AbrDiag[DiagramType]

4. **Utility Functions** (various):
   - `Convert-IpAddressToMaskLength` - IP/CIDR conversion
   - `ConvertTo-HashToYN` - bool → Yes/No conversion
   - `Invoke-CommandWithTimeout` - remote execution with timeout
   - `Get-ValidPSSession` - session validation/creation
   - `Test-WinRM` - WinRM connectivity check

### Data Structure Patterns

**Standard Data Object**:
```powershell
$inObj = [ordered] @{
    'Property Name' = $Value
    'Health Check Property' = $CheckResult
}
$OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
```

**Conversion Helper Usage**:
```powershell
# ConvertTo-HashToYN: Converts boolean $true/$false → "Yes"/"No"
$inObj | ConvertTo-HashToYN
```

**Style Application**:
```powershell
$OutObj | Set-Style -Style Critical -Property $PropertyName
$OutObj | Set-Style -Style Warning -Property $PropertyName
```

### Report Section Structure

**PScribo Section Hierarchy**:
```powershell
Section -Style Heading1 "Forest Name" {
    Paragraph "Introduction..."
    BlankLine
    
    Section -Style Heading2 "Subsection Title" {
        if ($Options.ShowDefinitionInfo) {
            Paragraph "Definition text..."
        }
        
        # Call data gatherer
        Get-AbrADForest
        
        if ($InfoLevel.Forest -ge 2) {
            # Advanced details
            Get-AbrADSite
        }
    }
}
```

**PScribo Elements Used**:
- `Section` - create section with heading levels (Heading1-Heading4)
- `Table` - display data in tabular format
- `Paragraph` - text with styling (Bold, Underline, Colors)
- `BlankLine` - spacing
- `PageBreak` - force page break in Word/PDF

### Translation/Localization Pattern

**Property Names Use Translated Strings**:
```powershell
# From Language/en-US/MicrosoftAD.psd1
@{
    GetAbrADForest = @{
        Collecting = 'Collecting Active Directory forest information.'
        ForestName = 'Forest Name'
        ForestFunctionalLevel = 'Forest Functional Level'
        ...
    }
}

# In function:
$reportTranslate.GetAbrADForest.Collecting  # Loaded at module init
```

**Multi-Language Support**:
- Each culture has its own .psd1 file (en-US, es-ES, etc.)
- Strings loaded into `$reportTranslate` hash at module load
- Property names in output tables are localized

### HealthCheck Patterns

**Pre-Check Pattern** (e.g., RID Pool):
```powershell
if ($HealthCheck.Domain.BestPractice) {
    if ([math]::Truncate($CompleteSIDS / $RIDsRemaining) -gt 80) {
        $OutObj | Set-Style -Style Warning -Property RIDProperty
        Paragraph "Health check message about RID pool..."
    }
}
```

**28 Functions Use HealthCheck** out of 52 data gatherers (~54%):
- Focus on security, best practices, service health
- Each check compares values against thresholds
- Styling applied: Warning, Critical, or Success

### Configuration-Driven Behavior

**Options Hash Controls**:
```json
"Options": {
    "ShowExecutionTime": false,        # Show timing info
    "ShowDefinitionInfo": false,       # Show definition text
    "PSDefaultAuthentication": "Negotiate",
    "Exclude": { "Domains": [], "DCs": [] },
    "Include": { "Domains": [] },      # Only these domains
    "WinRMSSL": false,
    "WinRMFallbackToNoSSL": true,
    "WinRMSSLPort": 5986,
    "WinRMPort": 5985,
    "EnableDiagrams": true,
    "DiagramTheme": "White",
    "JobsTimeOut": 900                 # 15-minute timeout
}
```

**Usage Example**:
```powershell
if ($Options.ShowDefinitionInfo) {
    Paragraph $reportTranslate.GetAbrForestSection.DefinitionText
}

$TimeoutSeconds = $Options.JobsTimeOut
```

### Error Handling & Timeouts

**Invoke-CommandWithTimeout Pattern**:
```powershell
function Invoke-CommandWithTimeout {
    param(
        [System.Management.Automation.Runspaces.PSSession]$Session,
        [scriptblock]$ScriptBlock,
        [int]$TimeoutSeconds = $Options.JobsTimeOut
    )
    
    # Run as background job with timeout
    $job = Invoke-Command -Session $Session -AsJob -ScriptBlock $ScriptBlock
    Wait-Job $job -Timeout $TimeoutSeconds
    Receive-Job $job
}
```

**Try-Catch in Data Gatherers**:
```powershell
try {
    Get-AbrADForest
} catch {
    Write-PScriboMessage -IsWarning $_.Exception.Message
}
```

### Sensitive Data Handling

**No explicit redaction observed**, but patterns suggest:
- Credentials passed via `$PSCredential` object (not stored)
- Session-based execution (no inline secrets)
- Remote execution prevents data capture on local disk
- Output tables contain parsed, non-sensitive data

**Recommendation**: Follow AD best practices - restrict report access, don't email to untrusted parties.

---

## 5. CONFIGURATION

### Primary Config File

**File**: `AsBuiltReport.Microsoft.AD/AsBuiltReport.Microsoft.AD.json`

**Structure**:
```json
{
    "Report": {
        "Name": "Microsoft Active Directory As Built Report",
        "Version": "1.0",
        "Status": "Released",
        "ShowCoverPageImage": true,
        "ShowTableOfContents": true,
        "ShowHeaderFooter": true,
        "ShowTableCaptions": true
    },
    "Options": { ... },           // Execution behavior
    "InfoLevel": { ... },         // Report verbosity
    "HealthCheck": { ... }        // Health check toggles
}
```

### Configuration Usage

Users provide config via **-ReportConfig parameter** to AsBuiltReport.Core:

```powershell
$ReportConfig = Get-Content 'config.json' | ConvertFrom-Json

New-AsBuiltReport -Report Microsoft.AD `
    -Target 'DC01.contoso.com' `
    -ReportConfig $ReportConfig `
    -Credential $cred `
    -Format HTML
```

**Module Loads**:
```powershell
$script:Report = $ReportConfig.Report
$script:InfoLevel = $ReportConfig.InfoLevel
$script:Options = $ReportConfig.Options
```

### Module Manifest

**File**: `AsBuiltReport.Microsoft.AD/AsBuiltReport.Microsoft.AD.psd1`

**Key Settings**:
- **Version**: 0.9.11
- **PowerShellVersion**: 5.1 (minimum, actually PS7 required)
- **CompatiblePSEditions**: Desktop, Core
- **GUID**: 0a3e1c04-13b8-418f-89bc-a5a18da07394

**Required Modules**:
- AsBuiltReport.Core (v1.6.2+)
- AsBuiltReport.Chart (v0.2.0+)
- Diagrammer.Core (v0.2.38+)
- PSPKI (v4.3.0+)

---

## 6. EXISTING AI CONFIGS

**None Found**. No existing files:
- `.cursorrules` ✗
- `.clinerules` ✗
- `.windsurfrules` ✗
- `CLAUDE.md` ✗
- `AGENTS.md` ✗
- `CONVENTIONS.md` ✗

---

## 7. README AND CONTRIBUTING

### README Key Points

**Project Purpose**:
- Community-maintained, no Microsoft sponsorship
- Generates as-built documentation for AD (Word/HTML/Text)
- Supports AD 2012/2016/2019/2022/2025
- **PowerShell 7+ required** (not PS 5.1!)
- Windows only (RSAT dependency)

**Supported Features**:
- Forest topology & schema info
- Domain configuration & replication
- DNS zones & scavenging
- PKI/Certificate Authority details
- Diagrams (Forest, Replication, Trusts, Sites, CA)
- Health checks for security/best practices
- Multi-language support (en-US, es-ES)

**Key Disclaimer**:
> This assessment is not exhaustive. All recommendations should be reviewed and implemented by qualified personnel. The author(s) assume no liability for any damages.

### CONTRIBUTING Guidelines

**Process**:
1. Fork repo, clone, add remote upstream
2. Create topic branch off dev/main
3. Make changes following project conventions
4. Commit with clear messages
5. Pull upstream dev before pushing
6. Open PR with clear description

**Requirements**:
- Follow existing code conventions (indentation, comments)
- Include test coverage (reference Pester tests)
- Respect git commit message guidelines
- No copyrighted content
- Agree to project license

**Key Restriction**:
- Ask before embarking on large features/refactoring
- Don't use issue tracker for personal support

---

## 8. CODE CONVENTIONS SUMMARY

### PowerShell Code Style

**Enforced via VSCode + PSScriptAnalyzer**:

**Formatting** (`.vscode/settings.json`):
- Tab size: 4 spaces (insert spaces, not tabs)
- Line length: 115 characters (ruler configured)
- Trim trailing whitespace: enabled
- Code folding: enabled
- Brace style:
  - Opening brace on same line: `if (...) {`
  - New line after opening brace: `{\n    ...`
  - New line after closing brace: disabled
- Whitespace:
  - Before open brace: enabled
  - Before open paren: enabled
  - Around operators: enabled
  - After separator (;): enabled
  - Around pipe: enabled

**Linting** (`PSScriptAnalyzerSettings.psd1`):
- No single-character variable names
- No double quotes for constant strings
- Case sensitivity enforced
- No aliases (full cmdlet names)
- Consistent whitespace

### Naming Conventions

**Variables**:
- PascalCase for scripts/function names: `$ValidDcFromDomain`
- $script: prefix for module-level vars: `$script:Report`, `$script:InfoLevel`
- Hungarian notation for collections: `$PSSTable`, `$DCStatus` (plural hint)

**Functions**:
- Verb-Noun format: `Get-AbrADForest`, `Invoke-CommandWithTimeout`
- Approved verbs: Get, New, Invoke, Test, Convert
- Hierarchy: `Get-[Abr][Component][Action]`

**Constants**:
- `[ordered]` for hash ordering
- `[System.Collections.ArrayList]` for dynamic arrays (preferred over `@()`)
- `[pscustomobject]` for object creation

### Error Handling

- Use **try-catch** blocks
- Write warnings via `Write-PScriboMessage -IsWarning`
- Write errors via `Write-Error` or `throw`
- Log activity via `Write-PScriboMessage`
- Show timing via `Show-AbrDebugExecutionTime`

### Documentation

- SYNOPSIS, DESCRIPTION, NOTES (version, author, twitter, github)
- .EXAMPLE, .LINK for help
- Inline comments for complex logic
- Parameter documentation with `[Parameter(...)]` attributes

---

## 9. CRITICAL DEVELOPMENT NOTES

### Must-Know Limitations

1. **WinRM Requirements**:
   - Target must be FQDN (not IP)
   - WinRM must be enabled on DC
   - Domain-joined machine required to run module
   - PowerShell 7+ on Windows only

2. **Execution Context**:
   - Must run `-RunAsAdministrator`
   - Cannot run inside PowerShell ISE
   - Remote execution via PSSession (not local cmdlets)

3. **Session Timeout**:
   - Default timeout: 900 seconds (15 minutes)
   - Configurable via `$Options.JobsTimeOut`
   - Long operations may timeout on slow links

### Development Workflow

1. **Make changes** to `.ps1` files in `Src/Public` or `Src/Private`
2. **Run tests** locally: `.\Tests\Invoke-Tests.ps1`
3. **Check linting**: PSScriptAnalyzer via VSCode
4. **Push to dev branch** (not master)
5. **CI/CD runs** Pester + PSScriptAnalyzer
6. **Create PR** to merge into master

### Debugging Tips

**Execution Timing**:
```powershell
if ($Options.ShowExecutionTime) {
    Show-AbrDebugExecutionTime -Start/Stop -TitleMessage 'Section Name'
}
```

**Logging Messages**:
```powershell
Write-PScriboMessage -Message "Collecting..."
Write-PScriboMessage -IsWarning "Warning message"
```

**Remote Session Debugging**:
```powershell
$session = Get-PSSession -Name 'DC01.contoso.com'
Invoke-Command -Session $session -ScriptBlock { Get-ADForest }
```

### Performance Considerations

- Remote data collection happens sequentially (per domain)
- Large forests (100+ domains) may take 30+ minutes
- CPU-intensive: Schema analysis, trust enumeration
- Network: WinRM traffic, potentially large XML responses
- Disk: HTML/DOCX output can be 50+ MB with diagrams

### Testing Strategy

**Unit Tests** (`Tests/AsBuiltReport.Microsoft.AD.Tests.ps1`):
- Module manifest validation
- Function availability
- Module dependency versions
- Export validation

**Integration Tests** (Not present):
- Would require live AD environment
- Manual testing against test domains recommended

**Code Coverage**:
- Current: Unknown (50% threshold enforced)
- Recommendation: Add more tests for edge cases

---

## 10. PROJECT-SPECIFIC GUIDANCE FOR AI ASSISTANTS

### When Making Code Changes

1. **Respect InfoLevel checks**: Wrap new sections with `if ($InfoLevel.Component -ge N)`
2. **Add HealthCheck conditionals**: Wrap checks with `if ($HealthCheck.Component.Feature)`
3. **Use localization strings**: Reference `$reportTranslate.FunctionName.PropertyName`
4. **Follow try-catch pattern**: Every data gatherer in try-catch with `-IsWarning`
5. **Apply Set-Style**: Mark warning/critical objects for report highlighting
6. **Use OrderedDictionary**: `[ordered] @{}` for property ordering
7. **Pass sessions as parameters**: Don't assume `$TempPssSession` global exists
8. **Document with `.SYNOPSIS`**: All functions need help documentation
9. **Return objects not strings**: Build arrays of `[pscustomobject]` for Table output
10. **Test with `-CodeCoverage`**: Ensure new code is covered by tests

### Common Tasks

**Add a new health check:**
1. Add boolean to `AsBuiltReport.Microsoft.AD.json` under `HealthCheck.Component.NewCheck`
2. In Get-Abr* function: `if ($HealthCheck.Component.NewCheck) { ... Set-Style ... }`
3. Add test case to `Tests/AsBuiltReport.Microsoft.AD.Tests.ps1`

**Add new report section:**
1. Create `Get-AbrNewSection` function in `Src/Private/`
2. Create `Get-AbrNewSectionData` data gatherer
3. Call from main entry point: `if ($InfoLevel.NewComponent -ge 1) { Get-AbrNewSection }`
4. Add InfoLevel config: `"NewComponent": 1` to JSON
5. Add translations to `Language/en-US/MicrosoftAD.psd1` and `es-ES/`

**Fix a timeout issue:**
1. Increase `$Options.JobsTimeOut` in JSON (default 900)
2. Or reduce data scope (disable HealthChecks or lower InfoLevel)
3. Or optimize remote query (use `-Filter` with better conditions)

### Module Dependencies to Understand

- **AsBuiltReport.Core**: Framework for report generation, parameter validation
- **PScribo**: Document markup (Section, Table, Paragraph, Set-Style)
- **ActiveDirectory**: AD cmdlets (Get-ADForest, Get-ADDomain, etc.) - Microsoft module
- **PSPKI**: PKI cmdlets (Get-CertificationAuthority) - community module
- **Diagrammer.Core**: Diagram generation for topology visualization
- **GroupPolicy**: GPO retrieval (Get-GPO, Get-GPOReport)
- **DnsServer**: DNS zone enumeration

---

## 11. QUICK REFERENCE

### Module Entry Point
- **Location**: `AsBuiltReport.Microsoft.AD/Src/Public/Invoke-AsBuiltReport.Microsoft.AD.ps1`
- **Exports**: Single public function (dot-notation name)
- **Parameters**: `$Target` (FQDN array), `$Credential` (PSCredential)
- **Returns**: Report file (HTML/Word/Text) via PScribo

### Main Directories
| Directory | Purpose | Files |
|-----------|---------|-------|
| `Src/Public` | Exported functions | 1 file (entry point) |
| `Src/Private` | Internal functions | 88 functions |
| `Language` | Localization | .psd1 per culture |
| `Tests` | Unit/integration tests | Pester framework |
| `.github/workflows` | CI/CD pipelines | 5 YAML files |

### Key Files
| File | Purpose | Size |
|------|---------|------|
| `AsBuiltReport.Microsoft.AD.psm1` | Module loader | 14 lines |
| `AsBuiltReport.Microsoft.AD.psd1` | Manifest | ~100 lines |
| `AsBuiltReport.Microsoft.AD.json` | Config template | 89 lines |
| `AsBuiltReport.Microsoft.AD.Style.ps1` | Report styling | 20 KB |

### Test Commands
```powershell
# Basic test run
.\Tests\Invoke-Tests.ps1

# With coverage
.\Tests\Invoke-Tests.ps1 -CodeCoverage -OutputFormat NUnitXml

# Output formats
.\Tests\Invoke-Tests.ps1 -OutputFormat JUnitXml
.\Tests\Invoke-Tests.ps1 -OutputFormat Console
```

### Required Modules (Minimum Versions)
```powershell
AsBuiltReport.Core        1.6.2+
AsBuiltReport.Chart       0.2.0+
Diagrammer.Core           0.2.38+
PSPKI                     4.3.0+
Pester                    5.0.0+
PScribo                   0.11.1+
PSScriptAnalyzer          1.0.0+
```

### Function Categories
| Category | Count | Examples |
|----------|-------|----------|
| Get-Abr* (data gathering) | 52 | Get-AbrADForest, Get-AbrADDomain |
| Get-Abr*Section (orchestration) | 4 | Get-AbrForestSection, Get-AbrDNSSection |
| Get-AbrDiag* (diagrams) | 8 | Get-AbrDiagrammer, Get-AbrDiagForest |
| Utility (conversion, helpers) | 24+ | ConvertTo-HashToYN, Invoke-CommandWithTimeout |

---

**Document Version**: 1.0  
**Last Updated**: 2024  
**Project Version**: 0.9.11  
**Target PowerShell**: 7+  
**Platform**: Windows Only

