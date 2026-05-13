
function Get-AbrAdLog {
    <#
    .SYNOPSIS
        Collects diagnostic information for AsBuiltReport.ActiveDirectory troubleshooting.
    .DESCRIPTION
        Gathers environment, module, PowerShell session, and error information from
        the current session and the machine running the report. Output is written to
        a structured JSON file, and a status message is written to the host when the
        collection completes successfully.
    .PARAMETER OutputFolderPath
        Directory where the diagnostic bundle (JSON file) is saved.
        Defaults to the system temporary folder.
    .PARAMETER IncludeErrorDetails
        When specified, captures the full $Error collection including stack traces.
        By default only the most recent 25 errors are included (without stack traces).
    .PARAMETER PassThru
        Returns the diagnostic object to the pipeline in addition to writing the file.
    .EXAMPLE
        Get-AbrAdLog

        Saves a diagnostic JSON to the system temp folder.
    .EXAMPLE
        Get-AbrAdLog -OutputFolderPath 'C:\Logs' -IncludeErrorDetails -PassThru

        Saves a full diagnostic JSON (with stack traces) to C:\Logs and returns the
        object to the pipeline.
    .NOTES
        Version:        0.1.0
        Author:         Jonathan Colon
        Github:         rebelinux
    .LINK
        https://github.com/AsBuiltReport/AsBuiltReport.ActiveDirectory
    #>

    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory = $false, HelpMessage = 'Directory where the diagnostic bundle is saved.')]
        [ValidateScript({ Test-Path $_ -PathType Container })]
        [String] $OutputFolderPath = ([System.IO.Path]::GetTempPath()),

        [Parameter(Mandatory = $false, HelpMessage = 'Include full stack traces for every error in $Error.')]
        [Switch] $IncludeErrorDetails,

        [Parameter(Mandatory = $false, HelpMessage = 'Return the diagnostic object to the pipeline.')]
        [Switch] $PassThru
    )

    begin {
        Write-Verbose 'Get-AbrAdLog: Starting diagnostic collection.'
        $TimeStamp = Get-Date -Format 'yyyyMMdd_HHmmss'
        $FileName = "AbrAdDiagnostics_$TimeStamp.json"
        $OutputFile = Join-Path -Path $OutputFolderPath -ChildPath $FileName

        # Compute platform once; used throughout process block.
        # PS 5.1 (Desktop) lacks $PSVersionTable.Platform, so fall back to env/API.
        $IsWindowsPlatform = if ($PSVersionTable.ContainsKey('Platform') -and $PSVersionTable.Platform) {
            $PSVersionTable.Platform -eq 'Win32NT'
        } else {
            ($env:OS -eq 'Windows_NT') -or ([System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT)
        }

        $Platform = if ($PSVersionTable.ContainsKey('Platform') -and $PSVersionTable.Platform) {
            $PSVersionTable.Platform
        } elseif ($IsWindowsPlatform) {
            'Win32NT'
        } else {
            [System.Environment]::OSVersion.Platform.ToString()
        }
    }

    process {
        $Diag = [ordered] @{}

        # --- Collection timestamp -----------------------------------------------
        $Diag['CollectedAt'] = (Get-Date -Format 'o')

        # --- PowerShell session info --------------------------------------------
        try {
            $Diag['PowerShellSession'] = [ordered] @{
                PSVersion = $PSVersionTable.PSVersion.ToString()
                PSEdition = $PSVersionTable.PSEdition
                CLRVersion = if ($PSVersionTable.CLRVersion) { $PSVersionTable.CLRVersion.ToString() } else { 'N/A' }
                WSManStackVersion = if ($PSVersionTable.WSManStackVersion) { $PSVersionTable.WSManStackVersion.ToString() } else { 'N/A' }
                OS = $PSVersionTable.OS
                Platform = $Platform
                ExecutionPolicy = (Get-ExecutionPolicy -Scope Process).ToString()
                CurrentPrincipal = if ($IsWindowsPlatform) {
                    [Security.Principal.WindowsIdentity]::GetCurrent().Name
                } else {
                    $EnvUser = [System.Environment]::GetEnvironmentVariable('USER')
                    if ($EnvUser) { $EnvUser } else { [System.Environment]::GetEnvironmentVariable('LOGNAME') }
                }
                IsAdministrator = if ($IsWindowsPlatform) {
                    ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
                } else {
                    try { (& id -u).Trim() -eq '0' } catch { 'N/A' }
                }
                HostName = $Host.Name
                HostVersion = $Host.Version.ToString()
                PID = $PID
            }
        } catch {
            $Diag['PowerShellSession'] = "Error collecting PowerShell session info: $($_.Exception.Message)"
        }

        # --- Machine / OS info --------------------------------------------------
        if ($IsWindowsPlatform) {
            try {
                $OS = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
                $CS = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
                $CPU = Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop | Select-Object -First 1
                $Diag['Machine'] = [ordered] @{
                    ComputerName = $env:COMPUTERNAME
                    Domain = $CS.Domain
                    Manufacturer = $CS.Manufacturer
                    Model = $CS.Model
                    TotalMemoryGB = [math]::Round($CS.TotalPhysicalMemory / 1GB, 2)
                    OSCaption = $OS.Caption
                    OSVersion = $OS.Version
                    OSBuildNumber = $OS.BuildNumber
                    OSArchitecture = $OS.OSArchitecture
                    OSLastBootUpTime = $OS.LastBootUpTime.ToString('o')
                    CPUName = $CPU.Name
                    CPUCores = $CPU.NumberOfCores
                    CPULogicalProc = $CPU.NumberOfLogicalProcessors
                    TimeZone = (Get-TimeZone).DisplayName
                }
            } catch {
                $Diag['Machine'] = "Error collecting machine info: $($_.Exception.Message)"
            }
        } else {
            # Unix (Linux / macOS)
            try {
                $KernelName = try { (& uname -s).Trim() } catch { 'N/A' }
                $KernelRelease = try { (& uname -r).Trim() } catch { 'N/A' }
                $Architecture = try { (& uname -m).Trim() } catch { 'N/A' }
                $HostName = [System.Net.Dns]::GetHostName()
                $EnvUser = [System.Environment]::GetEnvironmentVariable('USER')
                $CurrentUser = if ($EnvUser) { $EnvUser } else { [System.Environment]::GetEnvironmentVariable('LOGNAME') }
                $IsRoot = try { (& id -u).Trim() -eq '0' } catch { 'N/A' }

                if ($KernelName -eq 'Linux') {
                    $OSDescription = try {
                        $Release = Get-Content '/etc/os-release' -ErrorAction Stop
                        ($Release | Where-Object { $_ -match '^PRETTY_NAME=' } | Select-Object -First 1) -replace '^PRETTY_NAME=|"', ''
                    } catch { 'N/A' }

                    $MemInfo = Get-Content '/proc/meminfo' -ErrorAction SilentlyContinue
                    $MemKB = ($MemInfo | Where-Object { $_ -match '^MemTotal:' } | Select-Object -First 1) -replace '\D', ''
                    $MemGB = if ($MemKB) { [math]::Round([long]$MemKB / 1MB, 2) } else { 'N/A' }

                    $CpuInfo = Get-Content '/proc/cpuinfo' -ErrorAction SilentlyContinue
                    $CpuName = ($CpuInfo | Where-Object { $_ -match '^model name' } | Select-Object -First 1) -replace '^model name\s*:\s*', ''
                    $CpuCores = ($CpuInfo | Where-Object { $_ -match '^cpu cores' } | Select-Object -First 1) -replace '\D', ''
                    $CpuLogical = ($CpuInfo | Where-Object { $_ -match '^processor' }).Count
                } elseif ($KernelName -eq 'Darwin') {
                    $OSDescription = try { "$(& sw_vers -productName) $(& sw_vers -productVersion)".Trim() } catch { 'N/A' }
                    $MemBytes = try { [long](& sysctl -n hw.memsize) } catch { $null }
                    $MemGB = if ($null -ne $MemBytes) { [math]::Round($MemBytes / 1GB, 2) } else { 'N/A' }
                    $CpuName = try { (& sysctl -n machdep.cpu.brand_string).Trim() } catch { 'N/A' }
                    $CpuCores = try { (& sysctl -n hw.physicalcpu).Trim() } catch { 'N/A' }
                    $CpuLogical = try { (& sysctl -n hw.logicalcpu).Trim() } catch { 'N/A' }
                } else {
                    $OSDescription = "Unknown Unix ($KernelName)"
                    $MemGB = $CpuName = $CpuCores = $CpuLogical = 'N/A'
                }

                $Diag['Machine'] = [ordered] @{
                    ComputerName = $HostName
                    CurrentUser = $CurrentUser
                    IsRoot = $IsRoot
                    KernelName = $KernelName
                    KernelRelease = $KernelRelease
                    OSDescription = $OSDescription
                    Architecture = $Architecture
                    TotalMemoryGB = $MemGB
                    CPUName = if ($CpuName) { $CpuName }    else { 'N/A' }
                    CPUCores = if ($CpuCores) { $CpuCores }   else { 'N/A' }
                    CPULogicalProc = if ($CpuLogical) { $CpuLogical } else { 'N/A' }
                    TimeZone = (Get-TimeZone).DisplayName
                }
            } catch {
                $Diag['Machine'] = "Error collecting machine info: $($_.Exception.Message)"
            }
        }

        # --- Relevant installed modules -----------------------------------------
        try {
            $RelevantModuleNames = @(
                'AsBuiltReport.Microsoft.AD',
                'AsBuiltReport.Core',
                'AsBuiltReport.Chart',
                'AsBuiltReport.Diagram',
                'PScribo'
            )
            $ModuleInfo = foreach ($ModName in $RelevantModuleNames) {
                $Mods = Get-Module -ListAvailable -Name $ModName -ErrorAction SilentlyContinue |
                Sort-Object -Property Version -Descending
                if ($Mods) {
                    foreach ($Mod in $Mods) {
                        [ordered] @{
                            Name = $Mod.Name
                            Version = $Mod.Version.ToString()
                            Path = $Mod.ModuleBase
                            Description = $Mod.Description
                        }
                    }
                } else {
                    [ordered] @{
                        Name = $ModName
                        Version = 'Not installed'
                        Path = $null
                        Description = $null
                    }
                }
            }
            $Diag['InstalledModules'] = @($ModuleInfo)
        } catch {
            $Diag['InstalledModules'] = "Error collecting module info: $($_.Exception.Message)"
        }

        # --- Currently loaded modules in session --------------------------------
        try {
            $Diag['LoadedModules'] = @(
                Get-Module | Sort-Object -Property Name | ForEach-Object {
                    [ordered] @{
                        Name = $_.Name
                        Version = $_.Version.ToString()
                        Path = $_.ModuleBase
                    }
                }
            )
        } catch {
            $Diag['LoadedModules'] = "Error collecting loaded modules: $($_.Exception.Message)"
        }

        # --- $Error variable collection -----------------------------------------
        try {
            $MaxErrors = if ($IncludeErrorDetails) { $global:Error.Count } else { [math]::Min(25, $global:Error.Count) }
            $ErrorCollection = for ($i = 0; $i -lt $MaxErrors; $i++) {
                $Err = $global:Error[$i]
                if ($null -eq $Err) { continue }
                $ErrObj = [ordered] @{
                    Index = $i
                    Message = $Err.Exception.Message
                    FullyQualifiedErrorId = $Err.FullyQualifiedErrorId
                    Type = $Err.Exception.GetType().FullName
                    Category = $Err.CategoryInfo.Category.ToString()
                    CategoryReason = $Err.CategoryInfo.Reason
                    TargetName = $Err.CategoryInfo.TargetName
                    ErrorDetails = if ($Err.ErrorDetails) { $Err.ErrorDetails.Message } else { $null }
                    ScriptName = $Err.InvocationInfo.ScriptName
                    LineNumber = $Err.InvocationInfo.ScriptLineNumber
                    Line = $Err.InvocationInfo.Line -replace '\s+', ' '
                    CommandName = $Err.InvocationInfo.MyCommand.Name
                }
                if ($IncludeErrorDetails) {
                    $ErrObj['StackTrace'] = $Err.Exception.StackTrace
                    # Build full inner exception chain
                    $InnerChain = [System.Collections.Generic.List[string]]::new()
                    $Inner = $Err.Exception.InnerException
                    while ($null -ne $Inner) {
                        $InnerChain.Add("[$($Inner.GetType().FullName)] $($Inner.Message)")
                        $Inner = $Inner.InnerException
                    }
                    $ErrObj['InnerExceptions'] = if ($InnerChain.Count -gt 0) { $InnerChain.ToArray() } else { $null }
                }
                $ErrObj
            }
            $Diag['ErrorLog'] = [ordered] @{
                TotalErrors = $global:Error.Count
                CapturedErrors = $MaxErrors
                FullDetails = $IncludeErrorDetails.IsPresent
                Errors = @($ErrorCollection)
            }
        } catch {
            $Diag['ErrorLog'] = "Error collecting `$Error log: $($_.Exception.Message)"
        }

        # --- Environment variables (safe subset) --------------------------------
        try {
            $SafeEnvVars = if ($IsWindowsPlatform) {
                @('COMPUTERNAME', 'USERNAME', 'USERDOMAIN', 'USERDNSDOMAIN',
                    'OS', 'PROCESSOR_ARCHITECTURE', 'NUMBER_OF_PROCESSORS',
                    'TEMP', 'TMP', 'APPDATA', 'LOCALAPPDATA', 'PSModulePath')
            } else {
                @('USER', 'LOGNAME', 'HOME', 'SHELL', 'HOSTNAME', 'TMPDIR', 'TEMP', 'TMP',
                    'XDG_DATA_HOME', 'XDG_CONFIG_HOME', 'PSModulePath')
            }
            $EnvInfo = [ordered] @{}
            foreach ($VarName in $SafeEnvVars) {
                $EnvInfo[$VarName] = [System.Environment]::GetEnvironmentVariable($VarName)
            }
            $Diag['EnvironmentVariables'] = $EnvInfo
        } catch {
            $Diag['EnvironmentVariables'] = "Error collecting environment variables: $($_.Exception.Message)"
        }

        # --- Write output file --------------------------------------------------
        $DiagObject = [pscustomobject] $Diag
        try {
            $DiagObject | ConvertTo-Json -Depth 10 | Set-Content -Path $OutputFile -Encoding UTF8 -Force
            Write-Host "  [Get-AbrAdLog] Diagnostic bundle saved to: $OutputFile" -ForegroundColor Green
        } catch {
            Write-Warning "Get-AbrAdLog: Failed to write diagnostic file '$OutputFile': $($_.Exception.Message)"
        }

        if ($PassThru) {
            $DiagObject
        }
    }

    end {
        Write-Verbose 'Get-AbrAdLog: Diagnostic collection complete.'
    }
}
