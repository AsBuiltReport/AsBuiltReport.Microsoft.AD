<#
.SYNOPSIS
    Invoke Pester tests for AsBuiltReport.Microsoft.AD module

.DESCRIPTION
    This script runs Pester tests with optional code coverage analysis.
    It's designed to work with CI/CD pipelines and local development.

.PARAMETER CodeCoverage
    Enable code coverage analysis

.PARAMETER OutputFormat
    Specify the output format for test results (Console, NUnitXml, JUnitXml)

.EXAMPLE
    .\Invoke-Tests.ps1

.EXAMPLE
    .\Invoke-Tests.ps1 -CodeCoverage -OutputFormat NUnitXml
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [switch]$CodeCoverage,

    [Parameter(Mandatory = $false)]
    [ValidateSet('Console', 'NUnitXml', 'JUnitXml')]
    [string]$OutputFormat = 'Console'
)

# Ensure we're in the Tests directory
$TestsPath = $PSScriptRoot
if (-not (Test-Path $TestsPath)) {
    Write-Error "Tests directory not found at: $TestsPath"
    exit 1
}

# Get the module root directory
$ModuleRoot = Split-Path -Path $TestsPath -Parent
$ModuleName = 'AsBuiltReport.Microsoft.AD'
$ModulePath = Join-Path -Path $ModuleRoot -ChildPath $ModuleName

Write-Host "Module Root: $ModuleRoot" -ForegroundColor Cyan
Write-Host "Module Path: $ModulePath" -ForegroundColor Cyan
Write-Host "Tests Path: $TestsPath" -ForegroundColor Cyan

# Check PowerShell version
$PSVersion = $PSVersionTable.PSVersion
Write-Host "PowerShell Version: $PSVersion" -ForegroundColor Cyan

if ($PSVersion.Major -lt 7) {
    Write-Warning "PowerShell 7 or higher is recommended for optimal test execution"
}

# Install required modules
Write-Host "`nInstalling required modules..." -ForegroundColor Yellow

$RequiredModules = @(
    @{ Name = 'Pester'; MinimumVersion = '5.0.0' }
    @{ Name = 'PScribo'; MinimumVersion = '0.11.1' }
    @{ Name = 'PSScriptAnalyzer'; MinimumVersion = '1.0.0' }
)

foreach ($Module in $RequiredModules) {
    $InstalledModule = Get-Module -Name $Module.Name -ListAvailable |
        Where-Object { $_.Version -ge [Version]$Module.MinimumVersion } |
        Sort-Object -Property Version -Descending |
        Select-Object -First 1

    if (-not $InstalledModule) {
        Write-Host "Installing $($Module.Name) (minimum version $($Module.MinimumVersion))..." -ForegroundColor Yellow
        Install-Module -Name $Module.Name -MinimumVersion $Module.MinimumVersion -Repository PSGallery -Force -AllowClobber -Scope CurrentUser
    } else {
        Write-Host "$($Module.Name) version $($InstalledModule.Version) is already installed" -ForegroundColor Green
    }
}

# Remove any pre-loaded Pester module (PowerShell 5.1 ships with old Pester 3.4.0)
Get-Module Pester | Remove-Module -Force -ErrorAction SilentlyContinue

# Import Pester with explicit minimum version
Import-Module Pester -MinimumVersion 5.0.0 -Force -ErrorAction Stop

# Configure Pester
$PesterConfiguration = New-PesterConfiguration

# Run settings
$PesterConfiguration.Run.Path = $TestsPath
$PesterConfiguration.Run.Exit = $false
$PesterConfiguration.Run.PassThru = $true

# Output settings
$PesterConfiguration.Output.Verbosity = 'Detailed'

# TestResult settings
if ($OutputFormat -ne 'Console') {
    $PesterConfiguration.TestResult.Enabled = $true
    $ResultFile = Join-Path -Path $TestsPath -ChildPath 'testResults.xml'
    $PesterConfiguration.TestResult.OutputPath = $ResultFile

    if ($OutputFormat -eq 'NUnitXml') {
        $PesterConfiguration.TestResult.OutputFormat = 'NUnitXml'
    } elseif ($OutputFormat -eq 'JUnitXml') {
        $PesterConfiguration.TestResult.OutputFormat = 'JUnitXml'
    }

    Write-Host "Test results will be saved to: $ResultFile" -ForegroundColor Cyan
}

# Code Coverage settings
if ($CodeCoverage) {
    Write-Host "`nEnabling code coverage analysis..." -ForegroundColor Yellow

    $PesterConfiguration.CodeCoverage.Enabled = $true
    $PesterConfiguration.CodeCoverage.OutputFormat = 'JaCoCo'
    $CoverageFile = Join-Path -Path $TestsPath -ChildPath 'coverage.xml'
    $PesterConfiguration.CodeCoverage.OutputPath = $CoverageFile

    # Include all PowerShell files in the module
    $CoverageFiles = @(
        "$ModulePath\*.psm1"
        "$ModulePath\Src\Public\*.ps1"
        "$ModulePath\Src\Private\*.ps1"
    )

    $PesterConfiguration.CodeCoverage.Path = $CoverageFiles

    Write-Host "Code coverage will be saved to: $CoverageFile" -ForegroundColor Cyan
    Write-Host "Coverage files included:" -ForegroundColor Cyan
    foreach ($File in $CoverageFiles) {
        Write-Host "  - $File" -ForegroundColor Gray
    }
}

# Run Pester tests
Write-Host "`nRunning Pester tests..." -ForegroundColor Yellow
Write-Host "======================================" -ForegroundColor Cyan

$TestResults = Invoke-Pester -Configuration $PesterConfiguration

# Display results
Write-Host "`n======================================" -ForegroundColor Cyan
Write-Host "Test Results Summary" -ForegroundColor Yellow
Write-Host "======================================" -ForegroundColor Cyan
Write-Host "Total Tests: $($TestResults.TotalCount)" -ForegroundColor White
Write-Host "Passed: $($TestResults.PassedCount)" -ForegroundColor Green
Write-Host "Failed: $($TestResults.FailedCount)" -ForegroundColor $(if ($TestResults.FailedCount -gt 0) { 'Red' } else { 'Green' })
Write-Host "Skipped: $($TestResults.SkippedCount)" -ForegroundColor Yellow
Write-Host "Duration: $($TestResults.Duration)" -ForegroundColor White

# Display failed tests
if ($TestResults.FailedCount -gt 0) {
    Write-Host "`nFailed Tests:" -ForegroundColor Red
    foreach ($FailedTest in $TestResults.Failed) {
        Write-Host "  - $($FailedTest.Name)" -ForegroundColor Red
        Write-Host "    $($FailedTest.ErrorRecord)" -ForegroundColor Gray
    }
}

# Display code coverage summary
if ($CodeCoverage -and $TestResults.CodeCoverage) {
    Write-Host "`n======================================" -ForegroundColor Cyan
    Write-Host "Code Coverage Summary" -ForegroundColor Yellow
    Write-Host "======================================" -ForegroundColor Cyan

    $Coverage = $TestResults.CodeCoverage

    if ($Coverage.NumberOfCommandsAnalyzed -gt 0) {
        $CoveragePercent = [math]::Round(($Coverage.NumberOfCommandsExecuted / $Coverage.NumberOfCommandsAnalyzed) * 100, 2)
    } else {
        $CoveragePercent = 0
        Write-Host "Warning: No commands were analyzed for code coverage" -ForegroundColor Yellow
    }

    Write-Host "Commands Analyzed: $($Coverage.NumberOfCommandsAnalyzed)" -ForegroundColor White
    Write-Host "Commands Executed: $($Coverage.NumberOfCommandsExecuted)" -ForegroundColor White
    Write-Host "Commands Missed: $($Coverage.NumberOfCommandsMissed)" -ForegroundColor White
    Write-Host "Coverage: $CoveragePercent%" -ForegroundColor $(if ($CoveragePercent -ge 80) { 'Green' } elseif ($CoveragePercent -ge 60) { 'Yellow' } else { 'Red' })

    # Code coverage threshold enforcement
    $MinimumCoverageThreshold = 50  # Minimum 50% code coverage
    if ($CoveragePercent -lt $MinimumCoverageThreshold) {
        Write-Host "`nWARNING: Code coverage ($CoveragePercent%) is below minimum threshold ($MinimumCoverageThreshold%)" -ForegroundColor Red
        Write-Host "Consider adding more tests to improve coverage" -ForegroundColor Yellow

        # Uncomment the line below to fail builds when coverage is too low
        # exit 1
    } else {
        Write-Host "`nCode coverage meets minimum threshold ($MinimumCoverageThreshold%)" -ForegroundColor Green
    }
}

Write-Host "`n======================================" -ForegroundColor Cyan

# Exit with appropriate code
if ($TestResults.FailedCount -gt 0) {
    Write-Host "Tests FAILED" -ForegroundColor Red
    exit 1
} else {
    Write-Host "All tests PASSED" -ForegroundColor Green
    exit 0
}
