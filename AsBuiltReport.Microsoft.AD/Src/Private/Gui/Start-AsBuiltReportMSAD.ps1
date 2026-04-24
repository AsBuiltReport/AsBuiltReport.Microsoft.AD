#Requires -RunAsAdministrator

using namespace GliderUI
using namespace GliderUI.Avalonia
using namespace GliderUI.Avalonia.Controls
using namespace GliderUI.Avalonia.Platform.Storage
using namespace GliderUI.Avalonia.Media

function Start-AsBuiltReportMSAD {
    <#
    .SYNOPSIS
        GUI launcher for AsBuiltReport.Microsoft.AD — runs entirely in PowerShell 7.
    .DESCRIPTION
        A PowerShell 7.4+ desktop GUI (GliderUI / Avalonia) that collects connection,
        output and report options, then generates the Microsoft AD As-Built Report by
        calling New-AsBuiltReport directly — no child PS5.1 process required.
    .NOTES
        Requirements:
            PowerShell 7.4+                       — to run this script
            GliderUI 0.2.0+  (auto-installed on first run) — Install-PSResource -Name GliderUI -Version 0.2.0 -Scope CurrentUser -TrustRepository
            AsBuiltReport.Core                    — Install-PSResource -Name AsBuiltReport.Core
            AsBuiltReport.Microsoft.AD            — Install-PSResource -Name AsBuiltReport.Microsoft.AD
    #>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Scope = 'Function')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '', Scope = 'Function')]

    [CmdletBinding()]
    param()

    if ($PSVersionTable.PSVersion.Major -lt 7 -or ($PSVersionTable.PSVersion.Major -eq 7 -and $PSVersionTable.PSVersion.Minor -lt 4)) {
        throw "Start-AsBuiltReportMSAD requires PowerShell 7.4+. Current version: $($PSVersionTable.PSVersion)"
    }

    # ── Bootstrap GliderUI ──────────────────────────────────────────────────────
    $requiredGliderUIVersion = [version]'0.2.0'

    if (-not (Get-Module -ListAvailable -Name GliderUI)) {
        Write-Host 'GliderUI not found — installing from PSGallery…' -ForegroundColor Cyan
        Install-PSResource -Name GliderUI -Version $requiredGliderUIVersion -Scope CurrentUser -TrustRepository
    }

    $gliderMod = Get-Module -ListAvailable -Name GliderUI |
        Sort-Object Version -Descending |
        Select-Object -First 1

    if ($null -eq $gliderMod -or $gliderMod.Version -lt $requiredGliderUIVersion) {
        $found = if ($null -eq $gliderMod) { 'not installed' } else { "v$($gliderMod.Version)" }
        Write-Error ("GliderUI v{0} or later is required (found: {1}).`nInstall with: Install-PSResource -Name GliderUI -Version {0} -Scope CurrentUser -TrustRepository`nThen restart PowerShell." -f $requiredGliderUIVersion, $found)
        return
    }

    Import-Module GliderUI -Force

    # Thread-safe store shared between the main runspace and the report runspace
    $syncHash = [Hashtable]::Synchronized(@{
            CancelRequested = $false
            IsBusy          = $false
        })

    # ── UI Helper Functions ─────────────────────────────────────────────────────
    function New-SectionTitle ([string]$Text) {
        $tb = [TextBlock]::new()
        $tb.Text = $Text
        $tb.FontSize = 13
        $tb.FontWeight = 'SemiBold'
        $tb.Margin = '0,18,0,6'
        return $tb
    }

    function New-FormRow ([string]$Label, $Control, [int]$LabelWidth = 185) {
        $row = [StackPanel]::new()
        $row.Orientation = 'Horizontal'
        $row.Spacing = 10
        $row.Margin = '0,3,0,3'

        $lbl = [TextBlock]::new()
        $lbl.Text = $Label
        $lbl.Width = $LabelWidth
        $lbl.VerticalAlignment = 'Center'
        $lbl.FontSize = 12

        $row.Children.Add($lbl)
        $row.Children.Add($Control)
        return $row
    }

    function New-InlineLabel ([string]$Text) {
        $tb = [TextBlock]::new()
        $tb.Text = $Text
        $tb.VerticalAlignment = 'Center'
        $tb.Margin = '8,0,0,0'
        $tb.FontSize = 12
        return $tb
    }

    # Wraps a password TextBox with an eye-toggle button.
    function New-PasswordRow ($PasswordTextBox) {
        $btn = [Button]::new()
        $btn.Content = '👁'
        $btn.Padding = '6,2,6,2'
        $btn.VerticalAlignment = 'Center'
        $btn.AddClick({
                if ($PasswordTextBox.PasswordChar -eq [char]0) {
                    $PasswordTextBox.PasswordChar = [char]'●'
                } else {
                    $PasswordTextBox.PasswordChar = [char]0
                }
            }.GetNewClosure())

        $row = [StackPanel]::new()
        $row.Orientation = 'Horizontal'
        $row.Spacing = 6
        $row.Children.Add($PasswordTextBox)
        $row.Children.Add($btn)
        return $row
    }

    function New-DrawerMenuItem ([string]$Title, [string]$IconGeometry, $Page, $NavigationPage) {
        $icon = [PathIcon]::new()
        $icon.Data = [Geometry]::Parse($IconGeometry)

        $textBlock = [TextBlock]::new()
        $textBlock.Text = $Title
        $textBlock.VerticalAlignment = 'Center'

        $panel = [StackPanel]::new()
        $panel.Orientation = 'Horizontal'
        $panel.Spacing = 8
        $panel.Children.Add($icon)
        $panel.Children.Add($textBlock)

        $button = [Button]::new()
        $button.HorizontalAlignment = 'Stretch'
        $button.Padding = 12
        $button.Background = [SolidColorBrush]::new([Colors]::Transparent, 1)
        $button.Content = $panel
        $button.AddClick({
                param($argumentList)
                $targetPage, $navPage = $argumentList
                $navPage.ReplaceAsync($targetPage) | Out-Null
            }, @($Page, $NavigationPage))
        return $button
    }

    # ── Connection Controls ─────────────────────────────────────────────────────
    $txtServer = [TextBox]::new()
    $txtServer.Width = 240
    $txtServer.Watermark = 'dc01.contoso.com'

    $txtUser = [TextBox]::new()
    $txtUser.Width = 200
    $txtUser.Watermark = 'DOMAIN\username or user@domain'

    $txtPass = [TextBox]::new()
    $txtPass.Width = 200
    $txtPass.Watermark = 'Password'
    try { $txtPass.PasswordChar = [char]'●' } catch { Out-Null }

    # ── Saved Connections ───────────────────────────────────────────────────────
    $savedConnPath = if ($IsWindows) {
        [System.IO.Path]::Combine($env:USERPROFILE, 'AsBuiltReport', 'MSAD-SavedConnections.json')
    } else {
        [System.IO.Path]::Combine($env:HOME, 'AsBuiltReport', 'MSAD-SavedConnections.json')
    }

    $loadSavedConns = {
        if (Test-Path $savedConnPath) {
            try {
                $raw = Get-Content -Path $savedConnPath -Raw -Encoding UTF8 | ConvertFrom-Json
                if ($null -eq $raw) { return @() }
                return @($raw)
            } catch { return @() }
        }
        return @()
    }.GetNewClosure()

    $saveSavedConns = {
        param ([array]$Connections)
        $dir = Split-Path $savedConnPath -Parent
        if (-not (Test-Path $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }
        if ($Connections.Count -eq 0) {
            '[]' | Set-Content -Path $savedConnPath -Encoding UTF8
        } else {
            $Connections | ConvertTo-Json -Depth 3 | Set-Content -Path $savedConnPath -Encoding UTF8
        }
    }.GetNewClosure()

    $cboSavedConn = [ComboBox]::new()
    $cboSavedConn.Width = 262

    $refreshSavedConnCombo = {
        $cboSavedConn.Items.Clear()
        foreach ($c in (& $loadSavedConns)) {
            $cboSavedConn.Items.Add("$($c.Server) ($($c.Username))") | Out-Null
        }
    }.GetNewClosure()
    & $refreshSavedConnCombo

    $cboSavedConn.AddSelectionChanged({
            $idx = $cboSavedConn.SelectedIndex
            if ($idx -lt 0) { return }
            $conns = & $loadSavedConns
            if ($idx -ge $conns.Count) { return }
            $sel = $conns[$idx]
            $txtServer.Text = $sel.Server
            $txtUser.Text = $sel.Username
            $txtPass.Text = ''
        })

    $btnSaveConn = [Button]::new()
    $btnSaveConn.Content = '💾 Save Connection'
    $btnSaveConn.AddClick({
            $srv = $txtServer.Text.Trim()
            $usr = $txtUser.Text.Trim()
            if ([string]::IsNullOrWhiteSpace($srv) -or [string]::IsNullOrWhiteSpace($usr)) {
                $syncHash.lblConfigStatus.Text = '⚠ Enter a Domain Controller FQDN and username before saving.'
                return
            }
            $conns = [System.Collections.ArrayList]@()
            foreach ($c in (& $loadSavedConns)) { $conns.Add($c) | Out-Null }
            $dup = $conns | Where-Object { $_.Server -eq $srv -and $_.Username -eq $usr }
            if (-not $dup) {
                $conns.Add([PSCustomObject]@{ Server = $srv; Username = $usr }) | Out-Null
                & $saveSavedConns -Connections @($conns)
                & $refreshSavedConnCombo
                $syncHash.lblConfigStatus.Text = "✅ Connection saved: $srv ($usr)"
            } else {
                $syncHash.lblConfigStatus.Text = "ℹ Connection already exists: $srv ($usr)"
            }
        })

    $btnDeleteConn = [Button]::new()
    $btnDeleteConn.Content = '🗑 Delete'
    $btnDeleteConn.AddClick({
            $idx = $cboSavedConn.SelectedIndex
            if ($idx -lt 0) {
                $syncHash.lblConfigStatus.Text = '⚠ Select a saved connection to delete.'
                return
            }
            $conns = [System.Collections.ArrayList]@()
            foreach ($c in (& $loadSavedConns)) { $conns.Add($c) | Out-Null }
            if ($idx -ge $conns.Count) { return }
            $removed = $conns[$idx]
            $conns.RemoveAt($idx)
            & $saveSavedConns -Connections @($conns)
            $cboSavedConn.SelectedIndex = -1
            & $refreshSavedConnCombo
            $syncHash.lblConfigStatus.Text = "🗑 Deleted: $($removed.Server) ($($removed.Username))"
        })

    $savedConnActionsRow = [StackPanel]::new()
    $savedConnActionsRow.Orientation = 'Horizontal'
    $savedConnActionsRow.Spacing = 6
    $savedConnActionsRow.Children.Add($btnSaveConn)
    $savedConnActionsRow.Children.Add($btnDeleteConn)

    # ── Output Controls ─────────────────────────────────────────────────────────
    $chkHTML = [CheckBox]::new(); $chkHTML.Content = 'HTML'; $chkHTML.IsChecked = $true
    $chkWord = [CheckBox]::new(); $chkWord.Content = 'Word'; $chkWord.IsChecked = $false
    $chkText = [CheckBox]::new(); $chkText.Content = 'Text'; $chkText.IsChecked = $false

    $fmtPanel = [StackPanel]::new()
    $fmtPanel.Orientation = 'Horizontal'
    $fmtPanel.Spacing = 20
    $fmtPanel.Children.Add($chkHTML)
    $fmtPanel.Children.Add($chkWord)
    $fmtPanel.Children.Add($chkText)

    $txtOutput = [TextBox]::new()
    $txtOutput.Width = 240
    $txtOutput.Text = if ($IsWindows) {
        [System.IO.Path]::Combine($env:USERPROFILE, 'Documents', 'AsBuiltReport')
    } else {
        [System.IO.Path]::Combine($env:HOME, 'AsBuiltReport')
    }

    $btnBrowse = [Button]::new()
    $btnBrowse.Content = 'Browse…'
    $btnBrowse.AddClick({
            try {
                $btnBrowse.IsEnabled = $false
                $storageProvider = [Window]::GetTopLevel($btnBrowse).StorageProvider
                if ($null -eq $storageProvider) {
                    Write-Host 'Storage provider not available.' -ForegroundColor Yellow
                    return
                }
                $options = [FolderPickerOpenOptions]::new()
                $options.Title = 'Select Output Folder Path'
                $folders = $storageProvider.OpenFolderPickerAsync($options).WaitForCompleted()
                if ($folders -and $folders.Count -gt 0) {
                    $txtOutput.Text = $folders[0].Path.LocalPath
                }
            } catch {
                Write-Host "Folder picker error: $_" -ForegroundColor Red
            } finally {
                $btnBrowse.IsEnabled = $true
            }
        })

    $outputPathRow = [StackPanel]::new()
    $outputPathRow.Orientation = 'Horizontal'
    $outputPathRow.Spacing = 8
    $outputPathRow.Children.Add($txtOutput)
    $outputPathRow.Children.Add($btnBrowse)

    $cboLang = [ComboBox]::new()
    $cboLang.Width = 100
    $cboLang.Items.Add('en-US') | Out-Null
    $cboLang.Items.Add('es-ES') | Out-Null
    $cboLang.SelectedIndex = 0

    # ── Report Name ─────────────────────────────────────────────────────────────
    $txtReportName = [TextBox]::new()
    $txtReportName.Width = 300
    $txtReportName.Text = 'Microsoft Active Directory As Built Report'
    $txtReportName.Watermark = 'Output filename (without extension)'

    # ── Options Controls ────────────────────────────────────────────────────────
    # Options matching AsBuiltReport.Microsoft.AD.json > Options
    $swDiagrams       = [ToggleSwitch]::new(); $swDiagrams.IsChecked = $true
    $swExportDiagrams = [ToggleSwitch]::new(); $swExportDiagrams.IsChecked = $true
    $swTimestamp= [ToggleSwitch]::new(); $swTimestamp.IsChecked = $false
    $swWinRMSSL       = [ToggleSwitch]::new(); $swWinRMSSL.IsChecked = $false
    $swWinRMFallback  = [ToggleSwitch]::new(); $swWinRMFallback.IsChecked = $true

    $cboDiagramTheme = [ComboBox]::new()
    $cboDiagramTheme.Width = 120
    @('White', 'Black', 'Neon') | ForEach-Object { $cboDiagramTheme.Items.Add($_) | Out-Null }
    $cboDiagramTheme.SelectedIndex = 0

    $cboPSDefaultAuth = [ComboBox]::new()
    $cboPSDefaultAuth.Width = 160
    @('Negotiate', 'Kerberos', 'NTLM', 'Default') | ForEach-Object { $cboPSDefaultAuth.Items.Add($_) | Out-Null }
    $cboPSDefaultAuth.SelectedIndex = 0

    # ── InfoLevel Controls — matching AsBuiltReport.Microsoft.AD.json > InfoLevel ─
    function New-LevelCombo {
        $cbo = [ComboBox]::new()
        $cbo.Width = 160
        @('0 - Off', '1 - Enabled', '2 - Adv Summary', '3 - Detailed') | ForEach-Object { $cbo.Items.Add($_) | Out-Null }
        $cbo.SelectedIndex = 1
        return $cbo
    }

    $cboLvlForest = New-LevelCombo; $cboLvlForest.SelectedIndex = 2   # default 2 per JSON
    $cboLvlDomain = New-LevelCombo; $cboLvlDomain.SelectedIndex = 2   # default 2 per JSON
    $cboLvlDNS    = New-LevelCombo; $cboLvlDNS.SelectedIndex = 1      # default 1 per JSON

    # ── Progress Bar & Log ──────────────────────────────────────────────────────
    $progressBar = [ProgressBar]::new()
    $progressBar.IsIndeterminate = $true
    $progressBar.IsVisible = $false
    $progressBar.Margin = '0,8,0,4'
    $syncHash.progressBar = $progressBar

    $txtLog = [TextBox]::new()
    $txtLog.IsReadOnly = $true
    $txtLog.AcceptsReturn = $true
    $txtLog.Height = 220
    $txtLog.FontSize = 16
    $txtLog.TextWrapping = 'Wrap'
    $txtLog.Watermark = 'Output log will appear here…'
    try { $txtLog.FontFamily = 'Consolas,Courier New,Monospace' } catch { Out-Null }
    $syncHash.txtLog = $txtLog

    $chkVerbose = [CheckBox]::new()
    $chkVerbose.Content = '🔍Verbose'
    $chkVerbose.IsChecked = $false
    $chkVerbose.HorizontalAlignment = 'Right'
    $chkVerbose.VerticalAlignment = 'Center'
    $chkVerbose.Margin = '0,0,8,0'
    $syncHash.chkVerbose = $chkVerbose

    # ── Action Buttons ──────────────────────────────────────────────────────────
    $btnCancel = [Button]::new()
    $btnCancel.Content = '✕ Cancel'
    $btnCancel.IsVisible = $false
    $btnCancel.Margin = '0,0,0,0'
    $btnCancel.AddClick({
            $syncHash.CancelRequested = $true
            $rps = $syncHash.reportPS
            if ($null -ne $rps) { $rps.Stop() }
        })
    $syncHash.btnCancel = $btnCancel

    $btnExportLog = [Button]::new()
    $btnExportLog.Content = '💾 Export Log'
    $btnExportLog.Margin = '0,0,0,0'
    $btnExportLog.AddClick({
            try {
                $btnExportLog.IsEnabled = $false
                $logText = $syncHash.txtLog.Text
                if ([string]::IsNullOrWhiteSpace($logText)) {
                    $syncHash.lblConfigStatus.Text = '⚠ Log is empty — nothing to export.'
                    return
                }
                $storageProvider = [Window]::GetTopLevel($btnExportLog).StorageProvider
                if ($null -eq $storageProvider) { return }
                $saveOpts = [FilePickerSaveOptions]::new()
                $saveOpts.Title = 'Export Output Log'
                $saveOpts.SuggestedFileName = "MSAD-AsBuiltReport-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
                $file = $storageProvider.SaveFilePickerAsync($saveOpts).WaitForCompleted()
                if ($null -ne $file) {
                    $logText | Set-Content -Path $file.Path.LocalPath -Encoding UTF8
                    $syncHash.lblConfigStatus.Text = "✅ Log exported: $(Split-Path $file.Path.LocalPath -Leaf)"
                }
            } catch {
                $syncHash.lblConfigStatus.Text = "❌ Log export failed: $_"
            } finally {
                $btnExportLog.IsEnabled = $true
            }
        })

    $btnGenerate = [Button]::new()
    $btnGenerate.Content = '▶ Generate Report'
    $btnGenerate.HorizontalAlignment = 'Stretch'
    $btnGenerate.HorizontalContentAlignment = 'Center'
    $btnGenerate.FontSize = 14
    $btnGenerate.FontWeight = 'SemiBold'
    $btnGenerate.Margin = '0,22,0,0'
    $btnGenerate.Classes.Add('accent')
    $syncHash.btnGenerate = $btnGenerate

    # ── Generate Callback ────────────────────────────────────────────────────────
    $generateCallback = [EventCallback]::new()
    $generateCallback.RunspaceMode = 'RunspacePoolAsyncUI'
    $generateCallback.DisabledControlsWhileProcessing = $btnGenerate

    $generateCallback.ArgumentList = @{
        SyncHash         = $syncHash
        Server           = $txtServer
        Username         = $txtUser
        Password         = $txtPass
        ReportName       = $txtReportName
        OutPath          = $txtOutput
        FmtHTML          = $chkHTML
        FmtWord          = $chkWord
        FmtText          = $chkText
        Lang             = $cboLang
        DiagramTheme     = $cboDiagramTheme
        PSDefaultAuth    = $cboPSDefaultAuth
        Diagrams         = $swDiagrams
        ExportDiagrams   = $swExportDiagrams
        Timestamp        = $swTimestamp
        WinRMSSL         = $swWinRMSSL
        WinRMFallback    = $swWinRMFallback
        LvlForest        = $cboLvlForest
        LvlDomain        = $cboLvlDomain
        LvlDNS           = $cboLvlDNS
        Verbose          = $chkVerbose
        # ConfigPath and AbrConfigPath are late-bound below after TextBox creation
    }

    $generateCallback.ScriptBlock = {
        param ($ui)

        $sh = $ui.SyncHash
        if ($sh.IsBusy) {
            $sh.lblConfigStatus.Text = '⚠ Another operation is already running. Please wait.'
            return
        }
        $sh.IsBusy = $true
        $sh.CancelRequested = $false
        $sh.progressBar.IsVisible = $true
        $sh.btnCancel.IsVisible = $true
        $sh.txtLog.Text = ''

        $verboseEnabled = $ui.Verbose.IsChecked -eq $true

        function Write-Logging ([string]$Msg, [string]$Level = '', [bool]$AddTimestamp = $false) {
            $ts = Get-Date -Format 'HH:mm:ss'
            if ($Level -eq '') {
                if ($AddTimestamp) {
                    $sh.txtLog.Text += "[$ts] $Msg`n"
                } else {
                    $sh.txtLog.Text += "$Msg`n"
                }
            } else {
                if ($AddTimestamp) {
                    $sh.txtLog.Text += "[$ts][$Level] $Msg`n"
                } else {
                    $sh.txtLog.Text += "[$Level] $Msg`n"
                }
            }
            $sh.txtLog.CaretIndex = $sh.txtLog.Text.Length
        }

        function Build-MSADConfigObject {
            param (
                [string]$ReportName,
                [string]$Lang,
                [string]$Theme,
                [bool]$EnableDiagrams,
                [bool]$ExportDiagrams,
                [string]$PSDefaultAuthentication,
                [bool]$WinRMSSL,
                [bool]$WinRMFallbackToNoSSL,
                [int]$LvlForest,
                [int]$LvlDomain,
                [int]$LvlDNS
            )
            return [ordered]@{
                Report      = [ordered]@{
                    Name                = $ReportName
                    Version             = '1.0'
                    Status              = 'Released'
                    Language            = $Lang
                    ShowCoverPageImage  = $true
                    ShowTableOfContents = $true
                    ShowHeaderFooter    = $true
                    ShowTableCaptions   = $true
                }
                Options     = [ordered]@{
                    ShowExecutionTime       = $false
                    ShowDefinitionInfo      = $false
                    PSDefaultAuthentication = $PSDefaultAuthentication
                    Exclude                 = [ordered]@{ Domains = @(); DCs = @() }
                    Include                 = [ordered]@{ Domains = @() }
                    WinRMSSL                = $WinRMSSL
                    WinRMFallbackToNoSSL    = $WinRMFallbackToNoSSL
                    WinRMSSLPort            = 5986
                    WinRMPort               = 5985
                    EnableDiagrams          = $EnableDiagrams
                    EnableDiagramDebug      = $false
                    DiagramTheme            = $Theme
                    DiagramObjDebug         = $false
                    DiagramWaterMark        = ''
                    DiagramType             = [ordered]@{
                        CertificateAuthority = $true
                        Forest               = $true
                        Replication          = $true
                        Sites                = $true
                        SitesInventory       = $true
                        Trusts               = $true
                    }
                    ExportDiagrams          = $ExportDiagrams
                    ExportDiagramsFormat    = @('pdf')
                    EnableDiagramSignature  = $false
                    SignatureAuthorName     = ''
                    SignatureCompanyName    = ''
                    JobsTimeOut             = 900
                    DCStatusPingCount       = 2
                }
                InfoLevel   = [ordered]@{
                    Forest = $LvlForest
                    Domain = $LvlDomain
                    DNS    = $LvlDNS
                }
                HealthCheck = [ordered]@{
                    Domain           = [ordered]@{
                        GMSA            = $true
                        GPO             = $true
                        Backup          = $true
                        DFS             = $true
                        SPN             = $true
                        DuplicateObject = $true
                        Security        = $true
                        BestPractice    = $true
                    }
                    DomainController = [ordered]@{
                        Diagnostic   = $true
                        Services     = $true
                        Software     = $true
                        BestPractice = $true
                    }
                    Site             = [ordered]@{
                        Replication  = $true
                        BestPractice = $true
                    }
                    DNS              = [ordered]@{
                        Aging        = $true
                        DP           = $true
                        Zones        = $true
                        BestPractice = $true
                    }
                    CA               = [ordered]@{
                        Status       = $true
                        Statistics   = $true
                        BestPractice = $true
                    }
                }
            }
        }

        # ── Collect values ────────────────────────────────────────────────────────
        $server       = $ui.Server.Text.Trim()
        $username     = $ui.Username.Text.Trim()
        $password     = $ui.Password.Text
        $reportName   = $ui.ReportName.Text.Trim()
        $outPath      = $ui.OutPath.Text.Trim()
        $lang         = [string]$ui.Lang.SelectedItem
        $configPath   = $ui.ConfigPath.Text.Trim()
        $abrConfigPath = $ui.AbrConfigPath.Text.Trim()

        $formats = @()
        if ($ui.FmtHTML.IsChecked -eq $true) { $formats += 'Html' }
        if ($ui.FmtWord.IsChecked -eq $true) { $formats += 'Word' }
        if ($ui.FmtText.IsChecked -eq $true) { $formats += 'Text' }
        if ($formats.Count -eq 0) { $formats = @('Html') }

        $enableDiagrams   = [bool]$ui.Diagrams.IsChecked
        $exportDiagrams   = [bool]$ui.ExportDiagrams.IsChecked
        $addTimestamp     = [bool]$ui.Timestamp.IsChecked
        $winRMSSL         = [bool]$ui.WinRMSSL.IsChecked
        $winRMFallback    = [bool]$ui.WinRMFallback.IsChecked
        $psDefaultAuth    = [string]$ui.PSDefaultAuth.SelectedItem
        $diagramTheme     = [string]$ui.DiagramTheme.SelectedItem

        # Parse InfoLevel (first char = number)
        $lvlForest = [int]([string]$ui.LvlForest.SelectedItem).Substring(0, 1)
        $lvlDomain = [int]([string]$ui.LvlDomain.SelectedItem).Substring(0, 1)
        $lvlDNS    = [int]([string]$ui.LvlDNS.SelectedItem).Substring(0, 1)

        # ── Validation ────────────────────────────────────────────────────────────
        if ([string]::IsNullOrWhiteSpace($server)) {
            Write-Logging 'Domain Controller FQDN is required.' 'ERROR'
            $sh.progressBar.IsVisible = $false; $sh.btnCancel.IsVisible = $false; $sh.IsBusy = $false; return
        }
        if ([string]::IsNullOrWhiteSpace($username)) {
            Write-Logging 'Username is required.' 'ERROR'
            $sh.progressBar.IsVisible = $false; $sh.btnCancel.IsVisible = $false; $sh.IsBusy = $false; return
        }
        if ([string]::IsNullOrWhiteSpace($password)) {
            Write-Logging 'Password is required.' 'ERROR'
            $sh.progressBar.IsVisible = $false; $sh.btnCancel.IsVisible = $false; $sh.IsBusy = $false; return
        }
        if ([string]::IsNullOrWhiteSpace($outPath)) {
            $outPath = if ($IsWindows) {
                [System.IO.Path]::Combine($env:USERPROFILE, 'Documents', 'AsBuiltReport')
            } else {
                [System.IO.Path]::Combine($env:HOME, 'AsBuiltReport')
            }
        }
        if (-not (Test-Path $outPath)) {
            New-Item -Path $outPath -ItemType Directory -Force | Out-Null
            Write-Logging "Created output folder: $outPath"
        }
        if ([string]::IsNullOrWhiteSpace($reportName)) { $reportName = 'Microsoft Active Directory As Built Report' }
        if ([string]::IsNullOrWhiteSpace($abrConfigPath)) {
            Write-Logging 'AsBuiltReport config file path is required. Use the "⚙️ AsBuiltReport Global Settings" expander to create one.' 'ERROR'
            $sh.progressBar.IsVisible = $false; $sh.btnCancel.IsVisible = $false; $sh.IsBusy = $false; return
        }
        if (-not (Test-Path $abrConfigPath)) {
            Write-Logging "AsBuiltReport config file not found: $abrConfigPath" 'ERROR'
            $sh.progressBar.IsVisible = $false; $sh.btnCancel.IsVisible = $false; $sh.IsBusy = $false; return
        }

        Write-Logging "Target  : $server"
        Write-Logging "User    : $username"
        Write-Logging "Formats : $($formats -join ', ')"
        Write-Logging "Output  : $outPath"

        # ── Import modules in this runspace ───────────────────────────────────────
        Write-Logging 'Loading AsBuiltReport modules…'
        try {
            Import-Module AsBuiltReport.Core, AsBuiltReport.Microsoft.AD -Force -ErrorAction Stop
        } catch {
            Write-Logging "Failed to load modules: $_" 'ERROR'
            $sh.progressBar.IsVisible = $false; $sh.btnCancel.IsVisible = $false; $sh.IsBusy = $false; return
        }

        # ── Resolve ReportConfigFilePath ──────────────────────────────────────────
        # Use the saved config file from Config Management if provided;
        # otherwise build a temp config from the current UI control values.
        $tempConfig = $null
        if (-not [string]::IsNullOrWhiteSpace($configPath) -and (Test-Path $configPath)) {
            $reportConfigFilePath = $configPath
            Write-Logging "Using config file: $(Split-Path $configPath -Leaf)"
        } else {
            $configObj = Build-MSADConfigObject `
                -ReportName $reportName `
                -Lang $lang `
                -Theme $diagramTheme `
                -EnableDiagrams $enableDiagrams `
                -ExportDiagrams $exportDiagrams `
                -PSDefaultAuthentication $psDefaultAuth `
                -WinRMSSL $winRMSSL `
                -WinRMFallbackToNoSSL $winRMFallback `
                -LvlForest $lvlForest `
                -LvlDomain $lvlDomain `
                -LvlDNS $lvlDNS

            $tempConfig = [System.IO.Path]::Combine($env:TEMP, "MSAD_cfg_$(New-Guid).json")
            $configObj | ConvertTo-Json -Depth 6 | Set-Content -Path $tempConfig -Encoding UTF8
            $reportConfigFilePath = $tempConfig
            Write-Logging 'Using config built from UI controls.'
        }

        # ── Invoke New-AsBuiltReport ──────────────────────────────────────────────
        try {
            if ($sh.CancelRequested) { Write-Logging 'Cancelled before start.' 'WARN'; return }

            Write-Logging 'Starting report generation…'

            $securePassword = ConvertTo-SecureString $password -AsPlainText -Force
            $credential = [PSCredential]::new($username, $securePassword)

            $params = @{
                Report               = 'Microsoft.AD'
                Target               = $server
                Credential           = $credential
                OutputFolderPath     = $outPath
                Format               = $formats
                ReportConfigFilePath = $reportConfigFilePath
                AsBuiltConfigFilePath = $abrConfigPath
            }

            if ($addTimestamp) { $params['Timestamp'] = $true }
            if ($verboseEnabled) { $params['Verbose'] = $true }

            Write-Logging "Using AsBuiltReport config: $(Split-Path $abrConfigPath -Leaf)"

            New-AsBuiltReport @params *>&1 | ForEach-Object {
                $line = if ($_ -is [System.Management.Automation.ErrorRecord]) {
                    Write-Logging "$($_.Exception.Message)" 'ERROR'
                    return
                } elseif ($_ -is [System.Management.Automation.WarningRecord]) {
                    Write-Logging "$($_.Message)" 'WARN'
                    return
                } elseif ($_ -is [System.Management.Automation.VerboseRecord]) {
                    if ($verboseEnabled) {
                        Write-Logging "$($_.Message)" 'VERBOSE'
                    }
                    return
                } elseif ($_ -is [System.Management.Automation.InformationRecord]) {
                    "$($_.MessageData)"
                } else {
                    "$_"
                }
                if (-not [string]::IsNullOrWhiteSpace($line)) {
                    Write-Logging $line
                }
            }
            Write-Logging -Msg "✅ Report generation completed. Files saved to: $outPath" -Level '' -AddTimestamp $true
        } catch {
            Write-Logging $_.Exception.Message 'ERROR'
            if ($_.ScriptStackTrace) { Write-Logging $_.ScriptStackTrace 'ERROR' }
        } finally {
            if ($null -ne $tempConfig) {
                Remove-Item -Path $tempConfig -Force -ErrorAction SilentlyContinue
            }
            $sh.progressBar.IsVisible = $false
            $sh.btnCancel.IsVisible = $false
            $sh.IsBusy = $false
        }
    }

    $btnGenerate.AddClick($generateCallback)

    # ── Config Management Controls ───────────────────────────────────────────────
    $txtConfigPath = [TextBox]::new()
    $txtConfigPath.Width = 298
    $txtConfigPath.Watermark = 'Path to AsBuiltReport.Microsoft.AD.json (optional)'
    $txtConfigPath.Text = if ($IsWindows) {
        [System.IO.Path]::Combine($env:USERPROFILE, 'AsBuiltReport', 'AsBuiltReport.Microsoft.AD.json')
    } else {
        [System.IO.Path]::Combine($env:HOME, 'AsBuiltReport', 'AsBuiltReport.Microsoft.AD.json')
    }

    $btnBrowseConfig = [Button]::new()
    $btnBrowseConfig.Content = 'Browse…'
    $btnBrowseConfig.AddClick({
            try {
                $btnBrowseConfig.IsEnabled = $false
                $storageProvider = [Window]::GetTopLevel($btnBrowseConfig).StorageProvider
                if ($null -eq $storageProvider) {
                    Write-Host 'Storage provider not available.' -ForegroundColor Yellow
                    return
                }
                $options = [FilePickerOpenOptions]::new()
                $options.Title = 'Select AsBuiltReport.Microsoft.AD JSON Config File'
                $JsonConfigFile = $storageProvider.OpenFilePickerAsync($options).WaitForCompleted()
                if ($JsonConfigFile -and $JsonConfigFile.Count -gt 0) {
                    $txtConfigPath.Text = $JsonConfigFile[0].Path.LocalPath
                }
            } catch {
                Write-Host "File picker error: $_" -ForegroundColor Red
            } finally {
                $btnBrowseConfig.IsEnabled = $true
            }
        })

    $configPathRow = [StackPanel]::new()
    $configPathRow.Orientation = 'Horizontal'
    $configPathRow.Spacing = 8
    $configPathRow.Children.Add($txtConfigPath)
    $configPathRow.Children.Add($btnBrowseConfig)

    $lblConfigStatus = [TextBlock]::new()
    $lblConfigStatus.FontSize = 11
    $lblConfigStatus.Margin = '0,4,0,0'
    $lblConfigStatus.Text = ''
    $syncHash.lblConfigStatus = $lblConfigStatus

    # ── AsBuiltReport Global Config (AsBuiltReport.json) ─────────────────────────
    $txtAbrConfigPath = [TextBox]::new()
    $txtAbrConfigPath.Width = 298
    $txtAbrConfigPath.Watermark = 'Required: path to AsBuiltReport.json'

    $btnBrowseAbrConfig = [Button]::new()
    $btnBrowseAbrConfig.Content = 'Browse…'
    $btnBrowseAbrConfig.AddClick({
            try {
                $btnBrowseAbrConfig.IsEnabled = $false
                $storageProvider = [Window]::GetTopLevel($btnBrowseAbrConfig).StorageProvider
                if ($null -eq $storageProvider) { return }
                $options = [FilePickerOpenOptions]::new()
                $options.Title = 'Select AsBuiltReport.json'
                $options.AllowMultiple = $false
                $picked = $storageProvider.OpenFilePickerAsync($options).WaitForCompleted()
                if ($picked -and $picked.Count -gt 0) {
                    $txtAbrConfigPath.Text = $picked[0].Path.LocalPath
                    $syncHash.lblConfigStatus.Text = "📄 AsBuiltReport config: $(Split-Path $txtAbrConfigPath.Text -Leaf)"
                }
            } catch {
                $syncHash.lblConfigStatus.Text = "❌ Browse error: $_"
            } finally {
                $btnBrowseAbrConfig.IsEnabled = $true
            }
        })

    $abrConfigPathRow = [StackPanel]::new()
    $abrConfigPathRow.Orientation = 'Horizontal'
    $abrConfigPathRow.Spacing = 8
    $abrConfigPathRow.Children.Add($txtAbrConfigPath)
    $abrConfigPathRow.Children.Add($btnBrowseAbrConfig)

    # Late-bind after TextBox objects exist
    $generateCallback.ArgumentList['ConfigPath']    = $txtConfigPath
    $generateCallback.ArgumentList['AbrConfigPath'] = $txtAbrConfigPath

    # ── AsBuiltReport Global Settings (AsBuiltReport.json editor) ────────────────
    $txtAbrCoFullName  = [TextBox]::new(); $txtAbrCoFullName.Width = 298;  $txtAbrCoFullName.Watermark = 'e.g. Acme Corporation'
    $txtAbrCoShortName = [TextBox]::new(); $txtAbrCoShortName.Width = 298; $txtAbrCoShortName.Watermark = 'e.g. ACME'
    $txtAbrCoContact   = [TextBox]::new(); $txtAbrCoContact.Width = 298;   $txtAbrCoContact.Watermark = 'Contact person'
    $txtAbrCoPhone     = [TextBox]::new(); $txtAbrCoPhone.Width = 298;     $txtAbrCoPhone.Watermark = 'e.g. +1-800-555-0100'
    $txtAbrCoAddress   = [TextBox]::new(); $txtAbrCoAddress.Width = 298;   $txtAbrCoAddress.Watermark = 'Street, City, Country'
    $txtAbrCoEmail     = [TextBox]::new(); $txtAbrCoEmail.Width = 298;     $txtAbrCoEmail.Watermark = 'company@example.com'
    $txtAbrRptAuthor   = [TextBox]::new(); $txtAbrRptAuthor.Width = 298;   $txtAbrRptAuthor.Watermark = 'Report author'
    $txtAbrMailServer  = [TextBox]::new(); $txtAbrMailServer.Width = 298;  $txtAbrMailServer.Watermark = 'smtp.example.com'
    $txtAbrMailPort    = [TextBox]::new(); $txtAbrMailPort.Width = 298;    $txtAbrMailPort.Watermark = '587'
    $txtAbrMailFrom    = [TextBox]::new(); $txtAbrMailFrom.Width = 298;    $txtAbrMailFrom.Watermark = 'from@example.com'
    $txtAbrMailTo      = [TextBox]::new(); $txtAbrMailTo.Width = 298;      $txtAbrMailTo.Watermark = 'to@example.com, other@example.com'
    $txtAbrMailBody    = [TextBox]::new(); $txtAbrMailBody.Width = 298;    $txtAbrMailBody.Watermark = 'Email body text'
    $swAbrMailUseSSL   = [ToggleSwitch]::new(); $swAbrMailUseSSL.IsChecked = $true
    $swAbrMailCreds    = [ToggleSwitch]::new(); $swAbrMailCreds.IsChecked = $true
    $txtAbrFolderPath  = [TextBox]::new(); $txtAbrFolderPath.Width = 298;  $txtAbrFolderPath.Watermark = '.\AsBuiltReport'

    $loadAbrFields = {
        param ([hashtable]$j)
        $txtAbrCoFullName.Text  = if ($j.Company.FullName)    { $j.Company.FullName }    else { '' }
        $txtAbrCoShortName.Text = if ($j.Company.ShortName)   { $j.Company.ShortName }   else { '' }
        $txtAbrCoContact.Text   = if ($j.Company.Contact)     { $j.Company.Contact }     else { '' }
        $txtAbrCoPhone.Text     = if ($j.Company.Phone)       { $j.Company.Phone }       else { '' }
        $txtAbrCoAddress.Text   = if ($j.Company.Address)     { $j.Company.Address }     else { '' }
        $txtAbrCoEmail.Text     = if ($j.Company.Email)       { $j.Company.Email }       else { '' }
        $txtAbrRptAuthor.Text   = if ($j.Report.Author)       { $j.Report.Author }       else { '' }
        $txtAbrMailServer.Text  = if ($j.Email.Server)        { $j.Email.Server }        else { '' }
        $txtAbrMailPort.Text    = if ($j.Email.Port)          { $j.Email.Port }          else { '' }
        $txtAbrMailFrom.Text    = if ($j.Email.From)          { $j.Email.From }          else { '' }
        $txtAbrMailTo.Text      = if ($j.Email.To)            { ($j.Email.To -join ', ') } else { '' }
        $txtAbrMailBody.Text    = if ($j.Email.Body)          { $j.Email.Body }          else { '' }
        $swAbrMailUseSSL.IsChecked  = if ($null -ne $j.Email.UseSSL)      { [bool]$j.Email.UseSSL }      else { $true }
        $swAbrMailCreds.IsChecked   = if ($null -ne $j.Email.Credentials) { [bool]$j.Email.Credentials } else { $true }
        $txtAbrFolderPath.Text  = if ($j.UserFolder.Path) { $j.UserFolder.Path } else {
            if ($IsWindows) { [System.IO.Path]::Combine($env:USERPROFILE, 'Documents', 'AsBuiltReport') } else { [System.IO.Path]::Combine($env:HOME, 'AsBuiltReport') }
        }
    }

    $buildAbrConfig = {
        $toList  = ([string]$txtAbrMailTo.Text).Trim() -split '\s*,\s*' | Where-Object { $_ -ne '' }
        $portRaw = ([string]$txtAbrMailPort.Text).Trim()
        $portVal = if ($portRaw -match '^\d+$') { [int]$portRaw } else { $null }
        return [ordered]@{
            Company    = [ordered]@{
                FullName  = ([string]$txtAbrCoFullName.Text).Trim()
                Phone     = ([string]$txtAbrCoPhone.Text).Trim()
                Address   = ([string]$txtAbrCoAddress.Text).Trim()
                ShortName = ([string]$txtAbrCoShortName.Text).Trim()
                Contact   = ([string]$txtAbrCoContact.Text).Trim()
                Email     = ([string]$txtAbrCoEmail.Text).Trim()
            }
            Email      = [ordered]@{
                Credentials = [bool]$swAbrMailCreds.IsChecked
                Body        = ([string]$txtAbrMailBody.Text).Trim()
                From        = ([string]$txtAbrMailFrom.Text).Trim()
                UseSSL      = [bool]$swAbrMailUseSSL.IsChecked
                Server      = ([string]$txtAbrMailServer.Text).Trim()
                To          = if ($toList.Count -gt 0) { @($toList) } else { @() }
                Port        = $portVal
            }
            Report     = [ordered]@{ Author = ([string]$txtAbrRptAuthor.Text).Trim() }
            UserFolder = [ordered]@{ Path = ([string]$txtAbrFolderPath.Text).Trim() }
        }
    }.GetNewClosure()
    $syncHash.buildAbrConfig = $buildAbrConfig

    $validateAbrRequired = {
        $missing = @()
        if ([string]::IsNullOrWhiteSpace($txtAbrCoFullName.Text))  { $missing += 'Full Name' }
        if ([string]::IsNullOrWhiteSpace($txtAbrCoShortName.Text)) { $missing += 'Short Name' }
        if ([string]::IsNullOrWhiteSpace($txtAbrCoContact.Text))   { $missing += 'Contact' }
        if ([string]::IsNullOrWhiteSpace($txtAbrCoEmail.Text))     { $missing += 'Email' }
        if ([string]::IsNullOrWhiteSpace($txtAbrRptAuthor.Text))   { $missing += 'Author' }
        if ([string]::IsNullOrWhiteSpace($txtAbrFolderPath.Text))  { $missing += 'Path' }
        if ($missing.Count -gt 0) {
            return "⚠ Required fields missing: $($missing -join ', ')"
        }
        return $null
    }.GetNewClosure()
    $syncHash.validateAbrRequired = $validateAbrRequired

    $btnAbrNew = [Button]::new()
    $btnAbrNew.Content = '🆕 Create New'
    $btnAbrNew.Margin = '0,0,8,0'
    $btnAbrNew.AddClick({
            try {
                $btnAbrNew.IsEnabled = $false
                $storageProvider = [Window]::GetTopLevel($btnAbrNew).StorageProvider
                if ($null -eq $storageProvider) {
                    $syncHash.lblConfigStatus.Text = '⚠ Cannot open save dialog.'
                    return
                }
                $saveOpts = [FilePickerSaveOptions]::new()
                $saveOpts.Title = 'Create New AsBuiltReport Config File'
                $saveOpts.SuggestedFileName = 'AsBuiltReport.json'
                $saveOpts.DefaultExtension = 'json'
                $file = $storageProvider.SaveFilePickerAsync($saveOpts).WaitForCompleted()
                if ($null -eq $file) { return }
                if ($null -eq $file.Path) {
                    $syncHash.lblConfigStatus.Text = '⚠ Could not resolve file path from dialog.'
                    return
                }
                $validationError = & $syncHash.validateAbrRequired
                if ($null -ne $validationError) {
                    $syncHash.lblConfigStatus.Text = $validationError
                    return
                }
                $dest = $file.Path.LocalPath
                $cfg = & $syncHash.buildAbrConfig
                $destDir = Split-Path $dest -Parent
                if (-not (Test-Path $destDir)) { New-Item -Path $destDir -ItemType Directory -Force | Out-Null }
                $cfg | ConvertTo-Json -Depth 4 | Set-Content -Path $dest -Encoding UTF8
                $txtAbrConfigPath.Text = $dest
                $syncHash.lblConfigStatus.Text = "✅ Created: $(Split-Path $dest -Leaf)"
            } catch {
                $syncHash.lblConfigStatus.Text = "❌ Create failed: $_"
            } finally {
                $btnAbrNew.IsEnabled = $true
            }
        })

    $btnAbrLoad = [Button]::new()
    $btnAbrLoad.Content = '📂 Load from File'
    $btnAbrLoad.Margin = '0,0,8,0'
    $btnAbrLoad.AddClick({
            try {
                $btnAbrLoad.IsEnabled = $false
                $src = if ($txtAbrConfigPath.Text) { $txtAbrConfigPath.Text.Trim() } else { '' }
                if ([string]::IsNullOrWhiteSpace($src) -or -not (Test-Path $src)) {
                    $syncHash.lblConfigStatus.Text = '⚠ Set a valid AsBuiltReport.json path first.'
                    return
                }
                $j = Get-Content -Path $src -Raw | ConvertFrom-Json -AsHashtable
                & $loadAbrFields $j
                $syncHash.lblConfigStatus.Text = "✅ Loaded: $(Split-Path $src -Leaf)"
            } catch {
                $syncHash.lblConfigStatus.Text = "❌ Load failed: $_"
            } finally {
                $btnAbrLoad.IsEnabled = $true
            }
        })

    $btnAbrSave = [Button]::new()
    $btnAbrSave.Content = '💾 Save to File'
    $btnAbrSave.AddClick({
            try {
                $btnAbrSave.IsEnabled = $false
                $validationError = & $syncHash.validateAbrRequired
                if ($null -ne $validationError) {
                    $syncHash.lblConfigStatus.Text = $validationError
                    return
                }
                if ([string]::IsNullOrWhiteSpace($txtAbrConfigPath.Text)) {
                    $syncHash.lblConfigStatus.Text = '❌ Please provide a config file path before saving.'
                    return
                }
                $dest = $txtAbrConfigPath.Text.Trim()
                $cfg = & $syncHash.buildAbrConfig
                $destDir = Split-Path $dest -Parent
                if (-not (Test-Path $destDir)) { New-Item -Path $destDir -ItemType Directory -Force | Out-Null }
                $cfg | ConvertTo-Json -Depth 4 | Set-Content -Path $dest -Encoding UTF8
                $syncHash.lblConfigStatus.Text = "✅ Saved: $(Split-Path $dest -Leaf)"
            } catch {
                $syncHash.lblConfigStatus.Text = "❌ Save failed: $_"
            } finally {
                $btnAbrSave.IsEnabled = $true
            }
        })

    $abrActionRow = [StackPanel]::new()
    $abrActionRow.Orientation = 'Horizontal'
    $abrActionRow.Margin = '0,10,0,0'
    $abrActionRow.Children.Add($btnAbrNew)
    $abrActionRow.Children.Add($btnAbrLoad)
    $abrActionRow.Children.Add($btnAbrSave)

    $abrRequiredNote = [TextBlock]::new()
    $abrRequiredNote.Text = '* Required'
    $abrRequiredNote.FontSize = 12
    $abrRequiredNote.Margin = '0,0,0,8'
    $abrRequiredNote.TextAlignment = 'Right'

    $abrInnerPanel = [StackPanel]::new()
    $abrInnerPanel.Spacing = 2
    $abrInnerPanel.Margin = '4,4,4,8'
    $abrInnerPanel.Children.Add($abrRequiredNote)
    $abrInnerPanel.Children.Add((New-SectionTitle '🏢 Company'))
    $abrInnerPanel.Children.Add((New-FormRow -Label '* Full Name' -Control $txtAbrCoFullName))
    $abrInnerPanel.Children.Add((New-FormRow -Label '* Short Name' -Control $txtAbrCoShortName))
    $abrInnerPanel.Children.Add((New-FormRow -Label '* Contact' -Control $txtAbrCoContact))
    $abrInnerPanel.Children.Add((New-FormRow -Label 'Phone' -Control $txtAbrCoPhone))
    $abrInnerPanel.Children.Add((New-FormRow -Label 'Address' -Control $txtAbrCoAddress))
    $abrInnerPanel.Children.Add((New-FormRow -Label '* Email' -Control $txtAbrCoEmail))
    $abrInnerPanel.Children.Add((New-SectionTitle '📝 Report'))
    $abrInnerPanel.Children.Add((New-FormRow -Label '* Author' -Control $txtAbrRptAuthor))
    $abrInnerPanel.Children.Add((New-SectionTitle '📧 Email'))
    $abrInnerPanel.Children.Add((New-FormRow -Label 'SMTP Server' -Control $txtAbrMailServer))
    $abrInnerPanel.Children.Add((New-FormRow -Label 'Port' -Control $txtAbrMailPort))
    $abrInnerPanel.Children.Add((New-FormRow -Label 'From' -Control $txtAbrMailFrom))
    $abrInnerPanel.Children.Add((New-FormRow -Label 'To (comma-sep.)' -Control $txtAbrMailTo))
    $abrInnerPanel.Children.Add((New-FormRow -Label 'Body' -Control $txtAbrMailBody))
    $abrInnerPanel.Children.Add((New-FormRow -Label 'Use SSL' -Control $swAbrMailUseSSL))
    $abrInnerPanel.Children.Add((New-FormRow -Label 'Credentials' -Control $swAbrMailCreds))
    $abrInnerPanel.Children.Add((New-SectionTitle '📁 User Folder'))
    $abrInnerPanel.Children.Add((New-FormRow -Label '* Path' -Control $txtAbrFolderPath))
    $abrInnerPanel.Children.Add($abrActionRow)

    $abrExpander = [Expander]::new()
    $abrExpander.Header = '⚙️ AsBuiltReport Global Settings'
    $abrExpander.IsExpanded = $false
    $abrExpander.Margin = '0,8,0,0'
    $abrExpander.Content = $abrInnerPanel

    # ── Save Config Button ─────────────────────────────────────────────────────
    function Build-MSADConfigForSave {
        param (
            [string]$ReportName, [string]$Lang, [string]$Theme,
            [bool]$EnableDiagrams, [bool]$ExportDiagrams,
            [string]$PSDefaultAuthentication, [bool]$WinRMSSL, [bool]$WinRMFallbackToNoSSL,
            [int]$LvlForest, [int]$LvlDomain, [int]$LvlDNS
        )
        return [ordered]@{
            Report      = [ordered]@{
                Name                = $ReportName
                Version             = '1.0'
                Status              = 'Released'
                Language            = $Lang
                ShowCoverPageImage  = $true
                ShowTableOfContents = $true
                ShowHeaderFooter    = $true
                ShowTableCaptions   = $true
            }
            Options     = [ordered]@{
                ShowExecutionTime       = $false
                ShowDefinitionInfo      = $false
                PSDefaultAuthentication = $PSDefaultAuthentication
                Exclude                 = [ordered]@{ Domains = @(); DCs = @() }
                Include                 = [ordered]@{ Domains = @() }
                WinRMSSL                = $WinRMSSL
                WinRMFallbackToNoSSL    = $WinRMFallbackToNoSSL
                WinRMSSLPort            = 5986
                WinRMPort               = 5985
                EnableDiagrams          = $EnableDiagrams
                EnableDiagramDebug      = $false
                DiagramTheme            = $Theme
                DiagramObjDebug         = $false
                DiagramWaterMark        = ''
                DiagramType             = [ordered]@{
                    CertificateAuthority = $true
                    Forest               = $true
                    Replication          = $true
                    Sites                = $true
                    SitesInventory       = $true
                    Trusts               = $true
                }
                ExportDiagrams          = $ExportDiagrams
                ExportDiagramsFormat    = @('pdf')
                EnableDiagramSignature  = $false
                SignatureAuthorName     = ''
                SignatureCompanyName    = ''
                JobsTimeOut             = 900
                DCStatusPingCount       = 2
            }
            InfoLevel   = [ordered]@{
                Forest = $LvlForest
                Domain = $LvlDomain
                DNS    = $LvlDNS
            }
            HealthCheck = [ordered]@{
                Domain           = [ordered]@{
                    GMSA            = $true; GPO = $true; Backup = $true; DFS = $true
                    SPN             = $true; DuplicateObject = $true; Security = $true; BestPractice = $true
                }
                DomainController = [ordered]@{
                    Diagnostic = $true; Services = $true; Software = $true; BestPractice = $true
                }
                Site             = [ordered]@{ Replication = $true; BestPractice = $true }
                DNS              = [ordered]@{ Aging = $true; DP = $true; Zones = $true; BestPractice = $true }
                CA               = [ordered]@{ Status = $true; Statistics = $true; BestPractice = $true }
            }
        }
    }

    $btnSaveConfig = [Button]::new()
    $btnSaveConfig.Content = '💾 Save Config'
    $btnSaveConfig.HorizontalAlignment = 'Stretch'
    $btnSaveConfig.HorizontalContentAlignment = 'Center'
    $btnSaveConfig.Width = 196
    $btnSaveConfig.Margin = '0,0,4,0'
    $btnSaveConfig.AddClick({
            $destPath = $txtConfigPath.Text.Trim()
            if ([string]::IsNullOrWhiteSpace($destPath)) {
                $syncHash.lblConfigStatus.Text = '⚠ Please enter a destination path first.'
                return
            }
            try {
                $parent = Split-Path $destPath -Parent
                if (-not [string]::IsNullOrEmpty($parent) -and -not (Test-Path $parent)) {
                    New-Item -Path $parent -ItemType Directory -Force | Out-Null
                }
                function Get-LevelVal ($cbo) { [int]([string]$cbo.SelectedItem).Substring(0, 1) }
                $configObj = Build-MSADConfigForSave `
                    -ReportName ($txtReportName.Text.Trim()) `
                    -Lang ([string]$cboLang.SelectedItem) `
                    -Theme ([string]$cboDiagramTheme.SelectedItem) `
                    -EnableDiagrams ([bool]$swDiagrams.IsChecked) `
                    -ExportDiagrams ([bool]$swExportDiagrams.IsChecked) `
                    -PSDefaultAuthentication ([string]$cboPSDefaultAuth.SelectedItem) `
                    -WinRMSSL ([bool]$swWinRMSSL.IsChecked) `
                    -WinRMFallbackToNoSSL ([bool]$swWinRMFallback.IsChecked) `
                    -LvlForest (Get-LevelVal $cboLvlForest) `
                    -LvlDomain (Get-LevelVal $cboLvlDomain) `
                    -LvlDNS (Get-LevelVal $cboLvlDNS)
                $configObj| ConvertTo-Json -Depth 6 | Set-Content -Path $destPath -Encoding UTF8
                $syncHash.lblConfigStatus.Text = "✅ Config saved: $(Split-Path $destPath -Leaf)"
            } catch {
                $syncHash.lblConfigStatus.Text = "❌ Save failed: $_"
            }
        })

    $btnLoadConfig = [Button]::new()
    $btnLoadConfig.Content = '📂 Load Config'
    $btnLoadConfig.HorizontalAlignment = 'Stretch'
    $btnLoadConfig.HorizontalContentAlignment = 'Center'
    $btnLoadConfig.Width = 196
    $btnLoadConfig.Margin = '0,0,4,0'
    $btnLoadConfig.AddClick({
            $srcPath = $txtConfigPath.Text.Trim()
            if ([string]::IsNullOrWhiteSpace($srcPath) -or -not (Test-Path $srcPath)) {
                $syncHash.lblConfigStatus.Text = '⚠ Config file path not found.'
                return
            }
            try {
                $j = Get-Content -Path $srcPath -Raw | ConvertFrom-Json
                if ($j.Report.Name)    { $txtReportName.Text = $j.Report.Name }
                if ($j.Report.Language) { $idx = $cboLang.Items.IndexOf($j.Report.Language); if ($idx -ge 0) { $cboLang.SelectedIndex = $idx } }
                if ($null -ne $j.Options.EnableDiagrams)        { $swDiagrams.IsChecked = [bool]$j.Options.EnableDiagrams }
                if ($null -ne $j.Options.ExportDiagrams)        { $swExportDiagrams.IsChecked = [bool]$j.Options.ExportDiagrams }
                if ($null -ne $j.Options.ShowExecutionTime)     { Out-Null }
                if ($null -ne $j.Options.ShowDefinitionInfo)    { Out-Null }
                if ($null -ne $j.Options.WinRMSSL){ $swWinRMSSL.IsChecked = [bool]$j.Options.WinRMSSL }
                if ($null -ne $j.Options.WinRMFallbackToNoSSL)  { $swWinRMFallback.IsChecked = [bool]$j.Options.WinRMFallbackToNoSSL }
                if ($j.Options.DiagramTheme) { $idx = $cboDiagramTheme.Items.IndexOf($j.Options.DiagramTheme); if ($idx -ge 0) { $cboDiagramTheme.SelectedIndex = $idx } }
                if ($j.Options.PSDefaultAuthentication) { $idx = $cboPSDefaultAuth.Items.IndexOf($j.Options.PSDefaultAuthentication); if ($idx -ge 0) { $cboPSDefaultAuth.SelectedIndex = $idx } }
                if ($null -ne $j.InfoLevel.Forest) { $cboLvlForest.SelectedIndex = [int]$j.InfoLevel.Forest }
                if ($null -ne $j.InfoLevel.Domain) { $cboLvlDomain.SelectedIndex = [int]$j.InfoLevel.Domain }
                if ($null -ne $j.InfoLevel.DNS)    { $cboLvlDNS.SelectedIndex    = [int]$j.InfoLevel.DNS }
                $syncHash.lblConfigStatus.Text= "✅ Config loaded: $(Split-Path $srcPath -Leaf)"
            } catch {
                $syncHash.lblConfigStatus.Text = "❌ Load failed: $_"
            }
        })

    $btnOpenConfig = [Button]::new()
    $btnOpenConfig.Content = '📄 Open File'
    $btnOpenConfig.HorizontalAlignment = 'Stretch'
    $btnOpenConfig.HorizontalContentAlignment = 'Center'
    $btnOpenConfig.Width = 196
    $btnOpenConfig.AddClick({
            $filePath = $txtConfigPath.Text.Trim()
            if ([string]::IsNullOrWhiteSpace($filePath) -or -not (Test-Path $filePath)) {
                $syncHash.lblConfigStatus.Text = '⚠ Config file not found.'
                return
            }
            try { Start-Process $filePath } catch { $syncHash.lblConfigStatus.Text = "❌ Could not open file: $_" }
        })

    $cfgBtnRow = [StackPanel]::new()
    $cfgBtnRow.Orientation = 'Horizontal'
    $cfgBtnRow.Margin = '0,4,0,0'
    $cfgBtnRow.Children.Add($btnSaveConfig)
    $cfgBtnRow.Children.Add($btnLoadConfig)
    $cfgBtnRow.Children.Add($btnOpenConfig)

    # ── Assemble Main Panel (Report Page) ───────────────────────────────────────
    $mainPanel = [StackPanel]::new()
    $mainPanel.Margin = '28,20,28,24'
    $mainPanel.Spacing = 2

    $headerPanel = [StackPanel]::new()
    $headerPanel.HorizontalAlignment = 'Center'
    $headerPanel.Spacing = 4
    $headerPanel.Margin = '0,0,0,4'

    $hTitle = [TextBlock]::new()
    $hTitle.Text = 'Microsoft Active Directory'
    $hTitle.FontSize = 22
    $hTitle.FontWeight = 'Bold'
    $hTitle.HorizontalAlignment = 'Center'

    $hSub = [TextBlock]::new()
    $hSub.Text = 'As-Built Report Generator'
    $hSub.FontSize = 13
    $hSub.HorizontalAlignment = 'Center'

    $headerPanel.Children.Add($hTitle)
    $headerPanel.Children.Add($hSub)
    $mainPanel.Children.Add($headerPanel)

    # Row 1: Server Connection | Report Output
    $topGrid = [Grid]::new()
    $topGrid.ColumnDefinitions = [ColumnDefinitions]::Parse('*, *')
    $topGrid.ColumnSpacing = 24
    $topGrid.Margin = '0,4,0,0'

    $connPanel = [StackPanel]::new()
    $connPanel.Spacing = 2
    $connPanel.Children.Add((New-SectionTitle '🔌 Server Connection'))
    $connPanel.Children.Add((New-FormRow -Label 'Saved Connections' -Control $cboSavedConn -LabelWidth 150))
    $connPanel.Children.Add((New-FormRow -Label 'Domain Controller' -Control $txtServer -LabelWidth 150))
    $connPanel.Children.Add((New-FormRow -Label 'Username' -Control $txtUser -LabelWidth 150))
    $connPanel.Children.Add((New-FormRow -Label 'Password' -Control (New-PasswordRow $txtPass) -LabelWidth 150))
    $connPanel.Children.Add((New-FormRow -Label '' -Control $savedConnActionsRow -LabelWidth 150))
    [Grid]::SetColumn($connPanel, 0)
    $topGrid.Children.Add($connPanel)

    $outPanel = [StackPanel]::new()
    $outPanel.Spacing = 2
    $outPanel.Children.Add((New-SectionTitle '📄 Report Output'))
    $outPanel.Children.Add((New-FormRow -Label 'Report Name' -Control $txtReportName -LabelWidth 130))
    $outPanel.Children.Add((New-FormRow -Label 'Format' -Control $fmtPanel -LabelWidth 130))
    $outPanel.Children.Add((New-FormRow -Label 'Output Folder' -Control $outputPathRow -LabelWidth 130))
    $outPanel.Children.Add((New-FormRow -Label 'Language' -Control $cboLang -LabelWidth 130))
    $outPanel.Children.Add((New-FormRow -Label 'Add Timestamp' -Control $swTimestamp -LabelWidth 130))
    [Grid]::SetColumn($outPanel, 1)
    $topGrid.Children.Add($outPanel)

    $mainPanel.Children.Add($topGrid)

    # Row 2: Options | Info Level
    $bottomGrid = [Grid]::new()
    $bottomGrid.ColumnDefinitions = [ColumnDefinitions]::Parse('*, *')
    $bottomGrid.ColumnSpacing = 24
    $bottomGrid.Margin = '0,4,0,0'

    $optPanel = [StackPanel]::new()
    $optPanel.Spacing = 2
    $optPanel.Children.Add((New-SectionTitle '⚙️ Options'))
    $optPanel.Children.Add((New-FormRow -Label 'Enable Diagrams' -Control $swDiagrams -LabelWidth 185))
    $optPanel.Children.Add((New-FormRow -Label 'Export Diagrams' -Control $swExportDiagrams -LabelWidth 185))
    $optPanel.Children.Add((New-FormRow -Label 'Diagram Theme' -Control $cboDiagramTheme -LabelWidth 185))
    $optPanel.Children.Add((New-FormRow -Label 'WinRM SSL' -Control $swWinRMSSL -LabelWidth 185))
    $optPanel.Children.Add((New-FormRow -Label 'WinRM Fallback' -Control $swWinRMFallback -LabelWidth 185))
    $optPanel.Children.Add((New-FormRow -Label 'PS Authentication' -Control $cboPSDefaultAuth -LabelWidth 185))
    [Grid]::SetColumn($optPanel, 0)
    $bottomGrid.Children.Add($optPanel)

    $lvlPanel = [StackPanel]::new()
    $lvlPanel.Spacing = 2
    $lvlPanel.Children.Add((New-SectionTitle '📊 Info Level'))
    $lvlPanel.Children.Add((New-FormRow -Label 'Forest' -Control $cboLvlForest))
    $lvlPanel.Children.Add((New-FormRow -Label 'Domain' -Control $cboLvlDomain))
    $lvlPanel.Children.Add((New-FormRow -Label 'DNS' -Control $cboLvlDNS))
    [Grid]::SetColumn($lvlPanel, 1)
    $bottomGrid.Children.Add($lvlPanel)

    $mainPanel.Children.Add($bottomGrid)

    $mainPanel.Children.Add((New-SectionTitle '🗂️ Config Management'))
    $mainPanel.Children.Add((New-FormRow -Label '📄 MSAD Config File' -Control $configPathRow))
    $mainPanel.Children.Add($cfgBtnRow)
    $mainPanel.Children.Add((New-FormRow -Label '📄 AsBuiltReport Config File' -Control $abrConfigPathRow))
    $mainPanel.Children.Add($abrExpander)

    $mainPanel.Children.Add($btnGenerate)

    # Log area header
    $logTitle = [TextBlock]::new()
    $logTitle.Text = '📋 Output Log'
    $logTitle.FontSize = 13
    $logTitle.FontWeight = 'SemiBold'
    $logTitle.VerticalAlignment = 'Center'

    $logHeaderGrid = [Grid]::new()
    $logHeaderGrid.Margin = '0,14,0,6'
    $logHeaderGrid.ColumnDefinitions.Add(
        [ColumnDefinition]::new([GridLength]::new(1, [GridUnitType]::Star)))
    $logHeaderGrid.ColumnDefinitions.Add(
        [ColumnDefinition]::new([GridLength]::new(0, [GridUnitType]::Auto)))
    $logHeaderGrid.ColumnDefinitions.Add(
        [ColumnDefinition]::new([GridLength]::new(0, [GridUnitType]::Auto)))
    [Grid]::SetColumn($logTitle, 0)
    [Grid]::SetColumn($chkVerbose, 1)
    [Grid]::SetColumn($btnExportLog, 2)
    $logHeaderGrid.Children.Add($logTitle)
    $logHeaderGrid.Children.Add($chkVerbose)
    $logHeaderGrid.Children.Add($btnExportLog)

    $btnOpenOutputFolder = [Button]::new()
    $btnOpenOutputFolder.Content = '📁 Open Output Folder'
    $btnOpenOutputFolder.Margin = '0,0,8,0'
    $btnOpenOutputFolder.AddClick({
            $path = $txtOutput.Text.Trim()
            if ([string]::IsNullOrWhiteSpace($path)) {
                $syncHash.lblConfigStatus.Text = '⚠ No output folder set.'
                return
            }
            if (-not (Test-Path $path)) {
                $syncHash.lblConfigStatus.Text = "⚠ Output folder not found: $path"
                return
            }
            try { Start-Process $path } catch { $syncHash.lblConfigStatus.Text = "❌ Could not open folder: $_" }
        })

    $logActionsRow = [StackPanel]::new()
    $logActionsRow.Orientation = 'Horizontal'
    $logActionsRow.HorizontalAlignment = 'Right'
    $logActionsRow.Margin = '0,6,0,0'
    $logActionsRow.Children.Add($btnOpenOutputFolder)
    $logActionsRow.Children.Add($btnCancel)

    $scrollView = [ScrollViewer]::new()
    $scrollView.Content = $mainPanel

    # ── Drawer Pages ────────────────────────────────────────────────────────────
    $reportPage = [ContentPage]::new()
    $reportPage.Header = 'Report'
    $reportPage.Content = $scrollView

    $navigationPage = [NavigationPage]::new()
    $navigationPage.Content = $reportPage

    # MDI path geometry for nav icons
    $reportGeometry = 'M6,2A2,2 0 0,0 4,4V20A2,2 0 0,0 6,22H18A2,2 0 0,0 20,20V8L14,2H6M6,4H13V9H18V20H6V4M8,12V14H16V12H8M8,16V18H13V16H8Z'

    $btnNavReport = New-DrawerMenuItem -Title 'Report' -IconGeometry $reportGeometry -Page $reportPage -NavigationPage $navigationPage

    $drawerMenuPanel = [StackPanel]::new()
    $drawerMenuPanel.Margin = 12
    $drawerMenuPanel.Children.Add($btnNavReport)

    $drawerMenu = [ContentPage]::new()
    $drawerMenu.Content = $drawerMenuPanel

    $drawerHeader = [TextBlock]::new()
    $drawerHeader.Text = 'Navigation'
    $drawerHeader.FontSize = 16
    $drawerHeader.FontWeight = 'SemiBold'
    $drawerHeader.VerticalAlignment = 'Center'
    $drawerHeader.Padding = '16,10,12,10'

    $drawerPage = [DrawerPage]::new()
    $drawerPage.DrawerHeader = $drawerHeader
    $drawerPage.Drawer = $drawerMenu
    $drawerPage.Content = $navigationPage

    # ── Shared bottom strip (log + status — visible from all drawer pages) ────────
    $sharedBottomPanel = [StackPanel]::new()
    $sharedBottomPanel.Margin = '28,4,28,16'
    $sharedBottomPanel.Children.Add($progressBar)
    $sharedBottomPanel.Children.Add($logHeaderGrid)
    $sharedBottomPanel.Children.Add($txtLog)
    $sharedBottomPanel.Children.Add($logActionsRow)
    $sharedBottomPanel.Children.Add($lblConfigStatus)

    # ── Outer grid: drawer (fills space) above shared log strip ──────────────────
    $outerGrid = [Grid]::new()
    $outerGrid.RowDefinitions.Add([RowDefinition]::new([GridLength]::new(1, [GridUnitType]::Star)))
    $outerGrid.RowDefinitions.Add([RowDefinition]::new([GridLength]::new(0, [GridUnitType]::Auto)))
    [Grid]::SetRow($drawerPage, 0)
    [Grid]::SetRow($sharedBottomPanel, 1)
    $outerGrid.Children.Add($drawerPage)
    $outerGrid.Children.Add($sharedBottomPanel)

    # ── Window ──────────────────────────────────────────────────────────────────
    $win = [Window]::new()
    $win.Title = 'Microsoft AD — As-Built Report Generator'
    $win.Width = 1050
    $win.Height = 920
    $win.MinWidth = 880
    $win.MinHeight = 500
    $win.Content = $outerGrid

    $win.Show()
    $win.WaitForClosed()
}
