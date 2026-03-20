function Get-AbrADReportBrief {
    <#
    .SYNOPSIS
    Used by As Built Report to generate a one-page report brief for Microsoft Active Directory.
    .DESCRIPTION
        Documents the configuration of Microsoft AD in Word/HTML/Text formats using PScribo.
    .NOTES
        Version:        0.9.0
        Author:         Jonathan Colon
        Twitter:        @jcolonfzenpr
        GitHub:         rebelinux
        Credits:        Iain Brighton (@iainbrighton) - PScribo module

    .LINK
        https://github.com/AsBuiltReport/AsBuiltReport.Microsoft.AD
    #>
    [CmdletBinding()]
    param (

    )

    begin {
        Write-PScriboMessage -Message ($reportTranslate.GetAbrADReportBrief.Collecting -f $ForestInfo)
        Show-AbrDebugExecutionTime -Start -TitleMessage 'Report Brief'
    }

    process {
        try {
            Section -Style Heading1 $reportTranslate.GetAbrADReportBrief.ReportBrief -ExcludeFromTOC {
                Paragraph $reportTranslate.GetAbrADReportBrief.ReportBriefParagraph
                BlankLine

                # Report Overview
                try {
                    $inObj = [ordered] @{
                        $reportTranslate.GetAbrADReportBrief.ReportName = $Report.Name
                        $reportTranslate.GetAbrADReportBrief.ReportVersion = $Report.Version
                        $reportTranslate.GetAbrADReportBrief.TargetForest = $ForestInfo
                        $reportTranslate.GetAbrADReportBrief.GeneratedOn = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
                    }
                    $OutObj = [pscustomobject]$inObj

                    $TableParams = @{
                        Name = "$($reportTranslate.GetAbrADReportBrief.ReportOverview) - $ForestInfo"
                        List = $true
                        ColumnWidths = 40, 60
                    }
                    if ($Report.ShowTableCaptions) {
                        $TableParams['Caption'] = "- $($TableParams.Name)"
                    }
                    $OutObj | Table @TableParams
                } catch {
                    Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Report Brief - Report Overview)"
                }

                BlankLine

                # Forest Summary
                try {
                    $inObj = [ordered] @{
                        $reportTranslate.GetAbrADReportBrief.ForestName = $ADSystem.Name
                        $reportTranslate.GetAbrADReportBrief.ForestMode = $ADSystem.ForestMode
                        $reportTranslate.GetAbrADReportBrief.RootDomain = $ADSystem.RootDomain
                        $reportTranslate.GetAbrADReportBrief.TotalDomains = ($ADSystem.Domains | Measure-Object).Count
                        $reportTranslate.GetAbrADReportBrief.TotalSites = ($ADSystem.Sites | Measure-Object).Count
                        $reportTranslate.GetAbrADReportBrief.TotalGlobalCatalogs = ($ADSystem.GlobalCatalogs | Measure-Object).Count
                        $reportTranslate.GetAbrADReportBrief.TotalUPNSuffixes = if ($ADSystem.UPNSuffixes) { ($ADSystem.UPNSuffixes | Measure-Object).Count } else { 0 }
                    }
                    $OutObj = [pscustomobject]$inObj

                    $TableParams = @{
                        Name = "$($reportTranslate.GetAbrADReportBrief.ForestSummary) - $ForestInfo"
                        List = $true
                        ColumnWidths = 40, 60
                    }
                    if ($Report.ShowTableCaptions) {
                        $TableParams['Caption'] = "- $($TableParams.Name)"
                    }
                    $OutObj | Table @TableParams
                } catch {
                    Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Report Brief - Forest Summary)"
                }

                BlankLine

                # Domain Summary
                try {
                    $OutObj = [System.Collections.ArrayList]::new()
                    foreach ($Domain in $OrderedDomains) {
                        try {
                            $DomainInfo = Invoke-CommandWithTimeout -Session $TempPssSession -ScriptBlock {
                                Get-ADDomain -Identity $using:Domain -ErrorAction Stop
                            }
                            $DCCount = Invoke-CommandWithTimeout -Session $TempPssSession -ScriptBlock {
                                (Get-ADDomainController -Filter * -Server $using:Domain -ErrorAction Stop | Measure-Object).Count
                            }
                            $inObj = [ordered] @{
                                $reportTranslate.GetAbrADReportBrief.DomainName = $DomainInfo.DNSRoot
                                $reportTranslate.GetAbrADReportBrief.DomainMode = $DomainInfo.DomainMode
                                $reportTranslate.GetAbrADReportBrief.DomainControllers = $DCCount
                                $reportTranslate.GetAbrADReportBrief.PDCEmulator = $DomainInfo.PDCEmulator
                            }
                            $OutObj.Add([pscustomobject]$inObj) | Out-Null
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Report Brief - Domain Summary - $Domain)"
                        }
                    }

                    if ($OutObj) {
                        $TableParams = @{
                            Name = "$($reportTranslate.GetAbrADReportBrief.DomainSummary) - $ForestInfo"
                            List = $false
                            Headers = $reportTranslate.GetAbrADReportBrief.DomainName, $reportTranslate.GetAbrADReportBrief.DomainMode, $reportTranslate.GetAbrADReportBrief.DomainControllers, $reportTranslate.GetAbrADReportBrief.PDCEmulator
                            Columns = $reportTranslate.GetAbrADReportBrief.DomainName, $reportTranslate.GetAbrADReportBrief.DomainMode, $reportTranslate.GetAbrADReportBrief.DomainControllers, $reportTranslate.GetAbrADReportBrief.PDCEmulator
                            ColumnWidths = 25, 25, 15, 35
                        }
                        if ($Report.ShowTableCaptions) {
                            $TableParams['Caption'] = "- $($TableParams.Name)"
                        }
                        $OutObj | Table @TableParams
                    }
                } catch {
                    Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Report Brief - Domain Summary)"
                }

                BlankLine

                # Report Scope
                try {
                    $OutObj = [System.Collections.ArrayList]::new()
                    $ScopeMap = [ordered] @{
                        $reportTranslate.GetAbrADReportBrief.ScopeForest = $InfoLevel.Forest
                        $reportTranslate.GetAbrADReportBrief.ScopeDomain = $InfoLevel.Domain
                        $reportTranslate.GetAbrADReportBrief.ScopeDNS = $InfoLevel.DNS
                        $reportTranslate.GetAbrADReportBrief.ScopeCA = $InfoLevel.CA
                    }

                    foreach ($Entry in $ScopeMap.GetEnumerator()) {
                        $StatusText = switch ($Entry.Value) {
                            0 { $reportTranslate.GetAbrADReportBrief.ScopeDisabled }
                            1 { $reportTranslate.GetAbrADReportBrief.ScopeEnabled }
                            2 { $reportTranslate.GetAbrADReportBrief.ScopeAdvanced }
                            3 { $reportTranslate.GetAbrADReportBrief.ScopeDetailed }
                            default { "$($reportTranslate.GetAbrADReportBrief.ScopeEnabled) (Level $($Entry.Value))" }
                        }
                        $inObj = [ordered] @{
                            $reportTranslate.GetAbrADReportBrief.Section = $Entry.Key
                            $reportTranslate.GetAbrADReportBrief.DetailLevel = $StatusText
                        }
                        $OutObj.Add([pscustomobject]$inObj) | Out-Null
                    }

                    $TableParams = @{
                        Name = "$($reportTranslate.GetAbrADReportBrief.ReportScope) - $ForestInfo"
                        List = $false
                        Headers = $reportTranslate.GetAbrADReportBrief.Section, $reportTranslate.GetAbrADReportBrief.DetailLevel
                        Columns = $reportTranslate.GetAbrADReportBrief.Section, $reportTranslate.GetAbrADReportBrief.DetailLevel
                        ColumnWidths = 60, 40
                    }
                    if ($Report.ShowTableCaptions) {
                        $TableParams['Caption'] = "- $($TableParams.Name)"
                    }
                    $OutObj | Table @TableParams
                } catch {
                    Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Report Brief - Report Scope)"
                }
            }
            PageBreak
        } catch {
            Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Report Brief Section)"
        }
    }

    end {
        Show-AbrDebugExecutionTime -End -TitleMessage 'Report Brief'
    }
}
