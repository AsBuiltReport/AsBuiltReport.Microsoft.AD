function Get-AbrADSCCM {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD SCCM information
    .DESCRIPTION

    .NOTES
        Version:        0.9.12
        Author:         Jonathan Colon
        Twitter:        @jcolonfzenpr
        Github:         rebelinux
    .SCCMAMPLE

    .LINK

    #>
    [CmdletBinding()]
    param (
    )

    begin {
        Write-PScriboMessage -Message ($reportTranslate.GetAbrADSCCM.Collecting -f $ForestInfo.toUpper())
        Show-AbrDebugExecutionTime -Start -TitleMessage 'AD SCCM Infrastructure'
    }

    process {
        $DomainDN = Invoke-CommandWithTimeout -Session $TempPssSession -ScriptBlock { (Get-ADDomain -Identity (Get-ADForest | Select-Object -ExpandProperty RootDomain )).DistinguishedName }
        $SCCMMP = try { Invoke-CommandWithTimeout -Session $TempPssSession -ErrorAction SilentlyContinue -ScriptBlock { Get-ADObject -Filter { (objectClass -eq 'mSSMSManagementPoint') -and (Name -like 'SMS-MP-*') } -SearchBase "CN=System Management,CN=System,$using:DomainDN" -Properties * } } catch { $null }
        try {
            if ($SCCMMP ) {
                Section -Style Heading3 $reportTranslate.GetAbrADSCCM.Heading {
                    Paragraph $reportTranslate.GetAbrADSCCM.Paragraph
                    BlankLine
                    $SCCMInfo = [System.Collections.Generic.List[object]]::new()
                    foreach ($SCCMServer in $SCCMMP) {
                        try {
                            $inObj = [ordered] @{
                                $reportTranslate.GetAbrADSCCM.Name = $SCCMServer.Name
                                $reportTranslate.GetAbrADSCCM.ManagementPoint = $SCCMServer.mSSMSMPName -join ', '
                                $reportTranslate.GetAbrADSCCM.SiteCode = $SCCMServer.mSSMSSiteCode
                                $reportTranslate.GetAbrADSCCM.Version = $SCCMServer.mSSMSVersion
                            }
                            $SCCMInfo.Add([pscustomobject](ConvertTo-HashToYN $inObj))
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "$($_.SCCMception.Message) (SCCM Item)"
                        }
                    }

                    if ($InfoLevel.Forest -ge 2) {
                        foreach ($SCCMServer in $SCCMInfo) {
                            Section -Style NOTOCHeading4 -ExcludeFromTOC "$($SCCMServer.$($reportTranslate.GetAbrADSCCM.Name))" {
                                $TableParams = @{
                                    Name = "$($reportTranslate.GetAbrADSCCM.Heading) - $($SCCMServer.$($reportTranslate.GetAbrADSCCM.Name))"
                                    List = $true
                                    ColumnWidths = 40, 60
                                }
                                if ($Report.ShowTableCaptions) {
                                    $TableParams['Caption'] = "- $($TableParams.Name)"
                                }
                                $SCCMServer | Table @TableParams
                            }
                        }
                    } else {
                        $TableParams = @{
                            Name = "$($reportTranslate.GetAbrADSCCM.Heading) - $($ForestInfo.toUpper())"
                            List = $false
                            Columns = $reportTranslate.GetAbrADSCCM.Name, $reportTranslate.GetAbrADSCCM.ManagementPoint, $reportTranslate.GetAbrADSCCM.SiteCode, $reportTranslate.GetAbrADSCCM.Version
                            ColumnWidths = 35, 35, 15, 15
                        }
                        if ($Report.ShowTableCaptions) {
                            $TableParams['Caption'] = "- $($TableParams.Name)"
                        }
                        $SCCMInfo | Table @TableParams
                    }
                }
            } else {
                Write-PScriboMessage -Message "No SCCM Infrastructure information found in $($ForestInfo.toUpper()), Disabling this section."
                Paragraph $reportTranslate.GetAbrADSCCM.NotFound
                BlankLine
            }
        } catch {
            Write-PScriboMessage -IsWarning -Message "$($_.SCCMception.Message) (SCCM Table)"
        }
    }

    end {
        Show-AbrDebugExecutionTime -End -TitleMessage 'AD SCCM Infrastructure'
    }

}
