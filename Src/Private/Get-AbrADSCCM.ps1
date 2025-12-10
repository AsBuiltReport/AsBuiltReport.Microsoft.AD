function Get-AbrADSCCM {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD SCCM information
    .DESCRIPTION

    .NOTES
        Version:        0.9.8
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
        Write-PScriboMessage -Message "Collecting AD SCCM information of $($ForestInfo.toUpper())."
        Show-AbrDebugExecutionTime -Start -TitleMessage "AD SCCM Infrastructure"
    }

    process {
        $DomainDN = Invoke-CommandWithTimeout -Session $TempPssSession -ScriptBlock { (Get-ADDomain -Identity (Get-ADForest | Select-Object -ExpandProperty RootDomain )).DistinguishedName }
        $SCCMMP = try { Invoke-CommandWithTimeout -Session $TempPssSession -ErrorAction SilentlyContinue -ScriptBlock { Get-ADObject -Filter { (objectClass -eq "mSSMSManagementPoint") -and (Name -like "SMS-MP-*") } -SearchBase "CN=System Management,CN=System,$using:DomainDN" -Properties * } } catch { Out-Null }
        try {
            if ($SCCMMP ) {
                Section -Style Heading3 'SCCM Infrastructure' {
                    Paragraph "The following section provides a summary of the System Center Configuration Manager (SCCM) infrastructure registered in Active Directory."
                    BlankLine
                    $SCCMInfo = [System.Collections.ArrayList]::new()
                    foreach ($SCCMServer in $SCCMMP) {
                        try {
                            $inObj = [ordered] @{
                                'Name' = $SCCMServer.Name
                                'Management Point' = $SCCMServer.mSSMSMPName -join ', '
                                'Site Code' = $SCCMServer.mSSMSSiteCode
                                'Version' = $SCCMServer.mSSMSVersion
                            }
                            $SCCMInfo.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "$($_.SCCMception.Message) (SCCM Item)"
                        }
                    }

                    if ($InfoLevel.Forest -ge 2) {
                        foreach ($SCCMServer in $SCCMInfo) {
                            Section -Style NOTOCHeading4 -ExcludeFromTOC "$($SCCMServer.Name)" {
                                $TableParams = @{
                                    Name = "SCCM Infrastructure - $($SCCMServer.Name)"
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
                            Name = "SCCM Infrastructure - $($ForestInfo.toUpper())"
                            List = $false
                            Columns = 'Name', 'Management Point', 'Site Code', 'Version'
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
            }
        } catch {
            Write-PScriboMessage -IsWarning -Message "$($_.SCCMception.Message) (SCCM Table)"
        }
    }

    end {
        Show-AbrDebugExecutionTime -End -TitleMessage "AD SCCM Infrastructure"
    }

}