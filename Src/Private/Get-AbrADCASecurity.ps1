function Get-AbrADCASecurity {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Certification Authority Security information.
    .DESCRIPTION

    .NOTES
        Version:        0.9.9
        Author:         Jonathan Colon
        Twitter:        @jcolonfzenpr
        Github:         rebelinux
    .EXAMPLE

    .LINK

    #>
    [CmdletBinding()]
    param (
        [Parameter (
            Position = 0,
            Mandatory)]
        $CA
    )

    begin {
        Write-PScriboMessage -Message $reportTranslate.GetAbrADCASecurity.Collecting
        Show-AbrDebugExecutionTime -Start -TitleMessage 'CA Security'
    }

    process {
        if ($CA) {
            try {
                $CFP = Get-CertificateValidityPeriod -CertificationAuthority $CA
                if ($CFP) {
                    Section -Style Heading3 $reportTranslate.GetAbrADCASecurity.CertValidityPeriod {
                        Paragraph $reportTranslate.GetAbrADCASecurity.CertValidityPeriodParagraph
                        BlankLine
                        $OutObj = [System.Collections.ArrayList]::new()
                        try {
                            $inObj = [ordered] @{
                                $reportTranslate.GetAbrADCASecurity.CAName = $CFP.Name
                                $reportTranslate.GetAbrADCASecurity.ServerName = $CFP.ComputerName
                                $reportTranslate.GetAbrADCASecurity.ValidityPeriod = $CFP.ValidityPeriod
                            }
                            $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Certificate Validity Period Table)"
                        }

                        $TableParams = @{
                            Name = "$($reportTranslate.GetAbrADCASecurity.CertValidityPeriodTable) - $($ForestInfo.ToString().ToUpper())"
                            List = $True
                            ColumnWidths = 40, 60
                        }
                        if ($Report.ShowTableCaptions) {
                            $TableParams['Caption'] = "- $($TableParams.Name)"
                        }
                        $OutObj | Sort-Object -Property $reportTranslate.GetAbrADCASecurity.CAName | Table @TableParams
                    }
                }
            } catch {
                Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Certificate Validity Period Section)"
            }
            try {
                $ACLs = Get-CertificationAuthorityAcl -CertificationAuthority $CA
                if ($ACLs) {
                    Section -Style Heading4 $reportTranslate.GetAbrADCASecurity.ACL {
                        $OutObj = [System.Collections.ArrayList]::new()
                        try {
                            foreach ($ACL in $ACLs) {
                                try {
                                    $inObj = [ordered] @{
                                        $reportTranslate.GetAbrADCASecurity.DCName = $CA.DisplayName
                                        $reportTranslate.GetAbrADCASecurity.Owner = $ACL.Owner
                                        $reportTranslate.GetAbrADCASecurity.Group = $ACL.Group
                                    }
                                    $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                                } catch {
                                    Write-PScriboMessage -IsWarning $_.Exception.Message
                                }
                            }
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Access Control List table)"
                        }

                        $TableParams = @{
                            Name = "$($reportTranslate.GetAbrADCASecurity.ACLTable) - $($ForestInfo.ToString().ToUpper())"
                            List = $false
                            ColumnWidths = 40, 30, 30
                        }
                        if ($Report.ShowTableCaptions) {
                            $TableParams['Caption'] = "- $($TableParams.Name)"
                        }
                        $OutObj | Sort-Object -Property $reportTranslate.GetAbrADCASecurity.DCName | Table @TableParams
                        try {
                            Section -Style Heading5 $reportTranslate.GetAbrADCASecurity.AccessRights {
                                $OutObj = [System.Collections.ArrayList]::new()
                                foreach ($ACL in $ACLs.Access) {
                                    try {
                                        $inObj = [ordered] @{
                                            $reportTranslate.GetAbrADCASecurity.Identity = $ACL.IdentityReference
                                            $reportTranslate.GetAbrADCASecurity.AccessControlType = $ACL.AccessControlType
                                            $reportTranslate.GetAbrADCASecurity.Rights = $ACL.Rights
                                        }
                                        $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                                    } catch {
                                        Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Access Control List Rights table)"
                                    }
                                }

                                $TableParams = @{
                                    Name = "$($reportTranslate.GetAbrADCASecurity.AccessRightsTable) - $($CA.Name)"
                                    List = $false
                                    ColumnWidths = 40, 20, 40
                                }
                                if ($Report.ShowTableCaptions) {
                                    $TableParams['Caption'] = "- $($TableParams.Name)"
                                }
                                $OutObj | Sort-Object -Property $reportTranslate.GetAbrADCASecurity.Identity | Table @TableParams
                            }
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Access Control List Rights section)"
                        }
                    }
                }
            } catch {
                Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Access Control List Section)"
            }
        }
    }

    end {
        Show-AbrDebugExecutionTime -End -TitleMessage 'CA Security'
    }

}
