function Get-AbrADDuplicateSPN {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Domain Duplicate SPN information.
    .DESCRIPTION

    .NOTES
        Version:        0.9.12
        Author:         Jonathan Colon
        Twitter:        @jcolonfzenpr
        Github:         rebelinux
    .EXAMPLE

    .LINK

    #>
    [CmdletBinding()]
    param (
        $Domain
    )

    begin {
        Write-PScriboMessage -Message ($reportTranslate.GetAbrADDuplicateSPN.Collecting -f $Domain.DNSRoot)
        Show-AbrDebugExecutionTime -Start -TitleMessage 'AD Domain Duplicate SPN'
    }

    process {
        if ($HealthCheck.Domain.SPN) {
            try {
                $SPNs = Get-WinADDuplicateSPN -Domain $Domain.DNSRoot -Credential $Credential -ExcludeDomains $Options.Exclude.Domains
                if ($SPNs) {
                    Section -ExcludeFromTOC -Style NOTOCHeading4 $reportTranslate.GetAbrADDuplicateSPN.SectionTitle {
                        Paragraph ($reportTranslate.GetAbrADDuplicateSPN.SectionParagraph -f $Domain.DNSRoot.ToString().ToUpper())
                        BlankLine
                        $OutObj = [System.Collections.Generic.List[object]]::new()
                        foreach ($SPN in $SPNs) {
                            try {
                                $inObj = [ordered] @{
                                    $reportTranslate.GetAbrADDuplicateSPN.Name = $SPN.Name
                                    $reportTranslate.GetAbrADDuplicateSPN.Count = $SPN.Count
                                    $reportTranslate.GetAbrADDuplicateSPN.DistinguishedName = $SPN.List
                                }
                                $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj))

                                if ($HealthCheck.Domain.SPN) {
                                    $OutObj | Set-Style -Style Warning
                                }
                            } catch {
                                Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (SPN Item)"
                            }
                        }

                        $TableParams = @{
                            Name = "$($reportTranslate.GetAbrADDuplicateSPN.TableName) - $($Domain.DNSRoot.ToString().ToUpper())"
                            List = $false
                            ColumnWidths = 40, 10, 50
                        }

                        if ($Report.ShowTableCaptions) {
                            $TableParams['Caption'] = "- $($TableParams.Name)"
                        }
                        $OutObj | Sort-Object -Property $reportTranslate.GetAbrADDuplicateSPN.Name | Table @TableParams
                        if ($HealthCheck.Domain.SPN) {
                            Paragraph $reportTranslate.GetAbrADDuplicateSPN.HealthCheck -Bold -Underline
                            BlankLine
                            Paragraph {
                                Text $reportTranslate.GetAbrADDuplicateSPN.CorrectiveActions -Bold
                                Text $reportTranslate.GetAbrADDuplicateSPN.SPNBP
                            }
                        }
                    }
                } else {
                    Write-PScriboMessage -Message ($reportTranslate.GetAbrADDuplicateSPN.NoData -f $Domain.DNSRoot)
                }
            } catch {
                Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (SPN Table)"
            }
        }
    }

    end {
        Show-AbrDebugExecutionTime -End -TitleMessage 'AD Domain Duplicate SPN'
    }

}