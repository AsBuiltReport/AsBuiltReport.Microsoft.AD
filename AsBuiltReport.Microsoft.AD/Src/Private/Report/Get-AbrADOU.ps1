function Get-AbrADOU {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Organizational Unit information
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
        $Domain,
        [string]$ValidDCFromDomain
    )

    begin {
        Write-PScriboMessage -Message ($reportTranslate.GetAbrADOU.Collecting -f $Domain.DNSRoot)
        Show-AbrDebugExecutionTime -Start -TitleMessage 'AD Domain Organizational Unit'
    }

    process {
        try {
            $OUs = Invoke-CommandWithTimeout -Session $TempPssSession -ScriptBlock { Get-ADOrganizationalUnit -Server $using:ValidDCFromDomain -Properties * -SearchBase ($using:Domain).distinguishedName -Filter * }
            if ($OUs) {
                Section -Style Heading3 $reportTranslate.GetAbrADOU.OUSectionTitle {
                    Paragraph $reportTranslate.GetAbrADOU.OUSectionParagraph
                    BlankLine
                    $OutObj = [System.Collections.Generic.List[object]]::new()
                    foreach ($OU in $OUs) {
                        try {
                            $GPOArray = [System.Collections.Generic.List[object]]::new()
                            $GPOs = $OU.LinkedGroupPolicyObjects
                            foreach ($Object in $GPOs) {
                                try {
                                    $GP = Invoke-CommandWithTimeout -Session $TempPssSession -ScriptBlock { Get-GPO -Server $using:ValidDCFromDomain -Guid ($using:Object).Split(',')[0].Split('=')[1] -Domain ($using:Domain).DNSRoot }
                                    $GPOArray.Add($GP.DisplayName)
                                } catch {
                                    Write-PScriboMessage -IsWarning $_.Exception.Message
                                }
                            }
                            $inObj = [ordered] @{
                                $reportTranslate.GetAbrADOU.Name = ((ConvertTo-ADCanonicalName -DN $OU.DistinguishedName -Domain $Domain.DNSRoot -DC $ValidDCFromDomain).split('/') | Select-Object -Skip 1) -join '/'
                                $reportTranslate.GetAbrADOU.LinkedGPO = ($GPOArray -join ', ')
                                $reportTranslate.GetAbrADOU.Protected = $OU.ProtectedFromAccidentalDeletion
                            }
                            $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj))
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) ($($reportTranslate.GetAbrADOU.ErrorOUItem))"
                        }
                    }

                    if ($HealthCheck.Domain.BestPractice) {
                        $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADOU.Protected) -eq 'No' } | Set-Style -Style Warning -Property $reportTranslate.GetAbrADOU.Protected
                    }

                    $TableParams = @{
                        Name = "$($reportTranslate.GetAbrADOU.OUTableName) - $($Domain.DNSRoot.ToString().ToUpper())"
                        List = $false
                        ColumnWidths = 45, 45, 10
                    }
                    if ($Report.ShowTableCaptions) {
                        $TableParams['Caption'] = "- $($TableParams.Name)"
                    }
                    $OutObj | Sort-Object -Property $reportTranslate.GetAbrADOU.Name | Table @TableParams
                    if ($HealthCheck.Domain.BestPractice -and ($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADOU.Protected) -eq 'No' })) {
                        Paragraph $reportTranslate.GetAbrADOU.OUHealthCheck -Bold -Underline
                        BlankLine
                        Paragraph {
                            Text $reportTranslate.GetAbrADOU.OUBestPractice -Bold
                            Text $reportTranslate.GetAbrADOU.OUBP
                        }
                    }
                    if ($HealthCheck.Domain.GPO) {
                        try {
                            $OutObj = [System.Collections.Generic.List[object]]::new()
                            if ($OUs) {
                                foreach ($OU in $OUs) {
                                    try {
                                        $GpoInheritance = Invoke-CommandWithTimeout -Session $TempPssSession -ErrorAction Stop -ScriptBlock { Get-GPInheritance -Domain ($using:Domain).DNSRoot -Server $using:ValidDCFromDomain -Target ($using:OU).DistinguishedName }
                                        if ( $GpoInheritance.GPOInheritanceBlocked -eq 'True') {
                                            $inObj = [ordered] @{
                                                $reportTranslate.GetAbrADOU.OUName = $GpoInheritance.Name
                                                $reportTranslate.GetAbrADOU.ContainerType = $GpoInheritance.ContainerType
                                                $reportTranslate.GetAbrADOU.InheritanceBlocked = $GpoInheritance.GpoInheritanceBlocked
                                                $reportTranslate.GetAbrADOU.Path = ConvertTo-ADCanonicalName -DN $GpoInheritance.Path -Domain $Domain.DNSRoot -DC $ValidDCFromDomain
                                            }
                                            $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj))
                                        }
                                    } catch {
                                        Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) ($($reportTranslate.GetAbrADOU.ErrorBlockedInheritanceGPOItem))"
                                    }
                                }
                            }
                            if ($OutObj) {
                                Section -ExcludeFromTOC -Style NOTOCHeading4 $reportTranslate.GetAbrADOU.GPOBlockedTitle {
                                    if ($HealthCheck.Domain.GPO) {
                                        $OutObj | Set-Style -Style Warning
                                    }

                                    $TableParams = @{
                                        Name = "$($reportTranslate.GetAbrADOU.GPOBlockedTableName) - $($Domain.DNSRoot.ToString().ToUpper())"
                                        List = $false
                                        ColumnWidths = 35, 15, 15, 35
                                    }

                                    if ($Report.ShowTableCaptions) {
                                        $TableParams['Caption'] = "- $($TableParams.Name)"
                                    }
                                    $OutObj | Sort-Object -Property $reportTranslate.GetAbrADOU.OUName | Table @TableParams
                                    Paragraph $reportTranslate.GetAbrADOU.GPOBlockedHealthCheck -Bold -Underline
                                    BlankLine
                                    Paragraph {
                                        Text $reportTranslate.GetAbrADOU.GPOBlockedCorrectiveActions -Bold
                                        Text $reportTranslate.GetAbrADOU.GPOBlockedBP
                                    }
                                }
                            }

                        } catch {
                            Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) ($($reportTranslate.GetAbrADOU.ErrorBlockedInheritanceGPOSection))"
                        }
                    }
                }
            } else {
                Write-PScriboMessage -Message ($reportTranslate.GetAbrADOU.OUNoData -f $Domain.DNSRoot)
            }
        } catch {
            Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) ($($reportTranslate.GetAbrADOU.ErrorOUSection))"
        }
    }

    end {
        Show-AbrDebugExecutionTime -End -TitleMessage 'AD Domain Organizational Unit'
    }

}