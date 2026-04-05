function Get-AbrADAuthenticationPolicy {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Authentication Policy and Authentication Policy Silo information.
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
        [string]$ValidDcFromDomain
    )

    begin {
        Write-PScriboMessage -Message ($reportTranslate.GetAbrADAuthenticationPolicy.Collecting -f $Domain.DNSRoot.toUpper())
        Show-AbrDebugExecutionTime -Start -TitleMessage 'AD Authentication Policy Silos'
    }

    process {
        try {
            $SiloProperties = @('Name', 'Enforce', 'Description', 'UserAuthenticationPolicy', 'ServiceAuthenticationPolicy', 'ComputerAuthenticationPolicy', 'Members')
            $PolicyProperties = @('Name', 'Enforce', 'Description', 'UserTGTLifetimeMins', 'ServiceTGTLifetimeMins', 'ComputerTGTLifetimeMins')
            $AuthPolicySilos = Invoke-CommandWithTimeout -Session $TempPssSession -ScriptBlock { Get-ADAuthenticationPolicySilo -Filter * -Properties $using:SiloProperties -Server $using:ValidDcFromDomain -ErrorAction SilentlyContinue }
            $AuthPolicies = Invoke-CommandWithTimeout -Session $TempPssSession -ScriptBlock { Get-ADAuthenticationPolicy -Filter * -Properties $using:PolicyProperties -Server $using:ValidDcFromDomain -ErrorAction SilentlyContinue }
            if ($AuthPolicySilos -or $AuthPolicies) {
                Section -Style Heading3 $reportTranslate.GetAbrADAuthenticationPolicy.SectionTitle {
                    Paragraph $reportTranslate.GetAbrADAuthenticationPolicy.SectionParagraph
                    BlankLine
                    if ($AuthPolicySilos) {
                        try {
                            Section -Style Heading4 $reportTranslate.GetAbrADAuthenticationPolicy.SilosSection {
                                Paragraph ($reportTranslate.GetAbrADAuthenticationPolicy.SilosParagraph -f $Domain.DNSRoot.ToString().ToUpper())
                                BlankLine
                                $SiloInfo = [System.Collections.Generic.List[object]]::new()
                                foreach ($Silo in $AuthPolicySilos) {
                                    try {
                                        $inObj = [ordered] @{
                                            $reportTranslate.GetAbrADAuthenticationPolicy.SiloName = $Silo.Name
                                            $reportTranslate.GetAbrADAuthenticationPolicy.SiloEnforce = $Silo.Enforce
                                            $reportTranslate.GetAbrADAuthenticationPolicy.SiloDescription = & {
                                                if ([string]::IsNullOrEmpty($Silo.Description)) { '--' } else { $Silo.Description }
                                            }
                                            $reportTranslate.GetAbrADAuthenticationPolicy.UserAuthPolicy = & {
                                                if ([string]::IsNullOrEmpty($Silo.UserAuthenticationPolicy)) { '--' } else { $Silo.UserAuthenticationPolicy }
                                            }
                                            $reportTranslate.GetAbrADAuthenticationPolicy.ServiceAuthPolicy = & {
                                                if ([string]::IsNullOrEmpty($Silo.ServiceAuthenticationPolicy)) { '--' } else { $Silo.ServiceAuthenticationPolicy }
                                            }
                                            $reportTranslate.GetAbrADAuthenticationPolicy.ComputerAuthPolicy = & {
                                                if ([string]::IsNullOrEmpty($Silo.ComputerAuthenticationPolicy)) { '--' } else { $Silo.ComputerAuthenticationPolicy }
                                            }
                                        }
                                        $SiloInfo.Add([pscustomobject](ConvertTo-HashToYN $inObj))
                                    } catch {
                                        Write-PScriboMessage -IsWarning -Message "$($reportTranslate.GetAbrADAuthenticationPolicy.ErrorSiloItem) $($_.Exception.Message)"
                                    }
                                }

                                if ($HealthCheck.Domain.Security) {
                                    $SiloInfo | Where-Object { $_.$($reportTranslate.GetAbrADAuthenticationPolicy.SiloEnforce) -eq 'No' } | Set-Style -Style Warning -Property $reportTranslate.GetAbrADAuthenticationPolicy.SiloEnforce
                                }

                                if ($InfoLevel.Domain -ge 2) {
                                    foreach ($Silo in $SiloInfo) {
                                        Section -Style NOTOCHeading5 -ExcludeFromTOC "$($Silo.Name)" {
                                            $TableParams = @{
                                                Name = "$($reportTranslate.GetAbrADAuthenticationPolicy.SiloTableName) - $($Silo.Name)"
                                                List = $true
                                                ColumnWidths = 40, 60
                                            }
                                            if ($Report.ShowTableCaptions) {
                                                $TableParams['Caption'] = "- $($TableParams.Name)"
                                            }
                                            $Silo | Table @TableParams
                                        }
                                    }
                                } else {
                                    $TableParams = @{
                                        Name = "$($reportTranslate.GetAbrADAuthenticationPolicy.SilosTableName) - $($Domain.DNSRoot.ToString().ToUpper())"
                                        List = $false
                                        Columns = $reportTranslate.GetAbrADAuthenticationPolicy.SiloName, $reportTranslate.GetAbrADAuthenticationPolicy.SiloEnforce, $reportTranslate.GetAbrADAuthenticationPolicy.UserAuthPolicy, $reportTranslate.GetAbrADAuthenticationPolicy.ServiceAuthPolicy, $reportTranslate.GetAbrADAuthenticationPolicy.ComputerAuthPolicy
                                        ColumnWidths = 20, 12, 23, 23, 22
                                    }
                                    if ($Report.ShowTableCaptions) {
                                        $TableParams['Caption'] = "- $($TableParams.Name)"
                                    }
                                    $SiloInfo | Table @TableParams
                                }

                                if ($HealthCheck.Domain.Security -and ($SiloInfo | Where-Object { $_.$($reportTranslate.GetAbrADAuthenticationPolicy.SiloEnforce) -eq 'No' })) {
                                    Paragraph $reportTranslate.GetAbrADAuthenticationPolicy.HealthCheck -Bold -Underline
                                    BlankLine
                                    Paragraph {
                                        Text $reportTranslate.GetAbrADAuthenticationPolicy.BestPractice -Bold
                                        Text $reportTranslate.GetAbrADAuthenticationPolicy.SiloBP
                                    }
                                    BlankLine
                                }

                                try {
                                    $SiloMemberInfo = [System.Collections.Generic.List[object]]::new()
                                    foreach ($Silo in $AuthPolicySilos) {
                                        foreach ($Member in $Silo.Members) {
                                            try {
                                                $MemberObj = Invoke-CommandWithTimeout -Session $TempPssSession -ScriptBlock {
                                                    Get-ADObject -Identity $using:Member -Properties DistinguishedName, ObjectClass, SamAccountName -Server $using:ValidDcFromDomain -ErrorAction SilentlyContinue
                                                }
                                                if ($MemberObj) {
                                                    $inObj = [ordered] @{
                                                        $reportTranslate.GetAbrADAuthenticationPolicy.SiloMemberSiloName = $Silo.Name
                                                        $reportTranslate.GetAbrADAuthenticationPolicy.SiloMemberName = & {
                                                            if ($MemberObj.SamAccountName) { $MemberObj.SamAccountName } else { $MemberObj.Name }
                                                        }
                                                        $reportTranslate.GetAbrADAuthenticationPolicy.ObjectClass = $TextInfo.ToTitleCase($MemberObj.ObjectClass)
                                                        $reportTranslate.GetAbrADAuthenticationPolicy.DistinguishedName = $MemberObj.DistinguishedName
                                                    }
                                                    $SiloMemberInfo.Add([pscustomobject](ConvertTo-HashToYN $inObj))
                                                }
                                            } catch {
                                                Write-PScriboMessage -IsWarning -Message "$($reportTranslate.GetAbrADAuthenticationPolicy.ErrorSiloMemberItem) $($_.Exception.Message)"
                                            }
                                        }
                                    }
                                    if ($SiloMemberInfo) {
                                        Section -Style NOTOCHeading5 -ExcludeFromTOC $reportTranslate.GetAbrADAuthenticationPolicy.SiloMembersSection {
                                            Paragraph ($reportTranslate.GetAbrADAuthenticationPolicy.SiloMembersParagraph -f $Domain.DNSRoot.ToString().ToUpper())
                                            BlankLine
                                            $TableParams = @{
                                                Name = "$($reportTranslate.GetAbrADAuthenticationPolicy.SiloMembersTableName) - $($Domain.DNSRoot.ToString().ToUpper())"
                                                List = $false
                                                ColumnWidths = 20, 20, 15, 45
                                            }
                                            if ($Report.ShowTableCaptions) {
                                                $TableParams['Caption'] = "- $($TableParams.Name)"
                                            }
                                            $SiloMemberInfo | Table @TableParams
                                        }
                                    }
                                } catch {
                                    Write-PScriboMessage -IsWarning -Message "$($reportTranslate.GetAbrADAuthenticationPolicy.ErrorSiloMembersTable) $($_.Exception.Message)"
                                }
                            }
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "$($reportTranslate.GetAbrADAuthenticationPolicy.ErrorSilosSectionA) $($_.Exception.Message)"
                        }
                    } else {
                        Write-PScriboMessage -Message ($reportTranslate.GetAbrADAuthenticationPolicy.NoSiloInfo -f $Domain.DNSRoot)
                    }
                    if ($AuthPolicies) {
                        try {
                            Section -Style Heading4 $reportTranslate.GetAbrADAuthenticationPolicy.PoliciesSection {
                                Paragraph ($reportTranslate.GetAbrADAuthenticationPolicy.PoliciesParagraph -f $Domain.DNSRoot.ToString().ToUpper())
                                BlankLine
                                $PolicyInfo = [System.Collections.Generic.List[object]]::new()
                                foreach ($Policy in $AuthPolicies) {
                                    try {
                                        $inObj = [ordered] @{
                                            $reportTranslate.GetAbrADAuthenticationPolicy.PolicyName = $Policy.Name
                                            $reportTranslate.GetAbrADAuthenticationPolicy.PolicyEnforce = $Policy.Enforce
                                            $reportTranslate.GetAbrADAuthenticationPolicy.PolicyDescription = & {
                                                if ([string]::IsNullOrEmpty($Policy.Description)) { '--' } else { $Policy.Description }
                                            }
                                            $reportTranslate.GetAbrADAuthenticationPolicy.UserTGTLifetime = & {
                                                if ($null -eq $Policy.UserTGTLifetimeMins -or $Policy.UserTGTLifetimeMins -eq 0) { '--' } else { $Policy.UserTGTLifetimeMins }
                                            }
                                            $reportTranslate.GetAbrADAuthenticationPolicy.ServiceTGTLifetime = & {
                                                if ($null -eq $Policy.ServiceTGTLifetimeMins -or $Policy.ServiceTGTLifetimeMins -eq 0) { '--' } else { $Policy.ServiceTGTLifetimeMins }
                                            }
                                            $reportTranslate.GetAbrADAuthenticationPolicy.ComputerTGTLifetime = & {
                                                if ($null -eq $Policy.ComputerTGTLifetimeMins -or $Policy.ComputerTGTLifetimeMins -eq 0) { '--' } else { $Policy.ComputerTGTLifetimeMins }
                                            }
                                        }
                                        $PolicyInfo.Add([pscustomobject](ConvertTo-HashToYN $inObj))
                                    } catch {
                                        Write-PScriboMessage -IsWarning -Message "$($reportTranslate.GetAbrADAuthenticationPolicy.ErrorPolicyItem) $($_.Exception.Message)"
                                    }
                                }

                                if ($HealthCheck.Domain.Security) {
                                    $PolicyInfo | Where-Object { $_.$($reportTranslate.GetAbrADAuthenticationPolicy.PolicyEnforce) -eq 'No' } | Set-Style -Style Warning -Property $reportTranslate.GetAbrADAuthenticationPolicy.PolicyEnforce
                                }

                                if ($InfoLevel.Domain -ge 2) {
                                    foreach ($Policy in $PolicyInfo) {
                                        Section -Style NOTOCHeading5 -ExcludeFromTOC "$($Policy.Name)" {
                                            $TableParams = @{
                                                Name = "$($reportTranslate.GetAbrADAuthenticationPolicy.PolicyTableName) - $($Policy.Name)"
                                                List = $true
                                                ColumnWidths = 40, 60
                                            }
                                            if ($Report.ShowTableCaptions) {
                                                $TableParams['Caption'] = "- $($TableParams.Name)"
                                            }
                                            $Policy | Table @TableParams
                                        }
                                    }
                                } else {
                                    $TableParams = @{
                                        Name = "$($reportTranslate.GetAbrADAuthenticationPolicy.PoliciesTableName) - $($Domain.DNSRoot.ToString().ToUpper())"
                                        List = $false
                                        Columns = $reportTranslate.GetAbrADAuthenticationPolicy.PolicyName, $reportTranslate.GetAbrADAuthenticationPolicy.PolicyEnforce, $reportTranslate.GetAbrADAuthenticationPolicy.UserTGTLifetime, $reportTranslate.GetAbrADAuthenticationPolicy.ServiceTGTLifetime, $reportTranslate.GetAbrADAuthenticationPolicy.ComputerTGTLifetime
                                        ColumnWidths = 20, 12, 23, 23, 22
                                    }
                                    if ($Report.ShowTableCaptions) {
                                        $TableParams['Caption'] = "- $($TableParams.Name)"
                                    }
                                    $PolicyInfo | Table @TableParams
                                }

                                if ($HealthCheck.Domain.Security -and ($PolicyInfo | Where-Object { $_.$($reportTranslate.GetAbrADAuthenticationPolicy.PolicyEnforce) -eq 'No' })) {
                                    Paragraph $reportTranslate.GetAbrADAuthenticationPolicy.HealthCheck -Bold -Underline
                                    BlankLine
                                    Paragraph {
                                        Text $reportTranslate.GetAbrADAuthenticationPolicy.BestPractice -Bold
                                        Text $reportTranslate.GetAbrADAuthenticationPolicy.PolicyBP
                                    }
                                    BlankLine
                                }
                            }
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "$($reportTranslate.GetAbrADAuthenticationPolicy.ErrorPoliciesSection) $($_.Exception.Message)"
                        }
                    } else {
                        Write-PScriboMessage -Message ($reportTranslate.GetAbrADAuthenticationPolicy.NoPolicyInfo -f $Domain.DNSRoot)
                    }
                }
            } else {
                Write-PScriboMessage -Message ($reportTranslate.GetAbrADAuthenticationPolicy.NoAuthPolicyOrSiloInfo -f $Domain.DNSRoot)
            }
        } catch {
            Write-PScriboMessage -IsWarning -Message "$($reportTranslate.GetAbrADAuthenticationPolicy.ErrorSilosSectionA) $($_.Exception.Message)"
        }
    }

    end {
        Show-AbrDebugExecutionTime -End -TitleMessage 'AD Authentication Policy Silos'
    }

}
