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
        Write-PScriboMessage -Message "Collecting AD Authentication Policy and Silo information from $($Domain.DNSRoot.toUpper())."
        Show-AbrDebugExecutionTime -Start -TitleMessage 'AD Authentication Policy Silos'
    }

    process {
        try {
            $SiloProperties = @('Name', 'Enforce', 'Description', 'UserAuthenticationPolicy', 'ServiceAuthenticationPolicy', 'ComputerAuthenticationPolicy', 'Members')
            $PolicyProperties = @('Name', 'Enforce', 'Description', 'UserTGTLifetimeMins', 'ServiceTGTLifetimeMins', 'ComputerTGTLifetimeMins')
            $AuthPolicySilos = Invoke-CommandWithTimeout -Session $TempPssSession -ScriptBlock { Get-ADAuthenticationPolicySilo -Filter * -Properties $using:SiloProperties -Server $using:ValidDcFromDomain -ErrorAction SilentlyContinue }
            $AuthPolicies = Invoke-CommandWithTimeout -Session $TempPssSession -ScriptBlock { Get-ADAuthenticationPolicy -Filter * -Properties $using:PolicyProperties -Server $using:ValidDcFromDomain -ErrorAction SilentlyContinue }
            if ($AuthPolicySilos -or $AuthPolicies) {
                Section -Style Heading3 'Authentication Policies and Silos' {
                    Paragraph 'The following section provides an overview of Authentication Policy Silos and Authentication Policies configured in the domain. Authentication Policy Silos restrict where accounts can sign in and apply authentication policies to control the Kerberos ticket-granting ticket (TGT) lifetime for privileged accounts.'
                    BlankLine
                    if ($AuthPolicySilos) {
                        try {
                            Section -Style Heading4 'Authentication Policy Silos' {
                                Paragraph "The following table provides a summary of Authentication Policy Silos configured in domain $($Domain.DNSRoot.ToString().ToUpper())."
                                BlankLine
                                $SiloInfo = [System.Collections.ArrayList]::new()
                                foreach ($Silo in $AuthPolicySilos) {
                                    try {
                                        $inObj = [ordered] @{
                                            'Name' = $Silo.Name
                                            'Enforce' = $Silo.Enforce
                                            'Description' = & {
                                                if ([string]::IsNullOrEmpty($Silo.Description)) { '--' } else { $Silo.Description }
                                            }
                                            'User Authentication Policy' = & {
                                                if ([string]::IsNullOrEmpty($Silo.UserAuthenticationPolicy)) { '--' } else { $Silo.UserAuthenticationPolicy }
                                            }
                                            'Service Authentication Policy' = & {
                                                if ([string]::IsNullOrEmpty($Silo.ServiceAuthenticationPolicy)) { '--' } else { $Silo.ServiceAuthenticationPolicy }
                                            }
                                            'Computer Authentication Policy' = & {
                                                if ([string]::IsNullOrEmpty($Silo.ComputerAuthenticationPolicy)) { '--' } else { $Silo.ComputerAuthenticationPolicy }
                                            }
                                        }
                                        $SiloInfo.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                                    } catch {
                                        Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Authentication Policy Silo Item)"
                                    }
                                }

                                if ($HealthCheck.Domain.Security) {
                                    $SiloInfo | Where-Object { $_.'Enforce' -eq 'No' } | Set-Style -Style Warning -Property 'Enforce'
                                }

                                if ($InfoLevel.Domain -ge 2) {
                                    foreach ($Silo in $SiloInfo) {
                                        Section -Style NOTOCHeading5 -ExcludeFromTOC "$($Silo.Name)" {
                                            $TableParams = @{
                                                Name = "Authentication Policy Silo - $($Silo.Name)"
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
                                        Name = "Authentication Policy Silos - $($Domain.DNSRoot.ToString().ToUpper())"
                                        List = $false
                                        Columns = 'Name', 'Enforce', 'User Authentication Policy', 'Service Authentication Policy', 'Computer Authentication Policy'
                                        ColumnWidths = 20, 12, 23, 23, 22
                                    }
                                    if ($Report.ShowTableCaptions) {
                                        $TableParams['Caption'] = "- $($TableParams.Name)"
                                    }
                                    $SiloInfo | Table @TableParams
                                }

                                if ($HealthCheck.Domain.Security -and ($SiloInfo | Where-Object { $_.'Enforce' -eq 'No' })) {
                                    Paragraph 'Health Check:' -Bold -Underline
                                    BlankLine
                                    Paragraph {
                                        Text 'Best Practice:' -Bold
                                        Text 'Authentication Policy Silos should be set to Enforce mode to actively restrict where privileged accounts can authenticate. Silos in audit mode only log events without enforcing restrictions.'
                                    }
                                    BlankLine
                                }

                                try {
                                    $SiloMemberInfo = [System.Collections.ArrayList]::new()
                                    foreach ($Silo in $AuthPolicySilos) {
                                        foreach ($Member in $Silo.Members) {
                                            try {
                                                $MemberObj = Invoke-CommandWithTimeout -Session $TempPssSession -ScriptBlock {
                                                    Get-ADObject -Identity $using:Member -Properties DistinguishedName, ObjectClass, SamAccountName -Server $using:ValidDcFromDomain -ErrorAction SilentlyContinue
                                                }
                                                if ($MemberObj) {
                                                    $inObj = [ordered] @{
                                                        'Silo Name' = $Silo.Name
                                                        'Member Name' = & {
                                                            if ($MemberObj.SamAccountName) { $MemberObj.SamAccountName } else { $MemberObj.Name }
                                                        }
                                                        'Object Class' = $TextInfo.ToTitleCase($MemberObj.ObjectClass)
                                                        'Distinguished Name' = $MemberObj.DistinguishedName
                                                    }
                                                    $SiloMemberInfo.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                                                }
                                            } catch {
                                                Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Authentication Policy Silo Member Item)"
                                            }
                                        }
                                    }
                                    if ($SiloMemberInfo) {
                                        Section -Style NOTOCHeading5 -ExcludeFromTOC 'Silo Members' {
                                            Paragraph "The following table lists the accounts assigned to Authentication Policy Silos in domain $($Domain.DNSRoot.ToString().ToUpper())."
                                            BlankLine
                                            $TableParams = @{
                                                Name = "Authentication Policy Silo Members - $($Domain.DNSRoot.ToString().ToUpper())"
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
                                    Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Authentication Policy Silo Members Table)"
                                }
                            }
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Authentication Policy Silos Section)"
                        }
                    } else {
                        Write-PScriboMessage -Message "No Authentication Policy Silo information found in $($Domain.DNSRoot), Disabling this section."
                    }
                    if ($AuthPolicies) {
                        try {
                            Section -Style Heading4 'Authentication Policies' {
                                Paragraph "The following table provides a summary of Authentication Policies configured in domain $($Domain.DNSRoot.ToString().ToUpper())."
                                BlankLine
                                $PolicyInfo = [System.Collections.ArrayList]::new()
                                foreach ($Policy in $AuthPolicies) {
                                    try {
                                        $inObj = [ordered] @{
                                            'Name' = $Policy.Name
                                            'Enforce' = $Policy.Enforce
                                            'Description' = & {
                                                if ([string]::IsNullOrEmpty($Policy.Description)) { '--' } else { $Policy.Description }
                                            }
                                            'User TGT Lifetime (mins)' = & {
                                                if ($null -eq $Policy.UserTGTLifetimeMins -or $Policy.UserTGTLifetimeMins -eq 0) { '--' } else { $Policy.UserTGTLifetimeMins }
                                            }
                                            'Service TGT Lifetime (mins)' = & {
                                                if ($null -eq $Policy.ServiceTGTLifetimeMins -or $Policy.ServiceTGTLifetimeMins -eq 0) { '--' } else { $Policy.ServiceTGTLifetimeMins }
                                            }
                                            'Computer TGT Lifetime (mins)' = & {
                                                if ($null -eq $Policy.ComputerTGTLifetimeMins -or $Policy.ComputerTGTLifetimeMins -eq 0) { '--' } else { $Policy.ComputerTGTLifetimeMins }
                                            }
                                        }
                                        $PolicyInfo.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                                    } catch {
                                        Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Authentication Policy Item)"
                                    }
                                }

                                if ($HealthCheck.Domain.Security) {
                                    $PolicyInfo | Where-Object { $_.'Enforce' -eq 'No' } | Set-Style -Style Warning -Property 'Enforce'
                                }

                                if ($InfoLevel.Domain -ge 2) {
                                    foreach ($Policy in $PolicyInfo) {
                                        Section -Style NOTOCHeading5 -ExcludeFromTOC "$($Policy.Name)" {
                                            $TableParams = @{
                                                Name = "Authentication Policy - $($Policy.Name)"
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
                                        Name = "Authentication Policies - $($Domain.DNSRoot.ToString().ToUpper())"
                                        List = $false
                                        Columns = 'Name', 'Enforce', 'User TGT Lifetime (mins)', 'Service TGT Lifetime (mins)', 'Computer TGT Lifetime (mins)'
                                        ColumnWidths = 20, 12, 23, 23, 22
                                    }
                                    if ($Report.ShowTableCaptions) {
                                        $TableParams['Caption'] = "- $($TableParams.Name)"
                                    }
                                    $PolicyInfo | Table @TableParams
                                }

                                if ($HealthCheck.Domain.Security -and ($PolicyInfo | Where-Object { $_.'Enforce' -eq 'No' })) {
                                    Paragraph 'Health Check:' -Bold -Underline
                                    BlankLine
                                    Paragraph {
                                        Text 'Best Practice:' -Bold
                                        Text 'Authentication Policies should be set to Enforce mode to actively restrict Kerberos TGT lifetimes and account sign-in. Policies in audit mode only log events without enforcing restrictions.'
                                    }
                                    BlankLine
                                }
                            }
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Authentication Policies Section)"
                        }
                    } else {
                        Write-PScriboMessage -Message "No Authentication Policy information found in $($Domain.DNSRoot), Disabling this section."
                    }
                }
            } else {
                Write-PScriboMessage -Message "No Authentication Policy or Silo information found in $($Domain.DNSRoot), Disabling this section."
            }
        } catch {
            Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Authentication Policy Silos Section)"
        }
    }

    end {
        Show-AbrDebugExecutionTime -End -TitleMessage 'AD Authentication Policy Silos'
    }

}
