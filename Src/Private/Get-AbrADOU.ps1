function Get-AbrADOU {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Organizational Unit information
    .DESCRIPTION

    .NOTES
        Version:        0.9.6
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
        Write-PScriboMessage -Message "Collecting Active Directory Organizational Unit information on domain $($Domain.DNSRoot)"
    }

    process {
        try {
            $OUs = Invoke-Command -Session $TempPssSession -ScriptBlock { Get-ADOrganizationalUnit -Server $using:ValidDCFromDomain -Properties * -SearchBase ($using:Domain).distinguishedName -Filter * }
            if ($OUs) {
                Section -Style Heading3 "Organizational Units" {
                    Paragraph "The following section provides a summary of Active Directory Organizational Unit information."
                    BlankLine
                    $OutObj = @()
                    foreach ($OU in $OUs) {
                        try {
                            $GPOArray = @()
                            [array]$GPOs = $OU.LinkedGroupPolicyObjects
                            foreach ($Object in $GPOs) {
                                try {
                                    $GP = Invoke-Command -Session $TempPssSession -ScriptBlock { Get-GPO -Server $using:ValidDCFromDomain -Guid ($using:Object).Split(",")[0].Split("=")[1] -Domain ($using:Domain).DNSRoot }
                                    $GPOArray += $GP.DisplayName
                                } catch {
                                    Write-PScriboMessage -IsWarning $_.Exception.Message
                                }
                            }
                            $inObj = [ordered] @{
                                'Name' = ((ConvertTo-ADCanonicalName -DN $OU.DistinguishedName -Domain $Domain.DNSRoot -DC $ValidDCFromDomain).split('/') | Select-Object -Skip 1) -join "/"
                                'Linked GPO' = ($GPOArray -join ", ")
                                'Protected' = $OU.ProtectedFromAccidentalDeletion
                            }
                            $OutObj += [pscustomobject](ConvertTo-HashToYN $inObj)
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Organizational Unit Item)"
                        }
                    }

                    if ($HealthCheck.Domain.BestPractice) {
                        $OutObj | Where-Object { $_.'Protected' -eq 'No' } | Set-Style -Style Warning -Property 'Protected'
                    }

                    $TableParams = @{
                        Name = "Organizational Unit - $($Domain.DNSRoot.ToString().ToUpper())"
                        List = $false
                        ColumnWidths = 45, 45, 10
                    }
                    if ($Report.ShowTableCaptions) {
                        $TableParams['Caption'] = "- $($TableParams.Name)"
                    }
                    $OutObj | Sort-Object -Property 'Name' | Table @TableParams
                    if ($HealthCheck.Domain.BestPractice -and ($OutObj | Where-Object { $_.'Protected' -eq 'No' })) {
                        Paragraph "Health Check:" -Bold -Underline
                        BlankLine
                        Paragraph {
                            Text "Best Practice:" -Bold
                            Text "If the Organizational Units (OUs) in your Active Directory are not protected from accidental deletion, your environment can experience disruptions caused by accidental bulk deletion of objects. All OUs in this domain should be protected from accidental deletion."
                        }
                    }
                    if ($HealthCheck.Domain.GPO) {
                        try {
                            $OutObj = @()
                            if ($OUs) {
                                foreach ($OU in $OUs) {
                                    try {
                                        $GpoInheritance = Invoke-Command -Session $TempPssSession -ErrorAction Stop -ScriptBlock { Get-GPInheritance -Domain ($using:Domain).DNSRoot -Server $using:ValidDCFromDomain -Target ($using:OU).DistinguishedName }
                                        if ( $GpoInheritance.GPOInheritanceBlocked -eq "True") {
                                            $inObj = [ordered] @{
                                                'OU Name' = $GpoInheritance.Name
                                                'Container Type' = $GpoInheritance.ContainerType
                                                'Inheritance Blocked' = $GpoInheritance.GpoInheritanceBlocked
                                                'Path' = ConvertTo-ADCanonicalName -DN $GpoInheritance.Path -Domain $Domain.DNSRoot -DC $ValidDCFromDomain
                                            }
                                            $OutObj += [pscustomobject](ConvertTo-HashToYN $inObj)
                                        }
                                    } catch {
                                        Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Blocked Inheritance GPO Item)"
                                    }
                                }
                            }
                            if ($OutObj) {
                                Section -ExcludeFromTOC -Style NOTOCHeading4 "GPO Blocked Inheritance" {
                                    if ($HealthCheck.Domain.GPO) {
                                        $OutObj | Set-Style -Style Warning
                                    }

                                    $TableParams = @{
                                        Name = "Blocked Inheritance GPO - $($Domain.DNSRoot.ToString().ToUpper())"
                                        List = $false
                                        ColumnWidths = 35, 15, 15, 35
                                    }

                                    if ($Report.ShowTableCaptions) {
                                        $TableParams['Caption'] = "- $($TableParams.Name)"
                                    }
                                    $OutObj | Sort-Object -Property 'OU Name' | Table @TableParams
                                    Paragraph "Health Check:" -Bold -Underline
                                    BlankLine
                                    Paragraph {
                                        Text "Corrective Actions:" -Bold
                                        Text "Review the use of enforced policies and blocked policy inheritance in Active Directory. Enforced policies ensure that specific Group Policy Objects (GPOs) are applied and cannot be overridden by other GPOs. Blocked policy inheritance prevents GPOs from parent containers from being applied to the Organizational Unit (OU). While these settings can be useful for maintaining strict policy application, they can also lead to unexpected results and complicate troubleshooting. Ensure that the use of these settings aligns with your organization's policy management strategy and does not inadvertently cause issues."
                                    }
                                }
                            }

                        } catch {
                            Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Blocked Inheritance GPO Section)"
                        }
                    }
                }
            } else {
                Write-PScriboMessage -Message "No Organizational Units information found in $($Domain.DNSRoot), Disabling this section."
            }
        } catch {
            Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Organizational Unit Section)"
        }
    }

    end {}

}