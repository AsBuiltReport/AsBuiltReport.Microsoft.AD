function Get-AbrADDCRoleFeature {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Domain Controller Role & Features information.
    .DESCRIPTION

    .NOTES
        Version:        0.9.2
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
        [string]
        $DC
    )

    begin {
        Write-PScriboMessage "Collecting Active Directory DC Role & Features information of $DC."
    }

    process {
        try {
            $DCPssSession = Get-ValidPSSession -ComputerName $DC -SessionName 'ADDCRoleFeature'
            if ($DCPssSession) {
                $Features = Invoke-Command -Session $DCPssSession -ScriptBlock { Get-WindowsFeature | Where-Object { $_.installed -eq "True" -and $_.FeatureType -eq 'Role' } }
                Remove-PSSession -Session $DCPssSession
            } else {
                if (-Not $_.Exception.MessageId) {
                    $ErrorMessage = $_.FullyQualifiedErrorId
                } else { $ErrorMessage = $_.Exception.MessageId }
                Write-PScriboMessage -IsWarning "Roles Section: New-PSSession: Unable to connect to $($DC): $ErrorMessage"
            }
            if ($Features) {
                Section -ExcludeFromTOC -Style NOTOCHeading5 $($DC.ToString().ToUpper().Split(".")[0]) {
                    $OutObj = @()
                    foreach ($Feature in $Features) {
                        try {
                            $inObj = [ordered] @{
                                'Name' = $Feature.DisplayName
                                'Parent' = $Feature.FeatureType
                                'Description' = $Feature.Description
                            }
                            $OutObj += [pscustomobject](ConvertTo-HashToYN $inObj)
                        } catch {
                            Write-PScriboMessage -IsWarning "Roles $($Feature.DisplayName) Section: $($_.Exception.Message)"
                        }
                    }

                    if ($HealthCheck.DomainController.BestPractice) {
                        $OutObj | Where-Object { $_.'Name' -notin @('Active Directory Domain Services', 'DNS Server', 'File and Storage Services', 'DHCP Server') } | Set-Style -Style Warning
                    }

                    $TableParams = @{
                        Name = "Roles - $($DC.ToString().split('.')[0].ToUpper())"
                        List = $false
                        ColumnWidths = 20, 10, 70
                    }
                    if ($Report.ShowTableCaptions) {
                        $TableParams['Caption'] = "- $($TableParams.Name)"
                    }
                    $OutObj | Table @TableParams
                    if ($HealthCheck.DomainController.Software -and ($OutObj | Where-Object { $_.'Name' -notin @('Active Directory Domain Services', 'DNS Server', 'File and Storage Services') })) {
                        Paragraph "Health Check:" -Bold -Underline
                        BlankLine
                        Paragraph {
                            Text "Best Practices:" -Bold
                            Text "Domain Controllers should have limited software and agents installed including roles and services. Non-essential code running on Domain Controllers is a risk to the enterprise Active Directory environment. A Domain Controller should only run required software, services and roles critical to essential operation."
                        }
                    }
                }
            }
        } catch {
            Write-PScriboMessage -IsWarning "Roles Section: $($_.Exception.Message)"
        }
    }
    end {}
}