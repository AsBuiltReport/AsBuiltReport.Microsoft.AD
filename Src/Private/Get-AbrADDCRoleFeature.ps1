function Get-AbrADDCRoleFeature {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Domain Controller Role & Features information.
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
        $DC
    )

    begin {
        Write-PScriboMessage -Message "Collecting Active Directory DC Role & Features information of $DC."
        Show-AbrDebugExecutionTime -Start -TitleMessage "DC Role & Features"
    }

    process {
        try {
            $DCPssSession = Get-ValidPSSession -ComputerName $DC -SessionName $($DC) -PSSTable ([ref]$PSSTable)
            if ($DCPssSession) {
                $Features = Invoke-Command -Session $DCPssSession -ScriptBlock { Get-WindowsFeature | Where-Object { $_.installed -eq "True" -and $_.FeatureType -eq 'Role' } }
            } else {
                if (-Not $_.Exception.MessageId) {
                    $ErrorMessage = $_.FullyQualifiedErrorId
                } else { $ErrorMessage = $_.Exception.MessageId }
                Write-PScriboMessage -IsWarning -Message "Roles Section: New-PSSession: Unable to connect to $($DC): $ErrorMessage"
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
                            Write-PScriboMessage -IsWarning -Message "Roles $($Feature.DisplayName) Section: $($_.Exception.Message)"
                        }
                    }

                    if ($HealthCheck.DomainController.BestPractice) {
                        $List = @()
                        $OutObj | Where-Object { $_.'Name' -notin @('Active Directory Domain Services', 'DNS Server', 'File and Storage Services', 'DHCP Server') } | Set-Style -Style Warning
                        foreach ( $OBJ in ($OutObj | Where-Object { $_.'Name' -notin @('Active Directory Domain Services', 'DNS Server', 'File and Storage Services', 'DHCP Server') })) {
                            $OBJ.'Name' = $OBJ.'Name' + " (1)"
                            $List = "Domain Controllers should have limited software and agents installed including roles and services. Non-essential code running on Domain Controllers is a risk to the enterprise Active Directory environment. A Domain Controller should only run required software, services and roles critical to essential operation."
                        }
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
                    if ($HealthCheck.DomainController.Software -and $List) {
                        Paragraph "Health Check:" -Bold -Underline
                        BlankLine
                        Paragraph "Best Practices:" -Bold
                        List -Item $List -Numbered
                    }
                }
            }
        } catch {
            Write-PScriboMessage -IsWarning -Message "Roles Section: $($_.Exception.Message)"
        }
    }
    end {
        Show-AbrDebugExecutionTime -End -TitleMessage "DC Role & Features"
    }
}