function Get-AbrDHCPinAD {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD DHCP Servers information
    .DESCRIPTION

    .NOTES
        Version:        0.9.5
        Author:         Jonathan Colon
        Twitter:        @jcolonfzenpr
        Github:         rebelinux
    .EXAMPLE

    .LINK

    #>
    [CmdletBinding()]
    param (
        [ref]$DomainStatus
    )

    begin {
        Write-PScriboMessage -Message "Collecting AD DHCP Servers information of $($ForestInfo.toUpper())."
        Show-AbrDebugExecutionTime -Start -TitleMessage "DHCP Infrastructure"
    }

    process {
        $DomainInfo = Invoke-Command -Session $TempPssSession { Get-ADDomain ($using:ADSystem).RootDomain -ErrorAction Stop }
        if ($DomainInfo) {
            $DHCPServers = try {
                Get-ADObjectSearch -DN "CN=NetServices,CN=Services,CN=Configuration,$(($DomainInfo).DistinguishedName)" -Filter { objectclass -eq 'dHCPClass' -AND Name -ne 'dhcproot' } -Properties "*" -SelectPrty 'Name' -Session $TempPssSession
            } catch { Out-Null }
        }
        try {
            if ($Options.Exclude.Domains) {
                $DHCPServers = $DHCPServers | Where-Object { $_.Name -notmatch $Options.Exclude.Domains }
            }
            if ($DHCPServers) {
                try {
                    $DCServersinAD = @(
                        foreach ($Domain in $ADSystem.Domains | Where-Object { $_ -notin $Options.Exclude.Domains }) {
                            try {
                                if (Get-ValidDCfromDomain -Domain $Domain -DCStatus ([ref]$DCStatus)) {
                                    (Invoke-Command -Session $TempPssSession -ErrorAction Stop { Get-ADDomain -Identity $using:Domain }).ReplicaDirectoryServers
                                } else {
                                    $DomainStatus.Value += @{
                                        Name = $Domain
                                        Status = 'Offline'
                                    }
                                    Write-PScriboMessage -IsWarning -Message "Unable to get an available DC in $Domain domain. Removing it from the report."
                                }
                            } catch { Out-Null }
                        }
                    )
                } catch { Out-Null }
                Section -Style Heading3 'DHCP Infrastructure' {
                    Paragraph "The following section provides a summary of the DHCP infrastructure configured on Active Directory."
                    BlankLine
                    $DCHPInfo = @()
                    foreach ($DHCPServer in $DHCPServers) {
                        try {
                            $inObj = [ordered] @{
                                'Server Name' = $DHCPServer.Name
                                'Is Domain Controller?' = Switch ($DHCPServer.Name -in $DCServersinAD) {
                                    $True { 'Yes' }
                                    $false { 'No' }
                                    default { 'Unknown' }
                                }
                            }
                            $DCHPInfo += [pscustomobject](ConvertTo-HashToYN $inObj)
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (DHCP Item)"
                        }
                    }

                    $TableParams = @{
                        Name = "DHCP Infrastructure - $($ForestInfo.toUpper())"
                        List = $false
                        ColumnWidths = 50, 50
                    }
                    if ($Report.ShowTableCaptions) {
                        $TableParams['Caption'] = "- $($TableParams.Name)"
                    }
                    $DCHPInfo | Sort-Object -Property 'Server Name' | Table @TableParams
                }
            } else {
                Write-PScriboMessage -Message "No DHCP Infrastructure information found in $($ForestInfo.toUpper()), Disabling this section."
            }
        } catch {
            Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (DHCP Table)"
        }
    }

    end {
        Show-AbrDebugExecutionTime -End -TitleMessage "DHCP Infrastructure"
    }

}