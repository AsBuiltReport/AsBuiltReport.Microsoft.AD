function Get-AbrDHCPinAD {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD DHCP Servers information
    .DESCRIPTION

    .NOTES
        Version:        0.9.1
        Author:         Jonathan Colon
        Twitter:        @jcolonfzenpr
        Github:         rebelinux
    .EXAMPLE

    .LINK

    #>
    [CmdletBinding()]
    param (
    )

    begin {
        Write-PScriboMessage "Collecting AD DHCP Servers information of $($ForestInfo.toUpper()). Script Get-AbrDHCPinAD."
    }

    process {
        $DomainInfo = Invoke-Command -Session $TempPssSession { Get-ADDomain ($using:ADSystem).RootDomain -ErrorAction Stop }
        if ($DomainInfo) {
            $DHCPServers = try {
                Get-ADObjectSearch -DN "CN=NetServices,CN=Services,CN=Configuration,$(($DomainInfo).DistinguishedName)" -Filter { objectclass -eq 'dHCPClass' -AND Name -ne 'dhcproot' } -Properties "*" -SelectPrty 'Name' -Session $TempPssSession
            } catch { Out-Null }
        }
        try {
            if ($DHCPServers ) {
                try {
                    $DCServersinAD = @(foreach ($Domain in $ADSystem.Domains) {
                        (Invoke-Command -Session $TempPssSession -ErrorAction Stop { Get-ADDomain -Identity $using:Domain }).ReplicaDirectoryServers
                    })
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
                                    $True {'Yes'}
                                    $false {'No'}
                                    default {'Unknown'}
                                }
                            }
                            $DCHPInfo += [pscustomobject](ConvertTo-HashToYN $inObj)
                        } catch {
                            Write-PScriboMessage -IsWarning "$($_.Exception.Message) (DHCP Item)"
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
                Write-PScriboMessage -IsWarning "No DHCP Infrastructure information found in $($ForestInfo.toUpper()), disabling the section."
            }
        } catch {
            Write-PScriboMessage -IsWarning "$($_.Exception.Message) (DHCP Table)"
        }
    }

    end {}

}