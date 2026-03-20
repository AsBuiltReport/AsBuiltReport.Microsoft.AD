function Get-AbrDHCPinAD {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD DHCP Servers information
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
    )

    begin {
        Write-PScriboMessage -Message ($reportTranslate.GetAbrDHCPinAD.Collecting -f $ForestInfo.toUpper())
        Show-AbrDebugExecutionTime -Start -TitleMessage 'DHCP Infrastructure'
    }

    process {
        $DomainInfo = Invoke-CommandWithTimeout -Session $TempPssSession -ScriptBlock { Get-ADDomain ($using:ADSystem).RootDomain -ErrorAction Stop }
        if ($DomainInfo) {
            $DHCPServers = try {
                Get-ADObjectSearch -DN "CN=NetServices,CN=Services,CN=Configuration,$(($DomainInfo).DistinguishedName)" -Filter { objectclass -eq 'dHCPClass' -AND Name -ne 'dhcproot' } -Properties '*' -SelectPrty 'Name' -Session $TempPssSession
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
                                (Invoke-CommandWithTimeout -Session $TempPssSession -ErrorAction Stop -ScriptBlock { Get-ADDomain -Identity $using:Domain }).ReplicaDirectoryServers
                            } catch { Out-Null }
                        }
                    )
                } catch { Out-Null }
                Section -Style Heading3 $reportTranslate.GetAbrDHCPinAD.Heading {
                    Paragraph $reportTranslate.GetAbrDHCPinAD.Paragraph
                    BlankLine
                    $DCHPInfo = [System.Collections.ArrayList]::new()
                    foreach ($DHCPServer in $DHCPServers) {
                        try {
                            $inObj = [ordered] @{
                                $reportTranslate.GetAbrDHCPinAD.ServerName = $DHCPServer.Name
                                $reportTranslate.GetAbrDHCPinAD.IsDomainController = switch ($DHCPServer.Name -in $DCServersinAD) {
                                    $True { $reportTranslate.GetAbrDHCPinAD.Yes }
                                    $false { $reportTranslate.GetAbrDHCPinAD.No }
                                    default { $reportTranslate.GetAbrDHCPinAD.Unknown }
                                }
                            }
                            $DCHPInfo.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (DHCP Item)"
                        }
                    }

                    $TableParams = @{
                        Name = "$($reportTranslate.GetAbrDHCPinAD.Heading) - $($ForestInfo.toUpper())"
                        List = $false
                        ColumnWidths = 50, 50
                    }
                    if ($Report.ShowTableCaptions) {
                        $TableParams['Caption'] = "- $($TableParams.Name)"
                    }
                    $DCHPInfo | Sort-Object -Property $reportTranslate.GetAbrDHCPinAD.ServerName | Table @TableParams
                }
            } else {
                Write-PScriboMessage -Message "No DHCP Infrastructure information found in $($ForestInfo.toUpper()), Disabling this section."
                Paragraph $reportTranslate.GetAbrDHCPinAD.NotFound
                BlankLine
            }
        } catch {
            Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (DHCP Table)"
        }
    }

    end {
        Show-AbrDebugExecutionTime -End -TitleMessage 'DHCP Infrastructure'
    }

}
