function Get-AbrADInfrastructureService {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Domain Controller Infrastructure Services information.
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
        Write-PScriboMessage -Message "Collecting Active Directory DC Infrastructure Services information of $DC."
        Show-AbrDebugExecutionTime -Start -TitleMessage "AD Domain Controller Infrastructure Services"
    }

    process {
        try {
            $DCPssSession = Get-ValidPSSession -ComputerName $DC -SessionName $($DC) -PSSTable ([ref]$PSSTable)
            if ($DCPssSession) {
                $Available = Invoke-Command -Session $DCPssSession -ScriptBlock { Get-Service "W32Time" | Select-Object DisplayName, Name, Status }
            } else {
                if (-Not $_.Exception.MessageId) {
                    $ErrorMessage = $_.FullyQualifiedErrorId
                } else { $ErrorMessage = $_.Exception.MessageId }
                Write-PScriboMessage -IsWarning -Message "Domain Controller Infrastructure Services Section: New-PSSession: Unable to connect to $($DC): $ErrorMessage"
            }
            if ($Available) {
                $OutObj = [System.Collections.ArrayList]::new()
                $Services = @('CertSvc', 'DHCPServer', 'DNS', 'DFS Replication', 'Intersite Messaging', 'Kerberos Key Distribution Center', 'NetLogon', 'Active Directory Domain Services', 'W32Time', 'ADWS', 'RPCSS', 'EVENTSYSTEM', 'DNSCACHE', 'SAMSS', 'WORKSTATION', 'Spooler')
                foreach ($Service in $Services) {
                    try {
                        $Status = Invoke-Command -Session $DCPssSession -ScriptBlock { Get-Service $using:Service -ErrorAction SilentlyContinue | Select-Object DisplayName, Name, Status }
                        if ($Status) {
                            $inObj = [ordered] @{
                                'Display Name' = $Status.DisplayName
                                'Short Name' = $Status.Name
                                'Status' = $Status.Status
                            }
                            $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                        }
                    } catch {
                        Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Domain Controller Infrastructure Services Item)"
                    }
                }

                if ($HealthCheck.DomainController.Services) {
                    $OutObj | Where-Object { $_.'Status' -notlike 'Running' -and $_.'Short Name' -notlike 'Spooler' } | Set-Style -Style Warning -Property 'Status'
                    $OutObj | Where-Object { $_.'Short Name' -eq 'Spooler' } | Set-Style -Style Critical
                }

                if ($OutObj) {
                    Section -ExcludeFromTOC -Style NOTOCHeading5 $($DC.ToString().ToUpper().Split(".")[0]) {

                        $TableParams = @{
                            Name = "Infrastructure Services Status - $($DC.ToString().ToUpper().Split(".")[0])"
                            List = $false
                            ColumnWidths = 40, 40, 20
                        }

                        if ($Report.ShowTableCaptions) {
                            $TableParams['Caption'] = "- $($TableParams.Name)"
                        }

                        $OutObj | Sort-Object -Property 'Display Name' | Table @TableParams
                        if ($HealthCheck.DomainController.Services -and ($OutObj | Where-Object { $_.'Short Name' -eq 'Spooler' -and $_.'Status' -like 'Running' })) {
                            Paragraph "Health Check:" -Bold -Underline
                            BlankLine
                            Paragraph {
                                Text "Corrective Actions:" -Bold
                                Text "The Print Spooler service has been known to have vulnerabilities that can be exploited by attackers to gain unauthorized access or execute malicious code. Disabling this service on Domain Controllers and other critical servers that do not require print services can help reduce the attack surface and improve the overall security posture of your Active Directory environment."
                            }
                        }
                    }
                }
            } else {
                Write-PScriboMessage -Message "No Infrastructure Services Status information found in $DC, Disabling this section."
            }
        } catch {
            Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Domain Controller Infrastructure Services Section)"
        }
    }

    end {
        Show-AbrDebugExecutionTime -End -TitleMessage "AD Domain Controller Infrastructure Services"
    }

}