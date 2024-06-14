function Get-AbrADInfrastructureService {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Domain Controller Infrastructure Services information.
    .DESCRIPTION

    .NOTES
        Version:        0.8.2
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
        Write-PScriboMessage "Collecting Active Directory DC Infrastructure Services information of $DC."
    }

    process {
        try {
            $DCPssSession = try { New-PSSession -ComputerName $DC -Credential $Credential -Authentication $Options.PSDefaultAuthentication -Name 'DomainControllerInfrastructureServices' -ErrorAction Stop } catch {
                if (-Not $_.Exception.MessageId) {
                    $ErrorMessage = $_.FullyQualifiedErrorId
                } else { $ErrorMessage = $_.Exception.MessageId }
                Write-PScriboMessage -IsWarning "Domain Controller Infrastructure Services Section: New-PSSession: Unable to connect to $($DC): $ErrorMessage"
            }
            # $DCPssSession = New-PSSession $DC -Credential $Credential -Authentication $Options.PSDefaultAuthentication -Name 'DomainControllerInfrastructureServices'
            if ($DCPssSession) {
                $Available = Invoke-Command -Session $DCPssSession -ScriptBlock { Get-Service "W32Time" | Select-Object DisplayName, Name, Status }
            }
            if ($Available) {
                $OutObj = @()
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
                            $OutObj += [pscustomobject]$inobj
                        }
                    } catch {
                        Write-PScriboMessage -IsWarning "$($_.Exception.Message) (Domain Controller Infrastructure Services Item)"
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
                                Text "Disable Print Spooler service on DCs and all servers that do not perform Print services."
                            }
                        }
                    }
                }
            } else {
                Write-PScriboMessage -IsWarning "No Infrastructure Services Status information found in $DC, disabling the section."
            }
            if ($DCPssSession) {
                Remove-PSSession -Session $DCPssSession
            }
        } catch {
            Write-PScriboMessage -IsWarning "$($_.Exception.Message) (Domain Controller Infrastructure Services Section)"
        }
    }

    end {}

}