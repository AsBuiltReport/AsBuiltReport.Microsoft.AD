function Get-AbrADInfrastructureService {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Domain Controller Infrastructure Services information.
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
        $DC
    )

    begin {
        Write-PScriboMessage -Message ($reportTranslate.GetAbrADInfrastructureService.Collecting -f $DC)
        Show-AbrDebugExecutionTime -Start -TitleMessage 'AD Domain Controller Infrastructure Services'
    }

    process {
        try {
            $DCPssSession = Get-ValidPSSession -ComputerName $DC -SessionName $($DC) -PSSTable ([ref]$PSSTable)
            if ($DCPssSession) {
                $Available = Invoke-CommandWithTimeout -Session $DCPssSession -ScriptBlock { Get-Service 'W32Time' | Select-Object DisplayName, Name, Status }
            } else {
                if (-not $_.Exception.MessageId) {
                    $ErrorMessage = $_.FullyQualifiedErrorId
                } else { $ErrorMessage = $_.Exception.MessageId }
                Write-PScriboMessage -IsWarning -Message "Domain Controller Infrastructure Services Section: New-PSSession: Unable to connect to $($DC): $ErrorMessage"
            }
            if ($Available) {
                $OutObj = [System.Collections.ArrayList]::new()
                $Services = @('CertSvc', 'DHCPServer', 'DNS', 'DFS Replication', 'Intersite Messaging', 'Kerberos Key Distribution Center', 'NetLogon', 'Active Directory Domain Services', 'W32Time', 'ADWS', 'RPCSS', 'EVENTSYSTEM', 'DNSCACHE', 'SAMSS', 'WORKSTATION', 'Spooler')
                foreach ($Service in $Services) {
                    try {
                        $Status = Invoke-CommandWithTimeout -Session $DCPssSession -ScriptBlock { Get-Service $using:Service -ErrorAction SilentlyContinue | Select-Object DisplayName, Name, Status }
                        if ($Status) {
                            $inObj = [ordered] @{
                                $reportTranslate.GetAbrADInfrastructureService.DisplayName = $Status.DisplayName
                                $reportTranslate.GetAbrADInfrastructureService.ShortName = $Status.Name
                                $reportTranslate.GetAbrADInfrastructureService.Status = $Status.Status
                            }
                            $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                        }
                    } catch {
                        Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Domain Controller Infrastructure Services Item)"
                    }
                }

                if ($HealthCheck.DomainController.Services) {
                    $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADInfrastructureService.ShortName) -eq 'Spooler' } | Set-Style -Style Critical
                    $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADInfrastructureService.ShortName) -eq 'DHCPServer' } | Set-Style -Style Critical
                }

                if ($OutObj) {
                    Section -ExcludeFromTOC -Style NOTOCHeading5 $($DC.ToString().ToUpper().Split('.')[0]) {

                        $TableParams = @{
                            Name = "$($reportTranslate.GetAbrADInfrastructureService.TableName) - $($DC.ToString().ToUpper().Split('.')[0])"
                            List = $false
                            ColumnWidths = 40, 40, 20
                        }

                        if ($Report.ShowTableCaptions) {
                            $TableParams['Caption'] = "- $($TableParams.Name)"
                        }

                        $OutObj | Sort-Object -Property $reportTranslate.GetAbrADInfrastructureService.DisplayName | Table @TableParams
                        if ($HealthCheck.DomainController.Services -and (($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADInfrastructureService.ShortName) -eq 'Spooler' -and $_.$($reportTranslate.GetAbrADInfrastructureService.Status) -like 'Running' }) -or ($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADInfrastructureService.ShortName) -eq 'DHCPServer' -and $_.$($reportTranslate.GetAbrADInfrastructureService.Status) -like 'Running' }))) {
                            Paragraph $reportTranslate.GetAbrADInfrastructureService.HealthCheck -Bold -Underline
                            if ($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADInfrastructureService.ShortName) -eq 'Spooler' -and $_.$($reportTranslate.GetAbrADInfrastructureService.Status) -like 'Running' }) {
                                BlankLine
                                Paragraph {
                                    Text $reportTranslate.GetAbrADInfrastructureService.CorrectiveActions -Bold
                                    Text $reportTranslate.GetAbrADInfrastructureService.SpoolerBP
                                }
                            }
                            if ($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADInfrastructureService.ShortName) -eq 'DHCPServer' -and $_.$($reportTranslate.GetAbrADInfrastructureService.Status) -like 'Running' }) {
                                BlankLine
                                Paragraph {
                                    Text $reportTranslate.GetAbrADInfrastructureService.CorrectiveActions -Bold
                                    Text $reportTranslate.GetAbrADInfrastructureService.DHCPServerBP
                                }
                            }
                        }
                    }
                }
            } else {
                Write-PScriboMessage -Message ($reportTranslate.GetAbrADInfrastructureService.NoData -f $DC)
            }
        } catch {
            Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Domain Controller Infrastructure Services Section)"
        }
    }

    end {
        Show-AbrDebugExecutionTime -End -TitleMessage 'AD Domain Controller Infrastructure Services'
    }

}