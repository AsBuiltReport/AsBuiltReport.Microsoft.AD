function Get-AbrADInfrastructureService {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Domain Controller Infrastructure Services information.
    .DESCRIPTION

    .NOTES
        Version:        0.2.0
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
            $Domain,
            [string]
            $DC
    )

    begin {
        Write-PscriboMessage "Collecting AD Domain Controller Infrastructure Services information of $DC."
    }

    process {
        $Available = Invoke-Command -ComputerName $DC -ScriptBlock {Get-Service "W32Time" | Select-Object DisplayName, Name, Status}
        if ($Available) {
            Section -Style Heading5 "Domain Controller Infrastructure Services Status of $($DC.ToString().ToUpper().Split(".")[0])" {
                Paragraph "The following section provides a summary of the Domain Controller Infrastructure services status."
                BlankLine
                $OutObj = @()
                if ($Domain -and $DC) {
                    $Services = @('DNS','DFS Replication','Intersite Messaging','Kerberos Key Distribution Center','NetLogon','Active Directory Domain Services','W32Time')
                    foreach ($Service in $Services) {
                        $Status = Invoke-Command -ComputerName $DC -ScriptBlock {Get-Service $using:Service | Select-Object DisplayName, Name, Status}
                        $inObj = [ordered] @{
                            'Display Name' = $Status.DisplayName
                            'Short Name' = $Status.Name
                            'Status' = $Status.Status
                        }
                        $OutObj += [pscustomobject]$inobj
                    }

                    if ($HealthCheck.DomainController.Services) {
                        $OutObj | Where-Object { $_.'Status' -notlike 'Running'} | Set-Style -Style Warning -Property 'Status'
                    }

                    $TableParams = @{
                        Name = "Domain Controller Infrastructure Services Status Information."
                        List = $false
                        ColumnWidths = 40, 40, 20
                    }
                    if ($Report.ShowTableCaptions) {
                        $TableParams['Caption'] = "- $($TableParams.Name)"
                    }
                    $OutObj | Table @TableParams
                }
            }
        }
    }

    end {}

}