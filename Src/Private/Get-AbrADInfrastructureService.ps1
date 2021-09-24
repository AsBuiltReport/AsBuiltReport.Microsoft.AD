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
            $DC,
            [pscredential]
            $Cred
    )

    begin {
        Write-PscriboMessage "Discovering Active Directory DC Infrastructure Services information of $DC."
    }

    process {
        Write-PscriboMessage "Discovering AD Domain Controller Time Source information for $DC."
        try {
            $DCPssSession = New-PSSession $DC -Credential $Cred -Authentication Default
            $Available = Invoke-Command -Session $DCPssSession -ScriptBlock {Get-Service "W32Time" | Select-Object DisplayName, Name, Status}
            if ($Available) {
                Write-PscriboMessage "Discovered Active Directory DC Infrastructure Services information of $DC."
                Section -Style Heading5 "Domain Controller Infrastructure Services Status of $($DC.ToString().ToUpper().Split(".")[0])" {
                    Paragraph "The following section provides a summary of the Domain Controller Infrastructure services status."
                    BlankLine
                    $OutObj = @()
                    if ($DC) {
                        $Services = @('DNS','DFS Replication','Intersite Messaging','Kerberos Key Distribution Center','NetLogon','Active Directory Domain Services','W32Time')
                        foreach ($Service in $Services) {
                            $Status = Invoke-Command -Session $DCPssSession -ScriptBlock {Get-Service $using:Service | Select-Object DisplayName, Name, Status}
                            Write-PscriboMessage "Collecting Domain Controller '$($Status.DisplayName)' Services status on $DC."
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
                    Remove-PSSession -Session $DCPssSession
                }
            }
        }
        catch {
            Write-PscriboMessage -IsWarning "Error: Connecting to remote server $DC failed: WinRM cannot complete the operation."
            Write-PScriboMessage -IsDebug $_.Exception.Message
        }
    }

    end {}

}