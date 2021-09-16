function Get-AbrADInfrastructureService {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Domain Controller Infrastructure Services information.
    .DESCRIPTION

    .NOTES
        Version:        0.1.0
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
        Section -Style Heading5 "DC Infrastructure Services Status of $($DC.ToString().ToUpper().Split(".")[0])" {
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

    end {}

}