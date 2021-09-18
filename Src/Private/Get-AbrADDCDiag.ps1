function Get-AbrADDCDiag {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Domain Sites information.
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
            $Domain
    )

    begin {
        Write-PscriboMessage "Collecting AD DCDiag information."
    }

    process {
        function Invoke-DcDiag {
            param(
                [Parameter(Mandatory)]
                [ValidateNotNullOrEmpty()]
                [string]$DomainController
            )
            $result = dcdiag /s:$DomainController
            $result | select-string -pattern '\. (.*) \b(passed|failed)\b test (.*)' | ForEach-Object {
                $obj = @{
                    TestName = $_.Matches.Groups[3].Value
                    TestResult = $_.Matches.Groups[2].Value
                    Entity = $_.Matches.Groups[1].Value
                }
                [pscustomobject]$obj
            }
        }
        $OutObj = @()
        if ($Domain) {
            foreach ($Item in $Domain) {
                $DCs =  Get-ADDomain -Identity $Item | Select-Object -ExpandProperty ReplicaDirectoryServers
                foreach ($DC in $DCs) {
                    $DCDIAG = Invoke-DcDiag -DomainController $DC | Where-Object {$_.TestResult -eq "failed"}
                    foreach ($Result in $DCDIAG) {
                        $inObj = [ordered] @{
                            'DC Name' = $DC
                            'Test Name' = $Result.TestName
                            'Result' = $Result.TestResult
                        }
                        $OutObj += [pscustomobject]$inobj
                    }
                }
            }

            $TableParams = @{
                Name = "AD Domain Controller DCDiag Information - $($Domain.ToString().ToUpper())"
                List = $false
                ColumnWidths = 35, 35, 30
            }
            if ($Report.ShowTableCaptions) {
                $TableParams['Caption'] = "- $($TableParams.Name)"
            }
            $OutObj | Table @TableParams
        }
    }

    end {}

}