function Get-AbrADDCDiag {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Domain Sites information.
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
            $result | select-string -pattern '\. (.*) \b(passed|failed)\b test (.*)' | foreach {
                $obj = @{
                    TestName = $_.Matches.Groups[3].Value
                    TestResult = $_.Matches.Groups[2].Value
                    Entity = $_.Matches.Groups[1].Value
                }
                [pscustomobject]$obj
            }
        }
        $Data = (Get-ADForest).Domains
        $OutObj = @()
        if ($Data) {
            foreach ($Item in $Data.Split(" ")) {
                $Domain =  Get-ADDomain -Identity $Item | Select-Object -ExpandProperty ReplicaDirectoryServers
                foreach ($DC in $Domain) {
                    $DCDIAG = Invoke-DcDiag -DomainController $DC | Where-Object {$_.TestResult -eq "failed"}
                    foreach ($a in $DCDIAG) {
                        $inObj = [ordered] @{
                            'DC Name' = $DC
                            'Test Name' = $a.TestName
                            'Result' = $a.TestResult
                        }
                        $OutObj += [pscustomobject]$inobj
                    }
                }
            }

            $TableParams = @{
                Name = "AD Domain Controller DCDiag Information - $($ForestInfo)"
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