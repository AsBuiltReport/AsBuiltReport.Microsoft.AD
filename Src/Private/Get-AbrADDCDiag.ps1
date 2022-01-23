function Get-AbrADDCDiag {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Domain Sites information.
    .DESCRIPTION

    .NOTES
        Version:        0.6.2
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
            $DC,
            $Session
    )

    begin {
        Write-PscriboMessage "Discovering Active Directory DCDiag information for domain $Domain."
    }

    process {
        $OutObj = @()
        if ($DC) {
            try {
                Write-PscriboMessage "Discovering Active Directory DCDiag information for DC $DC."
                $DCDIAG = Invoke-DcDiag -DomainController $DC
                if ($DCDIAG) {
                    Write-PscriboMessage "Discovered Active Directory DCDiag information for DC $DC."
                    foreach ($Result in $DCDIAG) {
                        try {
                            Write-PscriboMessage "Collecting Active Directory DCDiag test '$($Result.TestName)' for DC $DC."
                            $inObj = [ordered] @{
                                'DC Name' = $DC
                                'Test Name' = $Result.TestName
                                'Result' = $Result.TestResult
                            }
                            $OutObj += [pscustomobject]$inobj
                        }
                        catch {
                            Write-PscriboMessage -IsWarning $_.Exception.Message
                        }
                    }
                    if ($HealthCheck.DomainController.Diagnostic) {
                        $OutObj | Where-Object { $_.'Result' -like 'failed'} | Set-Style -Style Critical -Property 'Result'
                    }
                    $TableParams = @{
                        Name = "Domain Controller DCDiag - $($DC.ToString().split('.')[0].ToUpper())"
                        List = $false
                        ColumnWidths = 35, 35, 30
                    }
                    if ($Report.ShowTableCaptions) {
                        $TableParams['Caption'] = "- $($TableParams.Name)"
                    }
                    $OutObj | Table @TableParams
                }
            }
            catch {
                Write-PscriboMessage -IsWarning $_.Exception.Message
            }
        }
    }

    end {}

}