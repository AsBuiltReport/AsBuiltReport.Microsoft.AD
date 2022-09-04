function Get-AbrADTrust {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Trust from Domain Controller
    .DESCRIPTION

    .NOTES
        Version:        0.7.6
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
        Write-PscriboMessage "Collecting AD Trust information of $($Domain.ToString().ToUpper())."
    }

    process {
        try {
            if ($Domain) {
                try {
                    $DC = Invoke-Command -Session $TempPssSession {Get-ADDomain -Identity $using:Domain | Select-Object -ExpandProperty ReplicaDirectoryServers | Select-Object -First 1}
                    $Trusts = Invoke-Command -Session $TempPssSession {Get-ADTrust -Filter * -Server $using:DC}
                    if ($Trusts) {
                        Section -Style Heading4 'Domain and Trusts' {
                            $OutObj = @()
                            Write-PScriboMessage "Discovered created trusts in domain $Domain"
                            foreach ($Trust in $Trusts) {
                                try {
                                    Write-PscriboMessage "Collecting Active Directory Domain Trust information from $($Trust.Name)"
                                    $inObj = [ordered] @{
                                        'Name' = $Trust.Name
                                        'Path' = ConvertTo-ADCanonicalName -DN $Trust.DistinguishedName -Domain $Domain
                                        'Source' = ConvertTo-ADObjectName $Trust.Source -Session $TempPssSession -DC $DC
                                        'Target' = $Trust.Target
                                        'Direction' = $Trust.Direction
                                        'IntraForest' =  ConvertTo-TextYN $Trust.IntraForest
                                        'Selective Authentication' =  ConvertTo-TextYN $Trust.SelectiveAuthentication
                                        'SID Filtering Forest Aware' =  ConvertTo-TextYN $Trust.SIDFilteringForestAware
                                        'SID Filtering Quarantined' =  ConvertTo-TextYN $Trust.SIDFilteringQuarantined
                                        'Trust Type' = $Trust.TrustType
                                        'Uplevel Only' = ConvertTo-TextYN $Trust.UplevelOnly
                                    }
                                    $OutObj = [pscustomobject]$inobj

                                    $TableParams = @{
                                        Name = "Trusts - $($Domain.ToString().ToUpper())"
                                        List = $true
                                        ColumnWidths = 40, 60
                                    }
                                    if ($Report.ShowTableCaptions) {
                                        $TableParams['Caption'] = "- $($TableParams.Name)"
                                    }
                                    $OutObj | Table @TableParams
                                }
                                catch {
                                    Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Trust Item)"
                                }
                            }
                        }
                    }
                }
                catch {
                    Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Trust Table)"
                }
            }
        }
        catch {
            Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Trust Section)"
        }
    }

    end {}

}