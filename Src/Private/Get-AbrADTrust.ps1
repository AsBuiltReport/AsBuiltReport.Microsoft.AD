function Get-AbrADTrust {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Trust from Domain Controller
    .DESCRIPTION

    .NOTES
        Version:        0.7.15
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
                    $DC = Invoke-Command -Session $TempPssSession {(Get-ADDomain -Identity $using:Domain).ReplicaDirectoryServers | Select-Object -First 1}
                    $Trusts = Invoke-Command -Session $TempPssSession {Get-ADTrust -Filter * -Server $using:DC}
                    if ($Trusts) {
                        Section -Style Heading3 'Domain and Trusts' {
                            $TrustInfo = @()
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
                                    $TrustInfo += [pscustomobject]$inobj
                                }
                                catch {
                                    Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Trust Item)"
                                }
                            }

                            if ($InfoLevel.Domain -ge 2) {
                                foreach ($Trust in $TrustInfo) {
                                    Section -Style NOTOCHeading4 -ExcludeFromTOC "$($Trust.Name)" {
                                        $TableParams = @{
                                            Name = "Trusts - $($Trust.Name)"
                                            List = $true
                                            ColumnWidths = 40, 60
                                        }
                                        if ($Report.ShowTableCaptions) {
                                            $TableParams['Caption'] = "- $($TableParams.Name)"
                                        }
                                        $Trust | Table @TableParams
                                    }
                                }
                            } else {
                                $TableParams = @{
                                    Name = "Trusts - $($Domain.ToString().ToUpper())"
                                    List = $false
                                    Columns = 'Name', 'Path', 'Source', 'Target', 'Direction'
                                    ColumnWidths = 20, 20, 20, 20, 20
                                }
                                if ($Report.ShowTableCaptions) {
                                    $TableParams['Caption'] = "- $($TableParams.Name)"
                                }
                                $TrustInfo | Table @TableParams
                            }
                        }
                    } else {
                        Write-PscriboMessage "No Domain Trust information found, disabling section"
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