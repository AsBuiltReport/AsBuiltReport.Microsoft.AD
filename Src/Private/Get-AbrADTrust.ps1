function Get-AbrADTrust {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Trust from Domain Controller
    .DESCRIPTION

    .NOTES
        Version:        0.8.1
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
        Write-PScriboMessage "Collecting AD Trust information of $($Domain.ToString().ToUpper())."
    }

    process {
        try {
            if ($Domain) {
                try {
                    $DC = Invoke-Command -Session $TempPssSession { (Get-ADDomain -Identity $using:Domain).ReplicaDirectoryServers | Select-Object -First 1 }
                    $Trusts = Invoke-Command -Session $TempPssSession { Get-ADTrust -Filter * -Properties * -Server $using:DC }
                    if ($Trusts) {
                        Section -Style Heading3 'Domain and Trusts' {
                            $TrustInfo = @()
                            foreach ($Trust in $Trusts) {
                                try {
                                    Write-PScriboMessage "Collecting Active Directory Domain Trust information from $($Trust.Name)"
                                    $inObj = [ordered] @{
                                        'Name' = $Trust.Name
                                        'Path' = ConvertTo-ADCanonicalName -DN $Trust.DistinguishedName -Domain $Domain
                                        'Source' = ConvertTo-ADObjectName $Trust.Source -Session $TempPssSession -DC $DC
                                        'Target' = $Trust.Target
                                        'Trust Type' = $Trust.TrustType
                                        'Trust Attributes' = switch ($Trust.TrustAttributes) {
                                            1 { "Non-Transitive" }
                                            2 { "Uplevel clients only (Windows 2000 or newer" }
                                            4 { "Quarantined Domain (External)" }
                                            8 { "Forest Trust" }
                                            16 { "Cross-Organizational Trust (Selective Authentication)" }
                                            32 { "Intra-Forest Trust (trust within the forest)" }
                                            64 { "Inter-Forest Trust (trust with another forest)" }
                                            default {$Trust.TrustAttributes}
                                        }
                                        'Trust Direction' = Switch ($Trust.TrustDirection) {
                                            0 { "Disabled (The trust relationship exists but has been disabled)" }
                                            1 { "Inbound (TrustING domain)" }
                                            2 { "Outbound (TrustED domain)" }
                                            3 { "Bidirectional (two-way trust)" }
                                            default {$Trust.TrustDirection}
                                        }
                                        'IntraForest' = ConvertTo-TextYN $Trust.IntraForest
                                        'Selective Authentication' = ConvertTo-TextYN $Trust.SelectiveAuthentication
                                        'SID Filtering Forest Aware' = ConvertTo-TextYN $Trust.SIDFilteringForestAware
                                        'SID Filtering Quarantined' = ConvertTo-TextYN $Trust.SIDFilteringQuarantined
                                        'TGT Delegation' = ConvertTo-TextYN $Trust.TGTDelegation
                                        'Kerberos AES Encryption' = ConvertTo-TextYN $Trust.UsesAESKeys
                                        'Kerberos RC4 Encryption' = ConvertTo-TextYN $Trust.UsesRC4Encryption
                                        'Uplevel Only' = ConvertTo-TextYN $Trust.UplevelOnly
                                    }
                                    $TrustInfo += [pscustomobject]$inobj
                                } catch {
                                    Write-PScriboMessage -IsWarning "$($_.Exception.Message) (Trust Item)"
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
                        Write-PScriboMessage -IsWarning "No Domain Trust information found in $Domain, disabling the section."
                    }
                } catch {
                    Write-PScriboMessage -IsWarning "$($_.Exception.Message) (Trust Table)"
                }
            }
        } catch {
            Write-PScriboMessage -IsWarning "$($_.Exception.Message) (Trust Section)"
        }
    }

    end {}

}