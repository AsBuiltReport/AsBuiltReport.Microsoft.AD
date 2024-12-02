function Get-AbrADTrust {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Trust from Domain Controller
    .DESCRIPTION

    .NOTES
        Version:        0.9.2
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
                    $DC = Get-ValidDCfromDomain -Domain $Domain
                    $Trusts = Invoke-Command -Session $TempPssSession { Get-ADTrust -Filter * -Properties * -Server $using:DC }
                    if ($Trusts) {
                        Section -Style Heading3 'Domain and Trusts' {
                            $TrustInfo = @()
                            foreach ($Trust in $Trusts) {
                                try {
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
                                            default { $Trust.TrustAttributes }
                                        }
                                        'Trust Direction' = Switch ($Trust.TrustDirection) {
                                            0 { "Disabled (The trust relationship exists but has been disabled)" }
                                            1 { "Inbound (TrustING domain)" }
                                            2 { "Outbound (TrustED domain)" }
                                            3 { "Bidirectional (two-way trust)" }
                                            default { $Trust.TrustDirection }
                                        }
                                        'IntraForest' = $Trust.IntraForest
                                        'Selective Authentication' = $Trust.SelectiveAuthentication
                                        'SID Filtering Forest Aware' = $Trust.SIDFilteringForestAware
                                        'SID Filtering Quarantined' = $Trust.SIDFilteringQuarantined
                                        'TGT Delegation' = $Trust.TGTDelegation
                                        'Kerberos AES Encryption' = $Trust.UsesAESKeys
                                        'Kerberos RC4 Encryption' = $Trust.UsesRC4Encryption
                                        'Uplevel Only' = $Trust.UplevelOnly
                                    }
                                    $TrustInfo += [pscustomobject](ConvertTo-HashToYN $inObj)
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
                                    Columns = 'Name', 'Path', 'Source', 'Target', 'Trust Direction'
                                    ColumnWidths = 20, 20, 20, 20, 20
                                }
                                if ($Report.ShowTableCaptions) {
                                    $TableParams['Caption'] = "- $($TableParams.Name)"
                                }
                                $TrustInfo | Table @TableParams
                            }
                            if ($Domain -eq $ADSystem.RootDomain) {
                                try {
                                    try {
                                        $Graph = New-ADDiagram -Target $System -Credential $Credential -Format base64 -Direction top-to-bottom -DiagramType Trusts
                                    } catch {
                                        Write-PScriboMessage -IsWarning "Domain and Trusts Diagram Graph: $($_.Exception.Message)"
                                    }

                                    if ($Graph) {
                                        If ((Get-DiaImagePercent -GraphObj $Graph).Width -gt 1500) { $ImagePrty = 10 } else { $ImagePrty = 50 }
                                        Section -Style Heading3 "Domain and Trusts Diagram." {
                                            Image -Base64 $Graph -Text "Domain and Trusts Diagram" -Percent $ImagePrty -Align Center
                                            Paragraph "Image preview: Opens the image in a new tab to view it at full resolution." -Tabs 2
                                        }
                                        BlankLine -Count 2
                                    }
                                } catch {
                                    Write-PScriboMessage -IsWarning "Domain and Trusts Diagram Section: $($_.Exception.Message)"
                                }
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