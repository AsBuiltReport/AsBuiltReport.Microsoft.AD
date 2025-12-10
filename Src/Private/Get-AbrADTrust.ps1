function Get-AbrADTrust {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Trust from Domain Controller
    .DESCRIPTION

    .NOTES
        Version:        0.9.8
        Author:         Jonathan Colon
        Twitter:        @jcolonfzenpr
        Github:         rebelinux
    .EXAMPLE

    .LINK

    #>
    [CmdletBinding()]
    param (
        $Domain,
        [string]$ValidDCFromDomain
    )

    begin {
        Write-PScriboMessage -Message "Collecting AD Trust information of $($Domain.DNSRoot.ToString().ToUpper())."
        Show-AbrDebugExecutionTime -Start -TitleMessage "AD Trust"
    }

    process {
        try {
            if ($Domain) {
                try {
                    $Trusts = Invoke-CommandWithTimeout -Session $TempPssSession -ScriptBlock { Get-ADTrust -Filter * -Properties * -Server $using:ValidDCFromDomain }
                    if ($Trusts) {
                        Section -Style Heading3 'Domain and Trusts' {
                            $TrustInfo = [System.Collections.ArrayList]::new()
                            foreach ($Trust in $Trusts) {
                                try {
                                    $inObj = [ordered] @{
                                        'Name' = $Trust.Name
                                        'Path' = $Trust.CanonicalName
                                        'Source' = ConvertTo-ADObjectName $Trust.Source -Session $TempPssSession -DC $ValidDCFromDomain
                                        'Target' = $Trust.Target
                                        'Trust Type' = switch ($Trust.TrustType) {
                                            1 { "Downlevel (NT domain)" }
                                            2 { "Uplevel (Active Directory)" }
                                            3 { "MIT (Kerberos Realm Trust )" }
                                            4 { "DCE" }
                                            default { $Trust.TrustType }
                                        }
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
                                        'Trust Direction' = switch ($Trust.TrustDirection) {
                                            0 { "Disabled (The trust relationship exists but has been disabled)" }
                                            1 { "Inbound (Trusting domain)" }
                                            2 { "Outbound (Trusted domain)" }
                                            3 { "Bidirectional (two-way trust)" }
                                            default { $Trust.TrustDirection }
                                        }
                                        'Intra Forest' = $Trust.IntraForest
                                        'Selective Authentication' = $Trust.SelectiveAuthentication
                                        'SID Filtering Forest Aware' = $Trust.SIDFilteringForestAware
                                        'SID Filtering Quarantined' = $Trust.SIDFilteringQuarantined
                                        'TGT Delegation' = $Trust.TGTDelegation
                                        'Kerberos AES Encryption' = $Trust.UsesAESKeys
                                        'Kerberos RC4 Encryption' = $Trust.UsesRC4Encryption
                                        'Uplevel Only' = $Trust.UplevelOnly
                                    }
                                    $TrustInfo.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                                } catch {
                                    Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Trust Item)"
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
                                    Name = "Trusts - $($Domain.DNSRoot.ToString().ToUpper())"
                                    List = $false
                                    Columns = 'Name', 'Path', 'Source', 'Target', 'Trust Direction'
                                    ColumnWidths = 20, 20, 20, 20, 20
                                }
                                if ($Report.ShowTableCaptions) {
                                    $TableParams['Caption'] = "- $($TableParams.Name)"
                                }
                                $TrustInfo | Table @TableParams
                            }
                            if ($Options.EnableDiagrams) {
                                try {
                                    try {
                                        $Graph = Get-AbrDiagrammer -DiagramType "Trusts" -DiagramOutput base64 -DomainController $ValidDCFromDomain
                                    } catch {
                                        Write-PScriboMessage -IsWarning -Message "Domain and Trusts Diagram Graph: $($_.Exception.Message)"
                                    }

                                    if ($Graph) {
                                        if ((Get-DiaImagePercent -GraphObj $Graph).Width -gt 600) { $ImagePrty = 20 } else { $ImagePrty = 40 }
                                        Section -Style Heading3 "Domain and Trusts Diagram." {
                                            Image -Base64 $Graph -Text "Domain and Trusts Diagram" -Percent $ImagePrty -Align Center
                                            Paragraph "Image preview: Opens the image in a new tab to view it at full resolution." -Tabs 2
                                        }
                                        BlankLine -Count 2
                                    }
                                } catch {
                                    Write-PScriboMessage -IsWarning -Message "Domain and Trusts Diagram Section: $($_.Exception.Message)"
                                }
                            }
                        }
                    } else {
                        Write-PScriboMessage -Message "No Domain Trust information found in $($Domain.DNSRoot), Disabling this section."
                    }
                } catch {
                    Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Trust Table)"
                }
            }
        } catch {
            Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Trust Section)"
        }
    }

    end {
        Show-AbrDebugExecutionTime -End -TitleMessage "AD Trust"
    }

}