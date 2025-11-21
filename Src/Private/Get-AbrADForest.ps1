function Get-AbrADForest {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD information from Domain Controller
    .DESCRIPTION

    .NOTES
        Version:        0.9.7
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
        $reportTranslate = $reportTranslate.GetAbrADForest
        Write-PScriboMessage -Message $reportTranslate.Collecting
        Show-AbrDebugExecutionTime -Start -TitleMessage 'AD Forest'
    }

    process {
        try {
            $Data = Invoke-Command -Session $TempPssSession { Get-ADForest }
            $ForestInfo = $Data.RootDomain.toUpper()
            $DomainDN = Invoke-Command -Session $TempPssSession { (Get-ADDomain -Identity (Get-ADForest | Select-Object -ExpandProperty RootDomain )).DistinguishedName }
            $TombstoneLifetime = Invoke-Command -Session $TempPssSession { Get-ADObject "CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,$using:DomainDN" -Properties tombstoneLifetime | Select-Object -ExpandProperty tombstoneLifetime }
            $ADVersion = Invoke-Command -Session $TempPssSession { Get-ADObject (Get-ADRootDSE).schemaNamingContext -property objectVersion | Select-Object -ExpandProperty objectVersion }
            $ValuedsHeuristics = Invoke-Command -Session $TempPssSession { Get-ADObject -Identity "CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,$(($using:DomainDN))" -Properties dsHeuristics -ErrorAction SilentlyContinue }

            if ($ADVersion -eq '88') { $server = 'Windows Server 2019' }
            elseif ($ADVersion -eq '91') { $server = 'Windows Server 2025' }
            elseif ($ADVersion -eq '87') { $server = 'Windows Server 2016' }
            elseif ($ADVersion -eq '69') { $server = 'Windows Server 2012 R2' }
            elseif ($ADVersion -eq '56') { $server = 'Windows Server 2012' }
            elseif ($ADVersion -eq '47') { $server = 'Windows Server 2008 R2' }
            elseif ($ADVersion -eq '44') { $server = 'Windows Server 2008' }
            elseif ($ADVersion -eq '31') { $server = 'Windows Server 2003 R2' }
            elseif ($ADVersion -eq '30') { $server = 'Windows Server 2003' }
            $OutObj = [System.Collections.ArrayList]::new()
            if ($Data) {
                foreach ($Item in $Data) {
                    try {
                        $inObj = [ordered] @{
                            $reportTranslate.ForestName = $Item.RootDomain
                            $reportTranslate.ForestFunctionalLevel = $Item.ForestMode
                            $reportTranslate.SchemaVersion = $reportTranslate.SchemaVersionValue -f $ADVersion, $server
                            $reportTranslate.TombstoneLifetime = $TombstoneLifetime
                            $reportTranslate.Domains = $Item.Domains -join '; '
                            $reportTranslate.GlobalCatalogs = $Item.GlobalCatalogs -join '; '
                            $reportTranslate.DomainsCount = $Item.Domains.Count
                            $reportTranslate.GlobalCatalogsCount = $Item.GlobalCatalogs.Count
                            $reportTranslate.SitesCount = $Item.Sites.Count
                            $reportTranslate.ApplicationPartitions = $Item.ApplicationPartitions
                            $reportTranslate.PartitionsContainer = [string]$Item.PartitionsContainer
                            $reportTranslate.SPNSuffixes = $Item.SPNSuffixes
                            $reportTranslate.UPNSuffixes = ($Item.UPNSuffixes -join ', ')
                            $reportTranslate.AnonymousAccess = & {
                                if (($ValuedsHeuristics.dsHeuristics -eq "") -or ($ValuedsHeuristics.dsHeuristics.Length -lt 7)) {
                                    $reportTranslate.AnonymousAccessDisabled
                                } elseif (($ValuedsHeuristics.dsHeuristics.Length -ge 7) -and ($ValuedsHeuristics.dsHeuristics[6] -eq "2")) {
                                    $reportTranslate.AnonymousAccessEnabled
                                }
                            }
                        }
                        $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                    } catch {
                        Write-PScriboMessage -IsWarning $_.Exception.Message
                    }
                }

                if ($HealthCheck.Domain.Security) {
                    $OutObj | Where-Object { $_.'Anonymous Access (dsHeuristics)' -eq 'Enabled' } | Set-Style -Style Critical -Property 'Anonymous Access (dsHeuristics)'
                    $OutObj | Where-Object { $_.'Tombstone Lifetime (days)' -lt 180 } | Set-Style -Style Warning -Property 'Tombstone Lifetime (days)'
                }

                $TableParams = @{
                    Name = "Forest Summary - $($ForestInfo)"
                    List = $true
                    ColumnWidths = 40, 60
                }
                if ($Report.ShowTableCaptions) {
                    $TableParams['Caption'] = "- $($TableParams.Name)"
                }
                $OutObj | Table @TableParams
                if ($HealthCheck.Domain.Security -and ($OutObj | Where-Object { $_.'Anonymous Access (dsHeuristics)' -eq 'Enabled' }) ) {
                    Paragraph "Health Check:" -Bold -Underline
                    BlankLine
                    if ($OutObj | Where-Object { $_.'Anonymous Access (dsHeuristics)' -eq 'Enabled' }) {
                        Paragraph {
                            Text "Best Practice:" -Bold
                            Text "Anonymous access to Active Directory forest data above the rootDSE level must be disabled. This is to ensure that unauthorized users cannot access sensitive directory information, which could potentially be exploited for malicious purposes."
                        }
                        BlankLine
                        Paragraph "Reference:" -Bold
                        BlankLine
                        Paragraph "https://www.stigviewer.com/stig/active_directory_forest/2016-02-19/finding/V-8555" -Color blue
                    }
                    if ($OutObj | Where-Object { $_.'Tombstone Lifetime (days)' -lt 180 }) {
                        Paragraph {
                            Text "Best Practice:" -Bold
                            Text "Set the Tombstone Lifetime to a minimum of 180 days to ensure that deleted objects are retained for a sufficient period before being permanently removed from the directory. This allows for recovery of accidentally deleted objects and helps in maintaining the integrity of the Active Directory environment."
                        }
                    }
                }
                if ($Options.EnableDiagrams) {
                    try {
                        try {
                            $Graph = Get-AbrDiagrammer -DiagramType 'Forest' -DiagramOutput base64 -PSSessionObject $TempPssSession
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "Forest Diagram Graph: $($_.Exception.Message)"
                        }

                        if ($Graph) {
                            if ((Get-DiaImagePercent -GraphObj $Graph).Width -gt 600) { $ImagePrty = 20 } else { $ImagePrty = 40 }
                            Section -Style Heading3 "Forest Diagram." {
                                Image -Base64 $Graph -Text "Forest Diagram" -Percent $ImagePrty -Align Center
                                Paragraph "Image preview: Opens the image in a new tab to view it at full resolution." -Tabs 2
                            }
                            BlankLine -Count 2
                        }
                    } catch {
                        Write-PScriboMessage -IsWarning -Message "Forest Diagram Section: $($_.Exception.Message)"
                    }
                }
            }
        } catch {
            Write-PScriboMessage -IsWarning $_.Exception.Message
        }
        try {
            $ConfigNCDN = $Data.PartitionsContainer.Split(',') | Select-Object -Skip 1
            $rootCA = Get-ADObjectSearch -DN "CN=Certification Authorities,CN=Public Key Services,CN=Services,$($ConfigNCDN -join ',')" -Filter { objectClass -eq "certificationAuthority" } -Properties "Name" -SelectPrty 'DistinguishedName', 'Name' -Session $TempPssSession
            $subordinateCA = Get-ADObjectSearch -DN "CN=Enrollment Services,CN=Public Key Services,CN=Services,$($ConfigNCDN -join ',')" -Filter { objectClass -eq "pKIEnrollmentService" } -Properties "*" -SelectPrty 'dNSHostName', 'Name' -Session $TempPssSession
            if ($rootCA -or $subordinateCA) {
                Section -Style Heading3 'Certificate Authority' {
                    if ($Options.ShowDefinitionInfo) {
                        Paragraph 'In cryptography, a certificate authority or certification authority (CA) is an entity that issues digital certificates. A digital certificate certifies the ownership of a public key by the named subject of the certificate. This allows others (relying parties) to rely upon signatures or on assertions made about the private key that corresponds to the certified public key. A CA acts as a trusted third party trusted both by the subject (owner) of the certificate and by the party relying upon the certificate. The format of these certificates is specified by the X.509 or EMV standard.'
                        BlankLine
                    }
                    if (-not $Options.ShowDefinitionInfo) {
                        Paragraph "The following section provides an overview of the Public Key Infrastructure (PKI) configuration deployed within the Active Directory environment."
                        BlankLine
                    }
                    if ($rootCA) {
                        Section -ExcludeFromTOC -Style NOTOCHeading4 'Certificate Authority Root(s)' {
                            $OutObj = [System.Collections.ArrayList]::new()
                            foreach ($Item in $rootCA) {
                                try {
                                    $inObj = [ordered] @{
                                        'Name' = $Item.Name
                                        'Distinguished Name' = $Item.DistinguishedName
                                    }
                                    $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                                } catch {
                                    Write-PScriboMessage -IsWarning $_.Exception.Message
                                }
                            }

                            if ($HealthCheck.Forest.BestPractice) {
                                ($OutObj | Measure-Object).Count -gt 1 | Set-Style -Style Warning
                            }

                            $TableParams = @{
                                Name = "Certificate Authority Root(s) - $($ForestInfo)"
                                List = $false
                                ColumnWidths = 40, 60
                            }
                            if ($Report.ShowTableCaptions) {
                                $TableParams['Caption'] = "- $($TableParams.Name)"
                            }
                            $OutObj | Sort-Object -Property 'Name' | Table @TableParams
                            if ($HealthCheck.Forest.BestPractice -and (($OutObj | Measure-Object).Count -gt 1 ) ) {
                                Paragraph "Health Check:" -Bold -Underline
                                BlankLine
                                Paragraph {
                                    Text "Best Practice:" -Bold
                                    Text "In most PKI (Public Key Infrastructure) implementations, it is not typical to have multiple Root CAs (Certificate Authorities). The Root CA is the top-most authority in a PKI hierarchy and is responsible for issuing certificates to subordinate CAs and end entities. Having multiple Root CAs can complicate the trust relationships and management of certificates. It is recommended to conduct a detailed review of the current PKI infrastructure and Root CA requirements to ensure proper security and management practices are followed."
                                }
                            }
                        }
                    } else {
                        Write-PScriboMessage -Message "No Certificate Authority Root information found in $ForestInfo, Disabling this section."
                    }

                    if ($subordinateCA) {
                        Section -ExcludeFromTOC -Style NOTOCHeading4 'Certificate Authority Issuer(s)' {
                            $OutObj = [System.Collections.ArrayList]::new()
                            foreach ($Item in $subordinateCA) {
                                try {
                                    $inObj = [ordered] @{
                                        'Name' = $Item.Name
                                        'DNS Name' = $Item.dNSHostName
                                    }
                                    $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                                } catch {
                                    Write-PScriboMessage -IsWarning $_.Exception.Message
                                }
                            }

                            $TableParams = @{
                                Name = "Certificate Authority Issuer(s) - $($ForestInfo)"
                                List = $false
                                ColumnWidths = 40, 60
                            }
                            if ($Report.ShowTableCaptions) {
                                $TableParams['Caption'] = "- $($TableParams.Name)"
                            }
                            $OutObj | Sort-Object -Property 'Name' | Table @TableParams
                        }
                    } else {
                        Write-PScriboMessage -Message "No Certificate Authority Issuer information found, Disabling this section."
                    }
                }
                if ($Options.EnableDiagrams) {
                    try {
                        try {
                            $Graph = Get-AbrDiagrammer -DiagramType "CertificateAuthority" -DiagramOutput base64 -PSSessionObject $TempPssSession
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "Certificate Authority Diagram Graph: $($_.Exception.Message)"
                        }

                        if ($Graph) {
                            if ((Get-DiaImagePercent -GraphObj $Graph).Width -gt 600) { $ImagePrty = 20 } else { $ImagePrty = 40 }
                            Section -Style Heading4 "Certificate Authority Diagram." {
                                Image -Base64 $Graph -Text "Certificate Authority Diagram" -Percent $ImagePrty -Align Center
                                Paragraph "Image preview: Opens the image in a new tab to view it at full resolution." -Tabs 2
                            }
                            BlankLine -Count 2
                        }
                    } catch {
                        Write-PScriboMessage -IsWarning -Message "Certificate Authority Diagram Section: $($_.Exception.Message)"
                    }
                }
            }
        } catch {
            Write-PScriboMessage -IsWarning $_.Exception.Message
        }
        try {
            Section -Style Heading3 'Optional Features' {
                $Data = Invoke-Command -Session $TempPssSession { Get-ADOptionalFeature -Filter * }
                $OutObj = [System.Collections.ArrayList]::new()
                if ($Data) {
                    foreach ($Item in $Data) {
                        try {
                            $inObj = [ordered] @{
                                'Name' = $Item.Name
                                'Required Forest Mode' = $Item.RequiredForestMode
                                'Enabled' = switch (($Item.EnabledScopes).count) {
                                    0 { 'No' }
                                    default { 'Yes' }
                                }
                            }
                            $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                        } catch {
                            Write-PScriboMessage -IsWarning $_.Exception.Message
                        }
                    }

                    if ($HealthCheck.Forest.BestPractice) {
                        $OutObj | Where-Object { $_.'Name' -eq 'Recycle Bin Feature' -and $_.'Enabled' -eq 'No' } | Set-Style -Style Warning -Property 'Enabled'
                    }

                    $TableParams = @{
                        Name = "Optional Features - $($ForestInfo)"
                        List = $false
                        ColumnWidths = 40, 30, 30
                    }
                    if ($Report.ShowTableCaptions) {
                        $TableParams['Caption'] = "- $($TableParams.Name)"
                    }
                    $OutObj | Sort-Object -Property 'Name' | Table @TableParams
                    if ($HealthCheck.Forest.BestPractice -and ($OutObj | Where-Object { $_.'Name' -eq 'Recycle Bin Feature' -and $_.'Enabled' -eq 'No' }) ) {
                        Paragraph "Health Check:" -Bold -Underline
                        BlankLine
                        Paragraph {
                            Text "Best Practice:" -Bold
                            Text "Accidental deletion of Active Directory objects is a common issue for AD DS users. Enabling the Recycle Bin feature allows for the recovery of these accidentally deleted objects, helping to maintain the integrity and continuity of the Active Directory environment."
                        }
                        BlankLine
                        Paragraph {
                            Text "Reference:" -Bold
                            BlankLine
                            Text "https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/the-ad-recycle-bin-understanding-implementing-best-practices-and/ba-p/396944" -Color blue

                        }
                    }
                } else {
                    Write-PScriboMessage -Message "No Optional Feature information found in $ForestInfo, Disabling this section."
                }
            }
        } catch {
            Write-PScriboMessage -IsWarning $_.Exception.Message
        }
    }

    end {
        Show-AbrDebugExecutionTime -End -TitleMessage 'AD Forest'
    }

}