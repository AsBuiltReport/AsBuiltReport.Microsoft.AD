function Get-AbrADForest {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD information from Domain Controller
    .DESCRIPTION

    .NOTES
        Version:        0.9.1
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
        Write-PScriboMessage "Collecting Active Directory forest information."
    }

    process {
        try {
            $Data = Invoke-Command -Session $TempPssSession { Get-ADForest }
            $ForestInfo = $Data.RootDomain.toUpper()
            $DomainDN = Invoke-Command -Session $TempPssSession { (Get-ADDomain -Identity (Get-ADForest | Select-Object -ExpandProperty RootDomain )).DistinguishedName }
            $TombstoneLifetime = Invoke-Command -Session $TempPssSession { Get-ADObject "CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,$using:DomainDN" -Properties tombstoneLifetime | Select-Object -ExpandProperty tombstoneLifetime }
            $ADVersion = Invoke-Command -Session $TempPssSession { Get-ADObject (Get-ADRootDSE).schemaNamingContext -property objectVersion | Select-Object -ExpandProperty objectVersion }
            $ValuedsHeuristics = Invoke-Command -Session $TempPssSession { Get-ADObject -Identity "CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,$(($using:DomainDN))" -Properties dsHeuristics -ErrorAction SilentlyContinue }

            If ($ADVersion -eq '88') { $server = 'Windows Server 2019' }
            ElseIf ($ADVersion -eq '91') { $server = 'Windows Server 2025' }
            ElseIf ($ADVersion -eq '87') { $server = 'Windows Server 2016' }
            ElseIf ($ADVersion -eq '69') { $server = 'Windows Server 2012 R2' }
            ElseIf ($ADVersion -eq '56') { $server = 'Windows Server 2012' }
            ElseIf ($ADVersion -eq '47') { $server = 'Windows Server 2008 R2' }
            ElseIf ($ADVersion -eq '44') { $server = 'Windows Server 2008' }
            ElseIf ($ADVersion -eq '31') { $server = 'Windows Server 2003 R2' }
            ElseIf ($ADVersion -eq '30') { $server = 'Windows Server 2003' }
            $OutObj = @()
            if ($Data) {
                foreach ($Item in $Data) {
                    try {
                        $inObj = [ordered] @{
                            'Forest Name' = $Item.RootDomain
                            'Forest Functional Level' = $Item.ForestMode
                            'Schema Version' = "ObjectVersion $ADVersion, Correspond to $server"
                            'Tombstone Lifetime (days)' = $TombstoneLifetime
                            'Domains' = $Item.Domains -join '; '
                            'Global Catalogs' = $Item.GlobalCatalogs -join '; '
                            'Domains Count' = $Item.Domains.Count
                            'Global Catalogs Count' = $Item.GlobalCatalogs.Count
                            'Sites Count' = $Item.Sites.Count
                            'Application Partitions' = $Item.ApplicationPartitions
                            'PartitionsContainer' = [string]$Item.PartitionsContainer
                            'SPN Suffixes' = $Item.SPNSuffixes
                            'UPN Suffixes' = ($Item.UPNSuffixes -join ', ')
                            'Anonymous Access (dsHeuristics)' = & {
                                if (($ValuedsHeuristics.dsHeuristics -eq "") -or ($ValuedsHeuristics.dsHeuristics.Length -lt 7)) {
                                    "Disabled"
                                } elseif (($ValuedsHeuristics.dsHeuristics.Length -ge 7) -and ($ValuedsHeuristics.dsHeuristics[6] -eq "2")) {
                                    "Enabled"
                                }
                            }
                        }
                        $OutObj += [pscustomobject](ConvertTo-HashToYN $inObj)
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
                            Text "Anonymous Access to Active Directory forest data above the rootDSE level must be disabled."
                        }
                        BlankLine
                        Paragraph "Reference:" -Bold
                        BlankLine
                        Paragraph "https://www.stigviewer.com/stig/active_directory_forest/2016-02-19/finding/V-8555" -Color blue
                    }
                    if ($OutObj | Where-Object { $_.'Tombstone Lifetime (days)' -lt 180 }) {
                        Paragraph {
                            Text "Best Practice:" -Bold
                            Text "Change the Tombstone Lifetime to 180 days, at a minimum."
                        }
                    }
                }
                try {
                    try {
                        $Graph = New-ADDiagram -Target $System -Credential $Credential -Format base64 -Direction top-to-bottom -DiagramType Forest
                    } catch {
                        Write-PScriboMessage -IsWarning "Forest Diagram Graph: $($_.Exception.Message)"
                    }

                    if ($Graph) {
                        If ((Get-DiaImagePercent -GraphObj $Graph).Width -gt 1500) { $ImagePrty = 10 } else { $ImagePrty = 50 }
                        Section -Style Heading3 "Forest Diagram." {
                            Image -Base64 $Graph -Text "Forest Diagram" -Percent $ImagePrty -Align Center
                            Paragraph "Image preview: Opens the image in a new tab to view it at full resolution." -Tabs 2
                        }
                        BlankLine -Count 2
                    }
                } catch {
                    Write-PScriboMessage -IsWarning "Forest Diagram Section: $($_.Exception.Message)"
                }
            }
        } catch {
            Write-PScriboMessage -IsWarning $_.Exception.Message
        }
        try {
            Section -Style Heading3 'Certificate Authority' {
                if ($Options.ShowDefinitionInfo) {
                    Paragraph 'In cryptography, a certificate authority or certification authority (CA) is an entity that issues digital certificates. A digital certificate certifies the ownership of a public key by the named subject of the certificate. This allows others (relying parties) to rely upon signatures or on assertions made about the private key that corresponds to the certified public key. A CA acts as a trusted third party trusted both by the subject (owner) of the certificate and by the party relying upon the certificate. The format of these certificates is specified by the X.509 or EMV standard.'
                    BlankLine
                }
                if (-Not $Options.ShowDefinitionInfo) {
                    Paragraph "The following section provides a summary of the Active Directory PKI Infrastructure Information."
                    BlankLine
                }
                $ConfigNCDN = $Data.PartitionsContainer.Split(',') | Select-Object -Skip 1
                $rootCA = Get-ADObjectSearch -DN "CN=Certification Authorities,CN=Public Key Services,CN=Services,$($ConfigNCDN -join ',')" -Filter { objectClass -eq "certificationAuthority" } -Properties "Name" -SelectPrty 'DistinguishedName', 'Name' -Session $TempPssSession
                if ($rootCA) {
                    Section -ExcludeFromTOC -Style NOTOCHeading4 'Certification Authority Root(s)' {
                        $OutObj = @()
                        foreach ($Item in $rootCA) {
                            try {
                                $inObj = [ordered] @{
                                    'Name' = $Item.Name
                                    'Distinguished Name' = $Item.DistinguishedName
                                }
                                $OutObj += [pscustomobject](ConvertTo-HashToYN $inObj)
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
                                Text "In most PKI implementations, it is not typical to have multiple Root CAs. Its recommended a detailed review of the current PKI infrastructure and Root CA requirements."
                            }
                        }
                    }
                } else {
                    Write-PScriboMessage -IsWarning "No Certificate Authority Root information found in $ForestInfo, disabling the section."
                }
                $ConfigNCDN = $Data.PartitionsContainer.Split(',') | Select-Object -Skip 1
                $subordinateCA = Get-ADObjectSearch -DN "CN=Enrollment Services,CN=Public Key Services,CN=Services,$($ConfigNCDN -join ',')" -Filter { objectClass -eq "pKIEnrollmentService" } -Properties "*" -SelectPrty 'dNSHostName', 'Name' -Session $TempPssSession
                if ($subordinateCA) {
                    Section -ExcludeFromTOC -Style NOTOCHeading4 'Certification Authority Issuer(s)' {
                        $OutObj = @()
                        foreach ($Item in $subordinateCA) {
                            try {
                                $inObj = [ordered] @{
                                    'Name' = $Item.Name
                                    'DNS Name' = $Item.dNSHostName
                                }
                                $OutObj += [pscustomobject](ConvertTo-HashToYN $inObj)
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
                    Write-PScriboMessage -IsWarning "No Certificate Authority Issuer information found, disabling the section."
                }
            }
        } catch {
            Write-PScriboMessage -IsWarning $_.Exception.Message
        }
        try {
            Section -Style Heading3 'Optional Features' {
                $Data = Invoke-Command -Session $TempPssSession { Get-ADOptionalFeature -Filter * }
                $OutObj = @()
                if ($Data) {
                    foreach ($Item in $Data) {
                        try {
                            $inObj = [ordered] @{
                                'Name' = $Item.Name
                                'Required Forest Mode' = $Item.RequiredForestMode
                                'Enabled' = Switch (($Item.EnabledScopes).count) {
                                    0 { 'No' }
                                    default { 'Yes' }
                                }
                            }
                            $OutObj += [pscustomobject](ConvertTo-HashToYN $inObj)
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
                            Text "Accidental deletion of Active Directory objects is common for Active Directory Domain Services (AD DS) users. With the Recycle Bin Feature, one could recover accidentally deleted objects in Active Directory. Enable the Recycle Bin feature for the forest."
                        }
                        BlankLine
                        Paragraph {
                            Text "Reference:" -Bold
                            BlankLine
                            Text "https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/the-ad-recycle-bin-understanding-implementing-best-practices-and/ba-p/396944" -Color blue

                        }
                    }
                } else {
                    Write-PScriboMessage -IsWarning "No Optional Feature information found in $ForestInfo, disabling the section."
                }
            }
        } catch {
            Write-PScriboMessage -IsWarning $_.Exception.Message
        }
    }

    end {}

}