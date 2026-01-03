function Get-AbrADCACRLSetting {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft Active Directory CA CRL Distribution Point information.
    .DESCRIPTION

    .NOTES
        Version:        0.9.9
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
        $CA
    )

    begin {
        Show-AbrDebugExecutionTime -Start -TitleMessage 'CA Certificate Revocation List Objects'
    }

    process {
        try {
            Section -Style Heading3 'Certificate Revocation List (CRL)' {
                Paragraph 'This section provides detailed information about the Certificate Revocation List (CRL) distribution settings and health status for the Certification Authority.'
                BlankLine
                Section -Style Heading4 'CRL Validity Period' {
                    $OutObj = [System.Collections.ArrayList]::new()
                    try {
                        Write-PScriboMessage -Message "Collecting AD CA CRL Validity Period information on $($CA.Name)."
                        $CRLs = Get-CRLValidityPeriod -CertificationAuthority $CA
                        foreach ($VP in $CRLs) {
                            try {
                                $inObj = [ordered] @{
                                    'CA Name' = $VP.Name
                                    'Base CRL' = $VP.BaseCRL
                                    'Base CRL Overlap' = $VP.BaseCRLOverlap
                                    'Delta CRL' = $VP.DeltaCRL
                                    'Delta CRL Overlap' = $VP.DeltaCRLOverlap
                                }
                                $OutObj.add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                            } catch {
                                Write-PScriboMessage -IsWarning -Message "CRL Validity Period $($VP.Name) Section: $($_.Exception.Message)"
                            }
                        }
                    } catch {
                        Write-PScriboMessage -IsWarning -Message "CRL Validity Period Section: $($_.Exception.Message)"
                    }

                    $TableParams = @{
                        Name = "CRL Validity Preriod - $($ForestInfo.toUpper())"
                        List = $false
                        ColumnWidths = 40, 15, 15, 15, 15
                    }
                    if ($Report.ShowTableCaptions) {
                        $TableParams['Caption'] = "- $($TableParams.Name)"
                    }
                    $OutObj | Sort-Object -Property 'CA Name' | Table @TableParams
                }
                try {
                    Section -Style Heading4 'CRL Flags Settings' {
                        $OutObj = [System.Collections.ArrayList]::new()
                        try {
                            Write-PScriboMessage -Message "Collecting AD CA CRL Distribution Point information on $($CA.Name)."
                            $CRLs = Get-CertificateRevocationListFlag -CertificationAuthority $CA
                            foreach ($Flag in $CRLs) {
                                try {
                                    $inObj = [ordered] @{
                                        'CA Name' = $Flag.Name
                                        'Server Name' = $Flag.ComputerName.ToString().ToUpper().Split('.')[0]
                                        'CRL Flags' = $Flag.CRLFlags
                                    }
                                    $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                                } catch {
                                    Write-PScriboMessage -IsWarning -Message "CRL Validity Period $($Flag.Name) Section: $($_.Exception.Message)"
                                }
                            }
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "CRL Validity Period Table Section: $($_.Exception.Message)"
                        }

                        $TableParams = @{
                            Name = "CRL Flags - $($ForestInfo.toUpper())"
                            List = $false
                            ColumnWidths = 40, 25, 35
                        }
                        if ($Report.ShowTableCaptions) {
                            $TableParams['Caption'] = "- $($TableParams.Name)"
                        }
                        $OutObj | Sort-Object -Property 'CA Name' | Table @TableParams
                    }
                } catch {
                    Write-PScriboMessage -IsWarning -Message "CRL Validity Period Section: $($_.Exception.Message)"
                }
                try {
                    Section -Style Heading4 'CRL Distribution Point' {
                        Paragraph 'This section provides detailed information about the Certificate Revocation List (CRL) Distribution Points configured on the Certification Authority, including URI locations and publication settings.'
                        BlankLine
                        Write-PScriboMessage -Message "Collecting AD CA CRL Distribution Point information on $($CA.NAme)."
                        $CRL = Get-CRLDistributionPoint -CertificationAuthority $CA
                        foreach ($URI in $CRL.URI) {
                            $OutObj = [System.Collections.ArrayList]::new()
                            try {
                                $inObj = [ordered] @{
                                    'Reg URI' = $URI.RegURI
                                    'Config URI' = $URI.ConfigURI
                                    'Url Scheme' = $URI.UrlScheme
                                    'ProjectedURI' = $URI.ProjectedURI
                                    'Flags' = ($URI.Flags -join ', ')
                                    'CRL Publish' = $URI.IncludeToExtension
                                    'Delta CRL Publish' = $URI.DeltaCRLPublish
                                    'Add To Cert CDP' = $URI.AddToCertCDP
                                    'Add To Fresh est CRL' = $URI.AddToFreshestCRL
                                    'Add To Crl cdp' = $URI.AddToCrlcdp
                                }
                                $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null

                                $TableParams = @{
                                    Name = "CRL Distribution Point - $($CA.Name)"
                                    List = $true
                                    ColumnWidths = 40, 60
                                }
                                if ($Report.ShowTableCaptions) {
                                    $TableParams['Caption'] = "- $($TableParams.Name)"
                                }
                                $OutObj | Table @TableParams
                            } catch {
                                Write-PScriboMessage -IsWarning "CRL Distribution Point Table: $($_.Exception.Message)"
                            }
                        }
                    }
                } catch {
                    Write-PScriboMessage -IsWarning "CRL Distribution Point Section: $($_.Exception.Message)"
                }
            }
        } catch {
            Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (CRL Distribution Point)"
        }
        try {
            Section -Style Heading3 'AIA and CDP Health Status' {
                Paragraph 'This section provides a comprehensive health check of the Certification Authority by verifying the CA certificate chain status and validating the accessibility of all Certificate Revocation List (CDP) and Authority Information Access (AIA) URLs for each certificate in the chain.'
                BlankLine
                $OutObj = [System.Collections.ArrayList]::new()
                $CAHealth = Get-EnterprisePKIHealthStatus -CertificateAuthority $CA
                foreach ($Health in $CAHealth) {
                    try {
                        Write-PScriboMessage -Message "Collecting AIA and CDP Health Status from $($Health.Name)."
                        $inObj = [ordered] @{
                            'CA Name' = $Health.Name
                            'Childs' = ($Health.Childs).Name
                            'Health' = $Health.Status
                        }
                        $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                    } catch {
                        Write-PScriboMessage -IsWarning "AIA and CDP Health Status Table: $($_.Exception.Message)"
                    }
                }

                if ($HealthCheck.CA.Status) {
                    $OutObj | Where-Object { $_.'Health' -notlike 'OK' } | Set-Style -Style Critical -Property 'Health'
                }

                $TableParams = @{
                    Name = "Certification Authority Health - $($ForestInfo.ToString().ToUpper())"
                    List = $false
                    ColumnWidths = 40, 40, 20
                }
                if ($Report.ShowTableCaptions) {
                    $TableParams['Caption'] = "- $($TableParams.Name)"
                }
                $OutObj | Sort-Object -Property 'CA Name' | Table @TableParams
            }
        } catch {
            Write-PScriboMessage -IsWarning "AIA and CDP Health Status Section: $($_.Exception.Message)"
        }
    }

    end {
        Show-AbrDebugExecutionTime -End -TitleMessage 'CA Certificate Revocation List Objects'
    }

}