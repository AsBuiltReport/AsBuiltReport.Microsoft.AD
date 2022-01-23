function Get-AbrADCACRLSetting {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft Active Directory CA CRL Distribution Point information.
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
    )

    begin {
        Write-PscriboMessage "Collecting AD Certification Authority Certificate Revocation List information."
    }

    process {
        try {
            Section -Style Heading4 "Certificate Revocation List (CRL) Configuration" {
                Paragraph "The following section provides the Certification Authority CRL Distribution Point information."
                BlankLine
                Section -Style Heading5 "CRL Validity Period" {
                    Paragraph "The following section provides the Certification Authority CRL Validity Period information."
                    BlankLine
                    $OutObj = @()
                    Write-PscriboMessage "Discovering Active Directory Certification Authority information on $($ForestInfo.toUpper())."
                    $CAs = Get-CertificationAuthority -Enterprise
                    if ($CAs) {Write-PscriboMessage "Discovered '$(($CAs | Measure-Object).Count)' Active Directory Certification Authority in forest $ForestInfo."}
                    foreach ($CA in $CAs) {
                        try {
                            Write-PscriboMessage "Collecting AD CA CRL Validity Period information on $CA."
                            $CRLs = Get-CRLValidityPeriod -CertificationAuthority $CA
                            foreach ($VP in $CRLs) {
                                $inObj = [ordered] @{
                                    'CA Name' = $VP.Name
                                    'Base CRL' = $VP.BaseCRL
                                    'Base CRL Overlap' = $VP.BaseCRLOverlap
                                    'Delta CRL' = $VP.DeltaCRL
                                    'Delta CRL Overlap' = $VP.DeltaCRLOverlap
                                }
                                $OutObj += [pscustomobject]$inobj
                            }
                        }
                        catch {
                            Write-PscriboMessage -IsWarning $_.Exception.Message
                        }
                    }

                    $TableParams = @{
                        Name = "CRL Validity Preriod - $($ForestInfo.toUpper())"
                        List = $false
                        ColumnWidths = 40, 15, 15, 15, 15
                    }
                    if ($Report.ShowTableCaptions) {
                        $TableParams['Caption'] = "- $($TableParams.Name)"
                    }
                    $OutObj | Table @TableParams
                }
                try {
                    Section -Style Heading5 "CRL Flags Settings" {
                        Paragraph "The following section provides the Certification Authority CRL Flags information."
                        BlankLine
                        $OutObj = @()
                        Write-PscriboMessage "Discovering Active Directory Certification Authority information on $($ForestInfo.toUpper())."
                        $CAs = Get-CertificationAuthority -Enterprise
                        if ($CAs) {Write-PscriboMessage "Discovered '$(($CAs | Measure-Object).Count)' Active Directory Certification Authority in forest $ForestInfo."}
                        foreach ($CA in $CAs) {
                            try {
                                Write-PscriboMessage "Collecting AD CA CRL Distribution Point information on $CA."
                                $CRLs = Get-CertificateRevocationListFlag -CertificationAuthority $CA
                                foreach ($Flag in $CRLs) {
                                    $inObj = [ordered] @{
                                        'CA Name' = $Flag.Name
                                        'Server Name' = $Flag.ComputerName.ToString().ToUpper().Split(".")[0]
                                        'CRL Flags' = $Flag.CRLFlags
                                    }
                                    $OutObj += [pscustomobject]$inobj
                                }
                            }
                            catch {
                                Write-PscriboMessage -IsWarning $_.Exception.Message
                            }
                        }

                        $TableParams = @{
                            Name = "CRL Flags - $($ForestInfo.toUpper())"
                            List = $false
                            ColumnWidths = 40, 25, 35
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
                try {
                    Section -Style Heading5 "CRL Distribution Point" {
                        Paragraph "The following section provides the Certification Authority CRL Distribution Point information."
                        BlankLine
                        Write-PscriboMessage "Discovering Active Directory Certification Authority information on $($ForestInfo.toUpper())."
                        $CAs = Get-CertificationAuthority -Enterprise
                        if ($CAs) {Write-PscriboMessage "Discovered '$(($CAs | Measure-Object).Count)' Active Directory Certification Authority in forest $ForestInfo."}
                        foreach ($CA in $CAs) {
                            try {
                                Section -Style Heading6 "$($CA.Name) Distribution Point" {
                                    Paragraph "The following section provides the Certification Authority CRL Distribution Point information."
                                    BlankLine
                                    $OutObj = @()
                                    Write-PscriboMessage "Collecting AD CA CRL Distribution Point information on $CA."
                                    $CRL = Get-CRLDistributionPoint -CertificationAuthority $CA
                                    foreach ($URI in $CRL.URI) {
                                        $inObj = [ordered] @{
                                            'Reg URI' = $URI.RegURI
                                            'Config URI' = $URI.ConfigURI
                                            'Url Scheme' = $URI.UrlScheme
                                            'ProjectedURI' = $URI.ProjectedURI
                                            'Flags' = ConvertTo-EmptyToFiller ($URI.Flags -join ", ")
                                            'CRL Publish' = ConvertTo-TextYN $URI.IncludeToExtension
                                            'Delta CRL Publish' = ConvertTo-TextYN $URI.DeltaCRLPublish
                                            'Add To Cert CDP' = ConvertTo-TextYN $URI.AddToCertCDP
                                            'Add To Fresh est CRL' = ConvertTo-TextYN $URI.AddToFreshestCRL
                                            'Add To Crl cdp' = ConvertTo-TextYN $URI.AddToCrlcdp
                                        }
                                        $OutObj += [pscustomobject]$inobj
                                    }

                                    $TableParams = @{
                                        Name = "CRL Distribution Point - $($CA.Name)"
                                        List = $true
                                        ColumnWidths = 40, 60
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
                }
                catch {
                    Write-PscriboMessage -IsWarning $_.Exception.Message
                }
            }
        }
        catch {
            Write-PscriboMessage -IsWarning "$($_.Exception.Message) (CRL Distribution Point)"
        }
        try {
            Section -Style Heading4 "AIA and CDP Health Status" {
                Paragraph "The following section is intended to perform Certification Authority health status checking by CA certificate chain status and validating all CRL Distribution Point (CDP) and Authority Information Access (AIA) URLs for each certificate in the chain."
                BlankLine
                $OutObj = @()
                if ($ForestInfo) {
                    Write-PscriboMessage "Discovering Active Directory Certification Authority Health information in $($ForestInfo.toUpper())."
                    $CAs =  Get-CertificationAuthority -Enterprise
                    foreach ($CA in $CAs) {
                        Write-PscriboMessage "Discovered '$(($CAs | Measure-Object).Count)' Active Directory Certification Authority in domain $ForestInfo."
                        try {
                            Write-PscriboMessage "Collecting AD Certification Authority Health information of $CA."
                            $CAHealth = Get-EnterprisePKIHealthStatus -CertificateAuthority $CA
                            foreach ($Health in $CAHealth) {
                                $inObj = [ordered] @{
                                    'CA Name' = $Health.Name
                                    'Childs' = ($Health.Childs).Name
                                    'Health' = $Health.Status
                                }
                                $OutObj += [pscustomobject]$inobj
                            }
                        }
                        catch {
                            Write-PscriboMessage -IsWarning $_.Exception.Message
                        }
                    }
                }

                if ($HealthCheck.CA.Status) {
                    $OutObj | Where-Object { $_.'Health' -notlike 'OK'} | Set-Style -Style Critical -Property 'Health'
                }

                $TableParams = @{
                    Name = "Certification Authority Health - $($ForestInfo.ToString().ToUpper())"
                    List = $false
                    ColumnWidths = 40, 40, 20
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

    end {}

}