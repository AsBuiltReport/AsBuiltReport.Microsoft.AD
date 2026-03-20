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
            Section -Style Heading3 $reportTranslate.GetAbrADCACRLSetting.CRLHeading {
                Paragraph $reportTranslate.GetAbrADCACRLSetting.CRLParagraph
                BlankLine
                Section -Style Heading4 $reportTranslate.GetAbrADCACRLSetting.CRLValidityPeriod {
                    $OutObj = [System.Collections.ArrayList]::new()
                    try {
                        Write-PScriboMessage -Message ([string]::Format($reportTranslate.GetAbrADCACRLSetting.CollectingVP, $CA.Name))
                        $CRLs = Get-CRLValidityPeriod -CertificationAuthority $CA
                        foreach ($VP in $CRLs) {
                            try {
                                $inObj = [ordered] @{
                                    $reportTranslate.GetAbrADCACRLSetting.CAName = $VP.Name
                                    $reportTranslate.GetAbrADCACRLSetting.BaseCRL = $VP.BaseCRL
                                    $reportTranslate.GetAbrADCACRLSetting.BaseCRLOverlap = $VP.BaseCRLOverlap
                                    $reportTranslate.GetAbrADCACRLSetting.DeltaCRL = $VP.DeltaCRL
                                    $reportTranslate.GetAbrADCACRLSetting.DeltaCRLOverlap = $VP.DeltaCRLOverlap
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
                        Name = "$($reportTranslate.GetAbrADCACRLSetting.CRLValidityPeriodTable) - $($ForestInfo.toUpper())"
                        List = $false
                        ColumnWidths = 40, 15, 15, 15, 15
                    }
                    if ($Report.ShowTableCaptions) {
                        $TableParams['Caption'] = "- $($TableParams.Name)"
                    }
                    $OutObj | Sort-Object -Property $reportTranslate.GetAbrADCACRLSetting.CAName | Table @TableParams
                }
                try {
                    Section -Style Heading4 $reportTranslate.GetAbrADCACRLSetting.CRLFlagsSettings {
                        $OutObj = [System.Collections.ArrayList]::new()
                        try {
                            Write-PScriboMessage -Message ([string]::Format($reportTranslate.GetAbrADCACRLSetting.CollectingCDP, $CA.Name))
                            $CRLs = Get-CertificateRevocationListFlag -CertificationAuthority $CA
                            foreach ($Flag in $CRLs) {
                                try {
                                    $inObj = [ordered] @{
                                        $reportTranslate.GetAbrADCACRLSetting.CAName = $Flag.Name
                                        $reportTranslate.GetAbrADCACRLSetting.ServerName = $Flag.ComputerName.ToString().ToUpper().Split('.')[0]
                                        $reportTranslate.GetAbrADCACRLSetting.CRLFlags = $Flag.CRLFlags
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
                            Name = "$($reportTranslate.GetAbrADCACRLSetting.CRLFlagsTable) - $($ForestInfo.toUpper())"
                            List = $false
                            ColumnWidths = 40, 25, 35
                        }
                        if ($Report.ShowTableCaptions) {
                            $TableParams['Caption'] = "- $($TableParams.Name)"
                        }
                        $OutObj | Sort-Object -Property $reportTranslate.GetAbrADCACRLSetting.CAName | Table @TableParams
                    }
                } catch {
                    Write-PScriboMessage -IsWarning -Message "CRL Validity Period Section: $($_.Exception.Message)"
                }
                try {
                    Section -Style Heading4 $reportTranslate.GetAbrADCACRLSetting.CRLDistributionPoint {
                        Paragraph $reportTranslate.GetAbrADCACRLSetting.CRLDistributionPointParagraph
                        BlankLine
                        Write-PScriboMessage -Message ([string]::Format($reportTranslate.GetAbrADCACRLSetting.CollectingCDP, $CA.Name))
                        $CRL = Get-CRLDistributionPoint -CertificationAuthority $CA
                        foreach ($URI in $CRL.URI) {
                            $OutObj = [System.Collections.ArrayList]::new()
                            try {
                                $inObj = [ordered] @{
                                    $reportTranslate.GetAbrADCACRLSetting.RegURI = $URI.RegURI
                                    $reportTranslate.GetAbrADCACRLSetting.ConfigURI = $URI.ConfigURI
                                    $reportTranslate.GetAbrADCACRLSetting.UrlScheme = $URI.UrlScheme
                                    $reportTranslate.GetAbrADCACRLSetting.ProjectedURI = $URI.ProjectedURI
                                    $reportTranslate.GetAbrADCACRLSetting.Flags = ($URI.Flags -join ', ')
                                    $reportTranslate.GetAbrADCACRLSetting.CRLPublish = $URI.IncludeToExtension
                                    $reportTranslate.GetAbrADCACRLSetting.DeltaCRLPublish = $URI.DeltaCRLPublish
                                    $reportTranslate.GetAbrADCACRLSetting.AddToCertCDP = $URI.AddToCertCDP
                                    $reportTranslate.GetAbrADCACRLSetting.AddToFreshestCRL = $URI.AddToFreshestCRL
                                    $reportTranslate.GetAbrADCACRLSetting.AddToCrlCDP = $URI.AddToCrlcdp
                                }
                                $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null

                                $TableParams = @{
                                    Name = "$($reportTranslate.GetAbrADCACRLSetting.CRLDistributionPointTable) - $($CA.Name)"
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
            Section -Style Heading3 $reportTranslate.GetAbrADCACRLSetting.AIACDPHealth {
                Paragraph $reportTranslate.GetAbrADCACRLSetting.AIACDPHealthParagraph
                BlankLine
                $OutObj = [System.Collections.ArrayList]::new()
                $CAHealth = Get-EnterprisePKIHealthStatus -CertificateAuthority $CA
                foreach ($Health in $CAHealth) {
                    try {
                        Write-PScriboMessage -Message ([string]::Format($reportTranslate.GetAbrADCACRLSetting.CollectingHealth, $Health.Name))
                        $inObj = [ordered] @{
                            $reportTranslate.GetAbrADCACRLSetting.CAName = $Health.Name
                            $reportTranslate.GetAbrADCACRLSetting.Childs = ($Health.Childs).Name
                            $reportTranslate.GetAbrADCACRLSetting.Health = $Health.Status
                        }
                        $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                    } catch {
                        Write-PScriboMessage -IsWarning "AIA and CDP Health Status Table: $($_.Exception.Message)"
                    }
                }

                if ($HealthCheck.CA.Status) {
                    $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADCACRLSetting.Health) -notlike $reportTranslate.GetAbrADCACRLSetting.OK } | Set-Style -Style Critical -Property $reportTranslate.GetAbrADCACRLSetting.Health
                }

                $TableParams = @{
                    Name = "$($reportTranslate.GetAbrADCACRLSetting.CAHealthTable) - $($ForestInfo.ToString().ToUpper())"
                    List = $false
                    ColumnWidths = 40, 40, 20
                }
                if ($Report.ShowTableCaptions) {
                    $TableParams['Caption'] = "- $($TableParams.Name)"
                }
                $OutObj | Sort-Object -Property $reportTranslate.GetAbrADCACRLSetting.CAName | Table @TableParams
            }
        } catch {
            Write-PScriboMessage -IsWarning "AIA and CDP Health Status Section: $($_.Exception.Message)"
        }
    }

    end {
        Show-AbrDebugExecutionTime -End -TitleMessage 'CA Certificate Revocation List Objects'
    }

}
