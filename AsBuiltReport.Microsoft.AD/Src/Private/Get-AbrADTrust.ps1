function Get-AbrADTrust {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Trust from Domain Controller
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
        $Domain,
        [string]$ValidDCFromDomain
    )

    begin {
        Write-PScriboMessage -Message ($reportTranslate.GetAbrADTrust.Collecting -f $Domain.DNSRoot.ToString().ToUpper())
        Show-AbrDebugExecutionTime -Start -TitleMessage 'AD Trust'
    }

    process {
        try {
            if ($Domain) {
                try {
                    $Trusts = Invoke-CommandWithTimeout -Session $TempPssSession -ScriptBlock { Get-ADTrust -Filter * -Properties * -Server $using:ValidDCFromDomain }
                    if ($Trusts) {
                        Section -Style Heading3 $reportTranslate.GetAbrADTrust.SectionTitle {
                            $TrustInfo = [System.Collections.Generic.List[object]]::new()
                            foreach ($Trust in $Trusts) {
                                try {
                                    $inObj = [ordered] @{
                                        $reportTranslate.GetAbrADTrust.Name = $Trust.Name
                                        $reportTranslate.GetAbrADTrust.Path = $Trust.CanonicalName
                                        $reportTranslate.GetAbrADTrust.Source = ConvertTo-ADObjectName $Trust.Source -Session $TempPssSession -DC $ValidDCFromDomain
                                        $reportTranslate.GetAbrADTrust.Target = $Trust.Target
                                        $reportTranslate.GetAbrADTrust.TrustType = switch ($Trust.TrustType) {
                                            1 { $reportTranslate.GetAbrADTrust.TrustTypeDownlevel }
                                            2 { $reportTranslate.GetAbrADTrust.TrustTypeUplevel }
                                            3 { $reportTranslate.GetAbrADTrust.TrustTypeMIT }
                                            4 { $reportTranslate.GetAbrADTrust.TrustTypeDCE }
                                            default { $Trust.TrustType }
                                        }
                                        $reportTranslate.GetAbrADTrust.TrustAttributes = switch ($Trust.TrustAttributes) {
                                            1 { $reportTranslate.GetAbrADTrust.TrustAttrNonTransitive }
                                            2 { $reportTranslate.GetAbrADTrust.TrustAttrUplevel }
                                            4 { $reportTranslate.GetAbrADTrust.TrustAttrQuarantine }
                                            8 { $reportTranslate.GetAbrADTrust.TrustAttrForest }
                                            16 { $reportTranslate.GetAbrADTrust.TrustAttrCrossOrg }
                                            32 { $reportTranslate.GetAbrADTrust.TrustAttrIntraForest }
                                            64 { $reportTranslate.GetAbrADTrust.TrustAttrInterForest }
                                            default { $Trust.TrustAttributes }
                                        }
                                        $reportTranslate.GetAbrADTrust.TrustDirection = switch ($Trust.TrustDirection) {
                                            0 { $reportTranslate.GetAbrADTrust.TrustDirDisabled }
                                            1 { $reportTranslate.GetAbrADTrust.TrustDirInbound }
                                            2 { $reportTranslate.GetAbrADTrust.TrustDirOutbound }
                                            3 { $reportTranslate.GetAbrADTrust.TrustDirBidirectional }
                                            default { $Trust.TrustDirection }
                                        }
                                        $reportTranslate.GetAbrADTrust.IntraForest = $Trust.IntraForest
                                        $reportTranslate.GetAbrADTrust.SelectiveAuthentication = $Trust.SelectiveAuthentication
                                        $reportTranslate.GetAbrADTrust.SIDFilteringForestAware = $Trust.SIDFilteringForestAware
                                        $reportTranslate.GetAbrADTrust.SIDFilteringQuarantined = $Trust.SIDFilteringQuarantined
                                        $reportTranslate.GetAbrADTrust.TGTDelegation = $Trust.TGTDelegation
                                        $reportTranslate.GetAbrADTrust.KerberosAESEncryption = $Trust.UsesAESKeys
                                        $reportTranslate.GetAbrADTrust.KerberosRC4Encryption = $Trust.UsesRC4Encryption
                                        $reportTranslate.GetAbrADTrust.UplevelOnly = $Trust.UplevelOnly
                                    }
                                    $TrustInfo.Add([pscustomobject](ConvertTo-HashToYN $inObj))
                                } catch {
                                    Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Trust Item)"
                                }
                            }

                            if ($HealthCheck.Domain.Security) {
                                $TrustInfo | Where-Object { $_.$($reportTranslate.GetAbrADTrust.KerberosAESEncryption) -eq 'No' } | Set-Style -Style Warning -Property $reportTranslate.GetAbrADTrust.KerberosAESEncryption
                                $TrustInfo | Where-Object { $_.$($reportTranslate.GetAbrADTrust.KerberosRC4Encryption) -eq 'Yes' } | Set-Style -Style Warning -Property $reportTranslate.GetAbrADTrust.KerberosRC4Encryption
                            }

                            if ($InfoLevel.Domain -ge 2) {
                                foreach ($Trust in $TrustInfo) {
                                    Section -Style NOTOCHeading4 -ExcludeFromTOC "$($Trust.$($reportTranslate.GetAbrADTrust.Name)) $($reportTranslate.GetAbrADTrust.Trust) Details" {
                                        $TableParams = @{
                                            Name = "$($reportTranslate.GetAbrADTrust.Trust) - $($Trust.Name)"
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
                                    Name = "$($reportTranslate.GetAbrADTrust.Trust) - $($Domain.DNSRoot.ToString().ToUpper())"
                                    List = $false
                                    Columns = $reportTranslate.GetAbrADTrust.Name, $reportTranslate.GetAbrADTrust.Path, $reportTranslate.GetAbrADTrust.Source, $reportTranslate.GetAbrADTrust.Target, $reportTranslate.GetAbrADTrust.TrustDirection
                                    ColumnWidths = 20, 20, 20, 20, 20
                                }
                                if ($Report.ShowTableCaptions) {
                                    $TableParams['Caption'] = "- $($TableParams.Name)"
                                }
                                $TrustInfo | Table @TableParams
                            }
                            if ($HealthCheck.Domain.Security -and ($TrustInfo | Where-Object { $_.$($reportTranslate.GetAbrADTrust.KerberosAESEncryption) -eq 'No' })) {
                                Paragraph $reportTranslate.GetAbrADTrust.HealthCheck -Bold -Underline
                                BlankLine
                                Paragraph {
                                    Text $reportTranslate.GetAbrADTrust.BestPractice -Bold
                                    Text $reportTranslate.GetAbrADTrust.AESBP
                                }
                            }
                            if ($Options.EnableDiagrams) {
                                try {
                                    try {
                                        $Graph = Get-AbrDiagrammer -DiagramType 'Trusts' -DiagramOutput base64 -DomainController $ValidDCFromDomain
                                    } catch {
                                        Write-PScriboMessage -IsWarning -Message "Domain and Trusts Diagram Graph: $($_.Exception.Message)"
                                    }

                                    if ($Graph) {
                                        $BestAspectRatio = Get-BestImageAspectRatio -GraphObj $Graph -MaxWidth 600
                                        Section -Style Heading3 $reportTranslate.GetAbrADTrust.TrustDiagramSection {
                                            Image -Base64 $Graph -Text $reportTranslate.GetAbrADTrust.TrustDiagramSection -Width $BestAspectRatio.Width -Height $BestAspectRatio.Height -Align Center
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
        Show-AbrDebugExecutionTime -End -TitleMessage 'AD Trust'
    }

}