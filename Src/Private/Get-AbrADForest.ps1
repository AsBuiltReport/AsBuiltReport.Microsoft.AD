function Get-AbrADForest {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD information from Domain Controller
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
    )

    begin {
        Write-PScriboMessage -Message $reportTranslate.GetAbrADForest.Collecting
        Show-AbrDebugExecutionTime -Start -TitleMessage 'AD Forest'
    }

    process {
        try {
            $Data = Invoke-CommandWithTimeout -Session $TempPssSession -ScriptBlock { Get-ADForest }
            $ForestInfo = $Data.RootDomain.toUpper()
            $DomainDN = Invoke-CommandWithTimeout -Session $TempPssSession -ScriptBlock { (Get-ADDomain -Identity (Get-ADForest | Select-Object -ExpandProperty RootDomain )).DistinguishedName }
            $TombstoneLifetime = Invoke-CommandWithTimeout -Session $TempPssSession -ScriptBlock { Get-ADObject "CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,$using:DomainDN" -Properties tombstoneLifetime | Select-Object -ExpandProperty tombstoneLifetime }
            $ADVersion = Invoke-CommandWithTimeout -Session $TempPssSession -ScriptBlock { Get-ADObject (Get-ADRootDSE).schemaNamingContext -property objectVersion | Select-Object -ExpandProperty objectVersion }
            $ValuedsHeuristics = Invoke-CommandWithTimeout -Session $TempPssSession -ScriptBlock { Get-ADObject -Identity "CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,$(($using:DomainDN))" -Properties dsHeuristics -ErrorAction SilentlyContinue }

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
                            $reportTranslate.GetAbrADForest.ForestName = $Item.RootDomain
                            $reportTranslate.GetAbrADForest.ForestFunctionalLevel = $Item.ForestMode
                            $reportTranslate.GetAbrADForest.SchemaVersion = $reportTranslate.GetAbrADForest.SchemaVersionValue -f $ADVersion, $server
                            $reportTranslate.GetAbrADForest.TombstoneLifetime = $TombstoneLifetime
                            $reportTranslate.GetAbrADForest.Domains = $Item.Domains -join '; '
                            $reportTranslate.GetAbrADForest.GlobalCatalogs = $Item.GlobalCatalogs -join '; '
                            $reportTranslate.GetAbrADForest.DomainsCount = $Item.Domains.Count
                            $reportTranslate.GetAbrADForest.GlobalCatalogsCount = $Item.GlobalCatalogs.Count
                            $reportTranslate.GetAbrADForest.SitesCount = $Item.Sites.Count
                            $reportTranslate.GetAbrADForest.ApplicationPartitions = $Item.ApplicationPartitions
                            $reportTranslate.GetAbrADForest.PartitionsContainer = [string]$Item.PartitionsContainer
                            $reportTranslate.GetAbrADForest.SPNSuffixes = $Item.SPNSuffixes
                            $reportTranslate.GetAbrADForest.UPNSuffixes = ($Item.UPNSuffixes -join ', ')
                            $reportTranslate.GetAbrADForest.AnonymousAccess = & {
                                if (($ValuedsHeuristics.dsHeuristics -eq '') -or ($ValuedsHeuristics.dsHeuristics.Length -lt 7)) {
                                    $reportTranslate.GetAbrADForest.AnonymousAccessDisabled
                                } elseif (($ValuedsHeuristics.dsHeuristics.Length -ge 7) -and ($ValuedsHeuristics.dsHeuristics[6] -eq '2')) {
                                    $reportTranslate.GetAbrADForest.AnonymousAccessEnabled
                                }
                            }
                        }
                        $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                    } catch {
                        Write-PScriboMessage -IsWarning $_.Exception.Message
                    }
                }

                if ($HealthCheck.Domain.Security) {
                    $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADForest.AnonymousAccess) -eq $reportTranslate.GetAbrADForest.AnonymousAccessEnabled } | Set-Style -Style Critical -Property $reportTranslate.GetAbrADForest.AnonymousAccess
                    $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADForest.TombstoneLifetime) -lt 180 } | Set-Style -Style Warning -Property $reportTranslate.GetAbrADForest.TombstoneLifetime
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
                if ($HealthCheck.Domain.Security -and ($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADForest.AnonymousAccess) -eq $reportTranslate.GetAbrADForest.AnonymousAccessEnabled }) ) {
                    Paragraph $reportTranslate.GetAbrADForest.HealthCheck -Bold -Underline
                    BlankLine
                    if ($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADForest.AnonymousAccess) -eq $reportTranslate.GetAbrADForest.AnonymousAccessEnabled }) {
                        Paragraph {
                            Text $reportTranslate.GetAbrADForest.BestPractice -Bold
                            Text $reportTranslate.GetAbrADForest.AnonAccessBP
                        }
                        BlankLine
                        Paragraph $reportTranslate.GetAbrADForest.Reference -Bold
                        BlankLine
                        Paragraph $reportTranslate.GetAbrADForest.AnonAccessRef -Color blue
                    }
                    if ($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADForest.TombstoneLifetime) -lt 180 }) {
                        Paragraph {
                            Text $reportTranslate.GetAbrADForest.BestPractice -Bold
                            Text $reportTranslate.GetAbrADForest.TombstoneBP
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
                            $BestAspectRatio = Get-DiaBestImageAspectRatio -GraphObj $Graph -MaxWidth 600
                            Section -Style Heading3 $reportTranslate.GetAbrADForest.ForestDiagram {
                                Image -Base64 $Graph -Text $reportTranslate.GetAbrADForest.ForestDiagram -Width $BestAspectRatio.Width -Height $BestAspectRatio.Height -Align Center
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
            $rootCA = Get-ADObjectSearch -DN "CN=Certification Authorities,CN=Public Key Services,CN=Services,$($ConfigNCDN -join ',')" -Filter { objectClass -eq 'certificationAuthority' } -Properties 'Name' -SelectPrty 'DistinguishedName', 'Name' -Session $TempPssSession
            $subordinateCA = Get-ADObjectSearch -DN "CN=Enrollment Services,CN=Public Key Services,CN=Services,$($ConfigNCDN -join ',')" -Filter { objectClass -eq 'pKIEnrollmentService' } -Properties '*' -SelectPrty 'dNSHostName', 'Name' -Session $TempPssSession
            if ($rootCA -or $subordinateCA) {
                Section -Style Heading3 $reportTranslate.GetAbrADForest.CASection {
                    if ($Options.ShowDefinitionInfo) {
                        Paragraph $reportTranslate.GetAbrADForest.CADefinition
                        BlankLine
                    }
                    if (-not $Options.ShowDefinitionInfo) {
                        Paragraph $reportTranslate.GetAbrADForest.CAParagraph
                        BlankLine
                    }
                    if ($rootCA) {
                        Section -ExcludeFromTOC -Style NOTOCHeading4 $reportTranslate.GetAbrADForest.CARootSection {
                            $OutObj = [System.Collections.ArrayList]::new()
                            foreach ($Item in $rootCA) {
                                try {
                                    $inObj = [ordered] @{
                                        $reportTranslate.GetAbrADForest.CAName = $Item.Name
                                        $reportTranslate.GetAbrADForest.CADistinguishedName = $Item.DistinguishedName
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
                                Name = "$($reportTranslate.GetAbrADForest.CARootSection) - $($ForestInfo)"
                                List = $false
                                ColumnWidths = 40, 60
                            }
                            if ($Report.ShowTableCaptions) {
                                $TableParams['Caption'] = "- $($TableParams.Name)"
                            }
                            $OutObj | Sort-Object -Property $reportTranslate.GetAbrADForest.CAName | Table @TableParams
                            if ($HealthCheck.Forest.BestPractice -and (($OutObj | Measure-Object).Count -gt 1 ) ) {
                                Paragraph $reportTranslate.GetAbrADForest.HealthCheck -Bold -Underline
                                BlankLine
                                Paragraph {
                                    Text $reportTranslate.GetAbrADForest.BestPractice -Bold
                                    Text $reportTranslate.GetAbrADForest.CAIssuerBP
                                }
                            }
                        }
                    } else {
                        Write-PScriboMessage -Message "No Certificate Authority Root information found in $ForestInfo, Disabling this section."
                    }

                    if ($subordinateCA) {
                        Section -ExcludeFromTOC -Style NOTOCHeading4 $reportTranslate.GetAbrADForest.CAIssuerSection {
                            $OutObj = [System.Collections.ArrayList]::new()
                            foreach ($Item in $subordinateCA) {
                                try {
                                    $inObj = [ordered] @{
                                        $reportTranslate.GetAbrADForest.CAName = $Item.Name
                                        $reportTranslate.GetAbrADForest.CADnsName = $Item.dNSHostName
                                    }
                                    $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                                } catch {
                                    Write-PScriboMessage -IsWarning $_.Exception.Message
                                }
                            }

                            $TableParams = @{
                                Name = "$($reportTranslate.GetAbrADForest.CAIssuerSection) - $($ForestInfo)"
                                List = $false
                                ColumnWidths = 40, 60
                            }
                            if ($Report.ShowTableCaptions) {
                                $TableParams['Caption'] = "- $($TableParams.Name)"
                            }
                            $OutObj | Sort-Object -Property $reportTranslate.GetAbrADForest.CAName | Table @TableParams
                        }
                    } else {
                        Write-PScriboMessage -Message 'No Certificate Authority Issuer information found, Disabling this section.'
                    }
                }
                if ($Options.EnableDiagrams) {
                    try {
                        try {
                            $Graph = Get-AbrDiagrammer -DiagramType 'CertificateAuthority' -DiagramOutput base64 -PSSessionObject $TempPssSession
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "Certificate Authority Diagram Graph: $($_.Exception.Message)"
                        }

                        if ($Graph) {
                            $BestAspectRatio = Get-DiaBestImageAspectRatio -GraphObj $Graph -MaxWidth 600
                            Section -Style Heading4 'Certificate Authority Diagram' {
                                Image -Base64 $Graph -Text 'Certificate Authority Diagram' -Width $BestAspectRatio.Width -Height $BestAspectRatio.Height -Align Center
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
            Section -Style Heading3 $reportTranslate.GetAbrADForest.OptionalFeatures {
                $Data = Invoke-CommandWithTimeout -Session $TempPssSession -ScriptBlock { Get-ADOptionalFeature -Filter * }
                $OutObj = [System.Collections.ArrayList]::new()
                if ($Data) {
                    foreach ($Item in $Data) {
                        try {
                            $inObj = [ordered] @{
                                $reportTranslate.GetAbrADForest.OFName = $Item.Name
                                $reportTranslate.GetAbrADForest.OFRequiredForestMode = $Item.RequiredForestMode
                                $reportTranslate.GetAbrADForest.OFEnabled = switch (($Item.EnabledScopes).count) {
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
                        $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADForest.OFName) -eq 'Recycle Bin Feature' -and $_.$($reportTranslate.GetAbrADForest.OFEnabled) -eq 'No' } | Set-Style -Style Warning -Property $reportTranslate.GetAbrADForest.OFEnabled
                    }

                    $TableParams = @{
                        Name = "$($reportTranslate.GetAbrADForest.OptionalFeatures) - $($ForestInfo)"
                        List = $false
                        ColumnWidths = 40, 30, 30
                    }
                    if ($Report.ShowTableCaptions) {
                        $TableParams['Caption'] = "- $($TableParams.Name)"
                    }
                    $OutObj | Sort-Object -Property $reportTranslate.GetAbrADForest.OFName | Table @TableParams
                    if ($HealthCheck.Forest.BestPractice -and ($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADForest.OFName) -eq 'Recycle Bin Feature' -and $_.$($reportTranslate.GetAbrADForest.OFEnabled) -eq 'No' }) ) {
                        Paragraph $reportTranslate.GetAbrADForest.HealthCheck -Bold -Underline
                        BlankLine
                        Paragraph {
                            Text $reportTranslate.GetAbrADForest.BestPractice -Bold
                            Text $reportTranslate.GetAbrADForest.RecycleBinBP
                        }
                        BlankLine
                        Paragraph {
                            Text $reportTranslate.GetAbrADForest.Reference -Bold
                            BlankLine
                            Text $reportTranslate.GetAbrADForest.RecycleBinRef -Color blue

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