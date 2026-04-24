function Get-AbrADForestInfo {
    <#
    .SYNOPSIS
        Function to extract microsoft active directory forest information.
    .DESCRIPTION
        Build a diagram of the configuration of Microsoft Active Directory to a supported formats using Psgraph.
    .NOTES
        Version:        1.0.0
        Author:         Jonathan Colon
        Twitter:        @jcolonfzenpr
        Github:         rebelinux
    .LINK
        https://github.com/rebelinux/Diagrammer.Microsoft.AD
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.List[object]])]

    param()

    begin {
    }

    process {
        Write-Verbose -Message ($reportTranslate.NewADDiagram.connectingForest -f $($ForestRoot))
        try {
            $ForestObj = $ADSystem
            $ChildDomains = $ADSystem.Domains

            # $ChildDomains = @("pharmax.local", "acad.pharmax.local", "it.admin.pharmax.local","acad.hr.pharmax.local","admin.hr.pharmax.local", "hr.pharmax.local", "admin.pharmax.local")
            # $ChildDomains = @("pharmax.local")

            $ParentToChildren = @{}
            foreach ($domain in $ChildDomains) {
                $parts = $domain -split '\.'
                if ($parts.Count -gt 2) {
                    $parent = ($parts[1..($parts.Count - 1)] -join '.')
                    if (-not $ParentToChildren.ContainsKey($parent)) {
                        $ParentToChildren[$parent] = @()
                    }
                    $ParentToChildren[$parent] += $domain
                } else {
                    if (-not $ParentToChildren.ContainsKey($domain)) {
                        $ParentToChildren[$domain] = @()
                    }
                }
            }

            $ParentChildObj = foreach ($parent in $ParentToChildren.Keys) {
                [PSCustomObject]@{
                    Parent = $parent
                    Children = $ParentToChildren[$parent]
                }
            }

            $ForestInfo = [System.Collections.Generic.List[object]]::new()
            if ($ParentChildObj.Children) {
                foreach ($Childs in $ParentChildObj | Sort-Object) {
                    foreach ($ChildDomain in $Childs.Children) {
                        $ChildDomainsInfo = try {
                            Invoke-CommandWithTimeout -Session $DiagramTempPssSession -ScriptBlock { Get-ADDomain -Identity $using:ChildDomain }
                        } catch {
                            Out-Null
                        }

                        $RootDomainsInfo = try {
                            Invoke-CommandWithTimeout -Session $DiagramTempPssSession -ScriptBlock { Get-ADDomain -Identity ($using:ForestObj).RootDomain }
                        } catch {
                            Out-Null
                        }

                        $FuncionalLevel = @{
                            Windows2012R2Domain = '2012 R2 (Domain)'
                            Windows2012R2Forest = '2012 R2 (Forest)'
                            Windows2016Domain = '2016 (Domain)'
                            Windows2016Forest = '2016 (Forest)'
                            Windows2025Domain = '2025 (Domain)'
                            Windows2025Forest = '2025 (Forest)'
                        }

                        $AditionalForestInfo = [PSCustomObject] [ordered] @{
                            $reportTranslate.NewADDiagram.fDomainNaming = $ForestObj.DomainNamingMaster.ToString().ToUpper().Split('.')[0]
                            $reportTranslate.NewADDiagram.fInfrastructure = switch ([string]::IsNullOrEmpty($RootDomainsInfo.InfrastructureMaster)) {
                                $true { 'Unknown' }
                                $false { $RootDomainsInfo.InfrastructureMaster.ToString().ToUpper().Split('.')[0] }
                                default { '--' }
                            }
                            $reportTranslate.NewADDiagram.fPDC = switch ([string]::IsNullOrEmpty($RootDomainsInfo.PDCEmulator)) {
                                $true { 'Unknown' }
                                $false { $RootDomainsInfo.PDCEmulator.ToString().ToUpper().Split('.')[0] }
                                default { '--' }
                            }
                            $reportTranslate.NewADDiagram.fRID = switch ([string]::IsNullOrEmpty($RootDomainsInfo.RIDMaster)) {
                                $true { 'Unknown' }
                                $false { $RootDomainsInfo.RIDMaster.ToString().ToUpper().Split('.')[0] }
                                default { '--' }
                            }
                            $reportTranslate.NewADDiagram.fSchema = $ForestObj.SchemaMaster.ToString().ToUpper().Split('.')[0]
                            $reportTranslate.NewADDiagram.fFuncLevel = "$($FuncionalLevel[$ForestObj.ForestMode]) $($FuncionalLevel[$RootDomainsInfo.DomainMode])"
                        }

                        $AditionalDomainInfo = [PSCustomObject] [ordered] @{
                            $reportTranslate.NewADDiagram.fInfrastructure = switch ([string]::IsNullOrEmpty($ChildDomainsInfo.InfrastructureMaster)) {
                                $true { 'Unknown' }
                                $false { $ChildDomainsInfo.InfrastructureMaster.ToString().ToUpper().Split('.')[0] }
                                default { '--' }
                            }
                            $reportTranslate.NewADDiagram.fPDC = switch ([string]::IsNullOrEmpty($ChildDomainsInfo.PDCEmulator)) {
                                $true { 'Unknown' }
                                $false { $ChildDomainsInfo.PDCEmulator.ToString().ToUpper().Split('.')[0] }
                                default { '--' }
                            }
                            $reportTranslate.NewADDiagram.fRID = switch ([string]::IsNullOrEmpty($ChildDomainsInfo.RIDMaster)) {
                                $true { 'Unknown' }
                                $false { $ChildDomainsInfo.RIDMaster.ToString().ToUpper().Split('.')[0] }
                                default { '--' }
                            }
                            $reportTranslate.NewADDiagram.fFuncLevel = switch ([string]::IsNullOrEmpty($ChildDomainsInfo.DomainMode)) {
                                $true { 'Unknown' }
                                $false { $FuncionalLevel[$ChildDomainsInfo.DomainMode] }
                                default { '--' }
                            }
                        }

                        if ($ChildDomain -eq $ForestObj.Name) {
                            $IsForest = $true

                        } else {
                            $IsForest = $false
                        }

                        $TempForestInfo = [PSCustomObject]@{
                            Name = Remove-SpecialCharacter -String "$($ChildDomain)ChildDomain" -SpecialChars '\-. '
                            ChildDomainLabel = $ChildDomain
                            Label = Add-NodeIcon -Name $ChildDomain -IconType 'AD_Domain' -Align 'Center' -ImagesObj $Images -IconDebug $IconDebug -AditionalInfo $AditionalDomainInfo -FontSize 18 -TableBackgroundColor $MainGraphBGColor -CellBackgroundColor $MainGraphBGColor -FontColor $Fontcolor
                            RootDomain = $ForestObj.RootDomain
                            RootDomainLabel = Add-NodeIcon -Name $ForestObj.RootDomain -IconType 'AD_Domain' -Align 'Center' -ImagesObj $Images -IconDebug $IconDebug -AditionalInfo $AditionalForestInfo -FontSize 18 -TableBackgroundColor $MainGraphBGColor -CellBackgroundColor $MainGraphBGColor -FontColor $Fontcolor
                            ChildDomain = $ChildDomain
                            ParentDomain = Remove-SpecialCharacter -String "$($Childs.Parent)ChildDomain" -SpecialChars '\-. '
                            AditionalInfo = $AditionalDomainInfo
                            IsForest = $IsForest
                        }
                        $ForestInfo.Add($TempForestInfo)
                    }
                }
            } else {
                $RootDomainsInfo = try {
                    Invoke-CommandWithTimeout -Session $DiagramTempPssSession -ScriptBlock { Get-ADDomain -Identity ($using:ForestObj).RootDomain }
                } catch {
                    Out-Null
                }

                $FuncionalLevel = @{
                    Windows2012R2Domain = '2012 R2 (Domain)'
                    Windows2012R2Forest = '2012 R2 (Forest)'
                    Windows2016Domain = '2016 (Domain)'
                    Windows2016Forest = '2016 (Forest)'
                    Windows2025Domain = '2025 (Domain)'
                    Windows2025Forest = '2025 (Forest)'
                }

                $AditionalForestInfo = [PSCustomObject] [ordered] @{
                    $reportTranslate.NewADDiagram.fDomainNaming = $ForestObj.DomainNamingMaster.ToString().ToUpper().Split('.')[0]
                    $reportTranslate.NewADDiagram.fInfrastructure = switch ([string]::IsNullOrEmpty($RootDomainsInfo.InfrastructureMaster)) {
                        $true { 'Unknown' }
                        $false { $RootDomainsInfo.InfrastructureMaster.ToString().ToUpper().Split('.')[0] }
                        default { '--' }
                    }
                    $reportTranslate.NewADDiagram.fPDC = switch ([string]::IsNullOrEmpty($RootDomainsInfo.PDCEmulator)) {
                        $true { 'Unknown' }
                        $false { $RootDomainsInfo.PDCEmulator.ToString().ToUpper().Split('.')[0] }
                        default { '--' }
                    }
                    $reportTranslate.NewADDiagram.fRID = switch ([string]::IsNullOrEmpty($RootDomainsInfo.RIDMaster)) {
                        $true { 'Unknown' }
                        $false { $RootDomainsInfo.RIDMaster.ToString().ToUpper().Split('.')[0] }
                        default { '--' }
                    }
                    $reportTranslate.NewADDiagram.fSchema = $ForestObj.SchemaMaster.ToString().ToUpper().Split('.')[0]
                    $reportTranslate.NewADDiagram.fFuncLevel = "$($FuncionalLevel[$ForestObj.ForestMode]) $($FuncionalLevel[$RootDomainsInfo.DomainMode])"
                }

                $TempForestInfo = [PSCustomObject]@{
                    Name = Remove-SpecialCharacter -String "$($ForestObj.Name)RootDomain" -SpecialChars '\-. '
                    Label = Add-NodeIcon -Name $ForestObj.RootDomain -IconType 'AD_Domain' -Align 'Center' -ImagesObj $Images -IconDebug $IconDebug -AditionalInfo $AditionalForestInfo -FontSize 18 -TableBackgroundColor $MainGraphBGColor -CellBackgroundColor $MainGraphBGColor -FontColor $Fontcolor
                    AditionalInfo = $AditionalForestInfo
                }
                $ForestInfo.Add($TempForestInfo)
            }
            $ForestInfo
        } catch {
            Write-Verbose $_.Exception.Message
        }
    }
    end {}
}
