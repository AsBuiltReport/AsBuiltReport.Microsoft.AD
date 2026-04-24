function Get-AbrDiagReplication {
    <#
    .SYNOPSIS
        Function to diagram Microsoft Active Directory Replication.
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
    [OutputType([System.Object[]])]

    param
    (

    )

    begin {
        Write-Verbose ($reportTranslate.NewADDiagram.gereratingDiag -f 'Replication')
    }

    process {
        Write-Verbose -Message ($reportTranslate.NewADDiagram.connectingReplication -f $($ForestRoot))
        try {
            if ($ForestRoot) {

                $ReplInfo = Get-AbrADReplicationInfo
                Write-Verbose -Message ($reportTranslate.NewADDiagram.buildingReplication -f $($ForestRoot))
                $HTMLLegend = ('<table border="0"><tr><td><font color="darkgreen">■</font> <b>{0}</b>  <font color="darkblue">■</font> <b>{1}</b></td></tr></table>' -f $reportTranslate.NewADDiagram.replIntraSite, $reportTranslate.NewADDiagram.replInterSite)
                if ($ReplInfo) {
                    SubGraph ForestSubGraph -Attributes @{Label = (Add-HtmlLabel -ImagesObj $Images -Label $ForestRoot -IconType 'ForestRoot' -IconDebug $IconDebug -SubgraphLabel -IconWidth 50 -IconHeight 50 -Fontsize 22 -FontName 'Segoe UI' -FontColor $Fontcolor -FontBold -TableBackgroundColor $MainGraphBGColor -CellBackgroundColor $MainGraphBGColor) ; fontsize = 24; penwidth = 1.5; labelloc = 't'; style = $SubGraphDebug.style; color = $SubGraphDebug.color } {
                        SubGraph MainSubGraph -Attributes @{Label = $HTMLLegend ; fontsize = 24; penwidth = 1.5; labelloc = 't'; style = $SubGraphDebug.style; color = $SubGraphDebug.color } {
                            # Collect unique sites and DCs from replication data
                            $Sites = ($ReplInfo | Select-Object -ExpandProperty FromSite) + ($ReplInfo | Select-Object -ExpandProperty ToSite) | Select-Object -Unique | Where-Object { $_ -ne 'Unknown' }
                            $AllDCs = ($ReplInfo | Select-Object -ExpandProperty FromServer) + ($ReplInfo | Select-Object -ExpandProperty ToServer) | Select-Object -Unique

                            if ($Sites -and ($Sites | Measure-Object).Count -gt 0) {

                                # Group DCs by site and draw each site as a visual subgraph
                                foreach ($Site in $Sites) {
                                    $SiteNodeName = Remove-SpecialCharacter -String $Site -SpecialChars '\-. '
                                    $SiteDCs = $AllDCs | Where-Object {
                                        $DC = $_
                                        ($ReplInfo | Where-Object { ($_.FromServer -eq $DC -and $_.FromSite -eq $Site) -or ($_.ToServer -eq $DC -and $_.ToSite -eq $Site) })
                                    } | Select-Object -Unique

                                    SubGraph $SiteNodeName -Attributes @{Label = (Add-HtmlLabel -ImagesObj $Images -Label $Site -IconType 'AD_Site' -IconDebug $IconDebug -SubgraphLabel -IconWidth 35 -IconHeight 35 -Fontsize 18 -FontName 'Segoe UI' -FontColor $Fontcolor -TableBackgroundColor $MainGraphBGColor -CellBackgroundColor $MainGraphBGColor); fontsize = 18; penwidth = 1.5; labelloc = 't'; style = 'dashed,rounded'; color = 'gray' } {
                                        foreach ($DC in $SiteDCs) {
                                            $DCNodeName = Remove-SpecialCharacter -String $DC -SpecialChars '\-. '
                                            Node -Name $DCNodeName -Attributes @{Label = (Add-NodeIcon -Name ($DC.Split('.')[0].ToUpper()) -IconType 'AD_DC' -Align 'Center' -ImagesObj $Images -IconDebug $IconDebug -FontSize 18 -TableBackgroundColor $MainGraphBGColor -CellBackgroundColor $MainGraphBGColor -FontColor $Fontcolor); shape = 'plain'; fillColor = 'transparent' }
                                        }
                                    }
                                }

                                # Draw DCs with unknown site affiliation in a separate subgraph
                                $UnknownSiteDCs = $AllDCs | Where-Object {
                                    $DC = $_
                                    -not ($ReplInfo | Where-Object { ($_.FromServer -eq $DC -and $_.FromSite -ne 'Unknown') -or ($_.ToServer -eq $DC -and $_.ToSite -ne 'Unknown') })
                                }
                                if ($UnknownSiteDCs) {
                                    SubGraph UnknownSite -Attributes @{Label = (Add-HtmlLabel -ImagesObj $Images -Label $reportTranslate.NewADDiagram.replUnknownSite -IconType 'AD_Site' -IconDebug $IconDebug -SubgraphLabel -IconWidth 35 -IconHeight 35 -Fontsize 18 -FontName 'Segoe UI' -FontColor $Fontcolor -TableBackgroundColor $MainGraphBGColor -CellBackgroundColor $MainGraphBGColor); fontsize = 18; penwidth = 1.5; labelloc = 't'; style = 'dashed,rounded'; color = 'gray' } {
                                        foreach ($DC in $UnknownSiteDCs) {
                                            $DCNodeName = Remove-SpecialCharacter -String $DC -SpecialChars '\-. '
                                            Node -Name $DCNodeName -Attributes @{Label = (Add-NodeIcon -Name ($DC.Split('.')[0].ToUpper()) -IconType 'AD_DC' -Align 'Center' -ImagesObj $Images -IconDebug $IconDebug -FontSize 18 -TableBackgroundColor $MainGraphBGColor -CellBackgroundColor $MainGraphBGColor -FontColor $Fontcolor); shape = 'plain'; fillColor = 'transparent' }
                                        }
                                    }
                                }
                            } else {
                                # No site information - draw all DCs without grouping
                                foreach ($DC in $AllDCs) {
                                    $DCNodeName = Remove-SpecialCharacter -String $DC -SpecialChars '\-. '
                                    Node -Name $DCNodeName -Attributes @{Label = (Add-NodeIcon -Name ($DC.Split('.')[0].ToUpper()) -IconType 'AD_DC' -Align 'Center' -ImagesObj $Images -IconDebug $IconDebug -FontSize 18 -TableBackgroundColor $MainGraphBGColor -CellBackgroundColor $MainGraphBGColor -FontColor $Fontcolor); shape = 'plain'; fillColor = 'transparent' }
                                }
                            }

                            # Draw replication edges between DCs
                            $DrawnEdges = [System.Collections.Generic.HashSet[string]]::new()
                            foreach ($Repl in $ReplInfo) {
                                $FromNodeName = Remove-SpecialCharacter -String $Repl.FromServer -SpecialChars '\-. '
                                $ToNodeName = Remove-SpecialCharacter -String $Repl.ToServer -SpecialChars '\-. '

                                if ($FromNodeName -and $ToNodeName -and $FromNodeName -ne $ToNodeName) {
                                    $EdgeKey = "$FromNodeName->$ToNodeName"
                                    if (-not $DrawnEdges.Contains($EdgeKey)) {
                                        $DrawnEdges.Add($EdgeKey) | Out-Null
                                        $EdgeColor = if ($Repl.FromSite -eq $Repl.ToSite) { 'darkgreen' } else { 'darkblue' }
                                        Edge -From $FromNodeName -To $ToNodeName @{minlen = 2; label = $Repl.TransportProtocol; fontsize = 16; fontname = 'Segoe UI'; color = $EdgeColor; penwidth = 1.5 }
                                    }
                                }
                            }
                        }
                    }
                } else {
                    Write-Verbose ($reportTranslate.NewADDiagram.emptyReplication)
                    Node -Name NoReplication @{Label = $reportTranslate.NewADDiagram.NoReplication; shape = 'rectangle'; labelloc = 'c'; fixedsize = $true; width = '3'; height = '2'; fillColor = 'transparent'; penwidth = 1.5; style = 'dashed'; color = 'gray' }
                }
            }
        } catch {
            Write-Verbose $_.Exception.Message
        }
    }
    end {}
}
