function Get-AbrDiagReplication {
    <#
    .SYNOPSIS
        Function to diagram Microsoft Active Directory Replication.
    .DESCRIPTION
        Build a diagram of the configuration of Microsoft Active Directory to a supported formats using Psgraph.
    .NOTES
        Version:        0.9.12
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
                $HTMLLegend = '<table border="0"><tr><td><font color="darkgreen">■</font> <b>IntraSite</b> <font color="darkblue">■</font> <b>InterSite</b></td></tr></table>'
                if ($ReplInfo) {
                    SubGraph ForestSubGraph -Attributes @{Label = (Add-DiaHtmlLabel -ImagesObj $Images -Label $ForestRoot -IconType 'ForestRoot' -IconDebug $IconDebug -SubgraphLabel -IconWidth 50 -IconHeight 50 -Fontsize 22 -FontName 'Segoe UI' -FontColor $Fontcolor -FontBold) ; fontsize = 24; penwidth = 1.5; labelloc = 't'; style = $SubGraphDebug.style; color = $SubGraphDebug.color } {
                        SubGraph MainSubGraph -Attributes @{Label = $HTMLLegend ; fontsize = 24; penwidth = 1.5; labelloc = 't'; style = $SubGraphDebug.style; color = $SubGraphDebug.color } {
                            # Collect unique sites from replication data
                            $Sites = ($ReplInfo | Select-Object -ExpandProperty FromSite) + ($ReplInfo | Select-Object -ExpandProperty ToSite) | Select-Object -Unique | Where-Object { $_ -ne 'Unknown' }

                            # Collect unique DCs from replication data
                            $AllDCs = ($ReplInfo | Select-Object -ExpandProperty FromServer) + ($ReplInfo | Select-Object -ExpandProperty ToServer) | Select-Object -Unique

                            if ($Sites -and ($Sites | Measure-Object).Count -gt 0) {

                                # Group DCs by site and draw site subgraphs
                                foreach ($Site in $Sites) {
                                    $SiteDCsFrom = $ReplInfo | Where-Object { $_.FromSite -eq $Site } | Select-Object -ExpandProperty FromServer -Unique
                                    $SiteDCsTo = $ReplInfo | Where-Object { $_.ToSite -eq $Site } | Select-Object -ExpandProperty ToServer -Unique
                                    $SiteDCs = ($SiteDCsFrom + $SiteDCsTo) | Select-Object -Unique

                                    $SiteNodeName = Remove-SpecialChar -String "$($Site)Site" -SpecialChars '\-. '
                                    SubGraph $SiteNodeName -Attributes @{Label = (Add-DiaHtmlLabel -ImagesObj $Images -Label $Site -IconType 'AD_Site' -IconDebug $IconDebug -SubgraphLabel -IconWidth 35 -IconHeight 35 -Fontsize 18 -FontName 'Segoe UI' -FontColor $Fontcolor -FontBold); fontsize = 18; penwidth = 1.5; labelloc = 't'; style = 'dashed,rounded'; color = 'gray' } {
                                        foreach ($DC in $SiteDCs) {
                                            $DCNodeName = Remove-SpecialChar -String $DC -SpecialChars '\-. '
                                            Node -Name $DCNodeName -Attributes @{Label = (Add-DiaNodeIcon -Name ($DC.Split('.')[0].ToUpper()) -IconType 'AD_DC' -Align 'Center' -ImagesObj $Images -IconDebug $IconDebug -FontSize 18); shape = 'plain'; fillColor = 'transparent' }
                                        }
                                    }
                                }

                                # Draw DCs with unknown site affiliation
                                $UnknownSiteDCs = $AllDCs | Where-Object {
                                    $DC = $_
                                    -not ($ReplInfo | Where-Object { ($_.FromServer -eq $DC -and $_.FromSite -ne 'Unknown') -or ($_.ToServer -eq $DC -and $_.ToSite -ne 'Unknown') })
                                }
                                if ($UnknownSiteDCs) {
                                    $UnknownSiteNodeName = 'UnknownSite'
                                    SubGraph $UnknownSiteNodeName -Attributes @{Label = (Add-DiaHtmlLabel -ImagesObj $Images -Label $reportTranslate.NewADDiagram.replUnknownSite -IconType 'AD_Site' -IconDebug $IconDebug -SubgraphLabel -IconWidth 35 -IconHeight 35 -Fontsize 18 -FontName 'Segoe UI' -FontColor $Fontcolor); fontsize = 18; penwidth = 1.5; labelloc = 't'; style = 'dashed,rounded'; color = 'gray' } {
                                        foreach ($DC in $UnknownSiteDCs) {
                                            $DCNodeName = Remove-SpecialChar -String $DC -SpecialChars '\-. '
                                            Node -Name $DCNodeName -Attributes @{Label = (Add-DiaNodeIcon -Name ($DC.Split('.')[0].ToUpper()) -IconType 'AD_DC' -Align 'Center' -ImagesObj $Images -IconDebug $IconDebug -FontSize 18); shape = 'plain'; fillColor = 'transparent' }
                                        }
                                    }
                                }

                            } else {
                                # No site information - draw all DCs flat
                                foreach ($DC in $AllDCs) {
                                    $DCNodeName = Remove-SpecialChar -String $DC -SpecialChars '\-. '
                                    Node -Name $DCNodeName -Attributes @{Label = (Add-DiaNodeIcon -Name ($DC.Split('.')[0].ToUpper()) -IconType 'AD_DC' -Align 'Center' -ImagesObj $Images -IconDebug $IconDebug -FontSize 18); shape = 'plain'; fillColor = 'transparent' }
                                }
                            }

                            # Draw replication edges between DCs
                            $DrawnEdges = [System.Collections.Generic.HashSet[string]]::new()
                            foreach ($Repl in $ReplInfo) {
                                $FromNodeName = Remove-SpecialChar -String $Repl.FromServer -SpecialChars '\-. '
                                $ToNodeName = Remove-SpecialChar -String $Repl.ToServer -SpecialChars '\-. '

                                if ($FromNodeName -and $ToNodeName -and $FromNodeName -ne $ToNodeName) {
                                    $EdgeKey = "$FromNodeName->$ToNodeName"
                                    if (-not $DrawnEdges.Contains($EdgeKey)) {
                                        $DrawnEdges.Add($EdgeKey) | Out-Null
                                        $EdgeLabel = & {
                                            if ($Repl.TransportProtocol) {
                                                $Repl.TransportProtocol
                                            } else {
                                                ' '
                                            }
                                        }
                                        if ($Repl.FromSite -eq $Repl.ToSite) {
                                            $EdgeColor = 'darkgreen'
                                        } else {
                                            $EdgeColor = 'darkblue'
                                        }
                                        Edge -From $FromNodeName -To $ToNodeName @{minlen = 2; label = $EdgeLabel; fontsize = 16; fontname = 'Segoe UI'; color = $EdgeColor; penwidth = 1.5 }
                                    }
                                }
                            }
                        }
                    }
                } else {
                    Node -Name NoReplication @{Label = $reportTranslate.NewADDiagram.NoReplication; shape = 'rectangle'; labelloc = 'c'; fixedsize = $true; width = '3'; height = '2'; fillColor = 'transparent'; penwidth = 1.5; style = 'dashed'; color = 'gray' }
                }
            }
        } catch {
            Write-Verbose $_.Exception.Message
        }
    }
    end {}
}
