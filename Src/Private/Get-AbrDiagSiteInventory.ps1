function Get-AbrDiagSiteInventory {
    <#
    .SYNOPSIS
        Function to diagram Microsoft Active Directory Sites Inventory.
    .DESCRIPTION
        Build a diagram of the configuration of Microsoft Active Directory to a supported formats using Psgraph.
    .NOTES
        Version:        0.9.9
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
        Write-Verbose ($reportTranslate.NewADDiagram.gereratingDiag -f 'Sites Inventory')
    }

    process {
        Write-Verbose -Message ($reportTranslate.NewADDiagram.connectingSites -f $($ForestRoot))
        try {
            if ($ForestRoot) {

                $SitesGroups = Get-AbrADSitesInventoryInfo

                if ($SitesGroups) {
                    SubGraph ForestSubGraph -Attributes @{Label = (Add-DiaHtmlLabel -ImagesObj $Images -Label $ForestRoot -IconType 'ForestRoot' -IconDebug $IconDebug -SubgraphLabel -IconWidth 50 -IconHeight 50 -Fontsize 22 -FontName 'Segoe UI' -FontColor $Fontcolor -FontBold) ; fontsize = 24; penwidth = 1.5; labelloc = 't'; style = $SubGraphDebug.style ; color = $SubGraphDebug.color } {
                        SubGraph MainSubGraph -Attributes @{Label = ' ' ; fontsize = 24; penwidth = 1.5; labelloc = 't'; style = $SubGraphDebug.style; color = $SubGraphDebug.color } {
                            if (($SitesGroups | Measure-Object).Count -ge 1) {
                                $ChildSiteSubgraphArray = @()
                                foreach ($SiteGroupOBJ in $SitesGroups) {

                                    if ($SiteGroupOBJ.DomainControllers.DCsArray) {

                                        $ChildDCsNodes = Add-DiaHtmlTable -Name ChildDCsNodes -ImagesObj $Images -Rows $SiteGroupOBJ.DomainControllers.DCsArray -ALIGN 'Center' -ColumnSize 3 -IconDebug $IconDebug -TableStyle 'dashed,rounded' -NoFontBold -FontSize 18

                                        $ChildDCsNodesSubgraph = Add-DiaHtmlSubGraph -Name ChildDCsNodesSubgraph -ImagesObj $Images -TableArray $ChildDCsNodes -Align 'Center' -IconDebug $IconDebug -Label $reportTranslate.NewADDiagram.DomainControllers -LabelPos 'top' -TableStyle 'dashed,rounded' -TableBorder '1' -ColumnSize 3 -TableBorderColor 'gray' -FontColor $Fontcolor -IconType 'AD_DC' -FontSize 18

                                    } else {

                                        $ChildDCsNodesSubgraph = Add-DiaHtmlSubGraph -Name ChildDCsNodesSubgraph -ImagesObj $Images -TableArray $reportTranslate.NewADDiagram.NoSiteDC -Align 'Center' -IconDebug $IconDebug -Label $reportTranslate.NewADDiagram.DomainControllers -LabelPos 'top' -TableStyle 'dashed,rounded' -TableBorder '1' -ColumnSize 3 -TableBorderColor 'gray' -FontColor $Fontcolor -IconType 'AD_DC' -FontSize 22
                                    }

                                    if ($SiteGroupOBJ.Subnets.SubnetArray) {

                                        $ChildSubnetsNodes = Add-DiaHtmlTable -Name ChildSubnetsNodes -ImagesObj $Images -Rows $SiteGroupOBJ.Subnets.SubnetArray -ALIGN 'Center' -ColumnSize 3 -IconDebug $IconDebug -TableStyle 'dashed,rounded' -NoFontBold -FontSize 18

                                        $ChildSubnetsNodesSubgraph = Add-DiaHtmlSubGraph -Name ChildSubnetsNodesSubgraph -ImagesObj $Images -TableArray $ChildSubnetsNodes -Align 'Center' -IconDebug $IconDebug -Label $reportTranslate.NewADDiagram.Subnets -LabelPos 'top' -TableStyle 'dashed,rounded' -TableBorder '1' -ColumnSize 3 -TableBorderColor 'gray' -FontColor $Fontcolor -IconType 'AD_Site_Subnet' -FontSize 22
                                    } else {

                                        $ChildSubnetsNodesSubgraph = Add-DiaHtmlSubGraph -Name ChildSubnetsNodesSubgraph -ImagesObj $Images -TableArray $reportTranslate.NewADDiagram.NoSiteSubnet -Align 'Center' -IconDebug $IconDebug -Label $reportTranslate.NewADDiagram.Subnets -LabelPos 'top' -TableStyle 'dashed,rounded' -TableBorder '1' -ColumnSize 3 -TableBorderColor 'gray' -FontColor $Fontcolor -IconType 'AD_Site_Subnet' -FontSize 22
                                    }

                                    $ChildSiteSubgraph = @()

                                    $ChildSiteSubgraph += $ChildDCsNodesSubgraph, $ChildSubnetsNodesSubgraph

                                    $ChildSiteSubgraphArray += Add-DiaHtmlSubGraph -Name ChildSiteSubgraphArray -ImagesObj $Images -TableArray $ChildSiteSubgraph -Align 'Center' -IconType 'AD_Site' -IconDebug $IconDebug -Label $SiteGroupOBJ.Name -LabelPos 'top' -TableStyle 'dashed,rounded' -TableBorder '1' -ColumnSize 3 -TableBorderColor 'gray' -FontColor $Fontcolor -FontSize 22
                                }

                                Node -Name 'SitesTopology' -Attributes @{Label = (Add-DiaHtmlSubGraph -Name SitesTopology -ImagesObj $Images -TableArray $ChildSiteSubgraphArray -Align 'Center' -IconDebug $IconDebug -Label $reportTranslate.NewADDiagram.Sites -LabelPos 'top' -TableStyle 'dashed,rounded' -TableBorder '1' -ColumnSize 3 -TableBorderColor 'gray' -FontColor $Fontcolor -FontSize 22); shape = 'plain'; fillColor = 'transparent'; fontsize = 14; fontname = 'Segoe Ui' }

                            } else {
                                Node -Name NoSites -Attributes @{Label = $reportTranslate.NewADDiagram.NoSites; shape = 'rectangle'; labelloc = 'c'; fixedsize = $true; width = '3'; height = '2'; fillColor = 'transparent'; penwidth = 0 }
                            }
                        }
                    }
                }
            }
        } catch {
            Write-Verbose $_.Exception.Message
        }
    }
    end {}
}