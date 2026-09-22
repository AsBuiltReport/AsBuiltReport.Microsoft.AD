function Get-AbrDiagSite {
    <#
    .SYNOPSIS
        Function to diagram Microsoft Active Directory Forest.
    .DESCRIPTION
        Build a diagram of the configuration of Microsoft Active Directory to a supported formats using Psgraph.
    .NOTES
        Version:        1.0.4
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
        Write-Verbose ($reportTranslate.NewADDiagram.gereratingDiag -f 'Sites')
    }

    process {
        Write-Verbose -Message ($reportTranslate.NewADDiagram.connectingSites -f $($ForestRoot))
        try {
            if ($ForestRoot) {

                $SitesInfo = Get-AbrADSitesInfo

                if ($SitesInfo) {
                    SubGraph ForestSubGraph -Attributes @{Label = (Add-HtmlLabel -ImagesObj $Images -Label $ForestRoot -IconType 'ForestRoot' -IconDebug $IconDebug -SubgraphLabel -IconWidth 50 -IconHeight 50 -Fontsize 22 -FontName 'Segoe UI' -FontColor $Fontcolor -FontBold -TableBackgroundColor $MainGraphBGColor -CellBackgroundColor $MainGraphBGColor) ; fontsize = 24; penwidth = 1.5; labelloc = 't'; style = $SubGraphDebug.style ; color = $SubGraphDebug.color } {
                        SubGraph MainSubGraph -Attributes @{Label = ' ' ; fontsize = 24; penwidth = 1.5; labelloc = 't'; style = $SubGraphDebug.style; color = $SubGraphDebug.color } {
                            if ($SitesInfo.Site) {
                                foreach ($SitesObj in $SitesInfo) {
                                    $Site = Remove-SpecialCharacter -String "$($SitesObj.Name)" -SpecialChars '\-. '
                                    Add-NodeIcon -Name $Site -FontBold -IconDebug $IconDebug -IconType 'NoIcon' -ImagesObj $Images -NodeObject -GraphvizAttributes @{Label = $SitesObj.Name; shape = 'rectangle'; labelloc = 'c'; penwidth = 0; fillColor = '#b14b5a' }
                                    foreach ($Link in $SitesObj.SiteLink) {
                                        # Start - Information for each SiteLink. Example: "Name: (Pharmax-to-Acad) SiteLink (Cost: 10) (Frequency: 15 minutes)"
                                        $SiteLink = Remove-SpecialCharacter -String $Link.Name -SpecialChars '\-. '
                                        Add-NodeIcon -Name $SiteLink -IconDebug $IconDebug -IconType 'NoIcon' -ImagesObj $Images -NodeObject -GraphvizAttributes @{Label = (Add-HtmlTable -Name SiteLink -Align 'Center' -IconDebug $IconDebug -Rows ($Link.AditionalInfo.GetEnumerator() | ForEach-Object { "$($_.key): $($_.value)" }) -ColumnSize 1 -FontSize 18 -FontColor $Fontcolor -TableBackgroundColor $MainGraphBGColor); shape = 'plain'; fillColor = 'transparent' }
                                        Add-NodeEdge -From $Site -To $SiteLink -EdgeLength 2 -EdgeStyle 'dashed' -EdgeColor $Edgecolor -EdgeThickness 1 -Arrowtail none -Arrowhead none
                                        # End - Information for each SiteLink
                                        foreach ($SiteLinkSite in $Link.Sites) {
                                            # Start - Information for each connected Site. Example: "Name: (Pharmax)"
                                            $SiteIncluded = Remove-SpecialCharacter -String $SiteLinkSite -SpecialChars '\-. '
                                            Add-NodeIcon -Name $SiteIncluded -FontBold -IconType 'AD_Site_Replications' -ImagesObj $Images -NodeObject -FontSize 18 -LabelName $SiteLinkSite -IconDebug $IconDebug
                                            Add-NodeEdge -From $SiteLink -To $SiteIncluded -EdgeLength 2 -EdgeStyle 'dashed' -EdgeColor $Edgecolor -EdgeThickness 1 -Arrowtail none -Arrowhead normal
                                        }
                                    }
                                }
                            } else {
                                $Site = Remove-SpecialCharacter -String "$($SitesInfo.Name)" -SpecialChars '\-. '
                                Add-NodeIcon -Name $Site -IconType 'NoIcon' -ImagesObj $Images -NodeObject -GraphvizAttributes @{Label = $SitesInfo.Name; penwidth = 1; width = 2; height = .5 }
                            }
                        }
                    }
                } else {
                    Add-NodeIcon -Name 'NoSites' -IconType 'NoIcon' -ImagesObj $Images -NodeObject -GraphvizAttributes @{Label = $reportTranslate.NewADDiagram.NoSites; shape = 'rectangle'; labelloc = 'c'; fixedsize = $true; width = '3'; height = '2'; fillColor = 'transparent'; penwidth = 0 }
                }
            }
        } catch {
            Write-Verbose $_.Exception.Message
        }
    }
    end {}
}
