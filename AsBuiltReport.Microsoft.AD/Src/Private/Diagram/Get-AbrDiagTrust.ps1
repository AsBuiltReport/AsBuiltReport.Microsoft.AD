function Get-AbrDiagTrust {
    <#
    .SYNOPSIS
        Function to diagram Microsoft Active Directory Trusts.
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
        Write-Verbose $reportTranslate.NewADDiagram.genDiagTrust
    }

    process {
        Write-Verbose -Message ($reportTranslate.NewADDiagram.connectingTrusts -f $($ForestRoot))
        try {
            if ($ForestRoot) {

                $TrustsInfo = Get-AbrADTrustsInfo

                if ($TrustsInfo) {
                    SubGraph ForestSubGraph -Attributes @{Label = (Add-HtmlLabel -ImagesObj $Images -Label $ForestRoot -IconType 'ForestRoot' -IconDebug $IconDebug -SubgraphLabel -IconWidth 50 -IconHeight 50 -Fontsize 22 -FontName 'Segoe UI' -FontColor $Fontcolor -FontBold -TableBackgroundColor $MainGraphBGColor -CellBackgroundColor $MainGraphBGColor); fontsize = 24; penwidth = 1.5; labelloc = 't'; style = $SubGraphDebug.style ; color = $SubGraphDebug.color } {
                        SubGraph MainSubGraph -Attributes @{Label = ' ' ; fontsize = 24; penwidth = 1.5; labelloc = 't'; style = $SubGraphDebug.style; color = $SubGraphDebug.color } {
                            if (($TrustsInfo.Name | Measure-Object).count -gt 10) {
                                $ChildDomainsNodes = $TrustsInfo.Label

                                $ForestRootDomain = Remove-SpecialCharacter -String "$($TrustsInfo.Source[0])ForestRoot" -SpecialChars '\-. '
                                Add-NodeIcon -Name 'TrustDestinations' -IconType 'NoIcon' -ImagesObj $Images -NodeObject -GraphvizAttributes @{Label = (Add-HtmlSubGraph -Name TrustDestinations -ImagesObj $Images -TableArray $ChildDomainsNodes -Align 'Center' -IconDebug $IconDebug -Label $reportTranslate.NewADDiagram.TrustRelationships -LabelPos 'top' -TableStyle 'dashed,rounded' -TableBorder '1' -ColumnSize 3 -FontSize 22 -FontName 'Segoe UI' -TableBorderColor $Edgecolor -FontColor $Fontcolor -TableBackgroundColor $MainGraphBGColor); shape = 'plain'; fillColor = 'transparent'; fontsize = 18; fontname = 'Segoe Ui' }
                                Add-NodeIcon -Name $ForestRootDomain -IconType 'NoIcon' -ImagesObj $Images -NodeObject -GraphvizAttributes @{Label = $TrustsInfo.SourceLabel[0]; shape = 'plain'; fillColor = 'transparent' }
                                Add-NodeEdge -From $ForestRootDomain -To 'TrustDestinations' -EdgeLength 2 -EdgeStyle 'dashed' -EdgeColor $Edgecolor -EdgeThickness 2 -Arrowtail 'normal'
                            } else {
                                foreach ($TrustsObj in $TrustsInfo) {
                                    $SourceDomain = Remove-SpecialCharacter -String "$($TrustsObj.Source)Trusts" -SpecialChars '\-. '
                                    Add-NodeIcon -Name $TrustsObj.Name -IconType 'NoIcon' -ImagesObj $Images -NodeObject -GraphvizAttributes @{Label = $TrustsObj.Label; shape = 'plain'; fillColor = 'transparent' }
                                    Add-NodeIcon -Name $SourceDomain -IconType 'NoIcon' -ImagesObj $Images -NodeObject -GraphvizAttributes @{Label = $TrustsObj.SourceLabel; shape = 'plain'; fillColor = 'transparent' }
                                    if ($TrustsObj.Direction -eq 'Bidirectional') {
                                        Add-NodeEdge -From $SourceDomain -To $TrustsObj.Name -EdgeLength 2 -EdgeStyle 'dashed' -EdgeColor $Edgecolor -EdgeThickness 2 -Arrowtail 'normal' -Arrowhead 'normal'
                                    } elseif ($TrustsObj.Direction -eq 'Outbound') {
                                        Add-NodeEdge -From $SourceDomain -To $TrustsObj.Name -EdgeLength 2 -EdgeStyle 'dashed' -EdgeColor $Edgecolor -EdgeThickness 2 -Arrowtail 'dot' -Arrowhead 'normal'
                                    } elseif ($TrustsObj.Direction -eq 'Inbound') {
                                        Add-NodeEdge -From $SourceDomain -To $TrustsObj.Name -EdgeLength 2 -EdgeStyle 'dashed' -EdgeColor $Edgecolor -EdgeThickness 2 -Arrowtail 'normal' -Arrowhead 'dot'
                                    } else {
                                        Add-NodeEdge -From $SourceDomain -To $TrustsObj.Name -EdgeLength 2 -EdgeStyle 'dashed' -EdgeColor $Edgecolor -EdgeThickness 2 -Arrowtail 'normal'
                                    }
                                }
                            }
                        }
                    }
                } else {
                    Add-NodeIcon -Name 'NoTrusts' -IconType 'NoIcon' -ImagesObj $Images -NodeObject -GraphvizAttributes @{Label = $reportTranslate.NewADDiagram.NoTrusts; shape = 'rectangle'; labelloc = 'c'; fixedsize = $true; width = '3'; height = '2'; fillColor = 'transparent'; penwidth = 1.5; style = 'dashed'; color = $Edgecolor }
                }
            }
        } catch {
            Write-Verbose $_.Exception.Message
        }
    }
    end {}
}