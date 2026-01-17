function Get-AbrDiagTrust {
    <#
    .SYNOPSIS
        Function to diagram Microsoft Active Directory Trusts.
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
        Write-Verbose $reportTranslate.NewADDiagram.genDiagTrust
    }

    process {
        Write-Verbose -Message ($reportTranslate.NewADDiagram.connectingTrusts -f $($ForestRoot))
        try {
            if ($ForestRoot) {

                $TrustsInfo = Get-AbrADTrustsInfo

                if ($TrustsInfo) {
                    SubGraph ForestSubGraph -Attributes @{Label = (Add-DiaHtmlLabel -ImagesObj $Images -Label $ForestRoot -IconType 'ForestRoot' -IconDebug $IconDebug -SubgraphLabel -IconWidth 50 -IconHeight 50 -Fontsize 22 -FontName 'Segoe UI' -FontColor $Fontcolor -FontBold); fontsize = 24; penwidth = 1.5; labelloc = 't'; style = $SubGraphDebug.style ; color = $SubGraphDebug.color } {
                        SubGraph MainSubGraph -Attributes @{Label = ' ' ; fontsize = 24; penwidth = 1.5; labelloc = 't'; style = $SubGraphDebug.style; color = $SubGraphDebug.color } {
                            if (($TrustsInfo.Name | Measure-Object).count -gt 3) {

                                $ChildDomainsNodes = $TrustsInfo.Label

                                Node -Name 'TrustDestinations' -Attributes @{Label = (Add-DiaHtmlSubGraph -Name TrustDestinations -ImagesObj $Images -TableArray $ChildDomainsNodes -Align 'Center' -IconDebug $IconDebug -Label $reportTranslate.NewADDiagram.TrustRelationships -LabelPos 'top' -TableStyle 'dashed,rounded' -TableBorder '1' -ColumnSize 3 -FontSize 22 -FontName 'Segoe UI' -TableBorderColor $Edgecolor -FontColor $Fontcolor); shape = 'plain'; fillColor = 'transparent'; fontsize = 18; fontname = 'Segoe Ui' }

                                $ForestRootDomain = Remove-SpecialChar -String "$($TrustsInfo.Source[0])ForestRoot" -SpecialChars '\-. '
                                Node -Name $ForestRootDomain -Attributes @{Label = $TrustsInfo.SourceLabel[0]; shape = 'plain'; fillColor = 'transparent' }
                                Edge -From $ForestRootDomain -To TrustDestinations @{minlen = 2 }
                            } else {
                                foreach ($TrustsObj in $TrustsInfo) {
                                    $SourceDomain = Remove-SpecialChar -String "$($TrustsObj.Source)Trusts" -SpecialChars '\-. '
                                    Node -Name $TrustsObj.Name -Attributes @{Label = $TrustsObj.Label; shape = 'plain'; fillColor = 'transparent' }
                                    Node -Name $SourceDomain -Attributes @{Label = $TrustsObj.SourceLabel; shape = 'plain'; fillColor = 'transparent' }
                                    if ($TrustsObj.Direction -eq 'Bidirectional') {
                                        Edge -From $SourceDomain -To $TrustsObj.Name @{minlen = 2; arrowtail = 'normal'; arrowhead = 'normal' }
                                    } elseif ($TrustsObj.Direction -eq 'Outbound') {
                                        Edge -From $SourceDomain -To $TrustsObj.Name @{minlen = 2; arrowtail = 'dot'; arrowhead = 'normal' }
                                    } elseif ($TrustsObj.Direction -eq 'Inbound') {
                                        Edge -From $SourceDomain -To $TrustsObj.Name @{minlen = 2; arrowtail = 'normal'; arrowhead = 'dot' }
                                    } else {
                                        Edge -From $SourceDomain -To $TrustsObj.Name @{minlen = 2 }
                                    }
                                }
                            }
                        }
                    }
                } else {
                    Node -Name NoTrusts @{Label = $reportTranslate.NewADDiagram.NoTrusts; shape = 'rectangle'; labelloc = 'c'; fixedsize = $true; width = '3'; height = '2'; fillColor = 'transparent'; penwidth = 1.5; style = 'dashed'; color = 'gray' }
                }
            }
        } catch {
            Write-Verbose $_.Exception.Message
        }
    }
    end {}
}