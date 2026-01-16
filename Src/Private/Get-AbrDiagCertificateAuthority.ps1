function Get-AbrDiagCertificateAuthority {
    <#
    .SYNOPSIS
        Function to diagram Microsoft Active Directory Certificate Authority.
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
        Write-Verbose -Message ($reportTranslate.NewADDiagram.gereratingDiag -f 'Certificate Authority')
    }

    process {
        Write-Verbose -Message ($reportTranslate.NewADDiagram.connectingDomain -f $($ForestRoot))
        try {
            if ($ForestRoot) {

                $CAInfo = Get-AbrADCAInfo

                if ($CAInfo) {
                    SubGraph ForestSubGraph -Attributes @{Label = (Add-DiaHtmlLabel -ImagesObj $Images -Label $ForestRoot -IconType 'ForestRoot' -IconDebug $IconDebug -SubgraphLabel -IconWidth 50 -IconHeight 50 -Fontsize 22 -FontName 'Segoe UI' -FontColor $Fontcolor -FontBold) ; fontsize = 24; penwidth = 1.5; labelloc = 't'; style = $SubGraphDebug.style ; color = $SubGraphDebug.color } {
                        SubGraph MainSubGraph -Attributes @{Label = ' ' ; fontsize = 24; penwidth = 1.5; labelloc = 't'; style = $SubGraphDebug.style; color = $SubGraphDebug.color } {
                            if ($CAInfo | Where-Object { $_.IsRoot }) {

                                if (($CAInfo | Where-Object { $_.IsRoot }).AditionalInfo.Type -eq 'Standalone CA') {
                                    $CALabel = $reportTranslate.NewADDiagram.caStdRootCA
                                } else {
                                    $CALabel = $reportTranslate.NewADDiagram.caEntRootCA
                                }

                                $CARootNodes = Add-DiaHtmlNodeTable -Name CARootNodes -ImagesObj $Images -inputObject ($CAInfo | Where-Object { $_.IsRoot }).CAName -Align 'Center' -iconType 'AD_Certificate' -ColumnSize 4 -IconDebug $IconDebug -MultiIcon -AditionalInfo ($CAInfo | Where-Object { $_.IsRoot }).AditionalInfo -FontSize 18 -TableBorderColor $Edgecolor

                                Node -Name 'RootCA' -Attributes @{Label = (Add-DiaHtmlSubGraph -Name RootCA -ImagesObj $Images -TableArray $CARootNodes -Align 'Center' -IconDebug $IconDebug -Label $CALabel -LabelPos 'top' -TableStyle 'dashed,rounded' -TableBorder '1' -ColumnSize 3 -IconType 'AD_PKI_Logo' -FontColor $Fontcolor -FontSize 24 -FontBold -TableBorderColor $Edgecolor); shape = 'plain'; fillColor = 'transparent'; fontsize = 18; fontname = 'Segoe Ui' }
                            }

                            if ($CAInfo | Where-Object { $_.IsRoot -eq $false }) {

                                $CASubordinateNodes = Add-DiaHtmlNodeTable -Name CASubordinateNodes -ImagesObj $Images -inputObject ($CAInfo | Where-Object { $_.IsRoot -eq $false }).CAName -Align 'Center' -iconType 'AD_Certificate' -ColumnSize 4 -IconDebug $IconDebug -MultiIcon -AditionalInfo ($CAInfo | Where-Object { $_.IsRoot -eq $false }).AditionalInfo -FontSize 18 -TableBorderColor $Edgecolor

                                Node -Name 'SubordinateCA' -Attributes @{Label = (Add-DiaHtmlSubGraph -Name SubordinateCA -ImagesObj $Images -TableArray $CASubordinateNodes -Align 'Center' -IconDebug $IconDebug -Label $reportTranslate.NewADDiagram.caEntSubCA -LabelPos 'top' -TableStyle 'dashed,rounded' -TableBorder '1' -ColumnSize 3 -IconType 'AD_PKI_Logo' -FontColor $Fontcolor -FontSize 24 -FontBold -TableBorderColor $Edgecolor); shape = 'plain'; fillColor = 'transparent'; fontsize = 18; fontname = 'Segoe Ui' }

                            }

                            if ($CARootNodes -and $CASubordinateNodes) {
                                Edge -From RootCA -To SubordinateCA @{minlen = 2 }
                            }
                        }
                    }
                } else {
                    Node -Name NoDomain @{Label = $reportTranslate.NewADDiagram.NoCA; shape = 'rectangle'; labelloc = 'c'; fixedsize = $true; width = '5'; height = '3'; fillColor = 'transparent'; penwidth = 1.5; style = 'dashed'; color = 'gray' }
                }
            }
        } catch {
            Write-Verbose $_.Exception.Message
        }
    }
    end {}
}