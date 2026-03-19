function Get-AbrForestSection {
    <#
    .SYNOPSIS
    Used by As Built Report to build Microsoft AD Forest Section.
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
        Write-PScriboMessage -Message ($reportTranslate.GetAbrForestSection.Collecting -f $ForestInfo)
        Show-AbrDebugExecutionTime -Start -TitleMessage 'Forest Section'
    }

    process {
        Section -Style Heading1 "$($ForestInfo.toUpper()) $($reportTranslate.GetAbrForestSection.TitleSuffix)" {
            Paragraph ($reportTranslate.GetAbrForestSection.Paragraph -f $ForestInfo)
            BlankLine
            Write-PScriboMessage -Message ($reportTranslate.GetAbrADForest.InfoLevel -f 'Forest', $InfoLevel.Forest)
            if ($InfoLevel.Forest -ge 1) {
                try {
                    Section -Style Heading2 $reportTranslate.GetAbrForestSection.Heading {
                        if ($Options.ShowDefinitionInfo) {
                            Paragraph $reportTranslate.GetAbrForestSection.DefinitionText
                            BlankLine
                        }
                        if (-not $Options.ShowDefinitionInfo) {
                            Paragraph $reportTranslate.GetAbrForestSection.ParagraphDetail
                            BlankLine
                        }
                        try {
                            Get-AbrADForest
                        } catch {
                            Write-PScriboMessage -IsWarning $_.Exception.Message
                        }
                    }
                    Section -Style Heading2 $reportTranslate.GetAbrForestSection.SitesHeading {
                        Paragraph $reportTranslate.GetAbrForestSection.SitesParagraph
                        BlankLine
                        try {
                            Get-AbrADSite
                        } catch {
                            Write-PScriboMessage -IsWarning $_.Exception.Message
                        }
                    }
                    Section -Style Heading2 $reportTranslate.GetAbrForestSection.InfraHeading {
                        Paragraph $reportTranslate.GetAbrForestSection.InfraParagraph
                        BlankLine
                        try {
                            Get-AbrADExchange
                        } catch {
                            Write-PScriboMessage -IsWarning $_.Exception.Message
                        }
                        try {
                            Get-AbrADSCCM
                        } catch {
                            Write-PScriboMessage -IsWarning $_.Exception.Message
                        }
                        try {
                            Get-AbrDHCPinAD
                        } catch {
                            Write-PScriboMessage -IsWarning $_.Exception.Message
                        }
                    }
                } catch {
                    Write-PScriboMessage -IsWarning -Message ($reportTranslate.GetAbrForestSection.ErrorForest -f $ForestInfo)
                    Write-PScriboMessage -IsWarning $_.Exception.Message
                }
            }
        }
    }
    end {
        Show-AbrDebugExecutionTime -End -TitleMessage 'Forest Section'
    }
}