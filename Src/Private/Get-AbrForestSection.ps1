function Get-AbrForestSection {
    <#
    .SYNOPSIS
    Used by As Built Report to build Microsoft AD Forest Section.
    .DESCRIPTION

    .NOTES
        Version:        0.7.15
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
        Write-PscriboMessage "Discovering Forest information from $Domain."
    }

    process {
        Section -Style Heading1 "$($ForestInfo.toUpper())" {
            Paragraph "The following section provides a summary of the Active Directory Infrastructure configuration for $($ForestInfo)."
            BlankLine
            Write-PScriboMessage "Forest InfoLevel set at $($InfoLevel.Forest)."
            if ($InfoLevel.Forest -ge 1) {
                try {
                    Section -Style Heading2 "Forest Configuration."  {
                        if ($Options.ShowDefinitionInfo) {
                            Paragraph "The Active Directory framework that holds the objects can be viewed at a number of levels. The forest, tree, and domain are the logical divisions in an Active Directory network. At the top of the structure is the forest. A forest is a collection of trees that share a common global catalog, directory schema, logical structure, and directory configuration. The forest represents the security boundary within which users, computers, groups, and other objects are accessible."
                            BlankLine
                        }
                        if (!$Options.ShowDefinitionInfo) {
                            Paragraph "The following section provides a summary of the Active Directory Forest Information."
                            BlankLine
                        }
                        try {
                            Get-AbrADForest
                        }
                        catch {
                            Write-PscriboMessage -IsWarning $_.Exception.Message
                        }
                        try {
                            Get-AbrADSite
                        }
                        catch {
                            Write-PscriboMessage -IsWarning $_.Exception.Message
                        }
                        try {
                            Get-AbrADExchange
                        }
                        catch {
                            Write-PscriboMessage -IsWarning $_.Exception.Message
                        }
                    }
                    if ($Options.EnableDiagrams) {
                        Try {
                            $Graph = New-ADDiagram -Target $System -Credential $Credential -Format base64 -Direction top-to-bottom -DiagramType Forest
                        } Catch {
                            Write-PscriboMessage -IsWarning "Forest Diagram: $($_.Exception.Message)"
                        }

                        if ($Graph) {
                            Section -Style Heading3 "Forest Diagram."  {
                                Image -Base64 $Graph -Text "Forest Diagram" -Percent (Get-ImagePercent -Graph $Graph) -Align Center
                                Paragraph "Image preview: Opens the image in a new tab to view it at full resolution." -Tabs 2
                            }
                            BlankLine -Count 2
                        }
                    }
                }
                catch {
                    Write-PscriboMessage -IsWarning "Error: Unable to retreive Forest: $ForestInfo information."
                    Write-PscriboMessage -IsWarning $_.Exception.Message
                }
            }
        }
    }
    end {}
}