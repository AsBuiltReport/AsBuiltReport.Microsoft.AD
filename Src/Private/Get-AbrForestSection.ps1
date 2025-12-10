function Get-AbrForestSection {
    <#
    .SYNOPSIS
    Used by As Built Report to build Microsoft AD Forest Section.
    .DESCRIPTION

    .NOTES
        Version:        0.9.8
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
        Write-PScriboMessage -Message "Collecting Forest information from $ForestInfo."
        Show-AbrDebugExecutionTime -Start -TitleMessage "Forest Section"
    }

    process {
        Section -Style Heading1 "$($ForestInfo.toUpper())" {
            Paragraph "This section provides a comprehensive overview of the Active Directory infrastructure and configuration for the $($ForestInfo) forest."
            BlankLine
            Write-PScriboMessage -Message "Forest InfoLevel set at $($InfoLevel.Forest)."
            if ($InfoLevel.Forest -ge 1) {
                try {
                    Section -Style Heading2 "Forest Configuration" {
                        if ($Options.ShowDefinitionInfo) {
                            Paragraph "The Active Directory framework that holds the objects can be viewed at several levels. The forest, tree, and domain are the logical divisions in an Active Directory network. At the top of the structure is the forest, which is a collection of trees that share a common global catalog, directory schema, logical structure, and directory configuration. The forest represents the security boundary within which users, computers, groups, and other objects are contained."
                            BlankLine
                        }
                        if (-not $Options.ShowDefinitionInfo) {
                            Paragraph "The following section provides a detailed summary of the Active Directory Forest infrastructure and configuration."
                            BlankLine
                        }
                        try {
                            Get-AbrADForest
                        } catch {
                            Write-PScriboMessage -IsWarning $_.Exception.Message
                        }
                        try {
                            Get-AbrADSite
                        } catch {
                            Write-PScriboMessage -IsWarning $_.Exception.Message
                        }
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
                            Get-AbrDHCPinAD -DomainStatus ([ref]$DomainStatus)
                        } catch {
                            Write-PScriboMessage -IsWarning $_.Exception.Message
                        }
                    }
                } catch {
                    Write-PScriboMessage -IsWarning -Message "Error: Unable to retreive Forest: $ForestInfo information."
                    Write-PScriboMessage -IsWarning $_.Exception.Message
                }
            }
        }
    }
    end {
        Show-AbrDebugExecutionTime -End -TitleMessage "Forest Section"
    }
}