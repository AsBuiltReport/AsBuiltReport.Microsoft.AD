function Get-AbrForestSection {
    <#
    .SYNOPSIS
    Used by As Built Report to build Microsoft AD Forest Section.
    .DESCRIPTION

    .NOTES
        Version:        0.8.2
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
        Write-PScriboMessage "Collecting Forest information from $ForestInfo."
    }

    process {
        Section -Style Heading1 "$($ForestInfo.toUpper())" {
            Paragraph "The following section provides a summary of the Active Directory Infrastructure configuration for $($ForestInfo)."
            BlankLine
            Write-PScriboMessage "Forest InfoLevel set at $($InfoLevel.Forest)."
            if ($InfoLevel.Forest -ge 1) {
                try {
                    Section -Style Heading2 "Forest Configuration." {
                        if ($Options.ShowDefinitionInfo) {
                            Paragraph "The Active Directory framework that holds the objects can be viewed at a number of levels. The forest, tree, and domain are the logical divisions in an Active Directory network. At the top of the structure is the forest. A forest is a collection of trees that share a common global catalog, directory schema, logical structure, and directory configuration. The forest represents the security boundary within which users, computers, groups, and other objects are accessible."
                            BlankLine
                        }
                        if (-Not $Options.ShowDefinitionInfo) {
                            Paragraph "The following section provides a summary of the Active Directory Forest Information."
                            BlankLine
                        }
                        try {
                            Write-Host "Beginning AD Forest section" -ForegroundColor Cyan
                            $SectionStartTime = Get-Date

                            Get-AbrADForest

                            $SectionEndTime = Get-Date
                            $elapsedTime = New-TimeSpan -Start $SectionStartTime -End $SectionEndTime
                            Write-Output "AD Forest Section execution time: $($elapsedTime.Hour) Hours $($elapsedTime.Minute) Minutes"
                        } catch {
                            Write-PScriboMessage -IsWarning $_.Exception.Message
                        }
                        try {
                            Write-Host "Beginning AD Site section" -ForegroundColor Cyan
                            $SectionStartTime = Get-Date

                            Get-AbrADSite

                            $SectionEndTime = Get-Date
                            $elapsedTime = New-TimeSpan -Start $SectionStartTime -End $SectionEndTime
                            Write-Output "AD Site Section execution time: $($elapsedTime.Hour) Hours $($elapsedTime.Minute) Minutes"
                        } catch {
                            Write-PScriboMessage -IsWarning $_.Exception.Message
                        }
                        try {
                            Write-Host "Beginning Exchange section" -ForegroundColor Cyan
                            $SectionStartTime = Get-Date

                            Get-AbrADExchange

                            $SectionEndTime = Get-Date
                            $elapsedTime = New-TimeSpan -Start $SectionStartTime -End $SectionEndTime
                            Write-Output "Exchange Section execution time: $($elapsedTime.Hour) Hours $($elapsedTime.Minute) Minutes"
                        } catch {
                            Write-PScriboMessage -IsWarning $_.Exception.Message
                        }
                        try {
                            Write-Host "Beginning DHCP section" -ForegroundColor Cyan
                            $SectionStartTime = Get-Date

                            Get-AbrDHCPinAD

                            $SectionEndTime = Get-Date
                            $elapsedTime = New-TimeSpan -Start $SectionStartTime -End $SectionEndTime
                            Write-Output "DHCP Section execution time: $($elapsedTime.Hour) Hours $($elapsedTime.Minute) Minutes"
                        } catch {
                            Write-PScriboMessage -IsWarning $_.Exception.Message
                        }
                    }
                } catch {
                    Write-PScriboMessage -IsWarning "Error: Unable to retreive Forest: $ForestInfo information."
                    Write-PScriboMessage -IsWarning $_.Exception.Message
                }
            }
        }
    }
    end {}
}