function Get-AbrADDuplicateObject {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Domain Duplicate Objects information.
    .DESCRIPTION

    .NOTES
        Version:        0.9.2
        Author:         Jonathan Colon
        Twitter:        @jcolonfzenpr
        Github:         rebelinux
    .EXAMPLE

    .LINK

    #>
    [CmdletBinding()]
    param (
        [Parameter (
            Position = 0,
            Mandatory)]
        [string]
        $Domain
    )

    begin {
        Write-PScriboMessage "Collecting duplicate Objects information on $Domain."
    }

    process {
        if ($HealthCheck.Domain.DuplicateObject) {
            try {
                $Objects = Get-WinADDuplicateObject -Domain $Domain -Credential $Credential
                if ($Objects) {
                    Section -ExcludeFromTOC -Style NOTOCHeading4 'Duplicate Objects' {
                        Paragraph "The following section details Duplicate Objects discovered on Domain $($Domain.ToString().ToUpper())."
                        BlankLine
                        $OutObj = @()
                        foreach ($Object in $Objects) {
                            try {
                                $inObj = [ordered] @{
                                    'Name' = $Object.Name
                                    'Created' = $Object.WhenCreated.ToString("yyyy:MM:dd")
                                    'Changed' = $Object.WhenChanged.ToString("yyyy:MM:dd")
                                    'Conflict Changed' = $Object.ConflictWhenChanged.ToString("yyyy:MM:dd")
                                }
                                $OutObj += [pscustomobject](ConvertTo-HashToYN $inObj)

                                if ($HealthCheck.Domain.DuplicateObject) {
                                    $OutObj | Set-Style -Style Warning
                                }
                            } catch {
                                Write-PScriboMessage -IsWarning "$($_.Exception.Message) (Duplicate Object Item)"
                            }
                        }

                        $TableParams = @{
                            Name = "Duplicate Object - $($Domain.ToString().ToUpper())"
                            List = $false
                            ColumnWidths = 40, 20, 20, 20
                        }

                        if ($Report.ShowTableCaptions) {
                            $TableParams['Caption'] = "- $($TableParams.Name)"
                        }
                        $OutObj | Table @TableParams
                        Paragraph "Health Check:" -Bold -Underline
                        BlankLine
                        Paragraph {
                            Text "Corrective Actions:" -Bold
                            Text "Ensure there aren't any duplicate objects in the Active Directory. Duplicate objects can cause various issues such as authentication problems, replication conflicts, and administrative overhead. It is recommended to regularly audit and clean up any duplicate objects to maintain a healthy and efficient Active Directory environment."
                        }
                    }
                } else {
                    Write-PScriboMessage "No Duplicate object information found in $Domain, Disabling this section."
                }
            } catch {
                Write-PScriboMessage -IsWarning "$($_.Exception.Message) (Duplicate Object Table)"
            }
        }
    }

    end {}

}