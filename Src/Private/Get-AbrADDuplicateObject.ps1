function Get-AbrADDuplicateObject {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Domain Duplicate Objects information.
    .DESCRIPTION

    .NOTES
        Version:        0.7.6
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
        Write-PscriboMessage "Discovering duplicate Objects information on $Domain."
    }

    process {
        if ($HealthCheck.Domain.DuplicateObject) {
            try {
                $Objects = Get-WinADDuplicateObject -Domain $Domain
                Write-PscriboMessage "Discovered AD Duplicate Objects information from $Domain."
                if ($Objects) {
                    Section -Style Heading5 'Duplicate Objects' {
                        Paragraph "The following section details Duplicate Objects discovered on Domain $($Domain.ToString().ToUpper())."
                        BlankLine
                        $OutObj = @()
                        foreach ($Object in $Objects) {
                            try {
                                Write-PscriboMessage "Collecting $($Object.Name) information from $($Domain)."
                                $inObj = [ordered] @{
                                    'Name' = $Object.Name
                                    'Created' = $Object.WhenCreated.ToString("yyyy:MM:dd")
                                    'Changed' = $Object.WhenChanged.ToString("yyyy:MM:dd")
                                    'Conflict Changed' = $Object.ConflictWhenChanged.ToString("yyyy:MM:dd")
                                }
                                $OutObj += [pscustomobject]$inobj

                                if ($HealthCheck.Domain.DuplicateObject) {
                                    $OutObj | Set-Style -Style Warning
                                }
                            }
                            catch {
                                Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Duplicate Object Item)"
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
                        Paragraph "Health Check:" -Italic -Bold -Underline
                        Paragraph "Corrective Actions: Ensure there aren't any duplicate object." -Italic -Bold
                    }
                }
            }
            catch {
                Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Duplicate Object Table)"
            }
        }
    }

    end {}

}