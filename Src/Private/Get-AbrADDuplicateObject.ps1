function Get-AbrADDuplicateObject {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Domain Duplicate Objects information.
    .DESCRIPTION

    .NOTES
        Version:        0.9.7
        Author:         Jonathan Colon
        Twitter:        @jcolonfzenpr
        Github:         rebelinux
    .EXAMPLE

    .LINK

    #>
    [CmdletBinding()]
    param (
        $Domain
    )

    begin {
        Write-PScriboMessage -Message "Collecting duplicate Objects information on $($Domain.DNSRoot)."
        Show-AbrDebugExecutionTime -Start -TitleMessage "AD Domain Duplicate Objects"
    }

    process {
        if ($HealthCheck.Domain.DuplicateObject) {
            try {
                $Objects = Get-WinADDuplicateObject -Domain $Domain.DNSRoot -Credential $Credential
                if ($Objects) {
                    Section -ExcludeFromTOC -Style NOTOCHeading4 'Duplicate Objects' {
                        Paragraph "The following section details duplicate objects detected in the domain $($Domain.DNSRoot.ToString().ToUpper()). These objects may indicate replication issues or administrative errors that require attention."
                        BlankLine
                        $OutObj = [System.Collections.ArrayList]::new()
                        foreach ($Object in $Objects) {
                            try {
                                $inObj = [ordered] @{
                                    'Name' = $Object.Name
                                    'Created' = $Object.WhenCreated.ToString("yyyy:MM:dd")
                                    'Changed' = $Object.WhenChanged.ToString("yyyy:MM:dd")
                                    'Conflict Changed' = $Object.ConflictWhenChanged.ToString("yyyy:MM:dd")
                                }
                                $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null

                                if ($HealthCheck.Domain.DuplicateObject) {
                                    $OutObj | Set-Style -Style Warning
                                }
                            } catch {
                                Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Duplicate Object Item)"
                            }
                        }

                        $TableParams = @{
                            Name = "Duplicate Object - $($Domain.DNSRoot.ToString().ToUpper())"
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
                    Write-PScriboMessage -Message "No Duplicate object information found in $($Domain.DNSRoot), Disabling this section."
                }
            } catch {
                Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Duplicate Object Table)"
            }
        }
    }

    end {
        Show-AbrDebugExecutionTime -End -TitleMessage "AD Domain Duplicate Objects"
    }

}