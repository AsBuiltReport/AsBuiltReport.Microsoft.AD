function Get-AbrADDuplicateObject {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Domain Duplicate Objects information.
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
        $Domain
    )

    begin {
        Write-PScriboMessage -Message ($reportTranslate.GetAbrADDuplicateObject.Collecting -f $Domain.DNSRoot)
        Show-AbrDebugExecutionTime -Start -TitleMessage 'AD Domain Duplicate Objects'
    }

    process {
        if ($HealthCheck.Domain.DuplicateObject) {
            try {
                $Objects = Get-WinADDuplicateObject -Domain $Domain.DNSRoot -Credential $Credential
                if ($Objects) {
                    Section -ExcludeFromTOC -Style NOTOCHeading4 $reportTranslate.GetAbrADDuplicateObject.SectionTitle {
                        Paragraph ($reportTranslate.GetAbrADDuplicateObject.SectionParagraph -f $Domain.DNSRoot.ToString().ToUpper())
                        BlankLine
                        $OutObj = [System.Collections.Generic.List[object]]::new()
                        foreach ($Object in $Objects) {
                            try {
                                $inObj = [ordered] @{
                                    $reportTranslate.GetAbrADDuplicateObject.Name = $Object.Name
                                    $reportTranslate.GetAbrADDuplicateObject.Created = $Object.WhenCreated.ToString('yyyy:MM:dd')
                                    $reportTranslate.GetAbrADDuplicateObject.Changed = $Object.WhenChanged.ToString('yyyy:MM:dd')
                                    $reportTranslate.GetAbrADDuplicateObject.ConflictChanged = $Object.ConflictWhenChanged.ToString('yyyy:MM:dd')
                                }
                                $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj))

                                if ($HealthCheck.Domain.DuplicateObject) {
                                    $OutObj | Set-Style -Style Warning
                                }
                            } catch {
                                Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Duplicate Object Item)"
                            }
                        }

                        $TableParams = @{
                            Name = "$($reportTranslate.GetAbrADDuplicateObject.TableName) - $($Domain.DNSRoot.ToString().ToUpper())"
                            List = $false
                            ColumnWidths = 40, 20, 20, 20
                        }

                        if ($Report.ShowTableCaptions) {
                            $TableParams['Caption'] = "- $($TableParams.Name)"
                        }
                        $OutObj | Table @TableParams
                        Paragraph $reportTranslate.GetAbrADDuplicateObject.HealthCheck -Bold -Underline
                        BlankLine
                        Paragraph {
                            Text $reportTranslate.GetAbrADDuplicateObject.CorrectiveActions -Bold
                            Text $reportTranslate.GetAbrADDuplicateObject.DuplicateObjectBP
                        }
                    }
                } else {
                    Write-PScriboMessage -Message ($reportTranslate.GetAbrADDuplicateObject.NoData -f $Domain.DNSRoot)
                }
            } catch {
                Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Duplicate Object Table)"
            }
        }
    }

    end {
        Show-AbrDebugExecutionTime -End -TitleMessage 'AD Domain Duplicate Objects'
    }

}