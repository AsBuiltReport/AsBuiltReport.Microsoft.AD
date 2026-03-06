function Get-AbrADCAAIA {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft Active Directory CA Authority Information Access information.
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
        [Parameter (
            Position = 0,
            Mandatory)]
        $CA
    )

    begin {
        Show-AbrDebugExecutionTime -Start -TitleMessage 'CA Authority Information Access Objects'
    }

    process {
        if ($CA) {
            Section -Style Heading3 $reportTranslate.GetAbrADCAAIA.Heading {
                Paragraph $reportTranslate.GetAbrADCAAIA.Paragraph
                BlankLine
                try {
                    Write-PScriboMessage -Message ([string]::Format($reportTranslate.GetAbrADCAAIA.Collecting, $CA.Name))
                    $AIA = Get-AuthorityInformationAccess -CertificationAuthority $CA
                    foreach ($URI in $AIA.URI) {
                        $OutObj = [System.Collections.ArrayList]::new()
                        try {
                            $inObj = [ordered] @{
                                $reportTranslate.GetAbrADCAAIA.RegURI = $URI.RegURI
                                $reportTranslate.GetAbrADCAAIA.ConfigURI = $URI.ConfigURI
                                $reportTranslate.GetAbrADCAAIA.Flags = ($URI.Flags -join ', ')
                                $reportTranslate.GetAbrADCAAIA.ServerPublish = $URI.ServerPublish
                                $reportTranslate.GetAbrADCAAIA.IncludeToExtension = $URI.IncludeToExtension
                                $reportTranslate.GetAbrADCAAIA.OCSP = $URI.OCSP
                            }
                            $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null

                            $TableParams = @{
                                Name = "$($reportTranslate.GetAbrADCAAIA.TableName) - $($CA.Name)"
                                List = $true
                                ColumnWidths = 40, 60
                            }
                            if ($Report.ShowTableCaptions) {
                                $TableParams['Caption'] = "- $($TableParams.Name)"
                            }
                            $OutObj | Table @TableParams
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "Authority Information Access Item $($URI.RegURI) Section: $($_.Exception.Message)"
                        }
                    }
                } catch {
                    Write-PScriboMessage -IsWarning -Message "Authority Information Access Section: $($_.Exception.Message)"
                }
            }
        }
    }

    end {
        if ($Options.ShowExecutionTime) {
            $SectionEndTime = Get-Date
            $elapsedTime = New-TimeSpan -Start $SectionStartTime -End $SectionEndTime
            Write-Host "CA Authority Information Access Objects Section execution time: $($elapsedTime.tostring('hh')) Hours $($elapsedTime.tostring('mm')) Minutes $($elapsedTime.tostring('ss')) Seconds"
        }
        Show-AbrDebugExecutionTime -End -TitleMessage 'CA Authority Information Access Objects'
    }

}
