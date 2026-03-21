function Get-AbrADCATemplate {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Certification Authority Templates information.
    .DESCRIPTION

    .NOTES
        Version:        0.9.12
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
        Write-PScriboMessage -Message ([string]::Format($reportTranslate.GetAbrADCATemplate.Collecting, $CA.ComputerName))
        Show-AbrDebugExecutionTime -Start -TitleMessage 'CA Certificate Templates'
    }

    process {
        $Templates = Get-CATemplate -CertificationAuthority $CA | Select-Object -ExpandProperty Templates
        if ($Templates) {
            try {
                Section -Style Heading3 $reportTranslate.GetAbrADCATemplate.Heading {
                    Paragraph $reportTranslate.GetAbrADCATemplate.Paragraph
                    BlankLine
                    $OutObj = [System.Collections.Generic.List[object]]::new()
                    foreach ($Template in $Templates) {
                        try {
                            $inObj = [ordered] @{
                                $reportTranslate.GetAbrADCATemplate.TemplateName = $Template.DisplayName
                                $reportTranslate.GetAbrADCATemplate.SchemaVersion = $Template.SchemaVersion
                                $reportTranslate.GetAbrADCATemplate.SupportedCA = $Template.SupportedCA
                                $reportTranslate.GetAbrADCATemplate.Autoenrollment = $Template.AutoenrollmentAllowed
                            }
                            $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj))
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (CA Certificate Templates table)"
                        }
                    }

                    $TableParams = @{
                        Name = "$($reportTranslate.GetAbrADCATemplate.IssuedTemplateTable) - $($CA.Name)"
                        List = $false
                        ColumnWidths = 40, 12, 30, 18
                    }
                    if ($Report.ShowTableCaptions) {
                        $TableParams['Caption'] = "- $($TableParams.Name)"
                    }
                    $OutObj | Sort-Object -Property $reportTranslate.GetAbrADCATemplate.TemplateName | Table @TableParams
                    if ($InfoLevel.CA -ge 3) {
                        try {
                            Section -Style Heading4 $reportTranslate.GetAbrADCATemplate.IssuedTemplateACLs {
                                Paragraph $reportTranslate.GetAbrADCATemplate.IssuedTemplateACLsParagraph
                                BlankLine
                                foreach ($Template in $Templates) {
                                    try {
                                        $Rights = Get-CertificateTemplateAcl -Template $Template | Select-Object -ExpandProperty Access
                                        if ($Rights) {
                                            Section -ExcludeFromTOC -Style NOTOCHeading5 "$($Template.DisplayName)" {
                                                $OutObj = [System.Collections.Generic.List[object]]::new()
                                                foreach ($Right in $Rights) {
                                                    try {
                                                        $inObj = [ordered] @{
                                                            $reportTranslate.GetAbrADCATemplate.Identity = $Right.IdentityReference
                                                            $reportTranslate.GetAbrADCATemplate.AccessControlType = $Right.AccessControlType
                                                            $reportTranslate.GetAbrADCATemplate.Rights = $Right.Rights
                                                            $reportTranslate.GetAbrADCATemplate.Inherited = $Right.IsInherited
                                                        }
                                                        $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj))
                                                    } catch {
                                                        Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Certificate Templates ACL Item)"
                                                    }
                                                }
                                                $TableParams = @{
                                                    Name = "$($reportTranslate.GetAbrADCATemplate.TemplateACLTable) - $($Template.DisplayName)"
                                                    List = $false
                                                    ColumnWidths = 40, 12, 30, 18
                                                }
                                                if ($Report.ShowTableCaptions) {
                                                    $TableParams['Caption'] = "- $($TableParams.Name)"
                                                }
                                                $OutObj | Sort-Object -Property $reportTranslate.GetAbrADCATemplate.Identity | Table @TableParams
                                            }
                                        }
                                    } catch {
                                        Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Certificate Templates ACL Table)"
                                    }
                                }
                            }
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Issued Certificate Template ACLs Section)"
                        }
                    }
                    if ($InfoLevel.CA -ge 2) {
                        try {
                            $Templates = Get-CertificateTemplate
                            if ($Templates) {
                                Section -Style Heading4 $reportTranslate.GetAbrADCATemplate.ADTemplates {
                                    Paragraph $reportTranslate.GetAbrADCATemplate.ADTemplatesParagraph
                                    BlankLine
                                    $OutObj = [System.Collections.Generic.List[object]]::new()
                                    foreach ($Template in $Templates) {
                                        try {
                                            $inObj = [ordered] @{
                                                $reportTranslate.GetAbrADCATemplate.TemplateName = $Template.DisplayName
                                                $reportTranslate.GetAbrADCATemplate.SchemaVersion = $Template.SchemaVersion
                                                $reportTranslate.GetAbrADCATemplate.SupportedCA = $Template.SupportedCA
                                                $reportTranslate.GetAbrADCATemplate.Autoenrollment = $Template.AutoenrollmentAllowed
                                            }
                                            $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj))
                                        } catch {
                                            Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Certificate Template In Active Directory Item)"
                                        }
                                    }

                                    $TableParams = @{
                                        Name = "$($reportTranslate.GetAbrADCATemplate.ADTemplatesTable) - $($ForestInfo.toUpper())"
                                        List = $false
                                        ColumnWidths = 40, 12, 30, 18
                                    }
                                    if ($Report.ShowTableCaptions) {
                                        $TableParams['Caption'] = "- $($TableParams.Name)"
                                    }
                                    $OutObj | Sort-Object -Property $reportTranslate.GetAbrADCATemplate.TemplateName | Table @TableParams
                                }
                            }
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Certificate Template In Active Directory Table)"
                        }
                    }
                }
            } catch {
                Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (CA Certificate Templates section)"
            }
        }
    }

    end {
        Show-AbrDebugExecutionTime -End -TitleMessage 'CA Certificate Templates'
    }

}
