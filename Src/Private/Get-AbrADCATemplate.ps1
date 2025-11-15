function Get-AbrADCATemplate {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Certification Authority Templates information.
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
        [Parameter (
            Position = 0,
            Mandatory)]
        $CA
    )

    begin {
        Write-PScriboMessage -Message "Collecting AD Certification Authority Templates information from $($CA.ComputerName)."
        Show-AbrDebugExecutionTime -Start -TitleMessage "CA Certificate Templates"
    }

    process {
        $Templates = Get-CATemplate -CertificationAuthority $CA | Select-Object -ExpandProperty Templates
        if ($Templates) {
            try {
                Section -Style Heading3 "Certificate Template Summary" {
                    Paragraph "The following section lists certificate templates assigned to the Certification Authority. The CA can only issue certificates based on these assigned templates."
                    BlankLine
                    $OutObj = [System.Collections.ArrayList]::new()
                    foreach ($Template in $Templates) {
                        try {
                            $inObj = [ordered] @{
                                'Template Name' = $Template.DisplayName
                                'Schema Version' = $Template.SchemaVersion
                                'Supported CA' = $Template.SupportedCA
                                'Autoenrollment' = $Template.AutoenrollmentAllowed
                            }
                            $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (CA Certificate Templates table)"
                        }
                    }

                    $TableParams = @{
                        Name = "Issued Certificate Template - $($CA.Name)"
                        List = $false
                        ColumnWidths = 40, 12, 30, 18
                    }
                    if ($Report.ShowTableCaptions) {
                        $TableParams['Caption'] = "- $($TableParams.Name)"
                    }
                    $OutObj | Sort-Object -Property 'Template Name' | Table @TableParams
                    if ($InfoLevel.CA -ge 3) {
                        try {
                            Section -Style Heading4 "Issued Certificate Template ACLs" {
                                Paragraph "The following section provides the Access Control List (ACL) for certificate templates assigned to the Certification Authority."
                                BlankLine
                                foreach ($Template in $Templates) {
                                    try {
                                        $Rights = Get-CertificateTemplateAcl -Template $Template | Select-Object -ExpandProperty Access
                                        if ($Rights) {
                                            Section -ExcludeFromTOC -Style NOTOCHeading5 "$($Template.DisplayName)" {
                                                $OutObj = [System.Collections.ArrayList]::new()
                                                foreach ($Right in $Rights) {
                                                    try {
                                                        $inObj = [ordered] @{
                                                            'Identity' = $Right.IdentityReference
                                                            'Access Control Type' = $Right.AccessControlType
                                                            'Rights' = $Right.Rights
                                                            'Inherited' = $Right.IsInherited
                                                        }
                                                        $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                                                    } catch {
                                                        Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Certificate Templates ACL Item)"
                                                    }
                                                }
                                                $TableParams = @{
                                                    Name = "Certificate Template ACL - $($Template.DisplayName)"
                                                    List = $false
                                                    ColumnWidths = 40, 12, 30, 18
                                                }
                                                if ($Report.ShowTableCaptions) {
                                                    $TableParams['Caption'] = "- $($TableParams.Name)"
                                                }
                                                $OutObj | Sort-Object -Property 'Identity' | Table @TableParams
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
                                Section -Style Heading4 "Certificate Template In Active Directory" {
                                    Paragraph "The following section lists all certificate templates registered in Active Directory, regardless of whether they are assigned to any Certification Authority."
                                    BlankLine
                                    $OutObj = [System.Collections.ArrayList]::new()
                                    foreach ($Template in $Templates) {
                                        try {
                                            $inObj = [ordered] @{
                                                'Template Name' = $Template.DisplayName
                                                'Schema Version' = $Template.SchemaVersion
                                                'Supported CA' = $Template.SupportedCA
                                                'Autoenrollment' = $Template.AutoenrollmentAllowed
                                            }
                                            $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                                        } catch {
                                            Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Certificate Template In Active Directory Item)"
                                        }
                                    }

                                    $TableParams = @{
                                        Name = "Certificate Template in AD - $($ForestInfo.toUpper())"
                                        List = $false
                                        ColumnWidths = 40, 12, 30, 18
                                    }
                                    if ($Report.ShowTableCaptions) {
                                        $TableParams['Caption'] = "- $($TableParams.Name)"
                                    }
                                    $OutObj | Sort-Object -Property 'Template Name' | Table @TableParams
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
        Show-AbrDebugExecutionTime -End -TitleMessage "CA Certificate Templates"
    }

}