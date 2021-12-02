function Get-AbrADCATemplate {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Certification Authority Templates information.
    .DESCRIPTION

    .NOTES
        Version:        0.5.0
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
        Write-PscriboMessage "Collecting AD Certification Authority Templates information."
    }

    process {
        Section -Style Heading4 "Certificate Template Summary" {
            Paragraph "The following section provides the certificate templates that are assigned to a specified Certification Authority (CA). CA server can issue certificates only based on assigned templates."
            BlankLine
            if ($ForestInfo) {
                Write-PscriboMessage "Discovering Active Directory Certification Authority information on $($ForestInfo.toUpper())."
                $CAs =  Get-CertificationAuthority -Enterprise
                Write-PscriboMessage "Discovered '$(($CAs | Measure-Object).Count)' Active Directory Certification Authority in domain $ForestInfo."
                foreach ($CA in $CAs) {
                    Section -Style Heading5 "$($CA.Name) Certificate Template" {
                        Paragraph "The following section provides the certificate templates that are assigned to a specified Certification Authority (CA). CA server can issue certificates only based on assigned templates."
                        BlankLine
                        $OutObj = @()
                        try {
                            Write-PscriboMessage "Collecting AD Certification Authority Issued Certificate Template information from $CA."
                            $Templates = Get-CATemplate -CertificationAuthority $CA | Select-Object -ExpandProperty Templates
                            foreach ($Template in $Templates) {
                                $inObj = [ordered] @{
                                    'Template Name' = $Template.DisplayName
                                    'Schema Version' = $Template.SchemaVersion
                                    'Supported CA' = $Template.SupportedCA
                                    'Autoenrollment' = ConvertTo-TextYN $Template.AutoenrollmentAllowed
                                }
                                $OutObj += [pscustomobject]$inobj
                            }
                        }
                        catch {
                            Write-PscriboMessage -IsWarning "$($_.Exception.Message) (CA Certificate Templates)"
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
                    }
                    if ($InfoLevel.CA -ge 3) {
                        Section -Style Heading5 "Issued Certificate Template ACLs" {
                            Paragraph "The following section provides the certificate templates Access Control List that are assigned to a specified Certification Authority (CA)."
                            BlankLine
                            if ($ForestInfo) {
                                Write-PscriboMessage "Discovering Active Directory Certification Authority information on $($ForestInfo.toUpper())."
                                $CAs =  Get-CertificationAuthority -Enterprise
                                Write-PscriboMessage "Discovered '$(($CAs | Measure-Object).Count)' Active Directory Certification Authority in domain $ForestInfo."
                                foreach ($CA in $CAs) {
                                    Section -Style Heading6 "$($CA.Name) Certificate Template ACL" {
                                        Paragraph "The following section provides per CA certificate templates Access Control List."
                                        try {
                                            Write-PscriboMessage "Collecting AD Certification Authority Issued Certificate Template information from $CA."
                                            $Templates = Get-CATemplate -CertificationAuthority $CA | Select-Object -ExpandProperty Templates
                                            foreach ($Template in $Templates) {
                                                Section -Style Heading6 "$($Template.DisplayName) ACL" {
                                                    Paragraph "The following section provides $($Template.DisplayName) certificate templates Access Control List."
                                                    BlankLine
                                                    $OutObj = @()
                                                    $Rights = Get-CertificateTemplateAcl -Template $Template.Name | Select-Object -ExpandProperty Access
                                                    foreach ($Right in $Rights) {
                                                        $inObj = [ordered] @{
                                                            'Identity' = $Right.IdentityReference
                                                            'Access Control Type' = $Right.AccessControlType
                                                            'Rights' = $Right.Rights
                                                            'Inherited' = ConvertTo-TextYN $Right.IsInherited
                                                        }
                                                        $OutObj += [pscustomobject]$inobj
                                                    }
                                                    $TableParams = @{
                                                        Name = "Certificate Template ACL - $($Template.DisplayName)"
                                                        List = $false
                                                        ColumnWidths = 40, 12, 30, 18
                                                    }
                                                    if ($Report.ShowTableCaptions) {
                                                        $TableParams['Caption'] = "- $($TableParams.Name)"
                                                    }
                                                    $OutObj | Table @TableParams
                                                }
                                            }
                                        }
                                        catch {
                                            Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Certificate Templates ACL)"
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            if ($InfoLevel.CA -ge 2) {
                try {
                    Section -Style Heading5 "Certificate Template In Active Directory" {
                        Paragraph "The following section provides registered certificate templates from Active Directory."
                        BlankLine
                        if ($ForestInfo) {
                            $OutObj = @()
                            Write-PscriboMessage "Discovering Active Directory Certification Authority information on $($ForestInfo.toUpper())."
                            $Templates =  Get-CertificateTemplate
                            Write-PscriboMessage "Discovered '$(($Templates | Measure-Object).Count)' Certification Authority Template in domain $ForestInfo."
                            foreach ($Template in $Templates) {
                                try {
                                    Write-PscriboMessage "Collecting AD Certification Authority Certificate Template information from $ForestInfo."
                                    $inObj = [ordered] @{
                                        'Template Name' = $Template.DisplayName
                                        'Schema Version' = $Template.SchemaVersion
                                        'Supported CA' = $Template.SupportedCA
                                        'Autoenrollment' = ConvertTo-TextYN $Template.AutoenrollmentAllowed
                                    }
                                    $OutObj += [pscustomobject]$inobj
                                }
                                catch {
                                    Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Certificate Templates in AD)"
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
                }
                catch {
                    Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Access Control List Global)"
                }
            }
        }
    }

    end {}

}