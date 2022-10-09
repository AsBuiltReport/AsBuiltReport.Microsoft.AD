function Get-AbrADCATemplate {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Certification Authority Templates information.
    .DESCRIPTION

    .NOTES
        Version:        0.7.9
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
        Write-PscriboMessage "Collecting AD Certification Authority Templates information from $($CA.ComputerName)."
    }

    process {
        $Templates = Get-CATemplate -CertificationAuthority $CA.ComputerName | Select-Object -ExpandProperty Templates
        if ($Templates) {
            try {
                Section -Style Heading4 "Certificate Template Summary" {
                    Paragraph "The following section provides the certificate templates that are assigned to a specified Certification Authority (CA). CA server can issue certificates only based on assigned templates."
                    BlankLine
                    $OutObj = @()
                    foreach ($Template in $Templates) {
                        Write-PscriboMessage "Collecting $($Template.DisplayName) Issued Certificate Template information from $($CA.Name)."
                        try {
                            $inObj = [ordered] @{
                                'Template Name' = $Template.DisplayName
                                'Schema Version' = $Template.SchemaVersion
                                'Supported CA' = $Template.SupportedCA
                                'Autoenrollment' = ConvertTo-TextYN $Template.AutoenrollmentAllowed
                            }
                            $OutObj += [pscustomobject]$inobj
                        }
                        catch {
                            Write-PscriboMessage -IsWarning "$($_.Exception.Message) (CA Certificate Templates table)"
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
                            Section -Style Heading5 "Issued Certificate Template ACLs" {
                                Paragraph "The following section provides the certificate templates Access Control List that are assigned to a specified Certification Authority (CA)."
                                BlankLine
                                foreach ($Template in $Templates) {
                                    try {
                                        $Rights = Get-CertificateTemplateAcl -Template $Template.Name | Select-Object -ExpandProperty Access
                                        if ($Rights) {
                                            Section -ExcludeFromTOC -Style NOTOCHeading6 "$($Template.DisplayName)" {
                                                $OutObj = @()
                                                foreach ($Right in $Rights) {
                                                    try {
                                                        $inObj = [ordered] @{
                                                            'Identity' = $Right.IdentityReference
                                                            'Access Control Type' = $Right.AccessControlType
                                                            'Rights' = $Right.Rights
                                                            'Inherited' = ConvertTo-TextYN $Right.IsInherited
                                                        }
                                                        $OutObj += [pscustomobject]$inobj
                                                    }
                                                    catch {
                                                        Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Certificate Templates ACL Item)"
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
                                    }
                                    catch {
                                        Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Certificate Templates ACL Table)"
                                    }
                                }
                            }
                        }
                        catch {
                            Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Issued Certificate Template ACLs Section)"
                        }
                    }
                    if ($InfoLevel.CA -ge 2) {
                        try {
                            $Templates =  Get-CertificateTemplate
                            if ($Templates) {
                                Section -Style Heading5 "Certificate Template In Active Directory" {
                                    Paragraph "The following section provides registered certificate templates from Active Directory."
                                    BlankLine
                                    $OutObj = @()
                                    Write-PscriboMessage "Discovered '$(($Templates | Measure-Object).Count)' Certification Authority Template in domain $ForestInfo."
                                    foreach ($Template in $Templates) {
                                        try {
                                            Write-PscriboMessage "Collecting $($Template.DisplayName) Certificate Template In Active Directory."
                                            $inObj = [ordered] @{
                                                'Template Name' = $Template.DisplayName
                                                'Schema Version' = $Template.SchemaVersion
                                                'Supported CA' = $Template.SupportedCA
                                                'Autoenrollment' = ConvertTo-TextYN $Template.AutoenrollmentAllowed
                                            }
                                            $OutObj += [pscustomobject]$inobj
                                        }
                                        catch {
                                            Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Certificate Template In Active Directory Item)"
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
                            Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Certificate Template In Active Directory Table)"
                        }
                    }
                }
            }
            catch {
                Write-PscriboMessage -IsWarning "$($_.Exception.Message) (CA Certificate Templates section)"
            }
        }
    }

    end {}

}