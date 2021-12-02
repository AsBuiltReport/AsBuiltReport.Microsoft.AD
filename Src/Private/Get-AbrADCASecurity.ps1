function Get-AbrADCASecurity {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Certification Authority Security information.
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
        Write-PscriboMessage "Collecting AD Certification Authority Security information."
    }

    process {
        Section -Style Heading4 "Certificate Validity Period" {
            Paragraph "The following section provides the Certification Authority Certificate Validity Period information."
            BlankLine
            $OutObj = @()
            if ($ForestInfo) {
                Write-PscriboMessage "Discovering Active Directory Certification Authority information on $($ForestInfo.toUpper())."
                $CAs =  Get-CertificationAuthority -Enterprise
                foreach ($CA in $CAs) {
                    Write-PscriboMessage "Discovered '$(($CAs | Measure-Object).Count)' Active Directory Certification Authority in domain $ForestInfo."
                    try {
                        Write-PscriboMessage "Collecting AD Certification Authority Certificate Validity Period information of $CA."
                        $CFP =  Get-CertificateValidityPeriod -CertificationAuthority $CA
                        $inObj = [ordered] @{
                            'CA Name' = $CFP.Name
                            'Server Name' = $CFP.ComputerName.ToString().ToUpper().Split(".")[0]
                            'Validity Period' = $CFP.ValidityPeriod
                        }
                        $OutObj += [pscustomobject]$inobj
                    }
                    catch {
                        Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Certificate Validity Period)"
                    }
                }
            }

            $TableParams = @{
                Name = "Certificate Validity Period - $($ForestInfo.ToString().ToUpper())"
                List = $false
                ColumnWidths = 40, 40, 20
            }
            if ($Report.ShowTableCaptions) {
                $TableParams['Caption'] = "- $($TableParams.Name)"
            }
            $OutObj | Table @TableParams
        }
        try {
            Section -Style Heading4 "Access Control List (ACL) Summary" {
                Paragraph "The following section provides the Certification Authority Access Control List (ACL) information."
                BlankLine
                $OutObj = @()
                if ($ForestInfo) {
                    Write-PscriboMessage "Discovering Active Directory Certification Authority information on $($ForestInfo.toUpper())."
                    $CAs =  Get-CertificationAuthority -Enterprise
                    if ($CAs) {Write-PscriboMessage "Discovered '$(($CAs | Measure-Object).Count)' Active Directory Certification Authority in domain $ForestInfo."}
                    foreach ($CA in $CAs) {
                        try {
                            Write-PscriboMessage "Collecting AD Certification Authority Access Control List information of $CA."
                            $ACLs =  Get-CertificationAuthorityAcl -CertificationAuthority $CA
                            foreach ($ACL in $ACLs) {
                                $inObj = [ordered] @{
                                    'DC Name' = $CA.DisplayName
                                    'Owner' = $ACL.Owner
                                    'Group' = $ACL.Group
                                }
                                $OutObj += [pscustomobject]$inobj
                            }
                        }
                        catch {
                            Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Access Control List Summary)"
                        }
                    }
                }

                $TableParams = @{
                    Name = "Access Control List - $($ForestInfo.ToString().ToUpper())"
                    List = $false
                    ColumnWidths = 40, 30, 30
                }
                if ($Report.ShowTableCaptions) {
                    $TableParams['Caption'] = "- $($TableParams.Name)"
                }
                $OutObj | Table @TableParams
                if ($ForestInfo) {
                    Write-PscriboMessage "Discovering Active Directory Certification Authority information on $($ForestInfo.toUpper())."
                    $CAs =  Get-CertificationAuthority -Enterprise
                    if ($CAs) {Write-PscriboMessage "Discovered '$(($CAs | Measure-Object).Count)' Active Directory Certification Authority in domain $ForestInfo."}
                    foreach ($CA in $CAs) {
                        try {
                            Section -Style Heading5 "$($CA.Name) Rights" {
                                Paragraph "The following section provides the Certification Authority Access Control List information on $($CA.Name)."
                                BlankLine
                                $OutObj = @()
                                Write-PscriboMessage "Collecting AD Certification Authority Access Control List information of $CA."
                                $ACLs =  Get-CertificationAuthorityAcl -CertificationAuthority $CA
                                foreach ($ACL in $ACLs.Access) {
                                    $inObj = [ordered] @{
                                        'Identity' = $ACL.IdentityReference
                                        'Access Control Type' = $ACL.AccessControlType
                                        'Rights' = $ACL.Rights
                                    }
                                    $OutObj += [pscustomobject]$inobj
                                }

                                $TableParams = @{
                                    Name = "ACL Rights - $($CA.Name)"
                                    List = $false
                                    ColumnWidths = 40, 20, 40
                                }
                                if ($Report.ShowTableCaptions) {
                                    $TableParams['Caption'] = "- $($TableParams.Name)"
                                }
                                $OutObj | Table @TableParams
                            }
                        }
                        catch {
                            Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Access Control List Item)"
                        }
                    }
                }
            }
        }
        catch {
            Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Access Control List Global)"
        }
    }

    end {}

}