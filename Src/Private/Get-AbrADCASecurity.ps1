function Get-AbrADCASecurity {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Certification Authority Security information.
    .DESCRIPTION

    .NOTES
        Version:        0.6.2
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
        if ($CAs) {
            Section -Style Heading4 "Certificate Validity Period" {
                Paragraph "The following section provides the Certification Authority Certificate Validity Period information."
                BlankLine
                $OutObj = @()
                foreach ($CA in $CAs) {
                    try {
                        $CFP =  Get-CertificateValidityPeriod -CertificationAuthority $CA
                        Write-PscriboMessage "Collecting Certificate Validity Period information of $($CFP.Name)."
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

                $TableParams = @{
                    Name = "Certificate Validity Period - $($ForestInfo.ToString().ToUpper())"
                    List = $false
                    ColumnWidths = 40, 40, 20
                }
                if ($Report.ShowTableCaptions) {
                    $TableParams['Caption'] = "- $($TableParams.Name)"
                }
                $OutObj | Sort-Object -Property 'CA Name' | Table @TableParams
                try {
                    Section -Style Heading4 "Access Control List (ACL) Summary" {
                        $OutObj = @()
                        foreach ($CA in $CAs) {
                            try {
                                $ACLs =  Get-CertificationAuthorityAcl -CertificationAuthority $CA
                                Write-PscriboMessage "Collecting Certification Authority Access Control List information of $($CA.Name)."
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

                        $TableParams = @{
                            Name = "Access Control List - $($ForestInfo.ToString().ToUpper())"
                            List = $false
                            ColumnWidths = 40, 30, 30
                        }
                        if ($Report.ShowTableCaptions) {
                            $TableParams['Caption'] = "- $($TableParams.Name)"
                        }
                        $OutObj | Sort-Object -Property 'DC Name' | Table @TableParams
                        foreach ($CA in $CAs) {
                            try {
                                Section -Style Heading5 "$($CA.Name) Rights" {
                                    $OutObj = @()
                                    Write-PscriboMessage "Collecting AD Certification Authority Access Control List information of $($CA.Name)."
                                    $ACLs =  Get-CertificationAuthorityAcl -CertificationAuthority $CA
                                    foreach ($ACL in $ACLs.Access) {
                                        try {
                                            $inObj = [ordered] @{
                                                'Identity' = $ACL.IdentityReference
                                                'Access Control Type' = $ACL.AccessControlType
                                                'Rights' = $ACL.Rights
                                            }
                                            $OutObj += [pscustomobject]$inobj
                                        }
                                        catch {
                                            Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Access Control List Item)"
                                        }
                                    }

                                    $TableParams = @{
                                        Name = "ACL Rights - $($CA.Name)"
                                        List = $false
                                        ColumnWidths = 40, 20, 40
                                    }
                                    if ($Report.ShowTableCaptions) {
                                        $TableParams['Caption'] = "- $($TableParams.Name)"
                                    }
                                    $OutObj | Sort-Object -Property 'Identity' | Table @TableParams
                                }
                            }
                            catch {
                                Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Access Control List Table)"
                            }
                        }
                    }
                }
                catch {
                    Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Access Control List Section)"
                }
            }
        }
    }

    end {}

}