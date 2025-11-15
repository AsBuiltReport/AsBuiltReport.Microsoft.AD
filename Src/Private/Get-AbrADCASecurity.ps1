function Get-AbrADCASecurity {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Certification Authority Security information.
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
        Write-PScriboMessage -Message "Collecting AD Certification Authority Security information."
        Show-AbrDebugExecutionTime -Start -TitleMessage "CA Security"
    }

    process {
        if ($CA) {
            try {
                $CFP = Get-CertificateValidityPeriod -CertificationAuthority $CA
                if ($CFP) {
                    Section -Style Heading3 "Certificate Validity Period" {
                        Paragraph "The following section provides certificate validity period configuration for the Certification Authority."
                        BlankLine
                        $OutObj = [System.Collections.ArrayList]::new()
                        try {
                            $inObj = [ordered] @{
                                'CA Name' = $CFP.Name
                                'Server Name' = $CFP.ComputerName
                                'Validity Period' = $CFP.ValidityPeriod
                            }
                            $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Certificate Validity Period Table)"
                        }

                        $TableParams = @{
                            Name = "Certificate Validity Period - $($ForestInfo.ToString().ToUpper())"
                            List = $True
                            ColumnWidths = 40, 60
                        }
                        if ($Report.ShowTableCaptions) {
                            $TableParams['Caption'] = "- $($TableParams.Name)"
                        }
                        $OutObj | Sort-Object -Property 'CA Name' | Table @TableParams
                    }
                }
            } catch {
                Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Certificate Validity Period Section)"
            }
            try {
                $ACLs = Get-CertificationAuthorityAcl -CertificationAuthority $CA
                if ($ACLs) {
                    Section -Style Heading4 "Access Control List (ACL)" {
                        $OutObj = [System.Collections.ArrayList]::new()
                        try {
                            foreach ($ACL in $ACLs) {
                                try {
                                    $inObj = [ordered] @{
                                        'DC Name' = $CA.DisplayName
                                        'Owner' = $ACL.Owner
                                        'Group' = $ACL.Group
                                    }
                                    $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                                } catch {
                                    Write-PScriboMessage -IsWarning $_.Exception.Message
                                }
                            }
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Access Control List table)"
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
                        try {
                            Section -Style Heading5 "Access Rights" {
                                $OutObj = [System.Collections.ArrayList]::new()
                                foreach ($ACL in $ACLs.Access) {
                                    try {
                                        $inObj = [ordered] @{
                                            'Identity' = $ACL.IdentityReference
                                            'Access Control Type' = $ACL.AccessControlType
                                            'Rights' = $ACL.Rights
                                        }
                                        $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                                    } catch {
                                        Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Access Control List Rights table)"
                                    }
                                }

                                $TableParams = @{
                                    Name = "Access Rights - $($CA.Name)"
                                    List = $false
                                    ColumnWidths = 40, 20, 40
                                }
                                if ($Report.ShowTableCaptions) {
                                    $TableParams['Caption'] = "- $($TableParams.Name)"
                                }
                                $OutObj | Sort-Object -Property 'Identity' | Table @TableParams
                            }
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Access Control List Rights section)"
                        }
                    }
                }
            } catch {
                Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Access Control List Section)"
            }
        }
    }

    end {
        Show-AbrDebugExecutionTime -End -TitleMessage "CA Security"
    }

}