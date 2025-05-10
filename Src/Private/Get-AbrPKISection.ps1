function Get-AbrPKISection {
    <#
    .SYNOPSIS
    Used by As Built Report to build Microsoft AD PKI Section.
    .DESCRIPTION

    .NOTES
        Version:        0.9.5
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
        Write-PScriboMessage -Message "Collecting PKI infrastructure information from $ForestInfo."
        Show-AbrDebugExecutionTime -Start -TitleMessage "PKI Section"
    }

    process {
        if ($InfoLevel.CA -ge 1) {
            try {
                $CurrentMachineADDomain = Get-ComputerADDomain -ErrorAction SilentlyContinue
            } catch {
                Write-PScriboMessage -IsWarning 'Unable to determine current AD Domain'
                Write-PScriboMessage -IsWarning $_.Exception.Message
            }
            if ($CurrentMachineADDomain.Name -in $ADSystem.Domains) {
                Write-PScriboMessage -Message "Current PC Domain $($CurrentMachineADDomain.Name) is in the Forest Domain list of $($ADSystem.Name). Enabling Certificate Authority section"
                try {
                    $script:CAs = Get-CertificationAuthority -Enterprise
                } catch {
                    Write-PScriboMessage -IsWarning $_.Exception.Message
                }

                if ($CAs) {
                    try {
                        Section -Style Heading1 "PKI Configuration" {
                            if ($Options.ShowDefinitionInfo) {
                                Paragraph 'In cryptography, a certificate authority or certification authority (CA) is an entity that issues digital certificates. A digital certificate certifies the ownership of a public key by the named subject of the certificate. This allows others (relying parties) to rely upon signatures or on assertions made about the private key that corresponds to the certified public key. A CA acts as a trusted third party trusted both by the subject (owner) of the certificate and by the party relying upon the certificate. The format of these certificates is specified by the X.509 or EMV standard.'
                                BlankLine
                            }
                            if (-Not $Options.ShowDefinitionInfo) {
                                Paragraph "The following section provides a summary of the Active Directory PKI Infrastructure Information."
                                BlankLine
                            }
                            try {
                                Get-AbrADCASummary
                            } catch {
                                Write-PScriboMessage -IsWarning $_.Exception.Message
                            }
                            if ($InfoLevel.CA -ge 2) {
                                try {
                                    Get-AbrADCARoot
                                    Get-AbrADCASubordinate
                                } catch {
                                    Write-PScriboMessage -IsWarning $_.Exception.Message
                                }
                            }
                            foreach ($CA in ($CAs | Where-Object { $_.IsAccessible -notlike 'False' }).ComputerName) {
                                $CAObject = Get-CertificationAuthority -Enterprise -ComputerName $CA
                                if ($CAObject) {
                                    Section -Style Heading2 "$($CAObject.DisplayName) Details" {
                                        try {
                                            Get-AbrADCASecurity -CA $CAObject
                                        } catch {
                                            Write-PScriboMessage -IsWarning $_.Exception.Message
                                        }
                                        try {
                                            Get-AbrADCACryptographyConfig -CA $CAObject
                                        } catch {
                                            Write-PScriboMessage -IsWarning $_.Exception.Message
                                        }
                                        if ($InfoLevel.CA -ge 2) {
                                            try {
                                                Get-AbrADCAAIA -CA $CAObject
                                                Get-AbrADCACRLSetting -CA $CAObject
                                            } catch {
                                                Write-PScriboMessage -IsWarning $_.Exception.Message
                                            }
                                        }
                                        if ($InfoLevel.CA -ge 2) {
                                            try {
                                                Get-AbrADCATemplate -CA $CAObject
                                            } catch {
                                                Write-PScriboMessage -IsWarning $_.Exception.Message
                                            }
                                        }
                                        try {
                                            Get-AbrADCAKeyRecoveryAgent -CA $CAObject
                                        } catch {
                                            Write-PScriboMessage -IsWarning $_.Exception.Message
                                        }
                                    }
                                }
                            }
                        }
                    } catch {
                        Write-PScriboMessage -IsWarning $_.Exception.Message
                        continue
                    }
                }
            } else {
                Write-PScriboMessage -IsWarning -Message "Current PC Domain $($CurrentMachineADDomain.Name) is not in the Forest Domain list of $($ADSystem.Name). Disabling Certificate Authority section"
            }
        }
    }
    end {
        Show-AbrDebugExecutionTime -End -TitleMessage "PKI Section"
    }
}
