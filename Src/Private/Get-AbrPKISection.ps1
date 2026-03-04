function Get-AbrPKISection {
    <#
    .SYNOPSIS
    Used by As Built Report to build Microsoft AD PKI Section.
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
    )

    begin {
        Write-PScriboMessage -Message ([string]::Format($reportTranslate.GetAbrPKISection.Collecting, $ForestInfo))
        Show-AbrDebugExecutionTime -Start -TitleMessage 'PKI Section'
    }

    process {
        if ($InfoLevel.CA -ge 1) {
            try {
                $CurrentMachineADDomain = Get-ComputerADDomain -ErrorAction SilentlyContinue
            } catch {
                Write-PScriboMessage -IsWarning $reportTranslate.GetAbrPKISection.UnableDomain
                Write-PScriboMessage -IsWarning $_.Exception.Message
            }
            if ($CurrentMachineADDomain.Name -in $ADSystem.Domains) {
                Write-PScriboMessage -Message ([string]::Format($reportTranslate.GetAbrPKISection.DomainInForest, $CurrentMachineADDomain.Name, $ADSystem.Name))
                try {
                    $script:CAs = Get-CertificationAuthority -Enterprise
                } catch {
                    Write-PScriboMessage -IsWarning $_.Exception.Message
                }

                if ($CAs) {
                    try {
                        Section -Style Heading1 $reportTranslate.GetAbrPKISection.Heading {
                            if ($Options.ShowDefinitionInfo) {
                                Paragraph $reportTranslate.GetAbrPKISection.DefinitionParagraph
                                BlankLine
                            }
                            if (-not $Options.ShowDefinitionInfo) {
                                Paragraph $reportTranslate.GetAbrPKISection.Paragraph
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
                                    Section -Style Heading2 "$($CAObject.DisplayName) $($reportTranslate.GetAbrPKISection.DetailsSuffix)" {
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
                Write-PScriboMessage -IsWarning -Message ([string]::Format($reportTranslate.GetAbrPKISection.DomainNotInForest, $CurrentMachineADDomain.Name, $ADSystem.Name))
            }
        }
    }
    end {
        Show-AbrDebugExecutionTime -End -TitleMessage 'PKI Section'
    }
}
