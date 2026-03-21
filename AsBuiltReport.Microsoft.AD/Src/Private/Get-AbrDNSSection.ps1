function Get-AbrDNSSection {
    <#
    .SYNOPSIS
    Used by As Built Report to build Microsoft AD DNS Section.
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
        [ref]$DomainStatus
    )

    begin {
        Write-PScriboMessage -Message ([string]::Format($reportTranslate.GetAbrDNSSection.Collecting, $ForestInfo))
        Show-AbrDebugExecutionTime -Start -TitleMessage 'DNS Section'
    }

    process {
        if ($InfoLevel.DNS -ge 1) {
            $DNSDomainObj = foreach ($Domain in ($OrderedDomains | Where-Object { $_ -notin $Options.Exclude.Domains })) {
                if ($Domain -and ($Domain -notin $DomainStatus.Value.Name)) {
                    if (Get-ValidDCfromDomain -Domain $Domain -DCStatus ([ref]$DCStatus)) {
                        try {
                            if ($DomainInfo = Invoke-CommandWithTimeout -Session $TempPssSession -ScriptBlock { Get-ADDomain -Identity $using:Domain }) {
                                Write-Host ([string]::Format("  - $($reportTranslate.GetAbrDNSSection.CollectingDomain)", $Domain))
                                $DCs = Invoke-CommandWithTimeout -Session $TempPssSession -ScriptBlock { Get-ADDomain -Identity $using:Domain | Select-Object -ExpandProperty ReplicaDirectoryServers | Where-Object { $_ -notin ($using:Options).Exclude.DCs } } | Sort-Object

                                Section -Style Heading2 "$($DomainInfo.DNSRoot.ToString().ToUpper())" {
                                    Paragraph $reportTranslate.GetAbrDNSSection.DomainParagraph
                                    BlankLine
                                    if ($TempCIMSession) {
                                        Get-AbrADDNSInfrastructure -Domain $DomainInfo -DCs $DCs
                                    } else {
                                        Write-PScriboMessage -IsWarning -Message ($reportTranslate.GetAbrDNSSection.NoCIMSession)
                                        Paragraph $reportTranslate.GetAbrDNSSection.NoCIMSession
                                        BlankLine
                                    }
                                    foreach ($DC in $DCs) {
                                        if (Get-DCWinRMState -ComputerName $DC -DCStatus ([ref]$DCStatus)) {
                                            Get-AbrADDNSZone -Domain $DomainInfo -DC $DC
                                        }
                                    }
                                }
                            } else {
                                Write-PScriboMessage -Message ([string]::Format($reportTranslate.GetAbrDNSSection.ExcludedDomain, $DomainInfo.DNSRoot))
                            }
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Domain Name System Information)"
                        }
                    } else {
                        Write-PScriboMessage -IsWarning -Message ([string]::Format($reportTranslate.GetAbrDNSSection.NoDCAvailable, $DomainInfo.DNSRoot))
                    }
                }
            }
            if ($DNSDomainObj) {
                Section -Style Heading1 $reportTranslate.GetAbrDNSSection.Heading {
                    if ($Options.ShowDefinitionInfo) {
                        Paragraph $reportTranslate.GetAbrDNSSection.DefinitionParagraph
                        BlankLine
                    }
                    if (-not $Options.ShowDefinitionInfo) {
                        Paragraph $reportTranslate.GetAbrDNSSection.Paragraph
                        BlankLine
                    }
                    $DNSDomainObj
                }
            }
        }
    }
    end {
        Show-AbrDebugExecutionTime -End -TitleMessage 'DNS Section'
    }
}
