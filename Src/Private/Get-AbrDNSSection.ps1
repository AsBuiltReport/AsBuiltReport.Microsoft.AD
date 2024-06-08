function Get-AbrDNSSection {
    <#
    .SYNOPSIS
    Used by As Built Report to build Microsoft AD DNS Section.
    .DESCRIPTION

    .NOTES
        Version:        0.8.2
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
        Write-PScriboMessage "Collecting DNS server information from $ForestInfo."
    }

    process {
        if ($InfoLevel.DNS -ge 1) {
            Section -Style Heading1 "DNS Configuration" {
                if ($Options.ShowDefinitionInfo) {
                    Paragraph "The Domain Name System (DNS) is a hierarchical and decentralized naming system for computers, services, or other resources connected to the Internet or a private network. It associates various information with domain names assigned to each of the participating entities. Most prominently, it translates more readily memorized domain names to the numerical IP addresses needed for locating and identifying computer services and devices with the underlying network protocols."
                    BlankLine
                }
                if (-Not $Options.ShowDefinitionInfo) {
                    Paragraph "The following section provides a summary of the Active Directory DNS Infrastructure Information."
                    BlankLine
                }
                foreach ($Domain in $OrderedDomains.split(" ")) {
                    if ($Domain) {
                        try {
                            # Define Filter option for Domain variable
                            if ($Options.Include.Domains) {
                                $DomainFilterOption = $Domain -in $Options.Include.Domains

                            } else {
                                $DomainFilterOption = $Domain -notin $Options.Exclude.Domains
                            }
                            if (( $DomainFilterOption ) -and (Invoke-Command -Session $TempPssSession { Get-ADDomain $using:Domain -ErrorAction Stop })) {
                                Section -Style Heading2 "$($Domain.ToString().ToUpper())" {
                                    Paragraph "The following section provides a configuration summary of the DNS service."
                                    BlankLine
                                    Get-AbrADDNSInfrastructure -Domain $Domain
                                    $DCs = Invoke-Command -Session $TempPssSession { Get-ADDomain $using:Domain | Select-Object -ExpandProperty ReplicaDirectoryServers | Where-Object { $_ -notin ($using:Options).Exclude.DCs } }
                                    foreach ($DC in $DCs) {
                                        if (Test-Connection -ComputerName $DC -Quiet -Count 2) {
                                            $DCPssSession = New-PSSession $DC -Credential $Credential -Authentication $Options.PSDefaultAuthentication -Name 'DDNSInfrastructure'
                                            Get-AbrADDNSZone -Domain $Domain -DC $DC
                                        }
                                        if ($DCPssSession) {
                                            Remove-PSSession -Session $DCPssSession
                                        }
                                    }
                                }
                            } else {
                                Write-PScriboMessage "$($Domain) disabled in Exclude.Domain variable"
                            }
                        } catch {
                            Write-PScriboMessage -IsWarning "$($_.Exception.Message) (Domain Name System Information)"
                        }
                    }
                }
            }
        }
    }
    end {}
}
