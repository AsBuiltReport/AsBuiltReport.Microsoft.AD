function Get-AbrADDomain {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Domain information from Domain Controller
    .DESCRIPTION

    .NOTES
        Version:        0.8.1
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
        [string]
        $Domain
    )

    begin {
        Write-PScriboMessage "Discovering AD Domain information on forest $Forestinfo."
    }

    process {
        $OutObj = @()
        if ($Domain) {
            try {
                $DomainInfo = Invoke-Command -Session $TempPssSession { Get-ADDomain $using:Domain -ErrorAction Stop }
                $DC = $DomainInfo | Select-Object -ExpandProperty ReplicaDirectoryServers | Select-Object -First 1
                $RIDPool = Invoke-Command -Session $TempPssSession { Get-ADObject -Server $using:DC -Identity "CN=RID Manager$,CN=System,$(($using:DomainInfo).DistinguishedName)" -Properties rIDAvailablePool -ErrorAction SilentlyContinue }
                $RIDavailable = $RIDPool.rIDAvailablePool
                [int32] $CompleteSIDS = $($RIDavailable) / ([math]::Pow(2, 32))
                [int64] $TEMP = $CompleteSIDS * ([math]::Pow(2, 32))
                $RIDsIssued = [int32]($($RIDavailable) - $TEMP)
                $RIDsRemaining = $CompleteSIDS - $RIDsIssued
                Write-PScriboMessage "Discovered Active Directory Domain information of domain $Domain."
                if ($DomainInfo) {
                    Write-PScriboMessage "Collecting Domain information of '$($DomainInfo)'."
                    $inObj = [ordered] @{
                        'Domain Name' = $DomainInfo.Name
                        'NetBIOS Name' = $DomainInfo.NetBIOSName
                        'Domain SID' = $DomainInfo.DomainSID
                        'Domain Functional Level' = $DomainInfo.DomainMode
                        'Domains' = ConvertTo-EmptyToFiller $DomainInfo.Domains
                        'Forest' = $DomainInfo.Forest
                        'Parent Domain' = ConvertTo-EmptyToFiller $DomainInfo.ParentDomain
                        'Replica Directory Servers' = $DomainInfo.ReplicaDirectoryServers
                        'Child Domains' = ConvertTo-EmptyToFiller $DomainInfo.ChildDomains
                        'Domain Path' = ConvertTo-ADCanonicalName -DN $DomainInfo.DistinguishedName -Domain $Domain
                        'Computers Container' = ConvertTo-ADCanonicalName -DN $DomainInfo.ComputersContainer -Domain $Domain
                        'Domain Controllers Container' = ConvertTo-ADCanonicalName -DN $DomainInfo.DomainControllersContainer -Domain $Domain
                        'Systems Container' = ConvertTo-ADCanonicalName -DN $DomainInfo.SystemsContainer -Domain $Domain
                        'Users Container' = ConvertTo-ADCanonicalName -DN $DomainInfo.UsersContainer -Domain $Domain
                        'Deleted Objects Container' = ConvertTo-ADCanonicalName -DN $DomainInfo.DeletedObjectsContainer -Domain $Domain
                        'Foreign Security Principals Container' = ConvertTo-ADCanonicalName -DN $DomainInfo.ForeignSecurityPrincipalsContainer -Domain $Domain
                        'Lost And Found Container' = ConvertTo-ADCanonicalName -DN $DomainInfo.LostAndFoundContainer -Domain $Domain
                        'Quotas Container' = ConvertTo-ADCanonicalName -DN $DomainInfo.QuotasContainer -Domain $Domain

                        'ReadOnly Replica Directory Servers' = ConvertTo-EmptyToFiller $DomainInfo.ReadOnlyReplicaDirectoryServers
                        'ms-DS-MachineAccountQuota' = Invoke-Command -Session $TempPssSession { (Get-ADObject -Server $using:DC -Identity (($using:DomainInfo).DistinguishedName) -Properties ms-DS-MachineAccountQuota -ErrorAction SilentlyContinue).'ms-DS-MachineAccountQuota' }
                        'RID Issued/Available' = try { "$($RIDsIssued) / $($RIDsRemaining) ($([math]::Truncate($CompleteSIDS / $RIDsRemaining))% Issued)" } catch { "$($RIDsIssued)/$($RIDsRemaining)" }
                    }
                    $OutObj += [pscustomobject]$inobj

                    if ($HealthCheck.Domain.BestPractice) {
                        if ([math]::Truncate($CompleteSIDS / $RIDsRemaining) -gt 80) {
                            $OutObj | Set-Style -Style Warning -Property 'RID Issued/Available'
                        }
                    }

                    $TableParams = @{
                        Name = "Domain Summary - $($Domain.ToString().ToUpper())"
                        List = $true
                        ColumnWidths = 40, 60
                    }
                    if ($Report.ShowTableCaptions) {
                        $TableParams['Caption'] = "- $($TableParams.Name)"
                    }
                    $OutObj | Table @TableParams
                    if ($HealthCheck.Domain.BestPractice -and ([math]::Truncate($CompleteSIDS / $RIDsRemaining) -gt 80)) {
                        Paragraph "Health Check:" -Bold -Underline
                        BlankLine
                        Paragraph {
                            Text "Best Practice:" -Bold
                            Text "The RID Issued is greater than 80%, a thorough evaluation of their utilization is recommended to prevent RIDs from being exhausted."
                        }
                        BlankLine
                        Paragraph {
                            Text "Reference:" -Bold
                            Text "https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/managing-rid-pool-depletion/ba-p/399736"
                        }
                    }
                }
            } catch {
                Write-PScriboMessage -IsWarning "AD Domain Summary Section: $($_.Exception.Message)"
            }
        }
    }

    end {}

}