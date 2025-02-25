function Get-AbrADDomain {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Domain information from Domain Controller
    .DESCRIPTION

    .NOTES
        Version:        0.9.2
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
        Write-PScriboMessage "Collecting AD Domain information on forest $Forestinfo."
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
                if ($DomainInfo) {
                    $inObj = [ordered] @{
                        'Domain Name' = $DomainInfo.Name
                        'NetBIOS Name' = $DomainInfo.NetBIOSName
                        'Domain SID' = $DomainInfo.DomainSID
                        'Domain Functional Level' = $DomainInfo.DomainMode
                        'Domains' = $DomainInfo.Domains
                        'Forest' = $DomainInfo.Forest
                        'Parent Domain' = $DomainInfo.ParentDomain
                        'Replica Directory Servers' = $DomainInfo.ReplicaDirectoryServers
                        'Child Domains' = $DomainInfo.ChildDomains
                        'Domain Path' = ConvertTo-ADCanonicalName -DN $DomainInfo.DistinguishedName -Domain $Domain
                        'Computers Container' = $DomainInfo.ComputersContainer
                        'Domain Controllers Container' = $DomainInfo.DomainControllersContainer
                        'Systems Container' = $DomainInfo.SystemsContainer
                        'Users Container' = $DomainInfo.UsersContainer
                        'Deleted Objects Container' = $DomainInfo.DeletedObjectsContainer
                        'Foreign Security Principals Container' = $DomainInfo.ForeignSecurityPrincipalsContainer
                        'Lost And Found Container' = $DomainInfo.LostAndFoundContainer
                        'Quotas Container' = $DomainInfo.QuotasContainer
                        'ReadOnly Replica Directory Servers' = $DomainInfo.ReadOnlyReplicaDirectoryServers
                        'ms-DS-MachineAccountQuota' = Invoke-Command -Session $TempPssSession { (Get-ADObject -Server $using:DC -Identity (($using:DomainInfo).DistinguishedName) -Properties ms-DS-MachineAccountQuota -ErrorAction SilentlyContinue).'ms-DS-MachineAccountQuota' }
                        'RID Issued/Available' = try { "$($RIDsIssued) / $($RIDsRemaining) ($([math]::Truncate($CompleteSIDS / $RIDsRemaining))% Issued)" } catch { "$($RIDsIssued)/$($RIDsRemaining)" }
                    }
                    $OutObj += [pscustomobject](ConvertTo-HashToYN $inObj)

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
                            Text "The RID Issued percentage exceeds 80%. It is recommended to evaluate the utilization of RIDs to prevent potential exhaustion and ensure the stability of the domain. The Relative Identifier (RID) is a crucial component in the SID (Security Identifier) for objects within the domain. Exhaustion of the RID pool can lead to the inability to create new security principals, such as user or computer accounts. Regular monitoring and proactive management of the RID pool are essential to maintain domain health and avoid disruptions."
                        }
                        BlankLine
                        Paragraph {
                            Text "Reference:" -Bold
                            Text "https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/managing-rid-pool-depletion/ba-p/399736" -Color blue
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