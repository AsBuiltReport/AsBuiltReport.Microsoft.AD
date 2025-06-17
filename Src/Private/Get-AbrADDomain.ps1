function Get-AbrADDomain {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Domain information from Domain Controller
    .DESCRIPTION

    .NOTES
        Version:        0.9.6
        Author:         Jonathan Colon
        Twitter:        @jcolonfzenpr
        Github:         rebelinux
    .EXAMPLE

    .LINK

    #>
    [CmdletBinding()]
    param (
        $Domain,
        [string]$ValidDcFromDomain
    )

    begin {
        Write-PScriboMessage -Message "Collecting AD Domain information on forest $Forestinfo."
        Show-AbrDebugExecutionTime -Start -TitleMessage "AD Domain"
    }

    process {
        $OutObj = [System.Collections.ArrayList]::new()
        if ($Domain) {
            try {
                $RIDPool = Invoke-Command -Session $TempPssSession { Get-ADObject -Server $using:ValidDcFromDomain -Identity "CN=RID Manager$,CN=System,$(($using:DomainInfo).DistinguishedName)" -Properties rIDAvailablePool -ErrorAction SilentlyContinue }
                $RIDavailable = $RIDPool.rIDAvailablePool
                [int32] $CompleteSIDS = $($RIDavailable) / ([math]::Pow(2, 32))
                [int64] $TEMP = $CompleteSIDS * ([math]::Pow(2, 32))
                $RIDsIssued = [int32]($($RIDavailable) - $TEMP)
                $RIDsRemaining = $CompleteSIDS - $RIDsIssued
                if ($Domain) {
                    $inObj = [ordered] @{
                        'Domain Name' = $Domain.Name
                        'NetBIOS Name' = $Domain.NetBIOSName
                        'Domain SID' = $Domain.DomainSID
                        'Domain Functional Level' = $Domain.DomainMode
                        'Domains' = $Domain.Domains
                        'Forest' = $Domain.Forest
                        'Parent Domain' = $Domain.ParentDomain
                        'Replica Directory Servers' = $Domain.ReplicaDirectoryServers
                        'Child Domains' = $Domain.ChildDomains
                        'Domain Path' = ConvertTo-ADCanonicalName -DN $Domain.DistinguishedName -Domain $Domain.DNSRoot
                        'Computers Container' = $Domain.ComputersContainer
                        'Domain Controllers Container' = $Domain.DomainControllersContainer
                        'Systems Container' = $Domain.SystemsContainer
                        'Users Container' = $Domain.UsersContainer
                        'Deleted Objects Container' = $Domain.DeletedObjectsContainer
                        'Foreign Security Principals Container' = $Domain.ForeignSecurityPrincipalsContainer
                        'Lost And Found Container' = $Domain.LostAndFoundContainer
                        'Quotas Container' = $Domain.QuotasContainer
                        'ReadOnly Replica Directory Servers' = $Domain.ReadOnlyReplicaDirectoryServers
                        'ms-DS-MachineAccountQuota' = Invoke-Command -Session $TempPssSession { (Get-ADObject -Server $using:ValidDcFromDomain -Identity (($using:Domain).DistinguishedName) -Properties ms-DS-MachineAccountQuota -ErrorAction SilentlyContinue).'ms-DS-MachineAccountQuota' }
                        'RID Issued/Available' = try { "$($RIDsIssued) / $($RIDsRemaining) ($([math]::Truncate($CompleteSIDS / $RIDsRemaining))% Issued)" } catch { "$($RIDsIssued)/$($RIDsRemaining)" }
                    }
                    $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null

                    if ($HealthCheck.Domain.BestPractice) {
                        if ([math]::Truncate($CompleteSIDS / $RIDsRemaining) -gt 80) {
                            $OutObj | Set-Style -Style Warning -Property 'RID Issued/Available'
                        }
                    }

                    $TableParams = @{
                        Name = "Domain Summary - $($Domain.DNSRoot.ToString().ToUpper())"
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
                Write-PScriboMessage -IsWarning -Message "AD Domain Summary Section: $($_.Exception.Message)"
            }
        }
    }

    end {
        Show-AbrDebugExecutionTime -End -TitleMessage "AD Domain"
    }

}