function Get-AbrADDomain {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Domain information from Domain Controller
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
        $Domain,
        [string]$ValidDcFromDomain
    )

    begin {
        Write-PScriboMessage -Message ($reportTranslate.GetAbrADDomain.Collecting -f $Forestinfo)
        Show-AbrDebugExecutionTime -Start -TitleMessage 'AD Domain'
    }

    process {
        $OutObj = [System.Collections.Generic.List[object]]::new()
        if ($Domain) {
            try {
                $RIDPool = Invoke-CommandWithTimeout -Session $TempPssSession -ScriptBlock { Get-ADObject -Server $using:ValidDcFromDomain -Identity "CN=RID Manager$,CN=System,$(($using:DomainInfo).DistinguishedName)" -Properties rIDAvailablePool -ErrorAction SilentlyContinue }
                $RIDavailable = $RIDPool.rIDAvailablePool
                [int32] $CompleteSIDS = $($RIDavailable) / ([math]::Pow(2, 32))
                [int64] $TEMP = $CompleteSIDS * ([math]::Pow(2, 32))
                $RIDsIssued = [int32]($($RIDavailable) - $TEMP)
                $RIDsRemaining = $CompleteSIDS - $RIDsIssued
                if ($Domain) {
                    $inObj = [ordered] @{
                        $reportTranslate.GetAbrADDomain.DomainName = $Domain.Name
                        $reportTranslate.GetAbrADDomain.NetBIOSName = $Domain.NetBIOSName
                        $reportTranslate.GetAbrADDomain.DomainSID = $Domain.DomainSID
                        $reportTranslate.GetAbrADDomain.DomainFunctionalLevel = $Domain.DomainMode
                        $reportTranslate.GetAbrADDomain.Domains = $Domain.Domains
                        $reportTranslate.GetAbrADDomain.Forest = $Domain.Forest
                        $reportTranslate.GetAbrADDomain.ParentDomain = $Domain.ParentDomain
                        $reportTranslate.GetAbrADDomain.ReplicaDirectoryServers = $Domain.ReplicaDirectoryServers
                        $reportTranslate.GetAbrADDomain.ChildDomains = $Domain.ChildDomains
                        $reportTranslate.GetAbrADDomain.DomainPath = ConvertTo-ADCanonicalName -DN $Domain.DistinguishedName -Domain $Domain.DNSRoot
                        $reportTranslate.GetAbrADDomain.ComputersContainer = $Domain.ComputersContainer
                        $reportTranslate.GetAbrADDomain.DomainControllersContainer = $Domain.DomainControllersContainer
                        $reportTranslate.GetAbrADDomain.SystemsContainer = $Domain.SystemsContainer
                        $reportTranslate.GetAbrADDomain.UsersContainer = $Domain.UsersContainer
                        $reportTranslate.GetAbrADDomain.DeletedObjectsContainer = $Domain.DeletedObjectsContainer
                        $reportTranslate.GetAbrADDomain.ForeignSecurityPrincipalsContainer = $Domain.ForeignSecurityPrincipalsContainer
                        $reportTranslate.GetAbrADDomain.LostAndFoundContainer = $Domain.LostAndFoundContainer
                        $reportTranslate.GetAbrADDomain.QuotasContainer = $Domain.QuotasContainer
                        $reportTranslate.GetAbrADDomain.ReadOnlyReplicaDirectoryServers = $Domain.ReadOnlyReplicaDirectoryServers
                        $reportTranslate.GetAbrADDomain.MachineAccountQuota = Invoke-CommandWithTimeout -Session $TempPssSession -ScriptBlock { (Get-ADObject -Server $using:ValidDcFromDomain -Identity (($using:Domain).DistinguishedName) -Properties ms-DS-MachineAccountQuota -ErrorAction SilentlyContinue).'ms-DS-MachineAccountQuota' }
                        $reportTranslate.GetAbrADDomain.RIDIssuedAvailable = try { "$($RIDsIssued) / $($RIDsRemaining) ($([math]::Truncate($CompleteSIDS / $RIDsRemaining))% Issued)" } catch { "$($RIDsIssued)/$($RIDsRemaining)" }
                    }
                    $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj))

                    if ($HealthCheck.Domain.BestPractice) {
                        if ([math]::Truncate($CompleteSIDS / $RIDsRemaining) -gt 80) {
                            $OutObj | Set-Style -Style Warning -Property $reportTranslate.GetAbrADDomain.RIDIssuedAvailable
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
                        Paragraph $reportTranslate.GetAbrADDomain.HealthCheck -Bold -Underline
                        BlankLine
                        Paragraph {
                            Text $reportTranslate.GetAbrADDomain.BestPractice -Bold
                            Text $reportTranslate.GetAbrADDomain.RIDBestPractice
                        }
                        BlankLine
                        Paragraph {
                            Text $reportTranslate.GetAbrADDomain.Reference -Bold
                            Text $reportTranslate.GetAbrADDomain.RIDReference -Color blue
                        }
                    }
                }
            } catch {
                Write-PScriboMessage -IsWarning -Message "AD Domain Summary Section: $($_.Exception.Message)"
            }
        }
    }

    end {
        Show-AbrDebugExecutionTime -End -TitleMessage 'AD Domain'
    }

}