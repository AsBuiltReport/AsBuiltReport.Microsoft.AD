function Get-AbrADDomain {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Domain information from Domain Controller
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
        [Parameter (
            Position = 0,
            Mandatory)]
            [string]
            $Domain,
            $Session,
            [pscredential]
            $Cred
    )

    begin {
        Write-PscriboMessage "Discovering AD Domain information on forest $Forestinfo."
    }

    process {
        $OutObj = @()
        if ($Domain) {
            try {
                $DomainInfo =  Invoke-Command -Session $Session {Get-ADDomain $using:Domain -ErrorAction Stop}
                Write-PscriboMessage "Discovered Active Directory Domain information of domain $Domain."
                if ($DomainInfo) {
                    Write-PscriboMessage "Collecting Domain information of '$($DomainInfo)'."
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
                        'Domain Path' = ConvertTo-ADCanonicalName -DN $DomainInfo.DistinguishedName -Credential $Cred -Domain $Domain
                        'Computers Container' = ConvertTo-ADCanonicalName -DN $DomainInfo.ComputersContainer -Credential $Cred -Domain $Domain
                        'Domain Controllers Container' = ConvertTo-ADCanonicalName -DN $DomainInfo.DomainControllersContainer -Credential $Cred -Domain $Domain
                        'Systems Container' = ConvertTo-ADCanonicalName -DN $DomainInfo.SystemsContainer -Credential $Cred -Domain $Domain
                        'Users Container' = ConvertTo-ADCanonicalName -DN $DomainInfo.UsersContainer -Credential $Cred -Domain $Domain
                        'ReadOnly Replica Directory Servers' = ConvertTo-EmptyToFiller $DomainInfo.ReadOnlyReplicaDirectoryServers
                    }
                    $OutObj += [pscustomobject]$inobj

                    $TableParams = @{
                        Name = "Domain Summary - $($Domain.ToString().ToUpper())"
                        List = $true
                        ColumnWidths = 40, 60
                    }
                    if ($Report.ShowTableCaptions) {
                        $TableParams['Caption'] = "- $($TableParams.Name)"
                    }
                    $OutObj | Table @TableParams
                }
            }
            catch {
                Write-PscriboMessage -IsWarning "$($_.Exception.Message) (AD Domain Summary)"
            }
        }
    }

    end {}

}