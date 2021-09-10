function Get-AbrADDomain {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Domain information from Domain Controller
    .DESCRIPTION

    .NOTES
        Version:        0.1.0
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
        Write-PscriboMessage "Collecting AD Domain information."
    }

    process {
        $Data = Get-ADForest | Select-Object -ExpandProperty Domains
        $OutObj = @()
        if ($Data) {
            foreach ($Item in $Data) {
                $Domains = Get-ADDomain -Identity $Item
                $inObj = [ordered] @{
                    'Domain Name' = $Domains.Name
                    'NetBIOS Name' = $Domains.NetBIOSName
                    'Domain SID' = $Domains.DomainSID
                    'Domain Functional Level' = $Domains.DomainMode
                    'Domains' = $Domains.Domains
                    'Forest' = $Domains.Forest
                    'Parent Domain' = $Domains.ParentDomain
                    'Replica Directory Servers' = $Domains.ReplicaDirectoryServers -join '; '
                    'Child Domains' = $Domains.ChildDomains -join '; '
                    'Computers Container' = $Domains.ComputersContainer
                    'Distinguished Name' = $Domains.DistinguishedName
                    'Domain Controllers Container' = $Domains.DomainControllersContainer
                    'Systems Container' = $Domains.SystemsContainer
                    'Users Container' = $Domains.UsersContainer
                    'ReadOnly Replica Directory Servers' = $Domains.ReadOnlyReplicaDirectoryServers
                }
                $OutObj += [pscustomobject]$inobj
            }

            $TableParams = @{
                Name = "AD Domain Summary Information - $($ForestInfo)"
                List = $true
                ColumnWidths = 40, 60
            }
            if ($Report.ShowTableCaptions) {
                $TableParams['Caption'] = "- $($TableParams.Name)"
            }
            $OutObj | Table @TableParams
        }
        Section -Style Heading5 'Active Directory Domain Object Count Summary' {
            Paragraph "The following section provides a summary of the Active Directory Object Count on $($ForestInfo)."
            BlankLine
            $Data = Get-ADForest | Select-Object -ExpandProperty Domains
            $OutObj = @()
            if ($Data) {
                foreach ($Item in $Data) {
                    $GlobalCatalog = Get-ADDomainController -Discover -Service GlobalCatalog
                    $Computers = (Get-ADComputer -Filter * -Server "$($GlobalCatalog.name):3268" -Searchbase (Get-ADDomain -Identity $Item).distinguishedName) | Measure-Object
                    #$Servers = (Get-ADComputer -LDAPFilter "(&(objectClass=Computer)(operatingSystem=*Windows server*))" -Server "$($GlobalCatalog.name):3268" -Searchbase (Get-ADDomain -Identity $Item).distinguishedName) | Measure-Object
                    $Users = (Get-ADUser -filter * -Server "$($GlobalCatalog.name):3268" -Searchbase (Get-ADDomain -Identity $Item).distinguishedName) | Measure-Object
                    $Group = (Get-ADGroup -filter * -Server "$($GlobalCatalog.name):3268" -Searchbase (Get-ADDomain -Identity $Item).distinguishedName) | Measure-Object
                    $inObj = [ordered] @{
                        'Domain Name' = $Item
                        'Computer Count' = $Computers.Count
                        #'Servers Count' = $Servers.Count
                        'Users Count' = $Users.Count
                        'Group Count' = $Group.Count
                    }
                    $OutObj += [pscustomobject]$inobj
                }

                $TableParams = @{
                    Name = "Active Directory Object Count Information - $($ForestInfo)"
                    List = $false
                    ColumnWidths = 40, 20, 20, 20
                }
                if ($Report.ShowTableCaptions) {
                    $TableParams['Caption'] = "- $($TableParams.Name)"
                }
                $OutObj | Table @TableParams
            }
        }
        Section -Style Heading5 'Active Directory Default Domain Password Policy Summary' {
            Paragraph "The following section provides a summary of the Default Domain Password Policy on $($ForestInfo)."
            BlankLine
            $Data = Get-ADForest | Select-Object -ExpandProperty Domains
            $OutObj = @()
            if ($Data) {
                foreach ($Item in $Data) {
                    $PasswordPolicy = Get-ADDefaultDomainPasswordPolicy -Identity $Item
                    $inObj = [ordered] @{
                        'Domain Name' = $Item
                        'Complexity Enabled' = Switch ($PasswordPolicy.ComplexityEnabled) {
                            "True" { "Yes" }
                            "False" { "No" }
                            default {$PasswordPolicy.ComplexityEnabled}
                        }
                        'Distinguished Name' = $PasswordPolicy.DistinguishedName
                        'Lockout Duration' = $PasswordPolicy.LockoutDuration.toString("dd' days 'hh' hours 'mm' minutes 'ss' seconds'")
                        'Lockout Threshold' = $PasswordPolicy.LockoutThreshold
                        'Lockout Observation Window' = $PasswordPolicy.LockoutObservationWindow.toString("dd' days 'hh' hours 'mm' minutes 'ss' seconds'")
                        'Max Password Age' = $PasswordPolicy.MaxPasswordAge.toString("dd' days 'hh' hours 'mm' minutes 'ss' seconds'")
                        'Min Password Age' = $PasswordPolicy.MinPasswordAge.toString("dd' days 'hh' hours 'mm' minutes 'ss' seconds'")
                        'Min Password Length' = $PasswordPolicy.MinPasswordLength
                        'Password History Count' = $PasswordPolicy.PasswordHistoryCount
                        'Reversible Encryption Enabled' = Switch ($PasswordPolicy.ReversibleEncryptionEnabled) {
                            "True" { "Yes" }
                            "False" { "No" }
                            default {$PasswordPolicy.ReversibleEncryptionEnabled}
                        }

                    }
                    $OutObj += [pscustomobject]$inobj
                }

                $TableParams = @{
                    Name = "Default Domain Password Policy Information - $($ForestInfo)"
                    List = $true
                    ColumnWidths = 40, 60
                }
                if ($Report.ShowTableCaptions) {
                    $TableParams['Caption'] = "- $($TableParams.Name)"
                }
                $OutObj | Table @TableParams
            }
        }
    }

    end {}

}