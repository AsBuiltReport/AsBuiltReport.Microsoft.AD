function Get-AbrADOU {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Organizational Unit information
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
        Write-PscriboMessage "Discovering Active Directory Organizational Unit information on domain $Domain"
    }

    process {
        try {
            $DC = Invoke-Command -Session $Session -ScriptBlock {Get-ADDomainController -Discover -Domain $using:Domain | Select-Object -ExpandProperty HostName}
            Write-PscriboMessage "Discovered Active Directory Organizational Unit information on DC $DC. (Organizational Unit)"
            $DCPssSession = New-PSSession $DC -Credential $Cred -Authentication Default
            $OUs = Invoke-Command -Session $DCPssSession -ScriptBlock {Get-ADOrganizationalUnit -Searchbase (Get-ADDomain -Identity $using:Domain).distinguishedName -Filter *}
            if ($OUs) {
                Section -Style Heading5 "Organizational Units" {
                    Paragraph "The following section provides a summary of Active Directory Organizational Unit information."
                    BlankLine
                    $OutObj = @()
                    foreach ($OU in $OUs) {
                        try {
                            Write-PscriboMessage "Collecting information of Active Directory Organizational Unit $OU."
                            $GPOArray = @()
                            [array]$GPOs = $OU.LinkedGroupPolicyObjects
                            foreach ($Object in $GPOs) {
                                $GP = Invoke-Command -Session $DCPssSession -ScriptBlock {Get-GPO -Guid ($using:Object).Split(",")[0].Split("=")[1] -Domain $using:Domain}
                                Write-PscriboMessage "Collecting linked GPO: '$($GP.DisplayName)' on Organizational Unit $OU."
                                $GPOArray += $GP.DisplayName
                            }
                            $inObj = [ordered] @{
                                'Name' = $OU.Name
                                'Path' = ConvertTo-ADCanonicalName -DN $OU.DistinguishedName -Credential $Cred -Domain $Domain
                                'Linked GPO' = ConvertTo-EmptyToFiller ($GPOArray -join ", ")
                            }
                            $OutObj += [pscustomobject]$inobj
                        }
                        catch {
                            Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Organizational Unit Item)"
                        }
                    }
                    Remove-PSSession -Session $DCPssSession

                    $TableParams = @{
                        Name = "Active Directory Organizational Unit Information - $($Domain.ToString().ToUpper())"
                        List = $false
                        ColumnWidths = 25, 40, 35
                    }
                    if ($Report.ShowTableCaptions) {
                        $TableParams['Caption'] = "- $($TableParams.Name)"
                    }
                    $OutObj | Table @TableParams
                    if ($HealthCheck.Domain.GPO) {
                        try {
                            $OutObj = @()
                            $DC = Invoke-Command -Session $Session {Get-ADDomain -Identity $using:Domain | Select-Object -ExpandProperty ReplicaDirectoryServers | Select-Object -First 1}
                            Write-PscriboMessage "Discovered Active Directory Domain Controller $DC in $Domain. (Group Policy Objects)"
                            $DCPssSession = New-PSSession $DC -Credential $Cred -Authentication Default
                            $OUs = Invoke-Command -Session $DCPssSession -ScriptBlock {Get-ADOrganizationalUnit -Filter * | Select-Object -Property DistinguishedName}
                            if ($OUs) {
                                Write-PscriboMessage "Discovered Active Directory Group Policy Objects information on $Domain. (Group Policy Objects)"
                                foreach ($OU in $OUs) {
                                    try {
                                        $GpoInheritance =  Invoke-Command -Session $DCPssSession -ScriptBlock { Get-GPInheritance -Target ($using:OU).DistinguishedName }
                                        if ( $GpoInheritance.GPOInheritanceBlocked -eq "True") {
                                            Write-PscriboMessage "Collecting Active Directory Blocked Inheritance Group Policy Objects'$($GpoEnforced.DisplayName)'."
                                            $PathCanonical = Invoke-Command -Session $DCPssSession -ScriptBlock { Get-ADObject -Identity ($using:GpoInheritance).Path -Properties * | Select-Object -ExpandProperty CanonicalName }
                                            $inObj = [ordered] @{
                                                'OU Name' = $GpoInheritance.Name
                                                'Container Type' = $GpoInheritance.ContainerType
                                                'Inheritance Blocked' = ConvertTo-TextYN $GpoInheritance.GpoInheritanceBlocked
                                                'Path' = ConvertTo-ADCanonicalName -DN $GpoInheritance.Path -Credential $Cred -Domain $Domain
                                            }
                                            $OutObj += [pscustomobject]$inobj
                                        }
                                    }
                                    catch {
                                        Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Blocked Inheritance GPO Item)"
                                    }
                                }
                            }
                            Remove-PSSession -Session $DCPssSession
                            if ($OutObj) {
                                Section -Style Heading5 "Health Check - OU with GPO Blocked Inheritance" {
                                    Paragraph "The following section provides a summary of the Blocked Inheritance Group Policy Objects."
                                    BlankLine

                                    if ($HealthCheck.Domain.GPO) {
                                        $OutObj | Set-Style -Style Warning
                                    }

                                    $TableParams = @{
                                        Name = "Blocked Inheritance GPO Information - $($Domain.ToString().ToUpper())"
                                        List = $false
                                        ColumnWidths = 35, 15, 15, 35
                                    }

                                    if ($Report.ShowTableCaptions) {
                                        $TableParams['Caption'] = "- $($TableParams.Name)"
                                    }
                                    $OutObj | Table @TableParams
                                }
                            }

                        }
                        catch {
                            Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Blocked Inheritance GPO Section)"
                        }
                    }
                }
            }
        }
        catch {
            Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Organizational Unit Section)"
        }
    }

    end {}

}