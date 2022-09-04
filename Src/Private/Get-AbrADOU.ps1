function Get-AbrADOU {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Organizational Unit information
    .DESCRIPTION

    .NOTES
        Version:        0.7.6
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
        Write-PscriboMessage "Discovering Active Directory Organizational Unit information on domain $Domain"
    }

    process {
        try {
            $DC = Invoke-Command -Session $TempPssSession -ScriptBlock {Get-ADDomainController -Discover -Domain $using:Domain | Select-Object -ExpandProperty HostName}
            Write-PscriboMessage "Discovered Active Directory Organizational Unit information on DC $DC. (Organizational Unit)"
            $OUs = Invoke-Command -Session $TempPssSession -ScriptBlock {Get-ADOrganizationalUnit -Server $using:DC -Searchbase (Get-ADDomain -Identity $using:Domain).distinguishedName -Filter *}
            if ($OUs) {
                Section -Style Heading4 "Organizational Units" {
                    Paragraph "The following section provides a summary of Active Directory Organizational Unit information."
                    BlankLine
                    $OutObj = @()
                    foreach ($OU in $OUs) {
                        try {
                            Write-PscriboMessage "Collecting information of Active Directory Organizational Unit $OU."
                            $GPOArray = @()
                            [array]$GPOs = $OU.LinkedGroupPolicyObjects
                            foreach ($Object in $GPOs) {
                                try {
                                    $GP = Invoke-Command -Session $TempPssSession -ScriptBlock {Get-GPO -Server $using:DC -Guid ($using:Object).Split(",")[0].Split("=")[1] -Domain $using:Domain}
                                    Write-PscriboMessage "Collecting linked GPO: '$($GP.DisplayName)' on Organizational Unit $OU."
                                    $GPOArray += $GP.DisplayName
                                }
                                catch {
                                    Write-PscriboMessage -IsWarning $_.Exception.Message
                                }
                            }
                            $inObj = [ordered] @{
                                'Name' = $OU.Name
                                'Path' = ConvertTo-ADCanonicalName -DN $OU.DistinguishedName -Domain $Domain -DC $DC
                                'Linked GPO' = ConvertTo-EmptyToFiller ($GPOArray -join ", ")
                            }
                            $OutObj += [pscustomobject]$inobj
                        }
                        catch {
                            Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Organizational Unit Item)"
                        }
                    }

                    $TableParams = @{
                        Name = "Organizational Unit - $($Domain.ToString().ToUpper())"
                        List = $false
                        ColumnWidths = 25, 40, 35
                    }
                    if ($Report.ShowTableCaptions) {
                        $TableParams['Caption'] = "- $($TableParams.Name)"
                    }
                    $OutObj | Sort-Object -Property 'Path' | Table @TableParams
                    if ($HealthCheck.Domain.GPO) {
                        try {
                            $OutObj = @()
                            $DC = Invoke-Command -Session $TempPssSession {Get-ADDomain -Identity $using:Domain | Select-Object -ExpandProperty ReplicaDirectoryServers | Select-Object -First 1}
                            Write-PscriboMessage "Discovered Active Directory Domain Controller $DC in $Domain. (Group Policy Objects)"
                            $OUs = Invoke-Command -Session $TempPssSession -ScriptBlock {Get-ADOrganizationalUnit -Server $using:DC -Filter * | Select-Object -Property DistinguishedName}
                            if ($OUs) {
                                Write-PscriboMessage "Discovered Active Directory Group Policy Objects information on $Domain. (Group Policy Objects)"
                                foreach ($OU in $OUs) {
                                    try {
                                        $GpoInheritance =  Invoke-Command -Session $TempPssSession -ScriptBlock { Get-GPInheritance -Domain $using:Domain -Server $using:DC -Target ($using:OU).DistinguishedName }
                                        if ( $GpoInheritance.GPOInheritanceBlocked -eq "True") {
                                            Write-PscriboMessage "Collecting Active Directory Blocked Inheritance Group Policy Objects'$($GpoEnforced.DisplayName)'."
                                            $PathCanonical = Invoke-Command -Session $TempPssSession -ScriptBlock { Get-ADObject -Server $using:DC -Identity ($using:GpoInheritance).Path -Properties * | Select-Object -ExpandProperty CanonicalName }
                                            $inObj = [ordered] @{
                                                'OU Name' = $GpoInheritance.Name
                                                'Container Type' = $GpoInheritance.ContainerType
                                                'Inheritance Blocked' = ConvertTo-TextYN $GpoInheritance.GpoInheritanceBlocked
                                                'Path' = ConvertTo-ADCanonicalName -DN $GpoInheritance.Path -Domain $Domain -DC $DC
                                            }
                                            $OutObj += [pscustomobject]$inobj
                                        }
                                    }
                                    catch {
                                        Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Blocked Inheritance GPO Item)"
                                    }
                                }
                            }
                            if ($OutObj) {
                                Section -Style Heading4 "GPO Blocked Inheritance" {
                                    if ($HealthCheck.Domain.GPO) {
                                        $OutObj | Set-Style -Style Warning
                                    }

                                    $TableParams = @{
                                        Name = "Blocked Inheritance GPO - $($Domain.ToString().ToUpper())"
                                        List = $false
                                        ColumnWidths = 35, 15, 15, 35
                                    }

                                    if ($Report.ShowTableCaptions) {
                                        $TableParams['Caption'] = "- $($TableParams.Name)"
                                    }
                                    $OutObj | Sort-Object -Property 'OU Name' | Table @TableParams
                                    Paragraph "Health Check:" -Italic -Bold -Underline
                                    Paragraph "Corrective Actions: Review use of enforcement and blocked policy inheritance in Active Directory." -Italic -Bold
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