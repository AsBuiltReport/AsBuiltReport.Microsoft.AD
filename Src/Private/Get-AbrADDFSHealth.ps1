function Get-AbrADDFSHealth {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Domain DFS Health information.
    .DESCRIPTION

    .NOTES
        Version:        0.7.13
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
        Write-PscriboMessage "Discovering AD Domain DFS Health information on $Domain."
    }

    process {
        if ($HealthCheck.Domain.DFS) {
            try {
                if ($Options.Exclude.DCs) {
                    $DFS = Get-WinADDFSHealth -Domain $Domain -Credential $Credential | Where-Object {$_.DomainController -notin ($Options.Exclude.DCs).split(".", 2)[0]}
                } Else {$DFS = Get-WinADDFSHealth -Domain $Domain -Credential $Credential}
                Write-PscriboMessage "Discovered AD Domain DFS Health information from $Domain."
                if ($DFS) {
                    Section -ExcludeFromTOC -Style NOTOCHeading5 'Sysvol Replication Status' {
                        Paragraph "The following section details the sysvol folder replication status for Domain $($Domain.ToString().ToUpper())."
                        BlankLine
                        $OutObj = @()
                        foreach ($DCStatus in $DFS) {
                            try {
                                Write-PscriboMessage "Collecting DFS information from $($Domain)."
                                $inObj = [ordered] @{
                                    'DC Name' = $DCStatus.DomainController
                                    'Replication Status' = $DCStatus.ReplicationState
                                    'GPO Count' = $DCStatus.GroupPolicyCount
                                    'Sysvol Count' = $DCStatus.SysvolCount
                                    'Identical Count' = ConvertTo-TextYN $DCStatus.IdenticalCount
                                    'Stop Replication On AutoRecovery' = ConvertTo-TextYN $DCStatus.StopReplicationOnAutoRecovery

                                }
                                $OutObj += [pscustomobject]$inobj
                            }
                            catch {
                                Write-PscriboMessage -IsWarning "Sysvol Replication Status Iten Section: $($_.Exception.Message)"
                            }
                        }

                        if ($HealthCheck.Domain.DFS) {
                            $ReplicationStatusError = @(
                                'Uninitialized',
                                'Auto recovery',
                                'In error state',
                                'Disabled',
                                'Unknown'
                            )
                            $ReplicationStatusWarn = @(
                                'Initialized',
                                'Initial synchronization'
                            )
                            $OutObj | Where-Object { $_.'Identical Count' -like 'No' } | Set-Style -Style Warning -Property 'Identical Count'
                            $OutObj | Where-Object { $_.'Replication Status' -eq 'Normal' } | Set-Style -Style OK -Property 'Replication Status'
                            $OutObj | Where-Object { $_.'Replication Status' -in $ReplicationStatusError } | Set-Style -Style Critical -Property 'Replication Status'
                            $OutObj | Where-Object { $_.'Replication Status' -in $ReplicationStatusWarn } | Set-Style -Style Warning -Property 'Replication Status'
                        }

                        $TableParams = @{
                            Name = "Sysvol Replication Status - $($Domain.ToString().ToUpper())"
                            List = $false
                            ColumnWidths = 20, 16, 16, 16, 16, 16
                        }

                        if ($Report.ShowTableCaptions) {
                            $TableParams['Caption'] = "- $($TableParams.Name)"
                        }
                        $OutObj | Sort-Object -Property 'DC Name' | Table @TableParams
                        if ($HealthCheck.Domain.DFS -and (($OutObj | Where-Object { $_.'Identical Count' -like 'No' }) -or ($OutObj | Where-Object { $_.'Replication Status' -in $ReplicationStatusError }))) {
                            Paragraph "Health Check:" -Italic -Bold -Underline
                            BlankLine
                            Paragraph "Corrective Actions: SYSVOL is a special directory that resides on each domain controller (DC) within a domain. The directory comprises folders that store Group Policy objects (GPOs) and logon scripts that clients need to access and synchronize between DCs. For these logon scripts and GPOs to function properly, SYSVOL should be replicated accurately and rapidly throughout the domain. Ensure that proper SYSVOL replication is in place to ensure identical GPO/SYSVOL content for the domain controller across all Active Directory domains." -Italic -Bold
                            BlankLine
                        }
                    }
                }
            }
            catch {
                Write-PscriboMessage -IsWarning "Sysvol Replication Status Table Section: $($_.Exception.Message)"
            }
            try {
                Write-PscriboMessage "Discovered AD Domain Sysvol Health information from $Domain."
                $DC = Invoke-Command -Session $TempPssSession {Get-ADDomain -Identity $using:Domain | Select-Object -ExpandProperty ReplicaDirectoryServers | Select-Object -First 1}
                $DCPssSession = New-PSSession $DC -Credential $Credential -Authentication $Options.PSDefaultAuthentication
                # Code taken from ClaudioMerola (https://github.com/ClaudioMerola/ADxRay)
                $SYSVOLFolder = Invoke-Command -Session $DCPssSession {Get-ChildItem -path $('\\'+$using:Domain+'\SYSVOL\'+$using:Domain) -Recurse | Where-Object -FilterScript {$_.PSIsContainer -eq $false} | Group-Object -Property Extension | ForEach-Object -Process {
                    New-Object -TypeName PSObject -Property @{
                        'Extension'= $_.name
                        'Count' = $_.count
                        'TotalSize'= '{0:N2}' -f ((($_.group | Measure-Object length -Sum).Sum) /1MB)
                        } } | Sort-Object -Descending -Property 'Totalsize'}
                if ($SYSVOLFolder) {
                    Section -ExcludeFromTOC -Style NOTOCHeading5 'Sysvol Content Status' {
                        Paragraph "The following section details domain $($Domain.ToString().ToUpper()) sysvol health status."
                        BlankLine
                        $OutObj = @()
                        Write-PscriboMessage "Collecting Sysvol information from $($Domain)."
                        foreach ($Extension in $SYSVOLFolder) {
                            try {
                                $inObj = [ordered] @{
                                    'Extension' = $Extension.Extension
                                    'File Count' = $Extension.Count
                                    'Size' = "$($Extension.TotalSize) MB"
                                }
                                $OutObj += [pscustomobject]$inobj
                            }
                            catch {
                                Write-PscriboMessage -IsWarning "Sysvol Health $($Extension.Extension) Section: $($_.Exception.Message)"
                            }
                        }

                        if ($HealthCheck.Domain.DFS) {
                            $OutObj | Where-Object { $_.'Extension' -notin ('.bat','.exe','.nix','.vbs','.pol','.reg','.xml','.admx','.adml','.inf','.ini','.adm','.kix','.msi','.ps1','.cmd','.ico') } | Set-Style -Style Warning -Property 'Extension'
                        }

                        $TableParams = @{
                            Name = "Sysvol Content Status - $($Domain.ToString().ToUpper())"
                            List = $false
                            ColumnWidths = 33, 33, 34
                        }

                        if ($Report.ShowTableCaptions) {
                            $TableParams['Caption'] = "- $($TableParams.Name)"
                        }
                        $OutObj | Sort-Object -Property 'Extension' | Table @TableParams
                        if ($OutObj | Where-Object { $_.'Extension' -notin ('.bat','.exe','.nix','.vbs','.pol','.reg','.xml','.admx','.adml','.inf','.ini','.adm','.kix','.msi','.ps1','.cmd','.ico')}) {
                            Paragraph "Health Check:" -Italic -Bold -Underline
                            BlankLine
                            Paragraph "Corrective Actions: Make sure Sysvol folder has no malicious extensions or unnecessary content." -Italic -Bold
                        }
                    }
                }
                if ($DCPssSession) {
                    Remove-PSSession -Session $DCPssSession
                }
            }
            catch {
                Write-PscriboMessage -IsWarning "Sysvol Health Table Section: $($_.Exception.Message)"
            }
            try {
                Write-PscriboMessage "Discovered AD Domain Netlogon Health information from $Domain."
                $DC = Invoke-Command -Session $TempPssSession {Get-ADDomain -Identity $using:Domain | Select-Object -ExpandProperty ReplicaDirectoryServers | Select-Object -First 1}
                $DCPssSession = New-PSSession $DC -Credential $Credential -Authentication $Options.PSDefaultAuthentication
                # Code taken from ClaudioMerola (https://github.com/ClaudioMerola/ADxRay)
                $NetlogonFolder = Invoke-Command -Session $DCPssSession {Get-ChildItem -path $('\\'+$using:Domain+'\NETLOGON\') -Recurse | Where-Object -FilterScript {$_.PSIsContainer -eq $false} | Group-Object -Property Extension | ForEach-Object -Process {
                    New-Object -TypeName PSObject -Property @{
                        'Extension'= $_.name
                        'Count' = $_.count
                        'TotalSize'= '{0:N2}' -f ((($_.group | Measure-Object length -Sum).Sum) /1MB)
                        } } | Sort-Object -Descending -Property 'Totalsize'}
                if ($NetlogonFolder) {
                    Section -ExcludeFromTOC -Style NOTOCHeading5 'Netlogon Content Status' {
                        Paragraph "The following section details domain $($Domain.ToString().ToUpper()) netlogon health status."
                        BlankLine
                        $OutObj = @()
                        Write-PscriboMessage "Collecting Netlogon information from $($Domain)."
                        foreach ($Extension in $NetlogonFolder) {
                            try {
                                $inObj = [ordered] @{
                                    'Extension' = $Extension.Extension
                                    'File Count' = $Extension.Count
                                    'Size' = "$($Extension.TotalSize) MB"
                                }
                                $OutObj += [pscustomobject]$inobj
                            }
                            catch {
                                Write-PscriboMessage -IsWarning "Netlogon Health $($Extension.Extension) Section: $($_.Exception.Message)"
                            }
                        }

                        if ($HealthCheck.Domain.DFS) {
                            $OutObj | Where-Object { $_.'Extension' -notin ('.bat','.exe','.nix','.vbs','.pol','.reg','.xml','.admx','.adml','.inf','.ini','.adm','.kix','.msi','.ps1','.cmd','.ico') } | Set-Style -Style Warning -Property 'Extension'
                        }

                        $TableParams = @{
                            Name = "Netlogon Content Status - $($Domain.ToString().ToUpper())"
                            List = $false
                            ColumnWidths = 33, 33, 34
                        }

                        if ($Report.ShowTableCaptions) {
                            $TableParams['Caption'] = "- $($TableParams.Name)"
                        }
                        $OutObj | Sort-Object -Property 'Extension' | Table @TableParams
                        if ($OutObj | Where-Object { $_.'Extension' -notin ('.bat','.exe','.nix','.vbs','.pol','.reg','.xml','.admx','.adml','.inf','.ini','.adm','.kix','.msi','.ps1','.cmd','.ico')}) {
                            Paragraph "Health Check:" -Italic -Bold -Underline
                            BlankLine
                            Paragraph "Corrective Actions: Make sure Netlogon folder has no malicious extensions or unnecessary content." -Italic -Bold
                        }
                    }
                }
                if ($DCPssSession) {
                    Remove-PSSession -Session $DCPssSession
                }
            }
            catch {
                Write-PscriboMessage -IsWarning "Sysvol Health Section: $($_.Exception.Message)"
            }
        }
    }

    end {}

}