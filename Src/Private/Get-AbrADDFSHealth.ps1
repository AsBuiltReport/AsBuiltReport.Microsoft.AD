function Get-AbrADDFSHealth {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Domain DFS Health information.
    .DESCRIPTION

    .NOTES
        Version:        0.9.4
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
        Write-PScriboMessage "Collecting AD Domain DFS Health information on $Domain."
    }

    process {
        if ($HealthCheck.Domain.DFS) {
            try {
                if ($Options.Exclude.DCs) {
                    $DFS = Get-WinADDFSHealth -Domain $Domain -Credential $Credential | Where-Object { $_.DomainController -notin ($Options.Exclude.DCs).split(".", 2)[0] }
                } Else { $DFS = Get-WinADDFSHealth -Domain $Domain -Credential $Credential }
                if ($DFS) {
                    Section -ExcludeFromTOC -Style NOTOCHeading4 'Sysvol Replication Status' {
                        Paragraph "The following section details the sysvol folder replication status for Domain $($Domain.ToString().ToUpper())."
                        BlankLine
                        $OutObj = @()
                        foreach ($DCStatus in $DFS) {
                            try {
                                $inObj = [ordered] @{
                                    'DC Name' = $DCStatus.DomainController
                                    'Replication Status' = Switch ([string]::IsNullOrEmpty($DCStatus.ReplicationState)) {
                                        $true { "Unknown" }
                                        $false { $DCStatus.ReplicationState }
                                        default { "--" }
                                    }
                                    'GPO Count' = $DCStatus.GroupPolicyCount
                                    'Sysvol Count' = $DCStatus.SysvolCount
                                    'Identical Count' = $DCStatus.IdenticalCount
                                    'Stop Replication On AutoRecovery' = $DCStatus.StopReplicationOnAutoRecovery

                                }
                                $OutObj += [pscustomobject](ConvertTo-HashToYN $inObj)
                            } catch {
                                Write-PScriboMessage -IsWarning "Sysvol Replication Status Iten Section: $($_.Exception.Message)"
                            }
                        }

                        if ($HealthCheck.Domain.DFS) {
                            $ReplicationStatusError = @(
                                'Uninitialized',
                                'Auto recovery',
                                'In error state',
                                'Disabled'
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
                            Paragraph "Health Check:" -Bold -Underline
                            BlankLine
                            Paragraph {
                                Text "Corrective Actions:" -Bold
                                Text "SYSVOL is a special directory that resides on each domain controller (DC) within a domain. The directory comprises folders that store Group Policy objects (GPOs) and logon scripts that clients need to access and synchronize between DCs. For these logon scripts and GPOs to function properly, SYSVOL should be replicated accurately and rapidly throughout the domain. Ensure that proper SYSVOL replication is in place to ensure identical GPO/SYSVOL content for the domain controller across all Active Directory domains."
                            }
                            BlankLine
                        }
                    }
                } else {
                    Write-PScriboMessage "No DFS information found in $Domain, Disabling this section."
                }
            } catch {
                Write-PScriboMessage -IsWarning "Sysvol Replication Status Table Section: $($_.Exception.Message)"
            }
            try {
                $DC = Get-ValidDCfromDomain -Domain $Domain -DCStatus ([ref]$DCStatus)

                $DCPssSession = Get-ValidPSSession -ComputerName $DC -SessionName $($DC) -PSSTable ([ref]$PSSTable)
                if ($DCPssSession) {
                    # Code taken from ClaudioMerola (https://github.com/ClaudioMerola/ADxRay)
                    $SYSVOLFolder = Invoke-Command -Session $DCPssSession { Get-ChildItem -Path $('\\' + $using:Domain + '\SYSVOL\' + $using:Domain) -Recurse | Where-Object -FilterScript { $_.PSIsContainer -eq $false } | Group-Object -Property Extension | ForEach-Object -Process {
                            New-Object -TypeName PSObject -Property @{
                                'Extension' = $_.name
                                'Count' = $_.count
                                'TotalSize' = '{0:N2}' -f ((($_.group | Measure-Object length -Sum).Sum) / 1MB)
                            } } | Sort-Object -Descending -Property 'Totalsize' }
                } else {
                    if (-Not $_.Exception.MessageId) {
                        $ErrorMessage = $_.FullyQualifiedErrorId
                    } else { $ErrorMessage = $_.Exception.MessageId }
                    Write-PScriboMessage -IsWarning "Sysvol Content Status Section: New-PSSession: Unable to connect to $($DC): $ErrorMessage"
                }
                if ($SYSVOLFolder) {
                    Section -ExcludeFromTOC -Style NOTOCHeading4 'Sysvol Content Status' {
                        Paragraph "The following section details domain $($Domain.ToString().ToUpper()) sysvol health status."
                        BlankLine
                        $OutObj = @()
                        foreach ($Extension in $SYSVOLFolder) {
                            try {
                                $inObj = [ordered] @{
                                    'Extension' = $Extension.Extension
                                    'File Count' = $Extension.Count
                                    'Size' = "$($Extension.TotalSize) MB"
                                }
                                $OutObj += [pscustomobject](ConvertTo-HashToYN $inObj)
                            } catch {
                                Write-PScriboMessage -IsWarning "Sysvol Health $($Extension.Extension) Section: $($_.Exception.Message)"
                            }
                        }

                        if ($HealthCheck.Domain.DFS) {
                            $OutObj | Where-Object { $_.'Extension' -notin ('.bat', '.exe', '.nix', '.vbs', '.pol', '.reg', '.xml', '.admx', '.adml', '.inf', '.ini', '.adm', '.kix', '.msi', '.ps1', '.cmd', '.ico', '.cmtx') } | Set-Style -Style Warning -Property 'Extension'
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
                        if ($OutObj | Where-Object { $_.'Extension' -notin ('.bat', '.exe', '.nix', '.vbs', '.pol', '.reg', '.xml', '.admx', '.adml', '.inf', '.ini', '.adm', '.kix', '.msi', '.ps1', '.cmd', '.ico') }) {
                            Paragraph "Health Check:" -Bold -Underline
                            BlankLine
                            Paragraph {
                                Text "Corrective Actions:" -Bold
                                Text "Review the files and extensions listed above and ensure they are necessary for the operation of your domain. Remove any files that are not required or that appear suspicious. Regularly monitor the Sysvol folder to maintain a healthy and secure Active Directory environment."
                            }
                        }
                    }
                } else {
                    Write-PScriboMessage "No SYSVOL folder information found in $Domain, Disabling this section."
                }
            } catch {
                Write-PScriboMessage -IsWarning "Sysvol Health Table Section: $($_.Exception.Message)"
            }
            try {
                $DC = Get-ValidDCfromDomain -Domain $Domain -DCStatus ([ref]$DCStatus)
                $DCPssSession = Get-ValidPSSession -ComputerName $DC -SessionName $($DC) -PSSTable ([ref]$PSSTable)
                if ($DCPssSession) {
                    # Code taken from ClaudioMerola (https://github.com/ClaudioMerola/ADxRay)
                    $NetlogonFolder = Invoke-Command -Session $DCPssSession { Get-ChildItem -Path $('\\' + $using:Domain + '\NETLOGON\') -Recurse | Where-Object -FilterScript { $_.PSIsContainer -eq $false } | Group-Object -Property Extension | ForEach-Object -Process {
                            New-Object -TypeName PSObject -Property @{
                                'Extension' = $_.name
                                'Count' = $_.count
                                'TotalSize' = '{0:N2}' -f ((($_.group | Measure-Object length -Sum).Sum) / 1MB)
                            } } | Sort-Object -Descending -Property 'Totalsize' }
                } else {
                    if (-Not $_.Exception.MessageId) {
                        $ErrorMessage = $_.FullyQualifiedErrorId
                    } else { $ErrorMessage = $_.Exception.MessageId }
                    Write-PScriboMessage -IsWarning "Netlogon Content Status Section: New-PSSession: Unable to connect to $($DC): $ErrorMessage"
                }
                if ($NetlogonFolder) {
                    Section -ExcludeFromTOC -Style NOTOCHeading4 'Netlogon Content Status' {
                        Paragraph "The following section details domain $($Domain.ToString().ToUpper()) netlogon health status."
                        BlankLine
                        $OutObj = @()
                        foreach ($Extension in $NetlogonFolder) {
                            try {
                                $inObj = [ordered] @{
                                    'Extension' = $Extension.Extension
                                    'File Count' = $Extension.Count
                                    'Size' = "$($Extension.TotalSize) MB"
                                }
                                $OutObj += [pscustomobject](ConvertTo-HashToYN $inObj)
                            } catch {
                                Write-PScriboMessage -IsWarning "Netlogon Health $($Extension.Extension) Section: $($_.Exception.Message)"
                            }
                        }

                        if ($HealthCheck.Domain.DFS) {
                            $OutObj | Where-Object { $_.'Extension' -notin ('.bat', '.exe', '.nix', '.vbs', '.pol', '.reg', '.xml', '.admx', '.adml', '.inf', '.ini', '.adm', '.kix', '.msi', '.ps1', '.cmd', '.ico', '.cmtx') } | Set-Style -Style Warning -Property 'Extension'
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
                        if ($OutObj | Where-Object { $_.'Extension' -notin ('.bat', '.exe', '.nix', '.vbs', '.pol', '.reg', '.xml', '.admx', '.adml', '.inf', '.ini', '.adm', '.kix', '.msi', '.ps1', '.cmd', '.ico') }) {
                            Paragraph "Health Check:" -Bold -Underline
                            BlankLine
                            Paragraph {
                                Text "Corrective Actions:" -Bold
                                Text "Review the files and extensions listed above and ensure they are necessary for the operation of your domain. Remove any files that are not required or that appear suspicious. Regularly monitor the Netlogon folder to maintain a healthy and secure Active Directory environment."
                            }
                        }
                    }
                } else {
                    Write-PScriboMessage "No NETLOGON folder information found in $Domain, Disabling this section."
                }
            } catch {
                Write-PScriboMessage -IsWarning "Netlogon Content Status Section: $($_.Exception.Message)"
            }
        }
    }

    end {}

}