function Get-AbrADDFSHealth {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Domain DFS Health information.
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
        [string[]]$DCs,
        $ValidDcFromDomain
    )

    begin {
        Write-PScriboMessage -Message "Collecting AD Domain DFS Health information on $($Domain.DNSRoot)."
        Show-AbrDebugExecutionTime -Start -TitleMessage "DFS Health"
    }

    process {
        if ($HealthCheck.Domain.DFS) {
            try {
                if ($Options.Exclude.DCs) {
                    $DFS = Get-WinADDFSHealth -Domain $Domain.DNSRoot -Credential $Credential -ExcludeDomains $Options.Exclude.Domains -ExcludeDomainControllers $Options.Exclude.DCs
                } Else { $DFS = Get-WinADDFSHealth -Domain $Domain.DNSRoot -Credential $Credential -ExcludeDomains $Options.Exclude.Domains }
                if ($DFS) {
                    Section -ExcludeFromTOC -Style NOTOCHeading4 'Sysvol Replication Status' {
                        Paragraph "The following section details the sysvol folder replication status for Domain $($Domain.DNSRoot.ToString().ToUpper())."
                        BlankLine
                        $OutObj = @()
                        foreach ($Controller in $DCs) {
                            try {
                                $RepState = $DFS | Where-Object { $_.DomainController -eq $Controller.Split('.')[0] } | Select-Object -Property ReplicationState, GroupPolicyCount, SysvolCount, IdenticalCount, StopReplicationOnAutoRecovery
                                $inObj = [ordered] @{
                                    'DC Name' = $Controller.Split('.')[0]
                                    'Replication Status' = Switch ([string]::IsNullOrEmpty($RepState.ReplicationState)) {
                                        $true { "Offline" }
                                        $false { $RepState.ReplicationState }
                                        default { "--" }
                                    }
                                    'GPO Count' = switch ([string]::IsNullOrEmpty($RepState.GroupPolicyCount)) {
                                        $true { "0" }
                                        $false { $RepState.GroupPolicyCount }
                                        default { "--" }
                                    }
                                    'Sysvol Count' = switch ([string]::IsNullOrEmpty($RepState.SysvolCount)) {
                                        $true { "0" }
                                        $false { $RepState.SysvolCount }
                                        default { "--" }
                                    }
                                    'Identical Count' = switch ([string]::IsNullOrEmpty($RepState.IdenticalCount)) {
                                        $true { "0" }
                                        $false { $RepState.IdenticalCount }
                                        default { "--" }
                                    }
                                    'Stop Replication On AutoRecovery' = switch ([string]::IsNullOrEmpty($RepState.StopReplicationOnAutoRecovery)) {
                                        $true { "0" }
                                        $false { $RepState.StopReplicationOnAutoRecovery }
                                        default { "--" }
                                    }

                                }
                                $OutObj += [pscustomobject](ConvertTo-HashToYN $inObj)
                            } catch {
                                Write-PScriboMessage -IsWarning -Message "Sysvol Replication Status Iten Section: $($_.Exception.Message)"
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
                            Name = "Sysvol Replication Status - $($Domain.DNSRoot.ToString().ToUpper()))"
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
                    Write-PScriboMessage -Message "No DFS information found in $($Domain.DNSRoot), Disabling this section."
                }
            } catch {
                Write-PScriboMessage -IsWarning -Message "Sysvol Replication Status Table Section: $($_.Exception.Message)"
            }
            try {

                $DCPssSession = Get-ValidPSSession -ComputerName $ValidDcFromDomain -SessionName $($ValidDcFromDomain) -PSSTable ([ref]$PSSTable)
                if ($DCPssSession) {
                    # Code taken from ClaudioMerola (https://github.com/ClaudioMerola/ADxRay)
                    $SYSVOLFolder = Invoke-Command -Session $DCPssSession { Get-ChildItem -Path $('\\' + ($using:Domain).DNSRoot + '\SYSVOL\' + ($using:Domain).DNSRoot) -Recurse | Where-Object -FilterScript { $_.PSIsContainer -eq $false } | Group-Object -Property Extension | ForEach-Object -Process {
                            New-Object -TypeName PSObject -Property @{
                                'Extension' = $_.name
                                'Count' = $_.count
                                'TotalSize' = '{0:N2}' -f ((($_.group | Measure-Object length -Sum).Sum) / 1MB)
                            } } | Sort-Object -Descending -Property 'Totalsize' }
                } else {
                    if (-Not $_.Exception.MessageId) {
                        $ErrorMessage = $_.FullyQualifiedErrorId
                    } else { $ErrorMessage = $_.Exception.MessageId }
                    Write-PScriboMessage -IsWarning -Message "Sysvol Content Status Section: New-PSSession: Unable to connect to $($ValidDcFromDomain): $ErrorMessage"
                }
                if ($SYSVOLFolder) {
                    Section -ExcludeFromTOC -Style NOTOCHeading4 'Sysvol Content Status' {
                        Paragraph "The following section details domain $($Domain.DNSRoot.ToString().ToUpper())) sysvol health status."
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
                                Write-PScriboMessage -IsWarning -Message "Sysvol Health $($Extension.Extension) Section: $($_.Exception.Message)"
                            }
                        }

                        if ($HealthCheck.Domain.DFS) {
                            $OutObj | Where-Object { $_.'Extension' -notin ('.bat', '.exe', '.nix', '.vbs', '.pol', '.reg', '.xml', '.admx', '.adml', '.inf', '.ini', '.adm', '.kix', '.msi', '.ps1', '.cmd', '.ico', '.cmtx') } | Set-Style -Style Warning -Property 'Extension'
                        }

                        $TableParams = @{
                            Name = "Sysvol Content Status - $($Domain.DNSRoot.ToString().ToUpper())"
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
                    Write-PScriboMessage -Message "No SYSVOL folder information found in $($Domain.DNSRoot), Disabling this section."
                }
            } catch {
                Write-PScriboMessage -IsWarning -Message "Sysvol Health Table Section: $($_.Exception.Message)"
            }
            try {
                $DCPssSession = Get-ValidPSSession -ComputerName $ValidDcFromDomain -SessionName $($ValidDcFromDomain) -PSSTable ([ref]$PSSTable)
                if ($DCPssSession) {
                    # Code taken from ClaudioMerola (https://github.com/ClaudioMerola/ADxRay)
                    $NetlogonFolder = Invoke-Command -Session $DCPssSession { Get-ChildItem -Path $('\\' + ($using:Domain).DNSRoot + '\NETLOGON\') -Recurse | Where-Object -FilterScript { $_.PSIsContainer -eq $false } | Group-Object -Property Extension | ForEach-Object -Process {
                            New-Object -TypeName PSObject -Property @{
                                'Extension' = $_.name
                                'Count' = $_.count
                                'TotalSize' = '{0:N2}' -f ((($_.group | Measure-Object length -Sum).Sum) / 1MB)
                            } } | Sort-Object -Descending -Property 'Totalsize' }
                } else {
                    if (-Not $_.Exception.MessageId) {
                        $ErrorMessage = $_.FullyQualifiedErrorId
                    } else { $ErrorMessage = $_.Exception.MessageId }
                    Write-PScriboMessage -IsWarning -Message "Netlogon Content Status Section: New-PSSession: Unable to connect to $($ValidDcFromDomain): $ErrorMessage"
                }
                if ($NetlogonFolder) {
                    Section -ExcludeFromTOC -Style NOTOCHeading4 'Netlogon Content Status' {
                        Paragraph "The following section details domain $($Domain.DNSRoot.ToString().ToUpper())) netlogon health status."
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
                                Write-PScriboMessage -IsWarning -Message "Netlogon Health $($Extension.Extension) Section: $($_.Exception.Message)"
                            }
                        }

                        if ($HealthCheck.Domain.DFS) {
                            $OutObj | Where-Object { $_.'Extension' -notin ('.bat', '.exe', '.nix', '.vbs', '.pol', '.reg', '.xml', '.admx', '.adml', '.inf', '.ini', '.adm', '.kix', '.msi', '.ps1', '.cmd', '.ico', '.cmtx') } | Set-Style -Style Warning -Property 'Extension'
                        }

                        $TableParams = @{
                            Name = "Netlogon Content Status - $($Domain.DNSRoot.ToString().ToUpper())"
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
                    Write-PScriboMessage -Message "No NETLOGON folder information found in $($Domain.DNSRoot), Disabling this section."
                }
            } catch {
                Write-PScriboMessage -IsWarning -Message "Netlogon Content Status Section: $($_.Exception.Message)"
            }
        }
    }

    end {
        Show-AbrDebugExecutionTime -End -TitleMessage "DFS Health"
    }

}