function Get-AbrADDFSHealth {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Domain DFS Health information.
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
        [string[]]$DCs,
        $ValidDcFromDomain
    )

    begin {
        Write-PScriboMessage -Message ($reportTranslate.GetAbrADDFSHealth.Collecting -f $Domain.DNSRoot)
        Show-AbrDebugExecutionTime -Start -TitleMessage 'DFS Health'
    }

    process {
        if ($HealthCheck.Domain.DFS) {
            try {
                if ($Options.Exclude.DCs) {
                    $DFS = Get-WinADDFSHealth -Domain $Domain.DNSRoot -Credential $Credential -ExcludeDomains $Options.Exclude.Domains -ExcludeDomainControllers $Options.Exclude.DCs
                } else { $DFS = Get-WinADDFSHealth -Domain $Domain.DNSRoot -Credential $Credential -ExcludeDomains $Options.Exclude.Domains }
                if ($DFS) {
                    Section -ExcludeFromTOC -Style NOTOCHeading4 $reportTranslate.GetAbrADDFSHealth.SysvolReplicationTitle {
                        Paragraph ($reportTranslate.GetAbrADDFSHealth.SysvolReplicationParagraph -f $Domain.DNSRoot.ToString().ToUpper())
                        BlankLine
                        $OutObj = [System.Collections.Generic.List[object]]::new()
                        foreach ($Controller in $DCs) {
                            try {
                                $RepState = $DFS | Where-Object { $_.DomainController -eq $Controller.Split('.')[0] } | Select-Object -Property ReplicationState, GroupPolicyCount, SysvolCount, IdenticalCount, StopReplicationOnAutoRecovery
                                $inObj = [ordered] @{
                                    $reportTranslate.GetAbrADDFSHealth.DCName = $Controller.Split('.')[0]
                                    $reportTranslate.GetAbrADDFSHealth.ReplicationStatus = switch ([string]::IsNullOrEmpty($RepState.ReplicationState)) {
                                        $true { $reportTranslate.GetAbrADDFSHealth.SysvolReplicationOffline }
                                        $false { $RepState.ReplicationState }
                                        default { '--' }
                                    }
                                    $reportTranslate.GetAbrADDFSHealth.GPOCount = switch ([string]::IsNullOrEmpty($RepState.GroupPolicyCount)) {
                                        $true { '0' }
                                        $false { $RepState.GroupPolicyCount }
                                        default { '--' }
                                    }
                                    $reportTranslate.GetAbrADDFSHealth.SysvolCount = switch ([string]::IsNullOrEmpty($RepState.SysvolCount)) {
                                        $true { '0' }
                                        $false { $RepState.SysvolCount }
                                        default { '--' }
                                    }
                                    $reportTranslate.GetAbrADDFSHealth.IdenticalCount = switch ([string]::IsNullOrEmpty($RepState.IdenticalCount)) {
                                        $true { '0' }
                                        $false { $RepState.IdenticalCount }
                                        default { '--' }
                                    }
                                    $reportTranslate.GetAbrADDFSHealth.StopReplicationOnAutoRecovery = switch ([string]::IsNullOrEmpty($RepState.StopReplicationOnAutoRecovery)) {
                                        $true { '0' }
                                        $false { $RepState.StopReplicationOnAutoRecovery }
                                        default { '--' }
                                    }

                                }
                                $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj))
                            } catch {
                                Write-PScriboMessage -IsWarning -Message "$($reportTranslate.GetAbrADDFSHealth.ErrorSysvolReplicationStatusItemSection) $($_.Exception.Message)"
                            }
                        }

                        if ($HealthCheck.Domain.DFS) {
                            $ReplicationStatusError = @(
                                'Uninitialized',
                                'Auto recovery',
                                'In error state',
                                'Disabled',
                                'Offline'
                            )
                            $ReplicationStatusWarn = @(
                                'Initialized',
                                'Initial synchronization'
                            )
                            $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADDFSHealth.IdenticalCount) -like 'No' } | Set-Style -Style Warning -Property $reportTranslate.GetAbrADDFSHealth.IdenticalCount
                            $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADDFSHealth.ReplicationStatus) -eq 'Normal' } | Set-Style -Style OK -Property $reportTranslate.GetAbrADDFSHealth.ReplicationStatus
                            $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADDFSHealth.ReplicationStatus) -in $ReplicationStatusError } | Set-Style -Style Critical -Property $reportTranslate.GetAbrADDFSHealth.ReplicationStatus
                            $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADDFSHealth.ReplicationStatus) -in $ReplicationStatusWarn } | Set-Style -Style Warning -Property $reportTranslate.GetAbrADDFSHealth.ReplicationStatus
                        }

                        $TableParams = @{
                            Name = "$($reportTranslate.GetAbrADDFSHealth.SysvolReplicationTableName) - $($Domain.DNSRoot.ToString().ToUpper())"
                            List = $false
                            ColumnWidths = 20, 16, 16, 16, 16, 16
                        }

                        if ($Report.ShowTableCaptions) {
                            $TableParams['Caption'] = "- $($TableParams.Name)"
                        }
                        $OutObj | Sort-Object -Property $reportTranslate.GetAbrADDFSHealth.DCName | Table @TableParams
                        if ($HealthCheck.Domain.DFS -and (($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADDFSHealth.IdenticalCount) -like 'No' }) -or ($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADDFSHealth.ReplicationStatus) -in $ReplicationStatusError }))) {
                            Paragraph $reportTranslate.GetAbrADDFSHealth.SysvolReplicationHealthCheck -Bold -Underline
                            BlankLine
                            Paragraph {
                                Text $reportTranslate.GetAbrADDFSHealth.SysvolReplicationCorrectiveActions -Bold
                                Text $reportTranslate.GetAbrADDFSHealth.SysvolReplicationBP
                            }
                            BlankLine
                        }
                    }
                } else {
                    Write-PScriboMessage -Message ($reportTranslate.GetAbrADDFSHealth.SysvolReplicationNoData -f $Domain.DNSRoot)
                }
            } catch {
                Write-PScriboMessage -IsWarning -Message "$($reportTranslate.GetAbrADDFSHealth.ErrorSysvolReplicationStatusTableSection) $($_.Exception.Message)"
            }
            try {

                $DCPssSession = Get-ValidPSSession -ComputerName $ValidDcFromDomain -SessionName $($ValidDcFromDomain) -PSSTable ([ref]$PSSTable)
                if ($DCPssSession) {
                    # Code taken from ClaudioMerola (https://github.com/ClaudioMerola/ADxRay)
                    $SYSVOLFolder = Invoke-CommandWithTimeout -Session $DCPssSession -ScriptBlock { Get-ChildItem -Path "\\$(($using:Domain).DNSRoot)\SYSVOL\$(($using:Domain).DNSRoot)" -Recurse | Where-Object -FilterScript { -not $_.PSIsContainer } | Group-Object -Property Extension | ForEach-Object -Process {
                            New-Object -TypeName PSObject -Property @{
                                'Extension' = $_.name
                                'Count' = $_.count
                                'TotalSize' = '{0:N2}' -f ((($_.group | Measure-Object length -Sum).Sum) / 1MB)
                            } } | Sort-Object -Descending -Property 'Totalsize' }
                } else {
                    if (-not $_.Exception.MessageId) {
                        $ErrorMessage = $_.FullyQualifiedErrorId
                    } else { $ErrorMessage = $_.Exception.MessageId }
                    Write-PScriboMessage -IsWarning -Message ($reportTranslate.GetAbrADDFSHealth.ErrorSysvolContentPSSession -f $ValidDcFromDomain, $ErrorMessage)
                }
                if ($SYSVOLFolder) {
                    Section -ExcludeFromTOC -Style NOTOCHeading4 $reportTranslate.GetAbrADDFSHealth.SysvolContentTitle {
                        Paragraph ($reportTranslate.GetAbrADDFSHealth.SysvolContentParagraph -f $Domain.DNSRoot.ToString().ToUpper())
                        BlankLine
                        $OutObj = [System.Collections.Generic.List[object]]::new()
                        foreach ($Extension in $SYSVOLFolder) {
                            try {
                                $inObj = [ordered] @{
                                    $reportTranslate.GetAbrADDFSHealth.Extension = $Extension.Extension
                                    $reportTranslate.GetAbrADDFSHealth.FileCount = $Extension.Count
                                    $reportTranslate.GetAbrADDFSHealth.Size = "$($Extension.TotalSize) MB"
                                }
                                $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj))
                            } catch {
                                Write-PScriboMessage -IsWarning -Message "$($reportTranslate.GetAbrADDFSHealth.ErrorSysvolHealthSection -f $Extension.Extension) $($_.Exception.Message)"
                            }
                        }

                        if ($HealthCheck.Domain.DFS) {
                            $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADDFSHealth.Extension) -notin ('.bat', '.exe', '.nix', '.vbs', '.pol', '.reg', '.xml', '.admx', '.adml', '.inf', '.ini', '.adm', '.kix', '.msi', '.ps1', '.cmd', '.ico', '.cmtx') } | Set-Style -Style Warning -Property $reportTranslate.GetAbrADDFSHealth.Extension
                        }

                        $TableParams = @{
                            Name = "$($reportTranslate.GetAbrADDFSHealth.SysvolContentTableName) - $($Domain.DNSRoot.ToString().ToUpper())"
                            List = $false
                            ColumnWidths = 33, 33, 34
                        }

                        if ($Report.ShowTableCaptions) {
                            $TableParams['Caption'] = "- $($TableParams.Name)"
                        }
                        $OutObj | Sort-Object -Property $reportTranslate.GetAbrADDFSHealth.Extension | Table @TableParams
                        if ($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADDFSHealth.Extension) -notin ('.bat', '.exe', '.nix', '.vbs', '.pol', '.reg', '.xml', '.admx', '.adml', '.inf', '.ini', '.adm', '.kix', '.msi', '.ps1', '.cmd', '.ico') }) {
                            Paragraph $reportTranslate.GetAbrADDFSHealth.ContentHealthCheck -Bold -Underline
                            BlankLine
                            Paragraph {
                                Text $reportTranslate.GetAbrADDFSHealth.ContentCorrectiveActions -Bold
                                Text $reportTranslate.GetAbrADDFSHealth.ContentSysvolBP
                            }
                        }
                    }
                } else {
                    Write-PScriboMessage -Message ($reportTranslate.GetAbrADDFSHealth.SysvolContentNoData -f $Domain.DNSRoot)
                }
            } catch {
                Write-PScriboMessage -IsWarning -Message "$($reportTranslate.GetAbrADDFSHealth.ErrorSysvolHealthTableSection) $($_.Exception.Message)"
            }
            try {
                $DCPssSession = Get-ValidPSSession -ComputerName $ValidDcFromDomain -SessionName $($ValidDcFromDomain) -PSSTable ([ref]$PSSTable)
                if ($DCPssSession) {
                    # Code taken from ClaudioMerola (https://github.com/ClaudioMerola/ADxRay)
                    $NetlogonFolder = Invoke-CommandWithTimeout -Session $DCPssSession -ScriptBlock { Get-ChildItem -Path "\\$(($using:Domain).DNSRoot)\NETLOGON\" -Recurse | Where-Object -FilterScript { -not $_.PSIsContainer } | Group-Object -Property Extension | ForEach-Object -Process {
                            New-Object -TypeName PSObject -Property @{
                                'Extension' = $_.name
                                'Count' = $_.count
                                'TotalSize' = '{0:N2}' -f ((($_.group | Measure-Object length -Sum).Sum) / 1MB)
                            } } | Sort-Object -Descending -Property 'Totalsize' }
                } else {
                    if (-not $_.Exception.MessageId) {
                        $ErrorMessage = $_.FullyQualifiedErrorId
                    } else { $ErrorMessage = $_.Exception.MessageId }
                    Write-PScriboMessage -IsWarning -Message ($reportTranslate.GetAbrADDFSHealth.ErrorNetlogonContentPSSession -f $ValidDcFromDomain, $ErrorMessage)
                }
                if ($NetlogonFolder) {
                    Section -ExcludeFromTOC -Style NOTOCHeading4 $reportTranslate.GetAbrADDFSHealth.NetlogonContentTitle {
                        Paragraph ($reportTranslate.GetAbrADDFSHealth.NetlogonContentParagraph -f $Domain.DNSRoot.ToString().ToUpper())
                        BlankLine
                        $OutObj = [System.Collections.Generic.List[object]]::new()
                        foreach ($Extension in $NetlogonFolder) {
                            try {
                                $inObj = [ordered] @{
                                    $reportTranslate.GetAbrADDFSHealth.Extension = $Extension.Extension
                                    $reportTranslate.GetAbrADDFSHealth.FileCount = $Extension.Count
                                    $reportTranslate.GetAbrADDFSHealth.Size = "$($Extension.TotalSize) MB"
                                }
                                $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj))
                            } catch {
                                Write-PScriboMessage -IsWarning -Message "$($reportTranslate.GetAbrADDFSHealth.ErrorNetlogonHealthSection -f $Extension.Extension) $($_.Exception.Message)"
                            }
                        }

                        if ($HealthCheck.Domain.DFS) {
                            $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADDFSHealth.Extension) -notin ('.bat', '.exe', '.nix', '.vbs', '.pol', '.reg', '.xml', '.admx', '.adml', '.inf', '.ini', '.adm', '.kix', '.msi', '.ps1', '.cmd', '.ico', '.cmtx') } | Set-Style -Style Warning -Property $reportTranslate.GetAbrADDFSHealth.Extension
                        }

                        $TableParams = @{
                            Name = "$($reportTranslate.GetAbrADDFSHealth.NetlogonContentTableName) - $($Domain.DNSRoot.ToString().ToUpper())"
                            List = $false
                            ColumnWidths = 33, 33, 34
                        }

                        if ($Report.ShowTableCaptions) {
                            $TableParams['Caption'] = "- $($TableParams.Name)"
                        }
                        $OutObj | Sort-Object -Property $reportTranslate.GetAbrADDFSHealth.Extension | Table @TableParams
                        if ($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADDFSHealth.Extension) -notin ('.bat', '.exe', '.nix', '.vbs', '.pol', '.reg', '.xml', '.admx', '.adml', '.inf', '.ini', '.adm', '.kix', '.msi', '.ps1', '.cmd', '.ico') }) {
                            Paragraph $reportTranslate.GetAbrADDFSHealth.ContentHealthCheck -Bold -Underline
                            BlankLine
                            Paragraph {
                                Text $reportTranslate.GetAbrADDFSHealth.ContentCorrectiveActions -Bold
                                Text $reportTranslate.GetAbrADDFSHealth.ContentNetlogonBP
                            }
                        }
                    }
                } else {
                    Write-PScriboMessage -Message ($reportTranslate.GetAbrADDFSHealth.NetlogonContentNoData -f $Domain.DNSRoot)
                }
            } catch {
                Write-PScriboMessage -IsWarning -Message "$($reportTranslate.GetAbrADDFSHealth.ErrorNetlogonContentStatusSection) $($_.Exception.Message)"
            }
        }
    }

    end {
        Show-AbrDebugExecutionTime -End -TitleMessage 'DFS Health'
    }

}