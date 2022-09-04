function Get-AbrADDFSHealth {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Domain DFS Health information.
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
        Write-PscriboMessage "Discovering AD Domain DFS Health information on $Domain."
    }

    process {
        if ($Domain -and $HealthCheck.Domain.DFS) {
            try {
                if ($Options.Exclude.DCs) {
                    $DFS = Get-WinADDFSHealth -Domain $Domain | Where-Object {$_.DomainController -notin ($Options.Exclude.DCs).split(".", 2)[0]}
                } Else {$DFS = Get-WinADDFSHealth -Domain $Domain}
                Write-PscriboMessage "Discovered AD Domain DFS Health information from $Domain."
                if ($DFS) {
                    Section -Style Heading5 'DFS Health' {
                        Paragraph "The following section details Distributed File System health status for Domain $($Domain.ToString().ToUpper())."
                        BlankLine
                        $OutObj = @()
                        foreach ($DCStatus in $DFS) {
                            try {
                                Write-PscriboMessage "Collecting DFS information from $($Domain)."
                                $inObj = [ordered] @{
                                    'DC Name' = $DCStatus.DomainController
                                    'Replication State' = $DCStatus.ReplicationState
                                    'GPO Count' = $DCStatus.GroupPolicyCount
                                    'Sysvol Count' = $DCStatus.SysvolCount
                                    'Identical Count' = ConvertTo-TextYN $DCStatus.IdenticalCount
                                    'Stop Replication On AutoRecovery' = ConvertTo-TextYN $DCStatus.StopReplicationOnAutoRecovery

                                }
                                $OutObj += [pscustomobject]$inobj
                            }
                            catch {
                                Write-PscriboMessage -IsWarning "$($_.Exception.Message) (DFS Health Item)"
                            }
                        }

                        if ($HealthCheck.Domain.DFS) {
                            $OutObj | Where-Object { $_.'Identical Count' -like 'No' } | Set-Style -Style Warning -Property 'Identical Count'
                        }

                        $TableParams = @{
                            Name = "Domain Last Backup - $($Domain.ToString().ToUpper())"
                            List = $false
                            ColumnWidths = 20, 16, 16, 16, 16, 16
                        }

                        if ($Report.ShowTableCaptions) {
                            $TableParams['Caption'] = "- $($TableParams.Name)"
                        }
                        $OutObj | Sort-Object -Property 'Naming Context' | Table @TableParams
                        Paragraph "Health Check:" -Italic -Bold -Underline
                        Paragraph "Corrective Actions: Ensure an identical GPO/SYSVOL content for the domain controller in all Active Directory domains." -Italic -Bold
                    }
                }
            }
            catch {
                Write-PscriboMessage -IsWarning "$($_.Exception.Message) (DFS Health Table)"
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
                    Section -Style Heading5 'Sysvol Folder Status' {
                        Paragraph "The following section details domain $($Domain.ToString().ToUpper()) sysvol health status."
                        BlankLine
                        $OutObj = @()
                        foreach ($Extension in $SYSVOLFolder) {
                            try {
                                Write-PscriboMessage "Collecting Sysvol information from $($Domain)."
                                $inObj = [ordered] @{
                                    'Extension' = $Extension.Extension
                                    'File Count' = $Extension.Count
                                    'Size' = "$($Extension.TotalSize) MB"
                                }
                                $OutObj += [pscustomobject]$inobj
                            }
                            catch {
                                Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Sysvol Health Item)"
                            }
                        }

                        if ($HealthCheck.Domain.DFS) {
                            $OutObj | Where-Object { $_.'Extension' -notin ('.bat','.exe','.nix','.vbs','.pol','.reg','.xml','.admx','.adml','.inf','.ini','.adm','.kix','.msi','.ps1','.cmd','.ico') } | Set-Style -Style Warning -Property 'Extension'
                        }

                        $TableParams = @{
                            Name = "Sysvol Folder Status - $($Domain.ToString().ToUpper())"
                            List = $false
                            ColumnWidths = 33, 33, 34
                        }

                        if ($Report.ShowTableCaptions) {
                            $TableParams['Caption'] = "- $($TableParams.Name)"
                        }
                        $OutObj | Sort-Object -Property 'Extension' | Table @TableParams
                        if ($OutObj | Where-Object { $_.'Extension' -notin ('.bat','.exe','.nix','.vbs','.pol','.reg','.xml','.admx','.adml','.inf','.ini','.adm','.kix','.msi','.ps1','.cmd','.ico')}) {
                            Paragraph "Health Check:" -Italic -Bold -Underline
                            Paragraph "Corrective Actions: Make sure Sysvol content has no malicious extensions or unnecessary content." -Italic -Bold
                        }
                    }
                }
            }
            catch {
                Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Sysvol Health Table)"
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
                    Section -Style Heading5 'Netlogon Folder Status' {
                        Paragraph "The following section details domain $($Domain.ToString().ToUpper()) netlogon health status."
                        BlankLine
                        $OutObj = @()
                        foreach ($Extension in $NetlogonFolder) {
                            try {
                                Write-PscriboMessage "Collecting Netlogon information from $($Domain)."
                                $inObj = [ordered] @{
                                    'Extension' = $Extension.Extension
                                    'File Count' = $Extension.Count
                                    'Size' = "$($Extension.TotalSize) MB"
                                }
                                $OutObj += [pscustomobject]$inobj
                            }
                            catch {
                                Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Netlogon Health Item)"
                            }
                        }

                        if ($HealthCheck.Domain.DFS) {
                            $OutObj | Where-Object { $_.'Extension' -notin ('.bat','.exe','.nix','.vbs','.pol','.reg','.xml','.admx','.adml','.inf','.ini','.adm','.kix','.msi','.ps1','.cmd','.ico') } | Set-Style -Style Warning -Property 'Extension'
                        }

                        $TableParams = @{
                            Name = "Netlogon Folder Status - $($Domain.ToString().ToUpper())"
                            List = $false
                            ColumnWidths = 33, 33, 34
                        }

                        if ($Report.ShowTableCaptions) {
                            $TableParams['Caption'] = "- $($TableParams.Name)"
                        }
                        $OutObj | Sort-Object -Property 'Extension' | Table @TableParams
                        if ($OutObj | Where-Object { $_.'Extension' -notin ('.bat','.exe','.nix','.vbs','.pol','.reg','.xml','.admx','.adml','.inf','.ini','.adm','.kix','.msi','.ps1','.cmd','.ico')}) {
                            Paragraph "Health Check:" -Italic -Bold -Underline
                            Paragraph "Corrective Actions: Make sure Netlogon content has no malicious extensions or unnecessary content." -Italic -Bold
                        }
                    }
                }
            }
            catch {
                Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Sysvol Health Table)"
            }
        }
    }

    end {}

}