function Get-AbrADSiteReplication {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Domain Sites Replication information.
    .DESCRIPTION

    .NOTES
        Version:        0.7.14
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
        Write-PscriboMessage "Collecting AD Domain Sites Replication information."
    }

    process {
        Write-PscriboMessage "Collecting AD Domain Sites Replication Summary. (Sites Replication Connection)"
        $DCs = Invoke-Command -Session $TempPssSession -ScriptBlock {Get-ADDomain -Identity $using:Domain | Select-Object -ExpandProperty ReplicaDirectoryServers}
        if ($DCs) {
            Write-PscriboMessage "Discovering Active Directory Sites Replication information on $Domain. (Sites Replication)"
            try {
                $ReplInfo = @()
                foreach ($DC in $DCs) {
                    if (Test-Connection -ComputerName $DC -Quiet -Count 2) {
                        $Replication = Invoke-Command -Session $TempPssSession -ScriptBlock {Get-ADReplicationConnection -Server $using:DC -Properties *}
                        if ($Replication) {
                            try {
                                Write-PscriboMessage "Collecting Active Directory Sites Replication information on $DC. (Sites Replication Connection)"
                                foreach ($Repl in $Replication) {
                                    try {
                                        $inObj = [ordered] @{
                                            'Name' = &{
                                                if ($Repl.AutoGenerated) {
                                                    "<automatically generated>"
                                                } else {
                                                    $Repl.Name
                                                }
                                            }
                                            'From Site' = $Repl.fromserver.Split(",")[3].SubString($Repl.fromserver.Split(",")[3].IndexOf("=")+1)
                                            'GUID' = $Repl.ObjectGUID
                                            'Description' = ConvertTo-EmptyToFiller $Repl.Description
                                            'From Server' = ConvertTo-ADObjectName $Repl.ReplicateFromDirectoryServer.Split(",", 2)[1] -Session $TempPssSession -DC $DC
                                            'To Server' = ConvertTo-ADObjectName $Repl.ReplicateToDirectoryServer -Session $TempPssSession -DC $DC
                                            'Replicated Naming Contexts' = $Repl.ReplicatedNamingContexts
                                            'Transport Protocol' = $Repl.InterSiteTransportProtocol
                                            'Auto Generated' =  ConvertTo-TextYN $Repl.AutoGenerated
                                            'Enabled' =  ConvertTo-TextYN $Repl.enabledConnection
                                            'Created' = ($Repl.Created).ToUniversalTime().toString("r")
                                        }
                                        $ReplInfo += [pscustomobject]$inobj

                                        if ($HealthCheck.Site.Replication) {
                                            $ReplInfo | Where-Object { $_.'Enabled' -ne 'Yes'} | Set-Style -Style Warning -Property 'Enabled'
                                            $ReplInfo | Where-Object { $_.'Auto Generated' -ne 'Yes'} | Set-Style -Style Warning -Property 'Auto Generated'
                                        }
                                    }
                                    catch {
                                        Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Site Replication Connection Item)"
                                    }
                                }
                            }
                            catch {
                                Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Site Replication Connection Section)"
                            }
                        }
                    }
                }
                if ($ReplInfo) {
                    if ($InfoLevel.Domain -ge 2) {
                        Section -Style Heading5 'Replication Connection' {
                            Paragraph "The following section provides detailed information about Replication Connection."
                            BlankLine
                            foreach ($Repl in ($ReplInfo | Sort-Object -Property 'Replicate From Directory Server')) {
                                Section -Style NOTOCHeading5 -ExcludeFromTOC "Site: $($Repl.'From Site'): From: $($Repl.'From Server') To: $($Repl.'To Server')" {
                                    $TableParams = @{
                                        Name = "Replication Connection - $($Repl.'To Server')"
                                        List = $true
                                        ColumnWidths = 40, 60
                                    }
                                    if ($Report.ShowTableCaptions) {
                                        $TableParams['Caption'] = "- $($TableParams.Name)"
                                    }
                                    $Repl | Table @TableParams
                                }
                            }
                        }
                    } else {
                        Section -Style Heading5 'Replication Connection' {
                            Paragraph "The following section provide connection objects to source server ."
                            BlankLine
                            $TableParams = @{
                                Name = "Replication Connection - $($Domain.ToString().ToUpper())"
                                List = $false
                                Columns = 'Name', 'From Server', 'From Site'
                                ColumnWidths = 33, 33, 34
                            }
                            if ($Report.ShowTableCaptions) {
                                $TableParams['Caption'] = "- $($TableParams.Name)"
                            }
                            $ReplInfo | Sort-Object -Property 'Replicate From Directory Server' | Table @TableParams
                        }
                    }
                }
            }
            catch {
                Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Replication Connection)"
            }
        }
        try {
            if ($HealthCheck.Site.Replication) {
                Write-PscriboMessage "Discovering Active Directory Replication Status on $Domain. (Replication Status)"
                $DC = Invoke-Command -Session $TempPssSession {(Get-ADDomain -Identity $using:Domain).ReplicaDirectoryServers | Select-Object -First 1}
                $DCPssSession = New-PSSession $DC -Credential $Credential -Authentication $Options.PSDefaultAuthentication
                Write-PscriboMessage "Discovered Active Directory Replication Status on $Domain. (Replication Status)"
                $RepStatus =  Invoke-Command -Session $DCPssSession -ScriptBlock {repadmin /showrepl /repsto /csv | ConvertFrom-Csv}
                if ($RepStatus) {
                    Section -Style Heading5 'Replication Status' {
                        $OutObj = @()
                        Write-PscriboMessage "Collecting Active Directory Replication Status from $($Domain). (Replication Status)"
                        foreach ($Status in $RepStatus) {
                            try {
                                $inObj = [ordered] @{
                                    'From Server' = $Status.'Source DSA'
                                    'To Server' = $Status.'Destination DSA'
                                    'From Site' = $Status.'Source DSA Site'
                                    'Last Success Time' =  $Status.'Last Success Time'
                                    'Last Failure Status' = $Status.'Last Failure Status'
                                    'Last Failure Time' = $Status.'Last Failure Time'
                                    'Failures' = $Status.'Number of Failures'
                                }
                                $OutObj += [pscustomobject]$inobj

                            }
                            catch {
                                Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Replication Status)"
                            }
                        }
                        if ($HealthCheck.Site.Replication) {
                            $OutObj | Where-Object {$_.'Last Failure Status' -gt 0} | Set-Style -Style Warning -Property 'Last Failure Status'
                        }

                        $TableParams = @{
                            Name = "Replication Status - $($Domain.ToUpper())"
                            List = $false
                            ColumnWidths = 14, 14, 14, 15, 14, 15 ,14
                        }
                        if ($Report.ShowTableCaptions) {
                            $TableParams['Caption'] = "- $($TableParams.Name)"
                        }
                        $OutObj| Sort-Object -Property 'Source DSA' | Table @TableParams
                        if ($HealthCheck.Site.Replication -and ($OutObj | Where-Object {$_.'Last Failure Status' -gt 0})) {
                            Paragraph "Health Check:" -Bold -Underline
                            BlankLine
                            Paragraph {
                                Text "Best Practices:" -Bold
                                Text "Replication failure can lead to object inconsistencies and major problems in Active Directory."
                            }
                            BlankLine
                        }
                    }
                }
                if ($DCPssSession) {
                    Remove-PSSession -Session $DCPssSession
                }
            }
        }
        catch {
            Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Site Replication Status)"
        }
    }

    end {}

}