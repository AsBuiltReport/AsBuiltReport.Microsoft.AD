function Get-AbrADSiteReplication {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Domain Sites Replication information.
    .DESCRIPTION

    .NOTES
        Version:        0.4.0
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
            $Session
    )

    begin {
        Write-PscriboMessage "Collecting AD Domain Sites Replication information."
    }

    process {
        Write-PscriboMessage "Collecting AD Domain Sites Replication Summary. (Sites Replication)"
        Section -Style Heading5 'Sites Replication' {
            Paragraph "The following section provides a summary of the Active Directory Site Replication information."
            BlankLine
            $OutObj = @()
            if ($Domain) {
                Write-PscriboMessage "Discovering Active Directory Sites Replication information on $Domain. (Sites Replication)"
                foreach ($Item in $Domain) {
                    try {
                        # TODO Why is this working? only God knows! (Investigate)
                        $DCs = Invoke-Command -Session $Session -ScriptBlock {Get-ADDomain -Identity $using:Item | Select-Object -ExpandProperty ReplicaDirectoryServers}
                        foreach ($DC in $DCs) {
                            $Replication = Invoke-Command -Session $Session -ScriptBlock {Get-ADReplicationConnection -Server $using:DC -Properties *}
                            if ($Replication) {Write-PscriboMessage "Collecting Active Directory Sites Replication information on $DC. (Sites Replication)"}
                            foreach ($Repl in $Replication) {
                                $inObj = [ordered] @{
                                    'DC Name' = $DC.ToString().ToUpper().Split(".")[0]
                                    'GUID' = $Repl.ObjectGUID
                                    'Description' = ConvertTo-EmptyToFiller $Repl.Description
                                    'Replicate From Directory Server' = ConvertTo-ADObjectName $Repl.ReplicateFromDirectoryServer.Split(",", 2)[1] -Session $Session
                                    'Replicate To Directory Server' = ConvertTo-ADObjectName $Repl.ReplicateToDirectoryServer -Session $Session
                                    'Replicated Naming Contexts' = $Repl.ReplicatedNamingContexts
                                    'Transport Protocol' = $Repl.InterSiteTransportProtocol
                                    'AutoGenerated' =  ConvertTo-TextYN $Repl.AutoGenerated
                                    'Enabled' =  ConvertTo-TextYN $Repl.enabledConnection
                                    'Created' = ($Repl.Created).ToUniversalTime().toString("r")
                                }
                            }
                            $OutObj += [pscustomobject]$inobj
                        }
                    }
                    catch {
                        Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Site Replication)"
                    }
                }

                if ($HealthCheck.Site.Replication) {
                    $OutObj | Where-Object { $_.'Enabled' -ne 'Yes'} | Set-Style -Style Warning -Property 'Enabled'
                }

                $TableParams = @{
                    Name = "Site Replication Information - $($Domain.ToString().ToUpper())"
                    List = $true
                    ColumnWidths = 40, 60
                }
                if ($Report.ShowTableCaptions) {
                    $TableParams['Caption'] = "- $($TableParams.Name)"
                }
                $OutObj | Table @TableParams
            }
        }
        if (($HealthCheck.Site.Replication) -and (Invoke-Command -Session $Session -ScriptBlock {Get-ADReplicationFailure -Target $using:Domain -Scope Domain})) {
            Write-PscriboMessage "Discovering Active Directory Sites Replication Failure on $Domain. (Sites Replication Failure)"
            Section -Style Heading5 'Sites Replication Failure' {
                Paragraph "The following section provides a summary of the Active Directory Site Replication Failure information."
                BlankLine
                $OutObj = @()
                foreach ($Item in $Domain) {
                    try {
                        Write-PscriboMessage "Discovered Active Directory Sites Replication Failure on $Item. (Sites Replication Failure)"
                        $Failures =  Invoke-Command -Session $Session -ScriptBlock {Get-ADReplicationFailure -Target $using:Domain -Scope Domain}
                        foreach ($Fails in $Failures) {
                            Write-PscriboMessage "Collecting Active Directory Sites Replication Failure on '$($Fails.Server)'. (Sites Replication Failure)"
                                $inObj = [ordered] @{
                                    'Server Name' = $Fails.Server.Split(".", 2)[0]
                                    'Partner' =  ConvertTo-ADObjectName $Fails.Partner.Split(",", 2)[1] -Session $Session
                                    'Last Error' = $Fails.LastError
                                    'Failure Type' =  $Fails.FailureType
                                    'Failure Count' = $Fails.FailureCount
                                    'First Failure Time' = ($Fails.FirstFailureTime).ToUniversalTime().toString("r")
                                }
                            $OutObj += [pscustomobject]$inobj
                        }
                    }
                    catch {
                        Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Site Replication Failure)"
                    }
                }

                if ($HealthCheck.Site.Replication) {
                    $OutObj | Where-Object {$NULL -notlike $_.'Last Error'} | Set-Style -Style Warning -Property 'Last Error', 'Failure Type', 'Failure Count', 'First Failure Time'
                }

                $TableParams = @{
                    Name = "Site Replication Failure Information - $($Domain.ToString().ToUpper())"
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