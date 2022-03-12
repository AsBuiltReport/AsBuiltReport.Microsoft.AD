function Get-AbrADDomainLastBackup {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Domain last backup information.
    .DESCRIPTION

    .NOTES
        Version:        0.7.0
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
        Write-PscriboMessage "Discovering AD Domain last backup information on $Domain."
    }

    process {
        if ($Domain) {
            try {
                $LastBackups =  Get-WinADLastBackup -Domain $Domain
                Write-PscriboMessage "Discovered last taken backup information of domain $Domain."
                if ($LastBackups) {
                    Section -Style Heading4 'Domain Naming Context Last Backup' {
                        Paragraph "The following section details naming context last backup time for Domain $($Domain.ToString().ToUpper())."
                        BlankLine
                        $OutObj = @()
                        foreach ($LastBackup in $LastBackups) {
                            Write-PscriboMessage "Collecting Domain information of $($Domain)."
                            $inObj = [ordered] @{
                                'Naming Context' = $LastBackup.NamingContext
                                'Last Backup' = $LastBackup.LastBackup.ToString("yyyy:MM:dd")
                                'Last Backup in Days' = $LastBackup.LastBackupDaysAgo
                            }
                            $OutObj += [pscustomobject]$inobj
                        }

                        $TableParams = @{
                            Name = "Domain Last Backup - $($Domain.ToString().ToUpper())"
                            List = $false
                            ColumnWidths = 60, 20, 20
                        }

                        if ($Report.ShowTableCaptions) {
                            $TableParams['Caption'] = "- $($TableParams.Name)"
                        }
                        $OutObj | Sort-Object -Property 'Naming Context' | Table @TableParams
                    }
                }
            }
            catch {
                Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Domain Last Backup)"
            }
        }
    }

    end {}

}