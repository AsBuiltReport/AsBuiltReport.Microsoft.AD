function Get-AbrADExchange {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Exchange information
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
    )

    begin {
        Write-PScriboMessage -Message ($reportTranslate.GetAbrADExchange.Collecting -f $ForestInfo.toUpper())
        Show-AbrDebugExecutionTime -Start -TitleMessage 'AD Exchange Infrastructure'
    }

    process {
        $EXServers = try { Get-ADExchangeServer } catch { $null }
        try {
            if ($EXServers ) {
                Section -Style Heading3 $reportTranslate.GetAbrADExchange.Heading {
                    Paragraph $reportTranslate.GetAbrADExchange.Paragraph
                    BlankLine
                    $EXInfo = [System.Collections.Generic.List[object]]::new()
                    foreach ($EXServer in $EXServers) {
                        try {
                            $inObj = [ordered] @{
                                $reportTranslate.GetAbrADExchange.Name = $EXServer.Name
                                $reportTranslate.GetAbrADExchange.DnsName = $EXServer.DnsHostName
                                $reportTranslate.GetAbrADExchange.ServerRoles = $EXServer.ServerRoles -join ', '
                                $reportTranslate.GetAbrADExchange.Version = $EXServer.Version
                            }
                            $EXInfo.Add([pscustomobject](ConvertTo-HashToYN $inObj))
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Exchange Item)"
                        }
                    }

                    if ($InfoLevel.Forest -ge 2) {
                        foreach ($EXServer in $EXInfo) {
                            Section -Style NOTOCHeading4 -ExcludeFromTOC "$($EXServer.$($reportTranslate.GetAbrADExchange.Name))" {
                                $TableParams = @{
                                    Name = "$($reportTranslate.GetAbrADExchange.Heading) - $($EXServer.$($reportTranslate.GetAbrADExchange.Name))"
                                    List = $true
                                    ColumnWidths = 40, 60
                                }
                                if ($Report.ShowTableCaptions) {
                                    $TableParams['Caption'] = "- $($TableParams.Name)"
                                }
                                $EXServer | Table @TableParams
                            }
                        }
                    } else {
                        $TableParams = @{
                            Name = "$($reportTranslate.GetAbrADExchange.Heading) - $($ForestInfo.toUpper())"
                            List = $false
                            Columns = $reportTranslate.GetAbrADExchange.Name, $reportTranslate.GetAbrADExchange.DnsName, $reportTranslate.GetAbrADExchange.ServerRoles, $reportTranslate.GetAbrADExchange.Version
                            ColumnWidths = 25, 25, 25, 25
                        }
                        if ($Report.ShowTableCaptions) {
                            $TableParams['Caption'] = "- $($TableParams.Name)"
                        }
                        $EXInfo | Table @TableParams
                    }
                }
            } else {
                Write-PScriboMessage -Message "No Exchange Infrastructure information found in $($ForestInfo.toUpper()), Disabling this section."
                Paragraph $reportTranslate.GetAbrADExchange.NotFound
                BlankLine
            }
        } catch {
            Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Exchabge Table)"
        }
    }

    end {
        Show-AbrDebugExecutionTime -End -TitleMessage 'AD Exchange Infrastructure'
    }

}
