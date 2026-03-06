function Get-AbrADCASummary {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Certification Authority information.
    .DESCRIPTION

    .NOTES
        Version:        0.9.9
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
        Write-PScriboMessage -Message $reportTranslate.GetAbrADCASummary.Collecting
        Show-AbrDebugExecutionTime -Start -TitleMessage 'CA Summary'
    }

    process {
        $OutObj = [System.Collections.ArrayList]::new()
        if ($ForestInfo) {
            foreach ($CA in $CAs) {
                try {
                    $inObj = [ordered] @{
                        $reportTranslate.GetAbrADCASummary.CAName = $CA.DisplayName
                        $reportTranslate.GetAbrADCASummary.ServerName = $CA.ComputerName.ToString().ToUpper().Split('.')[0]
                        $reportTranslate.GetAbrADCASummary.Type = $CA.Type
                        $reportTranslate.GetAbrADCASummary.Status = $CA.ServiceStatus
                    }
                    $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                } catch {
                    Write-PScriboMessage -IsWarning $_.Exception.Message
                }
            }

            if ($HealthCheck.CA.Status) {
                $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADCASummary.Status) -notlike 'Running' } | Set-Style -Style Critical -Property $reportTranslate.GetAbrADCASummary.Status
            }

            $TableParams = @{
                Name = "$($reportTranslate.GetAbrADCASummary.TableName) - $($ForestInfo.ToString().ToUpper())"
                List = $false
                ColumnWidths = 33, 33, 22, 12
            }
            if ($Report.ShowTableCaptions) {
                $TableParams['Caption'] = "- $($TableParams.Name)"
            }
            $OutObj | Sort-Object -Property $reportTranslate.GetAbrADCASummary.CAName | Table @TableParams
        }
    }

    end {
        Show-AbrDebugExecutionTime -End -TitleMessage 'CA Summary'
    }

}
