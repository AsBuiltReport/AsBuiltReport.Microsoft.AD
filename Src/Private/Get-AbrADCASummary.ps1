function Get-AbrADCASummary {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Certification Authority information.
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
    )

    begin {
        Write-PScriboMessage -Message "Collecting Certification Authority information."
    }

    process {
        $OutObj = @()
        if ($ForestInfo) {
            foreach ($CA in $CAs) {
                try {
                    $inObj = [ordered] @{
                        'CA Name' = $CA.DisplayName
                        'Server Name' = $CA.ComputerName.ToString().ToUpper().Split(".")[0]
                        'Type' = $CA.Type
                        'Status' = $CA.ServiceStatus
                    }
                    $OutObj += [pscustomobject](ConvertTo-HashToYN $inObj)
                } catch {
                    Write-PScriboMessage -IsWarning $_.Exception.Message
                }
            }

            if ($HealthCheck.CA.Status) {
                $OutObj | Where-Object { $_.'Service Status' -notlike 'Running' } | Set-Style -Style Critical -Property 'Service Status'
            }

            $TableParams = @{
                Name = "Certification Authority - $($ForestInfo.ToString().ToUpper())"
                List = $false
                ColumnWidths = 33, 33, 22, 12
            }
            if ($Report.ShowTableCaptions) {
                $TableParams['Caption'] = "- $($TableParams.Name)"
            }
            $OutObj  | Sort-Object -Property 'CA Name' | Table @TableParams
        }
    }

    end {}

}