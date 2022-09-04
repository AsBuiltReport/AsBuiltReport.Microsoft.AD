function Get-AbrADCASummary {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Certification Authority information.
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
    )

    begin {
        Write-PscriboMessage "Collecting Certification Authority information."
    }

    process {
        $OutObj = @()
        if ($ForestInfo) {
            Write-PscriboMessage "Discovering Active Directory Certification Authority information in $($ForestInfo.toUpper())."
            $CAs =  Get-CertificationAuthority -Enterprise
            foreach ($CA in $CAs) {
                Write-PscriboMessage "Discovered '$(($CAs | Measure-Object).Count)' Active Directory Certification Authority in domain $ForestInfo."
                try {
                    Write-PscriboMessage "Collecting AD Certification Authority Summary information of $($CA.DisplayName)."
                    $inObj = [ordered] @{
                        'CA Name' = $CA.DisplayName
                        'Server Name' = $CA.ComputerName.ToString().ToUpper().Split(".")[0]
                        'Type' = $CA.Type
                        'Status' = $CA.ServiceStatus
                    }
                    $OutObj += [pscustomobject]$inobj
                }
                catch {
                    Write-PscriboMessage -IsWarning $_.Exception.Message
                }
            }

            if ($HealthCheck.CA.Status) {
                $OutObj | Where-Object { $_.'Service Status' -notlike 'Running'} | Set-Style -Style Critical -Property 'Service Status'
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