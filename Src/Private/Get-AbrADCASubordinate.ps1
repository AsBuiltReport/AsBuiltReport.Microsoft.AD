function Get-AbrADCAPerDomain {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft Active Directory Subordinate Certification Authority information.
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
            $Session,
            [string]
            $Server
    )

    begin {
        Write-PscriboMessage "Collecting AD Certification Authority Per Domain information."
    }

    process {
        $OutObj = @()
        if ($Domain) {
            foreach ($Item in $Domain) {
                Write-PscriboMessage "Discovering Active Directory Certification Authority information in $ForestInfo.toUpper()."
                $CAs =  Get-CertificationAuthority -Enterprise
                foreach ($CA in $CAs) {
                    Write-PscriboMessage "Discovered '$(($CAs | Measure-Object).Count)' Active Directory Certification Authority in domain $ForestInfo."
                    try {
                        Write-PscriboMessage "Collecting AD Certification Authority Summary information of $CA."
                        $inObj = [ordered] @{
                            'CA Name' = $CA.DisplayName
                            'Server Name' = $CA.ComputerName.ToString().ToUpper().Split(".")[0]
                            'Type' = $CA.Type
                            'Status' = $CA.ServiceStatus
                        }
                        $OutObj += [pscustomobject]$inobj
                    }
                    catch {
                        Write-PscriboMessage -IsWarning "Error: Connecting to remote server $CA failed: WinRM cannot complete the operation."
                        Write-PscriboMessage -IsDebug $_.Exception.Message
                    }
                }
            }

            if ($HealthCheck.CA.Status) {
                $OutObj | Where-Object { $_.'Service Status' -notlike 'Running'} | Set-Style -Style Critical -Property 'Service Status'
            }

            $TableParams = @{
                Name = "Certification Authority Summary Information - $($ForestInfo.ToString().ToUpper())"
                List = $false
                ColumnWidths = 33, 33, 22, 12
            }
            if ($Report.ShowTableCaptions) {
                $TableParams['Caption'] = "- $($TableParams.Name)"
            }
            $OutObj | Table @TableParams
        }
    }

    end {}

}