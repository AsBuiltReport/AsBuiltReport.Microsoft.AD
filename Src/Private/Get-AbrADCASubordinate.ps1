function Get-AbrADCASubordinate {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft Active Directory Subordinate Certification Authority information.
    .DESCRIPTION

    .NOTES
        Version:        0.7.9
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
        Write-PscriboMessage "Collecting AD Certification Authority Per Domain information."
    }

    process {
        try {
            Write-PscriboMessage "Discovering Active Directory Certification Authority information in $($ForestInfo.toUpper())."
            if ($CAs | Where-Object {$_.IsRoot -like 'False'}) {
                Write-PscriboMessage "Discovered '$(($CAs | Measure-Object).Count)' Active Directory Certification Authority in domain $ForestInfo."
                Section -Style Heading3 "Enterprise Subordinate Certificate Authority" {
                    Paragraph "The following section provides the Enterprise Subordinate CA information."
                    BlankLine
                    $OutObj = @()
                    foreach ($CA in ($CAs | Where-Object {$_.IsRoot -like 'False'})) {
                        try {
                            Write-PscriboMessage "Collecting Enterprise Subordinate Certificate Authority information from $($CA.DisplayName)."
                            $inObj = [ordered] @{
                                'CA Name' = $CA.DisplayName
                                'Server Name' = $CA.ComputerName.ToString().ToUpper().Split(".")[0]
                                'Type' = $CA.Type
                                'Config String' = $CA.ConfigString
                                'Operating System' = $CA.OperatingSystem
                                'Certificate' = $CA.Certificate
                                'Status' = $CA.ServiceStatus
                            }
                            $OutObj = [pscustomobject]$inobj

                            if ($HealthCheck.CA.Status) {
                                $OutObj | Where-Object { $_.'Service Status' -notlike 'Running'} | Set-Style -Style Critical -Property 'Service Status'
                            }

                            $TableParams = @{
                                Name = "Enterprise Subordinate CA - $($CA.DisplayName)"
                                List = $true
                                ColumnWidths = 40, 60
                            }
                            if ($Report.ShowTableCaptions) {
                                $TableParams['Caption'] = "- $($TableParams.Name)"
                            }
                            $OutObj | Table @TableParams
                        }
                        catch {
                            Write-PscriboMessage -IsWarning $_.Exception.Message
                        }
                    }
                }
            }
        }
        catch {
            Write-PscriboMessage -IsWarning $_.Exception.Message
        }
    }

    end {}

}