function Get-AbrADCASubordinate {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft Active Directory Subordinate Certification Authority information.
    .DESCRIPTION

    .NOTES
        Version:        0.8.1
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
        Write-PScriboMessage "Collecting AD Certification Authority Per Domain information."
    }

    process {
        try {
            Write-PScriboMessage "Discovering Active Directory CA Enterprise Subordinate information in $($ForestInfo.toUpper())."
            if ($CAs | Where-Object { $_.IsRoot -like 'False' }) {
                Section -Style Heading2 "Enterprise Subordinate Certificate Authority" {
                    Paragraph "The following section provides the Enterprise Subordinate CA information."
                    BlankLine
                    $OutObj = @()
                    foreach ($CA in ($CAs | Where-Object { $_.IsRoot -like 'False' })) {
                        try {
                            Write-PScriboMessage "Collecting Enterprise Subordinate Certificate Authority information from $($CA.DisplayName)."
                            $inObj = [ordered] @{
                                'CA Name' = $CA.DisplayName
                                'Server Name' = $CA.ComputerName.ToString().ToUpper().Split(".")[0]
                                'Type' = $CA.Type
                                'Config String' = $CA.ConfigString
                                'Operating System' = $CA.OperatingSystem
                                'Certificate' = $CA.Certificate
                                'Auditing' = & {
                                    (Find-AuditingIssue -ADCSObjects (Get-ADCSObject $ForestInfo) | Where-Object { $_.Name -eq $CA.DisplayName }).Issue
                                }
                                'Status' = $CA.ServiceStatus
                            }
                            $OutObj = [pscustomobject]$inobj

                            if ($HealthCheck.CA.Status) {
                                $OutObj | Where-Object { $_.'Service Status' -notlike 'Running' } | Set-Style -Style Critical -Property 'Service Status'
                                $OutObj | Where-Object { $_.'Auditing' -notlike 'Running' } | Set-Style -Style Critical -Property 'Auditing'
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
                        } catch {
                            Write-PScriboMessage -IsWarning $_.Exception.Message
                        }
                    }
                }
            }
        } catch {
            Write-PScriboMessage -IsWarning $_.Exception.Message
        }
    }

    end {}

}