function Get-AbrADCARoot {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft Active Directory Root Certification Authority information.
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
        Write-PScriboMessage -Message "Collecting AD Certification Authority Per Domain information."
        Show-AbrDebugExecutionTime -Start -TitleMessage "AD Certification Authority Per Domain"
    }

    process {
        try {
            if ($CAs | Where-Object { $_.IsRoot -like 'True' }) {
                Section -Style Heading2 "Enterprise Root Certificate Authority" {
                    Paragraph "The following section provides the Enterprise Root CA information."
                    BlankLine
                    $OutObj = @()
                    foreach ($CA in ($CAs | Where-Object { $_.IsRoot -like 'True' })) {
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
                        $OutObj = [pscustomobject](ConvertTo-HashToYN $inObj)

                        if ($HealthCheck.CA.Status) {
                            $OutObj | Where-Object { $_.'Service Status' -notlike 'Running' } | Set-Style -Style Critical -Property 'Service Status'
                            $OutObj | Where-Object { $_.'Auditing' -notlike 'Running' } | Set-Style -Style Critical -Property 'Auditing'
                        }

                        $TableParams = @{
                            Name = "Enterprise Root CA - $($ForestInfo.ToString().ToUpper())"
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
        } catch {
            Write-PScriboMessage -IsWarning $_.Exception.Message
        }
    }

    end {
        Show-AbrDebugExecutionTime -End -TitleMessage "AD Certification Authority Per Domain"
    }

}