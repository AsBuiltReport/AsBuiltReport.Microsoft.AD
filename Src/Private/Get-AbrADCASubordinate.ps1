function Get-AbrADCASubordinate {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft Active Directory Subordinate Certification Authority information.
    .DESCRIPTION

    .NOTES
        Version:        0.9.11
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
        Write-PScriboMessage -Message 'Collecting AD Certification Authority Per Domain information.'
        Show-AbrDebugExecutionTime -Start -TitleMessage 'CA Subordinate'
    }

    process {
        try {
            if ($CAs | Where-Object { $_.IsRoot -like 'False' }) {
                Section -Style Heading2 'Enterprise Subordinate Certificate Authority' {
                    Paragraph 'The following section provides detailed information about Enterprise Subordinate Certification Authorities within the domain.'
                    BlankLine
                    foreach ($CA in ($CAs | Where-Object { $_.IsRoot -like 'False' })) {
                        if (Get-DCWinRMState -ComputerName $CA.ComputerName -DCStatus ([ref]$DCStatus)) {
                            $DCPssSession = Get-ValidPSSession -ComputerName $CA.ComputerName -SessionName $($CA.ComputerName) -PSSTable ([ref]$PSSTable)
                            if ($DCPssSession) {
                                $OutObj = [System.Collections.ArrayList]::new()
                                try {
                                    $AuditingIssue = Invoke-CommandWithTimeout -Session $DCPssSession -ScriptBlock {
                                        Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\$($using:CA.DisplayName)\" -Name 'AuditFilter'
                                    }
                                    $inObj = [ordered] @{
                                        'CA Name' = $CA.DisplayName
                                        'Server Name' = $CA.ComputerName.ToString().ToUpper().Split('.')[0]
                                        'Type' = $CA.Type
                                        'Config String' = $CA.ConfigString
                                        'Operating System' = $CA.OperatingSystem
                                        'Certificate' = $CA.Certificate
                                        'Auditing' = switch ($AuditingIssue) {
                                            $Null { 'Not Configured' }
                                            1 { 'Start and stop Active Directory® Certificate Services (1)' }
                                            2 { 'Back up and restore the CA database (2)' }
                                            4 { 'Issue and manage certificate requests (4)' }
                                            8 { 'Revoke certificates and publish CRLs (8)' }
                                            16 { 'Change CA security settings (16)' }
                                            32 { 'Change CA security settings (32)' }
                                            64 { 'Change CA configuration (64)' }
                                            127 { 'Auditing is fully enabled (127)' }
                                            default { 'Unknown' }
                                        }
                                        'Status' = $CA.ServiceStatus
                                    }
                                    $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null

                                    if ($HealthCheck.CA.Status) {
                                        $OutObj | Where-Object { $_.'Service Status' -notlike 'Running' } | Set-Style -Style Critical -Property 'Service Status'
                                        $OutObj | Where-Object { $_.'Auditing' -notlike 'Auditing is fully enabled (127)' } | Set-Style -Style Critical -Property 'Auditing'
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
                                    if ( $OutObj | Where-Object { $_.'Auditing' -notlike 'Auditing is fully enabled (127)' } ) {
                                        Paragraph 'Health Check:' -Bold -Underline
                                        BlankLine
                                        Paragraph {
                                            Text 'Secutiry Best Practice:' -Bold
                                            Text 'Auditing should be fully enabled for the Certification Authority to ensure that all relevant events are logged for security monitoring and incident response purposes. This includes events related to certificate issuance, revocation, and changes to CA configuration.'
                                        }
                                    }
                                } catch {
                                    Write-PScriboMessage -IsWarning $_.Exception.Message
                                }
                            }
                        }
                    }
                }
            }
        } catch {
            Write-PScriboMessage -IsWarning $_.Exception.Message
        }
    }

    end {
        Show-AbrDebugExecutionTime -End -TitleMessage 'CA Subordinate'
    }

}