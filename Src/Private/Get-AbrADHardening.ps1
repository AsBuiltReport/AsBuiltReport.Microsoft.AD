function Get-AbrADHardening {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Hardening information
    .DESCRIPTION

    .NOTES
        Version:        0.9.4
        Author:         Jonathan Colon
        Twitter:        @jcolonfzenpr
        Github:         rebelinux
    .EXAMPLE

    .LINK

    #>
    [CmdletBinding()]
    param (
        $Domain,
        [string]$ValidDcFromDomain
    )

    begin {
        Write-PScriboMessage "Collecting AD Hardening information from $($Domain.Name.toUpper())."
    }

    process {
        $DCPssSession = Get-ValidPSSession -ComputerName $ValidDcFromDomain -SessionName $($ValidDcFromDomain) -PSSTable ([ref]$PSSTable)

        $NTLMversion = Invoke-Command -Session $DCPssSession -ScriptBlock {
            $NTLMversion = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LmCompatibilityLevel' -ErrorAction SilentlyContinue
            if ($NTLMversion) {
                $NTLMversion = switch ($NTLMversion.LmCompatibilityLevel) {
                    0 { "Send LM & NTLM responses" }
                    1 { "Send LM & NTLM - use NTLMv2 session security if negotiated" }
                    2 { "Send NTLM response only" }
                    3 { "Send NTLMv2 response only" }
                    4 { "Send NTLMv2 response only\refuse LM" }
                    5 { "Send NTLMv2 response only\refuse LM & NTLM" }
                    default { "Unknown" }
                }
            } else {
                $NTLMversion = "Send NTLMv2 response only"
            }
            $NTLMversion
        }

        $SMBv1 = Invoke-Command -Session $DCPssSession -ScriptBlock {
            $SMBv1 = Get-SmbServerConfiguration -ErrorAction SilentlyContinue | Select-Object -ExpandProperty EnableSMB1Protocol
            if ($SMBv1) {
                $SMBv1 = switch ($SMBv1) {
                    'True' { "Installed\Enabled" }
                    'False' { "Uninstalled\Disabled" }
                    default { "Unknown" }
                }
            } else {
                $SMBv1 = "Removed"
            }
            $SMBv1
        }

        $SMBSigning = Invoke-Command -Session $DCPssSession -ScriptBlock {
            $SMBSigning = Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters' -Name 'requiresecuritysignature' -ErrorAction SilentlyContinue
            if ($SMBSigning.requiresecuritysignature) {
                $SMBSigning = switch ($SMBSigning.requiresecuritysignature) {
                    0 { "Disable" }
                    1 { "Enable" }
                    default { "Unknown" }
                }
            } else {
                $SMBSigning = "Not Configured/Disabled"
            }
            $SMBSigning
        }

        $LDAPSigning = Invoke-Command -Session $DCPssSession -ScriptBlock {
            $LDAPSigning = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name 'ldapserverintegrity' -ErrorAction SilentlyContinue
            if ($LDAPSigning.ldapserverintegrity) {
                $LDAPSigning = switch ($LDAPSigning.ldapserverintegrity) {
                    0 { "None" }
                    1 { "Require Signing" }
                    default { "Unknown" }
                }
            } else {
                $LDAPSigning = "None"
            }
            $LDAPSigning
        }

        $LDAPChannelBinding = Invoke-Command -Session $DCPssSession -ScriptBlock {
            $LDAPChannelBinding = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name 'LdapEnforceChannelBinding' -ErrorAction SilentlyContinue
            if ($LDAPChannelBinding.ldapserverintegrity) {
                $LDAPChannelBinding = switch ($LDAPChannelBinding.ldapserverintegrity) {
                    0 { "Never" }
                    1 { "When supported" }
                    2 { "Always" }
                    default { "Unknown" }
                }
            } else {
                $LDAPChannelBinding = "Not Configured/Disabled"
            }
            $LDAPChannelBinding
        }

        try {
            Section -Style Heading3 'Active Directory Hardening' {
                Paragraph "The following section provides a summary of the domain hardening configured in Active Directory."
                BlankLine
                $outObj = @()
                try {
                    $inObj = [ordered] @{
                        'NTLMv1 configuration' = $NTLMversion
                        'SMBv1 status' = $SMBv1
                        'Enforcing SMB Signing' = $SMBSigning
                        'Enforcing LDAP Signing' = $LDAPSigning
                        'Enforcing LDAP Channel Binding' = $LDAPChannelBinding
                    }
                    $outObj += [pscustomobject](ConvertTo-HashToYN $inObj)

                    if ($HealthCheck.Domain.BestPractice) {
                        $OutObj | Where-Object { $_.'NTLMv1 configuration' -in @('Send LM & NTLM responses', 'Send LM & NTLM - use NTLMv2 session security if negotiated', 'Send NTLM response only') } | Set-Style -Style Critical -Property 'NTLMv1 configuration'
                        $OutObj | Where-Object { $_.'SMBv1 status' -eq 'Installed\Enabled' } | Set-Style -Style Critical -Property 'SMBv1 status'
                        $OutObj | Where-Object { $_.'Enforcing SMB Signing' -in @('Not Configured/Disabled', 'Disable') } | Set-Style -Style Warning -Property 'Enforcing SMB Signing'
                        $OutObj | Where-Object { $_.'Enforcing LDAP Signing' -eq 'None' } | Set-Style -Style Warning -Property 'Enforcing LDAP Signing'
                        $OutObj | Where-Object { $_.'Enforcing LDAP Channel Binding' -in @('Never', 'Not Configured/Disabled') } | Set-Style -Style Warning -Property 'Enforcing LDAP Channel Binding'
                    }

                    $TableParams = @{
                        Name = "Active Directory Hardening - $($Domain.Name.toUpper())"
                        List = $true
                        ColumnWidths = 40, 60
                    }
                    if ($Report.ShowTableCaptions) {
                        $TableParams['Caption'] = "- $($TableParams.Name)"
                    }
                    $outObj | Table @TableParams
                    if ($HealthCheck.Domain.BestPractice -and (($OutObj | Where-Object { $_.'NTLMv1 configuration' -in @('Send LM & NTLM responses', 'Send LM & NTLM - use NTLMv2 session security if negotiated', 'Send NTLM response only') }) -or ($OutObj | Where-Object { $_.'SMBv1 status' -eq 'Installed\Enabled' }) -or ($OutObj | Where-Object { $_.'Enforcing SMB Signing' -in @('Not Configured/Disabled', 'Disable') }) -or ($OutObj | Where-Object { $_.'Enforcing LDAP Signing' -eq 'None' }) -or ($OutObj | Where-Object { $_.'Enforcing LDAP Channel Binding' -in @('Never', 'Not Configured/Disabled') }))) {
                        Paragraph "Health Check:" -Bold -Underline
                        BlankLine
                        if (($OutObj | Where-Object { $_.'Enforcing SMB Signing' -in @('Not Configured/Disabled', 'Disable') })) {
                            Paragraph {
                                Text "Best Practice:" -Bold
                                Text "Enforcing SMB Signing: SMB signing is a security feature that helps protect against man-in-the-middle attacks by ensuring the authenticity and integrity of SMB communications."
                            }
                            BlankLine
                        }
                        if (($OutObj | Where-Object { $_.'SMBv1 status' -eq 'Installed\Enabled' })) {
                            Paragraph {
                                Text "Best Practice:" -Bold
                                Text "SMBv1 status is enabled: SMBv1 is an outdated protocol that is vulnerable to several security issues. It is recommended to disable SMBv1 on all systems to enhance security and reduce the risk of exploitation. SMBv1 has been deprecated and replaced by SMBv2 and SMBv3, which offer improved security features."
                            }
                            BlankLine
                        }
                        if (($OutObj | Where-Object { $_.'Enforcing LDAP Signing' -eq 'None' })) {
                            Paragraph {
                                Text "Best Practice:" -Bold
                                Text "Enforcing LDAP Signing is not configured: LDAP signing is a security feature that helps protect the integrity and confidentiality of LDAP communications by requiring LDAP data signing."
                            }
                            BlankLine
                        }
                        if (($OutObj | Where-Object { $_.'Enforcing LDAP Channel Binding' -in @('Never', 'Not Configured/Disabled') })) {
                            Paragraph {
                                Text "Best Practice:" -Bold
                                Text "Enforcing LDAP Channel Binding is not configured: LDAP channel binding is a security feature that helps protect against man-in-the-middle attacks by ensuring the authenticity and integrity of LDAP communications."
                            }
                            BlankLine
                        }
                        if (($OutObj | Where-Object { $_.'NTLMv1 configuration' -in @('Send LM & NTLM responses', 'Send LM & NTLM - use NTLMv2 session security if negotiated', 'Send NTLM response only') })) {
                            Paragraph {
                                Text "Best Practice:" -Bold
                                Text "Disable NTLMv1: NTLMv1 is an outdated authentication protocol that is vulnerable to several security issues. It is recommended to disable NTLMv1 on all systems to enhance security and reduce the risk of exploitation. NTLMv1 has been deprecated and replaced by NTLMv2, which offers improved security features."
                            }
                            BlankLine
                        }
                    }
                } catch {
                    Write-PScriboMessage -IsWarning "$($_.Exception.Message) (ADHardening Item)"
                }
            }
        } catch {
            Write-PScriboMessage -IsWarning "$($_.Exception.Message) (ADHardening Section)"
        }
    }

    end {
    }

}