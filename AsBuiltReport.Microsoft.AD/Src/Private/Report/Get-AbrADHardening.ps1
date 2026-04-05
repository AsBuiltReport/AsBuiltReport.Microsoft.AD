function Get-AbrADHardening {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Hardening information
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
        $Domain,
        [string]$ValidDcFromDomain
    )

    begin {
        Write-PScriboMessage -Message ($reportTranslate.GetAbrADHardening.Collecting -f $Domain.Name.toUpper())
        Show-AbrDebugExecutionTime -Start -TitleMessage 'AD Hardening'
    }

    process {
        $DCPssSession = Get-ValidPSSession -ComputerName $ValidDcFromDomain -SessionName $($ValidDcFromDomain) -PSSTable ([ref]$PSSTable)

        $NTLMversion = Invoke-CommandWithTimeout -Session $DCPssSession -ScriptBlock {
            $NTLMversion = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LmCompatibilityLevel' -ErrorAction SilentlyContinue
            if ($NTLMversion) {
                $NTLMversion = switch ($NTLMversion.LmCompatibilityLevel) {
                    0 { 'Send LM & NTLM responses' }
                    1 { 'Send LM & NTLM - use NTLMv2 session security if negotiated' }
                    2 { 'Send NTLM response only' }
                    3 { 'Send NTLMv2 response only' }
                    4 { 'Send NTLMv2 response only\refuse LM' }
                    5 { 'Send NTLMv2 response only\refuse LM & NTLM' }
                    default { 'Unknown' }
                }
            } else {
                $NTLMversion = 'Send NTLMv2 response only'
            }
            $NTLMversion
        }

        $SMBv1 = Invoke-CommandWithTimeout -Session $DCPssSession -ScriptBlock {
            $SMBv1 = Get-SmbServerConfiguration -ErrorAction SilentlyContinue | Select-Object -ExpandProperty EnableSMB1Protocol
            if ($SMBv1) {
                $SMBv1 = switch ($SMBv1) {
                    'True' { 'Installed\Enabled' }
                    'False' { 'Uninstalled\Disabled' }
                    default { 'Unknown' }
                }
            } else {
                $SMBv1 = 'Removed'
            }
            $SMBv1
        }

        $SMBSigning = Invoke-CommandWithTimeout -Session $DCPssSession -ScriptBlock {
            $SMBSigning = Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters' -Name 'requiresecuritysignature' -ErrorAction SilentlyContinue
            if ($SMBSigning.requiresecuritysignature) {
                $SMBSigning = switch ($SMBSigning.requiresecuritysignature) {
                    0 { 'Disable' }
                    1 { 'Enable' }
                    default { 'Unknown' }
                }
            } else {
                $SMBSigning = 'Not Configured/Disabled'
            }
            $SMBSigning
        }

        $LDAPSigning = Invoke-CommandWithTimeout -Session $DCPssSession -ScriptBlock {
            $LDAPSigning = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name 'ldapserverintegrity' -ErrorAction SilentlyContinue
            if ($LDAPSigning.ldapserverintegrity) {
                $LDAPSigning = switch ($LDAPSigning.ldapserverintegrity) {
                    0 { 'None' }
                    1 { 'Require Signing' }
                    default { 'Unknown' }
                }
            } else {
                $LDAPSigning = 'None'
            }
            $LDAPSigning
        }

        $LDAPChannelBinding = Invoke-CommandWithTimeout -Session $DCPssSession -ScriptBlock {
            $LDAPChannelBinding = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name 'LdapEnforceChannelBinding' -ErrorAction SilentlyContinue
            if ($LDAPChannelBinding.ldapserverintegrity) {
                $LDAPChannelBinding = switch ($LDAPChannelBinding.ldapserverintegrity) {
                    0 { 'Never' }
                    1 { 'When supported' }
                    2 { 'Always' }
                    default { 'Unknown' }
                }
            } else {
                $LDAPChannelBinding = 'Not Configured/Disabled'
            }
            $LDAPChannelBinding
        }

        try {
            Section -Style Heading3 $reportTranslate.GetAbrADHardening.SectionTitle {
                Paragraph $reportTranslate.GetAbrADHardening.SectionParagraph
                BlankLine
                $OutObj = [System.Collections.Generic.List[object]]::new()
                try {
                    $inObj = [ordered] @{
                        $reportTranslate.GetAbrADHardening.NTLMv1Config = $NTLMversion
                        $reportTranslate.GetAbrADHardening.SMBv1Status = $SMBv1
                        $reportTranslate.GetAbrADHardening.EnforcingSMBSigning = $SMBSigning
                        $reportTranslate.GetAbrADHardening.EnforcingLDAPSigning = $LDAPSigning
                        $reportTranslate.GetAbrADHardening.EnforcingLDAPChannelBinding = $LDAPChannelBinding
                    }
                    $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj))

                    if ($HealthCheck.Domain.BestPractice) {
                        $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADHardening.NTLMv1Config) -in @('Send LM & NTLM responses', 'Send LM & NTLM - use NTLMv2 session security if negotiated', 'Send NTLM response only') } | Set-Style -Style Critical -Property $reportTranslate.GetAbrADHardening.NTLMv1Config
                        $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADHardening.SMBv1Status) -eq 'Installed\Enabled' } | Set-Style -Style Critical -Property $reportTranslate.GetAbrADHardening.SMBv1Status
                        $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADHardening.EnforcingSMBSigning) -in @('Not Configured/Disabled', 'Disable') } | Set-Style -Style Warning -Property $reportTranslate.GetAbrADHardening.EnforcingSMBSigning
                        $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADHardening.EnforcingLDAPSigning) -eq 'None' } | Set-Style -Style Warning -Property $reportTranslate.GetAbrADHardening.EnforcingLDAPSigning
                        $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADHardening.EnforcingLDAPChannelBinding) -in @('Never', 'Not Configured/Disabled') } | Set-Style -Style Warning -Property $reportTranslate.GetAbrADHardening.EnforcingLDAPChannelBinding
                    }

                    $TableParams = @{
                        Name = "$($reportTranslate.GetAbrADHardening.SectionTitle) - $($Domain.DNSRoot.toUpper())"
                        List = $true
                        ColumnWidths = 40, 60
                    }
                    if ($Report.ShowTableCaptions) {
                        $TableParams['Caption'] = "- $($TableParams.Name)"
                    }
                    $outObj | Table @TableParams
                    if ($HealthCheck.Domain.BestPractice -and (($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADHardening.NTLMv1Config) -in @('Send LM & NTLM responses', 'Send LM & NTLM - use NTLMv2 session security if negotiated', 'Send NTLM response only') }) -or ($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADHardening.SMBv1Status) -eq 'Installed\Enabled' }) -or ($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADHardening.EnforcingSMBSigning) -in @('Not Configured/Disabled', 'Disable') }) -or ($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADHardening.EnforcingLDAPSigning) -eq 'None' }) -or ($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADHardening.EnforcingLDAPChannelBinding) -in @('Never', 'Not Configured/Disabled') }))) {
                        Paragraph $reportTranslate.GetAbrADHardening.HealthCheck -Bold -Underline
                        BlankLine
                        if (($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADHardening.EnforcingSMBSigning) -in @('Not Configured/Disabled', 'Disable') })) {
                            Paragraph {
                                Text $reportTranslate.GetAbrADHardening.BestPractice -Bold
                                Text $reportTranslate.GetAbrADHardening.SMBSigningBP
                            }
                            BlankLine
                        }
                        if (($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADHardening.SMBv1Status) -eq 'Installed\Enabled' })) {
                            Paragraph {
                                Text $reportTranslate.GetAbrADHardening.BestPractice -Bold
                                Text $reportTranslate.GetAbrADHardening.SMBv1BP
                            }
                            BlankLine
                        }
                        if (($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADHardening.EnforcingLDAPSigning) -eq 'None' })) {
                            Paragraph {
                                Text $reportTranslate.GetAbrADHardening.BestPractice -Bold
                                Text $reportTranslate.GetAbrADHardening.LDAPSigningBP
                            }
                            BlankLine
                        }
                        if (($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADHardening.EnforcingLDAPChannelBinding) -in @('Never', 'Not Configured/Disabled') })) {
                            Paragraph {
                                Text $reportTranslate.GetAbrADHardening.BestPractice -Bold
                                Text $reportTranslate.GetAbrADHardening.LDAPCBBindingBP
                            }
                            BlankLine
                        }
                        if (($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADHardening.NTLMv1Config) -in @('Send LM & NTLM responses', 'Send LM & NTLM - use NTLMv2 session security if negotiated', 'Send NTLM response only') })) {
                            Paragraph {
                                Text $reportTranslate.GetAbrADHardening.BestPractice -Bold
                                Text $reportTranslate.GetAbrADHardening.NTLMv1BP
                            }
                            BlankLine
                        }
                    }
                } catch {
                    Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) ($($reportTranslate.GetAbrADHardening.ErrorADHardeningItem))"
                }
            }
        } catch {
            Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) ($($reportTranslate.GetAbrADHardening.ErrorADHardeningSection))"
        }
    }

    end {
        Show-AbrDebugExecutionTime -End -TitleMessage 'AD Hardening'
    }

}