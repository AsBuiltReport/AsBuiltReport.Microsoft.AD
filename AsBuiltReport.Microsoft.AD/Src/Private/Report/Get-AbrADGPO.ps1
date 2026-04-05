function Get-AbrADGPO {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft Active Directory Group Policy Objects information.
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
        [string]$ValidDCFromDomain
    )

    begin {
        Write-PScriboMessage -Message ($reportTranslate.GetAbrADGPO.Collecting -f $Domain.DNSRoot.ToString().ToUpper())
        Show-AbrDebugExecutionTime -Start -TitleMessage 'AD Group Policy Objects'
    }

    process {
        try {
            Section -Style Heading4 $reportTranslate.GetAbrADGPO.GPOSectionTitle {
                Paragraph ($reportTranslate.GetAbrADGPO.GPOSectionParagraph -f $Domain.DNSRoot.ToString().ToUpper())
                BlankLine
                $OutObj = [System.Collections.Generic.List[object]]::new()
                $GPOs = Invoke-CommandWithTimeout -Session $TempPssSession -ScriptBlock { Get-GPO -Domain ($using:Domain).DNSRoot -All }
                if ($GPOs) {
                    Section -Style Heading5 $reportTranslate.GetAbrADGPO.GPOInventoryTitle {
                        Paragraph $reportTranslate.GetAbrADGPO.GPOInventoryParagraph
                        BlankLine
                        if ($InfoLevel.Domain -eq 1) {
                            try {
                                foreach ($GPO in $GPOs) {
                                    try {
                                        [xml]$Links = Invoke-CommandWithTimeout -Session $TempPssSession -ScriptBlock { $using:GPO | Get-GPOReport -Domain ($using:Domain).DNSRoot -ReportType XML }
                                        $inObj = [ordered] @{
                                            $reportTranslate.GetAbrADGPO.GPOName = $GPO.DisplayName
                                            $reportTranslate.GetAbrADGPO.GPOStatus = ($GPO.GpoStatus -creplace '([A-Z\W_]|\d+)(?<![a-z])', ' $&').trim()
                                            $reportTranslate.GetAbrADGPO.SecurityFiltering = & {
                                                $GPOSECFILTER = Invoke-CommandWithTimeout -Session $TempPssSession -ScriptBlock { (Get-GPPermission -DomainName ($using:Domain).DNSRoot -All -Guid ($using:GPO).ID | Where-Object { $_.Permission -eq 'GpoApply' }).Trustee.Name }
                                                if ($GPOSECFILTER) {

                                                    $GPOSECFILTER

                                                } else { $reportTranslate.GetAbrADGPO.NoSecurityFiltering }
                                            }
                                            $reportTranslate.GetAbrADGPO.LinksCount = $Links.GPO.LinksTo.SOMPath.Count
                                        }
                                        $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj))
                                    } catch {
                                        Write-PScriboMessage -IsWarning -Message "$($reportTranslate.GetAbrADGPO.ErrorGPOItem) $($_.Exception.Message)"
                                    }
                                }

                                if ($HealthCheck.Domain.GPO) {
                                    $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADGPO.GPOStatus) -like $reportTranslate.GetAbrADGPO.AllSettingsDisabled } | Set-Style -Style Warning -Property $reportTranslate.GetAbrADGPO.GPOStatus
                                    $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADGPO.SecurityFiltering) -like $reportTranslate.GetAbrADGPO.NoSecurityFiltering } | Set-Style -Style Warning -Property $reportTranslate.GetAbrADGPO.SecurityFiltering
                                    $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADGPO.LinksCount) -eq 0 } | Set-Style -Style Warning -Property $reportTranslate.GetAbrADGPO.LinksCount
                                }

                                $TableParams = @{
                                    Name = "$($reportTranslate.GetAbrADGPO.GPOTableName) - $($Domain.DNSRoot.ToString().ToUpper())"
                                    List = $false
                                    ColumnWidths = 40, 25, 25, 10
                                }

                                if ($Report.ShowTableCaptions) {
                                    $TableParams['Caption'] = "- $($TableParams.Name)"
                                }
                                $OutObj | Sort-Object -Property $reportTranslate.GetAbrADGPO.GPOName | Table @TableParams
                                if ($HealthCheck.Domain.GPO -and (($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADGPO.GPOStatus) -like $reportTranslate.GetAbrADGPO.AllSettingsDisabled }) -or ($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADGPO.SecurityFiltering) -like $reportTranslate.GetAbrADGPO.NoSecurityFiltering }) -or ($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADGPO.LinksCount) -eq 0 }))) {
                                    Paragraph $reportTranslate.GetAbrADGPO.GPOHealthCheck -Bold -Underline
                                    BlankLine
                                    if (($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADGPO.GPOStatus) -like $reportTranslate.GetAbrADGPO.AllSettingsDisabled })) {
                                        Paragraph {
                                            Text $reportTranslate.GetAbrADGPO.GPOBestPractices -Bold
                                            Text $reportTranslate.GetAbrADGPO.GPOStatusBP
                                        }
                                        BlankLine
                                    }
                                    if (($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADGPO.SecurityFiltering) -like $reportTranslate.GetAbrADGPO.NoSecurityFiltering })) {
                                        Paragraph {
                                            Text $reportTranslate.GetAbrADGPO.GPOCorrectiveActions -Bold
                                            Text $reportTranslate.GetAbrADGPO.GPOSecurityFilteringBP
                                        }
                                        BlankLine
                                    }
                                    if ($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADGPO.LinksCount) -eq '0' }) {
                                        Paragraph {
                                            Text $reportTranslate.GetAbrADGPO.GPOCorrectiveActions -Bold
                                            Text $reportTranslate.GetAbrADGPO.GPOLinksCountBP
                                        }
                                        BlankLine
                                    }
                                }
                            } catch {
                                Write-PScriboMessage -IsWarning -Message "$($reportTranslate.GetAbrADGPO.ErrorGPOItem) $($_.Exception.Message)"
                            }
                        }
                        if ($InfoLevel.Domain -ge 2) {
                            try {
                                foreach ($GPO in $GPOs) {
                                    Section -ExcludeFromTOC -Style NOTOCHeading5 "$($GPO.DisplayName)" {
                                        $OutObj = [System.Collections.Generic.List[object]]::new()
                                        try {
                                            [xml]$Links = Invoke-CommandWithTimeout -Session $TempPssSession -ScriptBlock { $using:GPO | Get-GPOReport -Domain ($using:Domain).DNSRoot -ReportType XML }
                                            $inObj = [ordered] @{
                                                $reportTranslate.GetAbrADGPO.GPOStatus = ($GPO.GpoStatus -creplace '([A-Z\W_]|\d+)(?<![a-z])', ' $&').trim()
                                                $reportTranslate.GetAbrADGPO.GUID = $GPO.Id
                                                $reportTranslate.GetAbrADGPO.Created = $GPO.CreationTime.ToString('MM/dd/yyyy')
                                                $reportTranslate.GetAbrADGPO.Modified = $GPO.ModificationTime.ToString('MM/dd/yyyy')
                                                $reportTranslate.GetAbrADGPO.OwnerCol = $GPO.Owner
                                                $reportTranslate.GetAbrADGPO.ComputerVersion = "$($Links.GPO.Computer.VersionDirectory) (AD), $($Links.GPO.Computer.VersionSysvol) (SYSVOL)"
                                                $reportTranslate.GetAbrADGPO.UserVersion = "$($Links.GPO.User.VersionDirectory) (AD), $($Links.GPO.User.VersionSysvol) (SYSVOL)"
                                                $reportTranslate.GetAbrADGPO.WMIFilterCol = & {
                                                    $WMIFilter = Invoke-CommandWithTimeout -Session $TempPssSession -ScriptBlock { ((Get-GPO -DomainName $($using:Domain).DNSROot -Name $using:GPO.DisplayName).WMifilter.Name) }
                                                    if ($WMIFilter) {
                                                        $WMIFilter
                                                    } else { '--' }
                                                }
                                                $reportTranslate.GetAbrADGPO.SecurityFiltering = & {
                                                    $GPOSECFILTER = Invoke-CommandWithTimeout -Session $TempPssSession -ScriptBlock { (Get-GPPermission -DomainName ($using:Domain).DNSROot -All -Guid ($using:GPO).ID | Where-Object { $_.Permission -eq 'GpoApply' }).Trustee.Name }
                                                    if ($GPOSECFILTER) {

                                                        $GPOSECFILTER

                                                    } else { $reportTranslate.GetAbrADGPO.NoSecurityFiltering }
                                                }
                                                $reportTranslate.GetAbrADGPO.LinkedTarget = switch ([string]::IsNullOrEmpty($Links.GPO.LinksTo.SOMPath)) {
                                                    'True' { '--' }
                                                    'False' { $Links.GPO.LinksTo.SOMPath }
                                                    default { $reportTranslate.GetAbrADGPO.Unknown }
                                                }
                                                $reportTranslate.GetAbrADGPO.Description = $GPO.Description
                                            }

                                            $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj))

                                            if ($HealthCheck.Domain.GPO) {
                                                $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADGPO.GPOStatus) -like $reportTranslate.GetAbrADGPO.AllSettingsDisabled } | Set-Style -Style Warning -Property $reportTranslate.GetAbrADGPO.GPOStatus
                                                $OutObj | Where-Object { $Null -eq $_.$($reportTranslate.GetAbrADGPO.OwnerCol) } | Set-Style -Style Warning -Property $reportTranslate.GetAbrADGPO.OwnerCol
                                                $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADGPO.SecurityFiltering) -like $reportTranslate.GetAbrADGPO.NoSecurityFiltering } | Set-Style -Style Warning -Property $reportTranslate.GetAbrADGPO.SecurityFiltering
                                                $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADGPO.LinkedTarget) -eq '--' } | Set-Style -Style Warning -Property $reportTranslate.GetAbrADGPO.LinkedTarget
                                            }

                                            $TableParams = @{
                                                Name = "$($reportTranslate.GetAbrADGPO.GPODetailTableName) - $($GPO.DisplayName)"
                                                List = $true
                                                ColumnWidths = 40, 60
                                            }

                                            if ($Report.ShowTableCaptions) {
                                                $TableParams['Caption'] = "- $($TableParams.Name)"
                                            }
                                            $OutObj | Table @TableParams
                                            if ($HealthCheck.Domain.GPO -and (($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADGPO.GPOStatus) -like $reportTranslate.GetAbrADGPO.AllSettingsDisabled }) -or ($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADGPO.SecurityFiltering) -like $reportTranslate.GetAbrADGPO.NoSecurityFiltering }) -or ($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADGPO.LinkedTarget) -eq '--' }))) {
                                                Paragraph $reportTranslate.GetAbrADGPO.GPOHealthCheck -Bold -Underline
                                                BlankLine
                                                if (($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADGPO.GPOStatus) -like $reportTranslate.GetAbrADGPO.AllSettingsDisabled })) {
                                                    Paragraph {
                                                        Text $reportTranslate.GetAbrADGPO.GPOBestPractices -Bold
                                                        Text $reportTranslate.GetAbrADGPO.GPOStatusBP
                                                    }
                                                    BlankLine
                                                }
                                                if (($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADGPO.SecurityFiltering) -like $reportTranslate.GetAbrADGPO.NoSecurityFiltering })) {
                                                    Paragraph {
                                                        Text $reportTranslate.GetAbrADGPO.GPOCorrectiveActions -Bold
                                                        Text $reportTranslate.GetAbrADGPO.GPOSecurityFilteringBP
                                                    }
                                                    BlankLine
                                                }
                                                if ($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADGPO.LinkedTarget) -eq '--' }) {
                                                    Paragraph {
                                                        Text $reportTranslate.GetAbrADGPO.GPOCorrectiveActions -Bold
                                                        Text $reportTranslate.GetAbrADGPO.GPOLinksCountBP
                                                    }
                                                    BlankLine
                                                }
                                            }
                                        } catch {
                                            Write-PScriboMessage -IsWarning -Message "$($reportTranslate.GetAbrADGPO.ErrorGPOItem) $($_.Exception.Message)"
                                        }
                                    }
                                }
                            } catch {
                                Write-PScriboMessage -IsWarning -Message "$($reportTranslate.GetAbrADGPO.ErrorWMIFiltersItem) $($_.Exception.Message)"
                            }
                        }
                    }
                    Section -Style Heading5 $reportTranslate.GetAbrADGPO.GPOSettingsTitle {
                        Paragraph $reportTranslate.GetAbrADGPO.GPOSettingsParagraph
                        BlankLine
                        if ($InfoLevel.Domain -ge 2) {
                            try {
                                $DCPssSession = Get-ValidPSSession -ComputerName $ValidDCFromDomain -SessionName $($ValidDCFromDomain) -PSSTable ([ref]$PSSTable)

                                if ($DCPssSession) {
                                    $WmiFilters = Get-ADObjectSearch -DN "CN=SOM,CN=WMIPolicy,CN=System,$($Domain.DistinguishedName)" -Filter { objectClass -eq 'msWMI-Som' } -SelectPrty '*' -Session $DCPssSession | Sort-Object

                                } else {
                                    if (-not $_.Exception.MessageId) {
                                        $ErrorMessage = $_.FullyQualifiedErrorId
                                    } else { $ErrorMessage = $_.Exception.MessageId }
                                    Write-PScriboMessage -IsWarning -Message ($reportTranslate.GetAbrADGPO.ErrorWMIFiltersPSSession -f $ValidDCFromDomain, $ErrorMessage)
                                }

                                if ($WmiFilters) {
                                    Section -ExcludeFromTOC -Style NOTOCHeading6 $reportTranslate.GetAbrADGPO.WMIFiltersTitle {
                                        foreach ($WmiFilter in $WmiFilters) {
                                            $OutObj = [System.Collections.Generic.List[object]]::new()
                                            $inObj = [ordered] @{
                                                $reportTranslate.GetAbrADGPO.Name = $WmiFilter.'msWMI-Name'
                                                $reportTranslate.GetAbrADGPO.WMIAuthor = $WmiFilter.'msWMI-Author'
                                                $reportTranslate.GetAbrADGPO.WMIQuery = $WmiFilter.'msWMI-Parm2'
                                                $reportTranslate.GetAbrADGPO.Description = $WmiFilter.'msWMI-Parm1'
                                            }
                                            $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj))

                                            if ($HealthCheck.Domain.GPO) {
                                                $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADGPO.Description) -eq '--' } | Set-Style -Style Warning -Property $reportTranslate.GetAbrADGPO.Description
                                            }

                                            $TableParams = @{
                                                Name = "$($reportTranslate.GetAbrADGPO.WMITableName) - $($WmiFilter.'msWMI-Name')"
                                                List = $true
                                                ColumnWidths = 40, 60
                                            }

                                            if ($Report.ShowTableCaptions) {
                                                $TableParams['Caption'] = "- $($TableParams.Name)"
                                            }
                                            $OutObj | Table @TableParams
                                        }
                                    }
                                } else {
                                    Write-PScriboMessage -Message ($reportTranslate.GetAbrADGPO.WMINoData -f $Domain.DNSRoot)
                                }
                            } catch {
                                Write-PScriboMessage -IsWarning -Message "$($reportTranslate.GetAbrADGPO.ErrorWMIFiltersItem) $($_.Exception.Message)"
                            }
                        }
                        try {
                            $PATH = "\\$($Domain.DNSRoot)\SYSVOL\$($Domain.DNSRoot)\Policies\PolicyDefinitions"
                            $CentralStore = Invoke-CommandWithTimeout -Session $TempPssSession -ScriptBlock { Test-Path $using:PATH -PathType Container }
                            if ($PATH) {
                                Section -ExcludeFromTOC -Style NOTOCHeading6 $reportTranslate.GetAbrADGPO.CentralStoreTitle {
                                    $OutObj = [System.Collections.Generic.List[object]]::new()
                                    $inObj = [ordered] @{
                                        $reportTranslate.GetAbrADGPO.CentralStoreDomain = $Domain.Name.ToString().ToUpper()
                                        $reportTranslate.GetAbrADGPO.CentralStoreConfigured = $CentralStore
                                        $reportTranslate.GetAbrADGPO.CentralStorePath = "\\$($Domain.DNSRoot)\SYSVOL\$($Domain.DNSRoot)\Policies\PolicyDefinitions"
                                    }
                                    $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj))

                                    if ($HealthCheck.Domain.GPO) {
                                        $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADGPO.CentralStoreConfigured) -eq 'No' } | Set-Style -Style Warning -Property $reportTranslate.GetAbrADGPO.CentralStoreConfigured
                                    }

                                    $TableParams = @{
                                        Name = "$($reportTranslate.GetAbrADGPO.CentralStoreTableName) - $($Domain.DNSRoot.ToString().ToUpper())"
                                        List = $false
                                        ColumnWidths = 25, 15, 60
                                    }

                                    if ($Report.ShowTableCaptions) {
                                        $TableParams['Caption'] = "- $($TableParams.Name)"
                                    }
                                    $OutObj | Table @TableParams
                                    if ($HealthCheck.Domain.GPO -and ($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADGPO.CentralStoreConfigured) -eq 'No' })) {
                                        Paragraph $reportTranslate.GetAbrADGPO.CentralStoreHealthCheck -Bold -Underline
                                        BlankLine
                                        Paragraph {
                                            Text $reportTranslate.GetAbrADGPO.CentralStoreBestPractices -Bold
                                            Text $reportTranslate.GetAbrADGPO.CentralStoreBP
                                        }
                                    }
                                }
                            } else {
                                Write-PScriboMessage -Message ($reportTranslate.GetAbrADGPO.CentralStoreNoData -f $Domain.DNSRoot)
                            }
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "$($reportTranslate.GetAbrADGPO.ErrorGPOCentralStore) $($_.Exception.Message)"
                        }
                        try {
                            if ($GPOs) {
                                $OutObj = [System.Collections.Generic.List[object]]::new()
                                foreach ($GPO in $GPOs) {
                                    try {
                                        [xml]$Gpoxml = Invoke-CommandWithTimeout -Session $TempPssSession -ScriptBlock { Get-GPOReport -Domain ($using:Domain).DNSRoot -ReportType Xml -Guid ($using:GPO).Id }
                                        $UserScripts = $Gpoxml.GPO.User.ExtensionData | Where-Object { $_.Name -eq 'Scripts' }
                                        if ($UserScripts.extension.Script) {
                                            foreach ($Script in $UserScripts.extension.Script) {
                                                try {
                                                    $inObj = [ordered] @{
                                                        $reportTranslate.GetAbrADGPO.GPOName = $GPO.DisplayName
                                                        $reportTranslate.GetAbrADGPO.GPOStatus = ($GPO.GpoStatus -creplace '([A-Z\W_]|\d+)(?<![a-z])', ' $&').trim()
                                                        $reportTranslate.GetAbrADGPO.ScriptType = $Script.Type
                                                        $reportTranslate.GetAbrADGPO.Script = $Script.command
                                                    }
                                                    $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj))
                                                } catch {
                                                    Write-PScriboMessage -IsWarning $_.Exception.Message
                                                }
                                            }
                                        }
                                    } catch {
                                        Write-PScriboMessage -IsWarning -Message "$($reportTranslate.GetAbrADGPO.ErrorGPOLogonLogoffItem) $($_.Exception.Message)"
                                    }
                                }
                            }
                            if ($OutObj) {
                                Section -ExcludeFromTOC -Style NOTOCHeading6 $reportTranslate.GetAbrADGPO.LogonLogoffTitle {
                                    if ($HealthCheck.Domain.GPO) {
                                        $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADGPO.GPOStatus) -like $reportTranslate.GetAbrADGPO.AllSettingsDisabled } | Set-Style -Style Warning -Property $reportTranslate.GetAbrADGPO.GPOStatus
                                    }

                                    $TableParams = @{
                                        Name = "$($reportTranslate.GetAbrADGPO.LogonLogoffTableName) - $($Domain.DNSRoot.ToString().ToUpper())"
                                        List = $false
                                        ColumnWidths = 20, 15, 15, 50
                                    }

                                    if ($Report.ShowTableCaptions) {
                                        $TableParams['Caption'] = "- $($TableParams.Name)"
                                    }
                                    $OutObj | Sort-Object -Property $reportTranslate.GetAbrADGPO.GPOName | Table @TableParams
                                }
                            } else {
                                Write-PScriboMessage -Message ($reportTranslate.GetAbrADGPO.LogonLogoffNoData -f $Domain.DNSRoot)
                            }
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "$($reportTranslate.GetAbrADGPO.ErrorGPOLogonLogoffSection) $($_.Exception.Message)"
                        }
                        try {
                            if ($GPOs) {
                                $OutObj = [System.Collections.Generic.List[object]]::new()
                                foreach ($GPO in $GPOs) {
                                    try {
                                        [xml]$Gpoxml = Invoke-CommandWithTimeout -Session $TempPssSession -ScriptBlock { Get-GPOReport -Domain ($using:Domain).DNSROot -ReportType Xml -Guid ($using:GPO).Id }
                                        $ComputerScripts = $Gpoxml.GPO.Computer.ExtensionData | Where-Object { $_.Name -eq 'Scripts' }
                                        if ($ComputerScripts.extension.Script) {
                                            foreach ($Script in $ComputerScripts.extension.Script) {
                                                try {
                                                    $inObj = [ordered] @{
                                                        $reportTranslate.GetAbrADGPO.GPOName = $GPO.DisplayName
                                                        $reportTranslate.GetAbrADGPO.GPOStatus = ($GPO.GpoStatus -creplace '([A-Z\W_]|\d+)(?<![a-z])', ' $&').trim()
                                                        $reportTranslate.GetAbrADGPO.ScriptType = $Script.Type
                                                        $reportTranslate.GetAbrADGPO.Script = $Script.command
                                                    }
                                                    $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj))
                                                } catch {
                                                    Write-PScriboMessage -IsWarning -Message "$($reportTranslate.GetAbrADGPO.ErrorGPOStartupShutdownItem) $($_.Exception.Message)"
                                                }
                                            }
                                        }
                                    } catch {
                                        Write-PScriboMessage -IsWarning -Message "$($reportTranslate.GetAbrADGPO.ErrorGPOStartupShutdownItem) $($_.Exception.Message)"
                                    }
                                }
                            }
                            if ($OutObj) {
                                Section -ExcludeFromTOC -Style NOTOCHeading6 $reportTranslate.GetAbrADGPO.StartupShutdownTitle {
                                    if ($HealthCheck.Domain.GPO) {
                                        $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADGPO.GPOStatus) -like $reportTranslate.GetAbrADGPO.AllSettingsDisabled } | Set-Style -Style Warning -Property $reportTranslate.GetAbrADGPO.GPOStatus
                                    }

                                    $TableParams = @{
                                        Name = "$($reportTranslate.GetAbrADGPO.StartupShutdownTableName) - $($Domain.DNSRoot.ToString().ToUpper())"
                                        List = $false
                                        ColumnWidths = 20, 15, 15, 50
                                    }

                                    if ($Report.ShowTableCaptions) {
                                        $TableParams['Caption'] = "- $($TableParams.Name)"
                                    }
                                    $OutObj | Sort-Object -Property $reportTranslate.GetAbrADGPO.GPOName | Table @TableParams
                                }

                            } else {
                                Write-PScriboMessage -Message ($reportTranslate.GetAbrADGPO.StartupShutdownNoData -f $Domain.DNSRoot)
                            }
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "$($reportTranslate.GetAbrADGPO.ErrorGPOStartupShutdownSection) $($_.Exception.Message)"
                        }
                    }
                }
                if ($HealthCheck.Domain.GPO) {
                    Section -Style Heading5 $reportTranslate.GetAbrADGPO.GPOHealthTitle {
                        Paragraph $reportTranslate.GetAbrADGPO.GPOHealthParagraph
                        BlankLine
                        try {
                            $OutObj = [System.Collections.Generic.List[object]]::new()
                            if ($GPOs) {
                                foreach ($GPO in $GPOs) {
                                    try {
                                        [xml]$Gpoxml = Invoke-CommandWithTimeout -Session $TempPssSession -ScriptBlock { Get-GPOReport -Domain ($using:Domain).DNSROot -ReportType Xml -Guid ($using:GPO).Id }
                                        if (($Null -ne $Gpoxml.GPO.Name) -and ($Null -eq $Gpoxml.GPO.LinksTo.SOMPath)) {
                                            $inObj = [ordered] @{
                                                $reportTranslate.GetAbrADGPO.GPOName = $Gpoxml.GPO.Name
                                                $reportTranslate.GetAbrADGPO.Created = ($Gpoxml.GPO.CreatedTime).ToString().split('T')[0]
                                                $reportTranslate.GetAbrADGPO.Modified = ($Gpoxml.GPO.ModifiedTime).ToString().split('T')[0]
                                                $reportTranslate.GetAbrADGPO.ComputerEnabled = $gpoxml.GPO.Computer.Enabled
                                                $reportTranslate.GetAbrADGPO.UserEnabled = $gpoxml.GPO.User.Enabled
                                            }
                                            $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj))
                                        }
                                    } catch {
                                        Write-PScriboMessage -IsWarning -Message "$($reportTranslate.GetAbrADGPO.ErrorUnlinkedGPOItem) $($_.Exception.Message)"
                                    }
                                }
                            }
                            if ($OutObj) {
                                Section -ExcludeFromTOC -Style NOTOCHeading6 $reportTranslate.GetAbrADGPO.UnlinkedGPOTitle {
                                    if ($HealthCheck.Domain.GPO) {
                                        $OutObj | Set-Style -Style Warning
                                    }

                                    $TableParams = @{
                                        Name = "$($reportTranslate.GetAbrADGPO.UnlinkedGPOTableName) - $($Domain.DNSRoot.ToString().ToUpper())"
                                        List = $false
                                        ColumnWidths = 40, 15, 15, 15, 15
                                    }

                                    if ($Report.ShowTableCaptions) {
                                        $TableParams['Caption'] = "- $($TableParams.Name)"
                                    }
                                    $OutObj | Sort-Object -Property $reportTranslate.GetAbrADGPO.GPOName | Table @TableParams
                                    Paragraph $reportTranslate.GetAbrADGPO.UnlinkedGPOHealthCheck -Bold -Underline
                                    BlankLine
                                    Paragraph {
                                        Text $reportTranslate.GetAbrADGPO.UnlinkedGPOCorrectiveActions -Bold
                                        Text $reportTranslate.GetAbrADGPO.UnlinkedGPOBP
                                    }
                                }
                            } else {
                                Write-PScriboMessage -Message ($reportTranslate.GetAbrADGPO.UnlinkedGPONoData -f $Domain.DNSRoot)
                            }
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "$($reportTranslate.GetAbrADGPO.ErrorUnlinkedGPOSection) $($_.Exception.Message)"
                        }
                        try {
                            $OutObj = [System.Collections.Generic.List[object]]::new()
                            if ($GPOs) {
                                foreach ($GPO in $GPOs) {
                                    try {
                                        [xml]$Gpoxml = Invoke-CommandWithTimeout -Session $TempPssSession -ScriptBlock { Get-GPOReport -Domain ($using:Domain).DNSROot -ReportType Xml -Guid ($using:GPO).Id }
                                        if (($Null -eq ($Gpoxml.GPO.Computer.ExtensionData)) -and ($Null -eq ($Gpoxml.GPO.User.extensionData))) {
                                            $inObj = [ordered] @{
                                                $reportTranslate.GetAbrADGPO.GPOName = $Gpoxml.GPO.Name
                                                $reportTranslate.GetAbrADGPO.Created = ($Gpoxml.GPO.CreatedTime).ToString().split('T')[0]
                                                $reportTranslate.GetAbrADGPO.Modified = ($Gpoxml.GPO.ModifiedTime).ToString().split('T')[0]
                                                $reportTranslate.GetAbrADGPO.Description = $Gpoxml.GPO.Description
                                            }
                                            $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj))
                                        }
                                    } catch {
                                        Write-PScriboMessage -IsWarning -Message "$($reportTranslate.GetAbrADGPO.ErrorEmptyGPOItem) $($_.Exception.Message)"
                                    }
                                }
                            }
                            if ($OutObj) {
                                Section -ExcludeFromTOC -Style NOTOCHeading6 $reportTranslate.GetAbrADGPO.EmptyGPOTitle {
                                    if ($HealthCheck.Domain.GPO) {
                                        $OutObj | Set-Style -Style Warning
                                    }

                                    $TableParams = @{
                                        Name = "$($reportTranslate.GetAbrADGPO.EmptyGPOTableName) - $($Domain.DNSRoot.ToString().ToUpper())"
                                        List = $false
                                        ColumnWidths = 35, 15, 15, 35
                                    }

                                    if ($Report.ShowTableCaptions) {
                                        $TableParams['Caption'] = "- $($TableParams.Name)"
                                    }
                                    $OutObj | Sort-Object -Property $reportTranslate.GetAbrADGPO.GPOName | Table @TableParams
                                    Paragraph $reportTranslate.GetAbrADGPO.EmptyGPOHealthCheck -Bold -Underline
                                    BlankLine
                                    Paragraph {
                                        Text $reportTranslate.GetAbrADGPO.EmptyGPOCorrectiveActions -Bold
                                        Text $reportTranslate.GetAbrADGPO.EmptyGPOBP
                                    }
                                }
                            } else {
                                Write-PScriboMessage -Message ($reportTranslate.GetAbrADGPO.EmptyGPONoData -f $Domain.DNSRoot)
                            }
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "$($reportTranslate.GetAbrADGPO.ErrorEmptyGPOSection) $($_.Exception.Message)"
                        }
                        try {
                            $OutObj = [System.Collections.Generic.List[object]]::new()

                            $OUs = (Invoke-CommandWithTimeout -Session $TempPssSession -ScriptBlock { Get-ADOrganizationalUnit -Server $using:ValidDCFromDomain -Filter * }).DistinguishedName
                            if ($OUs) {
                                $OUs += $Domain.DistinguishedName
                            }
                            if ($OUs) {
                                foreach ($OU in $OUs) {
                                    try {
                                        $GpoEnforces = Invoke-CommandWithTimeout -Session $TempPssSession -ErrorAction Stop -ScriptBlock { Get-GPInheritance -Domain ($using:Domain).DNSRoot -Server $using:ValidDCFromDomain -Target $using:OU | Select-Object -ExpandProperty GpoLinks }
                                        foreach ($GpoEnforced in $GpoEnforces) {
                                            if ($GpoEnforced.Enforced -eq 'True') {
                                                $TargetCanonical = Invoke-CommandWithTimeout -Session $TempPssSession -ScriptBlock { Get-ADObject -Server $using:ValidDCFromDomain -Identity ($using:GpoEnforced).Target -Properties * | Select-Object -ExpandProperty CanonicalName }
                                                $inObj = [ordered] @{
                                                    $reportTranslate.GetAbrADGPO.GPOName = $GpoEnforced.DisplayName
                                                    $reportTranslate.GetAbrADGPO.Target = $TargetCanonical
                                                }
                                                $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj))
                                            }
                                        }
                                    } catch {
                                        Write-PScriboMessage -IsWarning -Message "OU: $($OU): $($reportTranslate.GetAbrADGPO.ErrorEnforcedGPOItem) $($_.Exception.Message)"
                                    }
                                }
                            }

                            if ($OutObj) {
                                Section -ExcludeFromTOC -Style NOTOCHeading6 $reportTranslate.GetAbrADGPO.EnforcedGPOTitle {
                                    if ($HealthCheck.Domain.GPO) {
                                        $OutObj | Set-Style -Style Warning
                                    }

                                    $TableParams = @{
                                        Name = "$($reportTranslate.GetAbrADGPO.EnforcedGPOTableName) - $($Domain.DNSRoot.ToString().ToUpper())"
                                        List = $false
                                        ColumnWidths = 50, 50
                                    }

                                    if ($Report.ShowTableCaptions) {
                                        $TableParams['Caption'] = "- $($TableParams.Name)"
                                    }
                                    $OutObj | Sort-Object -Property $reportTranslate.GetAbrADGPO.Target | Table @TableParams
                                    Paragraph $reportTranslate.GetAbrADGPO.EnforcedGPOHealthCheck -Bold -Underline
                                    BlankLine
                                    Paragraph {
                                        Text $reportTranslate.GetAbrADGPO.EnforcedGPOCorrectiveActions -Bold
                                        Text $reportTranslate.GetAbrADGPO.EnforcedGPOBP
                                    }

                                }
                            } else {
                                Write-PScriboMessage -Message ($reportTranslate.GetAbrADGPO.EnforcedGPONoData -f $Domain.DNSRoot)
                            }
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "$($reportTranslate.GetAbrADGPO.ErrorEnforcedGPOTable) $($_.Exception.Message)"
                        }
                        # Code taken from Jeremy Saunders
                        # https://github.com/jeremyts/ActiveDirectoryDomainServices/blob/master/Audit/FindOrphanedGPOs.ps1
                        try {
                            $DCPssSession = Get-ValidPSSession -ComputerName $ValidDCFromDomain -SessionName $($ValidDCFromDomain) -PSSTable ([ref]$PSSTable)

                            if ($DCPssSession) {
                                $GPOPoliciesADSI = (Get-ADObjectSearch -DN "CN=Policies,CN=System,$($Domain.DistinguishedName)" -Filter { objectClass -eq 'groupPolicyContainer' } -Properties 'Name' -SelectPrty 'Name' -Session $DCPssSession).Name.Trim('{}') | Sort-Object
                            } else {
                                if (-not $_.Exception.MessageId) {
                                    $ErrorMessage = $_.FullyQualifiedErrorId
                                } else { $ErrorMessage = $_.Exception.MessageId }
                                Write-PScriboMessage -IsWarning -Message ($reportTranslate.GetAbrADGPO.ErrorOrphanedGPOPSSession -f $ValidDCFromDomain, $ErrorMessage)
                            }
                            $GPOPoliciesSYSVOLUNC = "\\$($Domain.DNSRoot)\SYSVOL\$($Domain.DNSRoot)\Policies"
                            $OrphanGPOs = [System.Collections.Generic.List[object]]::new()
                            $GPOPoliciesSYSVOL = try { (Invoke-CommandWithTimeout -Session $TempPssSession -ScriptBlock { Get-ChildItem $using:GPOPoliciesSYSVOLUNC | Where-Object { $_.Name -ne 'PolicyDefinitions' } | Sort-Object }).Name.Trim('{}') } catch { $null }
                            $SYSVOLGPOList = [System.Collections.Generic.List[object]]::new()
                            foreach ($GPOinSYSVOL in $GPOPoliciesSYSVOL) {
                                $SYSVOLGPOList.Add($GPOinSYSVOL)
                            }
                            if ($GPOPoliciesADSI -and $SYSVOLGPOList) {
                                $MissingADGPOs = Compare-Object $SYSVOLGPOList $GPOPoliciesADSI -PassThru | Where-Object { $_.SideIndicator -eq '<=' }
                                $MissingSYSVOLGPOs = Compare-Object $GPOPoliciesADSI $SYSVOLGPOList -PassThru | Where-Object { $_.SideIndicator -eq '<=' }
                            }

                            if ($MissingADGPOs) {
                                $OrphanGPOs.Add($MissingADGPOs)
                            }
                            if ($MissingSYSVOLGPOs) {
                                $OrphanGPOs.Add($MissingSYSVOLGPOs)
                            }
                            if ($OrphanGPOs) {
                                Section -ExcludeFromTOC -Style NOTOCHeading6 $reportTranslate.GetAbrADGPO.OrphanedGPOTitle {
                                    Paragraph $reportTranslate.GetAbrADGPO.OrphanedGPOParagraph
                                    BlankLine
                                    foreach ($OrphanGPO in $OrphanGPOs) {
                                        $OutObj = [System.Collections.Generic.List[object]]::new()
                                        $inObj = [ordered] @{
                                            $reportTranslate.GetAbrADGPO.Name = switch (($GPOs | Where-Object { $_.id -eq $OrphanGPO }).DisplayName) {
                                                $Null { $reportTranslate.GetAbrADGPO.Unknown }
                                                default { ($GPOs | Where-Object { $_.id -eq $OrphanGPO }).DisplayName }
                                            }
                                            $reportTranslate.GetAbrADGPO.OrphanedGuid = $OrphanGPO
                                            $reportTranslate.GetAbrADGPO.ADDNDatabase = & {
                                                if ($OrphanGPO -in $MissingADGPOs) {
                                                    $reportTranslate.GetAbrADGPO.Missing
                                                } else { $reportTranslate.GetAbrADGPO.Valid }
                                            }
                                            $reportTranslate.GetAbrADGPO.ADDNPath = & {
                                                if ($OrphanGPO -in $MissingADGPOs) {
                                                    "CN={$($OrphanGPO)},CN=Policies,CN=System,$($Domain.DistinguishedName) ($($reportTranslate.GetAbrADGPO.Missing))"
                                                } else { "CN={$($OrphanGPO)},CN=Policies,CN=System,$($Domain.DistinguishedName) ($($reportTranslate.GetAbrADGPO.Valid))" }
                                            }
                                            $reportTranslate.GetAbrADGPO.SYSVOLGuidDirectory = & {
                                                if ($OrphanGPO -in $MissingSYSVOLGPOs) {
                                                    $reportTranslate.GetAbrADGPO.Missing
                                                } else { $reportTranslate.GetAbrADGPO.Valid }
                                            }
                                            $reportTranslate.GetAbrADGPO.SYSVOLGuidPath = & {
                                                if ($OrphanGPO -in $MissingSYSVOLGPOs) {
                                                    "\\$($Domain.DNSRoot)\SYSVOL\$($Domain.DNSRoot)\Policies\{$($OrphanGPO)} ($($reportTranslate.GetAbrADGPO.Missing))"
                                                } else { "\\$($Domain.DNSRoot)\SYSVOL\$($Domain.DNSRoot)\Policies\{$($OrphanGPO)} ($($reportTranslate.GetAbrADGPO.Valid))" }
                                            }
                                        }
                                        $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj))

                                        if ($HealthCheck.Domain.GPO) {
                                            $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADGPO.ADDNDatabase) -eq $reportTranslate.GetAbrADGPO.Missing } | Set-Style -Style Warning -Property $reportTranslate.GetAbrADGPO.ADDNDatabase, $reportTranslate.GetAbrADGPO.ADDNPath
                                            $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADGPO.SYSVOLGuidDirectory) -eq $reportTranslate.GetAbrADGPO.Missing } | Set-Style -Style Warning -Property $reportTranslate.GetAbrADGPO.SYSVOLGuidDirectory, $reportTranslate.GetAbrADGPO.SYSVOLGuidPath
                                        }

                                        $TableParams = @{
                                            Name = "$($reportTranslate.GetAbrADGPO.OrphanedGPOTableName) - $($Domain.DNSRoot.ToString().ToUpper())"
                                            List = $true
                                            ColumnWidths = 40, 60
                                        }

                                        if ($Report.ShowTableCaptions) {
                                            $TableParams['Caption'] = "- $($TableParams.Name)"
                                        }
                                        $OutObj | Table @TableParams
                                        if ($HealthCheck.Domain.GPO -and (($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADGPO.ADDNDatabase) -eq $reportTranslate.GetAbrADGPO.Missing }) -or ($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADGPO.SYSVOLGuidDirectory) -eq $reportTranslate.GetAbrADGPO.Missing }))) {
                                            Paragraph $reportTranslate.GetAbrADGPO.OrphanedGPOHealthCheck -Bold -Underline
                                            BlankLine
                                            if ($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADGPO.ADDNDatabase) -eq $reportTranslate.GetAbrADGPO.Missing }) {
                                                Paragraph {
                                                    Text $reportTranslate.GetAbrADGPO.OrphanedGPOCorrectiveActions -Bold
                                                    Text $reportTranslate.GetAbrADGPO.OrphanedGPOMissingADBP
                                                }
                                                BlankLine
                                            }
                                            if ($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADGPO.SYSVOLGuidDirectory) -eq $reportTranslate.GetAbrADGPO.Missing }) {
                                                Paragraph {
                                                    Text $reportTranslate.GetAbrADGPO.OrphanedGPOCorrectiveActions -Bold
                                                    Text $reportTranslate.GetAbrADGPO.OrphanedGPOMissingSYSVOLBP
                                                }
                                                BlankLine
                                            }
                                        }
                                    }
                                }
                            } else {
                                Write-PScriboMessage -Message ($reportTranslate.GetAbrADGPO.OrphanedGPONoData -f $Domain.DNSRoot)
                            }
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "$($reportTranslate.GetAbrADGPO.ErrorOrphanedGPOItem) $($_.Exception.Message)"
                        }
                    }
                }
            }
        } catch {
            Write-PScriboMessage -IsWarning -Message "$($reportTranslate.GetAbrADGPO.ErrorGPOSection) $($_.Exception.Message)"
        }
    }


    end {
        Show-AbrDebugExecutionTime -End -TitleMessage 'AD Domain Group Policy Objects'
    }

}