function Get-AbrADGPO {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft Active Directory Group Policy Objects information.
    .DESCRIPTION

    .NOTES
        Version:        0.9.2
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
        $Domain
    )

    begin {
        Write-PScriboMessage "Collecting Active Directory Group Policy Objects information for $($Domain.ToString().ToUpper())."
    }

    process {
        try {
            Section -Style Heading4 "Group Policy Objects" {
                Paragraph "The following section provides a summary of the Group Policy Objects for domain $($Domain.ToString().ToUpper())."
                BlankLine
                $OutObj = @()
                $GPOs = Invoke-Command -Session $TempPssSession -ScriptBlock { Get-GPO -Domain $using:Domain -All }
                if ($GPOs) {
                    if ($InfoLevel.Domain -eq 1) {
                        try {
                            foreach ($GPO in $GPOs) {
                                try {
                                    [xml]$Links = Invoke-Command -Session $TempPssSession -ScriptBlock { $using:GPO | Get-GPOReport -Domain $using:Domain -ReportType XML }
                                    $inObj = [ordered] @{
                                        'GPO Name' = $GPO.DisplayName
                                        'GPO Status' = ($GPO.GpoStatus -creplace '([A-Z\W_]|\d+)(?<![a-z])', ' $&').trim()
                                        'Security Filtering' = & {
                                            $GPOSECFILTER = Invoke-Command -Session $TempPssSession -ScriptBlock { (Get-GPPermission -DomainName $using:Domain -All -Guid ($using:GPO).ID | Where-Object { $_.Permission -eq 'GpoApply' }).Trustee.Name }
                                            if ($GPOSECFILTER) {

                                                return $GPOSECFILTER

                                            } else { 'No Security Filtering' }
                                        }
                                        'Links Count' = $Links.GPO.LinksTo.SOMPath.Count
                                    }
                                    $OutObj += [pscustomobject](ConvertTo-HashToYN $inObj)
                                } catch {
                                    Write-PScriboMessage -IsWarning "$($_.Exception.Message) (Group Policy Objects)"
                                }
                            }

                            if ($HealthCheck.Domain.GPO) {
                                $OutObj | Where-Object { $_.'GPO Status' -like 'All Settings Disabled' } | Set-Style -Style Warning -Property 'GPO Status'
                                $OutObj | Where-Object { $_.'Security Filtering' -like 'No Security Filtering' } | Set-Style -Style Warning -Property 'Security Filtering'
                                $OutObj | Where-Object { $_.'Links Count' -eq 0 } | Set-Style -Style Warning -Property 'Links Count'
                            }

                            $TableParams = @{
                                Name = "GPO - $($Domain.ToString().ToUpper())"
                                List = $false
                                ColumnWidths = 40, 25, 25, 10
                            }

                            if ($Report.ShowTableCaptions) {
                                $TableParams['Caption'] = "- $($TableParams.Name)"
                            }
                            $OutObj | Sort-Object -Property 'GPO Name' | Table @TableParams
                            if ($HealthCheck.Domain.GPO -and (($OutObj | Where-Object { $_.'GPO Status' -like 'All Settings Disabled' }) -or ($OutObj | Where-Object { $_.'Security Filtering' -like 'No Security Filtering' }) -or ($OutObj | Where-Object { $_.'Links Count' -eq 0 }))) {
                                Paragraph "Health Check:" -Bold -Underline
                                BlankLine
                                if (($OutObj | Where-Object { $_.'GPO Status' -like 'All Settings Disabled' })) {
                                    Paragraph {
                                        Text "Best Practices:" -Bold
                                        Text "Ensure 'All Settings Disabled' GPOs are removed from Active Directory."
                                    }
                                    BlankLine
                                }
                                if (($OutObj | Where-Object { $_.'Security Filtering' -like 'No Security Filtering' })) {
                                    Paragraph {
                                        Text "Corrective Actions:" -Bold
                                        Text "Determine which 'No Security Filtering' GPOs should be deleted and delete them."
                                    }
                                    BlankLine
                                }
                                if ($OutObj | Where-Object { $_.'Links Count' -eq '0' }) {
                                    Paragraph {
                                        Text "Corrective Actions:" -Bold
                                        Text "Ensure unused or unlinked GPOs are removed from Active Directory."
                                    }
                                    BlankLine
                                }
                            }
                        } catch {
                            Write-PScriboMessage -IsWarning "$($_.Exception.Message) (Group Policy Objects)"
                        }
                    }
                    if ($InfoLevel.Domain -ge 2) {
                        try {
                            foreach ($GPO in $GPOs) {
                                Section -ExcludeFromTOC -Style NOTOCHeading5 "$($GPO.DisplayName)" {
                                    try {
                                        [xml]$Links = Invoke-Command -Session $TempPssSession -ScriptBlock { $using:GPO | Get-GPOReport -Domain $using:Domain -ReportType XML }
                                        $inObj = [ordered] @{
                                            'GPO Status' = ($GPO.GpoStatus -creplace '([A-Z\W_]|\d+)(?<![a-z])', ' $&').trim()
                                            'GUID' = $GPO.Id
                                            'Created' = $GPO.CreationTime.ToString("MM/dd/yyyy")
                                            'Modified' = $GPO.ModificationTime.ToString("MM/dd/yyyy")
                                            'Owner' = $GPO.Owner
                                            'Computer Version' = "$($Links.GPO.Computer.VersionDirectory) (AD), $($Links.GPO.Computer.VersionSysvol) (SYSVOL)"
                                            'User Version' = "$($Links.GPO.User.VersionDirectory) (AD), $($Links.GPO.User.VersionSysvol) (SYSVOL)"
                                            'WMI Filter' = & {
                                                $WMIFilter = Invoke-Command -Session $TempPssSession -ScriptBlock { ((Get-GPO -DomainName $using:Domain  -Name $using:GPO.DisplayName).WMifilter.Name) }
                                                if ($WMIFilter) {
                                                    $WMIFilter
                                                } else { '--' }
                                            }
                                            'Security Filtering' = & {
                                                $GPOSECFILTER = Invoke-Command -Session $TempPssSession -ScriptBlock { (Get-GPPermission -DomainName $using:Domain -All -Guid ($using:GPO).ID | Where-Object { $_.Permission -eq 'GpoApply' }).Trustee.Name }
                                                if ($GPOSECFILTER) {

                                                    return $GPOSECFILTER

                                                } else { 'No Security Filtering' }
                                            }
                                            'Linked Target' = Switch ([string]::IsNullOrEmpty($Links.GPO.LinksTo.SOMPath)) {
                                                'True' { '--' }
                                                'False' { $Links.GPO.LinksTo.SOMPath }
                                                default { 'Unknown' }
                                            }
                                            'Description' = $GPO.Description
                                        }

                                        $OutObj = [pscustomobject](ConvertTo-HashToYN $inObj)

                                        if ($HealthCheck.Domain.GPO) {
                                            $OutObj | Where-Object { $_.'GPO Status' -like 'All Settings Disabled' } | Set-Style -Style Warning -Property 'GPO Status'
                                            $OutObj | Where-Object { $Null -eq $_.'Owner' } | Set-Style -Style Warning -Property 'Owner'
                                            $OutObj | Where-Object { $_.'Security Filtering' -like 'No Security Filtering' } | Set-Style -Style Warning -Property 'Security Filtering'
                                            $OutObj | Where-Object { $_.'Linked Target' -eq '--' } | Set-Style -Style Warning -Property 'Linked Target'
                                        }

                                        $TableParams = @{
                                            Name = "GPO - $($GPO.DisplayName)"
                                            List = $true
                                            ColumnWidths = 40, 60
                                        }

                                        if ($Report.ShowTableCaptions) {
                                            $TableParams['Caption'] = "- $($TableParams.Name)"
                                        }
                                        $OutObj | Table @TableParams
                                        if ($HealthCheck.Domain.GPO -and (($OutObj | Where-Object { $_.'GPO Status' -like 'All Settings Disabled' }) -or ($OutObj | Where-Object { $_.'Security Filtering' -like 'No Security Filtering' }) -or ($OutObj | Where-Object { $_.'Linked Target' -eq '--' }))) {
                                            Paragraph "Health Check:" -Bold -Underline
                                            BlankLine
                                            if (($OutObj | Where-Object { $_.'GPO Status' -like 'All Settings Disabled' })) {
                                                Paragraph {
                                                    Text "Best Practices:" -Bold
                                                    Text "Ensure 'All Settings Disabled' GPO are removed from Active Directory."
                                                }
                                                BlankLine
                                            }
                                            if (($OutObj | Where-Object { $_.'Security Filtering' -like 'No Security Filtering' })) {
                                                Paragraph {
                                                    Text "Corrective Actions:" -Bold
                                                    Text "Determine which 'No Security Filtering' Group Policies should be deleted and delete them."
                                                }
                                                BlankLine
                                            }
                                            if ($OutObj | Where-Object { $_.'Linked Target' -eq '--' }) {
                                                Paragraph {
                                                    Text "Corrective Actions:" -Bold
                                                    Text "Ensure unused or unlinked GPOs are removed from Active Directory."
                                                }
                                                BlankLine
                                            }
                                        }
                                    } catch {
                                        Write-PScriboMessage -IsWarning "$($_.Exception.Message) (Group Policy Objects)"
                                    }
                                }
                            }
                        } catch {
                            Write-PScriboMessage -IsWarning "$($_.Exception.Message) (WMI Filters)"
                        }
                    }
                    if ($InfoLevel.Domain -ge 2) {
                        try {
                            $DCList = Invoke-Command -Session $TempPssSession { (Get-ADDomain -Identity $using:Domain).ReplicaDirectoryServers }

                            $DC = foreach ($TestedDC in $DCList) {
                                if (Test-WSMan -ComputerName $TestedDC -ErrorAction SilentlyContinue) {
                                    Write-PScriboMessage "Using $TestedDC to retreive Active Directory Group Policy Objects information on $Domain."
                                    $TestedDC
                                    break
                                } else {
                                    Write-PScriboMessage "Unable to connect to $TestedDC to retreive Active Directory Group Policy Objects information on $Domain."
                                }
                            }
                            $DCPssSession = try { New-PSSession -ComputerName $DC -Credential $Credential -Authentication $Options.PSDefaultAuthentication -Name 'WmiFilters' -ErrorAction Stop } catch {
                                if (-Not $_.Exception.MessageId) {
                                    $ErrorMessage = $_.FullyQualifiedErrorId
                                } else {$ErrorMessage = $_.Exception.MessageId}
                                Write-PScriboMessage -IsWarning "Wmi Filters Section: New-PSSession: Unable to connect to $($DC): $ErrorMessage"
                            }
                            $DomainInfo = Invoke-Command -Session $TempPssSession { Get-ADDomain $using:Domain -ErrorAction Stop }
                            if ($DCPssSession) {
                                $WmiFilters = Get-ADObjectSearch -DN "CN=SOM,CN=WMIPolicy,CN=System,$($DomainInfo.DistinguishedName)" -Filter { objectClass -eq "msWMI-Som" } -SelectPrty '*' -Session $DCPssSession | Sort-Object
                                Remove-PSSession -Session $DCPssSession
                            }
                            if ($WmiFilters) {
                                Section -Style Heading5 "WMI Filters" {
                                    $OutObj = @()
                                    foreach ($WmiFilter in $WmiFilters) {
                                        $inObj = [ordered] @{
                                            'Name' = $WmiFilter.'msWMI-Name'
                                            'Author' = $WmiFilter.'msWMI-Author'
                                            'Query' = $WmiFilter.'msWMI-Parm2'
                                            'Description' = $WmiFilter.'msWMI-Parm1'
                                        }
                                        $OutObj = [pscustomobject](ConvertTo-HashToYN $inObj)

                                        if ($HealthCheck.Domain.GPO) {
                                            $OutObj | Where-Object { $_.'Description' -eq "--" } | Set-Style -Style Warning -Property 'Description'
                                        }

                                        $TableParams = @{
                                            Name = "WMI Filter - $($WmiFilter.'msWMI-Name')"
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
                                Write-PScriboMessage -IsWarning "No WMI Filter information found in $Domain, disabling the section."
                            }
                        } catch {
                            Write-PScriboMessage -IsWarning "$($_.Exception.Message) (WMI Filters)"
                        }
                    }
                    try {
                        $PATH = "\\$Domain\SYSVOL\$Domain\Policies\PolicyDefinitions"
                        $CentralStore = Invoke-Command -Session $TempPssSession -ScriptBlock { Test-Path $using:PATH }
                        if ($PATH) {
                            Section -Style Heading5 "Central Store Repository" {
                                $OutObj = @()
                                $inObj = [ordered] @{
                                    'Domain' = $Domain.ToString().ToUpper()
                                    'Configured' = $CentralStore
                                    'Central Store Path' = "\\$Domain\SYSVOL\$Domain\Policies\PolicyDefinitions"
                                }
                                $OutObj = [pscustomobject](ConvertTo-HashToYN $inObj)

                                if ($HealthCheck.Domain.GPO) {
                                    $OutObj | Where-Object { $_.'Configured' -eq 'No' } | Set-Style -Style Warning -Property 'Configured'
                                }

                                $TableParams = @{
                                    Name = "GPO Central Store - $($Domain.ToString().ToUpper())"
                                    List = $false
                                    ColumnWidths = 25, 15, 60
                                }

                                if ($Report.ShowTableCaptions) {
                                    $TableParams['Caption'] = "- $($TableParams.Name)"
                                }
                                $OutObj | Table @TableParams
                                if ($HealthCheck.Domain.GPO -and ($OutObj | Where-Object { $_.'Configured' -eq 'No' })) {
                                    Paragraph "Health Check:" -Bold -Underline
                                    BlankLine
                                    Paragraph {
                                        Text "Best Practices:" -Bold
                                        Text "The group policy central store is a central location to store all the group policy template files. This eliminates the need for admins to load and open group policy template files on systems used to manage group policy. Ensure Central Store is deployed to centralized GPO repository."
                                    }
                                }
                            }
                        } else {
                            Write-PScriboMessage -IsWarning "No GPO Central Store information found in $Domain, disabling the section."
                        }
                    } catch {
                        Write-PScriboMessage -IsWarning "$($_.Exception.Message) (GPO Central Store)"
                    }
                    try {
                        if ($GPOs) {
                            $OutObj = @()
                            foreach ($GPO in $GPOs) {
                                try {
                                    [xml]$Gpoxml = Invoke-Command -Session $TempPssSession -ScriptBlock { Get-GPOReport -Domain $using:Domain -ReportType Xml -Guid ($using:GPO).Id }
                                    $UserScripts = $Gpoxml.GPO.User.ExtensionData | Where-Object { $_.Name -eq 'Scripts' }
                                    if ($UserScripts.extension.Script) {
                                        foreach ($Script in $UserScripts.extension.Script) {
                                            try {
                                                $inObj = [ordered] @{
                                                    'GPO Name' = $GPO.DisplayName
                                                    'GPO Status' = ($GPO.GpoStatus -creplace '([A-Z\W_]|\d+)(?<![a-z])', ' $&').trim()
                                                    'Type' = $Script.Type
                                                    'Script' = $Script.command
                                                }
                                                $OutObj += [pscustomobject](ConvertTo-HashToYN $inObj)
                                            } catch {
                                                Write-PScriboMessage -IsWarning $_.Exception.Message
                                            }
                                        }
                                    }
                                } catch {
                                    Write-PScriboMessage -IsWarning "$($_.Exception.Message) (GPO with Logon/Logoff Script Item)"
                                }
                            }
                        }
                        if ($OutObj) {
                            Section -Style Heading5 "Logon/Logoff Script" {
                                if ($HealthCheck.Domain.GPO) {
                                    $OutObj | Where-Object { $_.'GPO Status' -like 'All Settings Disabled' } | Set-Style -Style Warning -Property 'GPO Status'
                                }

                                $TableParams = @{
                                    Name = "GPO with Logon/Logoff Script - $($Domain.ToString().ToUpper())"
                                    List = $false
                                    ColumnWidths = 20, 15, 15, 50
                                }

                                if ($Report.ShowTableCaptions) {
                                    $TableParams['Caption'] = "- $($TableParams.Name)"
                                }
                                $OutObj | Sort-Object -Property 'GPO Name' | Table @TableParams
                            }
                        } else {
                            Write-PScriboMessage -IsWarning "No GPO Logon/Logoff script information found in $Domain, disabling the section."
                        }
                    } catch {
                        Write-PScriboMessage -IsWarning "$($_.Exception.Message) (GPO with Logon/Logoff Script Section)"
                    }
                    try {
                        if ($GPOs) {
                            $OutObj = @()
                            foreach ($GPO in $GPOs) {
                                try {
                                    [xml]$Gpoxml = Invoke-Command -Session $TempPssSession -ScriptBlock { Get-GPOReport -Domain $using:Domain -ReportType Xml -Guid ($using:GPO).Id }
                                    $ComputerScripts = $Gpoxml.GPO.Computer.ExtensionData | Where-Object { $_.Name -eq 'Scripts' }
                                    if ($ComputerScripts.extension.Script) {
                                        foreach ($Script in $ComputerScripts.extension.Script) {
                                            try {
                                                $inObj = [ordered] @{
                                                    'GPO Name' = $GPO.DisplayName
                                                    'GPO Status' = ($GPO.GpoStatus -creplace '([A-Z\W_]|\d+)(?<![a-z])', ' $&').trim()
                                                    'Type' = $Script.Type
                                                    'Script' = $Script.command
                                                }
                                                $OutObj += [pscustomobject](ConvertTo-HashToYN $inObj)
                                            } catch {
                                                Write-PScriboMessage -IsWarning "$($_.Exception.Message) (GPO with Computer Startup/Shutdown Script Item)"
                                            }
                                        }
                                    }
                                } catch {
                                    Write-PScriboMessage -IsWarning "$($_.Exception.Message) (GPO with Computer Startup/Shutdown Script)"
                                }
                            }
                        }
                        if ($OutObj) {
                            Section -Style Heading5 "Startup/Shutdown Script" {
                                if ($HealthCheck.Domain.GPO) {
                                    $OutObj | Where-Object { $_.'GPO Status' -like 'All Settings Disabled' } | Set-Style -Style Warning -Property 'GPO Status'
                                }

                                $TableParams = @{
                                    Name = "GPO with Startup/Shutdown Script - $($Domain.ToString().ToUpper())"
                                    List = $false
                                    ColumnWidths = 20, 15, 15, 50
                                }

                                if ($Report.ShowTableCaptions) {
                                    $TableParams['Caption'] = "- $($TableParams.Name)"
                                }
                                $OutObj | Sort-Object -Property 'GPO Name' | Table @TableParams
                            }

                        } else {
                            Write-PScriboMessage -IsWarning "No GPO Computer Startup/Shutdown script information found in $Domain, disabling the section."
                        }
                    } catch {
                        Write-PScriboMessage -IsWarning "$($_.Exception.Message) (GPO with Computer Startup/Shutdown Script Section)"
                    }
                }
                if ($HealthCheck.Domain.GPO) {
                    try {
                        $OutObj = @()
                        if ($GPOs) {
                            foreach ($GPO in $GPOs) {
                                try {
                                    [xml]$Gpoxml = Invoke-Command -Session $TempPssSession -ScriptBlock { Get-GPOReport -Domain $using:Domain -ReportType Xml -Guid ($using:GPO).Id }
                                    if (($Null -ne $Gpoxml.GPO.Name) -and ($Null -eq $Gpoxml.GPO.LinksTo.SOMPath)) {
                                        $inObj = [ordered] @{
                                            'GPO Name' = $Gpoxml.GPO.Name
                                            'Created' = ($Gpoxml.GPO.CreatedTime).ToString().split("T")[0]
                                            'Modified' = ($Gpoxml.GPO.ModifiedTime).ToString().split("T")[0]
                                            'Computer Enabled' = $gpoxml.GPO.Computer.Enabled
                                            'User Enabled' = $gpoxml.GPO.User.Enabled
                                        }
                                        $OutObj += [pscustomobject](ConvertTo-HashToYN $inObj)
                                    }
                                } catch {
                                    Write-PScriboMessage -IsWarning "$($_.Exception.Message) (Unlinked Group Policy Objects Item)"
                                }
                            }
                        }
                        if ($OutObj) {
                            Section -Style Heading5 "Unlinked GPO" {
                                if ($HealthCheck.Domain.GPO) {
                                    $OutObj | Set-Style -Style Warning
                                }

                                $TableParams = @{
                                    Name = "Unlinked GPO - $($Domain.ToString().ToUpper())"
                                    List = $false
                                    ColumnWidths = 40, 15, 15, 15, 15
                                }

                                if ($Report.ShowTableCaptions) {
                                    $TableParams['Caption'] = "- $($TableParams.Name)"
                                }
                                $OutObj | Sort-Object -Property 'GPO Name' | Table @TableParams
                                Paragraph "Health Check:" -Bold -Underline
                                BlankLine
                                Paragraph {
                                    Text "Corrective Actions:" -Bold
                                    Text "Remove Unused GPO from Active Directory."
                                }
                            }
                        } else {
                            Write-PScriboMessage -IsWarning "No Unlinked Group Policy Objects information found in $Domain, disabling the section."
                        }
                    } catch {
                        Write-PScriboMessage -IsWarning "$($_.Exception.Message) (Unlinked Group Policy Objects Section)"
                    }
                    try {
                        $OutObj = @()
                        if ($GPOs) {
                            foreach ($GPO in $GPOs) {
                                try {
                                    [xml]$Gpoxml = Invoke-Command -Session $TempPssSession -ScriptBlock { Get-GPOReport -Domain $using:Domain -ReportType Xml -Guid ($using:GPO).Id }
                                    if (($Null -eq ($Gpoxml.GPO.Computer.ExtensionData)) -and ($Null -eq ($Gpoxml.GPO.User.extensionData))) {
                                        $inObj = [ordered] @{
                                            'GPO Name' = $Gpoxml.GPO.Name
                                            'Created' = ($Gpoxml.GPO.CreatedTime).ToString().split("T")[0]
                                            'Modified' = ($Gpoxml.GPO.ModifiedTime).ToString().split("T")[0]
                                            'Description' = $Gpoxml.GPO.Description
                                        }
                                        $OutObj += [pscustomobject](ConvertTo-HashToYN $inObj)
                                    }
                                } catch {
                                    Write-PScriboMessage -IsWarning "$($_.Exception.Message) (Empty Group Policy Objects Item)"
                                }
                            }
                        }
                        if ($OutObj) {
                            Section -Style Heading5 "Empty GPOs" {
                                if ($HealthCheck.Domain.GPO) {
                                    $OutObj | Set-Style -Style Warning
                                }

                                $TableParams = @{
                                    Name = "Empty GPO - $($Domain.ToString().ToUpper())"
                                    List = $false
                                    ColumnWidths = 35, 15, 15, 35
                                }

                                if ($Report.ShowTableCaptions) {
                                    $TableParams['Caption'] = "- $($TableParams.Name)"
                                }
                                $OutObj | Sort-Object -Property 'GPO Name' | Table @TableParams
                                Paragraph "Health Check:" -Bold -Underline
                                BlankLine
                                Paragraph {
                                    Text "Corrective Actions:" -Bold
                                    Text "No User and Computer parameters are set: Remove Unused GPO in Active Directory."
                                }
                            }
                        } else {
                            Write-PScriboMessage -IsWarning "No Empty GPO information found in $Domain, disabling the section."
                        }
                    } catch {
                        Write-PScriboMessage -IsWarning "$($_.Exception.Message) (Empty Group Policy Objects Section)"
                    }
                    try {
                        $OutObj = @()
                        $DM = Invoke-Command -Session $TempPssSession { Get-ADDomain -Identity $using:Domain }
                        $DCList = $DM.ReplicaDirectoryServers | Select-Object -First 1

                        $DC = foreach ($TestedDC in $DCList) {
                            if (Test-WSMan -ComputerName $TestedDC -ErrorAction SilentlyContinue) {
                                Write-PScriboMessage "Using $TestedDC to retreive Enforced Group Policy Objects information on $Domain."
                                $TestedDC
                                break
                            } else {
                                Write-PScriboMessage "Unable to connect to $TestedDC to retreive Enforced Group Policy Objects information on $Domain."
                            }
                        }
                        $OUs = (Invoke-Command -Session $TempPssSession -ScriptBlock { Get-ADOrganizationalUnit -Server $using:DC -Filter * }).DistinguishedName
                        if ($OUs) {
                            $OUs += $DM.DistinguishedName
                        }
                        if ($OUs) {
                            foreach ($OU in $OUs) {
                                try {
                                    $GpoEnforces = Invoke-Command -Session $TempPssSession -ErrorAction Stop  -ScriptBlock { Get-GPInheritance -Domain $using:Domain -Server $using:DC -Target $using:OU | Select-Object -ExpandProperty GpoLinks }
                                    foreach ($GpoEnforced in $GpoEnforces) {
                                        if ($GpoEnforced.Enforced -eq "True") {
                                            $TargetCanonical = Invoke-Command -Session $TempPssSession -ScriptBlock { Get-ADObject -Server $using:DC -Identity ($using:GpoEnforced).Target -Properties * | Select-Object -ExpandProperty CanonicalName }
                                            $inObj = [ordered] @{
                                                'GPO Name' = $GpoEnforced.DisplayName
                                                'Target' = $TargetCanonical
                                            }
                                            $OutObj += [pscustomobject](ConvertTo-HashToYN $inObj)
                                        }
                                    }
                                } catch {
                                    Write-PScriboMessage -IsWarning "$($_.Exception.Message) (Enforced Group Policy Objects Item)"
                                }
                            }
                        }

                        if ($OutObj) {
                            Section -Style Heading5 "Enforced GPO" {
                                if ($HealthCheck.Domain.GPO) {
                                    $OutObj | Set-Style -Style Warning
                                }

                                $TableParams = @{
                                    Name = "Enforced GPO - $($Domain.ToString().ToUpper())"
                                    List = $false
                                    ColumnWidths = 50, 50
                                }

                                if ($Report.ShowTableCaptions) {
                                    $TableParams['Caption'] = "- $($TableParams.Name)"
                                }
                                $OutObj | Sort-Object -Property 'Target' | Table @TableParams
                                Paragraph "Health Check:" -Bold -Underline
                                BlankLine
                                Paragraph {
                                    Text "Corrective Actions:" -Bold
                                    Text "Review use of enforcement and blocked policy inheritance in Active Directory."
                                }

                            }
                        } else {
                            Write-PScriboMessage -IsWarning "No Enforced GPO information found in $Domain, disabling the section."
                        }
                    } catch {
                        Write-PScriboMessage -IsWarning "$($_.Exception.Message) (Enforced Group Policy Objects Table)"
                    }
                    # Code taken from Jeremy Saunders
                    # https://github.com/jeremyts/ActiveDirectoryDomainServices/blob/master/Audit/FindOrphanedGPOs.ps1
                    try {
                        $DCList = Invoke-Command -Session $TempPssSession { (Get-ADDomain -Identity $using:Domain).ReplicaDirectoryServers }

                        $DC = foreach ($TestedDC in $DCList) {
                            if (Test-WSMan -ComputerName $TestedDC -ErrorAction SilentlyContinue) {
                                Write-PScriboMessage "Using $TestedDC to retreive Orphaned GPO information on $Domain."
                                $TestedDC
                                break
                            } else {
                                Write-PScriboMessage "Unable to connect to $TestedDC to retreive Orphaned GPO information on $Domain."
                            }
                        }
                        $DCPssSession = try { New-PSSession -ComputerName $DC -Credential $Credential -Authentication $Options.PSDefaultAuthentication -Name 'OrphanedGPO' -ErrorAction Stop } catch {
                            if (-Not $_.Exception.MessageId) {
                                $ErrorMessage = $_.FullyQualifiedErrorId
                            } else {$ErrorMessage = $_.Exception.MessageId}
                            Write-PScriboMessage -IsWarning "Orphaned GPO Section: New-PSSession: Unable to connect to $($DC): $ErrorMessage"
                        }
                        $DomainInfo = Invoke-Command -Session $TempPssSession { Get-ADDomain $using:Domain -ErrorAction Stop }
                        $GPOPoliciesSYSVOLUNC = "\\$Domain\SYSVOL\$Domain\Policies"
                        $OrphanGPOs = @()
                        if ($DCPssSession) {
                            $GPOPoliciesADSI = (Get-ADObjectSearch -DN "CN=Policies,CN=System,$($DomainInfo.DistinguishedName)" -Filter { objectClass -eq "groupPolicyContainer" } -Properties "Name" -SelectPrty 'Name' -Session $DCPssSession).Name.Trim("{}") | Sort-Object

                            Remove-PSSession -Session $DCPssSession
                        }
                        $GPOPoliciesSYSVOL = (Invoke-Command -Session $TempPssSession -ScriptBlock { Get-ChildItem $using:GPOPoliciesSYSVOLUNC | Sort-Object }).Name.Trim("{}")
                        $SYSVOLGPOList = @()
                        ForEach ($GPOinSYSVOL in $GPOPoliciesSYSVOL) {
                            If ($GPOinSYSVOL -ne "PolicyDefinitions") {
                                $SYSVOLGPOList += $GPOinSYSVOL
                            }
                        }
                        if ($GPOPoliciesADSI -and $SYSVOLGPOList) {
                            $MissingADGPOs = Compare-Object $SYSVOLGPOList $GPOPoliciesADSI -PassThru | Where-Object { $_.SideIndicator -eq '<=' }
                            $MissingSYSVOLGPOs = Compare-Object $GPOPoliciesADSI $SYSVOLGPOList -PassThru | Where-Object { $_.SideIndicator -eq '<=' }
                        }

                        $OrphanGPOs += $MissingADGPOs
                        $OrphanGPOs += $MissingSYSVOLGPOs
                        if ($OrphanGPOs) {
                            Section -Style Heading5 "Orphaned GPO" {
                                Paragraph "The following table summarizes the group policy objects that are orphaned or missing in the AD database or in the SYSVOL directory."
                                BlankLine
                                $OutObj = @()
                                foreach ($OrphanGPO in $OrphanGPOs) {
                                    $inObj = [ordered] @{
                                        'Name' = Switch (($GPOs | Where-Object { $_.id -eq $OrphanGPO }).DisplayName) {
                                            $Null { 'Unknown' }
                                            default { ($GPOs | Where-Object { $_.id -eq $OrphanGPO }).DisplayName }
                                        }
                                        'Guid' = $OrphanGPO
                                        'AD DN Database' = & {
                                            if ($OrphanGPO -in $MissingADGPOs) {
                                                return "Missing"
                                            } else { 'Valid' }
                                        }
                                        'AD DN Path' = & {
                                            if ($OrphanGPO -in $MissingADGPOs) {
                                                return "CN={$($OrphanGPO)},CN=Policies,CN=System,$($DomainInfo.DistinguishedName) (Missing)"
                                            } else { "CN={$($OrphanGPO)},CN=Policies,CN=System,$($DomainInfo.DistinguishedName) (Valid)" }
                                        }
                                        'SYSVOL Guid Directory' = & {
                                            if ($OrphanGPO -in $MissingSYSVOLGPOs) {
                                                return "Missing"
                                            } else { 'Valid' }
                                        }
                                        'SYSVOL Guid Path' = & {
                                            if ($OrphanGPO -in $MissingSYSVOLGPOs) {
                                                return "\\$Domain\SYSVOL\$Domain\Policies\{$($OrphanGPO)} (Missing)"
                                            } else { "\\$Domain\SYSVOL\$Domain\Policies\{$($OrphanGPO)} (Valid)" }
                                        }
                                    }
                                    $OutObj = [pscustomobject](ConvertTo-HashToYN $inObj)

                                    if ($HealthCheck.Domain.GPO) {
                                        $OutObj | Where-Object { $_.'AD DN Database' -eq 'Missing' } | Set-Style -Style Warning -Property 'AD DN Database', 'AD DN Path'
                                        $OutObj | Where-Object { $_.'SYSVOL Guid Directory' -eq 'Missing' } | Set-Style -Style Warning -Property 'SYSVOL Guid Directory', 'SYSVOL Guid Path'
                                    }

                                    $TableParams = @{
                                        Name = "Orphaned GPO - $($Domain.ToString().ToUpper())"
                                        List = $true
                                        ColumnWidths = 40, 60
                                    }

                                    if ($Report.ShowTableCaptions) {
                                        $TableParams['Caption'] = "- $($TableParams.Name)"
                                    }
                                    $OutObj | Table @TableParams
                                    if ($HealthCheck.Domain.GPO -and (($OutObj | Where-Object { $_.'AD DN Database' -eq 'Missing' }) -or ($OutObj | Where-Object { $_.'SYSVOL Guid Directory' -eq 'Missing' }))) {
                                        Paragraph "Health Check:" -Bold -Underline
                                        BlankLine
                                        if ($OutObj | Where-Object { $_.'AD DN Database' -eq 'Missing' }) {
                                            Paragraph {
                                                Text "Corrective Actions:" -Bold
                                                Text "Evaluate orphaned group policies objects that exist in SYSVOL but not in AD or the Group Policy Management Console (GPMC). These take up space in SYSVOL and bandwidth during replication."
                                            }
                                            BlankLine
                                        }
                                        if ($OutObj | Where-Object { $_.'SYSVOL Guid Directory' -eq 'Missing' }) {
                                            Paragraph {
                                                Text "Corrective Actions:" -Bold
                                                Text "Evaluate orphaned group policies folders and files that exist in AD or the Group Policy Management Console (GPMC) but not in SYSVOL. These take up space in the AD database and bandwidth during replication."
                                            }
                                            BlankLine
                                        }
                                    }
                                }
                            }
                        } else {
                            Write-PScriboMessage -IsWarning "No Orphaned GPO information found in $Domain, disabling the section."
                        }
                    } catch {
                        Write-PScriboMessage -IsWarning "$($_.Exception.Message) (Orphaned GPO)"
                    }
                }
            }
        } catch {
            Write-PScriboMessage -IsWarning "$($_.Exception.Message) (Group Policy Objects Section)"
        }
    }


    end {}

}