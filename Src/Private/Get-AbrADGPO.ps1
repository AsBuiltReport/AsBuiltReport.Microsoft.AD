function Get-AbrADGPO {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft Active Directory Group Policy Objects information.
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
        [string]$ValidDCFromDomain
    )

    begin {
        Write-PScriboMessage "Collecting Active Directory Group Policy Objects information for $($Domain.DNSRoot.ToString().ToUpper())."
    }

    process {
        try {
            Section -Style Heading4 "Group Policy Objects" {
                Paragraph "The following section provides a summary of the Group Policy Objects for domain $($Domain.DNSRoot.ToString().ToUpper())."
                BlankLine
                $OutObj = @()
                $GPOs = Invoke-Command -Session $TempPssSession -ScriptBlock { Get-GPO -Domain ($using:Domain).DNSRoot -All }
                if ($GPOs) {
                    if ($InfoLevel.Domain -eq 1) {
                        try {
                            foreach ($GPO in $GPOs) {
                                try {
                                    [xml]$Links = Invoke-Command -Session $TempPssSession -ScriptBlock { $using:GPO | Get-GPOReport -Domain ($using:Domain).DNSRoot -ReportType XML }
                                    $inObj = [ordered] @{
                                        'GPO Name' = $GPO.DisplayName
                                        'GPO Status' = ($GPO.GpoStatus -creplace '([A-Z\W_]|\d+)(?<![a-z])', ' $&').trim()
                                        'Security Filtering' = & {
                                            $GPOSECFILTER = Invoke-Command -Session $TempPssSession -ScriptBlock { (Get-GPPermission -DomainName ($using:Domain).DNSRoot -All -Guid ($using:GPO).ID | Where-Object { $_.Permission -eq 'GpoApply' }).Trustee.Name }
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
                                Name = "GPO - $($Domain.DNSRoot.ToString().ToUpper())"
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
                                        Text "Ensure 'All Settings Disabled' Group Policy Objects (GPOs) are removed from Active Directory. These GPOs do not apply any settings and can cause confusion or clutter in the environment."
                                    }
                                    BlankLine
                                }
                                if (($OutObj | Where-Object { $_.'Security Filtering' -like 'No Security Filtering' })) {
                                    Paragraph {
                                        Text "Corrective Actions:" -Bold
                                        Text "Identify 'No Security Filtering' Group Policy Objects (GPOs) that are not linked to any security groups or users. Determine which of these GPOs should be deleted to reduce clutter and improve manageability in Active Directory."
                                    }
                                    BlankLine
                                }
                                if ($OutObj | Where-Object { $_.'Links Count' -eq '0' }) {
                                    Paragraph {
                                        Text "Corrective Actions:" -Bold
                                        Text "Ensure unused or unlinked Group Policy Objects (GPOs) are removed from Active Directory. These GPOs do not apply any settings and can cause unnecessary complexity and potential confusion in the environment. Regularly review and clean up GPOs to maintain an organized and efficient Active Directory structure."
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
                                        [xml]$Links = Invoke-Command -Session $TempPssSession -ScriptBlock { $using:GPO | Get-GPOReport -Domain ($using:Domain).DNSRoot -ReportType XML }
                                        $inObj = [ordered] @{
                                            'GPO Status' = ($GPO.GpoStatus -creplace '([A-Z\W_]|\d+)(?<![a-z])', ' $&').trim()
                                            'GUID' = $GPO.Id
                                            'Created' = $GPO.CreationTime.ToString("MM/dd/yyyy")
                                            'Modified' = $GPO.ModificationTime.ToString("MM/dd/yyyy")
                                            'Owner' = $GPO.Owner
                                            'Computer Version' = "$($Links.GPO.Computer.VersionDirectory) (AD), $($Links.GPO.Computer.VersionSysvol) (SYSVOL)"
                                            'User Version' = "$($Links.GPO.User.VersionDirectory) (AD), $($Links.GPO.User.VersionSysvol) (SYSVOL)"
                                            'WMI Filter' = & {
                                                $WMIFilter = Invoke-Command -Session $TempPssSession -ScriptBlock { ((Get-GPO -DomainName $($using:Domain).DNSROot  -Name $using:GPO.DisplayName).WMifilter.Name) }
                                                if ($WMIFilter) {
                                                    $WMIFilter
                                                } else { '--' }
                                            }
                                            'Security Filtering' = & {
                                                $GPOSECFILTER = Invoke-Command -Session $TempPssSession -ScriptBlock { (Get-GPPermission -DomainName ($using:Domain).DNSROot -All -Guid ($using:GPO).ID | Where-Object { $_.Permission -eq 'GpoApply' }).Trustee.Name }
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
                                                    Text "Ensure 'All Settings Disabled' Group Policy Objects (GPOs) are removed from Active Directory. These GPOs do not apply any settings and can cause confusion or clutter in the environment."
                                                }
                                                BlankLine
                                            }
                                            if (($OutObj | Where-Object { $_.'Security Filtering' -like 'No Security Filtering' })) {
                                                Paragraph {
                                                    Text "Corrective Actions:" -Bold
                                                    Text "Identify 'No Security Filtering' Group Policy Objects (GPOs) that are not linked to any security groups or users. Determine which of these GPOs should be deleted to reduce clutter and improve manageability in Active Directory."
                                                }
                                                BlankLine
                                            }
                                            if ($OutObj | Where-Object { $_.'Linked Target' -eq '--' }) {
                                                Paragraph {
                                                    Text "Corrective Actions:" -Bold
                                                    Text "Ensure unused or unlinked Group Policy Objects (GPOs) are removed from Active Directory. These GPOs do not apply any settings and can cause unnecessary complexity and potential confusion in the environment. Regularly review and clean up GPOs to maintain an organized and efficient Active Directory structure."
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
                            $DCPssSession = Get-ValidPSSession -ComputerName $ValidDCFromDomain -SessionName $($ValidDCFromDomain) -PSSTable ([ref]$PSSTable)

                            if ($DCPssSession) {
                                $WmiFilters = Get-ADObjectSearch -DN "CN=SOM,CN=WMIPolicy,CN=System,$($Domain.DistinguishedName)" -Filter { objectClass -eq "msWMI-Som" } -SelectPrty '*' -Session $DCPssSession | Sort-Object

                            } else {
                                if (-Not $_.Exception.MessageId) {
                                    $ErrorMessage = $_.FullyQualifiedErrorId
                                } else { $ErrorMessage = $_.Exception.MessageId }
                                Write-PScriboMessage -IsWarning "Wmi Filters Section: New-PSSession: Unable to connect to $($ValidDCFromDomain): $ErrorMessage"
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
                                Write-PScriboMessage "No WMI Filter information found in $($Domain.DNSRoot), Disabling this section."
                            }
                        } catch {
                            Write-PScriboMessage -IsWarning "$($_.Exception.Message) (WMI Filters)"
                        }
                    }
                    try {
                        $PATH = "\\$($Domain.DNSRoot)\SYSVOL\$($Domain.DNSRoot)\Policies\PolicyDefinitions"
                        $CentralStore = Invoke-Command -Session $TempPssSession -ScriptBlock { Test-Path $using:PATH }
                        if ($PATH) {
                            Section -Style Heading5 "Central Store Repository" {
                                $OutObj = @()
                                $inObj = [ordered] @{
                                    'Domain' = $Domain.Name.ToString().ToUpper()
                                    'Configured' = $CentralStore
                                    'Central Store Path' = "\\$($Domain.DNSRoot)\SYSVOL\$($Domain.DNSRoot)\Policies\PolicyDefinitions"
                                }
                                $OutObj = [pscustomobject](ConvertTo-HashToYN $inObj)

                                if ($HealthCheck.Domain.GPO) {
                                    $OutObj | Where-Object { $_.'Configured' -eq 'No' } | Set-Style -Style Warning -Property 'Configured'
                                }

                                $TableParams = @{
                                    Name = "GPO Central Store - $($Domain.DNSRoot.ToString().ToUpper())"
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
                                        Text "The Group Policy Central Store is a central location to store all the Group Policy template files (ADMX/ADML files). This eliminates the need for administrators to load and open Group Policy template files on each system used to manage Group Policy. Ensure the Central Store is deployed to a centralized GPO repository to streamline management and ensure consistency across the environment."
                                    }
                                }
                            }
                        } else {
                            Write-PScriboMessage "No GPO Central Store information found in $($Domain.DNSRoot), Disabling this section."
                        }
                    } catch {
                        Write-PScriboMessage -IsWarning "$($_.Exception.Message) (GPO Central Store)"
                    }
                    try {
                        if ($GPOs) {
                            $OutObj = @()
                            foreach ($GPO in $GPOs) {
                                try {
                                    [xml]$Gpoxml = Invoke-Command -Session $TempPssSession -ScriptBlock { Get-GPOReport -Domain ($using:Domain).DNSROot -ReportType Xml -Guid ($using:GPO).Id }
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
                                    Name = "GPO with Logon/Logoff Script - $($Domain.DNSRoot.ToString().ToUpper())"
                                    List = $false
                                    ColumnWidths = 20, 15, 15, 50
                                }

                                if ($Report.ShowTableCaptions) {
                                    $TableParams['Caption'] = "- $($TableParams.Name)"
                                }
                                $OutObj | Sort-Object -Property 'GPO Name' | Table @TableParams
                            }
                        } else {
                            Write-PScriboMessage "No GPO Logon/Logoff script information found in $($Domain.DNSRoot), Disabling this section."
                        }
                    } catch {
                        Write-PScriboMessage -IsWarning "$($_.Exception.Message) (GPO with Logon/Logoff Script Section)"
                    }
                    try {
                        if ($GPOs) {
                            $OutObj = @()
                            foreach ($GPO in $GPOs) {
                                try {
                                    [xml]$Gpoxml = Invoke-Command -Session $TempPssSession -ScriptBlock { Get-GPOReport -Domain ($using:Domain).DNSROot -ReportType Xml -Guid ($using:GPO).Id }
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
                                    Name = "GPO with Startup/Shutdown Script - $($Domain.DNSRoot.ToString().ToUpper())"
                                    List = $false
                                    ColumnWidths = 20, 15, 15, 50
                                }

                                if ($Report.ShowTableCaptions) {
                                    $TableParams['Caption'] = "- $($TableParams.Name)"
                                }
                                $OutObj | Sort-Object -Property 'GPO Name' | Table @TableParams
                            }

                        } else {
                            Write-PScriboMessage "No GPO Computer Startup/Shutdown script information found in $($Domain.DNSRoot), Disabling this section."
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
                                    [xml]$Gpoxml = Invoke-Command -Session $TempPssSession -ScriptBlock { Get-GPOReport -Domain ($using:Domain).DNSROot -ReportType Xml -Guid ($using:GPO).Id }
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
                                    Name = "Unlinked GPO - $($Domain.DNSRoot.ToString().ToUpper())"
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
                                    Text "Remove unused Group Policy Objects (GPOs) from Active Directory. Unused GPOs can create unnecessary complexity and potential confusion. Regularly review and clean up GPOs to maintain an organized and efficient Active Directory environment."
                                }
                            }
                        } else {
                            Write-PScriboMessage "No Unlinked Group Policy Objects information found in $($Domain.DNSRoot), Disabling this section."
                        }
                    } catch {
                        Write-PScriboMessage -IsWarning "$($_.Exception.Message) (Unlinked Group Policy Objects Section)"
                    }
                    try {
                        $OutObj = @()
                        if ($GPOs) {
                            foreach ($GPO in $GPOs) {
                                try {
                                    [xml]$Gpoxml = Invoke-Command -Session $TempPssSession -ScriptBlock { Get-GPOReport -Domain ($using:Domain).DNSROot -ReportType Xml -Guid ($using:GPO).Id }
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
                                    Name = "Empty GPO - $($Domain.DNSRoot.ToString().ToUpper())"
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
                                    Text "No user or computer parameters are set in this GPO. Remove unused GPOs in Active Directory to reduce clutter and improve manageability."
                                }
                            }
                        } else {
                            Write-PScriboMessage "No Empty GPO information found in $($Domain.DNSRoot), Disabling this section."
                        }
                    } catch {
                        Write-PScriboMessage -IsWarning "$($_.Exception.Message) (Empty Group Policy Objects Section)"
                    }
                    try {
                        $OutObj = @()

                        $OUs = (Invoke-Command -Session $TempPssSession -ScriptBlock { Get-ADOrganizationalUnit -Server $using:ValidDCFromDomain -Filter * }).DistinguishedName
                        if ($OUs) {
                            $OUs += $Domain.DistinguishedName
                        }
                        if ($OUs) {
                            foreach ($OU in $OUs) {
                                try {
                                    $GpoEnforces = Invoke-Command -Session $TempPssSession -ErrorAction Stop  -ScriptBlock { Get-GPInheritance -Domain ($using:Domain).DNSRoot -Server $using:ValidDCFromDomain -Target $using:OU | Select-Object -ExpandProperty GpoLinks }
                                    foreach ($GpoEnforced in $GpoEnforces) {
                                        if ($GpoEnforced.Enforced -eq "True") {
                                            $TargetCanonical = Invoke-Command -Session $TempPssSession -ScriptBlock { Get-ADObject -Server $using:ValidDCFromDomain -Identity ($using:GpoEnforced).Target -Properties * | Select-Object -ExpandProperty CanonicalName }
                                            $inObj = [ordered] @{
                                                'GPO Name' = $GpoEnforced.DisplayName
                                                'Target' = $TargetCanonical
                                            }
                                            $OutObj += [pscustomobject](ConvertTo-HashToYN $inObj)
                                        }
                                    }
                                } catch {
                                    Write-PScriboMessage -IsWarning "OU: $($OU): $($_.Exception.Message) (Enforced Group Policy Objects Item)"
                                }
                            }
                        }

                        if ($OutObj) {
                            Section -Style Heading5 "Enforced GPO" {
                                if ($HealthCheck.Domain.GPO) {
                                    $OutObj | Set-Style -Style Warning
                                }

                                $TableParams = @{
                                    Name = "Enforced GPO - $($Domain.DNSRoot.ToString().ToUpper())"
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
                                    Text "Review the use of enforcement and blocked policy inheritance in Active Directory. Enforced policies ensure that critical settings are applied consistently across the organization, while blocked policy inheritance can prevent higher-level policies from affecting specific organizational units. Proper use of these settings is essential for maintaining a secure and well-managed environment."
                                }

                            }
                        } else {
                            Write-PScriboMessage "No Enforced GPO information found in $($Domain.DNSRoot), Disabling this section."
                        }
                    } catch {
                        Write-PScriboMessage -IsWarning "$($_.Exception.Message) (Enforced Group Policy Objects Table)"
                    }
                    # Code taken from Jeremy Saunders
                    # https://github.com/jeremyts/ActiveDirectoryDomainServices/blob/master/Audit/FindOrphanedGPOs.ps1
                    try {
                        $DCPssSession = Get-ValidPSSession -ComputerName $ValidDCFromDomain -SessionName $($ValidDCFromDomain) -PSSTable ([ref]$PSSTable)

                        if ($DCPssSession) {
                            $GPOPoliciesADSI = (Get-ADObjectSearch -DN "CN=Policies,CN=System,$($Domain.DistinguishedName)" -Filter { objectClass -eq "groupPolicyContainer" } -Properties "Name" -SelectPrty 'Name' -Session $DCPssSession).Name.Trim("{}") | Sort-Object

                        } else {
                            if (-Not $_.Exception.MessageId) {
                                $ErrorMessage = $_.FullyQualifiedErrorId
                            } else { $ErrorMessage = $_.Exception.MessageId }
                            Write-PScriboMessage -IsWarning "Orphaned GPO Section: New-PSSession: Unable to connect to $($ValidDCFromDomain): $ErrorMessage"
                        }
                        $GPOPoliciesSYSVOLUNC = "\\$($Domain.DNSRoot)\SYSVOL\$($Domain.DNSRoot)\Policies"
                        $OrphanGPOs = @()
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
                                                return "CN={$($OrphanGPO)},CN=Policies,CN=System,$($Domain.DistinguishedName) (Missing)"
                                            } else { "CN={$($OrphanGPO)},CN=Policies,CN=System,$($Domain.DistinguishedName) (Valid)" }
                                        }
                                        'SYSVOL Guid Directory' = & {
                                            if ($OrphanGPO -in $MissingSYSVOLGPOs) {
                                                return "Missing"
                                            } else { 'Valid' }
                                        }
                                        'SYSVOL Guid Path' = & {
                                            if ($OrphanGPO -in $MissingSYSVOLGPOs) {
                                                return "\\$($Domain.DNSRoot)\SYSVOL\$($Domain.DNSRoot)\Policies\{$($OrphanGPO)} (Missing)"
                                            } else { "\\$($Domain.DNSRoot)\SYSVOL\$($Domain.DNSRoot)\Policies\{$($OrphanGPO)} (Valid)" }
                                        }
                                    }
                                    $OutObj = [pscustomobject](ConvertTo-HashToYN $inObj)

                                    if ($HealthCheck.Domain.GPO) {
                                        $OutObj | Where-Object { $_.'AD DN Database' -eq 'Missing' } | Set-Style -Style Warning -Property 'AD DN Database', 'AD DN Path'
                                        $OutObj | Where-Object { $_.'SYSVOL Guid Directory' -eq 'Missing' } | Set-Style -Style Warning -Property 'SYSVOL Guid Directory', 'SYSVOL Guid Path'
                                    }

                                    $TableParams = @{
                                        Name = "Orphaned GPO - $($Domain.DNSRoot.ToString().ToUpper())"
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
                                                Text "Evaluate orphaned group policies objects that exist in SYSVOL but not in AD or the Group Policy Management Console (GPMC). These take up space in SYSVOL and bandwidth during replication. Ensure that these orphaned objects are reviewed and removed if they are no longer needed to maintain a clean and efficient Active Directory environment."
                                            }
                                            BlankLine
                                        }
                                        if ($OutObj | Where-Object { $_.'SYSVOL Guid Directory' -eq 'Missing' }) {
                                            Paragraph {
                                                Text "Corrective Actions:" -Bold
                                                Text "Evaluate orphaned group policies folders and files that exist in AD or the Group Policy Management Console (GPMC) but not in SYSVOL. These take up space in the AD database and bandwidth during replication. Ensure that these orphaned objects are reviewed and removed if they are no longer needed to maintain a clean and efficient Active Directory environment."
                                            }
                                            BlankLine
                                        }
                                    }
                                }
                            }
                        } else {
                            Write-PScriboMessage "No Orphaned GPO information found in $($Domain.DNSRoot), Disabling this section."
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