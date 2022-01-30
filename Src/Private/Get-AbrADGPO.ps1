function Get-AbrADGPO {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft Active Directory Group Policy Objects information.
    .DESCRIPTION

    .NOTES
        Version:        0.6.3
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
        Write-PscriboMessage "Discovering Active Directory Group Policy Objects information for $($Domain.ToString().ToUpper())."
    }

    process {
        try {
            Section -Style Heading5 "Group Policy Objects Summary" {
                Paragraph "The following section provides a summary of the Group Policy Objects for domain $($Domain.ToString().ToUpper())."
                BlankLine
                $OutObj = @()
                $GPOs = Invoke-Command -Session $TempPssSession -ScriptBlock {Get-GPO -Domain $using:Domain -All}
                Write-PscriboMessage "Discovered Active Directory Group Policy Objects information on $Domain. (Group Policy Objects)"
                if ($GPOs) {
                    if ($InfoLevel.Domain -le 2) {
                        try {
                            foreach ($GPO in $GPOs) {
                                try {
                                    Write-PscriboMessage "Collecting Active Directory Group Policy Objects '$($GPO.DisplayName)'. (Group Policy Objects)"
                                    $inObj = [ordered] @{
                                        'GPO Name' = $GPO.DisplayName
                                        'GPO Status' = ($GPO.GpoStatus -creplace  '([A-Z\W_]|\d+)(?<![a-z])',' $&').trim()
                                        'Created' = $GPO.CreationTime.ToString("MM/dd/yyyy")
                                        'Modified' = $GPO.ModificationTime.ToString("MM/dd/yyyy")
                                    }
                                    $OutObj += [pscustomobject]$inobj
                                }
                                catch {
                                    Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Group Policy Objects Summary)"
                                }
                            }

                            if ($HealthCheck.Domain.GPO) {
                                $OutObj | Where-Object { $_.'GPO Status' -like 'All Settings Disabled'} | Set-Style -Style Warning -Property 'GPO Status'
                                $OutObj | Where-Object {$Null -eq $_.'Owner'} | Set-Style -Style Warning -Property 'Owner'
                            }

                            $TableParams = @{
                                Name = "GPO - $($Domain.ToString().ToUpper())"
                                List = $false
                                ColumnWidths = 45, 25, 15, 15
                            }

                            if ($Report.ShowTableCaptions) {
                                $TableParams['Caption'] = "- $($TableParams.Name)"
                            }
                            $OutObj | Sort-Object -Property 'GPO Name' | Table @TableParams
                        }
                        catch {
                            Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Group Policy Objects Summary)"
                        }
                    }
                    if ($InfoLevel.Domain -ge 3) {
                        try {
                            foreach ($GPO in $GPOs) {
                                try {
                                    Write-PscriboMessage "Collecting Active Directory Group Policy Objects '$($GPO.DisplayName)'. (Group Policy Objects)"
                                    $inObj = [ordered] @{
                                        'GPO Name' = $GPO.DisplayName
                                        'GPO Status' = ($GPO.GpoStatus -creplace  '([A-Z\W_]|\d+)(?<![a-z])',' $&').trim()
                                        'Created' = $GPO.CreationTime.ToString("MM/dd/yyyy")
                                        'Modified' = $GPO.ModificationTime.ToString("MM/dd/yyyy")
                                    }
                                    if ($InfoLevel.Domain -ge 3) {
                                        $inObj.Add('Description', $GPO.Description)
                                        $inObj.Add('Owner', $GPO.Owner)
                                    }
                                    $OutObj = [pscustomobject]$inobj

                                    if ($HealthCheck.Domain.GPO) {
                                        $OutObj | Where-Object { $_.'GPO Status' -like 'All Settings Disabled'} | Set-Style -Style Warning -Property 'GPO Status'
                                        $OutObj | Where-Object {$Null -eq $_.'Owner'} | Set-Style -Style Warning -Property 'Owner'
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
                                }
                                catch {
                                    Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Group Policy Objects Summary)"
                                }
                            }
                        }
                        catch {
                            Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Group Policy Objects Summary)"
                        }
                    }

                    try {
                        $PATH = "\\$Domain\SYSVOL\$Domain\Policies\PolicyDefinitions"
                        $CentralStore = Invoke-Command -Session $TempPssSession -ScriptBlock {Test-Path $using:PATH}
                        if ($PATH) {
                            Section -Style Heading6 "GPO Central Store Repository" {
                                Paragraph "The following section provides information of the status of Central Store. Corrective Action: Deploy centralized GPO repository."
                                BlankLine
                                $OutObj = @()
                                Write-PscriboMessage "Discovered Active Directory Central Store information on $Domain. (Central Store)"
                                $inObj = [ordered] @{
                                    'Domain' = $Domain.ToString().ToUpper()
                                    'Configured' = ConvertTo-TextYN $CentralStore
                                    'Central Store Path' = "\\$Domain\SYSVOL\$Domain\Policies\PolicyDefinitions"
                                }
                                $OutObj = [pscustomobject]$inobj

                                if ($HealthCheck.Domain.GPO) {
                                    $OutObj | Where-Object { $_.'Configured' -eq 'No'} | Set-Style -Style Warning -Property 'Configured'
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
                            }
                        }
                    }
                    catch {
                        Write-PscriboMessage -IsWarning "$($_.Exception.Message) (GPO Central Store)"
                    }
                    try {
                        if ($GPOs) {
                            Write-PscriboMessage "Discovered Active Directory Group Policy Objects information on $Domain. (Group Policy Objects)"
                            $OutObj = @()
                            foreach ($GPO in $GPOs) {
                                try {
                                    [xml]$Gpoxml =  Invoke-Command -Session $TempPssSession -ScriptBlock {Get-GPOReport -Domain $using:Domain -ReportType Xml -Guid ($using:GPO).Id}
                                    $UserScripts = $Gpoxml.GPO.User.ExtensionData | Where-Object { $_.Name -eq 'Scripts' }
                                    if ($UserScripts.extension.Script) {
                                        foreach ($Script in $UserScripts.extension.Script) {
                                            try {
                                                Write-PscriboMessage "Collecting Active Directory Group Policy Objects with Logon/Logoff Script '$($GPO.DisplayName)'."
                                                $inObj = [ordered] @{
                                                    'GPO Name' = $GPO.DisplayName
                                                    'GPO Status' = ($GPO.GpoStatus -creplace  '([A-Z\W_]|\d+)(?<![a-z])',' $&').trim()
                                                    'Type' = $Script.Type
                                                    'Script' = $Script.command
                                                }
                                                $OutObj += [pscustomobject]$inobj
                                            }
                                            catch {
                                                Write-PscriboMessage -IsWarning $_.Exception.Message
                                            }
                                        }
                                    }
                                }
                                catch {
                                    Write-PscriboMessage -IsWarning "$($_.Exception.Message) (GPO with Logon/Logoff Script Item)"
                                }
                            }
                        }
                        if ($OutObj) {
                            Section -Style Heading6 "GPO with User Logon/Logoff Script" {
                                Paragraph "The following section provides a summary of Group Policy Objects with Logon/Logoff Script."
                                BlankLine

                                if ($HealthCheck.Domain.GPO) {
                                    $OutObj | Where-Object { $_.'GPO Status' -like 'All Settings Disabled'} | Set-Style -Style Warning -Property 'GPO Status'
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
                        }
                    }
                    catch {
                        Write-PscriboMessage -IsWarning "$($_.Exception.Message) (GPO with Logon/Logoff Script Section)"
                    }
                    try {
                        if ($GPOs) {
                            $OutObj = @()
                            Write-PscriboMessage "Discovered Active Directory Group Policy Objects information on $Domain. (Group Policy Objects)"
                            foreach ($GPO in $GPOs) {
                                try {
                                    [xml]$Gpoxml =  Invoke-Command -Session $TempPssSession -ScriptBlock {Get-GPOReport -Domain $using:Domain -ReportType Xml -Guid ($using:GPO).Id}
                                    $ComputerScripts = $Gpoxml.GPO.Computer.ExtensionData | Where-Object { $_.Name -eq 'Scripts' }
                                    if ($ComputerScripts.extension.Script) {
                                        foreach ($Script in $ComputerScripts.extension.Script) {
                                            try {
                                                Write-PscriboMessage "Collecting Active Directory Group Policy Objects with Startup/Shutdown Script '$($GPO.DisplayName)'."
                                                $inObj = [ordered] @{
                                                    'GPO Name' = $GPO.DisplayName
                                                    'GPO Status' = ($GPO.GpoStatus -creplace  '([A-Z\W_]|\d+)(?<![a-z])',' $&').trim()
                                                    'Type' = $Script.Type
                                                    'Script' = $Script.command
                                                }
                                                $OutObj += [pscustomobject]$inobj
                                            }
                                            catch {
                                                Write-PscriboMessage -IsWarning "$($_.Exception.Message) (GPO with Computer Startup/Shutdown Script Item)"
                                            }
                                        }
                                    }
                                }
                                catch {
                                    Write-PscriboMessage -IsWarning "$($_.Exception.Message) (GPO with Computer Startup/Shutdown Script)"
                                }
                            }
                        }
                        if ($OutObj) {
                            Section -Style Heading6 "GPO with Computer Startup/Shutdown Script" {
                                Paragraph "The following section provides a summary of Group Policy Objects with Startup/Shutdown Script."
                                BlankLine

                                if ($HealthCheck.Domain.GPO) {
                                    $OutObj | Where-Object { $_.'GPO Status' -like 'All Settings Disabled'} | Set-Style -Style Warning -Property 'GPO Status'
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

                        }
                    }
                    catch {
                        Write-PscriboMessage -IsWarning "$($_.Exception.Message) (GPO with Computer Startup/Shutdown Script Section)"
                    }
                }
                if ($HealthCheck.Domain.GPO) {
                    try {
                        $OutObj = @()
                        if ($GPOs) {
                            Write-PscriboMessage "Discovered Active Directory Group Policy Objects information on $Domain. (Group Policy Objects)"
                            foreach ($GPO in $GPOs) {
                                try {
                                    [xml]$Gpoxml =  Invoke-Command -Session $TempPssSession -ScriptBlock {Get-GPOReport -Domain $using:Domain -ReportType Xml -Guid ($using:GPO).Id}
                                    if (($Null -ne $Gpoxml.GPO.Name) -and ($Null -eq $Gpoxml.GPO.LinksTo.SOMPath)) {
                                        Write-PscriboMessage "Collecting Active Directory Unlinked Group Policy Objects '$($Gpoxml.GPO.Name)'."
                                        $inObj = [ordered] @{
                                            'GPO Name' = $Gpoxml.GPO.Name
                                            'Created' = ($Gpoxml.GPO.CreatedTime).ToString().split("T")[0]
                                            'Modified' = ($Gpoxml.GPO.ModifiedTime).ToString().split("T")[0]
                                            'Computer Enabled' = ConvertTo-TextYN $gpoxml.GPO.Computer.Enabled
                                            'User Enabled' = ConvertTo-TextYN $gpoxml.GPO.User.Enabled
                                        }
                                        $OutObj += [pscustomobject]$inobj
                                    }
                                }
                                catch {
                                    Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Unlinked Group Policy Objects Item)"
                                }
                            }
                        }
                        if ($OutObj) {
                            Section -Style Heading6 "Health Check - Unlinked GPO" {
                                Paragraph "The following section provides a summary of the Unlinked Group Policy Objects. Corrective Action: Remove Unused GPO."
                                BlankLine

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
                            }
                        }
                    }
                    catch {
                        Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Unlinked Group Policy Objects Section)"
                    }
                    try {
                        $OutObj = @()
                        if ($GPOs) {
                            Write-PscriboMessage "Discovered Active Directory Group Policy Objects information on $Domain. (Group Policy Objects)"
                            foreach ($GPO in $GPOs) {
                                try {
                                    [xml]$Gpoxml =  Invoke-Command -Session $TempPssSession -ScriptBlock {Get-GPOReport -Domain $using:Domain -ReportType Xml -Guid ($using:GPO).Id}
                                    if (($Null -eq ($Gpoxml.GPO.Computer.ExtensionData)) -and ($Null -eq ($Gpoxml.GPO.User.extensionData))) {
                                        Write-PscriboMessage "Collecting Active Directory Empty Group Policy Objects '$($Gpoxml.GPO.Name)'."
                                        $inObj = [ordered] @{
                                            'GPO Name' = $Gpoxml.GPO.Name
                                            'Created' = ($Gpoxml.GPO.CreatedTime).ToString().split("T")[0]
                                            'Modified' = ($Gpoxml.GPO.ModifiedTime).ToString().split("T")[0]
                                            'Description' = ConvertTo-EmptyToFiller $Gpoxml.GPO.Description
                                        }
                                        $OutObj += [pscustomobject]$inobj
                                    }
                                }
                                catch {
                                    Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Empty Group Policy Objects Item)"
                                }
                            }
                        }
                        if ($OutObj) {
                            Section -Style Heading6 "Health Check - Empty GPOs" {
                                Paragraph "The following section provides a summary of the Empty Group Policy Objects. Corrective Action: No User and Computer parameters are set : Remove Unused GPO."
                                BlankLine

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
                            }
                        }
                    }
                    catch {
                        Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Empty Group Policy Objects Section)"
                    }
                    try {
                        $OutObj = @()
                        Write-PscriboMessage "Discovered Active Directory Group Policy Objects information on $Domain. (Group Policy Objects)"
                        $DC = Invoke-Command -Session $TempPssSession {Get-ADDomain -Identity $using:Domain | Select-Object -ExpandProperty ReplicaDirectoryServers | Select-Object -First 1}
                        Write-PscriboMessage "Discovered Active Directory Domain Controller $DC in $Domain. (Group Policy Objects)"
                        $OUs = Invoke-Command -Session $TempPssSession -ScriptBlock {Get-ADOrganizationalUnit -Server $using:DC -Filter * | Select-Object -Property DistinguishedName}
                        if ($OUs) {
                            foreach ($OU in $OUs) {
                                try {
                                    $GpoEnforced = Invoke-Command -Session $TempPssSession -ScriptBlock { Get-GPInheritance -Domain $using:Domain -Server $using:DC -Target ($using:OU).DistinguishedName | Select-Object -ExpandProperty GpoLinks }
                                    if ($GpoEnforced.Enforced -eq "True") {
                                        Write-PscriboMessage "Collecting Active Directory Enforced owned Group Policy Objects'$($GpoEnforced.DisplayName)'."
                                        $TargetCanonical = Invoke-Command -Session $TempPssSession -ScriptBlock { Get-ADObject -Server $using:DC -Identity ($using:GpoEnforced).Target -Properties * | Select-Object -ExpandProperty CanonicalName }
                                        $inObj = [ordered] @{
                                            'GPO Name' = $GpoEnforced.DisplayName
                                            'Enforced' = ConvertTo-TextYN $GpoEnforced.Enforced
                                            'Order' = $GpoEnforced.Order
                                            'Target' = $TargetCanonical
                                        }
                                        $OutObj += [pscustomobject]$inobj
                                    }
                                }
                                catch {
                                    Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Enforced Group Policy Objects Item)"
                                }
                            }
                        }

                        if ($OutObj) {
                            Section -Style Heading6 "Health Check - Enforced GPO" {
                                Paragraph "The following section provides a summary of the Enforced Group Policy Objects."
                                BlankLine

                                if ($HealthCheck.Domain.GPO) {
                                    $OutObj | Set-Style -Style Warning
                                }

                                $TableParams = @{
                                    Name = "Enforced GPO - $($Domain.ToString().ToUpper())"
                                    List = $false
                                    ColumnWidths = 35, 15, 15, 35
                                }

                                if ($Report.ShowTableCaptions) {
                                    $TableParams['Caption'] = "- $($TableParams.Name)"
                                }
                                $OutObj | Sort-Object -Property 'GPO Name' | Table @TableParams
                            }
                        }
                    }
                    catch {
                        Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Enforced Group Policy Objects Table)"
                    }
                }
            }
        }
        catch {
            Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Group Policy Objects Section)"
        }
    }


    end {}

}