function Get-AbrADGPO {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft Active Directory Group Policy Objects information.
    .DESCRIPTION

    .NOTES
        Version:        0.4.0
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
            $Domain,
            $Session,
            [pscredential]
            $Cred
            )

    begin {
        Write-PscriboMessage "Discovering Active Directory Group Policy Objects information for $($Domain.ToString().ToUpper())."
    }

    process {
        Section -Style Heading5 "Group Policy Objects Summary" {
            Paragraph "The following section provides a summary of the Group Policy Objects for domain $($Domain.ToString().ToUpper())."
            BlankLine
            $OutObj = @()
            if ($Domain) {
                try {
                    $GPOs = Invoke-Command -Session $Session -ScriptBlock {Get-GPO -Domain $using:Domain -All}
                    Write-PscriboMessage "Discovered Active Directory Group Policy Objects information on $Domain. (Group Policy Objects)"
                    foreach ($GPO in $GPOs) {
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
                            #$inObj.Add('Filter Name', $Gpoxml.GPO.FilterName)
                            #$inObj.Add('Filter Description', $Gpoxml.GPO.FilterDescription)
                        }
                        $OutObj += [pscustomobject]$inobj
                    }
                }
                catch {
                    Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Group Policy Objects Summary)"
                }

                if ($HealthCheck.Domain.GPO) {
                    $OutObj | Where-Object { $_.'GPO Status' -like 'All Settings Disabled'} | Set-Style -Style Warning -Property 'GPO Status'
                    $OutObj | Where-Object {$Null -eq $_.'Owner'} | Set-Style -Style Warning -Property 'Owner'
                }

                if ($InfoLevel.Domain -le 2) {
                    $TableParams = @{
                        Name = "Group Policy Objects Information - $($Domain.ToString().ToUpper())"
                        List = $false
                        ColumnWidths = 45, 25, 15, 15
                    }
                }
                else {
                    $TableParams = @{
                        Name = "Group Policy Objects Information - $($Domain.ToString().ToUpper())"
                        List = $true
                        ColumnWidths = 40, 60
                    }
                }

                if ($Report.ShowTableCaptions) {
                    $TableParams['Caption'] = "- $($TableParams.Name)"
                }
                $OutObj | Table @TableParams
                try {
                    Section -Style Heading5 "Group Policy Objects with User Logon/Logoff Script Summary" {
                        Paragraph "The following section provides a summary of Group Policy Objects with Logon/Logoff Script."
                        BlankLine
                        $OutObj = @()
                        if ($Domain) {
                            $GPOs = Invoke-Command -Session $Session -ScriptBlock {Get-GPO -Domain $using:Domain -All}
                            Write-PscriboMessage "Discovered Active Directory Group Policy Objects information on $Domain. (Group Policy Objects)"
                            foreach ($GPO in $GPOs) {
                                [xml]$Gpoxml =  Invoke-Command -Session $Session -ScriptBlock {Get-GPOReport -Domain $using:Domain -ReportType Xml -Guid ($using:GPO).Id}
                                $UserScripts = $Gpoxml.GPO.User.ExtensionData | Where-Object { $_.Name -eq 'Scripts' }
                                if ($UserScripts.extension.Script) {
                                    foreach ($Script in $UserScripts.extension.Script) {
                                        Write-PscriboMessage "Collecting Active Directory Group Policy Objects with Logon/Logoff Script '$($GPO.DisplayName)'."
                                        $inObj = [ordered] @{
                                            'GPO Name' = $GPO.DisplayName
                                            'GPO Status' = ($GPO.GpoStatus -creplace  '([A-Z\W_]|\d+)(?<![a-z])',' $&').trim()
                                            'Type' = $Script.Type
                                            'Script' = $Script.command
                                        }
                                        $OutObj += [pscustomobject]$inobj
                                    }
                                }
                            }

                            if ($HealthCheck.Domain.GPO) {
                                $OutObj | Where-Object { $_.'GPO Status' -like 'All Settings Disabled'} | Set-Style -Style Warning -Property 'GPO Status'
                            }

                            $TableParams = @{
                                Name = "Group Policy Objects with Logon/Logoff Script Information - $($Domain.ToString().ToUpper())"
                                List = $false
                                ColumnWidths = 20, 15, 15, 50
                            }

                            if ($Report.ShowTableCaptions) {
                                $TableParams['Caption'] = "- $($TableParams.Name)"
                            }
                            $OutObj | Table @TableParams
                        }
                    }
                }
                catch {
                    Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Group Policy Objects with Logon/Logoff Script)"
                }
                try {
                    Section -Style Heading5 "Group Policy Objects with Computer Startup/Shutdown Script Summary" {
                        Paragraph "The following section provides a summary of Group Policy Objects with Startup/Shutdown Script."
                        BlankLine
                        $OutObj = @()
                        if ($Domain) {
                            $GPOs = Invoke-Command -Session $Session -ScriptBlock {Get-GPO -Domain $using:Domain -All}
                            Write-PscriboMessage "Discovered Active Directory Group Policy Objects information on $Domain. (Group Policy Objects)"
                            foreach ($GPO in $GPOs) {
                                [xml]$Gpoxml =  Invoke-Command -Session $Session -ScriptBlock {Get-GPOReport -Domain $using:Domain -ReportType Xml -Guid ($using:GPO).Id}
                                $ComputerScripts = $Gpoxml.GPO.Computer.ExtensionData | Where-Object { $_.Name -eq 'Scripts' }
                                if ($ComputerScripts.extension.Script) {
                                    foreach ($Script in $ComputerScripts.extension.Script) {
                                        Write-PscriboMessage "Collecting Active Directory Group Policy Objects with Startup/Shutdown Script '$($GPO.DisplayName)'."
                                        $inObj = [ordered] @{
                                            'GPO Name' = $GPO.DisplayName
                                            'GPO Status' = ($GPO.GpoStatus -creplace  '([A-Z\W_]|\d+)(?<![a-z])',' $&').trim()
                                            'Type' = $Script.Type
                                            'Script' = $Script.command
                                        }
                                        $OutObj += [pscustomobject]$inobj
                                    }
                                }
                            }

                            if ($HealthCheck.Domain.GPO) {
                                $OutObj | Where-Object { $_.'GPO Status' -like 'All Settings Disabled'} | Set-Style -Style Warning -Property 'GPO Status'
                            }

                            $TableParams = @{
                                Name = "Group Policy Objects with Startup/Shutdown Script Information - $($Domain.ToString().ToUpper())"
                                List = $false
                                ColumnWidths = 20, 15, 15, 50
                            }

                            if ($Report.ShowTableCaptions) {
                                $TableParams['Caption'] = "- $($TableParams.Name)"
                            }
                            $OutObj | Table @TableParams
                        }
                    }
                }
                catch {
                    Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Group Policy Objects with Computer Startup/Shutdown Script)"
                }
            }
            if ($HealthCheck.Domain.GPO) {
                try {
                    Section -Style Heading5 "Health Check - All Unlinked Group Policy Objects Summary" {
                        Paragraph "The following section provides a summary of the Unlinked Group Policy Objects. Corrective Action: Remove Unused GPO."
                        BlankLine
                        $OutObj = @()
                        if ($Domain) {
                            $GPOs = Invoke-Command -Session $Session -ScriptBlock {Get-GPO -Domain $using:Domain -All}
                            Write-PscriboMessage "Discovered Active Directory Group Policy Objects information on $Domain. (Group Policy Objects)"
                            foreach ($GPO in $GPOs) {
                                [xml]$Gpoxml =  Invoke-Command -Session $Session -ScriptBlock {Get-GPOReport -Domain $using:Domain -ReportType Xml -Guid ($using:GPO).Id}
                                if (($Null -ne $Gpoxml.GPO.Name) -and ($Null -eq $Gpoxml.GPO.LinksTo.SOMPath)) {
                                    Write-PscriboMessage "Collecting Active Directory Unlinked Group Policy Objects '$($Gpoxml.GPO.Name)'."
                                    $inObj = [ordered] @{
                                        'GPO Name' = $Gpoxml.GPO.Name
                                        'Created' = ($Gpoxml.GPO.CreatedTime).ToString().split("T")[0]
                                        'Modified' = ($Gpoxml.GPO.ModifiedTime).ToString().split("T")[0]
                                        'Computer Enabled' = ConvertTo-TextYN $gpoxml.GPO.Computer.Enabled
                                        'User Enabled' = ConvertTo-TextYN $gpoxml.GPO.User.Enabled
                                    }
                                    if ($InfoLevel.Domain -ge 3) {
                                        $inObj.Add('Description', $Gpoxml.GPO.Description)
                                        #$inObj.Add('Filter Name', $Gpoxml.GPO.FilterName)
                                        #$inObj.Add('Filter Description', $Gpoxml.GPO.FilterDescription)
                                    }
                                    $OutObj += [pscustomobject]$inobj
                                }
                            }

                            if ($HealthCheck.Domain.GPO) {
                                $OutObj | Set-Style -Style Warning
                            }

                            if ($InfoLevel.Domain -le 2) {
                                $TableParams = @{
                                    Name = "Unlinked Group Policy Objects Information - $($Domain.ToString().ToUpper())"
                                    List = $false
                                    ColumnWidths = 40, 15, 15, 15, 15
                                }
                            }
                            else {
                                $TableParams = @{
                                    Name = "Unlinked Group Policy Objects Information - $($Domain.ToString().ToUpper())"
                                    List = $true
                                    ColumnWidths = 40, 60
                                }
                            }

                            if ($Report.ShowTableCaptions) {
                                $TableParams['Caption'] = "- $($TableParams.Name)"
                            }
                            $OutObj | Table @TableParams
                        }
                    }
                }
                catch {
                    Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Unlinked Group Policy Objects Information)"
                }
                try {
                    Section -Style Heading5 "Health Check - All Empty Group Policy Objects Summary" {
                        Paragraph "The following section provides a summary of the Empty Group Policy Objects. Corrective Action: No User and Computer parameters are set : Remove Unused GPO."
                        BlankLine
                        $OutObj = @()
                        if ($Domain) {
                            $GPOs = Invoke-Command -Session $Session -ScriptBlock {Get-GPO -Domain $using:Domain -All}
                            Write-PscriboMessage "Discovered Active Directory Group Policy Objects information on $Domain. (Group Policy Objects)"
                            foreach ($GPO in $GPOs) {
                                [xml]$Gpoxml =  Invoke-Command -Session $Session -ScriptBlock {Get-GPOReport -Domain $using:Domain -ReportType Xml -Guid ($using:GPO).Id}
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

                            if ($HealthCheck.Domain.GPO) {
                                $OutObj | Set-Style -Style Warning
                            }

                            if ($InfoLevel.Domain -le 2) {
                                $TableParams = @{
                                    Name = "Empty Group Policy Objects Information - $($Domain.ToString().ToUpper())"
                                    List = $false
                                    ColumnWidths = 35, 15, 15, 35
                                }
                            }
                            else {
                                $TableParams = @{
                                    Name = "Empty Group Policy Objects Information - $($Domain.ToString().ToUpper())"
                                    List = $true
                                    ColumnWidths = 40, 60
                                }
                            }

                            if ($Report.ShowTableCaptions) {
                                $TableParams['Caption'] = "- $($TableParams.Name)"
                            }
                            $OutObj | Table @TableParams
                        }
                    }
                }
                catch {
                    Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Empty Group Policy Objects Information)"
                }
                try {
                    Section -Style Heading5 "Health Check - Enforced Group Policy Objects Summary" {
                        Paragraph "The following section provides a summary of the Enforced Group Policy Objects."
                        BlankLine
                        $OutObj = @()
                        if ($Domain) {
                            $DC = Invoke-Command -Session $Session {Get-ADDomain -Identity $using:Domain | Select-Object -ExpandProperty ReplicaDirectoryServers | Select-Object -First 1}
                            Write-PscriboMessage "Discovered Active Directory Domain Controller $DC in $Domain. (Group Policy Objects)"
                            $DCPssSession = New-PSSession $DC -Credential $Cred -Authentication Default
                            $OUs = Invoke-Command -Session $DCPssSession -ScriptBlock {Get-ADOrganizationalUnit -Filter * | Select-Object -Property DistinguishedName}
                            Write-PscriboMessage "Discovered Active Directory Group Policy Objects information on $Domain. (Group Policy Objects)"
                            foreach ($OU in $OUs) {
                                $GpoEnforced =  Invoke-Command -Session $DCPssSession -ScriptBlock { Get-GPInheritance -Target ($using:OU).DistinguishedName | Select-Object -ExpandProperty GpoLinks }
                                if ($GpoEnforced.Enforced -eq "True") {
                                    Write-PscriboMessage "Collecting Active Directory Enforced owned Group Policy Objects'$($GpoEnforced.DisplayName)'."
                                    $TargetCanonical = Invoke-Command -Session $DCPssSession -ScriptBlock { Get-ADObject -Identity ($using:GpoEnforced).Target -Properties * | Select-Object -ExpandProperty CanonicalName }
                                    $inObj = [ordered] @{
                                        'GPO Name' = $GpoEnforced.DisplayName
                                        'Enforced' = ConvertTo-TextYN $GpoEnforced.Enforced
                                        'Order' = $GpoEnforced.Order
                                        'Target' = $TargetCanonical
                                    }
                                    $OutObj += [pscustomobject]$inobj
                                }
                            }
                            Remove-PSSession -Session $DCPssSession

                            if ($HealthCheck.Domain.GPO) {
                                $OutObj | Set-Style -Style Warning
                            }

                            if ($InfoLevel.Domain -le 2) {
                                $TableParams = @{
                                    Name = "Enforced Group Policy Objects Information - $($Domain.ToString().ToUpper())"
                                    List = $false
                                    ColumnWidths = 35, 15, 15, 35
                                }
                            }
                            else {
                                $TableParams = @{
                                    Name = "Enforced Group Policy Objects Information - $($Domain.ToString().ToUpper())"
                                    List = $true
                                    ColumnWidths = 40, 60
                                }
                            }

                            if ($Report.ShowTableCaptions) {
                                $TableParams['Caption'] = "- $($TableParams.Name)"
                            }
                            $OutObj | Table @TableParams
                        }
                    }

                }
                catch {
                    Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Enforced Group Policy Objects Information)"
                }
            }
        }
    }


    end {}

}