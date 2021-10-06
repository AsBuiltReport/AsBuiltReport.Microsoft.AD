function Get-AbrADGPO {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft Active Directory Group Policy Objects information.
    .DESCRIPTION

    .NOTES
        Version:        0.3.0
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
            $Session
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
                    Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Group Policy Objects)"
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
                    Write-PscriboMessage -IsWarning "Error: Collecting Active Directory Unlinked Group Policy Objects for domain $($Domain.ToString().ToUpper())."
                    Write-PscriboMessage -IsDebug $_.Exception.Message
                }
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
                Write-PscriboMessage -IsWarning "Error: Collecting Active Directory Empty Group Policy Objects for domain $($Domain.ToString().ToUpper())."
                Write-PscriboMessage -IsDebug $_.Exception.Message
            }
        }
    }

    end {}

}