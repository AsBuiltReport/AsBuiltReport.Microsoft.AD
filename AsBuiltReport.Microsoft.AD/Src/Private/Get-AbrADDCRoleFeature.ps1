function Get-AbrADDCRoleFeature {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Domain Controller Role & Features information.
    .DESCRIPTION

    .NOTES
        Version:        0.9.9
        Author:         Jonathan Colon
        Twitter:        @jcolonfzenpr
        Github:         rebelinux
    .EXAMPLE

    .LINK

    #>
    [CmdletBinding()]
    param (
        $DC
    )

    begin {
        Write-PScriboMessage -Message ($reportTranslate.GetAbrADDCRoleFeature.Collecting -f $DC)
        Show-AbrDebugExecutionTime -Start -TitleMessage 'DC Role & Features'
    }

    process {
        try {
            $DCPssSession = Get-ValidPSSession -ComputerName $DC -SessionName $($DC) -PSSTable ([ref]$PSSTable)
            if ($DCPssSession) {
                $Features = Invoke-CommandWithTimeout -Session $DCPssSession -ScriptBlock { Get-WindowsFeature | Where-Object { $_.installed -eq 'True' -and $_.FeatureType -eq 'Role' } }
            } else {
                if (-not $_.Exception.MessageId) {
                    $ErrorMessage = $_.FullyQualifiedErrorId
                } else { $ErrorMessage = $_.Exception.MessageId }
                Write-PScriboMessage -IsWarning -Message "Roles Section: New-PSSession: Unable to connect to $($DC): $ErrorMessage"
            }
            if ($Features) {
                Section -ExcludeFromTOC -Style NOTOCHeading5 $($DC.ToString().ToUpper().Split('.')[0]) {
                    $OutObj = [System.Collections.Generic.List[object]]::new()
                    foreach ($Feature in $Features) {
                        try {
                            $inObj = [ordered] @{
                                $reportTranslate.GetAbrADDCRoleFeature.Name = $Feature.DisplayName
                                $reportTranslate.GetAbrADDCRoleFeature.Parent = $Feature.FeatureType
                                $reportTranslate.GetAbrADDCRoleFeature.Description = $Feature.Description
                            }
                            $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj))
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "Roles $($Feature.DisplayName) Section: $($_.Exception.Message)"
                        }
                    }

                    if ($HealthCheck.DomainController.BestPractice) {
                        $List = @()
                        $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADDCRoleFeature.Name) -notin @('Active Directory Domain Services', 'DNS Server', 'File and Storage Services') } | Set-Style -Style Warning
                        foreach ( $OBJ in ($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADDCRoleFeature.Name) -notin @('Active Directory Domain Services', 'DNS Server', 'File and Storage Services') })) {
                            $OBJ.$($reportTranslate.GetAbrADDCRoleFeature.Name) = "$($OBJ.$($reportTranslate.GetAbrADDCRoleFeature.Name)) (1)"
                            $List = $reportTranslate.GetAbrADDCRoleFeature.RoleBP
                        }
                    }

                    $TableParams = @{
                        Name = "$($reportTranslate.GetAbrADDCRoleFeature.TableName) - $($DC.ToString().split('.')[0].ToUpper())"
                        List = $false
                        ColumnWidths = 20, 10, 70
                    }
                    if ($Report.ShowTableCaptions) {
                        $TableParams['Caption'] = "- $($TableParams.Name)"
                    }
                    $OutObj | Table @TableParams
                    if ($HealthCheck.DomainController.Software -and $List) {
                        Paragraph $reportTranslate.GetAbrADDCRoleFeature.HealthCheck -Bold -Underline
                        BlankLine
                        Paragraph $reportTranslate.GetAbrADDCRoleFeature.BestPractices -Bold
                        List -Item $List -Numbered
                    }
                }
            }
        } catch {
            Write-PScriboMessage -IsWarning -Message "Roles Section: $($_.Exception.Message)"
        }
    }
    end {
        Show-AbrDebugExecutionTime -End -TitleMessage 'DC Role & Features'
    }
}