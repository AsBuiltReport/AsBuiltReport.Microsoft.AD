function Get-AbrADDCRoleFeature {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Domain Controller Role & Features information.
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
            $DC
    )

    begin {
        Write-PscriboMessage "Discovering Active Directory DC Role & Features information of $DC."
    }

    process {
        Write-PscriboMessage "Collecting AD Domain Controller Role & Features information for domain $Domain"
        try {
            $DCPssSession = New-PSSession $DC -Credential $Credential -Authentication $Options.PSDefaultAuthentication
            if ($DCPssSession) {
                Write-PscriboMessage "Discovered Active Directory DC Role & Features information of $DC."
                Section -Style Heading6 "$($DC.ToString().ToUpper().Split(".")[0])" {
                    $OutObj = @()
                    $Features = Invoke-Command -Session $DCPssSession -ScriptBlock {Get-WindowsFeature | Where-Object {$_.installed -eq "True" -and $_.FeatureType -eq 'Role'}}
                    Remove-PSSession -Session $DCPssSession
                    foreach ($Feature in $Features) {
                        try {
                            Write-PscriboMessage "Collecting DC Roles: $($Feature.DisplayName) on $DC."
                            $inObj = [ordered] @{
                                'Name' = $Feature.DisplayName
                                'Parent' = $Feature.FeatureType
                                'InstallState' = $Feature.Description
                            }
                            $OutObj += [pscustomobject]$inobj
                        }
                        catch {
                            Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Roles Item)"
                        }
                    }

                    $TableParams = @{
                        Name = "Roles - $($DC.ToString().split('.')[0].ToUpper())"
                        List = $false
                        ColumnWidths = 20, 10, 70
                    }
                    if ($Report.ShowTableCaptions) {
                        $TableParams['Caption'] = "- $($TableParams.Name)"
                    }
                    $OutObj | Table @TableParams
                    if ($HealthCheck.DomainController.Software) {
                        Paragraph "Health Check:" -Italic -Bold -Underline
                        Paragraph "Best Practices: Domain Controllers should have limited software and agents installed including roles and services. Non-essential code running on Domain Controllers is a risk to the enterprise Active Directory environment. A Domain Controller should only run required software, services and roles critical to essential operation" -Italic -Bold
                    }
                }
            }
        }
        catch {
            Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Role Section)"
        }
    }

    end {}

}