function Get-AbrADDCRoleFeature {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Domain Controller Role & Features information.
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
            $DC,
            [pscredential]
            $Cred
    )

    begin {
        Write-PscriboMessage "Discovering Active Directory DC Role & Features information of $DC."
    }

    process {
        Write-PscriboMessage "Collecting AD Domain Controller Role & Features information for domain $Domain"
        try {
            $DCPssSession = New-PSSession $DC -Credential $Cred -Authentication Default
            if ($DCPssSession) {
                Write-PscriboMessage "Discovered Active Directory DC Role & Features information of $DC."
                Section -Style Heading6 "Role & Features on $($DC.ToString().ToUpper().Split(".")[0])" {
                    Paragraph "The following section provides a summary of the Domain Controller Role & Features information."
                    BlankLine
                    $OutObj = @()
                    Write-PscriboMessage "Collecting Domain Controller Role & Features: '$($Features.DisplayName)' on $DC."
                    $Features = Invoke-Command -Session $DCPssSession -ScriptBlock {Get-WindowsFeature | Where-Object {$_.installed -eq "True"}}
                    Remove-PSSession -Session $DCPssSession
                    foreach ($Feature in $Features) {
                        $inObj = [ordered] @{
                            'Name' = $Feature.DisplayName
                            'Parent' = $Feature.FeatureType
                            'InstallState' = $Feature.Description
                        }
                        $OutObj += [pscustomobject]$inobj
                    }

                    $TableParams = @{
                        Name = "Domain Controller Role & Features Information."
                        List = $false
                        ColumnWidths = 20, 10, 70
                    }
                    if ($Report.ShowTableCaptions) {
                        $TableParams['Caption'] = "- $($TableParams.Name)"
                    }
                    $OutObj | Table @TableParams
                }
            }
        }
        catch {
            Write-PscriboMessage -IsWarning "Error: Connecting to remote server $DC failed: WinRM cannot complete the operation."
            Write-PScriboMessage -IsDebug $_.Exception.Message
        }
    }

    end {}

}