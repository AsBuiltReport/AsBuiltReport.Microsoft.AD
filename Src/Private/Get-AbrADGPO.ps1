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
        Section -Style Heading5 "Group Policy Objects Summary for domain $($Domain.ToString().ToUpper().Split(".")[0])" {
            Paragraph "The following section provides a summary of the Group Policy Objects."
            BlankLine
            $OutObj = @()
            if ($Domain) {
                try {
                    $GPOs = Invoke-Command -Session $Session -ScriptBlock {Get-GPO -Domain $using:Domain -All}
                    Write-PscriboMessage "Discovered Active Directory Group Policy Objects information on $Domain. (Group Policy Objects)"
                    foreach ($GPO in $GPOs) {
                        Write-PscriboMessage "Collecting Active Directory Group Policy Objects '$($GPO.DisplayName)'. (Group Policy Objects)"
                        $inObj = [ordered] @{
                            'Display Name' = $GPO.DisplayName
                            'GPO Status' = ($GPO.GpoStatus -creplace  '([A-Z\W_]|\d+)(?<![a-z])',' $&').trim()
                            'Created' = $GPO.CreationTime.ToString("MM/dd/yyyy")
                            'Modified' = $GPO.ModificationTime.ToString("MM/dd/yyyy")
                        }
                        $OutObj += [pscustomobject]$inobj
                    }
                }
                catch {
                    Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Group Policy Objects)"
                }
                $TableParams = @{
                    Name = "Group Policy Objects Information."
                    List = $false
                    ColumnWidths = 45, 25, 15, 15
                }
                if ($Report.ShowTableCaptions) {
                    $TableParams['Caption'] = "- $($TableParams.Name)"
                }
                $OutObj | Table @TableParams
            }
        }
    }

    end {}

}