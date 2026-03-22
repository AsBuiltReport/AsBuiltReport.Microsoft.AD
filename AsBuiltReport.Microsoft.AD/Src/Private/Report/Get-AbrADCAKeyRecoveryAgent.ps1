function Get-AbrADCAKeyRecoveryAgent {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft Active Directory CA Key Recovery Agent information.
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
        [Parameter (
            Position = 0,
            Mandatory)]
        $CA
    )

    begin {
        Write-PScriboMessage -Message $reportTranslate.GetAbrADCAKeyRecoveryAgent.Collecting
        Show-AbrDebugExecutionTime -Start -TitleMessage 'CA Key Recovery Agent'
    }

    process {
        $OutObj = [System.Collections.Generic.List[object]]::new()
        try {
            $KRA = Get-CAKRACertificate -CertificationAuthority $CA
            if ($KRA.Certificate) {
                $inObj = [ordered] @{
                    $reportTranslate.GetAbrADCAKeyRecoveryAgent.CAName = $KRA.DisplayName
                    $reportTranslate.GetAbrADCAKeyRecoveryAgent.ServerName = $KRA.ComputerName.ToString().ToUpper().Split('.')[0]
                    $reportTranslate.GetAbrADCAKeyRecoveryAgent.Certificate = $KRA.Certificate
                }
                $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj))
            }
        } catch {
            Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Key Recovery Agent Certificate Item)"
        }

        if ($OutObj) {
            Section -Style Heading3 $reportTranslate.GetAbrADCAKeyRecoveryAgent.Heading {
                Paragraph $reportTranslate.GetAbrADCAKeyRecoveryAgent.Paragraph
                BlankLine
                foreach ($Item in $OutObj) {
                    $TableParams = @{
                        Name = "$($reportTranslate.GetAbrADCAKeyRecoveryAgent.TableName) - $($Item.$($reportTranslate.GetAbrADCAKeyRecoveryAgent.CAName))"
                        List = $true
                        ColumnWidths = 40, 60
                    }
                    if ($Report.ShowTableCaptions) {
                        $TableParams['Caption'] = "- $($TableParams.Name)"
                    }
                    $Item | Table @TableParams
                }
            }
        }
    }

    end {
        Show-AbrDebugExecutionTime -End -TitleMessage 'CA Key Recovery Agent'
    }

}
