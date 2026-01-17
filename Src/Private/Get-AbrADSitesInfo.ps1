function Get-AbrADSitesInfo {
    <#
    .SYNOPSIS
        Function to extract microsoft active directory sites information.
    .DESCRIPTION
        Build a diagram of the configuration of Microsoft Active Directory to a supported formats using Psgraph.
    .NOTES
        Version:        0.9.9
        Author:         Jonathan Colon
        Twitter:        @jcolonfzenpr
        Github:         rebelinux
    .LINK
        https://github.com/rebelinux/Diagrammer.Microsoft.AD
    #>
    [CmdletBinding()]
    [OutputType([System.Object[]])]

    param()

    begin {
    }

    process {
        Write-Verbose -Message ($reportTranslate.NewADDiagram.buildingSites -f $($ForestRoot))
        try {
            $Sites = Invoke-CommandWithTimeout -Session $TempPssSession -ScriptBlock { [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().Sites | Select-Object Name, @{l = 'SitesLink'; e = { $_.sitelinks } } }

            $SitesInfo = @()
            if ($Sites) {
                foreach ($SitesLink in $Sites) {
                    $TempSitesInfo = [PSCustomObject]@{
                        'Name' = $SitesLink.Name
                        'SiteLink' = & {
                            foreach ($Link in $SitesLink.SitesLink.Name) {
                                $SitesLinkInfo = Invoke-CommandWithTimeout -Session $TempPssSession -ScriptBlock { Get-ADReplicationSiteLink -Identity $using:Link -Properties * }
                                @{
                                    'Name' = $Link
                                    'Sites' = $SitesLinkInfo.SitesIncluded | ForEach-Object { ConvertTo-ADObjectName -Session $TempPssSession -DN $_ -DC $System }
                                    'AditionalInfo' = [ordered]@{
                                        $reportTranslate.NewADDiagram.siteLinkName = $Link
                                        $reportTranslate.NewADDiagram.siteLinkCost = $SitesLinkInfo.Cost
                                        $reportTranslate.NewADDiagram.siteLinkFrequency = "$($SitesLinkInfo.ReplicationFrequencyInMinutes) $($reportTranslate.NewADDiagram.siteLinkFrequencyMinutes)"
                                        $reportTranslate.NewADDiagram.siteLinkNameInterSiteTP = $SitesLinkInfo.InterSiteTransportProtocol
                                    }
                                }
                            }
                        }
                    }
                    $SitesInfo += $TempSitesInfo
                }
            }

            return $SitesInfo
        } catch {
            Write-Verbose $_.Exception.Message
        }
    }
    end {}
}