function Get-AbrADTrust {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Trust from Domain Controller
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
            [PSCredential]
            $Cred
    )

    begin {
        Write-PscriboMessage "Collecting AD Trust information of $($Domain.ToString().ToUpper())."
    }

    process {
        Section -Style Heading5 'Domain and Trusts' {
            Paragraph "The following section provides a summary of Active Directory Trust information on $($Domain.ToString().ToUpper())."
            BlankLine
            $OutObj = @()
            if ($Domain) {
                try {
                    $DC = Invoke-Command -Session $Session {Get-ADDomain -Identity $using:Domain | Select-Object -ExpandProperty ReplicaDirectoryServers | Select-Object -First 1}
                    Write-PScriboMessage "Discovered '$(($DC | Measure-Object).Count)' Active Directory Domain Controller in domain $Domain."
                    $DCPssSession = New-PSSession $DC -Credential $Cred -Authentication Default
                    $Trusts = Invoke-Command -Session $DCPssSession {Get-ADTrust -Filter *}
                    if ($Trusts) {Write-PScriboMessage "Discovered created trusts in domain $Domain"}
                    foreach ($Trust in $Trusts) {
                        Write-PscriboMessage "Collecting Active Directory Domain Trust information from $($Trust.Name)"
                        $inObj = [ordered] @{
                            'Name' = $Trust.Name
                            'Path' = ConvertTo-ADCanonicalName -DN $Trust.DistinguishedName -Credential $Cred -Domain $Domain
                            'Source' = ConvertTo-ADObjectName $Trust.Source -Session $DCPssSession
                            'Target' = $Trust.Target
                            'Direction' = $Trust.Direction
                            'IntraForest' =  ConvertTo-TextYN $Trust.IntraForest
                            'Selective Authentication' =  ConvertTo-TextYN $Trust.SelectiveAuthentication
                            'SID Filtering Forest Aware' =  ConvertTo-TextYN $Trust.SIDFilteringForestAware
                            'SID Filtering Quarantined' =  ConvertTo-TextYN $Trust.SIDFilteringQuarantined
                            'Trust Type' = $Trust.TrustType
                            'Uplevel Only' = ConvertTo-TextYN $Trust.UplevelOnly
                        }
                        $OutObj += [pscustomobject]$inobj
                    }
                    Remove-PSSession -Session $DCPssSession
                }
                catch {
                    Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Trust Summary)"
                    }
                }

            $TableParams = @{
                Name = "Active Directory Trusts Information - $($Domain.ToString().ToUpper())"
                List = $true
                ColumnWidths = 40, 60
            }
            if ($Report.ShowTableCaptions) {
                $TableParams['Caption'] = "- $($TableParams.Name)"
            }
            $OutObj | Table @TableParams
        }
    }

    end {}

}