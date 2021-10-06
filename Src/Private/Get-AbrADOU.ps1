function Get-AbrADOU {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Organizational Unit information
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
        Write-PscriboMessage "Discovering Active Directory Organizational Unit information on domain $Domain"
    }

    process {
        Section -Style Heading5 "Organizational Unit Summary" {
            Paragraph "The following section provides a summary of Active Directory OU information on $($Domain.ToString().ToUpper())."
            BlankLine
            $OutObj = @()
            if ($Domain) {
                try {
                    $DC = Invoke-Command -Session $Session -ScriptBlock {Get-ADDomainController -Discover -Domain $using:Domain | Select-Object -ExpandProperty HostName}
                    Write-PscriboMessage "Discovered Active Directory Organizational Unit information on DC $DC. (Organizational Unit)"
                    $OUs = Invoke-Command -Session $Session -ScriptBlock {Get-ADOrganizationalUnit -Server $using:DC -Searchbase (Get-ADDomain -Identity $using:Domain).distinguishedName -Filter *}
                    foreach ($OU in $OUs) {
                        Write-PscriboMessage "Collecting information of Active Directory Organizational Unit $OU. (Organizational Unit)"
                        $GPOArray = @()
                        [array]$GPOs = $OU.LinkedGroupPolicyObjects
                        foreach ($Object in $GPOs) {
                            $GP = Invoke-Command -Session $Session -ScriptBlock {Get-GPO -Guid ($using:Object).Split(",")[0].Split("=")[1] -Domain $using:Domain}
                            Write-PscriboMessage "Collecting linked GPO: '$($GP.DisplayName)' on Organizational Unit $OU. (Organizational Unit)"
                            $GPOArray += $GP.DisplayName
                        }
                        $inObj = [ordered] @{
                            'Name' = $OU.Name
                            'Distinguished Name' = $OU.DistinguishedName
                            'Linked GPO' = ConvertTo-EmptyToFiller ($GPOArray -join ", ")
                        }
                        $OutObj += [pscustomobject]$inobj
                    }
                }
                catch {
                    Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Organizational Unit)"
                }

                $TableParams = @{
                    Name = "Active Directory Organizational Unit Information - $($Domain.ToString().ToUpper())"
                    List = $false
                    ColumnWidths = 25, 40, 35
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