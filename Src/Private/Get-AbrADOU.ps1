function Get-AbrADOU {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Organizational Unit information
    .DESCRIPTION

    .NOTES
        Version:        0.1.0
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
            $Domain
    )

    begin {
        Write-PscriboMessage "Collecting AD Organizational Unit information."
    }

    process {
        Section -Style Heading5 "Organizational Unit summary for domain $($Domain.ToString().ToUpper().Split(".")[0])" {
            Paragraph "The following section provides a summary of Active Directory OU information on $($Domain.ToString().ToUpper())."
            BlankLine
            $OutObj = @()
            if ($Domain) {
                $DC = Get-ADDomainController -Discover -Domain $Domain | Select-Object -ExpandProperty HostName
                $OUs = Get-ADOrganizationalUnit -Server $DC -Searchbase (Get-ADDomain -Identity $Domain).distinguishedName -Filter *
                foreach ($OU in $OUs) {
                    $GPOArray = @()
                    [array]$GPOs = $OU.LinkedGroupPolicyObjects
                    foreach ($Object in $GPOs) {
                        $GP = Get-GPO -Guid $Object.Split(",")[0].Split("=")[1]
                        $GPOArray += $GP.DisplayName
                    }
                    $inObj = [ordered] @{
                        'Name' = $OU.Name
                        'Distinguished Name' = $OU.DistinguishedName
                        'Linked GPO' = $GPOArray -join ", "
                    }
                    $OutObj += [pscustomobject]$inobj
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