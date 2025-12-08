function ConvertFrom-DistinguishedName {
    <#
    .SYNOPSIS
    Converts a Distinguished Name to CN, OU, Multiple OUs or DC

    .DESCRIPTION
    Converts a Distinguished Name to CN, OU, Multiple OUs or DC

    .PARAMETER DistinguishedName
    Distinguished Name to convert

    .PARAMETER ToOrganizationalUnit
    Converts DistinguishedName to Organizational Unit

    .PARAMETER ToDC
    Converts DistinguishedName to DC

    .PARAMETER ToDomainCN
    Converts DistinguishedName to Domain CN

    .EXAMPLE
    $DistinguishedName = 'CN=Przemyslaw Klys,OU=Users,OU=Production,DC=ad,DC=evotec,DC=xyz'
    ConvertFrom-DistinguishedName -DistinguishedName $DistinguishedName -ToOrganizationalUnit

    Output:
    OU=Users,OU=Production,DC=ad,DC=evotec,DC=xyz

    .EXAMPLE
    $DistinguishedName = 'CN=Przemyslaw Klys,OU=Users,OU=Production,DC=ad,DC=evotec,DC=xyz'
    ConvertFrom-DistinguishedName -DistinguishedName $DistinguishedName

    Output:
    Przemyslaw Klys

    .EXAMPLE
    ConvertFrom-DistinguishedName -DistinguishedName 'OU=Users,OU=Production,DC=ad,DC=evotec,DC=xyz' -ToMultipleOrganizationalUnit -IncludeParent

    Output:
    OU=Users,OU=Production,DC=ad,DC=evotec,DC=xyz
    OU=Production,DC=ad,DC=evotec,DC=xyz

    .EXAMPLE
    ConvertFrom-DistinguishedName -DistinguishedName 'OU=Users,OU=Production,DC=ad,DC=evotec,DC=xyz' -ToMultipleOrganizationalUnit

    Output:
    OU=Production,DC=ad,DC=evotec,DC=xyz

    .EXAMPLE
    $Con = @(
        'CN=Windows Authorization Access Group,CN=Builtin,DC=ad,DC=evotec,DC=xyz'
        'CN=Mmm,DC=elo,CN=nee,DC=RootDNSServers,CN=MicrosoftDNS,CN=System,DC=ad,DC=evotec,DC=xyz'
        'CN=e6d5fd00-385d-4e65-b02d-9da3493ed850,CN=Operations,CN=DomainUpdates,CN=System,DC=ad,DC=evotec,DC=xyz'
        'OU=Domain Controllers,DC=ad,DC=evotec,DC=pl'
        'OU=Microsoft Exchange Security Groups,DC=ad,DC=evotec,DC=xyz'
    )

    ConvertFrom-DistinguishedName -DistinguishedName $Con -ToLastName

    Output:
    Windows Authorization Access Group
    Mmm
    e6d5fd00-385d-4e65-b02d-9da3493ed850
    Domain Controllers
    Microsoft Exchange Security Groups

    .NOTES
        Version:        0.1.0
        Author:         Przemysław Kłys

    #>
    [CmdletBinding(DefaultParameterSetName = 'Default')]
    param(
        [Parameter(ParameterSetName = 'ToOrganizationalUnit')]
        [Parameter(ParameterSetName = 'ToMultipleOrganizationalUnit')]
        [Parameter(ParameterSetName = 'ToDC')]
        [Parameter(ParameterSetName = 'ToDomainCN')]
        [Parameter(ParameterSetName = 'Default')]
        [Parameter(ParameterSetName = 'ToLastName')]
        [alias('Identity', 'DN')][Parameter(ValueFromPipeline, ValueFromPipelineByPropertyName, Position = 0)][string[]] $DistinguishedName,
        [Parameter(ParameterSetName = 'ToOrganizationalUnit')][switch] $ToOrganizationalUnit,
        [Parameter(ParameterSetName = 'ToMultipleOrganizationalUnit')][alias('ToMultipleOU')][switch] $ToMultipleOrganizationalUnit,
        [Parameter(ParameterSetName = 'ToMultipleOrganizationalUnit')][switch] $IncludeParent,
        [Parameter(ParameterSetName = 'ToDC')][switch] $ToDC,
        [Parameter(ParameterSetName = 'ToDomainCN')][switch] $ToDomainCN,
        [Parameter(ParameterSetName = 'ToLastName')][switch] $ToLastName
    )
    process {
        foreach ($Distinguished in $DistinguishedName) {
            if ($ToDomainCN) {
                $DN = $Distinguished -replace '.*?((DC=[^=]+,)+DC=[^=]+)$', '$1'
                $CN = $DN -replace ',DC=', '.' -replace "DC="
                if ($CN) {
                    $CN
                }
            } elseif ($ToOrganizationalUnit) {
                $Value = [Regex]::Match($Distinguished, '(?=OU=)(.*\n?)(?<=.)').Value
                if ($Value) {
                    $Value
                }
            } elseif ($ToMultipleOrganizationalUnit) {
                if ($IncludeParent) {
                    $Distinguished
                }
                while ($true) {
                    $Distinguished = $Distinguished -replace '^.+?,(?=..=)'
                    if ($Distinguished -match '^DC=') {
                        break
                    }
                    $Distinguished
                }
            } elseif ($ToDC) {
                $Value = $Distinguished -replace '.*?((DC=[^=]+,)+DC=[^=]+)$', '$1'
                if ($Value) {
                    $Value
                }
            } elseif ($ToLastName) {
                $NewDN = $Distinguished -split ",DC="
                if ($NewDN[0].Contains(",OU=")) {
                    [Array] $ChangedDN = $NewDN[0] -split ",OU="
                } elseif ($NewDN[0].Contains(",CN=")) {
                    [Array] $ChangedDN = $NewDN[0] -split ",CN="
                } else {
                    [Array] $ChangedDN = $NewDN[0]
                }
                if ($ChangedDN[0].StartsWith('CN=')) {
                    $ChangedDN[0] -replace 'CN=', ''
                } else {
                    $ChangedDN[0] -replace 'OU=', ''
                }
            } else {
                $Regex = '^CN=(?<cn>.+?)(?<!\\),(?<ou>(?:(?:OU|CN).+?(?<!\\),)+(?<dc>DC.+?))$'
                $Found = $Distinguished -match $Regex
                if ($Found) {
                    $Matches.cn
                }
            }
        }
    }
}