function Get-ComputerSplit {
    <#
    .SYNOPSIS

    .DESCRIPTION

    .NOTES
        Version:        0.1.0
        Author:         Przemysław Kłys

    .EXAMPLE

    .LINK

    #>
    [CmdletBinding()]
    [OutputType([Array])]
    param(
        [string[]] $ComputerName
    )
    if ($null -eq $ComputerName) {
        $ComputerName = $Env:COMPUTERNAME
    }
    try {
        $LocalComputerDNSName = [System.Net.Dns]::GetHostByName($Env:COMPUTERNAME).HostName
    } catch {
        $LocalComputerDNSName = $Env:COMPUTERNAME
    }
    $ComputersLocal = $null
    [Array] $Computers = foreach ($Computer in $ComputerName) {
        if ($Computer -eq '' -or $null -eq $Computer) {
            $Computer = $Env:COMPUTERNAME
        }
        if ($Computer -ne $Env:COMPUTERNAME -and $Computer -ne $LocalComputerDNSName) {
            $Computer
        } else {
            $ComputersLocal = $Computer
        }
    }
    , @($ComputersLocal, $Computers)
}

