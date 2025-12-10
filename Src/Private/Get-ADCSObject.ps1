function Get-ADCSObject {
    <#
    .SYNOPSIS
    Used by As Built Report to find PKI Server auditing not enabled.
    .DESCRIPTION

    .NOTES
        Version:        2023.08
        Author:         Jake Hildreth

    .EXAMPLE

    .LINK
        https://github.com/TrimarcJake/Locksmith
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Target
    )
    try {
        $ADRoot = Invoke-CommandWithTimeout -Session $TempPssSession -ScriptBlock { (Get-ADRootDSE -Server $Using:Target).defaultNamingContext }
        Invoke-CommandWithTimeout -Session $TempPssSession -ScriptBlock { Get-ADObject -Filter * -SearchBase "CN=Public Key Services,CN=Services,CN=Configuration,$Using:ADRoot" -SearchScope 2 -Properties * }
    } catch {
        Write-PScriboMessage -IsWarning -Message "Unable to find CA auditing information"
    }
}