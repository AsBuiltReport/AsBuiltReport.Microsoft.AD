function ConvertTo-ADCanonicalName {
    <#
    .SYNOPSIS
    Used by As Built Report to translate Active Directory DN to CanonicalName.
    .DESCRIPTION

    .NOTES
        Version:        0.4.0
        Author:         Jonathan Colon

    .EXAMPLE

    .LINK

    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        $DN,
        $Domain,
        $DC
    )
    $ADObject = [System.Collections.Generic.List[object]]::new()
    $DC = Invoke-CommandWithTimeout -Session $TempPssSession -ScriptBlock { Get-ADDomainController -Discover -Domain $using:Domain | Select-Object -ExpandProperty HostName }
    foreach ($Object in $DN) {
        $ADObject.Add((Invoke-CommandWithTimeout -Session $TempPssSession -ScriptBlock { Get-ADObject $using:Object -Properties * -Server $using:DC | Select-Object -ExpandProperty CanonicalName }))
    }
    $ADObject;
}# end