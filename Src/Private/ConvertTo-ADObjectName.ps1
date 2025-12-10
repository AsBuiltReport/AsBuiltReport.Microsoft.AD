function ConvertTo-ADObjectName {
    <#
    .SYNOPSIS
    Used by As Built Report to translate Active Directory DN to Name.
    .DESCRIPTION

    .NOTES
        Version:        0.4.0
        Author:         Jonathan Colon

    .EXAMPLE

    .LINK

    #>
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        $DN,
        $Session,
        $DC
    )
    $ADObject = [System.Collections.ArrayList]::new()
    foreach ($Object in $DN) {
        $ADObject.Add((Invoke-CommandWithTimeout -Session $Session -ScriptBlock { Get-ADObject $using:Object -Server $using:DC | Select-Object -ExpandProperty Name })) | Out-Null
    }
    return $ADObject;
}# end