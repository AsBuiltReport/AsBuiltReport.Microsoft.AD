function Get-ADObjectSearch {
    <#
    .SYNOPSIS
    Used by As Built Report to lookup Object subtree in Active Directory.
    .DESCRIPTION

    .NOTES
        Version:        0.1.0
        Author:         Jonathan Colon

    .EXAMPLE

    .LINK

    #>
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        $DN,
        $Session,
        $Filter,
        $Properties = '*',
        $SelectPrty

    )
    $ADObject = [System.Collections.ArrayList]::new()
    foreach ($Object in $DN) {
        $ADObject.Add((Invoke-CommandWithTimeout -Session $Session -ScriptBlock { Get-ADObject -SearchBase $using:DN -SearchScope OneLevel -Filter $using:Filter -Properties $using:Properties -EA 0 | Select-Object $using:SelectPrty })) | Out-Null
    }
    return $ADObject;
}# end