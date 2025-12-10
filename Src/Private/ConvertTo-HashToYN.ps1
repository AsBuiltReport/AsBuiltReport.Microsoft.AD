function ConvertTo-HashToYN {
    <#
    .SYNOPSIS
        Used by As Built Report to convert array content true or false automatically to Yes or No.
    .DESCRIPTION

    .NOTES
        Version:        0.2.0
        Author:         Jonathan Colon

    .EXAMPLE

    .LINK

    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param (
        [Parameter (Position = 0, Mandatory)]
        [AllowEmptyString()]
        [System.Collections.Specialized.OrderedDictionary] $TEXT
    )

    $result = [ordered] @{}
    foreach ($i in $TEXT.GetEnumerator()) {
        try {
            $result.add($i.Key, (ConvertTo-TextYN $i.Value))
        } catch {
            $result.add($i.Key, ($i.Value))
        }
    }
    if ($result) {
        return $result
    } else { return $TEXT }
} # end