function ConvertTo-EmptyToFiller {
    <#
        .SYNOPSIS
        Used by As Built Report to convert empty culumns to "--".
        .DESCRIPTION

        .NOTES
            Version:        0.4.0
            Author:         Jonathan Colon

        .EXAMPLE

        .LINK

        #>
    [CmdletBinding()]
    [OutputType([String])]
    param
    (
        [Parameter (
            Position = 0,
            Mandatory)]
        [AllowEmptyString()]
        [string]
        $TEXT
    )

    switch ($TEXT) {
        "" { "--"; break }
        $Null { "--"; break }
        "True" { "Yes"; break }
        "False" { "No"; break }
        default { $TEXT }
    }
} # end