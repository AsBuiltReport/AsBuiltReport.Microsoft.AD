function ConvertTo-TextYN {
        <#
    .SYNOPSIS
    Used by As Built Report to convert true or false automatically to Yes or No.
    .DESCRIPTION

    .NOTES
        Version:        0.1.0
        Author:         LEE DAILEY

    .EXAMPLE

    .LINK

    #>
    [CmdletBinding()]
    Param
        (
        [Parameter (
            Position = 0,
            Mandatory)]
            [string]
            $Input
        )
    
    switch ($Input)
        {
        {"True"} {"Yes"; break}
        {"False"} {"No"; break}
        default {$Input}
        }
    } # end