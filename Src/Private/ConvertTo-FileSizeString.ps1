function ConvertTo-FileSizeString {
    <#
    .SYNOPSIS
    Used by As Built Report to convert bytes automatically to GB or TB based on size.
    .DESCRIPTION
    .NOTES
        Version:        0.1.0
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
        [int64]
        $Size
    )

    $Unit = switch ($Size) {
        { $Size -gt 1PB } { 'PB' ; break }
        { $Size -gt 1TB } { 'TB' ; break }
        { $Size -gt 1GB } { 'GB' ; break }
        { $Size -gt 1Mb } { 'MB' ; break }
        default { 'KB' }
    }
    return "$([math]::Round(($Size / $("1" + $Unit)), 0)) $Unit"
} # end