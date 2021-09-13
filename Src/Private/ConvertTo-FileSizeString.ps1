function ConvertTo-FileSizeString {
        <#
    .SYNOPSIS
    Used by As Built Report to convert bytes automatically to GB or TB based on size.
    .DESCRIPTION

    .NOTES
        Version:        0.1.0
        Author:         LEE DAILEY

    .EXAMPLE

    .LINK

    #>
    [CmdletBinding()]
    [OutputType([String])]
    Param
        (
        [Parameter (
            Position = 0,
            Mandatory)]
            [int64]
            $Size
        )

    switch ($Size)
        {
        {$_ -gt 1TB}
            {[string]::Format("{0:0.00} TB", $Size / 1TB); break}
        {$_ -gt 1GB}
            {[string]::Format("{0:0.00} GB", $Size / 1GB); break}
        {$_ -gt 1MB}
            {[string]::Format("{0:0.00} MB", $Size / 1MB); break}
        {$_ -gt 1KB}
            {[string]::Format("{0:0.00} KB", $Size / 1KB); break}
        {$_ -gt 0}
            {[string]::Format("{0} B", $Size); break}
        {$_ -eq 0}
            {"0 KB"; break}
        default
            {"0 KB"}
        }
    } # end >> function Format-FileSize