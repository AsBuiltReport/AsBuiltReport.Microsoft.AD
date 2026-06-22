function Remove-NonPrintableAscii {
    <#
    .SYNOPSIS
        Removes non-printable ASCII characters from a string.
    .DESCRIPTION
        This function takes a string as input and returns a new string
        where all characters outside the printable ASCII range (ASCII 32-126)
        have been removed. If the input is null or empty, it returns an empty string.
    .PARAMETER InputString
        The string from which to remove non-printable ASCII characters.
    .EXAMPLE
        Remove-NonPrintableAscii -InputString "Hello`nWorld`t!"
        # Output: "HelloWorld!"

    .EXAMPLE
        "This string has a null character: `0" | Remove-NonPrintableAscii
        # Output: "This string has a null character: "

    .EXAMPLE
        $null | Remove-NonPrintableAscii
        # Output: "" (empty string)

    .EXAMPLE
        "" | Remove-NonPrintableAscii
        # Output: "" (empty string)
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    [OutputType([String])]

    param (
        [Parameter(ValueFromPipeline = $true)]
        [string]$InputString
    )

    process {
        if ($PSCmdlet.ShouldProcess($InputString, 'Remove non-printable ASCII characters')) {
            # Check if the input string is null or empty.
            # If it is, return an empty string immediately to avoid errors.
            if ([string]::IsNullOrEmpty($InputString)) {
                return ''
            }

            # Regular expression to match any character that is NOT a printable ASCII character.
            # [^\x20-\x7E] matches any character that is not in the range of ASCII 32 (space) to 126 (tilde).
            $cleanedString = $InputString -replace '[^\x20-\x7E]', ''
            return $cleanedString
        }
    }
}