function ConvertTo-HashToYN {
    <#
    .SYNOPSIS
        Used by As Built Report to convert array content true or false automatically to Yes or No.
    .DESCRIPTION
        Used by As Built Report to convert array content true or false automatically to Yes or No.
        Now also strips non-printable ASCII characters from string values while creating the array hash.
		This is required for Word Document Output as PSCribo cannot create Word documents with non-ASCII characters
    .NOTES
        Version:        0.1.1
        Author:         Jonathan Colon
        Changes:        0.1.1 - Updated to include non-unicode character string cleaning. Graham Flynn - 30/07/2025

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
            $valueToProcess = $i.Value

            # Check if the value is a string before attempting to clean it
            if ($valueToProcess -is [string]) {
                $valueToProcess = $valueToProcess | Remove-NonPrintableAscii
            }

            $convertedValue = ConvertTo-TextYN $valueToProcess

            $result.add($i.Key, $convertedValue)
        } catch {
            # If ConvertTo-TextYN fails, still try to clean the original value if it's a string
            $originalValue = $i.Value
            if ($originalValue -is [string]) {
                $originalValue = $originalValue | Remove-NonPrintableAscii
            }
            $result.add($i.Key, ($originalValue)) # Add the (potentially cleaned) original value
        }
    }
    if ($result) {
        return $result
    } else {
        return $TEXT
    }
} # end