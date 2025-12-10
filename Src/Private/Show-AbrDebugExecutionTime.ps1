function Show-AbrDebugExecutionTime {
    <#
    .SYNOPSIS
    Tracks and logs the execution time of a specific operation or script block.

    .PARAMETER Start
    Indicates the start of the execution time tracking.

    .PARAMETER End
    Indicates the end of the execution time tracking.

    .PARAMETER TitleMessage
    Specifies a custom message or title to associate with the execution time log.

    .DESCRIPTION
    This function is used to measure and log the execution time of a specific operation or script block.
    The Start switch initializes the timer, and the End switch stops the timer and logs the elapsed time.
    An optional TitleMessage can be provided to include a descriptive label in the log.

    .EXAMPLE
    Get-AbrDebugExecutionTime -Start -TitleMessage "Starting operation"
    # Perform some operations
    Get-AbrDebugExecutionTime -End -TitleMessage "Ending operation"

    .NOTES
    This function is typically used for debugging or performance analysis purposes.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'Start')]
        [Switch]$Start,

        [Parameter(Mandatory = $true, ParameterSetName = 'End')]
        [Switch]$End,

        [Parameter(Mandatory = $false)]
        [string]$TitleMessage = "Operation"
    )

    begin {
    }

    process {
        try {
            if ($Options.ShowExecutionTime -and $Start) {
                $script:SectionStartTime = Get-Date
            }
        } catch { Out-Null }

        try {
            if ($Options.ShowExecutionTime -and $End) {
                $script:SectionEndTime = Get-Date
                $elapsedTime = New-TimeSpan -Start $SectionStartTime -End $SectionEndTime
                Write-Host -ForegroundColor Cyan "$($TitleMessage) section execution time [hh:mm:ss]: $($elapsedTime.tostring("hh")):$($elapsedTime.tostring("mm")):$($elapsedTime.tostring("ss"))"
            }
        } catch { Out-Null }
    }

    end {}

}