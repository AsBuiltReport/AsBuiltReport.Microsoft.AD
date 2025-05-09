function Show-AbrDebugExecutionTime {
    <#
    .SYNOPSIS
    Used by As Built Report to debug execution time
    .DESCRIPTION

    .NOTES
        Version:        0.9.6
        Author:         Jonathan Colon
        Twitter:        @jcolonfzenpr
        Github:         rebelinux
    .EXAMPLE

    .LINK

    #>
    [CmdletBinding()]
    param (
        [Switch]$Start,
        [Switch]$End,
        [string]$TitleMessage
    )

    begin {
    }

    process {
        if ($Start) {
            $script:SectionStartTime = Get-Date
            Write-Host "Beginning $($TitleMessage) section: $($SectionStartTime)" -ForegroundColor Cyan
        }

        if ($End) {
            $script:SectionEndTime = Get-Date
            # Write-Host "Ending $($TitleMessage) section: $($SectionEndTime)" -ForegroundColor Cyan
            $elapsedTime = New-TimeSpan -Start $SectionStartTime -End $SectionEndTime
            Write-Host "$($TitleMessage) section execution time: $($elapsedTime.tostring("hh")) Hours $($elapsedTime.tostring("mm")) Minutes $($elapsedTime.tostring("ss")) Seconds"
        }
    }

    end {}

}