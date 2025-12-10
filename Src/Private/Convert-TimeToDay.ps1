function Convert-TimeToDay {
    [CmdletBinding()]
    param (
        $StartTime,
        $EndTime,
        #[nullable[DateTime]] $StartTime, # can't use this just yet, some old code uses strings in StartTime/EndTime.
        #[nullable[DateTime]] $EndTime, # After that's fixed will change this.
        [string] $Ignore = '*1601*'
    )
    if ($null -ne $StartTime -and $null -ne $EndTime) {
        try {
            if ($StartTime -notlike $Ignore -and $EndTime -notlike $Ignore) {
                $Days = (New-TimeSpan -Start $StartTime -End $EndTime).Days
            }
        } catch { Out-Null }
    } elseif ($null -ne $EndTime) {
        if ($StartTime -notlike $Ignore -and $EndTime -notlike $Ignore) {
            $Days = (New-TimeSpan -Start (Get-Date) -End ($EndTime)).Days
        }
    } elseif ($null -ne $StartTime) {
        if ($StartTime -notlike $Ignore -and $EndTime -notlike $Ignore) {
            $Days = (New-TimeSpan -Start $StartTime -End (Get-Date)).Days
        }
    }
    return $Days
}