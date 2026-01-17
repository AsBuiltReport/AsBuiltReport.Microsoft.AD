function Invoke-DcDiag {
    <#
    .SYNOPSIS
    Used by As Built Report to get the dcdiag tests for a Domain Controller.
    .DESCRIPTION

    .NOTES
        Version:        0.9.9
        Author:         Adam Bertram

    .EXAMPLE

    .LINK

    #>
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$DomainController
    )

    $DCPssSessionDCDiag = Get-ValidPSSession -ComputerName $DomainController -SessionName "$($DomainController)_DCDiag" -PSSTable ([ref]$PSSTable)

    try {
        $result = Invoke-CommandWithTimeout -Session $DCPssSessionDCDiag -ScriptBlock { dcdiag /c /s:$using:DomainController } -TimeoutSeconds 60
    } catch {
        Write-PScriboMessage -Message "Invoke-DcDiag - Failed to get DCDiag for $DomainController with error: $($_.Exception.Message)"
        return
    }

    if ($result) {
        $result | Select-String -Pattern '\. (.*) \b(passed|failed)\b test (.*)' | ForEach-Object {
            $obj = @{
                TestName = $_.Matches.Groups[3].Value
                TestResult = $_.Matches.Groups[2].Value
                Entity = $_.Matches.Groups[1].Value
            }
            [pscustomobject]$obj
        }
    }
}# end