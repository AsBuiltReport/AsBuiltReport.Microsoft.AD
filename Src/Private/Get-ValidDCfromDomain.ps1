function Get-ValidDCfromDomain {
    <#
    .SYNOPSIS
        Used by As Built Report to get a valid Domain Controller from Domain.
    .DESCRIPTION
        Function to get a valid DC from a Active Directory Domain string.
        It use Test-WsMan to test WinRM status of the machine.
    .NOTES
        Version:        0.1.0
        Author:         Jonathan Colon
    .EXAMPLE
        PS C:\Users\JohnDoe> Get-ValidDCfromDomain -Domain 'pharmax.local'
            Server-DC-01V.pharmax.local
    #>
    [CmdletBinding()]
    [OutputType([String])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Domain,
        [ref]$DCStatus
    )

    $DCList = Invoke-CommandWithTimeout -Session $TempPssSession -ScriptBlock { (Get-ADDomain -Identity $using:Domain).ReplicaDirectoryServers }

    if ($DCList) {
        foreach ($TestedDC in $DCList) {
            if (Get-DCWinRMState -ComputerName $TestedDC -DCStatus $DCStatus) {
                Write-PScriboMessage -Message "Using $TestedDC to retreive $Domain information."
                $TestedDC
                break
            } else {
                Write-PScriboMessage -Message "Unable to connect to $TestedDC to retreive $Domain information."
            }
        }
    } else {
        Write-PScriboMessage -Message "Unable to connect to $Domain to get a valid Domain Controller list."
    }
}# end