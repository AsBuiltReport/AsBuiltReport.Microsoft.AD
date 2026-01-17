function Get-DCWinRMState {
    <#
    .SYNOPSIS
        Checks the WinRM status of a specified domain controller.

    .DESCRIPTION
        The Get-DCWinRMState function checks if the Windows Remote Management (WinRM) service is available and accessible on a specified domain controller.

    .PARAMETER ComputerName
        The name of the computer (domain controller) to check the WinRM status for.

    .OUTPUTS
        [Bool]
        Returns $true if WinRM is accessible on the specified computer, otherwise returns $false.

    .EXAMPLE
        PS C:\> Get-DCWinRMState -ComputerName "DC01"
        Checks the WinRM status on the domain controller named "DC01".

    .NOTES
        This function requires the PScribo module for logging messages.
        Ensure that the $Credential and $Options variables are properly set in the calling scope.
    #>
    [CmdletBinding()]
    [OutputType([Bool])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ComputerName,
        [ref]$DCStatus
    )
    if ($Options.DCStatusPingCount) { $DCStatusPingCount = $Options.DCStatusPingCount } else { $DCStatusPingCount = 2 }
    $PingStatus = switch (Test-Connection -ComputerName $ComputerName -Count $DCStatusPingCount -Quiet) {
        'True' { 'Online' }
        'False' { 'Offline' }
    }

    Write-PScriboMessage -Message "Validating WinRM status of $ComputerName in Cache"
    if ($DCStatus.Value | Where-Object { $_.DCName -eq $ComputerName -and $_.Status -eq 'Offline' -and $_.Protocol -eq 'WinRMSSL' }) {
        Write-PScriboMessage -Message "Valid WinRM status of $ComputerName found in Cache: Offline"
        return $false
    } elseif ($DCStatus.Value | Where-Object { $_.DCName -eq $ComputerName -and $_.Status -eq 'Offline' -and $_.Protocol -eq 'WinRM' }) {
        Write-PScriboMessage -Message "Valid WinRM status of $ComputerName found in Cache: Offline"
        return $false
    }


    if ($DCStatus.Value | Where-Object { $_.DCName -eq $ComputerName -and $_.Status -eq 'Online' }) {
        Write-PScriboMessage -Message "Valid WinRM status of $ComputerName found in Cache: return True"
        return $true
    } else {
        Write-PScriboMessage -Message "No valid WinRM status of $ComputerName found in Cache: Building new connection."
        # build the connection to the DC
        $ConnectionParams = @{
            ComputerName = $ComputerName
            Credential = $Credential
            Authentication = $Options.PSDefaultAuthentication
            ErrorAction = 'SilentlyContinue'
        }

        if ($Options.WinRMSSL) {
            $ConnectionParams.Add('UseSSL', $true)
            $ConnectionParams.Add('Port', $Options.WinRMSSLPort)
            $WinRMType = 'WinRMSSL'
        } else {
            $ConnectionParams.Add('Port', $Options.WinRMPort)
            $WinRMType = 'WinRM'
        }

        if (Test-WSMan @ConnectionParams) {
            $DCStatus.Value += @{
                DCName = $ComputerName
                Status = 'Online'
                Protocol = $WinRMType
                PingStatus = $PingStatus
            }
            Write-PScriboMessage -Message "WinRM status in $ComputerName is Online ($WinRMType)."
            return $true
        }

        if ($Options.WinRMFallbackToNoSSL) {
            $ConnectionParams['UseSSL'] = $false
            $ConnectionParams['Port'] = $Options.WinRMPort
            $WinRMType = 'WinRM'
            if (Test-WSMan @ConnectionParams) {
                Write-PScriboMessage -Message "WinRM status in $ComputerName is Online ($WinRMType)."
                $DCStatus.Value += @{
                    DCName = $ComputerName
                    Status = 'Online'
                    Protocol = $WinRMType
                    PingStatus = $PingStatus
                }
                return $true
            } else {
                Write-PScriboMessage -Message "Unable to connect to $ComputerName through $WinRMType."
                $DCStatus.Value += @{
                    DCName = $ComputerName
                    Status = 'Offline'
                    Protocol = $WinRMType
                    PingStatus = $PingStatus
                }
                return $false
            }

        } else {
            $DCStatus.Value += @{
                DCName = $ComputerName
                Status = 'Offline'
                Protocol = $WinRMType
                PingStatus = $PingStatus
            }
            Write-PScriboMessage -Message "Unable to connect to $ComputerName through $WinRMType."
            return $false
        }
    }
}# end