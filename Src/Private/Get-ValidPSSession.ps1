function Get-ValidPSSession {
    <#
    .SYNOPSIS
        Used by As Built Report to get generate a valid WinRM session.
    .DESCRIPTION
        Function to generate a valid WinRM session from a computer string.
    .NOTES
        Version:        0.9.6
        Author:         Jonathan Colon
    .EXAMPLE
        PS C:\Users\JohnDoe> Get-ValidPSSession -ComputerName 'server-dc-01v.pharmax.local'
            Id Name            ComputerName    ComputerType    State         ConfigurationName     Availability
            -- ----            ------------    ------------    -----         -----------------     ------------
            9 Global:TempP... server-dc-01... RemoteMachine   Opened        Microsoft.PowerShell     Available

    .Todo
    #>
    [CmdletBinding()]
    [OutputType([String])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ComputerName,
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$SessionName,
        [ref]$PSSTable,
        [bool]$InitialForrestConnection = $false
    )

    if ((-not $Options.WinRMFallbackToNoSSL) -and ($PSSTable.Value | Where-Object { $_.DCName -eq $ComputerName -and $_.Status -eq 'Offline' -and $_.Protocol -eq 'PSSessionSSL' })) {
        throw "Unable to connect to $ComputerName through PSSession (WinRM with SSL)."
    } elseif (($Options.WinRMFallbackToNoSSL) -and ($PSessionObj = $PSSTable.Value | Where-Object { $_.DCName -eq $ComputerName -and $_.Status -eq 'Online' -and $_.Protocol -eq 'PSSession' })) {
        # Write-PScriboMessage -Message "Unable to connect to $ComputerName through PSSession (WinRM with SSL)."
        Write-PScriboMessage -Message "Using available '$ComputerName' PSSession id: $($PSessionObj.Id) (WinRM)."
        return Get-PSSession $PSessionObj.Id
    }

    if ($Options.WinRMSSL) {
        if ($PSessionObj = $PSSTable.Value | Where-Object { $_.DCName -eq $ComputerName -and $_.Status -eq 'Online' -and $_.Protocol -eq 'PSSessionSSL' }) {
            Write-PScriboMessage -Message "Using available '$ComputerName' PSSession id: $($PSessionObj.Id) (WinRM with SSL)."
            return Get-PSSession $PSessionObj.Id
        } else {
            try {
                Write-PScriboMessage -Message "Connecting to '$ComputerName' through PSSession with SSL."
                if ($SessionObject = New-PSSession $ComputerName -Credential $Credential -Authentication $Options.PSDefaultAuthentication -ErrorAction Stop -Name $SessionName -UseSSL -Port $Options.WinRMSSLPort) {
                    Write-PScriboMessage -Message "Connected to '$ComputerName' through PSSession (WinRM with SSL)."
                    $PSSTable.Value += @{
                        DCName = $ComputerName
                        Status = 'Online'
                        Protocol = 'PSSessionSSL'
                        Id = $SessionObject.Id
                    }
                    return $SessionObject
                }
            } catch {
                Write-PScriboMessage -Message "Unable to Connect to '$ComputerName' through PSSession with SSL."
                $PSSTable.Value += @{
                    DCName = $ComputerName
                    Status = 'Offline'
                    Protocol = 'PSSessionSSL'
                    Id = 'None'
                }
                if ($Options.WinRMFallbackToNoSSL) {
                    if ($PSessionObj = Get-PSSession | Where-Object { $_.ComputerName -eq $ComputerName -and $_.Availability -eq 'Available' -and $_.State -eq 'Opened' -and $_.Runspace.ConnectionInfo.Scheme -eq 'http' -and $_.Runspace.ConnectionInfo.Credential.Username -eq $Credential.UserName }) {
                        Write-PScriboMessage -Message "Using available '$ComputerName' PSSession id: $($PSessionObj.Id) (WinRM without SSL)."
                        $PSSTable.Value += @{
                            DCName = $ComputerName
                            Status = 'Online'
                            Protocol = 'PSSession'
                            Id = $PSessionObj.Id
                        }
                        return $PSessionObj
                    } else {
                        Write-PScriboMessage -Message "Generating a PSSession to '$ComputerName' (WinRM without SSL)."
                        try {
                            if ($SessionObject = New-PSSession $ComputerName -Credential $Credential -Authentication $Options.PSDefaultAuthentication -ErrorAction Stop -Name $SessionName -Port $Options.WinRMPort) {
                                Write-PScriboMessage -Message "Connected to '$ComputerName' through PSSession (WinRM without SSL)."
                                $PSSTable.Value += @{
                                    DCName = $ComputerName
                                    Status = 'Online'
                                    Protocol = 'PSSession'
                                    Id = $SessionObject.Id
                                }
                                return $SessionObject
                            }
                        } catch {
                            $PSSTable.Value += @{
                                DCName = $ComputerName
                                Status = 'Offline'
                                Protocol = 'PSSession'
                                Id = 'None'
                            }
                            if ($InitialForrestConnection) {
                                throw "Unable to Connect to '$ComputerName' through PSSession. Error details: $($_.Exception.Message)"
                            } else {
                                Write-PScriboMessage -Message "Unable to Connect to '$ComputerName' through PSSession."
                            }
                        }
                    }
                } else {
                    throw
                }
            }
        }
    } else {
        if ($PSSTable.Value | Where-Object { $_.DCName -eq $ComputerName -and $_.Status -eq 'Offline' -and $_.Protocol -eq 'PSSession' }) {
            throw "Unable to connect to $ComputerName through PSSession (WinRM)."
        } elseif ($PSessionObj = $PSSTable.Value | Where-Object { $_.DCName -eq $ComputerName -and $_.Status -eq 'Online' -and $_.Protocol -eq 'PSSession' }) {
            Write-PScriboMessage -Message "Using available '$ComputerName' PSSession id: $($PSessionObj.Id)"
            return Get-PSSession $PSessionObj.Id
        } else {
            Write-PScriboMessage -Message "Generating a PSSession to '$ComputerName'."
            try {
                if ($SessionObject = New-PSSession $ComputerName -Credential $Credential -Authentication $Options.PSDefaultAuthentication -ErrorAction Stop -Name $SessionName -Port $Options.WinRMPort) {
                    $PSSTable.Value += @{
                        DCName = $ComputerName
                        Status = 'Online'
                        Protocol = 'PSSession'
                        Id = $SessionObject.Id
                    }
                    return $SessionObject
                }
            } catch {
                $PSSTable.Value += @{
                    DCName = $ComputerName
                    Status = 'Offline'
                    Protocol = 'PSSession'
                    Id = 'None'
                }
                if ($InitialForrestConnection) {
                    throw "Unable to Connect to '$ComputerName' through PSSession. Error details: $($_.Exception.Message)"
                } else {
                    Write-PScriboMessage -Message "Unable to Connect to '$ComputerName' through PSSession."
                }
            }
        }
    }
}# end