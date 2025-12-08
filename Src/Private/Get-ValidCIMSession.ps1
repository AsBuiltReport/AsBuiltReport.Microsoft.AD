function Get-ValidCIMSession {
    <#
    .SYNOPSIS
        Used by As Built Report to get generate a valid CIM session.
    .DESCRIPTION
        Function to generate a valid CIM session from a computer string.
    .NOTES
        Version:        0.9.6
        Author:         Jonathan Colon
    .EXAMPLE
        PS C:\Users\JohnDoe> Get-ValidCIMSession -ComputerName 'server-dc-01v.pharmax.local'
            Server-DC-01V.pharmax.local
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
        [ref]$CIMTable
    )

    if ((-not $Options.WinRMFallbackToNoSSL) -and ($CIMTable.Value | Where-Object { $_.DCName -eq $ComputerName -and $_.Status -eq 'Offline' -and $_.Protocol -eq 'CimSessionSSL' })) {
        throw "Unable to connect to $ComputerName through CimSession (CIM with SSL)."
    } elseif (($Options.WinRMFallbackToNoSSL) -and ($CIMSessionObj = $CIMTable.Value | Where-Object { $_.DCName -eq $ComputerName -and $_.Status -eq 'Online' -and $_.Protocol -eq 'CimSession' })) {
        Write-PScriboMessage -Message "Unable to connect to $ComputerName through CimSession (CIM with SSL)."
        Write-PScriboMessage -Message "WinRMFallbackToNoSSL option set using available '$ComputerName' CimSession id: $($CIMSessionObj.Id) (WinRM)."
        return Get-CimSession $CIMSessionObj.Id
    }

    if ($Options.WinRMSSL) {
        if ($CIMSessionObj = $CIMTable.Value | Where-Object { $_.DCName -eq $ComputerName -and $_.Status -eq 'Online' -and $_.Protocol -eq 'CimSessionSSL' }) {
            Write-PScriboMessage -Message "Using available '$ComputerName' CIMSession id: $($CIMSessionObj.Id) (CimSession)."
            return Get-CimSession $CIMSessionObj.Id
        } else {
            try {
                Write-PScriboMessage -Message "No available CimSession with SSL found for '$ComputerName': Generating a new one."
                $CimSessionOptions = New-CimSessionOption -ProxyAuthentication $Options.PSDefaultAuthentication -ProxyCredential $Credential -UseSsl
                Write-PScriboMessage -Message "Connecting to '$ComputerName' through CimSession with SSL."
                if ($CIMSessionObj = New-CimSession $ComputerName -SessionOption $CimSessionOptions -Port $Options.WinRMSSLPort -Name $SessionName -ErrorAction Stop) {
                    Write-PScriboMessage -Message "Connected to '$ComputerName' through CimSession with SSL."
                    $CIMTable.Value += @{
                        DCName = $ComputerName
                        Status = 'Online'
                        Protocol = 'CimSessionSSL'
                        Id = $CIMSessionObj.Id
                        InstanceId = $CIMSessionObj.InstanceId
                    }
                    $CIMSessionObj
                }
            } catch {
                if ($Options.WinRMFallbackToNoSSL) {
                    Write-PScriboMessage -Message "Unable to Connect to '$ComputerName' through CimSession with SSL. Reverting to Cim without SSL!"
                    $CIMTable.Value += @{
                        DCName = $ComputerName
                        Status = 'Offline'
                        Protocol = 'CimSessionSSL'
                        Id = 'None'
                        InstanceId = 'None'
                    }
                    try {
                        if ($CIMSessionObj = New-CimSession $ComputerName -Credential $Credential -Authentication $Options.PSDefaultAuthentication -ErrorAction Stop -Name $SessionName -Port $Options.WinRMPort) {
                            Write-PScriboMessage -Message "Connected to '$ComputerName' through CimSession without SSL."
                            $CIMTable.Value += @{
                                DCName = $ComputerName
                                Status = 'Online'
                                Protocol = 'CimSession'
                                Id = $CIMSessionObj.Id
                                InstanceId = $CIMSessionObj.InstanceId
                            }
                            $CIMSessionObj
                        }
                    } catch {
                        Write-PScriboMessage -Message "Unable to Connect to '$ComputerName' through CimSession without SSL."
                        $CIMTable.Value += @{
                            DCName = $ComputerName
                            Status = 'Offline'
                            Protocol = 'CimSession'
                            Id = 'None'
                            InstanceId = 'None'
                        }
                    }
                }
            }
        }
    } else {
        if ($CIMTable.Value | Where-Object { $_.DCName -eq $ComputerName -and $_.Status -eq 'Offline' -and $_.Protocol -eq 'CimSession' }) {
            throw "Unable to connect to $ComputerName through CimSession (CimSession)."
        } elseif ($CIMSessionObj = $CIMTable.Value | Where-Object { $_.DCName -eq $ComputerName -and $_.Status -eq 'Online' -and $_.Protocol -eq 'CimSession' }) {
            Write-PScriboMessage -Message "Using available '$ComputerName' CIMSession id: $($CIMSessionObj.Id) (CimSession without SSL)."
            return Get-CimSession $CIMSessionObj.Id
        } else {
            Write-PScriboMessage -Message "Connecting to '$ComputerName' through CimSession without SSL."
            try {
                if ($CIMSessionObj = New-CimSession $ComputerName -Credential $Credential -Authentication $Options.PSDefaultAuthentication -Name $SessionName -Port $Options.WinRMPort) {
                    Write-PScriboMessage -Message "Connected to '$ComputerName' CimSession without SSL."
                    $CIMTable.Value += @{
                        DCName = $ComputerName
                        Status = 'Online'
                        Protocol = 'CimSession'
                        Id = $CIMSessionObj.Id
                        InstanceId = $CIMSessionObj.InstanceId
                    }
                    $CIMSessionObj
                }
            } catch {
                Write-PScriboMessage -Message "Unable to Connect to '$ComputerName' through CimSession without SSL."
                $CIMTable.Value += @{
                    DCName = $ComputerName
                    Status = 'Offline'
                    Protocol = 'CimSession'
                    Id = 'None'
                    InstanceId = 'None'
                }
            }
        }
    }
}# end