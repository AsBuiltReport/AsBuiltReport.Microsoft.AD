function Test-ComputerPort {
    [CmdletBinding()]
    param (
        [alias('Server')][string[]] $ComputerName,
        [int[]] $PortTCP,
        [int[]] $PortUDP,
        [int]$Timeout = 5000
    )
    begin {
        if ($Global:ProgressPreference -ne 'SilentlyContinue') {
            $TemporaryProgress = $Global:ProgressPreference
            $Global:ProgressPreference = 'SilentlyContinue'
        }
    }
    process {
        foreach ($Computer in $ComputerName) {
            foreach ($P in $PortTCP) {
                $Output = [ordered] @{
                    'ComputerName' = $Computer
                    'Port' = $P
                    'Protocol' = 'TCP'
                    'Status' = $null
                    'Summary' = $null
                    'Response' = $null
                }

                $TcpClient = Test-NetConnection -ComputerName $Computer -Port $P -InformationLevel Detailed -WarningAction SilentlyContinue
                if ($TcpClient.TcpTestSucceeded) {
                    $Output['Status'] = $TcpClient.TcpTestSucceeded
                    $Output['Summary'] = "TCP $P Successful"
                } else {
                    $Output['Status'] = $false
                    $Output['Summary'] = "TCP $P Failed"
                    $Output['Response'] = $Warnings
                }
                [PSCustomObject]$Output
            }
            foreach ($P in $PortUDP) {
                $Output = [ordered] @{
                    'ComputerName' = $Computer
                    'Port' = $P
                    'Protocol' = 'UDP'
                    'Status' = $null
                    'Summary' = $null
                }
                $UdpClient = [System.Net.Sockets.UdpClient]::new($Computer, $P)
                $UdpClient.Client.ReceiveTimeout = $Timeout
                # $UdpClient.Connect($Computer, $P)
                $Encoding = [System.Text.ASCIIEncoding]::new()
                $byte = $Encoding.GetBytes('Evotec')
                [void]$UdpClient.Send($byte, $byte.length)
                $RemoteEndpoint = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 0)
                try {
                    $Bytes = $UdpClient.Receive([ref]$RemoteEndpoint)
                    [string]$Data = $Encoding.GetString($Bytes)
                    if ($Data) {
                        $Output['Status'] = $true
                        $Output['Summary'] = "UDP $P Successful"
                        $Output['Response'] = $Data
                    }
                } catch {
                    $Output['Status'] = $false
                    $Output['Summary'] = "UDP $P Failed"
                    $Output['Response'] = $_.Exception.Message
                }
                $UdpClient.Close()
                $UdpClient.Dispose()
                [PSCustomObject]$Output
            }

        }
    }
    end {
        # Bring back setting as per default
        if ($TemporaryProgress) {
            $Global:ProgressPreference = $TemporaryProgress
        }
    }
}