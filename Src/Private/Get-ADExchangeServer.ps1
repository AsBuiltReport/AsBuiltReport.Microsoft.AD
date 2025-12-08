function Get-ADExchangeServer {
    <#
    .SYNOPSIS
    Used by As Built Report to get Exchange information from AD forest.
    .DESCRIPTION

    .NOTES
        Version:        0.1.0
        Author:         Brian Farnsworth

    .EXAMPLE
    Get-ADExchangeServer

    .LINK
    https://codeandkeep.com/PowerShell-ActiveDirectory-Exchange-Part1/
    #>
    function ConvertToExchangeRole {
        param(
            [Parameter(Position = 0)]
            [int]$roles
        )

        $roleNumber = @{
            2 = 'MBX';
            4 = 'CAS';
            16 = 'UM';
            32 = 'HUB';
            64 = 'EDGE';
        }

        $roleList = New-Object -TypeName Collections.ArrayList

        foreach ($key in ($roleNumber).Keys) {
            if ($key -band $roles) {
                [void]$roleList.Add($roleNumber.$key)
            }
        }

        Write-Output $roleList
    }

    # Get the Configuration Context
    $rootDse = Invoke-CommandWithTimeout -Session $TempPssSession -ScriptBlock { Get-ADRootDSE }
    $cfgCtx = $rootDse.ConfigurationNamingContext

    # Query AD for Exchange Servers
    $exchServers = Invoke-CommandWithTimeout -ErrorAction SilentlyContinue -Session $TempPssSession -ScriptBlock { Get-ADObject -Filter "ObjectCategory -eq 'msExchExchangeServer'" -SearchBase $using:cfgCtx -Properties msExchCurrentServerRoles, networkAddress, serialNumber }
    foreach ($server in $exchServers) {
        try {
            $roles = ConvertToExchangeRole -roles $server.msExchCurrentServerRoles

            $fqdn = ($server.networkAddress | Where-Object { $_ -like 'ncacn_ip_tcp:*' }).Split(':')[1]

            New-Object -TypeName PSObject -Property @{
                Name = $server.Name;
                DnsHostName = $fqdn;
                Version = $server.serialNumber[0];
                ServerRoles = $roles;
            }
        } catch {
            Write-PScriboMessage -IsWarning -Message "ExchangeServer: [$($server.Name)]. $($_.Exception.Message)"
        }
    }
}