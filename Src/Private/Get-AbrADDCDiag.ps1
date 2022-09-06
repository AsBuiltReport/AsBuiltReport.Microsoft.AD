function Get-AbrADDCDiag {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Domain Sites information.
    .DESCRIPTION

    .NOTES
        Version:        0.7.6
        Author:         Jonathan Colon
        Twitter:        @jcolonfzenpr
        Github:         rebelinux
    .EXAMPLE

    .LINK

    #>
    [CmdletBinding()]
    param (
        [Parameter (
            Position = 0,
            Mandatory)]
            [string]
            $Domain,
            [string]
            $DC
    )

    begin {
        Write-PscriboMessage "Discovering Active Directory DCDiag information for domain $Domain."
    }

    process {
        if ($DC) {
            try {
                Write-PscriboMessage "Discovering Active Directory DCDiag information for DC $DC."
                $DCDIAG = Invoke-DcDiag -DomainController $DC
                if ($DCDIAG) {
                    Section -ExcludeFromTOC -Style NOTOCHeading5 $($DC.ToString().split('.')[0].ToUpper()) {
                        $OutObj = @()
                        $Description = @{
                            "Advertising" = "Validates this Domain Controller can be correctly located through the KDC service. It does not validate the Kerberos tickets answer or the communication through the TCP and UDP port 88.", 'High'
                            "Connectivity" = "Initial connection validation, checks if the DC can be located in the DNS, validates the ICMP ping (1 hop), checks LDAP binding and also the RPC connection. This initial test requires ICMP, LDAP, DNS and RPC connectivity to work properly.", 'Medium'
                            'VerifyReferences' = 'Validates that several attributes are present for the domain in the countainer and subcontainers in the DC objetcs. This test will fail if any attribute is missing.', 'High'
                            'FrsEvent' = 'Checks if theres any errors in the event logs regarding FRS replication. If running Windows Server 2008 R2 or newer on all Domain Controllers is possible SYSVOL were already migrated to DFSR, in this case errors found here can be ignored.', 'Medium'
                            'DFSREvent' = 'Checks if theres any errors in the event logs regarding DFSR replication. If running Windows Server 2008 or older on all Domain Controllers is possible SYSVOL is still using FRS, and in this case errors found here can be ignored. Obs. is highly recommended to migrate SYSVOL to DFSR.', 'Medium'
                            'SysVolCheck' = 'Validates if the registry key HKEY_Local_Machine\System\CurrentControlSet\Services\Netlogon\Parameters\SysvolReady=1 exist. This registry has to exist with value 1 for the DCs SYSVOL to be advertised.', 'High'
                            'KccEvent' = 'Validates through KCC there were no errors in the Event Viewer > Applications and Services Logs > Directory Services event log in the past 15 minutes (default time).', 'High'
                            'KnowsOfRoleHolders' = 'Checks if this Domain Controller is aware of which DC (or DCs) hold the FSMOs.', 'High'
                            'MachineAccount' = 'Checks if this computer account exist in Active Directory and the main attributes are set. If this validation reports error. the following parameters of DCDIAG might help: /RecreateMachineAccount and /FixMachineAccount.', 'High'
                            'NCSecDesc' = 'Validates if permissions are correctly set in this Domain Controller for all naming contexts. Those permissions directly affect replications health.', 'Medium'
                            'NetLogons' = 'Validates if core security groups (including administrators and Authenticated Users) can connect and read NETLOGON and SYSVOL folders. It also validates access to IPC$. which can lead to failures in organizations that disable IPC$.', 'High'
                            'ObjectsReplicated' = 'Checks the replication health of core objects and attributes.', 'High'
                            'Replications' = 'Makes a deep validation to check the main replication for all naming contexts in this Domain Controller.', 'High'
                            'RidManager' = 'Validates this Domain Controller can locate and contact the RID Master FSMO role holder. This test is skipped in RODCs.', 'High'
                            'Services' = 'Validates if the core Active Directory services are running in this Domain Controller. The services verified are: RPCSS, EVENTSYSTEM, DNSCACHE, ISMSERV, KDC, SAMSS, WORKSTATION, W32TIME, NETLOGON, NTDS (in case Windows Server 2008 or newer) and DFSR (if SYSVOL is using DFSR).', 'High'
                            'SystemLog' = 'Checks if there is any erros in the Event Viewer > System event log in the past 60 minutes. Since the System event log records data from many places, errors reported here may lead to false positive and must be investigated further. The impact of this validation is marked as Low.', 'Low'
                            'Topology' = 'Topology Checks that the KCC has generated a fully connected topology for all domain controllers.', 'Medium'
                            'VerifyReplicas' = 'Checks that all application directory partitions are fully instantiated on all replica servers.', 'High'
                            'CutoffServers' = 'Checks for any server that is not receiving replications because its partners are not running', 'Medium'
                            'DNS' = 'DNS Includes six optional DNS-related tests, as well as the Connectivity test, which runs by default.', 'Medium'
                            'CheckSecurityError' = 'Reports on the overall health of replication with respect to Active Directory security in domain controllers running Windows Server 2003 SP1.', 'Medium'
                            'FrsSysVol' = 'Checks that the file replication system (FRS) system volume (SYSVOL) is ready', 'Medium'
                        }
                        Write-PscriboMessage "Discovered Active Directory DCDiag information for DC $DC."
                        foreach ($Result in $DCDIAG | Where-Object {$_.Entity -eq $($DC.ToString().split('.')[0].ToUpper())}) {
                            try {
                                Write-PscriboMessage "Collecting Active Directory DCDiag test '$($Result.TestName)' for DC $DC."
                                $inObj = [ordered] @{
                                    'Test Name' = $Result.TestName
                                    'Result' = $TextInfo.ToTitleCase($Result.TestResult)
                                    'Impact' = $Description[$Result.TestName][1]
                                    'Description' = $Description[$Result.TestName][0]
                                }
                                $OutObj += [pscustomobject]$inobj
                            }
                            catch {
                                Write-PscriboMessage -IsWarning $_.Exception.Message
                            }
                        }
                        if ($HealthCheck.DomainController.Diagnostic) {
                            $OutObj | Where-Object { $_.'Result' -like 'failed'} | Set-Style -Style Critical
                        }
                        $TableParams = @{
                            Name = "DCDiag Test Status - $($DC.ToString().split('.')[0].ToUpper())"
                            List = $false
                            ColumnWidths = 23, 10, 10, 57
                        }
                        if ($Report.ShowTableCaptions) {
                            $TableParams['Caption'] = "- $($TableParams.Name)"
                        }
                        $OutObj | Sort-Object -Property 'Entity' | Table @TableParams
                    }
                }
            }
            catch {
                Write-PscriboMessage -IsWarning $_.Exception.Message
            }
        }
    }

    end {}

}