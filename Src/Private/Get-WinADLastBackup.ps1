function Get-WinADLastBackup {
    <#
    .SYNOPSIS
    Gets Active directory forest or domain last backup time
    .DESCRIPTION
    Gets Active directory forest or domain last backup time
    .PARAMETER Domain
    Optionally you can pass Domains by hand
    .EXAMPLE
    $LastBackup = Get-WinADLastBackup
    $LastBackup | Format-Table -AutoSize
    .EXAMPLE
    $LastBackup = Get-WinADLastBackup -Domain 'ad.evotec.pl'
    $LastBackup | Format-Table -AutoSize
    .NOTES
    General notes
    #>
    [cmdletBinding()]
    param(
        [string[]] $Domains,
        [pscredential] $Credential,
        [ref]$DCStatus
    )
    $NameUsed = [System.Collections.Generic.List[string]]::new()
    [DateTime] $CurrentDate = Get-Date
    if (-not $Domains) {
        try {
            $Forest = $ADSystem
            $Domains = $Forest.Domains
        } catch {
            Write-PScriboMessage -Message "Get-WinADLastBackup - Failed to gather Forest Domains $($_.Exception.Message)"
            break
        }
    }
    foreach ($Domain in $Domains) {
        try {
            $DCServer = Get-ValidDCfromDomain -Domain $Domain -DCStatus $DCStatus
            [string[]]$Partitions = (Get-ADRootDSE -Credential $Credential -Server $DCServer -ErrorAction Stop).namingContexts
            [System.DirectoryServices.ActiveDirectory.DirectoryContextType] $contextType = [System.DirectoryServices.ActiveDirectory.DirectoryContextType]::Domain
            [System.DirectoryServices.ActiveDirectory.DirectoryContext] $context = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext($contextType, $Domain, $Credential.UserName, $Credential.GetNetworkCredential().Password)
            [System.DirectoryServices.ActiveDirectory.DomainController] $domainController = [System.DirectoryServices.ActiveDirectory.DomainController]::FindOne($context)
        } catch {
            Write-PScriboMessage -Message "Get-WinADLastBackup - Failed to gather partitions information for $Domain with error: $($_.Exception.Message)"
            break
        }
        $Output = foreach ($Name in $Partitions) {
            if ($NameUsed -contains $Name) {
                continue
            } else {
                $NameUsed.Add($Name)
            }
            $domainControllerMetadata = $domainController.GetReplicationMetadata($Name)
            $dsaSignature = $domainControllerMetadata.Item("dsaSignature")
            $LastBackup = [DateTime] $($dsaSignature.LastOriginatingChangeTime)
            [PSCustomObject] @{
                Domain = $Domain
                NamingContext = $Name
                LastBackup = $LastBackup
                LastBackupDaysAgo = - (Convert-TimeToDay -StartTime ($CurrentDate) -EndTime ($LastBackup))
            }
        }
        $Output
    }
}