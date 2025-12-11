function Get-WinADDuplicateObject {
    <#
    .SYNOPSIS
    Used by As Built Report to get AD duplicate object info.
    .DESCRIPTION

    .NOTES
        Version:        0.1.0
        Author:         Przemysław Kłys

    .EXAMPLE

    .LINK

    #>

    [alias('Get-WinADForestObjectsConflict')]
    [CmdletBinding()]
    param(
        [alias('ForestName')][string] $Forest,
        [string[]] $ExcludeDomains,
        [alias('Domain', 'Domains')][string[]] $IncludeDomains,
        [System.Collections.IDictionary] $ExtendedForestInformation,
        [string] $PartialMatchDistinguishedName,
        [string[]] $IncludeObjectClass,
        [string[]] $ExcludeObjectClass,
        [switch] $Extended,
        [switch] $NoPostProcessing,
        [pscredential] $Credential

    )
    # Based on https://gallery.technet.microsoft.com/scriptcenter/Get-ADForestConflictObjects-4667fa37
    $ForestInformation = Get-WinADForestDetail -Forest $Forest -IncludeDomains $IncludeDomains -ExcludeDomains $ExcludeDomains -ExtendedForestInformation $ExtendedForestInformation -Credential $Credential
    foreach ($Domain in $ForestInformation.Domains) {
        $DC = $ForestInformation['QueryServers']["$Domain"].HostName[0]
        #Get conflict objects
        $getADObjectSplat = @{
            LDAPFilter = "(|(cn=*\0ACNF:*)(ou=*CNF:*))"
            Properties = 'DistinguishedName', 'ObjectClass', 'DisplayName', 'SamAccountName', 'Name', 'ObjectCategory', 'WhenCreated', 'WhenChanged', 'ProtectedFromAccidentalDeletion', 'ObjectGUID'
            Server = $DC
            SearchScope = 'Subtree'
            Credential = $Credential
        }
        $Objects = Get-ADObject @getADObjectSplat
        foreach ($Object in $Objects) {
            # Lets allow users to filter on it
            if ($ExcludeObjectClass) {
                if ($ExcludeObjectClass -contains $Object.ObjectClass) {
                    continue
                }
            }
            if ($IncludeObjectClass) {
                if ($IncludeObjectClass -notcontains $Object.ObjectClass) {
                    continue
                }
            }
            if ($PartialMatchDistinguishedName) {
                if ($Object.DistinguishedName -notlike $PartialMatchDistinguishedName) {
                    continue
                }
            }
            if ($NoPostProcessing) {
                $Object
                continue
            }
            $DomainName = ConvertFrom-DistinguishedName -DistinguishedName $Object.DistinguishedName -ToDomainCN
            # Lets create separate objects for different purpoeses
            $ConflictObject = [ordered] @{
                ConflictDN = $Object.DistinguishedName
                ConflictWhenChanged = $Object.WhenChanged
                DomainName = $DomainName
                ObjectClass = $Object.ObjectClass
            }
            $LiveObjectData = [ordered] @{
                LiveDn = "N/A"
                LiveWhenChanged = "N/A"
            }
            $RestData = [ordered] @{
                DisplayName = $Object.DisplayName
                Name = $Object.Name.Replace("`n", ' ')
                SamAccountName = $Object.SamAccountName
                ObjectCategory = $Object.ObjectCategory
                WhenCreated = $Object.WhenCreated
                WhenChanged = $Object.WhenChanged
                ProtectedFromAccidentalDeletion = $Object.ProtectedFromAccidentalDeletion
                ObjectGUID = $Object.ObjectGUID.Guid
            }
            if ($Extended) {
                $LiveObject = $null
                $ConflictObject = $ConflictObject + $LiveObjectData + $RestData
                #See if we are dealing with a 'cn' conflict object
                if (Select-String -SimpleMatch "\0ACNF:" -InputObject $ConflictObject.ConflictDn) {
                    #Split the conflict object DN so we can remove the conflict notation
                    $SplitConfDN = $ConflictObject.ConflictDn -split "0ACNF:"
                    #Remove the conflict notation from the DN and try to get the live AD object
                    try {
                        $LiveObject = Get-ADObject -Credential $Credential -Identity "$($SplitConfDN[0].TrimEnd("\"))$($SplitConfDN[1].Substring(36))" -Properties WhenChanged -Server $DC -ErrorAction Stop
                    } catch { Out-Null }
                    if ($LiveObject) {
                        $ConflictObject.LiveDN = $LiveObject.DistinguishedName
                        $ConflictObject.LiveWhenChanged = $LiveObject.WhenChanged
                    }
                } else {
                    #Split the conflict object DN so we can remove the conflict notation for OUs
                    $SplitConfDN = $ConflictObject.ConflictDn -split "CNF:"
                    #Remove the conflict notation from the DN and try to get the live AD object
                    try {
                        $LiveObject = Get-ADObject -Credential $Credential -Identity "$($SplitConfDN[0])$($SplitConfDN[1].Substring(36))" -Properties WhenChanged -Server $DC -ErrorAction Stop
                    } catch { Out-Null }
                    if ($LiveObject) {
                        $ConflictObject.LiveDN = $LiveObject.DistinguishedName
                        $ConflictObject.LiveWhenChanged = $LiveObject.WhenChanged
                    }
                }
            } else {
                $ConflictObject = $ConflictObject + $RestData
            }
            [PSCustomObject] $ConflictObject
        }
    }
}