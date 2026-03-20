function Get-ADObjectList {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Active Directory objects via the LDAP protocol.
    .DESCRIPTION
    Queries Active Directory objects using the LDAP:// protocol with explicit credential-based
    authentication. Supports retrieving Users, Computers, Groups, DomainControllers, GPOs, and OUs.

    .NOTES
        Version:        0.2.0
        Author:         Jonathan Colon

    .EXAMPLE
        Get-ADObjectList -Domain 'contoso.com' -Server 'dc01.contoso.com' -Object 'Users' -Credential $Cred

    .LINK

    #>
    [OutputType([System.Collections.Generic.List[PSObject]])]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Domain,

        [Parameter(Mandatory = $false)]
        [string]$Server,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Users', 'Computers', 'Groups', 'DomainControllers', 'GPOs', 'OUs')]
        [string[]]$Object,

        [Parameter(Mandatory = $false)]
        [pscredential]$Credential
    )

    $adObjects = [System.Collections.Generic.List[PSObject]]::new()
    $ConstructedDomainName = ($Domain.Split('.') | ForEach-Object { "DC=$_" }) -join ','

    if ($Server) {
        $ldapPath = "LDAP://$Server/$ConstructedDomainName"
    } else {
        $ldapPath = "LDAP://$ConstructedDomainName"
    }

    if ($Credential) {
        $directoryEntry = New-Object System.DirectoryServices.DirectoryEntry($ldapPath, $Credential.UserName, $Credential.GetNetworkCredential().Password)
    } else {
        $directoryEntry = New-Object System.DirectoryServices.DirectoryEntry($ldapPath)
    }

    $searcher = New-Object System.DirectoryServices.DirectorySearcher($directoryEntry)
    $searcher.PageSize = 1000
    $searcher.PropertiesToLoad.Add('*')
    $searcher.SearchScope = 'Subtree'

    # Construct the LDAP filter based on the -Object parameter
    $filters = [System.Collections.Generic.List[object]]::new()
    foreach ($item in $Object) {
        switch ($item) {
            'Users' { $filters.Add('(objectCategory=person)') }
            'Computers' { $filters.Add('(objectCategory=computer)') }
            'Groups' { $filters.Add('(objectCategory=group)') }
            'DomainControllers' { $filters.Add('(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))') }
            'OUs' { $filters.Add('(objectCategory=organizationalUnit)') }
            'GPOs' { $filters.Add('(objectClass=groupPolicyContainer)') }
        }
    }

    # Combine the filters with an OR if multiple categories are specified
    if ($filters.Count -gt 1) {
        $searcher.Filter = '(|' + ($filters -join '') + ')'
    } elseif ($filters.Count -eq 1) {
        $searcher.Filter = $filters[0]
    } else {
        $searcher.Filter = '(objectClass=*)'
    }

    $results = $searcher.FindAll()
    foreach ($result in $results) {
        $properties = $result.Properties
        $obj = New-Object PSObject
        foreach ($propertyName in $properties.PropertyNames) {
            $value = if ($properties[$propertyName].Count -eq 1) { $properties[$propertyName][0] } else { $properties[$propertyName] }
            $obj | Add-Member -NotePropertyName $propertyName -NotePropertyValue $value
        }
        $obj | Add-Member -NotePropertyName 'domain' -NotePropertyValue $Domain
        $adObjects.Add($obj)
    }
    $results.Dispose()
    $searcher.Dispose()
    $directoryEntry.Dispose()
    $adObjects
}