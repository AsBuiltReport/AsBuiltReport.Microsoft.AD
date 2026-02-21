function Get-ADObjectList {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Domain,

        [Parameter(Mandatory = $false)]
        [string]$Server,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Users', 'Computers', 'Groups', 'DomainControllers', 'GPOs', 'OUs')]
        [string[]]$Object
    )

    [System.Collections.Generic.List[PSObject]]$adObjects = [System.Collections.ArrayList]::new()
    $searcher = New-Object System.DirectoryServices.DirectorySearcher
    $ConstructedDomainName = 'DC=' + $Domain.Split('.')
    $ConstructedDomainName = $ConstructedDomainName -replace ' ', ',DC='

    if ($Server) {
        $searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Server/$ConstructedDomainName", $Credential.UserName, $Credential.GetNetworkCredential().Password)
    } else {
        $searcher.SearchRoot = "LDAP://$ConstructedDomainName"
    }

    $searcher.PageSize = 1000
    $searcher.PropertiesToLoad.Add('*') | Out-Null
    $searcher.SearchScope = 'Subtree'

    # Construct the LDAP filter based on the -Collect parameter
    $filters = [System.Collections.ArrayList]::new()
    foreach ($item in $Object) {
        switch ($item) {
            'Users' { $filters.Add('(objectCategory=person)') | Out-Null }
            'Computers' { $filters.Add('(objectCategory=computer)') | Out-Null }
            'Groups' { $filters.Add('(objectCategory=group)') | Out-Null }
            'DomainControllers' { $filters.Add('(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))') | Out-Null }
            'OUs' { $filters.Add('(objectCategory=organizationalUnit)') | Out-Null }
            'GPOs' { $filters.Add('(objectClass=groupPolicyContainer)') | Out-Null }
        }
    }
    # Combine the filters with an OR if multiple categories are specified
    $searcher.Filter = if ($filters.Count -gt 1) { '(|' + ($filters -join '') + ')' } else { $filters[0] }

    $results = $searcher.FindAll()
    foreach ($result in $results) {
        $properties = $result.Properties
        $obj = New-Object PSObject
        foreach ($propertyName in $properties.PropertyNames) {
            $value = if ($properties[$propertyName].Count -eq 1) { $properties[$propertyName][0] } else { $properties[$propertyName] }
            $obj | Add-Member -NotePropertyName $propertyName -NotePropertyValue $value
        }
        $obj | Add-Member -NotePropertyName 'domain' -NotePropertyValue $Domain
        $adObjects.Add($obj) | Out-Null
    }
    $searcher.Dispose()
    $adObjects
}