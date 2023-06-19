function Get-AbrADForest {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD information from Domain Controller
    .DESCRIPTION

    .NOTES
        Version:        0.7.2
        Author:         Jonathan Colon
        Twitter:        @jcolonfzenpr
        Github:         rebelinux
    .EXAMPLE

    .LINK

    #>
    [CmdletBinding()]
    param (
    )

    begin {
        Write-PscriboMessage "Discovering Active Directory forest information."
    }

    process {
        try {
            $Data = Invoke-Command -Session $TempPssSession {Get-ADForest}
            $ForestInfo =  $Data.RootDomain.toUpper()
            Write-PscriboMessage "Discovered Active Directory information of forest $ForestInfo."
            $DomainDN = Invoke-Command -Session $TempPssSession {(Get-ADDomain -Identity (Get-ADForest | Select-Object -ExpandProperty RootDomain )).DistinguishedName}
            $TombstoneLifetime = Invoke-Command -Session $TempPssSession {Get-ADObject "CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,$using:DomainDN" -Properties tombstoneLifetime | Select-Object -ExpandProperty tombstoneLifetime}
            $ADVersion = Invoke-Command -Session $TempPssSession {Get-ADObject (Get-ADRootDSE).schemaNamingContext -property objectVersion | Select-Object -ExpandProperty objectVersion}
            $ValuedsHeuristics = Invoke-Command -Session $TempPssSession {Get-ADObject -Identity "CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,$(($using:DomainDN))" -Properties dsHeuristics -ErrorAction SilentlyContinue}

            If ($ADVersion -eq '88') {$server = 'Windows Server 2019'}
            ElseIf ($ADVersion -eq '87') {$server = 'Windows Server 2016'}
            ElseIf ($ADVersion -eq '69') {$server = 'Windows Server 2012 R2'}
            ElseIf ($ADVersion -eq '56') {$server = 'Windows Server 2012'}
            ElseIf ($ADVersion -eq '47') {$server = 'Windows Server 2008 R2'}
            ElseIf ($ADVersion -eq '44') {$server = 'Windows Server 2008'}
            ElseIf ($ADVersion -eq '31') {$server = 'Windows Server 2003 R2'}
            ElseIf ($ADVersion -eq '30') {$server = 'Windows Server 2003'}
            $OutObj = @()
            if ($Data) {
                Write-PscriboMessage "Collecting Active Directory information of forest $ForestInfo."
                foreach ($Item in $Data) {
                    try {
                        $inObj = [ordered] @{
                            'Forest Name' = $Item.RootDomain
                            'Forest Functional Level' = $Item.ForestMode
                            'Schema Version' = "ObjectVersion $ADVersion, Correspond to $server"
                            'Tombstone Lifetime (days)' = $TombstoneLifetime
                            'Domains' = $Item.Domains -join '; '
                            'Global Catalogs' = $Item.GlobalCatalogs -join '; '
                            'Domains Count' = $Item.Domains.Count
                            'Global Catalogs Count' = $Item.GlobalCatalogs.Count
                            'Sites Count' = $Item.Sites.Count
                            'Application Partitions' = $Item.ApplicationPartitions
                            'PartitionsContainer' = [string]$Item.PartitionsContainer
                            'SPN Suffixes' = ConvertTo-EmptyToFiller $Item.SPNSuffixes
                            'UPN Suffixes' = ConvertTo-EmptyToFiller ($Item.UPNSuffixes -join ', ')
                            'Anonymous Access (dsHeuristics)' = &{
                                if (($ValuedsHeuristics.dsHeuristics -eq "") -or ($ValuedsHeuristics.dsHeuristics.Length -lt 7)) {
                                    "Disabled"
                                } elseif (($ValuedsHeuristics.dsHeuristics.Length -ge 7) -and ($ValuedsHeuristics.dsHeuristics[6] -eq "2")) {
                                    "Enabled"
                                }
                            }
                        }
                        $OutObj += [pscustomobject]$inobj
                    }
                    catch {
                        Write-PscriboMessage -IsWarning $_.Exception.Message
                    }
                }

                if ($HealthCheck.Domain.Security) {
                    $OutObj | Where-Object { $_.'Anonymous Access (dsHeuristics)' -eq 'Enabled'} | Set-Style -Style Warning -Property 'Anonymous Access (dsHeuristics)'
                }

                $TableParams = @{
                    Name = "Forest Summary - $($ForestInfo)"
                    List = $true
                    ColumnWidths = 50, 50
                }
                if ($Report.ShowTableCaptions) {
                    $TableParams['Caption'] = "- $($TableParams.Name)"
                }
                $OutObj | Table @TableParams
                if ($HealthCheck.Domain.Security -and ($OutObj | Where-Object { $_.'Anonymous Access (dsHeuristics)' -eq 'Enabled'}) ) {
                    Paragraph "Health Check:" -Italic -Bold -Underline
                    BlankLine
                    Paragraph "Best Practice: Anonymous Access to Active Directory forest data above the rootDSE level must be disabled." -Italic -Bold
                    Paragraph "Reference:" -Italic -Bold -Underline
                    Paragraph "https://www.stigviewer.com/stig/active_directory_forest/2016-02-19/finding/V-8555" -Bold
                }
            }
        }
        catch {
            Write-PscriboMessage -IsWarning $_.Exception.Message
        }
        try {
            Section -Style Heading3 'Certificate Authority' {
                Write-PscriboMessage "Discovering certificate authority information on forest $ForestInfo."
                $ConfigNCDN = $Data.PartitionsContainer.Split(',') | Select-Object -Skip 1
                $rootCA = Get-ADObjectSearch -DN "CN=Certification Authorities,CN=Public Key Services,CN=Services,$($ConfigNCDN -join ',')" -Filter { objectClass -eq "certificationAuthority" } -Properties "Name" -SelectPrty 'DistinguishedName','Name' -Session $TempPssSession
                if ($rootCA) {
                    Section -ExcludeFromTOC -Style NOTOCHeading4 'Certification Authority Root(s)' {
                        $OutObj = @()
                        Write-PscriboMessage "Discovered Certificate Authority Information on forest $ForestInfo."
                        foreach ($Item in $rootCA) {
                            try {
                                Write-PscriboMessage "Collecting Certificate Authority Information '$($Item.Name)'"
                                $inObj = [ordered] @{
                                    'Name' = $Item.Name
                                    'Distinguished Name' = $Item.DistinguishedName
                                }
                                $OutObj += [pscustomobject]$inobj
                            }
                            catch {
                                Write-PscriboMessage -IsWarning $_.Exception.Message
                            }
                        }

                        if ($HealthCheck.Forest.BestPractice) {
                            ($OutObj | Measure-Object).Count -gt 1 | Set-Style -Style Warning
                        }

                        $TableParams = @{
                            Name = "Certificate Authority Root(s) - $($ForestInfo)"
                            List = $false
                            ColumnWidths = 50, 50
                        }
                        if ($Report.ShowTableCaptions) {
                            $TableParams['Caption'] = "- $($TableParams.Name)"
                        }
                        $OutObj | Sort-Object -Property 'Name' | Table @TableParams
                        if ($HealthCheck.Forest.BestPractice -and (($OutObj | Measure-Object).Count -gt 1 ) ) {
                            Paragraph "Health Check:" -Italic -Bold -Underline
                            BlankLine
                            Paragraph "Best Practice: In most PKI implementations, it is not typical to have multiple Root CAs. Its recommended a detailed review of the current PKI infrastructure and Root CA requirements." -Italic -Bold
                        }
                    }
                }
                Write-PscriboMessage "Discovering certificate authority issuers on forest $ForestInfo."
                $ConfigNCDN = $Data.PartitionsContainer.Split(',') | Select-Object -Skip 1
                $subordinateCA = Get-ADObjectSearch -DN "CN=Enrollment Services,CN=Public Key Services,CN=Services,$($ConfigNCDN -join ',')" -Filter { objectClass -eq "pKIEnrollmentService" } -Properties "*" -SelectPrty 'dNSHostName','Name' -Session $TempPssSession
                if ($subordinateCA) {
                    Section -ExcludeFromTOC -Style NOTOCHeading4 'Certification Authority Issuer(s)' {
                        $OutObj = @()
                        Write-PscriboMessage "Discovered Certificate Authority issuers on forest $ForestInfo."
                        foreach ($Item in $subordinateCA) {
                            try {
                                Write-PscriboMessage "Collecting Certificate Authority issuers '$($Item.Name)'"
                                $inObj = [ordered] @{
                                    'Name' = $Item.Name
                                    'DNS Name' = $Item.dNSHostName
                                }
                                $OutObj += [pscustomobject]$inobj
                            }
                            catch {
                                Write-PscriboMessage -IsWarning $_.Exception.Message
                            }
                        }

                        $TableParams = @{
                            Name = "Certificate Authority Issuer(s) - $($ForestInfo)"
                            List = $false
                            ColumnWidths = 50, 50
                        }
                        if ($Report.ShowTableCaptions) {
                            $TableParams['Caption'] = "- $($TableParams.Name)"
                        }
                        $OutObj | Sort-Object -Property 'Name' | Table @TableParams
                    }
                }
            }
        }
        catch {
            Write-PscriboMessage -IsWarning $_.Exception.Message
        }
        try {
            Section -Style Heading3 'Optional Features' {
                Write-PscriboMessage "Discovering Optional Features enabled on forest $ForestInfo."
                $Data = Invoke-Command -Session $TempPssSession {Get-ADOptionalFeature -Filter *}
                $OutObj = @()
                if ($Data) {
                    Write-PscriboMessage "Discovered Optional Features enabled on forest $ForestInfo."
                    foreach ($Item in $Data) {
                        try {
                            Write-PscriboMessage "Collecting Optional Features '$($Item.Name)'"
                            $inObj = [ordered] @{
                                'Name' = $Item.Name
                                'Required Forest Mode' = $Item.RequiredForestMode
                                'Enabled' = Switch (($Item.EnabledScopes).count) {
                                    0 {'No'}
                                    default {'Yes'}
                                }
                            }
                            $OutObj += [pscustomobject]$inobj
                        }
                        catch {
                            Write-PscriboMessage -IsWarning $_.Exception.Message
                        }
                    }

                    if ($HealthCheck.Forest.BestPractice) {
                        $OutObj | Where-Object { $_.'Name' -eq 'Recycle Bin Feature' -and $_.'Enabled' -eq 'No'} | Set-Style -Style Warning -Property 'Enabled'
                    }

                    $TableParams = @{
                        Name = "Optional Features - $($ForestInfo)"
                        List = $false
                        ColumnWidths = 40, 30, 30
                    }
                    if ($Report.ShowTableCaptions) {
                        $TableParams['Caption'] = "- $($TableParams.Name)"
                    }
                    $OutObj | Sort-Object -Property 'Name' | Table @TableParams
                    if ($HealthCheck.Forest.BestPractice -and ($OutObj | Where-Object { $_.'Name' -eq 'Recycle Bin Feature' -and $_.'Enabled' -eq 'No'}) ) {
                        Paragraph "Health Check:" -Italic -Bold -Underline
                        BlankLine
                        Paragraph "Best Practice: Accidental deletion of Active Directory objects is common for Active Directory Domain Services (AD DS) users. With the Recycle Bin Feature, one could recover accidentally deleted objects in Active Directory. Enable the Recycle Bin feature for the forest." -Italic -Bold
                        BlankLine
                        Paragraph "Reference:" -Italic -Bold -Underline
                        BlankLine
                        Paragraph "https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/the-ad-recycle-bin-understanding-implementing-best-practices-and/ba-p/396944" -Bold
                    }
                }
            }
        }
        catch {
            Write-PscriboMessage -IsWarning $_.Exception.Message
        }
    }

    end {}

}