function Get-AbrADDomainController {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Domain Controller information.
    .DESCRIPTION

    .NOTES
        Version:        0.1.0
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
            $Domain
    )

    begin {
        Write-PscriboMessage "Collecting AD Domain Controller information."
    }

    process {
        $OutObj = @()
        if ($Domain) {
            foreach ($Item in $Domain) {
                $DCs =  Get-ADDomain -Identity $Item | Select-Object -ExpandProperty ReplicaDirectoryServers
                foreach ($DC in $DCs) {
                    $DCs = Get-ADDomainController -Server $DC
                    $inObj = [ordered] @{
                        'DC Name' = $DCs.Name
                        'Domain Name' = $DCs.Domain
                        'Site' = $DCs.Site
                        'Global Catalog' = ConvertTo-TextYN $DCs.IsGlobalCatalog
                        'Read Only' = ConvertTo-TextYN $DCs.IsReadOnly
                        'IP Address' = $DCs.IPv4Address
                    }
                    $OutObj += [pscustomobject]$inobj
                }
            }

            $TableParams = @{
                Name = "AD Domain Controller Summary Information - $($Domain.ToString().ToUpper())"
                List = $false
                ColumnWidths = 25, 25, 15, 10, 10, 15
            }
            if ($Report.ShowTableCaptions) {
                $TableParams['Caption'] = "- $($TableParams.Name)"
            }
            $OutObj | Table @TableParams
        }
        Section -Style Heading5 'Active Directory Domain Controller Hardware Summary' {
            Paragraph "The following section provides a summary of the Domain Controller Hardware for $($Domain.ToString().ToUpper())."
            BlankLine
            $OutObj = @()
            if ($Domain) {
                foreach ($Item in $Domain) {
                    $DCs =  Get-ADDomain -Identity $Item | Select-Object -ExpandProperty ReplicaDirectoryServers
                    foreach ($DC in $DCs) {
                        $HW = Invoke-Command -ComputerName $DC -ScriptBlock { Get-ComputerInfo }
                        $inObj = [ordered] @{
                            'Name' = $DC
                            'WindowsProductName' = $HW.WindowsProductName
                            'Manufacturer' = $HW.CsManufacturer
                            'CsModel' = $HW.CsModel
                            'Bios Type' = $HW.BiosFirmwareType
                            'CPU Socket' = $HW.CsNumberOfProcessors
                            'CPU Cores' = $HW.CsNumberOfLogicalProcessors
                            'Total RAM' = ConvertTo-FileSizeString $HW.CsTotalPhysicalMemory
                        }
                        $OutObj += [pscustomobject]$inobj
                    }
                }

                $TableParams = @{
                    Name = "AD Domain Controller Hardware Information - $($Domain.ToString().ToUpper())"
                    List = $true
                    ColumnWidths = 40, 60
                }
                if ($Report.ShowTableCaptions) {
                    $TableParams['Caption'] = "- $($TableParams.Name)"
                }
                $OutObj | Table @TableParams
            }
        }
        Section -Style Heading5 'Active Directory Domain Controller NTDS Summary' {
            Paragraph "The following section provides a summary of the Domain Controller NTDS file size on $($Domain.ToString().ToUpper())."
            BlankLine
            $OutObj = @()
            if ($Domain) {
                foreach ($Item in $Domain) {
                    $DCs =  Get-ADDomain -Identity $Item | Select-Object -ExpandProperty ReplicaDirectoryServers
                    foreach ($DC in $DCs) {
                        $NTDS = Invoke-Command -ComputerName $DC -ScriptBlock {Get-ItemProperty -Path HKLM:\System\CurrentControlSet\Services\NTDS\Parameters | Select-Object -ExpandProperty 'DSA Database File'}
                        $size = Invoke-Command -ComputerName $DC -ScriptBlock {(Get-ItemProperty -Path $using:NTDS).Length}
                        $inObj = [ordered] @{
                            'Name' = $DC
                            'DSA Database File' = $NTDS
                            'Size' = ConvertTo-FileSizeString $size
                        }
                        $OutObj += [pscustomobject]$inobj
                    }
                }

                $TableParams = @{
                    Name = "Domain Controller NTDS Database File Usage Information - $($Domain.ToString().ToUpper())"
                    List = $false
                    ColumnWidths = 40, 40, 20
                }
                if ($Report.ShowTableCaptions) {
                    $TableParams['Caption'] = "- $($TableParams.Name)"
                }
                $OutObj | Table @TableParams
            }
        }
    }

    end {}

}