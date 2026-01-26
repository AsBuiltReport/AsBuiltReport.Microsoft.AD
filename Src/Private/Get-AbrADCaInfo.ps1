function Get-AbrADCAInfo {
    <#
    .SYNOPSIS
        Function to extract microsoft active directory certificate authority information.
    .DESCRIPTION
        Build a diagram of the configuration of Microsoft Active Directory to a supported formats using Psgraph.
    .NOTES
        Version:        0.9.9
        Author:         Jonathan Colon
        Twitter:        @jcolonfzenpr
        Github:         rebelinux
    .LINK
        https://github.com/rebelinux/Diagrammer.Microsoft.AD
    #>
    [CmdletBinding()]
    [OutputType([System.Object[]])]

    param()

    begin {
        Write-Verbose -Message ($reportTranslate.NewADDiagram.connectingForest -f $($ForestRoot))
    }

    process {
        try {
            $ForestObj = $ADSystem

            $ConfigNCDN = $ForestObj.PartitionsContainer.Split(',') | Select-Object -Skip 1
            $rootCAs = Get-ADObjectSearch -DN "CN=Certification Authorities,CN=Public Key Services,CN=Services,$($ConfigNCDN -join ',')" -Filter { objectClass -eq 'certificationAuthority' } -Properties '*' -SelectPrty 'DistinguishedName', 'Name', 'cACertificate' -Session $DiagramTempPssSession

            $subordinateCAs = Get-ADObjectSearch -DN "CN=Enrollment Services,CN=Public Key Services,CN=Services,$($ConfigNCDN -join ',')" -Filter { objectClass -eq 'pKIEnrollmentService' } -Properties '*' -SelectPrty 'dNSHostName', 'Name', 'cACertificate' -Session $DiagramTempPssSession

            $CAInfo = @()
            if ($rootCAs) {
                foreach ($rootCA in $rootCAs) {

                    $AditionalInfo = [ordered] @{
                        $reportTranslate.NewADDiagram.caNotBefore = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($rootCA.cACertificate[0]).NotBefore.ToShortDateString()
                        $reportTranslate.NewADDiagram.caNotAfter = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($rootCA.cACertificate[0]).NotAfter.ToShortDateString()
                        $reportTranslate.NewADDiagram.caType = $reportTranslate.NewADDiagram.caEnterpriseCA
                    }

                    $TempCAInfo = [PSCustomObject]@{
                        Name = Remove-SpecialChar -String "$($rootCA.Name)RootCA" -SpecialChars '\-. '
                        CAName = $rootCA.Name
                        Label = Add-DiaNodeIcon -Name $rootCA.Name -IconType 'AD_Domain' -Align 'Center' -ImagesObj $Images -IconDebug $IconDebug -Rows $AditionalInfo
                        AditionalInfo = $AditionalInfo
                        IsRoot = $true
                    }
                    $CAInfo += $TempCAInfo
                }
            } else {
                if ($subordinateCAs) {
                    foreach ($subordinateCA in $subordinateCAs) {

                        $AditionalInfo = [ordered] @{
                            $reportTranslate.NewADDiagram.caNotBefore = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($subordinateCA.cACertificate[0]).NotBefore.ToShortDateString()
                            $reportTranslate.NewADDiagram.caNotAfter = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($subordinateCA.cACertificate[0]).NotAfter.ToShortDateString()
                            $reportTranslate.NewADDiagram.caType = $reportTranslate.NewADDiagram.caStandaloneCA
                        }

                        $RootCAName = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($subordinateCA.cACertificate[0]).Issuer.Split(',').Split('=')[1]

                        $TempCAInfo = [PSCustomObject]@{
                            Name = Remove-SpecialChar -String $RootCAName -SpecialChars '\-. '
                            CAName = $RootCAName
                            Label = Add-DiaNodeIcon -Name $RootCAName -IconType 'AD_Domain' -Align 'Center' -ImagesObj $Images -IconDebug $IconDebug -Rows $AditionalInfo
                            AditionalInfo = $AditionalInfo
                            IsRoot = $true
                        }
                        $CAInfo += $TempCAInfo
                    }
                }
            }
            if ($subordinateCAs) {
                foreach ($subordinateCA in $subordinateCAs) {

                    $AditionalInfo = [ordered] @{
                        $reportTranslate.NewADDiagram.caDnsName = $subordinateCA.dNSHostName
                        $reportTranslate.NewADDiagram.caRootCaIssuer = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($subordinateCA.cACertificate[0]).Issuer.Split(',').Split('=')[1]
                        $reportTranslate.NewADDiagram.caNotBefore = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($subordinateCA.cACertificate[0]).NotBefore.ToShortDateString()
                        $reportTranslate.NewADDiagram.caNotAfter = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($subordinateCA.cACertificate[0]).NotAfter.ToShortDateString()
                        $reportTranslate.NewADDiagram.caType = $reportTranslate.NewADDiagram.caSubordinateCA
                    }

                    $TempCAInfo = [PSCustomObject]@{
                        Name = Remove-SpecialChar -String $subordinateCA.Name -SpecialChars '\-. '
                        CAName = $subordinateCA.Name
                        Label = Add-DiaNodeIcon -Name $subordinateCA.dNSHostName -IconType 'AD_Domain' -Align 'Center' -ImagesObj $Images -IconDebug $IconDebug -Rows $AditionalInfo
                        AditionalInfo = $AditionalInfo
                        IsRoot = $false
                    }
                    $CAInfo += $TempCAInfo
                }

            }

            return $CAInfo

        } catch {
            Write-Verbose $_.Exception.Message
        }
    }
    end {}
}