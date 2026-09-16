
function Get-AbrDiagrammer {
    <#
    .SYNOPSIS
    Used by As Built Report to generate the Microsoft AD diagram.
    .DESCRIPTION
        Documents the configuration of Microsoft AD in Word/HTML/Text formats using PScribo.
    .NOTES
        Version:        1.0.4
        Author:         Jonathan Colon
        Twitter:        @jcolonfzenpr
        Github:         rebelinux
        Credits:        Iain Brighton (@iainbrighton) - PScribo module

    .LINK
        https://github.com/AsBuiltReport/AsBuiltReport.Microsoft.AD
    #>
    [CmdletBinding()]
    param (
        [Parameter(
            Mandatory = $true,
            Position = 0,
            HelpMessage = 'Please provide diagram type to generate'
        )]
        [ValidateNotNullOrEmpty()]
        [ValidateSet('Forest', 'CertificateAuthority', 'Sites', 'SitesInventory', 'Trusts', 'Replication', 'All')]
        [string]$DiagramType,
        [Parameter(
            Mandatory = $false,
            Position = 1,
            HelpMessage = 'Please provide diagram output format to generate'
        )]
        [ValidateNotNullOrEmpty()]
        [ValidateSet('png', 'pdf', 'base64', 'jpg', 'svg')]
        [string]$DiagramOutput,
        [Parameter(
            Position = 2,
            Mandatory = $false,
            HelpMessage = 'Please provide path to use for the output folder'
        )]
        [Switch]$ExportPath = $false,
        [Parameter(
            Position = 4,
            Mandatory = $false,
            HelpMessage = 'Please provide pssession to use for the connection'
        )]
        [ValidateNotNullOrEmpty()]
        $PSSessionObject,
        [Parameter(
            Position = 5,
            Mandatory = $false,
            HelpMessage = 'Please provide Domain controller to use'
        )]
        [string]$DomainController = $System,
        [Parameter(
            Position = 6,
            Mandatory = $false,
            HelpMessage = 'Please provide file name without extension to use for the diagram output'
        )]
        [string]$FileName
    )

    begin {
        Write-PScriboMessage -Message ($reportTranslate.GetAbrDiagrammer.GettingDiagram -f $DiagramType, $DomainController)
    }

    process {
        try {
            # Set default theme styles
            if (-not $Options.DiagramTheme) {
                $DiagramTheme = 'White'
            } else {
                $DiagramTheme = $Options.DiagramTheme
            }
            $DiagramTypeArray = [System.Collections.Generic.List[object]]::new()

            if (-not $Options.DiagramType) {
                $DiagramTypeArray.Add('All')
            } elseif ($Options.DiagramType) {
                $DiagramTypeArray = $Options.DiagramType
            } else {
                $DiagramType = 'Forest'
            }

            if (-not $Options.ExportDiagramsFormat) {
                $DiagramFormat = 'png'
            } elseif ($DiagramOutput) {
                $DiagramFormat = $DiagramOutput
            } else {
                $DiagramFormat = $Options.ExportDiagramsFormat
            }
            try {
                $DiagramLabel = switch ($DiagramType) {
                    'Forest' { $reportTranslate.NewADDiagram.forestgraphlabel }
                    'CertificateAuthority' { $reportTranslate.NewADDiagram.caDiagramLabel }
                    'Sites' { $reportTranslate.NewADDiagram.sitesgraphlabel }
                    'SitesInventory' { $reportTranslate.NewADDiagram.sitesinventorygraphlabel }
                    'Trusts' { $reportTranslate.NewADDiagram.trustsDiagramLabel }
                    'Replication' { $reportTranslate.NewADDiagram.replicationDiagramLabel }
                }
                $IconPath = Join-Path -Path $PSScriptRoot -ChildPath 'icons'

                $IconDebug = [bool]$Options.EnableDiagramDebug
                $SubGraphDebug = if ($IconDebug) {
                    @{ style = 'dashed'; color = 'red' }
                } else {
                    @{ style = 'invis'; color = $Edgecolor }
                }

                if ($PSSessionObject) {
                    $DiagramTempPssSession = $PSSessionObject
                } else {
                    $DiagramTempPssSession = New-PSSession $DomainController -Credential $Credential `
                        -Authentication $Options.PSDefaultAuthentication -ErrorAction Stop
                }
                $ADSystem = Invoke-CommandWithTimeout -Session $DiagramTempPssSession `
                    -ScriptBlock { Get-ADForest -ErrorAction Stop }
                $ForestRoot = $ADSystem.Name.ToString().ToUpper()
                if (-not $PSSessionObject) {
                    Remove-PSSession -Session $DiagramTempPssSession
                }
                $script:ForestRoot = $ForestRoot

                $DiagramParams = @{
                    'OutputFolderPath' = $OutputFolderPath
                    'MainDiagramLabel' = $DiagramLabel
                    'MainDiagramLabelFontsize' = 24
                    'MainDiagramLabelFontname' = 'Segoe UI Bold'
                    'IconPath' = $IconPath
                    'ImagesObj' = $Images
                    'LogoName' = 'Microsoft_Logo'
                    'SignatureLogoName' = 'AD_LOGO_Footer'
                    'WaterMarkText' = $Options.DiagramWaterMark
                    'WaterMarkFontOpacity' = 20
                    'Direction' = 'top-to-bottom'
                    'DisableMainDiagramLogo' = $Options.DisableDiagramMainLogo
                    'EdgeType' = 'spline'
                    'EdgeLineWidth' = 1
                }

                # Apply theme-specific colour overrides on top of the defaults.
                if ($DiagramTheme -eq 'Black') {
                    $DiagramParams.add('MainGraphBGColor', 'Black')
                    $DiagramParams.add('Edgecolor', 'White')
                    $DiagramParams.add('Fontcolor', 'White')
                    $DiagramParams.add('NodeFontcolor', 'White')
                    $DiagramParams.add('WaterMarkColor', 'White')
                    $DiagramParams.add('SignatureTableBorderColor', 'Black')
                    $DiagramParams.add('SignatureTableBackgroundColor', 'Black')
                    $DiagramParams.add('MainDiagramLabelFontcolor', 'White')
                    $DiagramParams.add('MainDiagramLabelTableBackgroundColor', 'Black')
                    $MainGraphBGColor = 'Black'
                    $Edgecolor = 'White'
                    $Fontcolor = 'White'
                    $NodeFontcolor = 'White'
                } elseif ($DiagramTheme -eq 'Neon') {
                    $DiagramParams.add('MainGraphBGColor', 'grey14')
                    $DiagramParams.add('Edgecolor', 'gold2')
                    $DiagramParams.add('Fontcolor', 'gold2')
                    $DiagramParams.add('NodeFontcolor', 'gold2')
                    $DiagramParams.add('WaterMarkColor', '#FFD700')
                    $DiagramParams.add('SignatureTableBorderColor', 'gold2')
                    $DiagramParams.add('SignatureTableBackgroundColor', 'grey14')
                    $DiagramParams.add('MainDiagramLabelFontcolor', 'gold2')
                    $DiagramParams.add('MainDiagramLabelTableBackgroundColor', 'grey14')
                    $MainGraphBGColor = 'grey14'
                    $Edgecolor = 'gold2'
                    $Fontcolor = 'gold2'
                    $NodeFontcolor = 'gold2'
                } else {
                    $DiagramParams.add('WaterMarkColor', '#333333')
                    $DiagramParams.add('SignatureTableBorderColor', '#71797E')
                    $DiagramParams.add('SignatureTableBackgroundColor', 'White')
                    $DiagramParams.add('MainDiagramLabelFontcolor', '#565656')
                    $DiagramParams.add('MainDiagramLabelTableBackgroundColor', 'White')
                    $DiagramParams.add('MainGraphBGColor', 'White')
                    $DiagramParams.add('Edgecolor', '#71797E')
                    $DiagramParams.add('Fontcolor', '#565656')
                    $DiagramParams.add('NodeFontcolor', 'Black')
                    $MainGraphBGColor = 'White'
                    $Edgecolor = '#71797E'
                    $Fontcolor = '#565656'
                    $NodeFontcolor = 'Black'
                }

                if ($SubGraphDebug.style -eq 'dashed') {
                    $DiagramParams.Add('DraftMode', $true)
                }

                if ($Options.EnableDiagramSignature) {
                    $DiagramParams.Add('Signature', $true)
                    $DiagramParams.Add('AuthorName', $Options.SignatureAuthorName)
                    $DiagramParams.Add('CompanyName', $Options.SignatureCompanyName)
                }

                $DiagramGraph = switch ($DiagramType) {
                    'Forest' { Get-AbrDiagForest }
                    'CertificateAuthority' { Get-AbrDiagCertificateAuthority }
                    'Sites' { Get-AbrDiagSite }
                    'SitesInventory' { Get-AbrDiagSiteInventory }
                    'Trusts' { Get-AbrDiagTrust }
                    'Replication' { Get-AbrDiagReplication }
                }
                if (-not $DiagramGraph) {
                    return
                }

                $DiagramParams.add('InputObject', $DiagramGraph)

                foreach ($Format in $DiagramFormat) {
                    if ($Format -eq 'base64') {
                        $DiagramParams['Format'] = $Format
                        $Graph = New-AbrDiagram @DiagramParams
                        if ($Graph) {
                            $Graph
                        }
                    } else {
                        if ($FileName) {
                            $DiagramFileName = $FileName
                        } else {
                            $DiagramFileName = "AsBuiltReport.Microsoft.AD-($($DiagramType))"
                        }
                        $DiagramParams['Format'] = $Format
                        $DiagramParams['Filename'] = $DiagramFileName
                        $Graph = New-AbrDiagram @DiagramParams
                        if ($Graph) {
                            if ($ExportPath) {
                                $FilePath = Join-Path -Path $OutputFolderPath -ChildPath "$($DiagramFileName).$($Format)"
                                if (Test-Path -Path $FilePath -PathType Leaf) {
                                    $FilePath
                                } else {
                                    Write-PScriboMessage -IsWarning -Message "$($reportTranslate.GetAbrDiagrammer.ErrorExportDiagram -f $DiagramType) $($_.Exception.Message)"
                                }
                            } else {
                                Write-Information "Saved '$($DiagramFileName).$($Format)' diagram to '$($OutputFolderPath)'." -InformationAction Continue
                            }
                        }
                    }
                }
            } catch {
                Write-PScriboMessage -IsWarning -Message "$($reportTranslate.GetAbrDiagrammer.ErrorExportDiagram -f $DiagramType) $($_.Exception.Message)"
            }
        } catch {
            Write-PScriboMessage -IsWarning -Message "$($reportTranslate.GetAbrDiagrammer.ErrorGetDiagram -f $DiagramType) $($_.Exception.Message)"
        }
    }
    end {}
}