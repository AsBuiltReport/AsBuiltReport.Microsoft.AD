
function Get-AbrDiagrammer {
    <#
    .SYNOPSIS
    Used by As Built Report to get the Diagrammer.AD diagram.
    .DESCRIPTION
        Documents the configuration of Microsoft AD in Word/HTML/Text formats using PScribo.
    .NOTES
        Version:        0.9.8
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
        [ValidateSet('Forest', 'CertificateAuthority', 'Sites', 'SitesInventory', 'Trusts', 'All')]
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
            HelpMessage = 'Plea'
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
        Write-PScriboMessage -Message "Getting $($DiagramType) diagram from $DomainController ."
    }

    process {
        try {
            # Set default theme styles
            if (-not $Options.DiagramTheme) {
                $DiagramTheme = 'White'
            } else {
                $DiagramTheme = $Options.DiagramTheme
            }
            $DiagramTypeArray = [System.Collections.ArrayList]::new()

            if (-not $Options.DiagramType) {
                $DiagramTypeArray.Add('All') | Out-Null
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
            $DiagramParams = @{
                'OutputFolderPath' = $OutputFolderPath
                'Credential' = $Credential
                'Target' = $DomainController
                'Direction' = 'top-to-bottom'
                'WaterMarkText' = $Options.DiagramWaterMark
                'WaterMarkColor' = '#565656'
                'DiagramTheme' = $DiagramTheme
            }

            if ($PSSessionObject) {
                $DiagramParams.Add('PSSessionObject', $PSSessionObject)
                $DiagramParams.remove('Credential')
            }

            if ($Options.EnableDiagramDebug) {
                $DiagramParams.Add('EnableEdgeDebug', $True)
                $DiagramParams.Add('EnableSubGraphDebug', $True)
            }

            if ($Options.EnableDiagramSignature) {
                $DiagramParams.Add('Signature', $True)
                $DiagramParams.Add('AuthorName', $Options.SignatureAuthorName)
                $DiagramParams.Add('CompanyName', $Options.SignatureCompanyName)
            }

            try {
                foreach ($Format in $DiagramFormat) {
                    if ($Format -eq "base64") {
                        $Graph = New-ADDiagram @DiagramParams -DiagramType $DiagramType -Format $Format
                        if ($Graph) {
                            $Graph
                        }
                    } else {
                        if ($FileName) {
                            $FileName = "$($FileName).$($Format)"
                            $Graph = New-ADDiagram @DiagramParams -DiagramType $DiagramType -Format $Format -Filename $FileName
                        } else {
                            $FileName = "AsBuiltReport.Microsoft.AD-($($DiagramType)).$($Format)"
                            $Graph = New-ADDiagram @DiagramParams -DiagramType $DiagramType -Format $Format -Filename $FileName
                        }
                        if ($Graph) {
                            if ($ExportPath) {
                                $FilePath = Join-Path -Path $OutputFolderPath -ChildPath $FileName
                                if (Test-Path -Path $FilePath) {
                                    $FilePath
                                } else {
                                    Write-PScriboMessage -IsWarning -Message "Unable to export the $DiagramType Diagram: $($_.Exception.Message)"
                                }
                            } else {
                                Write-Information "Saved '$FileName' diagram to '$($OutputFolderPath)'." -InformationAction Continue
                            }
                        }
                    }
                }
            } catch {
                Write-PScriboMessage -IsWarning -Message "Unable to export the $DiagramType Diagram: $($_.Exception.Message)"
            }
        } catch {
            Write-PScriboMessage -IsWarning -Message "Unable to get the $DiagramType Diagram: $($_.Exception.Message)"
        }
    }
    end {}
}