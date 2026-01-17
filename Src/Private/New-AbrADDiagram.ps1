function New-AbrADDiagram {
    <#
    .SYNOPSIS
        Diagram the configuration of Microsoft AD infrastructure to a supported formats using PSGraph and Graphviz.
    .DESCRIPTION
        Diagram the configuration of Microsoft AD  infrastructure to a supported formats using PSGraph and Graphviz.
    .PARAMETER DiagramType
        Specifies the type of active directory diagram that will be generated.
        The supported output diagrams are:
                    'Forest'
                    'Sites'
                    'SitesInventory'
                    'Trusts'
    .PARAMETER Target
        Specifies the IP/FQDN of the system to connect.
        Multiple targets may be specified, separated by a comma.
    .PARAMETER Credential
        Specifies the stored credential of the target system.
    .PARAMETER Username
        Specifies the username for the target system.
    .PARAMETER Password
        Specifies the password for the target system.
    .PARAMETER Format
        Specifies the output format of the diagram.
        The supported output formats are JPG, PDF, PNG, DOT & SVG.
        Multiple output formats may be specified, separated by a comma.
    .PARAMETER Direction
        Set the direction in which resource are plotted on the visualization
        The supported directions are:
            'top-to-bottom', 'left-to-right'
        By default, direction will be set to top-to-bottom.
    .PARAMETER NodeSeparation
        Controls Node separation ratio in visualization
        By default, NodeSeparation will be set to .60.
    .PARAMETER SectionSeparation
        Controls Section (Subgraph) separation ratio in visualization
        By default, NodeSeparation will be set to .75.
    .PARAMETER EdgeType
        Controls how edges lines appear in visualization
        The supported edge type are:
            'polyline', 'curved', 'ortho', 'line', 'spline'
        By default, EdgeType will be set to spline.
        References: https://graphviz.org/docs/attrs/splines/
    .PARAMETER OutputFolderPath
        Specifies the folder path to save the diagram.
    .PARAMETER Filename
        Specifies a filename for the diagram.
    .PARAMETER EnableEdgeDebug
        Control to enable edge debugging ( Dummy Edge and Node lines ).
    .PARAMETER EnableSubGraphDebug
        Control to enable subgraph debugging ( Subgraph Lines ).
    .PARAMETER EnableErrorDebug
        Control to enable error debugging.
    .PARAMETER AuthorName
        Allow to set footer signature Author Name.
    .PARAMETER CompanyName
        Allow to set footer signature Company Name.
    .PARAMETER Logo
        Allow to change the Microsoft logo to a custom one.
        Image should be 400px x 100px or less in size.
    .PARAMETER SignatureLogo
        Allow to change the Microsoft signature logo to a custom one.
        Image should be 120px x 130px or less in size.
    .PARAMETER Signature
        Allow the creation of footer signature.
        AuthorName and CompanyName must be set to use this property.
    .PARAMETER WatermarkText
        Allow to add a watermark to the output image (Not supported in svg format).
    .PARAMETER WatermarkColor
        Allow to specified the color used for the watermark text. Default: #565656.
    .NOTES
        Version:        0.9.9
        Author(s):      Jonathan Colon
        Twitter:        @jcolonfzenpr
        Github:         rebelinux
        Credits:        Kevin Marquette (@KevinMarquette) -  PSGraph module
        Credits:        Prateek Singh (@PrateekKumarSingh) - AzViz module
    .LINK
        https://github.com/rebelinux/Diagrammer.Microsoft.AD
        https://github.com/KevinMarquette/PSGraph
    #>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '', Scope = 'Function')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingUserNameAndPassWordParams', '', Scope = 'Function')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '', Scope = 'Function')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Scope = 'Function')]

    [CmdletBinding(
        PositionalBinding = $false,
        DefaultParameterSetName = 'Credential'
    )]

    param (

        [Parameter(
            Position = 0,
            Mandatory = $true,
            HelpMessage = 'Please provide the IP/FQDN of the system'
        )]
        [ValidateNotNullOrEmpty()]
        [Alias('Server', 'IP')]
        [String[]] $Target,

        [Parameter(
            Position = 1,
            Mandatory = $true,
            HelpMessage = 'Please provide credentials to connect to the system',
            ParameterSetName = 'Credential'
        )]
        [ValidateNotNullOrEmpty()]
        [PSCredential] $Credential,

        [Parameter(
            Position = 2,
            Mandatory = $true,
            HelpMessage = 'Please provide the username to connect to the target system',
            ParameterSetName = 'UsernameAndPassword'
        )]
        [ValidateNotNullOrEmpty()]
        [String] $Username,

        [Parameter(
            Position = 3,
            Mandatory = $true,
            HelpMessage = 'Please provide the password to connect to the target system',
            ParameterSetName = 'UsernameAndPassword'
        )]
        [ValidateNotNullOrEmpty()]
        [String] $Password,

        [Parameter(
            Position = 4,
            Mandatory = $true,
            HelpMessage = 'Please provide pssession to use for the connection',
            ParameterSetName = 'PSSession'
        )]
        [ValidateNotNullOrEmpty()]
        $PSSessionObject,

        [Parameter(
            Position = 5,
            Mandatory = $false,
            HelpMessage = 'Please provide the diagram output format'
        )]
        [ValidateNotNullOrEmpty()]
        [ValidateSet('pdf', 'svg', 'png', 'dot', 'base64', 'jpg')]
        [Array] $Format = 'pdf',

        [Parameter(
            Mandatory = $false,
            HelpMessage = 'Direction in which resource are plotted on the visualization'
        )]
        [ValidateSet('left-to-right', 'top-to-bottom')]
        [string] $Direction = 'top-to-bottom',

        [Parameter(
            Mandatory = $false,
            HelpMessage = 'Please provide the path to the diagram output file'
        )]
        [ValidateScript({
                if (-not ($_ | Test-Path) ) {
                    throw 'Folder does not exist'
                }
                return $true
            })]
        [System.IO.FileInfo] $OutputFolderPath = [System.IO.Path]::GetTempPath(),

        [Parameter(
            Mandatory = $false,
            HelpMessage = 'Please provide the path to the custom logo used for Signature'
        )]
        [ValidateScript( {
                if (Test-Path -Path $_) {
                    $true
                } else {
                    throw "File $_ not found!"
                }
            })]
        [string] $SignatureLogo,

        [Parameter(
            Mandatory = $false,
            HelpMessage = 'Please provide the path to the custom logo'
        )]
        [ValidateScript( {
                if (Test-Path -Path $_) {
                    $true
                } else {
                    throw "File $_ not found!"
                }
            })]
        [string] $Logo,

        [Parameter(
            Mandatory = $false,
            HelpMessage = 'Specify the diagram output file name path'
        )]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({
                if ($Format.count -lt 2) {
                    $true
                } else {
                    throw 'Format value must be unique if Filename is especified.'
                }
                if (-not $_.EndsWith($Format)) {
                    throw "The file specified in the path argument must be of type $Format"
                }
                return $true
            })]
        [String] $Filename,

        [Parameter(
            Mandatory = $false,
            HelpMessage = 'Controls how edges lines appear in visualization'
        )]
        [ValidateSet('polyline', 'curved', 'ortho', 'line', 'spline')]
        [string] $EdgeType = 'spline',

        [Parameter(
            Mandatory = $false,
            HelpMessage = 'Controls Node separation ratio in visualization'
        )]
        [ValidateSet(0, 1, 2, 3)]
        [string] $NodeSeparation = .60,

        [Parameter(
            Mandatory = $false,
            HelpMessage = 'Controls Section (Subgraph) separation ratio in visualization'
        )]
        [ValidateSet(0, 1, 2, 3)]
        [string] $SectionSeparation = .75,

        [Parameter(
            Mandatory = $true,
            HelpMessage = 'Controls type of Active Directory generated diagram'
        )]
        [ValidateSet('Forest', 'Sites', 'SitesInventory', 'Trusts', 'CertificateAuthority')]
        [string] $DiagramType,

        [Parameter(
            Mandatory = $false,
            HelpMessage = 'Allow to rotate the diagram output image. valid rotation degree (0, 90)'
        )]
        [ValidateSet(0, 90)]
        [int] $Rotate = 0,

        [Parameter(
            Mandatory = $false,
            HelpMessage = 'Allow to enable edge debugging ( Dummy Edge and Node lines)'
        )]
        [Switch] $EnableEdgeDebug = $false,

        [Parameter(
            Mandatory = $false,
            HelpMessage = 'Allow to enable subgraph debugging ( Subgraph Lines )'
        )]
        [Switch] $EnableSubGraphDebug = $false,
        [Parameter(
            Mandatory = $false,
            HelpMessage = 'Allow to enable error debugging'
        )]
        [Switch] $EnableErrorDebug = $false,
        [Parameter(
            Mandatory = $false,
            HelpMessage = 'Allow to enable error debugging'
        )]
        [ValidateSet('Negotiate', 'Kerberos')]
        [String] $PSDefaultAuthentication = 'Negotiate',

        [Parameter(
            Mandatory = $false,
            HelpMessage = 'Controls verbose of Active Directory generated diagram'
        )]
        [ValidateSet(1, 2)]
        [int] $DiagramVerbosity = 1,

        [Parameter(
            Mandatory = $false,
            HelpMessage = 'Allow to set footer signature Author Name'
        )]
        [string] $AuthorName,

        [Parameter(
            Mandatory = $false,
            HelpMessage = 'Allow to set footer signature Company Name'
        )]
        [string] $CompanyName,

        [Parameter(
            Mandatory = $false,
            HelpMessage = 'Allow the creation of footer signature'
        )]
        [Switch] $Signature = $false,

        [Parameter(
            Mandatory = $false,
            HelpMessage = 'Allow to add a watermark to the output image (Not supported in svg format)'
        )]
        [string] $WaterMarkText,

        [Parameter(
            Mandatory = $false,
            HelpMessage = 'Allow to specified the color used for the watermark text'
        )]
        [string] $WaterMarkColor = '#565656',

        [Parameter(
            Mandatory = $false,
            HelpMessage = 'Allow the specified the text language'
        )]
        [ValidateSet('en-US', 'es-ES')]
        [string] $UICulture,
        [Parameter(
            Mandatory = $false,
            HelpMessage = 'Use it to set the diagram theme. (Black/White/Neon)'
        )]
        [ValidateSet('Black', 'White', 'Neon')]
        [string] $DiagramTheme = 'White'
    )


    begin {

        # Setup all paths required for script to run
        $script:RootPath = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
        $script:IconPath = Join-Path $RootPath 'icons'


        $MainGraphLabel = switch ($DiagramType) {
            'Forest' { $reportTranslate.NewADDiagram.forestgraphlabel }
            'Domain' { $reportTranslate.NewADDiagram.domaingraphlabel }
            'Sites' { $reportTranslate.NewADDiagram.sitesgraphlabel }
            'SitesInventory' { $reportTranslate.NewADDiagram.sitesinventorygraphlabel }
            'Trusts' { $reportTranslate.NewADDiagram.trustsDiagramLabel }
            'CertificateAuthority' { $reportTranslate.NewADDiagram.caDiagramLabel }
        }

        if ($Format -ne 'Base64') {
            Write-ColorOutput -Color 'Blue' -String ($reportTranslate.NewADDiagram.genMain -f $MainGraphLabel)
            Write-ColorOutput -Color 'White' -String $reportTranslate.NewADDiagram.InfoProject
            Write-ColorOutput -Color 'White' -String $reportTranslate.NewADDiagram.InfoDocumentation
            Write-ColorOutput -Color 'White' -String $reportTranslate.NewADDiagram.InfoIssues
            Write-ColorOutput -Color 'White' -String $reportTranslate.NewADDiagram.InfoCommunity


            # Check the current Diagrammer.Microsoft.AD module
            $ModuleArray = @('Diagrammer.Microsoft.AD', 'Diagrammer.Core')

            foreach ($Module in $ModuleArray) {
                try {
                    $InstalledVersion = Get-Module -ListAvailable -Name $Module -ErrorAction SilentlyContinue | Sort-Object -Property Version -Descending | Select-Object -First 1 -ExpandProperty Version

                    if ($InstalledVersion) {
                        Write-ColorOutput -Color 'White' -String ($reportTranslate.NewADDiagram.InfoVersion -f $($Module), $($InstalledVersion.ToString()))
                        $LatestVersion = Find-Module -Name $Module -Repository PSGallery -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Version
                        if ([version]$InstalledVersion -lt [version]$LatestVersion) {
                            Write-ColorOutput -Color 'Yellow' -String ($reportTranslate.NewADDiagram.WarningUpdate -f $($Module), $($LatestVersion.ToString()))
                            Write-ColorOutput -Color 'Yellow' -String ($reportTranslate.NewADDiagram.WarningUpdateCommand -f $($Module))
                        }
                    }
                } catch {
                    Write-Warning $_.Exception.Message
                }
            }
        }

        $Verbose = if ($PSBoundParameters.ContainsKey('Verbose')) {
            $PSCmdlet.MyInvocation.BoundParameters['Verbose'].IsPresent
        } else {
            $false
        }

        # If Username and Password parameters used, convert specified Password to secure string and store in $Credential
        #@tpcarman
        if (($Username -and $Password)) {
            $SecurePassword = ConvertTo-SecureString $Password -AsPlainText -Force
            $Credential = New-Object System.Management.Automation.PSCredential ($Username, $SecurePassword)
        }

        if (($Format -ne 'base64') -and !(Test-Path $OutputFolderPath)) {
            Write-Error ($reportTranslate.NewADDiagram.outputfolderpatherror -f $OutputFolderPath)
            break
        }

        $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())

        if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {

            throw $reportTranslate.NewADDiagram.runasadmin
        }

        if ($Signature -and (([string]::IsNullOrEmpty($AuthorName)) -or ([string]::IsNullOrEmpty($CompanyName)))) {
            throw $reportTranslate.NewADDiagram.signaturerequirements
        }

        #Validate Required Modules and Features
        $OSType = (Get-ComputerInfo).OsProductType
        if ($OSType -eq 'WorkStation') {
            Get-RequiredFeature -Name 'Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0' -OSType $OSType
        }
        if ($OSType -eq 'Server' -or $OSType -eq 'DomainController') {
            Get-RequiredFeature -Name RSAT-AD-PowerShell -OSType $OSType
        }

        $script:IconDebug = $false

        if ($EnableEdgeDebug) {
            $script:EdgeDebug = @{style = 'filled'; color = 'red' }
            $script:IconDebug = $true
        } else { $script:EdgeDebug = @{style = 'invis'; color = 'red' } }

        if ($EnableSubGraphDebug) {
            $SubGraphDebug = @{style = 'dashed'; color = 'red' }
            $script:NodeDebug = @{color = 'black'; style = 'red' }
            $script:IconDebug = $true
        } else {
            $SubGraphDebug = @{style = 'invis'; color = 'gray' }
            $script:NodeDebug = @{color = 'transparent'; style = 'transparent' }
        }

        # Used to set diagram theme
        if ($DiagramTheme -eq 'Black') {
            $MainGraphBGColor = 'Black'
            $Edgecolor = 'White'
            $Fontcolor = 'White'
            $NodeFontcolor = 'White'
            $EdgeArrowSize = 1
            $EdgeLineWidth = 1
        } elseif ($DiagramTheme -eq 'Neon') {
            $MainGraphBGColor = 'grey14'
            $Edgecolor = 'gold2'
            $Fontcolor = 'gold2'
            $NodeFontcolor = 'gold2'
            $EdgeArrowSize = 1
            $EdgeLineWidth = 1
        } elseif ($DiagramTheme -eq 'White') {
            $MainGraphBGColor = 'White'
            $Edgecolor = '#71797E'
            $Fontcolor = '#565656'
            $NodeFontcolor = 'Black'
            $EdgeArrowSize = 1
            $EdgeLineWidth = 1
        }

        $Dir = switch ($Direction) {
            'top-to-bottom' { 'TB' }
            'left-to-right' { 'LR' }
        }

        # Validate Custom logo
        if ($Logo) {
            $CustomLogo = Test-Logo -LogoPath (Get-ChildItem -Path $Logo).FullName -IconPath $IconPath -ImagesObj $Images
        } else {
            $CustomLogo = 'Microsoft_Logo'
        }
        # Validate Custom Signature Logo
        if ($SignatureLogo) {
            $CustomSignatureLogo = Test-Logo -LogoPath (Get-ChildItem -Path $SignatureLogo).FullName -IconPath $IconPath -ImagesObj $Images
        }

        # Change variable Scope

        # Main Diagram Attributes
        $MainGraphAttributes = @{
            pad = 1.0
            rankdir = $Dir
            overlap = 'true'
            splines = $EdgeType
            penwidth = 1.5
            fontname = 'Segoe UI'
            fontcolor = $Fontcolor
            fontsize = 32
            style = 'dashed'
            labelloc = 't'
            imagepath = $IconPath
            nodesep = $NodeSeparation
            ranksep = $SectionSeparation
            ratio = 'auto'
            rotate = $Rotate
            bgcolor = $MainGraphBGColor
        }
        if ($DiagramType -eq 'Sites') {
            $MainGraphAttributes.Add('concentrate', 'true')
        }
    }

    process {
        foreach ($System in $Target) {

            if (Select-String -InputObject $System -Pattern '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
                throw "Please use the Fully Qualified Domain Name (FQDN) instead of an IP address when connecting to the Domain Controller: $System"
            }

            try {
                # Connection setup
                if ($PSSessionObject) {
                    $TempPssSession = $PSSessionObject
                    $script:ADSystem = Invoke-CommandWithTimeout -Session $TempPssSession -ScriptBlock { Get-ADForest -ErrorAction Stop }
                } else {
                    Write-Verbose ($reportTranslate.NewADDiagram.psSessionSetup -f $($System))
                    $script:TempPssSession = New-PSSession $System -Credential $Credential -Authentication $PSDefaultAuthentication -ErrorAction Stop
                    $script:ADSystem = Invoke-CommandWithTimeout -Session $TempPssSession -ScriptBlock { Get-ADForest -ErrorAction Stop }
                }
            } catch { throw ($reportTranslate.NewADDiagram.unableToConnect -f $System) }

            $Graph = Graph -Name MicrosoftAD -Attributes $MainGraphAttributes {
                # Node default theme
                Node @{
                    shape = 'rectangle'
                    labelloc = 'c'
                    style = 'filled'
                    fillColor = 'transparent'
                    imagescale = $true
                    color = '#003099'
                    penwidth = 3
                    fontname = 'Segoe UI'
                    fontsize = $NodeFontSize
                    fontcolor = $NodeFontcolor
                }
                # Edge default theme
                Edge @{
                    style = 'dashed'
                    dir = 'both'
                    arrowtail = 'dot'
                    color = $Edgecolor
                    penwidth = $EdgeLineWidth
                    arrowsize = $EdgeArrowSize
                    fontcolor = $Edgecolor
                }

                if ($Signature) {
                    Write-Verbose 'Generating diagram signature'
                    if ($CustomSignatureLogo) {
                        $Signature = (Add-DiaHtmlSignatureTable -ImagesObj $Images -Rows "Author: $($AuthorName)", "Company: $($CompanyName)" -TableBorder 2 -CellBorder 0 -Align 'left' -Logo $CustomSignatureLogo -IconDebug $IconDebug)
                    } else {
                        $Signature = (Add-DiaHtmlSignatureTable -ImagesObj $Images -Rows "Author: $($AuthorName)", "Company: $($CompanyName)" -TableBorder 2 -CellBorder 0 -Align 'left' -Logo 'AD_LOGO_Footer' -IconDebug $IconDebug)
                    }
                } else {
                    Write-Verbose $reportTranslate.NewADDiagram.diagramSignature
                    $Signature = ' '
                }

                # Used for the Legend or SignatureLogo
                SubGraph OUTERDRAWBOARD1 -Attributes @{Label = $Signature; fontsize = 24; penwidth = 1.5; labelloc = 'b'; labeljust = 'r'; style = $SubGraphDebug.style; color = $SubGraphDebug.color } {

                    Write-Verbose $reportTranslate.NewADDiagram.genDiagramSignature

                    # Main Graph SubGraph
                    SubGraph MainGraph -Attributes @{Label = (Add-DiaHtmlLabel -ImagesObj $Images -Label $MainGraphLabel -IconType $CustomLogo -IconDebug $IconDebug -IconWidth 250 -IconHeight 80 -Fontsize 24 -FontName 'Segoe UI Bold' -FontColor $Fontcolor ); fontsize = 22; penwidth = 0; labelloc = 't'; labeljust = 'c' } {
                        Write-Verbose $reportTranslate.NewADDiagram.genDiagramMain

                        $script:ForestRoot = $ADSystem.Name.ToString().ToUpper()

                        # Call Forest Diagram
                        if ($DiagramType -eq 'Forest') {
                            if ($ForestInfo = Get-AbrDiagForest | Select-String -Pattern '"([A-Z])\w+"\s\[label="";style="invis";shape="point";]' -NotMatch) {
                                $ForestInfo
                            } else { Write-Warning $reportTranslate.NewADDiagram.emptyForest }
                        } elseif ($DiagramType -eq 'CertificateAuthority') {
                            $CAInfo = Get-AbrDiagCertificateAuthority
                            if ($CAInfo = Get-AbrDiagCertificateAuthority | Select-String -Pattern '"([A-Z])\w+"\s\[label="";style="invis";shape="point";]' -NotMatch) {
                                $CAInfo
                            } else { Write-Warning $reportTranslate.NewADDiagram.emptyForest }
                        } elseif ($DiagramType -eq 'Sites') {
                            if ($SitesInfo = Get-AbrDiagSite | Select-String -Pattern '"([A-Z])\w+"\s\[label="";style="invis";shape="point";]' -NotMatch) {
                                $SitesInfo
                            } else { Write-Warning $reportTranslate.NewADDiagram.emptySites }
                        } elseif ($DiagramType -eq 'SitesInventory') {
                            if ($SitesInfo = Get-AbrDiagSiteInventory | Select-String -Pattern '"([A-Z])\w+"\s\[label="";style="invis";shape="point";]' -NotMatch) {
                                $SitesInfo
                            } else { Write-Warning $reportTranslate.NewADDiagram.emptySites }
                        } elseif ($DiagramType -eq 'Trusts') {
                            if ($TrustsInfo = Get-AbrDiagTrust | Select-String -Pattern '"([A-Z])\w+"\s\[label="";style="invis";shape="point";]' -NotMatch) {
                                $TrustsInfo
                            } else { Write-Warning $reportTranslate.NewADDiagram.emptyTrusts }
                        }
                    }
                }
            }
        }
    } end {
        if (-not $PSSessionObject) {
            # Remove used PSSession
            Write-Verbose ($reportTranslate.NewADDiagram.psSession -f $($TempPssSession.Id))
            Remove-PSSession -Session $TempPssSession
        }

        #Export Diagram
        foreach ($OutputFormat in $Format) {

            $OutputDiagram = Export-Diagrammer -GraphObj ($Graph | Select-String -Pattern '"([A-Z])\w+"\s\[label="";style="invis";shape="point";]' -NotMatch) -ErrorDebug $EnableErrorDebug -Format $OutputFormat -Filename $Filename -OutputFolderPath $OutputFolderPath -WaterMarkText $WaterMarkText -WaterMarkColor $WaterMarkColor -IconPath $IconPath -Verbose:$Verbose -Rotate $Rotate

            if ($OutputDiagram) {
                if ($OutputFormat -ne 'Base64') {
                    # If not Base64 format return image path
                    Write-ColorOutput -Color 'White' -String ($reportTranslate.NewADDiagram.DiagramOutput -f $MainGraphLabel, $OutputDiagram.Name, $OutputDiagram.Directory)
                } else {
                    Write-Verbose $reportTranslate.NewADDiagram.Base64Output
                    # Return Base64 string
                    $OutputDiagram
                }
            }
        }
    }
}