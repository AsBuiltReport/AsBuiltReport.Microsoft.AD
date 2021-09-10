function Invoke-AsBuiltReport.Microsoft.AD {
    <#
    .SYNOPSIS
        PowerShell script to document the configuration of Microsoft AD in Word/HTML/Text formats
    .DESCRIPTION
        Documents the configuration of Microsoft AD in Word/HTML/Text formats using PScribo.
    .NOTES
        Version:        0.1.0
        Author:         Jonathan Colon
        Twitter:
        Github:
        Credits:        Iain Brighton (@iainbrighton) - PScribo module

    .LINK
        https://github.com/AsBuiltReport/AsBuiltReport.Microsoft.AD
    #>

	# Do not remove or add to these parameters
    param (
        [String[]] $Target,
        [PSCredential] $Credential
    )

    # Import Report Configuration
    $Report = $ReportConfig.Report
    $InfoLevel = $ReportConfig.InfoLevel
    $Options = $ReportConfig.Options

    # Used to set values to TitleCase where required
    $TextInfo = (Get-Culture).TextInfo

	# Update/rename the $System variable and build out your code within the ForEach loop. The ForEach loop enables AsBuiltReport to generate an as built configuration against multiple defined targets.

    #region foreach loop
    foreach ($System in $Target) {
        Try {
            Write-PScriboMessage "Connecting to AD System '$System'."
            $ADSystem = Get-ADForest -Server $System -Credential $Credential -ErrorAction Stop
        } Catch {
            Write-Verbose "Unable to connect to the $System"
            throw
        }
        $Data = Get-ADForest
        $ForestInfo =  $Data.RootDomain.toUpper()
        #region Forest Section
        Section -Style Heading1 "Report for Active Directory $($ForestInfo.toUpper())" {
            Paragraph "The following section provides a summary of the Active Directory Infrastructure configuration for $($ForestInfo)."
            BlankLine
            #region Forest Section
            Write-PScriboMessage "Forest InfoLevel set at $($InfoLevel.Forest)."
            if ($InfoLevel.Forest -gt 0) {
                Section -Style Heading2 'Active Directory Forest Information' {
                    Get-AbrADForest
                    Section -Style Heading3 'Active Directory FSMO Information' {
                        Paragraph "The following section provides a summary of the Active Directory FSMO on $($ForestInfo)."
                        BlankLine
                        Get-AbrADFSMO
                    }
                    Get-AbrADTrusts
                }
                Section -Style Heading3 'Active Directory Domain Information' {
                    Paragraph "The following section provides a summary of the AD Domain Information on $($ForestInfo)."
                    BlankLine
                    Get-AbrADDomain
                    Section -Style Heading4 'Active Directory Domain Site Information' {
                        Paragraph "The following section provides a summary of the Active Directory Sites on $($ForestInfo)."
                        BlankLine
                        Get-AbrADSite
                    }
                    Section -Style Heading4 'Active Directory Domain Controller Information' {
                        Paragraph "The following section provides a summary of the Active Directory DC on $($ForestInfo)."
                        BlankLine
                        Get-AbrADDomainController
                        if ($HealthCheck.DomainController.Diagnostic) {
                            Section -Style Heading4 'Active Directory DCDiag Information' {
                                Paragraph "The following section provides a summary of the Active Directory DC Diagnostic on $($ForestInfo)."
                                BlankLine
                                Get-AbrADDCDiag
                            }
                        }
                    }
                }
            }
        }#endregion Cluster Section
	}
	#endregion foreach loop
}