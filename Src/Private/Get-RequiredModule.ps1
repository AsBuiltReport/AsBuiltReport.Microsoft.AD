function Get-RequiredModule {
    <#
    .SYNOPSIS
    Function to check if the required version of Module is installed
    .DESCRIPTION
    Function to check if the required version of Module is installed
    .NOTES
        Version:        0.1.0
        Author:         Tim Carman
        Twitter:        @tpcarman
        Github:         tpcarman
    .PARAMETER Name
    The name of the required PowerShell module
    .PARAMETER Version
    The version of the required PowerShell module
    #>

    Param
    (
        [CmdletBinding()]
        [Parameter(Mandatory = $true, ValueFromPipeline = $false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Name,

        [Parameter(Mandatory = $true, ValueFromPipeline = $false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Version
    )

    process {
        # Check if the required version of Module is installed
        $RequiredModule = Get-Module -ListAvailable -Name $Name | Sort-Object -Property Version -Descending | Select-Object -First 1
        $ModuleVersion = "$($RequiredModule.Version.Major)" + "." + "$($RequiredModule.Version.Minor)" + "." + "$($RequiredModule.Version.Build)"
        if ($ModuleVersion -eq ".")  {
            throw "$Name $Version or higher is required to run the Microsoft Azure As Built Report. Run 'Install-Module -Name $Name -MinimumVersion $Version' to install the required modules. https://github.com/AsBuiltReport/AsBuiltReport.Microsoft.AD"
        }
        if ($ModuleVersion -lt $Version) {
            throw "$Name  $Version or higher is required to run the Microsoft Azure As Built Report. Run 'Update-Module -Name $Name -MinimumVersion $Version' to update the required modules. https://github.com/AsBuiltReport/AsBuiltReport.Microsoft.AD"
        }
    }
    end {}
}