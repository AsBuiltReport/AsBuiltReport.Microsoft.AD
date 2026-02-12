# Get assemblies files and import them
switch ($PSVersionTable.PSEdition) {
    'Core' {
        Import-Module ("$PSScriptRoot{0}Src{0}Tools{0}Bin{0}windows-x64{0}AsBuiltReportChart.dll" -f [System.IO.Path]::DirectorySeparatorChar)
    }
    'Desktop' {
        Import-Module ("$PSScriptRoot{0}Src{0}Tools{0}Bin{0}windows-x64{0}AsBuiltReportChart.dll" -f [System.IO.Path]::DirectorySeparatorChar)
    }
    default {
        Write-Verbose -Message 'Unable to find compatible assemblies.'
    }
}

# Get public and private function definition files and dot source them
$Public = @(Get-ChildItem -Path $PSScriptRoot\Src\Public\*.ps1 -ErrorAction SilentlyContinue)
$Private = @(Get-ChildItem -Path $PSScriptRoot\Src\Private\*.ps1 -ErrorAction SilentlyContinue)

foreach ($Module in @($Public + $Private)) {
    try {
        . $Module.FullName
    } catch {
        Write-Error -Message "Failed to import function $($Module.FullName): $_"
    }
}

Export-ModuleMember -Function $Public.BaseName
Export-ModuleMember -Function $Private.BaseName