# Get public and private function definition files and dot source them
$Public = @(Get-ChildItem -Path $PSScriptRoot\Src\Public\*.ps1 -ErrorAction SilentlyContinue)
$Diagram = @(Get-ChildItem -Path $PSScriptRoot\Src\Private\Diagram\*.ps1 -ErrorAction SilentlyContinue)
$Report = @(Get-ChildItem -Path $PSScriptRoot\Src\Private\Report\*.ps1 -ErrorAction SilentlyContinue)
$Tools = @(Get-ChildItem -Path $PSScriptRoot\Src\Private\Tools\*.ps1 -ErrorAction SilentlyContinue)
$Gui = @(Get-ChildItem -Path $PSScriptRoot\Src\Private\Gui\*.ps1 -ErrorAction SilentlyContinue)

foreach ($Module in @($Public + $Report + $Diagram + $Tools + $Gui)) {
    try {
        . $Module.FullName
    } catch {
        Write-Error -Message "Failed to import function $($Module.FullName): $_"
    }
}

Export-ModuleMember -Function $Public.BaseName
Export-ModuleMember -Function $Report.BaseName
Export-ModuleMember -Function $Diagram.BaseName
Export-ModuleMember -Function $Tools.BaseName
Export-ModuleMember -Function $Gui.BaseName