function Get-ComputerADDomain {
    <#
            .Synopsis
            Return the current domain
            .DESCRIPTION
            Use .net to get the current domain
            .EXAMPLE
            Get-ComputerADDomain
    #>
    [CmdletBinding()]
    [OutputType([System.DirectoryServices.ActiveDirectory.Domain])]
    param
    ()
    Write-PScriboMessage -Message 'Calling GetCurrentDomain()'
    ([DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain())
}