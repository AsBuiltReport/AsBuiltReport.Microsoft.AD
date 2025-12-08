function Find-AuditingIssue {
    <#
    .SYNOPSIS
    Used by As Built Report to find PKI Server auditing not enabled.
    .DESCRIPTION

    .NOTES
        Version:        2023.08
        Author:         Jake Hildreth

    .EXAMPLE

    .LINK
        https://github.com/TrimarcJake/Locksmith
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$ADCSObjects
    )
    $ADCSObjects | Where-Object {
        ($_.objectClass -eq 'pKIEnrollmentService') -and
        ($_.AuditFilter -ne '127')
    } | ForEach-Object {
        $Issue = New-Object -TypeName pscustomobject
        $Issue | Add-Member -MemberType NoteProperty -Name Forest -Value $_.CanonicalName.split('/')[0] -Force
        $Issue | Add-Member -MemberType NoteProperty -Name Name -Value $_.Name -Force
        $Issue | Add-Member -MemberType NoteProperty -Name DistinguishedName -Value $_.DistinguishedName -Force
        if ($_.AuditFilter -match 'CA Unavailable') {
            $Issue | Add-Member -MemberType NoteProperty -Name Issue -Value $_.AuditFilter -Force
            $Issue | Add-Member -MemberType NoteProperty -Name Fix -Value 'N/A' -Force
            $Issue | Add-Member -MemberType NoteProperty -Name Revert -Value 'N/A' -Force
            $Issue | Add-Member -MemberType NoteProperty -Name Technique -Value 'DETECT' -Force
        } else {
            $AuditValue = switch ($_.AuditFilter) {
                $Null { 'Never Configured' }
                default { $_.AuditFilter }
            }
            $Issue | Add-Member -MemberType NoteProperty -Name Issue -Value "Auditing is not fully enabled. Current value is $($AuditValue)" -Force
            $Issue | Add-Member -MemberType NoteProperty -Name Fix `
                -Value "certutil -config `'$($_.CAFullname)`' -setreg `'CA\AuditFilter`' 127; Invoke-Command -ComputerName `'$($_.dNSHostName)`' -ScriptBlock { Get-Service -Name `'certsvc`' | Restart-Service -Force }" -Force
            $Issue | Add-Member -MemberType NoteProperty -Name Revert `
                -Value "certutil -config $($_.CAFullname) -setreg CA\AuditFilter  $($_.AuditFilter); Invoke-Command -ComputerName `'$($_.dNSHostName)`' -ScriptBlock { Get-Service -Name `'certsvc`' | Restart-Service -Force }" -Force
            $Issue | Add-Member -MemberType NoteProperty -Name Technique -Value 'DETECT' -Force
        }
        $Severity = Get-Severity -Issue $Issue
        $Issue | Add-Member -MemberType NoteProperty -Name Severity -Value $Severity
        $Issue
    }
}