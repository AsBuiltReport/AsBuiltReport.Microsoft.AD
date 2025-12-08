function Invoke-CommandWithTimeout {
    <#
    .SYNOPSIS
        Invokes a PowerShell command within a remote session with a timeout mechanism.

    .DESCRIPTION
        Executes a script block on a remote PowerShell session as a background job and waits for completion within a specified timeout period. If the job exceeds the timeout duration, it is terminated and an error is raised.

    .PARAMETER Session
        The PSSession object representing the remote PowerShell session where the script block will be executed.

    .PARAMETER ScriptBlock
        The script block containing the commands to be executed on the remote session.

    .PARAMETER TimeoutSeconds
        The maximum number of seconds to wait for the job to complete. Defaults to the value specified in $Options.JobsTimeOut. If the job does not complete within this period, it will be stopped and an error will be thrown.

    .OUTPUTS
        System.Management.Automation.PSRemotingJob or System.Object
        Returns the job results if completed successfully within the timeout period. Returns $null if the job times out.

    .EXAMPLE
        $session = New-PSSession -ComputerName "Server01"
        Invoke-CommandWithTimeout -Session $session -ScriptBlock { Get-Process } -TimeoutSeconds 30

    .NOTES
        This function is useful for preventing indefinite hangs when executing commands on remote systems. If a timeout occurs, the job will be stopped and an error message will be written to the error stream.
    #>
    param(
        [Parameter(
            Mandatory,
            HelpMessage = 'The PSSession to run the command in.'
        )]
        [System.Management.Automation.Runspaces.PSSession]$Session,

        [Parameter(
            Mandatory,
            HelpMessage = 'The script block to execute on the remote session.'
        )]
        [scriptblock]$ScriptBlock,

        [Parameter(
            Mandatory = $false,
            HelpMessage = 'The maximum number of seconds to wait for the job to complete.'
        )]
        [int]$TimeoutSeconds = $Options.JobsTimeOut
    )

    Write-PScriboMessage -Message "Invoking '$ScriptBlock' with timeout of $(if ($TimeoutSeconds) {$TimeoutSeconds / 60} else {'Unknown'} ) minutes."

    # Start the command as a job
    $job = Invoke-Command -Session $Session -ScriptBlock $ScriptBlock -AsJob

    # Wait for the job to complete or timeout
    $null = $job | Wait-Job -Timeout $TimeoutSeconds

    # Check if the job is still running (indicating a timeout)
    if ($job.State -eq 'Running') {
        # Stop the job if it has timed out
        $job | Stop-Job -ErrorAction SilentlyContinue
        Remove-Job -Job $job -ErrorAction SilentlyContinue

        Write-PScriboMessage -Message "Invoking '$ScriptBlock' command timed out after $(if ($TimeoutSeconds) {$TimeoutSeconds / 60} else {'Unknown'} ) minutes" -IsWarning

        # Return null to indicate timeout
        return $null
    }

    # Get the job results if completed successfully
    $results = Receive-Job -Job $job -ErrorAction SilentlyContinue
    # Remove the job after receiving results
    Remove-Job -Job $job -ErrorAction SilentlyContinue

    # Return the job results
    return $results
}
