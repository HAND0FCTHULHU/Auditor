#Requires -Version 5.1
<#
.SYNOPSIS
    Process Monitor Module for DCSA Auditing Software

.DESCRIPTION
    Monitors process execution, including command line arguments,
    parent processes, and termination. Critical for detecting
    unauthorized or suspicious application usage.
#>

# Import utilities
$modulePath = Split-Path -Parent $PSScriptRoot
Import-Module "$modulePath\utils\AuditUtilities.psm1" -Force

# Script-level variables
$script:ProcessEventSubscriptions = @()
$script:ProcessCache = @{}

function Start-ProcessMonitoring {
    <#
    .SYNOPSIS
        Starts process execution monitoring
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [switch]$AsJob
    )

    $config = Get-AuditConfig

    if (-not $config.ProcessMonitoring.Enabled) {
        Write-Warning "Process monitoring is disabled in configuration"
        return
    }

    Write-AuditLog -Category "Process" -Message "Process monitoring started" -Severity "Information"

    if ($AsJob) {
        $job = Start-Job -ScriptBlock {
            param($ModulePath, $Config)
            Import-Module "$ModulePath\utils\AuditUtilities.psm1" -Force
            Import-Module "$ModulePath\modules\ProcessMonitor.psm1" -Force

            Register-ProcessEvents

            while ($true) {
                # Poll Security log for process events as backup
                Get-ProcessEventsFromLog
                Start-Sleep -Seconds 30
            }
        } -ArgumentList $modulePath, $config

        return $job
    } else {
        Register-ProcessEvents

        while ($true) {
            Get-ProcessEventsFromLog
            Start-Sleep -Seconds 30
        }
    }
}

function Register-ProcessEvents {
    <#
    .SYNOPSIS
        Registers WMI event subscriptions for process events
    #>
    [CmdletBinding()]
    param()

    $config = Get-AuditConfig

    try {
        # Process creation events
        if ($config.ProcessMonitoring.LogProcessStart) {
            $createQuery = "SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'"
            $createAction = {
                $process = $Event.SourceEventArgs.NewEvent.TargetInstance
                Write-ProcessEvent -EventType "Started" -Process $process
            }
            $script:ProcessEventSubscriptions += Register-WmiEvent -Query $createQuery -Action $createAction -ErrorAction Stop
        }

        # Process termination events
        if ($config.ProcessMonitoring.LogProcessEnd) {
            $deleteQuery = "SELECT * FROM __InstanceDeletionEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'"
            $deleteAction = {
                $process = $Event.SourceEventArgs.NewEvent.TargetInstance
                Write-ProcessEvent -EventType "Terminated" -Process $process
            }
            $script:ProcessEventSubscriptions += Register-WmiEvent -Query $deleteQuery -Action $deleteAction -ErrorAction Stop
        }

        Write-AuditLog -Category "Process" -Message "Process event monitoring registered" -Severity "Information"

    } catch {
        Write-AuditLog -Category "System" -Message "Failed to register process events: $_" -Severity "Error"
    }
}

function Write-ProcessEvent {
    <#
    .SYNOPSIS
        Writes a process event to the audit log
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet("Started", "Terminated")]
        [string]$EventType,

        [Parameter()]
        $Process,

        [Parameter()]
        [hashtable]$AdditionalData = @{}
    )

    $config = Get-AuditConfig

    $processInfo = @{
        EventType = $EventType
        ProcessId = $Process.ProcessId
        ProcessName = $Process.Name
        ExecutablePath = $Process.ExecutablePath
        ParentProcessId = $Process.ParentProcessId
    }

    # Get command line if enabled and available
    if ($config.ProcessMonitoring.LogCommandLine -and $Process.CommandLine) {
        # Sanitize command line to remove potential sensitive data
        $commandLine = $Process.CommandLine
        # Mask potential passwords/keys in command line
        $commandLine = $commandLine -replace '(?i)(password|pwd|key|secret|token)[=:]\s*\S+', '$1=***REDACTED***'
        $processInfo["CommandLine"] = $commandLine
    }

    # Get process owner
    try {
        if ($Process.PSObject.Methods['GetOwner']) {
            $owner = $Process.GetOwner()
            if ($owner.ReturnValue -eq 0) {
                $processInfo["Owner"] = "$($owner.Domain)\$($owner.User)"
            }
        }
    } catch { }

    # Get parent process name
    try {
        $parentProcess = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $($Process.ParentProcessId)" -ErrorAction SilentlyContinue
        if ($parentProcess) {
            $processInfo["ParentProcessName"] = $parentProcess.Name
        }
    } catch { }

    # Check if this is a watched process
    $isWatched = $Process.Name -in $config.ProcessMonitoring.WatchedProcesses
    $processInfo["IsWatchedProcess"] = $isWatched

    # Merge additional data
    foreach ($key in $AdditionalData.Keys) {
        $processInfo[$key] = $AdditionalData[$key]
    }

    # Determine severity
    $severity = if ($isWatched) { "Warning" } else { "Information" }

    $message = "Process $EventType - $($Process.Name) (PID: $($Process.ProcessId))"
    if ($isWatched) {
        $message += " [WATCHED]"
    }

    Write-AuditLog -Category "Process" -Message $message -Severity $severity -AdditionalData $processInfo

    # Cache process info for later reference
    if ($EventType -eq "Started") {
        $script:ProcessCache[$Process.ProcessId] = $processInfo
    } elseif ($EventType -eq "Terminated") {
        $script:ProcessCache.Remove($Process.ProcessId)
    }
}

function Get-ProcessEventsFromLog {
    <#
    .SYNOPSIS
        Gets process creation/termination events from Windows Security log
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [datetime]$Since = (Get-Date).AddMinutes(-5)
    )

    $config = Get-AuditConfig

    # Security log event IDs for process tracking
    # 4688 = New process created
    # 4689 = Process terminated
    $processEventIds = @()
    if ($config.ProcessMonitoring.LogProcessStart) { $processEventIds += 4688 }
    if ($config.ProcessMonitoring.LogProcessEnd) { $processEventIds += 4689 }

    if ($processEventIds.Count -eq 0) { return }

    try {
        $filterXml = @"
<QueryList>
    <Query Id="0" Path="Security">
        <Select Path="Security">*[System[($(($processEventIds | ForEach-Object { "EventID=$_" }) -join ' or ')) and TimeCreated[@SystemTime >= '$(($Since).ToUniversalTime().ToString("o"))']]]</Select>
    </Query>
</QueryList>
"@

        $events = Get-WinEvent -FilterXml $filterXml -ErrorAction SilentlyContinue

        foreach ($event in $events) {
            $eventXml = [xml]$event.ToXml()
            $eventData = @{}

            foreach ($data in $eventXml.Event.EventData.Data) {
                if ($data.Name -and $data.'#text') {
                    $eventData[$data.Name] = $data.'#text'
                }
            }

            # Create a pseudo-process object
            $processInfo = @{
                ProcessId = $eventData.NewProcessId ?? $eventData.ProcessId
                Name = [System.IO.Path]::GetFileName($eventData.NewProcessName ?? $eventData.ProcessName)
                ExecutablePath = $eventData.NewProcessName ?? $eventData.ProcessName
                ParentProcessId = $eventData.ParentProcessId
                CommandLine = $eventData.CommandLine
            }

            $eventType = if ($event.Id -eq 4688) { "Started" } else { "Terminated" }

            # Check if this is a watched process
            $isWatched = $processInfo.Name -in $config.ProcessMonitoring.WatchedProcesses

            # Only log if it's a watched process or if we're logging all processes
            if ($isWatched -or -not $config.ProcessMonitoring.WatchedProcesses.Count) {
                Write-ProcessEvent -EventType $eventType -Process ([PSCustomObject]$processInfo) -AdditionalData @{
                    SubjectUserName = $eventData.SubjectUserName
                    SubjectDomainName = $eventData.SubjectDomainName
                    TokenElevationType = $eventData.TokenElevationType
                    Source = "SecurityLog"
                    RecordId = $event.RecordId
                }
            }
        }
    } catch {
        if ($_.Exception.Message -notmatch "No events were found") {
            Write-AuditLog -Category "System" -Message "Error collecting process events: $_" -Severity "Error"
        }
    }
}

function Get-RunningProcesses {
    <#
    .SYNOPSIS
        Gets a snapshot of currently running processes
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [switch]$WatchedOnly
    )

    $config = Get-AuditConfig

    $processes = Get-CimInstance -ClassName Win32_Process -ErrorAction SilentlyContinue

    $result = foreach ($proc in $processes) {
        $isWatched = $proc.Name -in $config.ProcessMonitoring.WatchedProcesses

        if ($WatchedOnly -and -not $isWatched) { continue }

        # Get owner
        $owner = $null
        try {
            $ownerInfo = Invoke-CimMethod -InputObject $proc -MethodName GetOwner -ErrorAction SilentlyContinue
            if ($ownerInfo.ReturnValue -eq 0) {
                $owner = "$($ownerInfo.Domain)\$($ownerInfo.User)"
            }
        } catch { }

        [PSCustomObject]@{
            ProcessId = $proc.ProcessId
            Name = $proc.Name
            ExecutablePath = $proc.ExecutablePath
            CommandLine = $proc.CommandLine
            ParentProcessId = $proc.ParentProcessId
            CreationDate = $proc.CreationDate
            Owner = $owner
            IsWatchedProcess = $isWatched
            WorkingSetSize = $proc.WorkingSetSize
            ThreadCount = $proc.ThreadCount
        }
    }

    return $result
}

function Get-ProcessTree {
    <#
    .SYNOPSIS
        Gets the process tree for a given process ID
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [int]$ProcessId,

        [Parameter()]
        [int]$Depth = 5
    )

    $tree = @()
    $currentPid = $ProcessId
    $currentDepth = 0

    while ($currentPid -and $currentDepth -lt $Depth) {
        $proc = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $currentPid" -ErrorAction SilentlyContinue
        if (-not $proc) { break }

        $tree += [PSCustomObject]@{
            Level = $currentDepth
            ProcessId = $proc.ProcessId
            Name = $proc.Name
            ParentProcessId = $proc.ParentProcessId
            ExecutablePath = $proc.ExecutablePath
        }

        $currentPid = $proc.ParentProcessId
        $currentDepth++
    }

    return $tree
}

function Get-ProcessSummary {
    <#
    .SYNOPSIS
        Generates a summary of process activity
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [datetime]$StartTime = (Get-Date).AddDays(-1),

        [Parameter()]
        [datetime]$EndTime = (Get-Date)
    )

    $config = Get-AuditConfig
    $logPath = "$($config.LogStorage.BasePath)\Process"

    $events = @()

    # Read from audit logs
    $logFiles = Get-ChildItem -Path $logPath -Filter "*.log" -ErrorAction SilentlyContinue

    foreach ($file in $logFiles) {
        $lines = Get-Content -Path $file.FullName -ErrorAction SilentlyContinue

        foreach ($line in $lines) {
            if ($line -match '^(.+)\|HASH:') {
                try {
                    $jsonPart = $Matches[1]
                    $entry = $jsonPart | ConvertFrom-Json

                    $eventTime = [datetime]::Parse($entry.Timestamp)
                    if ($eventTime -ge $StartTime -and $eventTime -le $EndTime) {
                        $events += $entry
                    }
                } catch { }
            }
        }
    }

    $summary = @{
        TimeRange = @{
            Start = $StartTime.ToString("o")
            End = $EndTime.ToString("o")
        }
        TotalEvents = $events.Count
        ProcessesStarted = ($events | Where-Object { $_.EventType -eq "Started" }).Count
        ProcessesTerminated = ($events | Where-Object { $_.EventType -eq "Terminated" }).Count
        WatchedProcessEvents = ($events | Where-Object { $_.IsWatchedProcess -eq $true }).Count
        UniqueProcesses = ($events | Select-Object -ExpandProperty ProcessName -Unique -ErrorAction SilentlyContinue).Count
        TopProcesses = @{}
        WatchedProcessBreakdown = @{}
    }

    # Top processes by count
    $events | Where-Object { $_.EventType -eq "Started" } | Group-Object ProcessName | Sort-Object Count -Descending | Select-Object -First 20 | ForEach-Object {
        $summary.TopProcesses[$_.Name] = $_.Count
    }

    # Watched processes breakdown
    $config.ProcessMonitoring.WatchedProcesses | ForEach-Object {
        $procName = $_
        $count = ($events | Where-Object { $_.ProcessName -eq $procName }).Count
        $summary.WatchedProcessBreakdown[$procName] = $count
    }

    return [PSCustomObject]$summary
}

function Stop-ProcessMonitoring {
    <#
    .SYNOPSIS
        Stops process monitoring and cleans up
    #>
    [CmdletBinding()]
    param()

    foreach ($subscription in $script:ProcessEventSubscriptions) {
        Unregister-Event -SubscriptionId $subscription.Id -ErrorAction SilentlyContinue
    }

    $script:ProcessEventSubscriptions.Clear()
    $script:ProcessCache.Clear()

    Write-AuditLog -Category "Process" -Message "Process monitoring stopped" -Severity "Information"
}

# Export functions
Export-ModuleMember -Function @(
    'Start-ProcessMonitoring',
    'Register-ProcessEvents',
    'Write-ProcessEvent',
    'Get-ProcessEventsFromLog',
    'Get-RunningProcesses',
    'Get-ProcessTree',
    'Get-ProcessSummary',
    'Stop-ProcessMonitoring'
)
