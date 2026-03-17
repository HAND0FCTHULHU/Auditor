#Requires -Version 5.1
<#
.SYNOPSIS
    User Activity Monitor Module for DCSA Auditing Software

.DESCRIPTION
    Monitors user sessions, idle time, screen lock/unlock events,
    and session duration for compliance tracking.
#>

# Import utilities
$modulePath = Split-Path -Parent $PSScriptRoot
Import-Module "$modulePath\utils\AuditUtilities.psm1" -Force

# Script-level tracking variables
$script:ActiveSessions = @{}
$script:LastActivityTime = @{}

function Start-UserActivityMonitoring {
    <#
    .SYNOPSIS
        Starts continuous user activity monitoring
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [switch]$AsJob
    )

    $config = Get-AuditConfig

    if (-not $config.UserActivity.Enabled) {
        Write-Warning "User activity monitoring is disabled in configuration"
        return
    }

    Write-AuditLog -Category "UserActivity" -Message "User activity monitoring started" -Severity "Information"

    # Record current user session
    Record-SessionStart

    if ($AsJob) {
        $job = Start-Job -ScriptBlock {
            param($ModulePath, $Config)
            Import-Module "$ModulePath\utils\AuditUtilities.psm1" -Force
            Import-Module "$ModulePath\modules\UserActivityMonitor.psm1" -Force

            while ($true) {
                Update-UserActivityStatus
                Start-Sleep -Seconds 60
            }
        } -ArgumentList $modulePath, $config

        return $job
    } else {
        while ($true) {
            Update-UserActivityStatus
            Start-Sleep -Seconds 60
        }
    }
}

function Record-SessionStart {
    <#
    .SYNOPSIS
        Records the start of a user session
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$UserName = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    )

    $sessionInfo = @{
        UserName = $UserName
        SessionStart = Get-Date
        ComputerName = $env:COMPUTERNAME
        SessionId = [System.Diagnostics.Process]::GetCurrentProcess().SessionId
        LogonType = "Interactive"
    }

    $script:ActiveSessions[$UserName] = $sessionInfo
    $script:LastActivityTime[$UserName] = Get-Date

    Write-AuditLog -Category "UserActivity" -Message "Session started for user: $UserName" -Severity "Information" -AdditionalData $sessionInfo
}

function Record-SessionEnd {
    <#
    .SYNOPSIS
        Records the end of a user session
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$UserName = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    )

    if ($script:ActiveSessions.ContainsKey($UserName)) {
        $sessionInfo = $script:ActiveSessions[$UserName]
        $sessionEnd = Get-Date
        $duration = $sessionEnd - $sessionInfo.SessionStart

        $endData = @{
            UserName = $UserName
            SessionStart = $sessionInfo.SessionStart.ToString("o")
            SessionEnd = $sessionEnd.ToString("o")
            DurationMinutes = [math]::Round($duration.TotalMinutes, 2)
        }

        Write-AuditLog -Category "UserActivity" -Message "Session ended for user: $UserName (Duration: $([math]::Round($duration.TotalMinutes, 0)) minutes)" -Severity "Information" -AdditionalData $endData

        $script:ActiveSessions.Remove($UserName)
        $script:LastActivityTime.Remove($UserName)
    }
}

function Update-UserActivityStatus {
    <#
    .SYNOPSIS
        Updates user activity status and checks for idle time
    #>
    [CmdletBinding()]
    param()

    $config = Get-AuditConfig

    foreach ($userName in @($script:ActiveSessions.Keys)) {
        # Check idle time using last input info
        $idleTime = Get-UserIdleTime

        if ($config.UserActivity.TrackIdleTime) {
            if ($idleTime.TotalMinutes -ge $config.UserActivity.IdleTimeoutMinutes) {
                # User has been idle
                if (-not $script:ActiveSessions[$userName].ContainsKey("IdleStart")) {
                    $script:ActiveSessions[$userName]["IdleStart"] = Get-Date

                    Write-AuditLog -Category "UserActivity" -Message "User idle detected: $userName (Idle for $([math]::Round($idleTime.TotalMinutes, 0)) minutes)" -Severity "Warning" -AdditionalData @{
                        UserName = $userName
                        IdleMinutes = [math]::Round($idleTime.TotalMinutes, 2)
                    }
                }
            } else {
                # User is active
                if ($script:ActiveSessions[$userName].ContainsKey("IdleStart")) {
                    $idleDuration = (Get-Date) - $script:ActiveSessions[$userName]["IdleStart"]
                    $script:ActiveSessions[$userName].Remove("IdleStart")

                    Write-AuditLog -Category "UserActivity" -Message "User activity resumed: $userName (Was idle for $([math]::Round($idleDuration.TotalMinutes, 0)) minutes)" -Severity "Information" -AdditionalData @{
                        UserName = $userName
                        IdleDurationMinutes = [math]::Round($idleDuration.TotalMinutes, 2)
                    }
                }
                $script:LastActivityTime[$userName] = Get-Date
            }
        }
    }

    # Check for screen lock/unlock events
    if ($config.UserActivity.LogScreenLock) {
        Check-ScreenLockEvents
    }
}

function Get-UserIdleTime {
    <#
    .SYNOPSIS
        Gets the current user's idle time using Windows API
    #>
    [CmdletBinding()]
    param()

    Add-Type @"
    using System;
    using System.Runtime.InteropServices;

    public struct LASTINPUTINFO {
        public uint cbSize;
        public uint dwTime;
    }

    public class IdleTime {
        [DllImport("user32.dll")]
        public static extern bool GetLastInputInfo(ref LASTINPUTINFO plii);
    }
"@ -ErrorAction SilentlyContinue

    $lastInput = New-Object LASTINPUTINFO
    $lastInput.cbSize = [System.Runtime.InteropServices.Marshal]::SizeOf($lastInput)

    if ([IdleTime]::GetLastInputInfo([ref]$lastInput)) {
        $idleMilliseconds = [Environment]::TickCount - $lastInput.dwTime
        return [TimeSpan]::FromMilliseconds($idleMilliseconds)
    }

    return [TimeSpan]::Zero
}

function Check-ScreenLockEvents {
    <#
    .SYNOPSIS
        Checks for recent screen lock/unlock events
    #>
    [CmdletBinding()]
    param()

    # Event IDs for session lock/unlock
    # 4800 = Workstation locked
    # 4801 = Workstation unlocked
    # 4802 = Screen saver invoked
    # 4803 = Screen saver dismissed

    $lockEventIds = @(4800, 4801, 4802, 4803)
    $since = (Get-Date).AddMinutes(-2)

    try {
        $events = Get-WinEvent -FilterHashtable @{
            LogName = 'Security'
            Id = $lockEventIds
            StartTime = $since
        } -ErrorAction SilentlyContinue

        foreach ($event in $events) {
            $eventXml = [xml]$event.ToXml()
            $userName = ($eventXml.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'

            $eventType = switch ($event.Id) {
                4800 { "Workstation Locked" }
                4801 { "Workstation Unlocked" }
                4802 { "Screen Saver Invoked" }
                4803 { "Screen Saver Dismissed" }
            }

            # Only log if not already logged (check cache)
            $cacheKey = "$($event.RecordId)"
            if (-not $script:LastActivityTime.ContainsKey($cacheKey)) {
                $script:LastActivityTime[$cacheKey] = $true

                Write-AuditLog -Category "UserActivity" -Message "$eventType - User: $userName" -Severity "Information" -AdditionalData @{
                    EventType = $eventType
                    EventId = $event.Id
                    UserName = $userName
                    TimeCreated = $event.TimeCreated.ToString("o")
                }
            }
        }
    } catch {
        # Silently continue if no events found
    }
}

function Get-ActiveUserSessions {
    <#
    .SYNOPSIS
        Returns information about all active user sessions on the system
    #>
    [CmdletBinding()]
    param()

    $sessions = @()

    # Query active sessions using quser/query user
    try {
        $quserOutput = quser 2>$null

        if ($quserOutput) {
            # Skip header line
            $lines = $quserOutput | Select-Object -Skip 1

            foreach ($line in $lines) {
                # Parse quser output
                if ($line -match '^\s*(\S+)\s+(\S+)?\s+(\d+)\s+(\S+)\s+(.+)$') {
                    $sessionInfo = @{
                        UserName = $Matches[1]
                        SessionName = $Matches[2]
                        SessionId = $Matches[3]
                        State = $Matches[4]
                        IdleTime = $Matches[5].Trim()
                    }
                    $sessions += [PSCustomObject]$sessionInfo
                }
            }
        }
    } catch {
        Write-AuditLog -Category "System" -Message "Error querying user sessions: $_" -Severity "Warning"
    }

    return $sessions
}

function Get-LogonHistory {
    <#
    .SYNOPSIS
        Gets logon history for a specified time period
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [datetime]$StartTime = (Get-Date).AddDays(-7),

        [Parameter()]
        [datetime]$EndTime = (Get-Date),

        [Parameter()]
        [string]$UserName
    )

    $filterHash = @{
        LogName = 'Security'
        Id = @(4624, 4625, 4634, 4647)
        StartTime = $StartTime
        EndTime = $EndTime
    }

    try {
        $events = Get-WinEvent -FilterHashtable $filterHash -ErrorAction SilentlyContinue

        $history = foreach ($event in $events) {
            $eventXml = [xml]$event.ToXml()
            $targetUser = ($eventXml.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
            $logonType = ($eventXml.Event.EventData.Data | Where-Object { $_.Name -eq 'LogonType' }).'#text'
            $ipAddress = ($eventXml.Event.EventData.Data | Where-Object { $_.Name -eq 'IpAddress' }).'#text'

            # Filter by username if specified
            if ($UserName -and $targetUser -notlike "*$UserName*") {
                continue
            }

            # Skip system accounts
            if ($targetUser -in @('SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE', 'DWM-1', 'UMFD-0', 'UMFD-1')) {
                continue
            }

            [PSCustomObject]@{
                TimeCreated = $event.TimeCreated
                EventType = switch ($event.Id) {
                    4624 { "Logon" }
                    4625 { "Failed Logon" }
                    4634 { "Logoff" }
                    4647 { "User Initiated Logoff" }
                }
                UserName = $targetUser
                LogonType = Get-LogonTypeName -LogonType $logonType
                IpAddress = $ipAddress
                EventId = $event.Id
            }
        }

        return $history | Sort-Object TimeCreated -Descending
    } catch {
        Write-AuditLog -Category "System" -Message "Error retrieving logon history: $_" -Severity "Error"
        return @()
    }
}

function Get-LogonTypeName {
    <#
    .SYNOPSIS
        Returns human-readable logon type name
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$LogonType
    )

    $types = @{
        "2" = "Interactive"
        "3" = "Network"
        "4" = "Batch"
        "5" = "Service"
        "7" = "Unlock"
        "8" = "NetworkCleartext"
        "9" = "NewCredentials"
        "10" = "RemoteInteractive"
        "11" = "CachedInteractive"
    }

    $result = $types[$LogonType]
    if ($null -eq $result) { $result = "Unknown ($LogonType)" }
    return $result
}

function Get-UserActivitySummary {
    <#
    .SYNOPSIS
        Generates a summary of user activity for reporting
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [datetime]$StartTime = (Get-Date).AddDays(-1),

        [Parameter()]
        [datetime]$EndTime = (Get-Date)
    )

    $history = Get-LogonHistory -StartTime $StartTime -EndTime $EndTime

    $summary = @{
        TimeRange = @{
            Start = $StartTime.ToString("o")
            End = $EndTime.ToString("o")
        }
        TotalLogons = ($history | Where-Object { $_.EventType -eq "Logon" }).Count
        TotalLogoffs = ($history | Where-Object { $_.EventType -in @("Logoff", "User Initiated Logoff") }).Count
        FailedLogons = ($history | Where-Object { $_.EventType -eq "Failed Logon" }).Count
        UniqueUsers = ($history | Select-Object -ExpandProperty UserName -Unique).Count
        LogonsByType = @{}
        UserStats = @{}
    }

    # Group by logon type
    $history | Where-Object { $_.EventType -eq "Logon" } | Group-Object LogonType | ForEach-Object {
        $summary.LogonsByType[$_.Name] = $_.Count
    }

    # Stats per user
    $history | Group-Object UserName | ForEach-Object {
        $userEvents = $_.Group
        $summary.UserStats[$_.Name] = @{
            Logons = ($userEvents | Where-Object { $_.EventType -eq "Logon" }).Count
            Logoffs = ($userEvents | Where-Object { $_.EventType -in @("Logoff", "User Initiated Logoff") }).Count
            FailedLogons = ($userEvents | Where-Object { $_.EventType -eq "Failed Logon" }).Count
            FirstActivity = ($userEvents | Sort-Object TimeCreated | Select-Object -First 1).TimeCreated
            LastActivity = ($userEvents | Sort-Object TimeCreated -Descending | Select-Object -First 1).TimeCreated
        }
    }

    return [PSCustomObject]$summary
}

# Export functions
Export-ModuleMember -Function @(
    'Start-UserActivityMonitoring',
    'Record-SessionStart',
    'Record-SessionEnd',
    'Update-UserActivityStatus',
    'Get-UserIdleTime',
    'Check-ScreenLockEvents',
    'Get-ActiveUserSessions',
    'Get-LogonHistory',
    'Get-LogonTypeName',
    'Get-UserActivitySummary'
)
