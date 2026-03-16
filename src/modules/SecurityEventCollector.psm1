#Requires -Version 5.1
<#
.SYNOPSIS
    Security Event Collector Module for DCSA Auditing Software

.DESCRIPTION
    Collects and processes Windows Security events including logon/logoff,
    privilege use, account management, and policy changes.
#>

# Import utilities
$modulePath = Split-Path -Parent $PSScriptRoot
Import-Module "$modulePath\utils\AuditUtilities.psm1" -Force

# Script-level variables for event tracking
$script:LastEventTime = $null
$script:EventCache = @{}

function Start-SecurityEventCollection {
    <#
    .SYNOPSIS
        Starts continuous security event collection
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [switch]$AsJob
    )

    $config = Get-AuditConfig

    if (-not $config.SecurityEvents.Enabled) {
        Write-Warning "Security event collection is disabled in configuration"
        return
    }

    Write-AuditLog -Category "Security" -Message "Security event collection started" -Severity "Information"

    if ($AsJob) {
        $job = Start-Job -ScriptBlock {
            param($ModulePath, $Config)
            Import-Module "$ModulePath\utils\AuditUtilities.psm1" -Force
            Import-Module "$ModulePath\modules\SecurityEventCollector.psm1" -Force

            while ($true) {
                Get-SecurityEventsIncremental
                Start-Sleep -Seconds $Config.SecurityEvents.PollIntervalSeconds
            }
        } -ArgumentList $modulePath, $config

        return $job
    } else {
        while ($true) {
            Get-SecurityEventsIncremental
            Start-Sleep -Seconds $config.SecurityEvents.PollIntervalSeconds
        }
    }
}

function Get-SecurityEventsIncremental {
    <#
    .SYNOPSIS
        Retrieves new security events since last check
    #>
    [CmdletBinding()]
    param()

    $config = Get-AuditConfig
    $monitoredIDs = $config.SecurityEvents.MonitoredEventIDs

    # Set initial time if first run
    if ($null -eq $script:LastEventTime) {
        $script:LastEventTime = (Get-Date).AddMinutes(-5)
    }

    try {
        $filterXml = @"
<QueryList>
    <Query Id="0" Path="Security">
        <Select Path="Security">*[System[($(($monitoredIDs | ForEach-Object { "EventID=$_" }) -join ' or ')) and TimeCreated[@SystemTime >= '$(($script:LastEventTime).ToUniversalTime().ToString("o"))']]]</Select>
    </Query>
</QueryList>
"@

        $events = Get-WinEvent -FilterXml $filterXml -ErrorAction SilentlyContinue

        foreach ($event in $events) {
            Process-SecurityEvent -Event $event
        }

        if ($events.Count -gt 0) {
            $script:LastEventTime = ($events | Sort-Object TimeCreated -Descending | Select-Object -First 1).TimeCreated
        }

    } catch {
        if ($_.Exception.Message -notmatch "No events were found") {
            Write-AuditLog -Category "System" -Message "Error collecting security events: $_" -Severity "Error"
        }
    }
}

function Process-SecurityEvent {
    <#
    .SYNOPSIS
        Processes and logs individual security events
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Diagnostics.Eventing.Reader.EventLogRecord]$Event
    )

    $config = Get-AuditConfig
    $eventId = $Event.Id
    $eventXml = [xml]$Event.ToXml()

    # Extract common properties
    $eventData = @{
        EventID = $eventId
        TimeCreated = $Event.TimeCreated.ToUniversalTime().ToString("o")
        RecordId = $Event.RecordId
        Computer = $Event.MachineName
        EventType = Get-SecurityEventTypeName -EventId $eventId
    }

    # Extract event-specific data
    $eventDataNode = $eventXml.Event.EventData
    if ($eventDataNode) {
        foreach ($data in $eventDataNode.Data) {
            if ($data.Name -and $data.'#text') {
                $eventData[$data.Name] = $data.'#text'
            }
        }
    }

    # Determine severity based on event type
    $severity = Get-SecurityEventSeverity -EventId $eventId -EventData $eventData

    # Create message
    $message = Format-SecurityEventMessage -EventId $eventId -EventData $eventData

    # Log the event
    Write-AuditLog -Category "Security" -Message $message -Severity $severity -AdditionalData $eventData

    # Check for alerting conditions
    Check-SecurityAlerts -EventId $eventId -EventData $eventData

    # Trigger HTML report update on successful logon
    if ($eventId -eq 4624) {
        try {
            Import-Module "$modulePath\modules\ReportGenerator.psm1" -Force -ErrorAction SilentlyContinue
            Update-ReportOnLogon
        } catch { }
    }
}

function Get-SecurityEventTypeName {
    <#
    .SYNOPSIS
        Returns human-readable event type name
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [int]$EventId
    )

    $eventTypes = @{
        4624 = "Successful Logon"
        4625 = "Failed Logon"
        4634 = "Logoff"
        4647 = "User Initiated Logoff"
        4648 = "Explicit Credential Logon"
        4672 = "Special Privileges Assigned"
        4720 = "User Account Created"
        4722 = "User Account Enabled"
        4723 = "Password Change Attempt"
        4724 = "Password Reset Attempt"
        4725 = "User Account Disabled"
        4726 = "User Account Deleted"
        4738 = "User Account Changed"
        4740 = "User Account Locked Out"
        4704 = "User Right Assigned"
        4705 = "User Right Removed"
        4706 = "Trust Created"
        4713 = "Kerberos Policy Changed"
        4719 = "System Audit Policy Changed"
        4656 = "Handle to Object Requested"
        4658 = "Handle to Object Closed"
        4660 = "Object Deleted"
        4663 = "Object Access Attempt"
        4670 = "Permissions Changed"
        4673 = "Privileged Service Called"
        4674 = "Privileged Object Operation"
        4608 = "Windows Starting Up"
        4609 = "Windows Shutting Down"
        4616 = "System Time Changed"
        4902 = "Per-User Audit Policy Created"
        4906 = "CrashOnAuditFail Changed"
        4907 = "Auditing Settings Changed"
        4912 = "Per-User Audit Policy Changed"
    }

    return $eventTypes[$EventId] ?? "Unknown Event ($EventId)"
}

function Get-SecurityEventSeverity {
    <#
    .SYNOPSIS
        Determines severity level for security events
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [int]$EventId,

        [Parameter()]
        [hashtable]$EventData = @{}
    )

    # Critical events
    $criticalEvents = @(4719, 4906, 4907, 4616, 4740)
    if ($EventId -in $criticalEvents) { return "Critical" }

    # Error events (failed operations)
    $errorEvents = @(4625)
    if ($EventId -in $errorEvents) { return "Error" }

    # Warning events (account changes, privilege use)
    $warningEvents = @(4720, 4722, 4723, 4724, 4725, 4726, 4738, 4704, 4705, 4672, 4673, 4674)
    if ($EventId -in $warningEvents) { return "Warning" }

    # Everything else is informational
    return "Information"
}

function Format-SecurityEventMessage {
    <#
    .SYNOPSIS
        Formats a human-readable message for security events
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [int]$EventId,

        [Parameter(Mandatory)]
        [hashtable]$EventData
    )

    $eventType = Get-SecurityEventTypeName -EventId $EventId

    switch ($EventId) {
        4624 {
            return "$eventType - User: $($EventData.TargetUserName) Domain: $($EventData.TargetDomainName) LogonType: $($EventData.LogonType) from $($EventData.IpAddress)"
        }
        4625 {
            return "$eventType - User: $($EventData.TargetUserName) Domain: $($EventData.TargetDomainName) Reason: $($EventData.FailureReason) from $($EventData.IpAddress)"
        }
        4634 {
            return "$eventType - User: $($EventData.TargetUserName) LogonType: $($EventData.LogonType)"
        }
        4672 {
            return "$eventType - User: $($EventData.SubjectUserName) Privileges: $($EventData.PrivilegeList)"
        }
        4720 {
            return "$eventType - New User: $($EventData.TargetUserName) Created By: $($EventData.SubjectUserName)"
        }
        4740 {
            return "$eventType - User: $($EventData.TargetUserName) Locked by: $($EventData.SubjectUserName)"
        }
        4719 {
            return "$eventType - Changed By: $($EventData.SubjectUserName)"
        }
        4616 {
            return "$eventType - Changed By: $($EventData.SubjectUserName) New Time: $($EventData.NewTime)"
        }
        default {
            return "$eventType"
        }
    }
}

function Check-SecurityAlerts {
    <#
    .SYNOPSIS
        Checks security events against alerting rules
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [int]$EventId,

        [Parameter(Mandatory)]
        [hashtable]$EventData
    )

    $config = Get-AuditConfig

    if (-not $config.Alerting.Enabled) { return }

    # Check for failed logon threshold
    if ($EventId -eq 4625) {
        $user = $EventData.TargetUserName
        $windowStart = (Get-Date).AddMinutes(-$config.Alerting.FailedLogonWindowMinutes)

        # Track failed logons in cache
        if (-not $script:EventCache.ContainsKey("FailedLogons")) {
            $script:EventCache["FailedLogons"] = @{}
        }

        if (-not $script:EventCache["FailedLogons"].ContainsKey($user)) {
            $script:EventCache["FailedLogons"][$user] = @()
        }

        $script:EventCache["FailedLogons"][$user] += Get-Date

        # Clean old entries
        $script:EventCache["FailedLogons"][$user] = $script:EventCache["FailedLogons"][$user] | Where-Object { $_ -gt $windowStart }

        # Check threshold
        if ($script:EventCache["FailedLogons"][$user].Count -ge $config.Alerting.FailedLogonThreshold) {
            $alertMsg = "ALERT: Multiple failed logon attempts for user '$user' - $($script:EventCache["FailedLogons"][$user].Count) failures in $($config.Alerting.FailedLogonWindowMinutes) minutes"
            Write-AuditLog -Category "Alert" -Message $alertMsg -Severity "Critical" -AdditionalData @{
                AlertType = "FailedLogonThreshold"
                User = $user
                FailureCount = $script:EventCache["FailedLogons"][$user].Count
            }
        }
    }

    # Check for after-hours activity
    if ($config.Alerting.AfterHoursAlerts -and $EventId -in @(4624, 4648)) {
        $currentHour = (Get-Date).Hour
        if ($currentHour -lt $config.Alerting.BusinessHoursStart -or $currentHour -ge $config.Alerting.BusinessHoursEnd) {
            $alertMsg = "ALERT: After-hours logon detected - User: $($EventData.TargetUserName) at $(Get-Date -Format 'HH:mm')"
            Write-AuditLog -Category "Alert" -Message $alertMsg -Severity "Warning" -AdditionalData @{
                AlertType = "AfterHoursLogon"
                User = $EventData.TargetUserName
                Hour = $currentHour
            }
        }
    }

    # Alert on critical events
    if ($EventId -in @(4719, 4906, 4907, 4616, 4740)) {
        $alertMsg = "ALERT: Critical security event detected - $(Get-SecurityEventTypeName -EventId $EventId)"
        Write-AuditLog -Category "Alert" -Message $alertMsg -Severity "Critical" -AdditionalData @{
            AlertType = "CriticalSecurityEvent"
            EventId = $EventId
            EventType = Get-SecurityEventTypeName -EventId $EventId
        }
    }
}

function Get-SecurityEventSummary {
    <#
    .SYNOPSIS
        Generates a summary of security events for reporting
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [datetime]$StartTime = (Get-Date).AddDays(-1),

        [Parameter()]
        [datetime]$EndTime = (Get-Date)
    )

    $config = Get-AuditConfig
    $monitoredIDs = $config.SecurityEvents.MonitoredEventIDs

    try {
        $filterXml = @"
<QueryList>
    <Query Id="0" Path="Security">
        <Select Path="Security">*[System[($(($monitoredIDs | ForEach-Object { "EventID=$_" }) -join ' or ')) and TimeCreated[@SystemTime >= '$(($StartTime).ToUniversalTime().ToString("o"))' and @SystemTime &lt;= '$(($EndTime).ToUniversalTime().ToString("o"))']]]</Select>
    </Query>
</QueryList>
"@

        $events = Get-WinEvent -FilterXml $filterXml -ErrorAction SilentlyContinue

        $summary = @{
            TimeRange = @{
                Start = $StartTime.ToString("o")
                End = $EndTime.ToString("o")
            }
            TotalEvents = $events.Count
            EventsByType = @{}
            SuccessfulLogons = 0
            FailedLogons = 0
            PrivilegeUse = 0
            AccountChanges = 0
            PolicyChanges = 0
            UniqueUsers = @()
        }

        foreach ($event in $events) {
            $eventType = Get-SecurityEventTypeName -EventId $event.Id

            if (-not $summary.EventsByType.ContainsKey($eventType)) {
                $summary.EventsByType[$eventType] = 0
            }
            $summary.EventsByType[$eventType]++

            switch ($event.Id) {
                4624 { $summary.SuccessfulLogons++ }
                4625 { $summary.FailedLogons++ }
                { $_ -in @(4672, 4673, 4674) } { $summary.PrivilegeUse++ }
                { $_ -in @(4720, 4722, 4723, 4724, 4725, 4726, 4738, 4740) } { $summary.AccountChanges++ }
                { $_ -in @(4704, 4705, 4719, 4902, 4906, 4907, 4912) } { $summary.PolicyChanges++ }
            }

            # Extract username
            $eventXml = [xml]$event.ToXml()
            $targetUser = ($eventXml.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
            if ($targetUser -and $targetUser -notin $summary.UniqueUsers) {
                $summary.UniqueUsers += $targetUser
            }
        }

        return [PSCustomObject]$summary

    } catch {
        Write-AuditLog -Category "System" -Message "Error generating security event summary: $_" -Severity "Error"
        return $null
    }
}

# Export functions
Export-ModuleMember -Function @(
    'Start-SecurityEventCollection',
    'Get-SecurityEventsIncremental',
    'Process-SecurityEvent',
    'Get-SecurityEventTypeName',
    'Get-SecurityEventSeverity',
    'Format-SecurityEventMessage',
    'Check-SecurityAlerts',
    'Get-SecurityEventSummary'
)
