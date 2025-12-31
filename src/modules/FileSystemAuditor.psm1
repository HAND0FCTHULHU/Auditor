#Requires -Version 5.1
<#
.SYNOPSIS
    File System Auditor Module for DCSA Auditing Software

.DESCRIPTION
    Monitors file system access, modifications, and deletions on
    sensitive directories. Uses Windows file system auditing events
    and FileSystemWatcher for real-time monitoring.
#>

# Import utilities
$modulePath = Split-Path -Parent $PSScriptRoot
Import-Module "$modulePath\utils\AuditUtilities.psm1" -Force

# Script-level variables
$script:FileWatchers = @{}
$script:FileAccessCache = @{}

function Start-FileSystemAuditing {
    <#
    .SYNOPSIS
        Starts file system auditing for configured directories
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [switch]$AsJob
    )

    $config = Get-AuditConfig

    if (-not $config.FileSystem.Enabled) {
        Write-Warning "File system auditing is disabled in configuration"
        return
    }

    Write-AuditLog -Category "FileSystem" -Message "File system auditing started" -Severity "Information"

    if ($AsJob) {
        $job = Start-Job -ScriptBlock {
            param($ModulePath, $Config)
            Import-Module "$ModulePath\utils\AuditUtilities.psm1" -Force
            Import-Module "$ModulePath\modules\FileSystemAuditor.psm1" -Force

            # Initialize watchers
            Initialize-FileWatchers

            # Keep the job running
            while ($true) {
                # Poll for file access events from Security log
                Get-FileAccessEvents
                Start-Sleep -Seconds 30
            }
        } -ArgumentList $modulePath, $config

        return $job
    } else {
        Initialize-FileWatchers

        while ($true) {
            Get-FileAccessEvents
            Start-Sleep -Seconds 30
        }
    }
}

function Initialize-FileWatchers {
    <#
    .SYNOPSIS
        Initializes FileSystemWatcher instances for monitored paths
    #>
    [CmdletBinding()]
    param()

    $config = Get-AuditConfig

    foreach ($pathPattern in $config.FileSystem.MonitoredPaths) {
        # Expand wildcards in paths
        $expandedPaths = @()
        if ($pathPattern -match '\*') {
            $basePath = Split-Path $pathPattern -Parent
            $pattern = Split-Path $pathPattern -Leaf
            if (Test-Path $basePath) {
                $expandedPaths = Get-ChildItem -Path $basePath -Directory -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name -like $pattern } |
                    Select-Object -ExpandProperty FullName
            }
        } else {
            if (Test-Path $pathPattern) {
                $expandedPaths = @($pathPattern)
            }
        }

        foreach ($path in $expandedPaths) {
            try {
                $watcher = New-Object System.IO.FileSystemWatcher
                $watcher.Path = $path
                $watcher.IncludeSubdirectories = $true
                $watcher.EnableRaisingEvents = $true
                $watcher.NotifyFilter = [System.IO.NotifyFilters]::FileName -bor
                                        [System.IO.NotifyFilters]::DirectoryName -bor
                                        [System.IO.NotifyFilters]::LastWrite -bor
                                        [System.IO.NotifyFilters]::Security

                # Register event handlers
                $createdAction = {
                    param($sender, $e)
                    Write-FileAuditEvent -EventType "Created" -Path $e.FullPath
                }

                $deletedAction = {
                    param($sender, $e)
                    Write-FileAuditEvent -EventType "Deleted" -Path $e.FullPath
                }

                $changedAction = {
                    param($sender, $e)
                    Write-FileAuditEvent -EventType "Modified" -Path $e.FullPath
                }

                $renamedAction = {
                    param($sender, $e)
                    Write-FileAuditEvent -EventType "Renamed" -Path $e.FullPath -AdditionalData @{OldPath = $e.OldFullPath}
                }

                Register-ObjectEvent -InputObject $watcher -EventName Created -Action $createdAction | Out-Null
                Register-ObjectEvent -InputObject $watcher -EventName Deleted -Action $deletedAction | Out-Null
                Register-ObjectEvent -InputObject $watcher -EventName Changed -Action $changedAction | Out-Null
                Register-ObjectEvent -InputObject $watcher -EventName Renamed -Action $renamedAction | Out-Null

                $script:FileWatchers[$path] = $watcher

                Write-AuditLog -Category "FileSystem" -Message "File watcher initialized for: $path" -Severity "Information"
            } catch {
                Write-AuditLog -Category "System" -Message "Failed to initialize file watcher for $path : $_" -Severity "Error"
            }
        }
    }
}

function Write-FileAuditEvent {
    <#
    .SYNOPSIS
        Writes a file system audit event to the log
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet("Created", "Deleted", "Modified", "Renamed", "Accessed", "PermissionChanged")]
        [string]$EventType,

        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter()]
        [hashtable]$AdditionalData = @{}
    )

    $config = Get-AuditConfig

    # Deduplicate rapid events
    $cacheKey = "$EventType|$Path"
    $now = Get-Date
    if ($script:FileAccessCache.ContainsKey($cacheKey)) {
        $lastEvent = $script:FileAccessCache[$cacheKey]
        if (($now - $lastEvent).TotalSeconds -lt 2) {
            return  # Skip duplicate within 2 seconds
        }
    }
    $script:FileAccessCache[$cacheKey] = $now

    # Get file information
    $fileInfo = @{
        Path = $Path
        EventType = $EventType
        Extension = [System.IO.Path]::GetExtension($Path)
        Directory = [System.IO.Path]::GetDirectoryName($Path)
        FileName = [System.IO.Path]::GetFileName($Path)
    }

    # Check if this is a sensitive file type
    $isSensitive = $config.FileSystem.SensitiveExtensions -contains $fileInfo.Extension

    # Get additional file info if file exists
    if (Test-Path $Path -ErrorAction SilentlyContinue) {
        $item = Get-Item $Path -ErrorAction SilentlyContinue
        if ($item) {
            $fileInfo["Size"] = $item.Length
            $fileInfo["LastModified"] = $item.LastWriteTime.ToString("o")
            $fileInfo["Attributes"] = $item.Attributes.ToString()
        }
    }

    # Merge additional data
    foreach ($key in $AdditionalData.Keys) {
        $fileInfo[$key] = $AdditionalData[$key]
    }

    # Determine severity
    $severity = if ($isSensitive -or $EventType -eq "Deleted") { "Warning" } else { "Information" }
    if ($EventType -eq "PermissionChanged") { $severity = "Warning" }

    $message = "File $EventType - $Path"
    if ($isSensitive) { $message += " [SENSITIVE]" }

    Write-AuditLog -Category "FileSystem" -Message $message -Severity $severity -AdditionalData $fileInfo
}

function Get-FileAccessEvents {
    <#
    .SYNOPSIS
        Retrieves file access events from Windows Security log
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [datetime]$Since = (Get-Date).AddMinutes(-5)
    )

    $config = Get-AuditConfig

    # File object access events
    $fileEventIds = @(4656, 4658, 4660, 4663, 4670)

    try {
        $filterXml = @"
<QueryList>
    <Query Id="0" Path="Security">
        <Select Path="Security">*[System[($(($fileEventIds | ForEach-Object { "EventID=$_" }) -join ' or ')) and TimeCreated[@SystemTime >= '$(($Since).ToUniversalTime().ToString("o"))']]]</Select>
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

            # Only log if in monitored paths
            $objectName = $eventData.ObjectName
            if (-not $objectName) { continue }

            $isMonitored = $false
            foreach ($pathPattern in $config.FileSystem.MonitoredPaths) {
                $checkPath = $pathPattern -replace '\*', '.*'
                if ($objectName -match [regex]::Escape($checkPath)) {
                    $isMonitored = $true
                    break
                }
            }

            if ($isMonitored) {
                $eventType = switch ($event.Id) {
                    4656 { "Accessed" }
                    4660 { "Deleted" }
                    4663 { "Accessed" }
                    4670 { "PermissionChanged" }
                    default { "Unknown" }
                }

                Write-FileAuditEvent -EventType $eventType -Path $objectName -AdditionalData @{
                    AccessMask = $eventData.AccessMask
                    ProcessName = $eventData.ProcessName
                    SubjectUserName = $eventData.SubjectUserName
                    EventId = $event.Id
                }
            }
        }
    } catch {
        if ($_.Exception.Message -notmatch "No events were found") {
            Write-AuditLog -Category "System" -Message "Error collecting file access events: $_" -Severity "Error"
        }
    }
}

function Enable-FileSystemAuditPolicy {
    <#
    .SYNOPSIS
        Enables Windows file system auditing policy for specified paths
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter()]
        [switch]$Success = $true,

        [Parameter()]
        [switch]$Failure = $true
    )

    if (-not (Test-IsAdministrator)) {
        Write-Warning "Administrator privileges required to set audit policy"
        return $false
    }

    try {
        $acl = Get-Acl -Path $Path -Audit -ErrorAction Stop

        # Create audit rule for Everyone
        $auditRule = New-Object System.Security.AccessControl.FileSystemAuditRule(
            "Everyone",
            "Read, Write, Delete, ChangePermissions",
            "ContainerInherit, ObjectInherit",
            "None",
            "Success, Failure"
        )

        $acl.AddAuditRule($auditRule)
        Set-Acl -Path $Path -AclObject $acl -ErrorAction Stop

        Write-AuditLog -Category "FileSystem" -Message "Audit policy enabled for: $Path" -Severity "Information"
        return $true

    } catch {
        Write-AuditLog -Category "System" -Message "Failed to set audit policy for $Path : $_" -Severity "Error"
        return $false
    }
}

function Get-FileSystemAuditSummary {
    <#
    .SYNOPSIS
        Generates a summary of file system activity
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [datetime]$StartTime = (Get-Date).AddDays(-1),

        [Parameter()]
        [datetime]$EndTime = (Get-Date)
    )

    $config = Get-AuditConfig
    $logPath = "$($config.LogStorage.BasePath)\FileSystem"

    $events = @()

    # Read log files in date range
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
                } catch {
                    # Skip malformed entries
                }
            }
        }
    }

    $summary = @{
        TimeRange = @{
            Start = $StartTime.ToString("o")
            End = $EndTime.ToString("o")
        }
        TotalEvents = $events.Count
        EventsByType = @{}
        SensitiveFileAccess = 0
        TopDirectories = @{}
        TopFileTypes = @{}
    }

    foreach ($event in $events) {
        # Count by event type
        $eventType = $event.EventType
        if (-not $summary.EventsByType.ContainsKey($eventType)) {
            $summary.EventsByType[$eventType] = 0
        }
        $summary.EventsByType[$eventType]++

        # Check for sensitive files
        if ($event.Message -match '\[SENSITIVE\]') {
            $summary.SensitiveFileAccess++
        }

        # Count by directory
        $dir = $event.Directory
        if ($dir) {
            if (-not $summary.TopDirectories.ContainsKey($dir)) {
                $summary.TopDirectories[$dir] = 0
            }
            $summary.TopDirectories[$dir]++
        }

        # Count by file type
        $ext = $event.Extension
        if ($ext) {
            if (-not $summary.TopFileTypes.ContainsKey($ext)) {
                $summary.TopFileTypes[$ext] = 0
            }
            $summary.TopFileTypes[$ext]++
        }
    }

    # Sort and limit top directories/types
    $summary.TopDirectories = $summary.TopDirectories.GetEnumerator() |
        Sort-Object Value -Descending |
        Select-Object -First 10 |
        ForEach-Object { @{$_.Key = $_.Value} }

    $summary.TopFileTypes = $summary.TopFileTypes.GetEnumerator() |
        Sort-Object Value -Descending |
        Select-Object -First 10 |
        ForEach-Object { @{$_.Key = $_.Value} }

    return [PSCustomObject]$summary
}

function Stop-FileSystemAuditing {
    <#
    .SYNOPSIS
        Stops file system auditing and cleans up watchers
    #>
    [CmdletBinding()]
    param()

    foreach ($path in @($script:FileWatchers.Keys)) {
        $watcher = $script:FileWatchers[$path]
        if ($watcher) {
            $watcher.EnableRaisingEvents = $false
            $watcher.Dispose()
        }
    }

    $script:FileWatchers.Clear()

    # Unregister all file watcher events
    Get-EventSubscriber | Where-Object { $_.SourceObject -is [System.IO.FileSystemWatcher] } | Unregister-Event

    Write-AuditLog -Category "FileSystem" -Message "File system auditing stopped" -Severity "Information"
}

# Export functions
Export-ModuleMember -Function @(
    'Start-FileSystemAuditing',
    'Initialize-FileWatchers',
    'Write-FileAuditEvent',
    'Get-FileAccessEvents',
    'Enable-FileSystemAuditPolicy',
    'Get-FileSystemAuditSummary',
    'Stop-FileSystemAuditing'
)
