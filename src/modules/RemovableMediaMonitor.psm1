#Requires -Version 5.1
<#
.SYNOPSIS
    Removable Media Monitor Module for DCSA Auditing Software

.DESCRIPTION
    Monitors USB and removable media device connections and file transfers.
    Critical for classified system security to track data exfiltration risks.
#>

# Import utilities
$modulePath = Split-Path -Parent $PSScriptRoot
Import-Module "$modulePath\utils\AuditUtilities.psm1" -Force

# Script-level variables
$script:KnownDevices = @{}
$script:DeviceEventSubscriptions = @()

function Start-RemovableMediaMonitoring {
    <#
    .SYNOPSIS
        Starts removable media monitoring using WMI events
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [switch]$AsJob
    )

    $config = Get-AuditConfig

    if (-not $config.RemovableMedia.Enabled) {
        Write-Warning "Removable media monitoring is disabled in configuration"
        return
    }

    Write-AuditLog -Category "RemovableMedia" -Message "Removable media monitoring started" -Severity "Information"

    # Capture current devices as baseline
    Get-CurrentRemovableDevices | ForEach-Object {
        $script:KnownDevices[$_.DeviceID] = $_
    }

    # Get poll interval from config (default 30 seconds)
    $pollInterval = 30
    if ($config.RemovableMedia.PollIntervalSeconds) {
        $pollInterval = $config.RemovableMedia.PollIntervalSeconds
    }

    if ($AsJob) {
        $job = Start-Job -ScriptBlock {
            param($ModulePath, $Config, $PollInterval)
            Import-Module "$ModulePath\utils\AuditUtilities.psm1" -Force
            Import-Module "$ModulePath\modules\RemovableMediaMonitor.psm1" -Force

            Register-DeviceEvents

            while ($true) {
                # Poll for device changes as backup to WMI events
                Check-DeviceChanges
                Start-Sleep -Seconds $PollInterval
            }
        } -ArgumentList $modulePath, $config, $pollInterval

        return $job
    } else {
        Register-DeviceEvents

        while ($true) {
            Check-DeviceChanges
            Start-Sleep -Seconds $pollInterval
        }
    }
}

function Register-DeviceEvents {
    <#
    .SYNOPSIS
        Registers WMI event subscriptions for USB STORAGE device changes only
        Note: Only monitors actual storage devices, not all USB devices
    #>
    [CmdletBinding()]
    param()

    try {
        # USB disk drive insertion (storage devices only)
        $diskInsertQuery = "SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_DiskDrive'"
        $diskInsertAction = {
            $disk = $Event.SourceEventArgs.NewEvent.TargetInstance
            # Only log USB storage devices
            if ($disk.InterfaceType -eq "USB") {
                Write-DeviceEvent -EventType "DiskConnected" -Device $disk
            }
        }
        $script:DeviceEventSubscriptions += Register-WmiEvent -Query $diskInsertQuery -Action $diskInsertAction -ErrorAction Stop

        # USB disk drive removal
        $diskRemoveQuery = "SELECT * FROM __InstanceDeletionEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_DiskDrive'"
        $diskRemoveAction = {
            $disk = $Event.SourceEventArgs.NewEvent.TargetInstance
            if ($disk.InterfaceType -eq "USB") {
                Write-DeviceEvent -EventType "DiskDisconnected" -Device $disk
            }
        }
        $script:DeviceEventSubscriptions += Register-WmiEvent -Query $diskRemoveQuery -Action $diskRemoveAction -ErrorAction Stop

        Write-AuditLog -Category "RemovableMedia" -Message "USB storage device monitoring registered" -Severity "Information"

    } catch {
        Write-AuditLog -Category "System" -Message "Failed to register device events: $_" -Severity "Error"
    }
}

function Write-DeviceEvent {
    <#
    .SYNOPSIS
        Writes a device event to the audit log
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet("Connected", "Disconnected", "DiskConnected", "DiskDisconnected", "FileTransfer")]
        [string]$EventType,

        [Parameter()]
        $Device,

        [Parameter()]
        [hashtable]$AdditionalData = @{}
    )

    $config = Get-AuditConfig

    $deviceInfo = @{
        EventType = $EventType
        Timestamp = Get-AuditTimestamp
    }

    if ($Device) {
        $deviceInfo["DeviceID"] = $Device.DeviceID
        $deviceName = $Device.Name
        if (-not $deviceName) { $deviceName = $Device.Caption }
        if (-not $deviceName) { $deviceName = "Unknown Device" }
        $deviceInfo["Name"] = $deviceName
        $deviceInfo["Description"] = $Device.Description
        $deviceInfo["Manufacturer"] = $Device.Manufacturer
        $deviceInfo["PNPDeviceID"] = $Device.PNPDeviceID

        # For disk drives, get additional info
        if ($Device.PSObject.Properties['Size']) {
            $deviceInfo["Size"] = $Device.Size
            $deviceInfo["SizeGB"] = [math]::Round($Device.Size / 1GB, 2)
        }
        if ($Device.PSObject.Properties['SerialNumber']) {
            $deviceInfo["SerialNumber"] = $Device.SerialNumber
        }
        if ($Device.PSObject.Properties['InterfaceType']) {
            $deviceInfo["InterfaceType"] = $Device.InterfaceType
        }
    }

    # Merge additional data
    foreach ($key in $AdditionalData.Keys) {
        $deviceInfo[$key] = $AdditionalData[$key]
    }

    # Check if device is authorized
    $isAuthorized = $true
    if ($config.RemovableMedia.AuthorizedDevices.Count -gt 0) {
        $isAuthorized = $deviceInfo.DeviceID -in $config.RemovableMedia.AuthorizedDevices -or
                        $deviceInfo.SerialNumber -in $config.RemovableMedia.AuthorizedDevices
    }

    $deviceInfo["IsAuthorized"] = $isAuthorized

    # Determine severity
    $severity = if (-not $isAuthorized -and $EventType -in @("Connected", "DiskConnected")) {
        "Critical"
    } elseif ($EventType -in @("Connected", "DiskConnected")) {
        "Warning"
    } else {
        "Information"
    }

    $message = "Removable Media $EventType - $($deviceInfo.Name)"
    if (-not $isAuthorized) {
        $message += " [UNAUTHORIZED]"
    }

    Write-AuditLog -Category "RemovableMedia" -Message $message -Severity $severity -AdditionalData $deviceInfo

    # Generate alert for unauthorized devices
    if (-not $isAuthorized -and $config.RemovableMedia.AlertOnUnauthorized -and $EventType -in @("Connected", "DiskConnected")) {
        Write-AuditLog -Category "Alert" -Message "ALERT: Unauthorized removable device detected - $($deviceInfo.Name) ($($deviceInfo.DeviceID))" -Severity "Critical" -AdditionalData @{
            AlertType = "UnauthorizedDevice"
            DeviceID = $deviceInfo.DeviceID
            DeviceName = $deviceInfo.Name
        }
    }
}

function Get-CurrentRemovableDevices {
    <#
    .SYNOPSIS
        Gets all currently connected USB STORAGE devices only
        Filters out non-storage USB devices (keyboards, mice, etc.)
    #>
    [CmdletBinding()]
    param()

    $config = Get-AuditConfig
    $devices = @()

    # Get minimum size filter from config (default 1MB)
    $minSizeBytes = 1MB
    if ($config.RemovableMedia.MinimumDeviceSizeMB) {
        $minSizeBytes = $config.RemovableMedia.MinimumDeviceSizeMB * 1MB
    }

    # Get USB storage devices only (actual disk drives)
    try {
        $usbDisks = Get-CimInstance -ClassName Win32_DiskDrive -ErrorAction SilentlyContinue |
            Where-Object {
                $_.InterfaceType -eq "USB" -and
                $_.MediaType -and
                # Filter out card readers without media and devices below minimum size
                $_.Size -ge $minSizeBytes
            }

        foreach ($disk in $usbDisks) {
            $devices += [PSCustomObject]@{
                DeviceID = $disk.DeviceID
                Name = $disk.Caption
                Type = "USB Storage"
                Size = $disk.Size
                SizeGB = [math]::Round($disk.Size / 1GB, 2)
                SerialNumber = $disk.SerialNumber
                InterfaceType = $disk.InterfaceType
                Manufacturer = $disk.Manufacturer
                Model = $disk.Model
                MediaType = $disk.MediaType
            }
        }
    } catch {
        Write-AuditLog -Category "System" -Message "Error enumerating USB disks: $_" -Severity "Warning"
    }

    # Get removable logical drives with media present
    try {
        $removableDrives = Get-CimInstance -ClassName Win32_LogicalDisk -ErrorAction SilentlyContinue |
            Where-Object {
                $_.DriveType -eq 2 -and       # DriveType 2 = Removable
                $_.Size -ge $minSizeBytes     # Has media inserted and meets minimum size
            }

        foreach ($drive in $removableDrives) {
            # Check if this drive letter is already associated with a USB disk we found
            $alreadyListed = $false
            foreach ($usbDisk in $devices) {
                if ($usbDisk.DeviceID -and $drive.DeviceID) {
                    # Skip duplicate entries
                    $alreadyListed = $true
                    break
                }
            }

            if (-not $alreadyListed) {
                $devices += [PSCustomObject]@{
                    DeviceID = $drive.DeviceID
                    Name = "$($drive.DeviceID) ($($drive.VolumeName))"
                    Type = "Removable Drive"
                    Size = $drive.Size
                    SizeGB = [math]::Round($drive.Size / 1GB, 2)
                    FreeSpace = $drive.FreeSpace
                    FileSystem = $drive.FileSystem
                    VolumeSerialNumber = $drive.VolumeSerialNumber
                }
            }
        }
    } catch {
        Write-AuditLog -Category "System" -Message "Error enumerating removable drives: $_" -Severity "Warning"
    }

    return $devices
}

function Check-DeviceChanges {
    <#
    .SYNOPSIS
        Checks for device changes by comparing current devices to known devices
    #>
    [CmdletBinding()]
    param()

    $currentDevices = Get-CurrentRemovableDevices

    # Check for new devices
    foreach ($device in $currentDevices) {
        if (-not $script:KnownDevices.ContainsKey($device.DeviceID)) {
            Write-DeviceEvent -EventType "Connected" -Device $device
            $script:KnownDevices[$device.DeviceID] = $device
        }
    }

    # Check for removed devices
    $currentDeviceIds = $currentDevices | Select-Object -ExpandProperty DeviceID
    $removedDevices = $script:KnownDevices.Keys | Where-Object { $_ -notin $currentDeviceIds }

    foreach ($deviceId in $removedDevices) {
        $device = $script:KnownDevices[$deviceId]
        Write-DeviceEvent -EventType "Disconnected" -Device $device
        $script:KnownDevices.Remove($deviceId)
    }
}

function Get-RemovableMediaEvents {
    <#
    .SYNOPSIS
        Gets removable storage events from Windows Security Event Log
        Focuses on event 6416 (external device recognized) for DCSA compliance
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [datetime]$StartTime = (Get-Date).AddDays(-1),

        [Parameter()]
        [datetime]$EndTime = (Get-Date)
    )

    $events = @()

    # Security log - Event ID 6416 = New external device recognized
    # This is the primary event for DCSA removable media auditing
    try {
        $securityEvents = Get-WinEvent -FilterHashtable @{
            LogName = 'Security'
            Id = 6416
            StartTime = $StartTime
            EndTime = $EndTime
        } -ErrorAction SilentlyContinue

        foreach ($event in $securityEvents) {
            $eventXml = [xml]$event.ToXml()
            $deviceId = ($eventXml.Event.EventData.Data | Where-Object { $_.Name -eq 'DeviceId' }).'#text'
            $deviceDesc = ($eventXml.Event.EventData.Data | Where-Object { $_.Name -eq 'DeviceDescription' }).'#text'
            $className = ($eventXml.Event.EventData.Data | Where-Object { $_.Name -eq 'ClassName' }).'#text'

            # Only include storage-related device classes
            $storageClasses = @("DiskDrive", "CDROM", "FloppyDisk", "USB", "USBSTOR", "WPD")
            $isStorage = $false
            foreach ($sc in $storageClasses) {
                if ($className -match $sc -or $deviceId -match $sc -or $deviceDesc -match "storage|disk|drive|mass storage") {
                    $isStorage = $true
                    break
                }
            }

            if ($isStorage) {
                $events += [PSCustomObject]@{
                    TimeCreated = $event.TimeCreated
                    EventId = $event.Id
                    DeviceId = $deviceId
                    DeviceDescription = $deviceDesc
                    ClassName = $className
                    Source = "Security"
                }
            }
        }
    } catch { }

    return $events | Sort-Object TimeCreated -Descending
}

function Get-RemovableMediaSummary {
    <#
    .SYNOPSIS
        Generates a summary of removable media activity
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [datetime]$StartTime = (Get-Date).AddDays(-1),

        [Parameter()]
        [datetime]$EndTime = (Get-Date)
    )

    $config = Get-AuditConfig
    $logPath = "$($config.LogStorage.BasePath)\RemovableMedia"

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
        DeviceConnections = ($events | Where-Object { $_.EventType -in @("Connected", "DiskConnected") }).Count
        DeviceDisconnections = ($events | Where-Object { $_.EventType -in @("Disconnected", "DiskDisconnected") }).Count
        UnauthorizedDevices = ($events | Where-Object { $_.IsAuthorized -eq $false }).Count
        UniqueDevices = ($events | Select-Object -ExpandProperty DeviceID -Unique -ErrorAction SilentlyContinue).Count
        CurrentlyConnected = (Get-CurrentRemovableDevices).Count
        DeviceList = @()
    }

    # List of unique devices with their activity
    $events | Group-Object DeviceID | ForEach-Object {
        $deviceEvents = $_.Group
        $summary.DeviceList += @{
            DeviceID = $_.Name
            DeviceName = ($deviceEvents | Select-Object -First 1).Name
            EventCount = $_.Count
            FirstSeen = ($deviceEvents | Sort-Object Timestamp | Select-Object -First 1).Timestamp
            LastSeen = ($deviceEvents | Sort-Object Timestamp -Descending | Select-Object -First 1).Timestamp
            IsAuthorized = ($deviceEvents | Select-Object -First 1).IsAuthorized
        }
    }

    return [PSCustomObject]$summary
}

function Stop-RemovableMediaMonitoring {
    <#
    .SYNOPSIS
        Stops removable media monitoring and cleans up
    #>
    [CmdletBinding()]
    param()

    foreach ($subscription in $script:DeviceEventSubscriptions) {
        Unregister-Event -SubscriptionId $subscription.Id -ErrorAction SilentlyContinue
    }

    $script:DeviceEventSubscriptions.Clear()
    $script:KnownDevices.Clear()

    Write-AuditLog -Category "RemovableMedia" -Message "Removable media monitoring stopped" -Severity "Information"
}

# Export functions
Export-ModuleMember -Function @(
    'Start-RemovableMediaMonitoring',
    'Register-DeviceEvents',
    'Write-DeviceEvent',
    'Get-CurrentRemovableDevices',
    'Check-DeviceChanges',
    'Get-RemovableMediaEvents',
    'Get-RemovableMediaSummary',
    'Stop-RemovableMediaMonitoring'
)
