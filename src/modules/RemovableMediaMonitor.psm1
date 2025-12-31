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

    if ($AsJob) {
        $job = Start-Job -ScriptBlock {
            param($ModulePath, $Config)
            Import-Module "$ModulePath\utils\AuditUtilities.psm1" -Force
            Import-Module "$ModulePath\modules\RemovableMediaMonitor.psm1" -Force

            Register-DeviceEvents

            while ($true) {
                # Poll for device changes as backup to WMI events
                Check-DeviceChanges
                Start-Sleep -Seconds 10
            }
        } -ArgumentList $modulePath, $config

        return $job
    } else {
        Register-DeviceEvents

        while ($true) {
            Check-DeviceChanges
            Start-Sleep -Seconds 10
        }
    }
}

function Register-DeviceEvents {
    <#
    .SYNOPSIS
        Registers WMI event subscriptions for device changes
    #>
    [CmdletBinding()]
    param()

    try {
        # USB device insertion
        $insertQuery = "SELECT * FROM __InstanceCreationEvent WITHIN 2 WHERE TargetInstance ISA 'Win32_USBHub'"
        $insertAction = {
            $device = $Event.SourceEventArgs.NewEvent.TargetInstance
            Write-DeviceEvent -EventType "Connected" -Device $device
        }
        $script:DeviceEventSubscriptions += Register-WmiEvent -Query $insertQuery -Action $insertAction -ErrorAction Stop

        # USB device removal
        $removeQuery = "SELECT * FROM __InstanceDeletionEvent WITHIN 2 WHERE TargetInstance ISA 'Win32_USBHub'"
        $removeAction = {
            $device = $Event.SourceEventArgs.NewEvent.TargetInstance
            Write-DeviceEvent -EventType "Disconnected" -Device $device
        }
        $script:DeviceEventSubscriptions += Register-WmiEvent -Query $removeQuery -Action $removeAction -ErrorAction Stop

        # Disk drive events
        $diskInsertQuery = "SELECT * FROM __InstanceCreationEvent WITHIN 2 WHERE TargetInstance ISA 'Win32_DiskDrive'"
        $diskInsertAction = {
            $disk = $Event.SourceEventArgs.NewEvent.TargetInstance
            if ($disk.InterfaceType -eq "USB") {
                Write-DeviceEvent -EventType "DiskConnected" -Device $disk
            }
        }
        $script:DeviceEventSubscriptions += Register-WmiEvent -Query $diskInsertQuery -Action $diskInsertAction -ErrorAction Stop

        Write-AuditLog -Category "RemovableMedia" -Message "Device event monitoring registered" -Severity "Information"

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
        $deviceInfo["Name"] = $Device.Name ?? $Device.Caption ?? "Unknown Device"
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
        Gets all currently connected removable devices
    #>
    [CmdletBinding()]
    param()

    $devices = @()

    # Get USB storage devices
    try {
        $usbDisks = Get-CimInstance -ClassName Win32_DiskDrive -ErrorAction SilentlyContinue |
            Where-Object { $_.InterfaceType -eq "USB" }

        foreach ($disk in $usbDisks) {
            $devices += [PSCustomObject]@{
                DeviceID = $disk.DeviceID
                Name = $disk.Caption
                Type = "USB Disk"
                Size = $disk.Size
                SizeGB = [math]::Round($disk.Size / 1GB, 2)
                SerialNumber = $disk.SerialNumber
                InterfaceType = $disk.InterfaceType
                Manufacturer = $disk.Manufacturer
                Model = $disk.Model
            }
        }
    } catch {
        Write-AuditLog -Category "System" -Message "Error enumerating USB disks: $_" -Severity "Warning"
    }

    # Get logical drives that are removable
    try {
        $removableDrives = Get-CimInstance -ClassName Win32_LogicalDisk -ErrorAction SilentlyContinue |
            Where-Object { $_.DriveType -eq 2 }  # DriveType 2 = Removable

        foreach ($drive in $removableDrives) {
            $devices += [PSCustomObject]@{
                DeviceID = $drive.DeviceID
                Name = "$($drive.DeviceID) ($($drive.VolumeName))"
                Type = "Removable Drive"
                Size = $drive.Size
                SizeGB = if ($drive.Size) { [math]::Round($drive.Size / 1GB, 2) } else { 0 }
                FreeSpace = $drive.FreeSpace
                FileSystem = $drive.FileSystem
                VolumeSerialNumber = $drive.VolumeSerialNumber
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
        Gets removable media events from Windows Event Log
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [datetime]$StartTime = (Get-Date).AddDays(-1),

        [Parameter()]
        [datetime]$EndTime = (Get-Date)
    )

    $events = @()

    # Microsoft-Windows-DriverFrameworks-UserMode operational log
    # Event ID 2003 = Device connected
    # Event ID 2102 = Device removed
    try {
        $driverEvents = Get-WinEvent -FilterHashtable @{
            LogName = 'Microsoft-Windows-DriverFrameworks-UserMode/Operational'
            StartTime = $StartTime
            EndTime = $EndTime
        } -ErrorAction SilentlyContinue

        foreach ($event in $driverEvents) {
            $events += [PSCustomObject]@{
                TimeCreated = $event.TimeCreated
                EventId = $event.Id
                Message = $event.Message
                Source = "DriverFrameworks"
            }
        }
    } catch { }

    # Security log - Removable storage events
    # Event ID 6416 = New external device recognized
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

            $events += [PSCustomObject]@{
                TimeCreated = $event.TimeCreated
                EventId = $event.Id
                DeviceId = $deviceId
                DeviceDescription = $deviceDesc
                Source = "Security"
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
