#Requires -Version 5.1
<#
.SYNOPSIS
    Utility functions for the DCSA Auditing Software

.DESCRIPTION
    This module provides common utility functions used across all auditing modules
    including logging, hashing, configuration management, and timestamp handling.
#>

# Script-level variables
$script:Config = $null
$script:LogPath = $null

function Initialize-AuditEnvironment {
    <#
    .SYNOPSIS
        Initializes the audit environment and loads configuration
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$ConfigPath = "$PSScriptRoot\..\config\AuditConfig.psd1"
    )

    try {
        # Load configuration
        if (Test-Path $ConfigPath) {
            $script:Config = Import-PowerShellDataFile -Path $ConfigPath
        } else {
            throw "Configuration file not found: $ConfigPath"
        }

        # Create log directory structure
        $script:LogPath = $script:Config.LogStorage.BasePath
        $directories = @(
            $script:LogPath,
            "$($script:LogPath)\Security",
            "$($script:LogPath)\UserActivity",
            "$($script:LogPath)\FileSystem",
            "$($script:LogPath)\RemovableMedia",
            "$($script:LogPath)\Process",
            "$($script:LogPath)\Baseline",
            "$($script:LogPath)\Reports",
            "$($script:LogPath)\Integrity"
        )

        foreach ($dir in $directories) {
            if (-not (Test-Path $dir)) {
                New-Item -Path $dir -ItemType Directory -Force | Out-Null
                # Set restrictive ACL on audit directories
                Set-AuditDirectoryPermissions -Path $dir
            }
        }

        # Create custom event log if it doesn't exist
        $eventLogName = $script:Config.Alerting.EventLogName
        if (-not [System.Diagnostics.EventLog]::SourceExists($eventLogName)) {
            try {
                New-EventLog -LogName $eventLogName -Source $eventLogName -ErrorAction Stop
            } catch {
                Write-Warning "Could not create event log: $_"
            }
        }

        Write-AuditLog -Category "System" -Message "Audit environment initialized successfully" -Severity "Information"
        return $true

    } catch {
        Write-Error "Failed to initialize audit environment: $_"
        return $false
    }
}

function Get-AuditConfig {
    <#
    .SYNOPSIS
        Returns the current audit configuration
    #>
    [CmdletBinding()]
    param()

    if ($null -eq $script:Config) {
        Initialize-AuditEnvironment | Out-Null
    }
    return $script:Config
}

function Get-AuditTimestamp {
    <#
    .SYNOPSIS
        Returns a properly formatted timestamp for audit logging
    #>
    [CmdletBinding()]
    param()

    $config = Get-AuditConfig
    if ($config.General.UseUTCTime) {
        return (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    } else {
        return (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss.fffzzz")
    }
}

function Write-AuditLog {
    <#
    .SYNOPSIS
        Writes an entry to the audit log with integrity protection
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet("Security", "UserActivity", "FileSystem", "RemovableMedia", "Process", "Baseline", "System", "Alert")]
        [string]$Category,

        [Parameter(Mandatory)]
        [string]$Message,

        [Parameter()]
        [ValidateSet("Information", "Warning", "Error", "Critical")]
        [string]$Severity = "Information",

        [Parameter()]
        [hashtable]$AdditionalData = @{}
    )

    $config = Get-AuditConfig
    $timestamp = Get-AuditTimestamp

    # Build log entry
    $logEntry = [ordered]@{
        Timestamp = $timestamp
        Category = $Category
        Severity = $Severity
        Message = $Message
        ComputerName = $env:COMPUTERNAME
        UserName = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    }

    # Add any additional data
    foreach ($key in $AdditionalData.Keys) {
        $logEntry[$key] = $AdditionalData[$key]
    }

    # Convert to JSON for structured logging
    $jsonEntry = $logEntry | ConvertTo-Json -Compress

    # Calculate hash for integrity
    $hash = Get-StringHash -InputString $jsonEntry -Algorithm $config.LogStorage.HashAlgorithm

    # Create final log line with hash
    $logLine = "$jsonEntry|HASH:$hash"

    # Determine log file path
    $dateStr = (Get-Date).ToString("yyyy-MM-dd")
    $logFile = "$($config.LogStorage.BasePath)\$Category\$Category-$dateStr.log"

    # Write to log file (thread-safe)
    $mutex = New-Object System.Threading.Mutex($false, "Global\AuditLog_$Category")
    try {
        $mutex.WaitOne() | Out-Null
        Add-Content -Path $logFile -Value $logLine -Encoding UTF8
    } finally {
        $mutex.ReleaseMutex()
    }

    # Write to Event Log if it's an alert
    if ($Category -eq "Alert" -and $config.Alerting.WriteToEventLog) {
        $eventType = switch ($Severity) {
            "Information" { "Information" }
            "Warning" { "Warning" }
            "Error" { "Error" }
            "Critical" { "Error" }
        }
        try {
            Write-EventLog -LogName $config.Alerting.EventLogName -Source $config.Alerting.EventLogName `
                -EventId 1000 -EntryType $eventType -Message $Message
        } catch {
            # Silently continue if event log write fails
        }
    }

    # Verbose output if enabled
    if ($config.General.VerboseLogging) {
        Write-Verbose "[$timestamp] [$Category] [$Severity] $Message"
    }
}

function Get-StringHash {
    <#
    .SYNOPSIS
        Calculates a cryptographic hash of a string
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$InputString,

        [Parameter()]
        [ValidateSet("SHA256", "SHA384", "SHA512")]
        [string]$Algorithm = "SHA256"
    )

    $bytes = [System.Text.Encoding]::UTF8.GetBytes($InputString)
    $hashAlgorithm = [System.Security.Cryptography.HashAlgorithm]::Create($Algorithm)
    $hashBytes = $hashAlgorithm.ComputeHash($bytes)
    return [BitConverter]::ToString($hashBytes) -replace '-', ''
}

function Get-FileHash256 {
    <#
    .SYNOPSIS
        Calculates SHA256 hash of a file
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$FilePath
    )

    if (Test-Path $FilePath) {
        return (Get-FileHash -Path $FilePath -Algorithm SHA256).Hash
    }
    return $null
}

function Set-AuditDirectoryPermissions {
    <#
    .SYNOPSIS
        Sets restrictive permissions on audit directories
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    try {
        $acl = Get-Acl -Path $Path

        # Disable inheritance
        $acl.SetAccessRuleProtection($true, $false)

        # Clear existing rules
        $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) } | Out-Null

        # Add SYSTEM - Full Control
        $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            "NT AUTHORITY\SYSTEM",
            "FullControl",
            "ContainerInherit,ObjectInherit",
            "None",
            "Allow"
        )
        $acl.AddAccessRule($systemRule)

        # Add Administrators - Full Control
        $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            "BUILTIN\Administrators",
            "FullControl",
            "ContainerInherit,ObjectInherit",
            "None",
            "Allow"
        )
        $acl.AddAccessRule($adminRule)

        Set-Acl -Path $Path -AclObject $acl
    } catch {
        Write-Warning "Could not set permissions on $Path : $_"
    }
}

function Test-IsAdministrator {
    <#
    .SYNOPSIS
        Checks if the current user has administrator privileges
    #>
    [CmdletBinding()]
    param()

    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function ConvertTo-AuditReport {
    <#
    .SYNOPSIS
        Converts audit data to various report formats
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [array]$Data,

        [Parameter(Mandatory)]
        [string]$Title,

        [Parameter()]
        [ValidateSet("HTML", "CSV", "JSON")]
        [string]$Format = "HTML",

        [Parameter(Mandatory)]
        [string]$OutputPath
    )

    $config = Get-AuditConfig
    $timestamp = Get-AuditTimestamp

    switch ($Format) {
        "HTML" {
            $htmlHeader = @"
<!DOCTYPE html>
<html>
<head>
    <title>$Title</title>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .header { background-color: #1a365d; color: white; padding: 20px; margin-bottom: 20px; }
        .header h1 { margin: 0; }
        .classification { background-color: #c53030; color: white; padding: 5px 10px; text-align: center; font-weight: bold; }
        table { border-collapse: collapse; width: 100%; background-color: white; box-shadow: 0 1px 3px rgba(0,0,0,0.12); }
        th { background-color: #2c5282; color: white; padding: 12px; text-align: left; }
        td { padding: 10px; border-bottom: 1px solid #e2e8f0; }
        tr:hover { background-color: #f7fafc; }
        .severity-Critical { color: #c53030; font-weight: bold; }
        .severity-Error { color: #dd6b20; }
        .severity-Warning { color: #d69e2e; }
        .severity-Information { color: #2b6cb0; }
        .footer { margin-top: 20px; font-size: 12px; color: #718096; }
    </style>
</head>
<body>
    <div class="classification">$($config.General.ClassificationLevel)</div>
    <div class="header">
        <h1>$Title</h1>
        <p>Generated: $timestamp | System: $env:COMPUTERNAME | Organization: $($config.General.OrganizationName)</p>
    </div>
"@
            $htmlFooter = @"
    <div class="footer">
        <p>DCSA Auditor v$($config.General.Version) | This report contains security-sensitive information</p>
    </div>
    <div class="classification">$($config.General.ClassificationLevel)</div>
</body>
</html>
"@
            $htmlTable = $Data | ConvertTo-Html -Fragment
            $htmlContent = $htmlHeader + $htmlTable + $htmlFooter
            $htmlContent | Out-File -FilePath $OutputPath -Encoding UTF8
        }

        "CSV" {
            $Data | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
        }

        "JSON" {
            $Data | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputPath -Encoding UTF8
        }
    }
}

function Invoke-LogRotation {
    <#
    .SYNOPSIS
        Rotates and archives old audit logs
    #>
    [CmdletBinding()]
    param()

    $config = Get-AuditConfig
    $basePath = $config.LogStorage.BasePath
    $retentionDays = $config.LogStorage.RetentionDays
    $maxSizeMB = $config.LogStorage.MaxLogSizeMB
    $compress = $config.LogStorage.CompressArchivedLogs

    $cutoffDate = (Get-Date).AddDays(-$retentionDays)

    Get-ChildItem -Path $basePath -Recurse -Filter "*.log" | ForEach-Object {
        # Check if file is older than retention period
        if ($_.LastWriteTime -lt $cutoffDate) {
            if ($compress) {
                # Compress before deleting
                $archivePath = "$basePath\Archive"
                if (-not (Test-Path $archivePath)) {
                    New-Item -Path $archivePath -ItemType Directory -Force | Out-Null
                }
                $zipPath = "$archivePath\$($_.BaseName).zip"
                Compress-Archive -Path $_.FullName -DestinationPath $zipPath -Force
            }
            Remove-Item $_.FullName -Force
            Write-AuditLog -Category "System" -Message "Archived and removed old log: $($_.Name)" -Severity "Information"
        }

        # Check file size and rotate if necessary
        if (($_.Length / 1MB) -gt $maxSizeMB) {
            $newName = "$($_.DirectoryName)\$($_.BaseName)_$(Get-Date -Format 'yyyyMMdd_HHmmss')$($_.Extension)"
            Rename-Item -Path $_.FullName -NewName $newName
            Write-AuditLog -Category "System" -Message "Rotated large log file: $($_.Name)" -Severity "Information"
        }
    }
}

function Verify-LogIntegrity {
    <#
    .SYNOPSIS
        Verifies the integrity of audit log files
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$LogPath,

        [Parameter()]
        [switch]$Detailed
    )

    $config = Get-AuditConfig
    if (-not $LogPath) {
        $LogPath = $config.LogStorage.BasePath
    }

    $results = @()
    $logFiles = Get-ChildItem -Path $LogPath -Recurse -Filter "*.log" -ErrorAction SilentlyContinue

    foreach ($file in $logFiles) {
        $fileResult = @{
            FilePath = $file.FullName
            TotalLines = 0
            ValidLines = 0
            InvalidLines = 0
            TamperedLines = @()
        }

        $lines = Get-Content -Path $file.FullName -ErrorAction SilentlyContinue

        foreach ($line in $lines) {
            $fileResult.TotalLines++

            if ($line -match '^(.+)\|HASH:([A-F0-9]+)$') {
                $jsonPart = $Matches[1]
                $recordedHash = $Matches[2]
                $calculatedHash = Get-StringHash -InputString $jsonPart -Algorithm $config.LogStorage.HashAlgorithm

                if ($calculatedHash -eq $recordedHash) {
                    $fileResult.ValidLines++
                } else {
                    $fileResult.InvalidLines++
                    if ($Detailed) {
                        $fileResult.TamperedLines += @{
                            LineNumber = $fileResult.TotalLines
                            Content = $jsonPart
                        }
                    }
                }
            } else {
                $fileResult.InvalidLines++
            }
        }

        $fileResult.IntegrityStatus = if ($fileResult.InvalidLines -eq 0) { "VALID" } else { "COMPROMISED" }
        $results += [PSCustomObject]$fileResult
    }

    return $results
}

# Export functions
Export-ModuleMember -Function @(
    'Initialize-AuditEnvironment',
    'Get-AuditConfig',
    'Get-AuditTimestamp',
    'Write-AuditLog',
    'Get-StringHash',
    'Get-FileHash256',
    'Set-AuditDirectoryPermissions',
    'Test-IsAdministrator',
    'ConvertTo-AuditReport',
    'Invoke-LogRotation',
    'Verify-LogIntegrity'
)
