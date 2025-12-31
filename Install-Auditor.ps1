#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    DCSA Security Auditor Installer

.DESCRIPTION
    Installs and configures the DCSA Security Auditor for Windows 11.
    This script sets up audit policies, creates required directories,
    configures the system for comprehensive security auditing, and
    optionally registers the auditor as a scheduled task.

.PARAMETER InstallPath
    Installation directory. Default is C:\Program Files\DCSA-Auditor

.PARAMETER LogPath
    Audit log storage directory. Default is C:\AuditLogs

.PARAMETER RegisterScheduledTask
    Register the auditor to run automatically at system startup

.PARAMETER ConfigureAuditPolicy
    Configure Windows audit policies for comprehensive logging

.EXAMPLE
    .\Install-Auditor.ps1 -RegisterScheduledTask -ConfigureAuditPolicy
    Full installation with scheduled task and audit policy configuration
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$InstallPath = "C:\Program Files\DCSA-Auditor",

    [Parameter()]
    [string]$LogPath = "C:\AuditLogs",

    [Parameter()]
    [switch]$RegisterScheduledTask,

    [Parameter()]
    [switch]$ConfigureAuditPolicy
)

$ErrorActionPreference = "Stop"

# Banner
function Show-Banner {
    $banner = @"

    ╔═══════════════════════════════════════════════════════════════╗
    ║                                                               ║
    ║     DCSA SECURITY AUDITOR INSTALLER                          ║
    ║     For Windows 11 Standalone Systems                         ║
    ║                                                               ║
    ╚═══════════════════════════════════════════════════════════════╝

"@
    Write-Host $banner -ForegroundColor Cyan
}

function Test-Prerequisites {
    Write-Host "`n[*] Checking prerequisites..." -ForegroundColor Yellow

    # Check Windows version
    $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
    $osBuild = [int]$osInfo.BuildNumber

    if ($osBuild -lt 22000) {
        Write-Host "    [!] Warning: This system is not Windows 11 (Build: $osBuild)" -ForegroundColor Yellow
        Write-Host "    [!] The auditor is designed for Windows 11 but may work on Windows 10" -ForegroundColor Yellow
    } else {
        Write-Host "    [+] Windows 11 detected (Build: $osBuild)" -ForegroundColor Green
    }

    # Check PowerShell version
    $psVersion = $PSVersionTable.PSVersion
    if ($psVersion.Major -lt 5) {
        Write-Host "    [!] PowerShell 5.1 or later required. Current: $psVersion" -ForegroundColor Red
        return $false
    }
    Write-Host "    [+] PowerShell version: $psVersion" -ForegroundColor Green

    # Check admin privileges
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Host "    [!] Administrator privileges required" -ForegroundColor Red
        return $false
    }
    Write-Host "    [+] Running with Administrator privileges" -ForegroundColor Green

    # Check disk space (minimum 1GB recommended)
    $drive = (Get-Item $LogPath.Substring(0,2) -ErrorAction SilentlyContinue) ?? (Get-Item "C:")
    $freeSpace = (Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='$($drive.Name)'").FreeSpace
    $freeSpaceGB = [math]::Round($freeSpace / 1GB, 2)

    if ($freeSpaceGB -lt 1) {
        Write-Host "    [!] Low disk space: $freeSpaceGB GB free. Minimum 1GB recommended." -ForegroundColor Yellow
    } else {
        Write-Host "    [+] Disk space: $freeSpaceGB GB free" -ForegroundColor Green
    }

    return $true
}

function Install-AuditorFiles {
    Write-Host "`n[*] Installing auditor files..." -ForegroundColor Yellow

    # Create installation directory
    if (-not (Test-Path $InstallPath)) {
        New-Item -Path $InstallPath -ItemType Directory -Force | Out-Null
        Write-Host "    [+] Created installation directory: $InstallPath" -ForegroundColor Green
    }

    # Copy files
    $sourceDir = $PSScriptRoot
    $filesToCopy = @(
        "Start-Auditor.ps1",
        "README.md"
    )

    foreach ($file in $filesToCopy) {
        $sourcePath = Join-Path $sourceDir $file
        if (Test-Path $sourcePath) {
            Copy-Item -Path $sourcePath -Destination $InstallPath -Force
            Write-Host "    [+] Copied: $file" -ForegroundColor Green
        }
    }

    # Copy directories
    $dirsToCopy = @("src", "scripts")
    foreach ($dir in $dirsToCopy) {
        $sourcePath = Join-Path $sourceDir $dir
        if (Test-Path $sourcePath) {
            Copy-Item -Path $sourcePath -Destination $InstallPath -Recurse -Force
            Write-Host "    [+] Copied directory: $dir" -ForegroundColor Green
        }
    }

    # Create additional directories
    $additionalDirs = @("logs", "reports", "baselines")
    foreach ($dir in $additionalDirs) {
        $dirPath = Join-Path $InstallPath $dir
        if (-not (Test-Path $dirPath)) {
            New-Item -Path $dirPath -ItemType Directory -Force | Out-Null
        }
    }

    # Set permissions on installation directory
    Write-Host "    [*] Setting directory permissions..." -ForegroundColor Cyan
    $acl = Get-Acl -Path $InstallPath
    $acl.SetAccessRuleProtection($true, $false)

    # SYSTEM - Full Control
    $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        "NT AUTHORITY\SYSTEM", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"
    )
    $acl.AddAccessRule($systemRule)

    # Administrators - Full Control
    $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        "BUILTIN\Administrators", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"
    )
    $acl.AddAccessRule($adminRule)

    Set-Acl -Path $InstallPath -AclObject $acl
    Write-Host "    [+] Permissions set" -ForegroundColor Green

    return $true
}

function Initialize-LogDirectory {
    Write-Host "`n[*] Initializing log directory..." -ForegroundColor Yellow

    # Create log directory structure
    $logDirs = @(
        $LogPath,
        "$LogPath\Security",
        "$LogPath\UserActivity",
        "$LogPath\FileSystem",
        "$LogPath\RemovableMedia",
        "$LogPath\Process",
        "$LogPath\Baseline",
        "$LogPath\Alert",
        "$LogPath\Reports",
        "$LogPath\Integrity"
    )

    foreach ($dir in $logDirs) {
        if (-not (Test-Path $dir)) {
            New-Item -Path $dir -ItemType Directory -Force | Out-Null
            Write-Host "    [+] Created: $dir" -ForegroundColor Green
        }
    }

    # Set restrictive permissions on log directory
    Write-Host "    [*] Setting log directory permissions..." -ForegroundColor Cyan
    $acl = Get-Acl -Path $LogPath
    $acl.SetAccessRuleProtection($true, $false)

    # SYSTEM - Full Control
    $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        "NT AUTHORITY\SYSTEM", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"
    )
    $acl.AddAccessRule($systemRule)

    # Administrators - Full Control
    $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        "BUILTIN\Administrators", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"
    )
    $acl.AddAccessRule($adminRule)

    Set-Acl -Path $LogPath -AclObject $acl
    Write-Host "    [+] Log directory permissions set" -ForegroundColor Green

    # Update configuration with actual log path
    $configPath = "$InstallPath\src\config\AuditConfig.psd1"
    if (Test-Path $configPath) {
        $configContent = Get-Content -Path $configPath -Raw
        $configContent = $configContent -replace 'BasePath = "C:\\AuditLogs"', "BasePath = `"$($LogPath -replace '\\', '\\')`""
        $configContent | Set-Content -Path $configPath -Encoding UTF8
        Write-Host "    [+] Configuration updated with log path" -ForegroundColor Green
    }

    return $true
}

function Set-WindowsAuditPolicy {
    Write-Host "`n[*] Configuring Windows audit policies..." -ForegroundColor Yellow

    if (-not $ConfigureAuditPolicy) {
        Write-Host "    [-] Skipping audit policy configuration (use -ConfigureAuditPolicy to enable)" -ForegroundColor Yellow
        return $true
    }

    # Audit policies to enable (Success and Failure)
    $auditCategories = @(
        @{ Subcategory = "Logon"; Success = "enable"; Failure = "enable" },
        @{ Subcategory = "Logoff"; Success = "enable"; Failure = "enable" },
        @{ Subcategory = "Account Lockout"; Success = "enable"; Failure = "enable" },
        @{ Subcategory = "Special Logon"; Success = "enable"; Failure = "enable" },
        @{ Subcategory = "Other Logon/Logoff Events"; Success = "enable"; Failure = "enable" },
        @{ Subcategory = "User Account Management"; Success = "enable"; Failure = "enable" },
        @{ Subcategory = "Security Group Management"; Success = "enable"; Failure = "enable" },
        @{ Subcategory = "Computer Account Management"; Success = "enable"; Failure = "enable" },
        @{ Subcategory = "Process Creation"; Success = "enable"; Failure = "enable" },
        @{ Subcategory = "Process Termination"; Success = "enable"; Failure = "enable" },
        @{ Subcategory = "File System"; Success = "enable"; Failure = "enable" },
        @{ Subcategory = "Registry"; Success = "enable"; Failure = "enable" },
        @{ Subcategory = "Removable Storage"; Success = "enable"; Failure = "enable" },
        @{ Subcategory = "Audit Policy Change"; Success = "enable"; Failure = "enable" },
        @{ Subcategory = "Authentication Policy Change"; Success = "enable"; Failure = "enable" },
        @{ Subcategory = "Sensitive Privilege Use"; Success = "enable"; Failure = "enable" },
        @{ Subcategory = "System Integrity"; Success = "enable"; Failure = "enable" },
        @{ Subcategory = "Security State Change"; Success = "enable"; Failure = "enable" },
        @{ Subcategory = "Security System Extension"; Success = "enable"; Failure = "enable" }
    )

    foreach ($policy in $auditCategories) {
        try {
            $result = auditpol /set /subcategory:"$($policy.Subcategory)" /success:$($policy.Success) /failure:$($policy.Failure) 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Host "    [+] Enabled: $($policy.Subcategory)" -ForegroundColor Green
            } else {
                Write-Host "    [-] Could not enable: $($policy.Subcategory)" -ForegroundColor Yellow
            }
        } catch {
            Write-Host "    [!] Error setting $($policy.Subcategory): $_" -ForegroundColor Red
        }
    }

    # Enable command line logging in process creation events
    Write-Host "    [*] Enabling command line in process creation events..." -ForegroundColor Cyan
    try {
        $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
        if (-not (Test-Path $regPath)) {
            New-Item -Path $regPath -Force | Out-Null
        }
        Set-ItemProperty -Path $regPath -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord
        Write-Host "    [+] Command line logging enabled" -ForegroundColor Green
    } catch {
        Write-Host "    [!] Could not enable command line logging: $_" -ForegroundColor Yellow
    }

    return $true
}

function Register-AuditorTask {
    Write-Host "`n[*] Registering scheduled task..." -ForegroundColor Yellow

    if (-not $RegisterScheduledTask) {
        Write-Host "    [-] Skipping scheduled task registration (use -RegisterScheduledTask to enable)" -ForegroundColor Yellow
        return $true
    }

    $taskName = "DCSA-SecurityAuditor"
    $taskDescription = "DCSA Security Auditor for Windows 11 - Continuous security monitoring for accredited systems"

    # Remove existing task if present
    $existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    if ($existingTask) {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
        Write-Host "    [*] Removed existing task" -ForegroundColor Cyan
    }

    # Create task action
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -File `"$InstallPath\Start-Auditor.ps1`" -Mode Service"

    # Create trigger (at system startup)
    $trigger = New-ScheduledTaskTrigger -AtStartup

    # Create principal (run as SYSTEM)
    $principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest

    # Create settings
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit (New-TimeSpan -Days 365)

    # Register task
    try {
        Register-ScheduledTask -TaskName $taskName -Description $taskDescription -Action $action -Trigger $trigger -Principal $principal -Settings $settings | Out-Null
        Write-Host "    [+] Scheduled task registered: $taskName" -ForegroundColor Green
        Write-Host "    [+] Task will start automatically at system startup" -ForegroundColor Green
    } catch {
        Write-Host "    [!] Failed to register scheduled task: $_" -ForegroundColor Red
        return $false
    }

    return $true
}

function Create-CustomEventLog {
    Write-Host "`n[*] Creating custom event log..." -ForegroundColor Yellow

    $logName = "DCSA-Auditor"

    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists($logName)) {
            New-EventLog -LogName $logName -Source $logName
            Write-Host "    [+] Created event log: $logName" -ForegroundColor Green
        } else {
            Write-Host "    [+] Event log already exists: $logName" -ForegroundColor Green
        }

        # Set log size (64MB)
        Limit-EventLog -LogName $logName -MaximumSize 64MB -OverflowAction OverwriteOlder
        Write-Host "    [+] Event log configured (64MB max)" -ForegroundColor Green
    } catch {
        Write-Host "    [!] Could not create event log: $_" -ForegroundColor Yellow
    }

    return $true
}

function Show-PostInstallInfo {
    Write-Host "`n" + "=" * 60 -ForegroundColor Cyan
    Write-Host "    INSTALLATION COMPLETE" -ForegroundColor Green
    Write-Host "=" * 60 -ForegroundColor Cyan

    Write-Host "`nInstallation Summary:" -ForegroundColor Yellow
    Write-Host "  Installation Path: $InstallPath"
    Write-Host "  Log Path: $LogPath"
    Write-Host "  Audit Policy: $(if ($ConfigureAuditPolicy) { 'Configured' } else { 'Not configured' })"
    Write-Host "  Scheduled Task: $(if ($RegisterScheduledTask) { 'Registered' } else { 'Not registered' })"

    Write-Host "`nTo start the auditor manually:" -ForegroundColor Yellow
    Write-Host "  cd `"$InstallPath`""
    Write-Host "  .\Start-Auditor.ps1"

    Write-Host "`nTo start in interactive mode:" -ForegroundColor Yellow
    Write-Host "  .\Start-Auditor.ps1 -Mode Interactive"

    Write-Host "`nTo generate a compliance report:" -ForegroundColor Yellow
    Write-Host "  .\scripts\Generate-ComplianceReport.ps1"

    if ($RegisterScheduledTask) {
        Write-Host "`nThe auditor will start automatically at next system boot." -ForegroundColor Cyan
        Write-Host "To start now, run:" -ForegroundColor Yellow
        Write-Host "  Start-ScheduledTask -TaskName 'DCSA-SecurityAuditor'"
    }

    Write-Host "`n" + "=" * 60 -ForegroundColor Cyan
}

# Main installation
function Main {
    Show-Banner

    Write-Host "Installation Parameters:" -ForegroundColor Cyan
    Write-Host "  Install Path: $InstallPath"
    Write-Host "  Log Path: $LogPath"
    Write-Host "  Configure Audit Policy: $ConfigureAuditPolicy"
    Write-Host "  Register Scheduled Task: $RegisterScheduledTask"

    # Confirm installation
    $confirm = Read-Host "`nProceed with installation? (y/n)"
    if ($confirm -ne 'y') {
        Write-Host "Installation cancelled." -ForegroundColor Yellow
        exit 0
    }

    # Run installation steps
    if (-not (Test-Prerequisites)) {
        Write-Host "`n[!] Prerequisites check failed. Exiting." -ForegroundColor Red
        exit 1
    }

    if (-not (Install-AuditorFiles)) {
        Write-Host "`n[!] File installation failed. Exiting." -ForegroundColor Red
        exit 1
    }

    if (-not (Initialize-LogDirectory)) {
        Write-Host "`n[!] Log directory initialization failed. Exiting." -ForegroundColor Red
        exit 1
    }

    Set-WindowsAuditPolicy | Out-Null
    Create-CustomEventLog | Out-Null
    Register-AuditorTask | Out-Null

    Show-PostInstallInfo
}

Main
