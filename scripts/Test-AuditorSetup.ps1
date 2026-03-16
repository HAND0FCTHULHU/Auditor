#Requires -Version 5.1
<#
.SYNOPSIS
    Validates the DCSA Auditor installation and configuration

.DESCRIPTION
    Performs pre-flight checks to ensure the auditor will work correctly.
    Run this before starting the auditor for the first time.

.EXAMPLE
    .\Test-AuditorSetup.ps1
#>

[CmdletBinding()]
param()

$scriptRoot = Split-Path -Parent $PSScriptRoot
$ErrorActionPreference = "Continue"

Write-Host "`n=== DCSA AUDITOR PRE-FLIGHT CHECK ===" -ForegroundColor Cyan
Write-Host "Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray

$allPassed = $true
$warnings = @()
$errors = @()

# Check 1: Administrator privileges
Write-Host "`n[1/10] Checking administrator privileges..." -ForegroundColor Yellow
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($isAdmin) {
    Write-Host "    [PASS] Running as Administrator" -ForegroundColor Green
} else {
    Write-Host "    [FAIL] Not running as Administrator" -ForegroundColor Red
    $errors += "Administrator privileges required"
    $allPassed = $false
}

# Check 2: PowerShell version
Write-Host "`n[2/10] Checking PowerShell version..." -ForegroundColor Yellow
$psVersion = $PSVersionTable.PSVersion
if ($psVersion.Major -ge 5) {
    Write-Host "    [PASS] PowerShell $psVersion" -ForegroundColor Green
} else {
    Write-Host "    [FAIL] PowerShell 5.1+ required (found $psVersion)" -ForegroundColor Red
    $errors += "PowerShell 5.1 or later required"
    $allPassed = $false
}

# Check 3: Windows version
Write-Host "`n[3/10] Checking Windows version..." -ForegroundColor Yellow
$osInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
$osBuild = [int]$osInfo.BuildNumber
if ($osBuild -ge 22000) {
    Write-Host "    [PASS] Windows 11 (Build $osBuild)" -ForegroundColor Green
} elseif ($osBuild -ge 17763) {
    Write-Host "    [WARN] Windows 10 detected (Build $osBuild) - Windows 11 recommended" -ForegroundColor Yellow
    $warnings += "Windows 11 recommended for full compatibility"
} else {
    Write-Host "    [FAIL] Windows 10 1809+ or Windows 11 required" -ForegroundColor Red
    $errors += "Unsupported Windows version"
    $allPassed = $false
}

# Check 4: Configuration file
Write-Host "`n[4/10] Checking configuration file..." -ForegroundColor Yellow
$configPath = "$scriptRoot\src\config\AuditConfig.psd1"
if (Test-Path $configPath) {
    try {
        $config = Import-PowerShellDataFile -Path $configPath
        Write-Host "    [PASS] Configuration file valid" -ForegroundColor Green
    } catch {
        Write-Host "    [FAIL] Configuration file invalid: $_" -ForegroundColor Red
        $errors += "Configuration file parse error"
        $allPassed = $false
    }
} else {
    Write-Host "    [FAIL] Configuration file not found: $configPath" -ForegroundColor Red
    $errors += "Configuration file missing"
    $allPassed = $false
}

# Check 5: Required modules
Write-Host "`n[5/10] Checking required modules..." -ForegroundColor Yellow
$modules = @(
    "AuditUtilities.psm1",
    "SecurityEventCollector.psm1",
    "UserActivityMonitor.psm1",
    "FileSystemAuditor.psm1",
    "RemovableMediaMonitor.psm1",
    "ProcessMonitor.psm1",
    "BaselineMonitor.psm1",
    "ReportGenerator.psm1"
)
$missingModules = @()
foreach ($mod in $modules) {
    $modPath = if ($mod -eq "AuditUtilities.psm1") { "$scriptRoot\src\utils\$mod" } else { "$scriptRoot\src\modules\$mod" }
    if (-not (Test-Path $modPath)) {
        $missingModules += $mod
    }
}
if ($missingModules.Count -eq 0) {
    Write-Host "    [PASS] All $($modules.Count) modules present" -ForegroundColor Green
} else {
    Write-Host "    [FAIL] Missing modules: $($missingModules -join ', ')" -ForegroundColor Red
    $errors += "Missing required modules"
    $allPassed = $false
}

# Check 6: Log directory access
Write-Host "`n[6/10] Checking log directory..." -ForegroundColor Yellow
if ($config) {
    $logPath = $config.LogStorage.BasePath
    if (Test-Path $logPath) {
        Write-Host "    [PASS] Log directory exists: $logPath" -ForegroundColor Green
    } else {
        Write-Host "    [INFO] Log directory will be created: $logPath" -ForegroundColor Cyan
        try {
            New-Item -Path $logPath -ItemType Directory -Force | Out-Null
            Write-Host "    [PASS] Created log directory" -ForegroundColor Green
        } catch {
            Write-Host "    [FAIL] Cannot create log directory: $_" -ForegroundColor Red
            $errors += "Cannot create log directory"
            $allPassed = $false
        }
    }
} else {
    Write-Host "    [SKIP] Cannot check - configuration not loaded" -ForegroundColor Yellow
}

# Check 7: Disk space
Write-Host "`n[7/10] Checking disk space..." -ForegroundColor Yellow
try {
    $drive = "C:"
    $disk = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='$drive'" -ErrorAction Stop
    $freeGB = [math]::Round($disk.FreeSpace / 1GB, 2)
    if ($freeGB -ge 5) {
        Write-Host "    [PASS] $freeGB GB free on $drive" -ForegroundColor Green
    } elseif ($freeGB -ge 1) {
        Write-Host "    [WARN] Only $freeGB GB free on $drive (5GB+ recommended)" -ForegroundColor Yellow
        $warnings += "Low disk space"
    } else {
        Write-Host "    [FAIL] Critically low disk space: $freeGB GB" -ForegroundColor Red
        $errors += "Insufficient disk space"
        $allPassed = $false
    }
} catch {
    Write-Host "    [WARN] Could not check disk space: $_" -ForegroundColor Yellow
    $warnings += "Disk space check failed"
}

# Check 8: Security Event Log access
Write-Host "`n[8/10] Checking Security Event Log access..." -ForegroundColor Yellow
try {
    $events = Get-WinEvent -LogName Security -MaxEvents 1 -ErrorAction Stop
    Write-Host "    [PASS] Can read Security Event Log" -ForegroundColor Green
} catch {
    if ($_.Exception.Message -match "Access is denied") {
        Write-Host "    [FAIL] Access denied to Security Event Log" -ForegroundColor Red
        $errors += "Cannot access Security Event Log"
        $allPassed = $false
    } else {
        Write-Host "    [WARN] Security Event Log issue: $_" -ForegroundColor Yellow
        $warnings += "Security Event Log access issue"
    }
}

# Check 9: Audit policy status
Write-Host "`n[9/10] Checking audit policy configuration..." -ForegroundColor Yellow
try {
    $auditOutput = auditpol /get /category:"Logon/Logoff" 2>$null
    if ($auditOutput -match "Success and Failure|Success|Failure") {
        Write-Host "    [PASS] Audit policies configured" -ForegroundColor Green
    } else {
        Write-Host "    [WARN] Audit policies may not be fully configured" -ForegroundColor Yellow
        Write-Host "    [INFO] Run Install-Auditor.ps1 -ConfigureAuditPolicy to configure" -ForegroundColor Cyan
        $warnings += "Audit policies may need configuration"
    }
} catch {
    Write-Host "    [WARN] Could not check audit policy: $_" -ForegroundColor Yellow
    $warnings += "Audit policy check failed"
}

# Check 10: Event log registration
Write-Host "`n[10/10] Checking custom event log..." -ForegroundColor Yellow
$eventLogName = "DCSA-Auditor"
try {
    if ([System.Diagnostics.EventLog]::SourceExists($eventLogName)) {
        Write-Host "    [PASS] Custom event log registered: $eventLogName" -ForegroundColor Green
    } else {
        Write-Host "    [INFO] Custom event log will be created on first run" -ForegroundColor Cyan
    }
} catch {
    Write-Host "    [INFO] Custom event log will be created on first run" -ForegroundColor Cyan
}

# Summary
Write-Host "`n=== SUMMARY ===" -ForegroundColor Cyan

if ($errors.Count -gt 0) {
    Write-Host "`nErrors ($($errors.Count)):" -ForegroundColor Red
    foreach ($e in $errors) {
        Write-Host "  - $e" -ForegroundColor Red
    }
}

if ($warnings.Count -gt 0) {
    Write-Host "`nWarnings ($($warnings.Count)):" -ForegroundColor Yellow
    foreach ($w in $warnings) {
        Write-Host "  - $w" -ForegroundColor Yellow
    }
}

if ($allPassed) {
    Write-Host "`n[READY] All critical checks passed. The auditor is ready to run." -ForegroundColor Green
    Write-Host "        Start with: .\Start-Auditor.ps1" -ForegroundColor Cyan
    exit 0
} else {
    Write-Host "`n[NOT READY] Please fix the errors above before running the auditor." -ForegroundColor Red
    exit 1
}
