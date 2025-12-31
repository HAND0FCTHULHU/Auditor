#Requires -Version 5.1
<#
.SYNOPSIS
    Displays the current status of the DCSA Auditor

.DESCRIPTION
    Shows configuration, running jobs, log integrity, and recent activity.
#>

[CmdletBinding()]
param()

$scriptRoot = Split-Path -Parent $PSScriptRoot
Import-Module "$scriptRoot\src\utils\AuditUtilities.psm1" -Force

Write-Host "`n=== DCSA AUDITOR STATUS ===" -ForegroundColor Cyan
Write-Host "Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray

$config = Get-AuditConfig

# System Information
Write-Host "`n--- System Information ---" -ForegroundColor Yellow
Write-Host "Computer Name: $env:COMPUTERNAME"
Write-Host "Organization: $($config.General.OrganizationName)"
Write-Host "Classification: $($config.General.ClassificationLevel)"

# Configuration Status
Write-Host "`n--- Configuration ---" -ForegroundColor Yellow
Write-Host "Log Path: $($config.LogStorage.BasePath)"
Write-Host "Retention Days: $($config.LogStorage.RetentionDays)"
Write-Host "Security Events: $(if ($config.SecurityEvents.Enabled) { 'Enabled' } else { 'Disabled' })"
Write-Host "User Activity: $(if ($config.UserActivity.Enabled) { 'Enabled' } else { 'Disabled' })"
Write-Host "File System: $(if ($config.FileSystem.Enabled) { 'Enabled' } else { 'Disabled' })"
Write-Host "Removable Media: $(if ($config.RemovableMedia.Enabled) { 'Enabled' } else { 'Disabled' })"
Write-Host "Process Monitoring: $(if ($config.ProcessMonitoring.Enabled) { 'Enabled' } else { 'Disabled' })"
Write-Host "Baseline Monitoring: $(if ($config.BaselineMonitoring.Enabled) { 'Enabled' } else { 'Disabled' })"

# Log Storage Status
Write-Host "`n--- Log Storage ---" -ForegroundColor Yellow
if (Test-Path $config.LogStorage.BasePath) {
    $logFiles = Get-ChildItem -Path $config.LogStorage.BasePath -Recurse -Filter "*.log" -ErrorAction SilentlyContinue
    $totalSize = ($logFiles | Measure-Object -Property Length -Sum).Sum
    $totalSizeMB = [math]::Round($totalSize / 1MB, 2)

    Write-Host "Log Files: $($logFiles.Count)"
    Write-Host "Total Size: $totalSizeMB MB"

    # Recent log activity
    $recentLogs = $logFiles | Sort-Object LastWriteTime -Descending | Select-Object -First 5
    Write-Host "`nRecent Log Activity:"
    foreach ($log in $recentLogs) {
        Write-Host "  $($log.Name) - $(Get-Date $log.LastWriteTime -Format 'yyyy-MM-dd HH:mm:ss')"
    }
} else {
    Write-Host "Log directory not found: $($config.LogStorage.BasePath)" -ForegroundColor Red
}

# Log Integrity
Write-Host "`n--- Log Integrity ---" -ForegroundColor Yellow
try {
    $integrityResults = Verify-LogIntegrity
    $validCount = ($integrityResults | Where-Object { $_.IntegrityStatus -eq "VALID" }).Count
    $totalCount = $integrityResults.Count

    if ($validCount -eq $totalCount) {
        Write-Host "Status: ALL LOGS VALID ($validCount/$totalCount)" -ForegroundColor Green
    } else {
        Write-Host "Status: INTEGRITY ISSUES DETECTED" -ForegroundColor Red
        Write-Host "Valid: $validCount / $totalCount" -ForegroundColor Yellow

        $compromised = $integrityResults | Where-Object { $_.IntegrityStatus -eq "COMPROMISED" }
        foreach ($file in $compromised) {
            Write-Host "  [!] $($file.FilePath) - $($file.InvalidLines) invalid lines" -ForegroundColor Red
        }
    }
} catch {
    Write-Host "Could not verify log integrity: $_" -ForegroundColor Yellow
}

# Scheduled Task Status
Write-Host "`n--- Scheduled Task ---" -ForegroundColor Yellow
$task = Get-ScheduledTask -TaskName "DCSA-SecurityAuditor" -ErrorAction SilentlyContinue
if ($task) {
    $taskInfo = Get-ScheduledTaskInfo -TaskName "DCSA-SecurityAuditor" -ErrorAction SilentlyContinue
    Write-Host "Status: $($task.State)"
    Write-Host "Last Run: $($taskInfo.LastRunTime)"
    Write-Host "Next Run: $($taskInfo.NextRunTime)"
    Write-Host "Last Result: $($taskInfo.LastTaskResult)"
} else {
    Write-Host "Scheduled task not registered" -ForegroundColor Yellow
}

Write-Host "`n=== END STATUS ===" -ForegroundColor Cyan
