#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    DCSA Security Auditor - Main Entry Point

.DESCRIPTION
    Starts the DCSA Security Auditor for Windows 11 standalone systems.
    This script orchestrates all auditing modules and provides a unified
    interface for security monitoring on classified systems.

.PARAMETER Mode
    Operating mode: 'Service' for continuous monitoring, 'Interactive' for console mode

.PARAMETER Components
    Specific components to start. Default is 'All'.
    Options: All, Security, UserActivity, FileSystem, RemovableMedia, Process, Baseline

.EXAMPLE
    .\Start-Auditor.ps1
    Starts all auditing components in service mode

.EXAMPLE
    .\Start-Auditor.ps1 -Mode Interactive -Components Security,UserActivity
    Starts specific components in interactive mode
#>

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateSet("Service", "Interactive")]
    [string]$Mode = "Service",

    [Parameter()]
    [ValidateSet("All", "Security", "UserActivity", "FileSystem", "RemovableMedia", "Process", "Baseline")]
    [string[]]$Components = @("All")
)

# Script configuration
$ErrorActionPreference = "Stop"
$script:AuditorRoot = $PSScriptRoot
$script:ModulesPath = "$PSScriptRoot\src\modules"
$script:UtilsPath = "$PSScriptRoot\src\utils"
$script:RunningJobs = @{}

# Banner
function Show-Banner {
    $banner = @"

    ╔═══════════════════════════════════════════════════════════════╗
    ║                                                               ║
    ║     DCSA SECURITY AUDITOR FOR WINDOWS 11                     ║
    ║     Version 1.0.0                                             ║
    ║                                                               ║
    ║     Defense Counterintelligence and Security Agency           ║
    ║     Accredited System Auditing Software                       ║
    ║                                                               ║
    ╚═══════════════════════════════════════════════════════════════╝

"@
    Write-Host $banner -ForegroundColor Cyan
}

# Import core modules
function Initialize-Modules {
    Write-Host "[*] Initializing audit modules..." -ForegroundColor Yellow

    try {
        # Import utilities first
        Import-Module "$script:UtilsPath\AuditUtilities.psm1" -Force -Global
        Write-Host "    [+] Utilities module loaded" -ForegroundColor Green

        # Initialize environment
        $initResult = Initialize-AuditEnvironment
        if (-not $initResult) {
            throw "Failed to initialize audit environment"
        }
        Write-Host "    [+] Audit environment initialized" -ForegroundColor Green

        # Import all component modules
        $modules = @(
            "SecurityEventCollector",
            "UserActivityMonitor",
            "FileSystemAuditor",
            "RemovableMediaMonitor",
            "ProcessMonitor",
            "BaselineMonitor",
            "ReportGenerator"
        )

        foreach ($module in $modules) {
            $modulePath = "$script:ModulesPath\$module.psm1"
            if (Test-Path $modulePath) {
                Import-Module $modulePath -Force -Global
                Write-Host "    [+] $module loaded" -ForegroundColor Green
            } else {
                Write-Host "    [-] $module not found" -ForegroundColor Red
            }
        }

        return $true
    } catch {
        Write-Host "    [!] Error initializing modules: $_" -ForegroundColor Red
        return $false
    }
}

# Start auditing components
function Start-AuditComponents {
    param(
        [string[]]$ComponentList
    )

    Write-Host "`n[*] Starting audit components..." -ForegroundColor Yellow

    $config = Get-AuditConfig

    # Expand 'All' to all components
    if ("All" -in $ComponentList) {
        $ComponentList = @("Security", "UserActivity", "FileSystem", "RemovableMedia", "Process", "Baseline")
    }

    foreach ($component in $ComponentList) {
        Write-Host "    [*] Starting $component monitoring..." -ForegroundColor Cyan

        try {
            switch ($component) {
                "Security" {
                    if ($config.SecurityEvents.Enabled) {
                        $job = Start-SecurityEventCollection -AsJob
                        $script:RunningJobs["Security"] = $job
                        Write-Host "    [+] Security event collection started (Job ID: $($job.Id))" -ForegroundColor Green
                    } else {
                        Write-Host "    [-] Security event collection disabled in config" -ForegroundColor Yellow
                    }
                }
                "UserActivity" {
                    if ($config.UserActivity.Enabled) {
                        $job = Start-UserActivityMonitoring -AsJob
                        $script:RunningJobs["UserActivity"] = $job
                        Write-Host "    [+] User activity monitoring started (Job ID: $($job.Id))" -ForegroundColor Green
                    } else {
                        Write-Host "    [-] User activity monitoring disabled in config" -ForegroundColor Yellow
                    }
                }
                "FileSystem" {
                    if ($config.FileSystem.Enabled) {
                        $job = Start-FileSystemAuditing -AsJob
                        $script:RunningJobs["FileSystem"] = $job
                        Write-Host "    [+] File system auditing started (Job ID: $($job.Id))" -ForegroundColor Green
                    } else {
                        Write-Host "    [-] File system auditing disabled in config" -ForegroundColor Yellow
                    }
                }
                "RemovableMedia" {
                    if ($config.RemovableMedia.Enabled) {
                        $job = Start-RemovableMediaMonitoring -AsJob
                        $script:RunningJobs["RemovableMedia"] = $job
                        Write-Host "    [+] Removable media monitoring started (Job ID: $($job.Id))" -ForegroundColor Green
                    } else {
                        Write-Host "    [-] Removable media monitoring disabled in config" -ForegroundColor Yellow
                    }
                }
                "Process" {
                    if ($config.ProcessMonitoring.Enabled) {
                        $job = Start-ProcessMonitoring -AsJob
                        $script:RunningJobs["Process"] = $job
                        Write-Host "    [+] Process monitoring started (Job ID: $($job.Id))" -ForegroundColor Green
                    } else {
                        Write-Host "    [-] Process monitoring disabled in config" -ForegroundColor Yellow
                    }
                }
                "Baseline" {
                    if ($config.BaselineMonitoring.Enabled) {
                        $job = Start-BaselineMonitoring -AsJob
                        $script:RunningJobs["Baseline"] = $job
                        Write-Host "    [+] Baseline monitoring started (Job ID: $($job.Id))" -ForegroundColor Green
                    } else {
                        Write-Host "    [-] Baseline monitoring disabled in config" -ForegroundColor Yellow
                    }
                }
            }
        } catch {
            Write-Host "    [!] Error starting $component : $_" -ForegroundColor Red
        }
    }

    Write-Host "`n[+] Audit components started: $($script:RunningJobs.Count)" -ForegroundColor Green
}

# Monitor running jobs
function Watch-AuditJobs {
    Write-Host "`n[*] Monitoring audit jobs. Press Ctrl+C to stop..." -ForegroundColor Yellow
    Write-Host "    Log location: $((Get-AuditConfig).LogStorage.BasePath)" -ForegroundColor Cyan

    try {
        while ($true) {
            # Check job status
            foreach ($name in @($script:RunningJobs.Keys)) {
                $job = $script:RunningJobs[$name]
                if ($job.State -eq "Failed") {
                    Write-Host "[!] $name job failed. Restarting..." -ForegroundColor Red
                    $job | Receive-Job -ErrorAction SilentlyContinue
                    $job | Remove-Job -Force

                    # Restart the component
                    Start-AuditComponents -ComponentList @($name)
                }
            }

            Start-Sleep -Seconds 60

            # Log rotation check (hourly)
            if ((Get-Date).Minute -eq 0) {
                Invoke-LogRotation
            }

            # Daily report generation
            $config = Get-AuditConfig
            if ($config.Reporting.DailySummary -and (Get-Date).Hour -eq 0 -and (Get-Date).Minute -lt 5) {
                Write-Host "[*] Generating daily summary report..." -ForegroundColor Cyan
                New-DailySummaryReport -Date (Get-Date).AddDays(-1).Date | Out-Null
            }

            # Weekly compliance report (Sunday at midnight)
            if ($config.Reporting.WeeklyComplianceReport -and (Get-Date).DayOfWeek -eq "Sunday" -and (Get-Date).Hour -eq 0 -and (Get-Date).Minute -lt 5) {
                Write-Host "[*] Generating weekly compliance report..." -ForegroundColor Cyan
                New-WeeklyComplianceReport | Out-Null
            }
        }
    } finally {
        Stop-AllAuditJobs
    }
}

# Stop all audit jobs
function Stop-AllAuditJobs {
    Write-Host "`n[*] Stopping audit jobs..." -ForegroundColor Yellow

    foreach ($name in @($script:RunningJobs.Keys)) {
        $job = $script:RunningJobs[$name]
        Write-Host "    [*] Stopping $name..." -ForegroundColor Cyan
        $job | Stop-Job -ErrorAction SilentlyContinue
        $job | Remove-Job -Force -ErrorAction SilentlyContinue
    }

    $script:RunningJobs.Clear()
    Write-Host "[+] All audit jobs stopped" -ForegroundColor Green
}

# Get current status
function Get-AuditorStatus {
    Write-Host "`n=== DCSA Auditor Status ===" -ForegroundColor Cyan

    $config = Get-AuditConfig

    Write-Host "`nConfiguration:" -ForegroundColor Yellow
    Write-Host "  Organization: $($config.General.OrganizationName)"
    Write-Host "  Classification: $($config.General.ClassificationLevel)"
    Write-Host "  Log Path: $($config.LogStorage.BasePath)"

    Write-Host "`nRunning Jobs:" -ForegroundColor Yellow
    foreach ($name in $script:RunningJobs.Keys) {
        $job = $script:RunningJobs[$name]
        $status = switch ($job.State) {
            "Running" { "Running" }
            "Completed" { "Completed" }
            "Failed" { "FAILED" }
            default { $job.State }
        }
        $color = if ($job.State -eq "Running") { "Green" } elseif ($job.State -eq "Failed") { "Red" } else { "Yellow" }
        Write-Host "  $name : $status" -ForegroundColor $color
    }

    Write-Host "`nLog Integrity:" -ForegroundColor Yellow
    $integrity = Verify-LogIntegrity
    $valid = ($integrity | Where-Object { $_.IntegrityStatus -eq "VALID" }).Count
    $total = $integrity.Count
    $color = if ($valid -eq $total) { "Green" } else { "Red" }
    Write-Host "  Valid: $valid / $total" -ForegroundColor $color
}

# Interactive menu
function Show-InteractiveMenu {
    while ($true) {
        Write-Host "`n=== DCSA Auditor Menu ===" -ForegroundColor Cyan
        Write-Host "1. View Status"
        Write-Host "2. Generate Daily Report"
        Write-Host "3. Generate Weekly Compliance Report"
        Write-Host "4. Verify Log Integrity"
        Write-Host "5. Check Baseline"
        Write-Host "6. View Current Devices"
        Write-Host "7. View Running Processes"
        Write-Host "8. Create New Baseline"
        Write-Host "9. Approve Compliance Report"
        Write-Host "10. Exit"
        Write-Host ""

        $choice = Read-Host "Select option"

        switch ($choice) {
            "1" { Get-AuditorStatus }
            "2" {
                Write-Host "Generating daily report..." -ForegroundColor Yellow
                $report = New-DailySummaryReport
                Write-Host "Report generated. Path: $((Get-AuditConfig).Reporting.OutputPath)" -ForegroundColor Green
            }
            "3" {
                Write-Host "Generating weekly compliance report..." -ForegroundColor Yellow
                $report = New-WeeklyComplianceReport
                Write-Host "Report generated. Status: $($report.ComplianceStatus)" -ForegroundColor Green
            }
            "4" {
                Write-Host "Verifying log integrity..." -ForegroundColor Yellow
                $results = Verify-LogIntegrity -Detailed
                $results | Format-Table FilePath, TotalLines, ValidLines, InvalidLines, IntegrityStatus
            }
            "5" {
                Write-Host "Checking baseline..." -ForegroundColor Yellow
                $deviations = Compare-SystemToBaseline
                if ($deviations.Count -eq 0) {
                    Write-Host "No baseline deviations detected." -ForegroundColor Green
                } else {
                    Write-Host "Deviations found: $($deviations.Count)" -ForegroundColor Yellow
                    $deviations | Format-Table ItemType, ChangeType, ItemName, Details
                }
            }
            "6" {
                Write-Host "Current removable devices:" -ForegroundColor Yellow
                Get-CurrentRemovableDevices | Format-Table Name, Type, SizeGB, SerialNumber
            }
            "7" {
                Write-Host "Watched processes currently running:" -ForegroundColor Yellow
                Get-RunningProcesses -WatchedOnly | Format-Table ProcessId, Name, Owner, CreationDate
            }
            "8" {
                $confirm = Read-Host "Create new baseline? This will archive the current baseline. (y/n)"
                if ($confirm -eq "y") {
                    Write-Host "Creating new baseline..." -ForegroundColor Yellow
                    New-SystemBaseline -Force | Out-Null
                    Write-Host "New baseline created." -ForegroundColor Green
                }
            }
            "9" {
                Write-Host "`nAvailable reports:" -ForegroundColor Yellow
                $reports = Get-AuditReportList
                if ($reports.Count -eq 0) {
                    Write-Host "No reports found." -ForegroundColor Red
                } else {
                    $index = 1
                    foreach ($r in $reports) {
                        $approvalStatus = Get-ReportApprovalStatus -ReportPath $r.Path
                        $approvalTag = if ($approvalStatus) { " [$($approvalStatus.Status)]" } else { " [Not Approved]" }
                        Write-Host "  $index. $($r.Name)$approvalTag" -ForegroundColor Cyan
                        $index++
                    }

                    $selection = Read-Host "`nSelect report number to approve"
                    $selectedIndex = [int]$selection - 1
                    if ($selectedIndex -ge 0 -and $selectedIndex -lt $reports.Count) {
                        $selectedReport = $reports[$selectedIndex]
                        $reviewerName = Read-Host "Reviewer name"

                        $reviewerRole = ""
                        while ($reviewerRole -notin @("ISSM", "FSO")) {
                            $reviewerRole = Read-Host "Role (ISSM or FSO)"
                            if ($reviewerRole -notin @("ISSM", "FSO")) {
                                Write-Host "Invalid role. Please enter ISSM or FSO." -ForegroundColor Red
                            }
                        }

                        $statusChoice = ""
                        $validStatuses = @("Approved", "Rejected", "ConditionallyApproved")
                        while ($statusChoice -notin $validStatuses) {
                            $statusChoice = Read-Host "Status (Approved, Rejected, or ConditionallyApproved)"
                            if ($statusChoice -notin $validStatuses) {
                                Write-Host "Invalid status. Please enter Approved, Rejected, or ConditionallyApproved." -ForegroundColor Red
                            }
                        }

                        $comments = Read-Host "Comments (optional)"

                        try {
                            $result = Approve-AuditReport -ReportPath $selectedReport.Path `
                                -ReviewerName $reviewerName -ReviewerRole $reviewerRole `
                                -Status $statusChoice -Comments $comments
                            Write-Host "`nReport approved successfully." -ForegroundColor Green
                            Write-Host "  Reviewer: $($result.ReviewerName) ($($result.ReviewerRole))" -ForegroundColor Cyan
                            Write-Host "  Status: $($result.Status)" -ForegroundColor Cyan
                            Write-Host "  Timestamp: $($result.Timestamp)" -ForegroundColor Cyan
                        } catch {
                            Write-Host "Error approving report: $_" -ForegroundColor Red
                        }
                    } else {
                        Write-Host "Invalid selection." -ForegroundColor Red
                    }
                }
            }
            "10" {
                Write-Host "Exiting..." -ForegroundColor Yellow
                return
            }
            default {
                Write-Host "Invalid option" -ForegroundColor Red
            }
        }
    }
}

# Main execution
function Main {
    Show-Banner

    # Check for admin privileges
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Host "[!] This script requires Administrator privileges." -ForegroundColor Red
        Write-Host "    Please run PowerShell as Administrator and try again." -ForegroundColor Yellow
        exit 1
    }

    Write-Host "[+] Running with Administrator privileges" -ForegroundColor Green
    Write-Host "[*] Mode: $Mode" -ForegroundColor Cyan
    Write-Host "[*] Components: $($Components -join ', ')" -ForegroundColor Cyan

    # Initialize modules
    $initSuccess = Initialize-Modules
    if (-not $initSuccess) {
        Write-Host "[!] Failed to initialize. Exiting." -ForegroundColor Red
        exit 1
    }

    # Start components
    Start-AuditComponents -ComponentList $Components

    # Run based on mode
    if ($Mode -eq "Interactive") {
        Show-InteractiveMenu
        Stop-AllAuditJobs
    } else {
        Watch-AuditJobs
    }
}

# Handle Ctrl+C gracefully
$null = Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action {
    Stop-AllAuditJobs
}

# Run main
Main
