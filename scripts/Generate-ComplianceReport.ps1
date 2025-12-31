#Requires -Version 5.1
<#
.SYNOPSIS
    Generates a DCSA compliance report

.DESCRIPTION
    Generates daily or weekly compliance reports for security review.

.PARAMETER ReportType
    Type of report: Daily or Weekly

.PARAMETER OutputFormat
    Output format: HTML, CSV, or JSON

.EXAMPLE
    .\Generate-ComplianceReport.ps1 -ReportType Weekly -OutputFormat HTML
#>

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateSet("Daily", "Weekly")]
    [string]$ReportType = "Daily",

    [Parameter()]
    [ValidateSet("HTML", "CSV", "JSON")]
    [string[]]$OutputFormat = @("HTML")
)

$scriptRoot = Split-Path -Parent $PSScriptRoot
Import-Module "$scriptRoot\src\utils\AuditUtilities.psm1" -Force
Import-Module "$scriptRoot\src\modules\ReportGenerator.psm1" -Force

Write-Host "DCSA Auditor - Compliance Report Generator" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

if ($ReportType -eq "Daily") {
    Write-Host "Generating daily summary report..." -ForegroundColor Yellow
    $report = New-DailySummaryReport -Date (Get-Date).Date -Formats $OutputFormat
    Write-Host "Daily report generated." -ForegroundColor Green
} else {
    Write-Host "Generating weekly compliance report..." -ForegroundColor Yellow
    $report = New-WeeklyComplianceReport -WeekEndDate (Get-Date).Date -Formats $OutputFormat
    Write-Host "Weekly report generated." -ForegroundColor Green
    Write-Host "Compliance Status: $($report.ComplianceStatus)" -ForegroundColor $(if ($report.ComplianceStatus -match "COMPLIANT" -and $report.ComplianceStatus -notmatch "NON") { "Green" } else { "Yellow" })
}

$config = Get-AuditConfig
Write-Host "`nReport location: $($config.Reporting.OutputPath)" -ForegroundColor Cyan
