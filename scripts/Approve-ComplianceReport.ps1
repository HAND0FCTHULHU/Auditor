#Requires -Version 5.1
<#
.SYNOPSIS
    Approves a DCSA compliance report

.DESCRIPTION
    Records a formal ISSM or FSO approval on a compliance report. The approval
    includes the reviewer's identity, role, decision, and optional comments.
    A SHA256 hash of the report is captured at the time of approval to ensure
    the signed content has not been modified afterwards.

.PARAMETER ReportPath
    Full path to the report file to approve. If not specified, the script lists
    available reports and prompts for selection.

.PARAMETER ReviewerName
    Name of the person approving the report.

.PARAMETER ReviewerRole
    Role of the reviewer: ISSM or FSO.

.PARAMETER Status
    Approval decision: Approved, Rejected, or ConditionallyApproved.

.PARAMETER Comments
    Optional comments or conditions.

.EXAMPLE
    .\Approve-ComplianceReport.ps1 -ReviewerName "Jane Smith" -ReviewerRole ISSM -Status Approved

.EXAMPLE
    .\Approve-ComplianceReport.ps1 -ReportPath "C:\AuditLogs\Reports\WeeklyCompliance_2026-03-15.html" `
        -ReviewerName "John Doe" -ReviewerRole FSO -Status ConditionallyApproved `
        -Comments "Conditional on resolving finding #2"
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$ReportPath,

    [Parameter(Mandatory)]
    [string]$ReviewerName,

    [Parameter(Mandatory)]
    [ValidateSet("ISSM", "FSO")]
    [string]$ReviewerRole,

    [Parameter(Mandatory)]
    [ValidateSet("Approved", "Rejected", "ConditionallyApproved")]
    [string]$Status,

    [Parameter()]
    [string]$Comments = ""
)

$scriptRoot = Split-Path -Parent $PSScriptRoot
Import-Module "$scriptRoot\src\utils\AuditUtilities.psm1" -Force
Import-Module "$scriptRoot\src\modules\ReportGenerator.psm1" -Force

Write-Host "DCSA Auditor - Report Approval" -ForegroundColor Cyan
Write-Host "===============================" -ForegroundColor Cyan

# If no report path specified, list available reports
if (-not $ReportPath) {
    $reports = Get-AuditReportList
    if ($reports.Count -eq 0) {
        Write-Host "No reports found." -ForegroundColor Red
        exit 1
    }

    Write-Host "`nAvailable reports:" -ForegroundColor Yellow
    $index = 1
    foreach ($r in $reports) {
        $approvalStatus = Get-ReportApprovalStatus -ReportPath $r.Path
        $tag = if ($approvalStatus) { " [$($approvalStatus.Status)]" } else { " [Not Approved]" }
        Write-Host "  $index. $($r.Name)$tag"
        $index++
    }

    $selection = Read-Host "`nSelect report number"
    $selectedIndex = [int]$selection - 1
    if ($selectedIndex -lt 0 -or $selectedIndex -ge $reports.Count) {
        Write-Host "Invalid selection." -ForegroundColor Red
        exit 1
    }
    $ReportPath = $reports[$selectedIndex].Path
}

Write-Host "`nApproving report: $(Split-Path $ReportPath -Leaf)" -ForegroundColor Yellow
Write-Host "  Reviewer: $ReviewerName ($ReviewerRole)" -ForegroundColor Gray
Write-Host "  Decision: $Status" -ForegroundColor Gray
if ($Comments) {
    Write-Host "  Comments: $Comments" -ForegroundColor Gray
}

try {
    $result = Approve-AuditReport -ReportPath $ReportPath `
        -ReviewerName $ReviewerName -ReviewerRole $ReviewerRole `
        -Status $Status -Comments $Comments

    Write-Host "`nApproval recorded successfully." -ForegroundColor Green
    Write-Host "  Timestamp: $($result.Timestamp)" -ForegroundColor Cyan
    Write-Host "  Report Hash: $($result.ReportHash)" -ForegroundColor Cyan
    Write-Host "  Approval saved alongside report." -ForegroundColor Cyan
} catch {
    Write-Host "Error recording approval: $_" -ForegroundColor Red
    exit 1
}
