# How to Approve an Audit Report

This guide walks through the complete process of formally approving a DCSA
compliance report. Every weekly compliance report must be reviewed and signed off
by an authorized reviewer before it is considered accepted.

---

## Who Can Approve

| Role | Description |
|------|-------------|
| **ISSM** | Information System Security Manager — primary reviewer |
| **FSO** | Facility Security Officer — secondary reviewer when applicable |

## Approval Decisions

| Status | Meaning |
|--------|---------|
| `Approved` | Findings reviewed and accepted — no further action needed |
| `Rejected` | Findings require remediation before the report can be accepted |
| `ConditionallyApproved` | Approved with conditions noted in the comments field |

---

## Method 1 — Command-Line Script (Recommended)

Open PowerShell as Administrator and navigate to the Auditor directory.

### Step 1: Generate the report (if not already generated)

```powershell
.\scripts\Generate-ComplianceReport.ps1 -ReportType Weekly -OutputFormat HTML
```

### Step 2: Approve with all parameters

```powershell
.\scripts\Approve-ComplianceReport.ps1 `
    -ReviewerName "Jane Smith" `
    -ReviewerRole ISSM `
    -Status Approved `
    -Comments "All findings reviewed and acceptable."
```

If you omit `-ReportPath`, the script lists all available reports and prompts you
to pick one by number.

### Step 3: Approve a specific report by path

```powershell
.\scripts\Approve-ComplianceReport.ps1 `
    -ReportPath "C:\AuditLogs\Reports\WeeklyCompliance_2026-03-15.html" `
    -ReviewerName "Jane Smith" `
    -ReviewerRole ISSM `
    -Status Approved
```

### Step 4: Verify the approval was recorded

After approval, two artifacts are created:

1. **Sidecar file** — `WeeklyCompliance_2026-03-15.approval.json` appears next
   to the report. Open it to confirm:

   ```powershell
   Get-Content "C:\AuditLogs\Reports\WeeklyCompliance_2026-03-15.approval.json" | ConvertFrom-Json
   ```

2. **Approval log** — a tamper-evident entry is appended to
   `C:\AuditLogs\Approvals\Approvals-<date>.log`.

---

## Method 2 — Interactive Menu

### Step 1: Start the auditor in interactive mode

```powershell
.\Start-Auditor.ps1 -Mode Interactive
```

### Step 2: Select option **9** (Approve Compliance Report)

```
=== DCSA Auditor Menu ===
1. View Status
2. Generate Daily Report
3. Generate Weekly Compliance Report
4. Verify Log Integrity
5. Check Baseline
6. View Current Devices
7. View Running Processes
8. Create New Baseline
9. Approve Compliance Report      <-- select this
10. Exit
```

### Step 3: Follow the prompts

1. Pick a report from the numbered list.
2. Enter your name.
3. Enter your role (`ISSM` or `FSO`).
4. Enter the approval status (`Approved`, `Rejected`, or `ConditionallyApproved`).
5. Enter any comments (or press Enter to skip).

The system confirms the approval with the timestamp and report hash.

---

## Method 3 — PowerShell Function (Programmatic)

Import the module and call `Approve-AuditReport` directly:

```powershell
Import-Module .\src\utils\AuditUtilities.psm1 -Force
Import-Module .\src\modules\ReportGenerator.psm1 -Force

# Approve
Approve-AuditReport `
    -ReportPath "C:\AuditLogs\Reports\WeeklyCompliance_2026-03-15.html" `
    -ReviewerName "Jane Smith" `
    -ReviewerRole ISSM `
    -Status Approved `
    -Comments "Weekly review completed."

# Check status later
Get-ReportApprovalStatus -ReportPath "C:\AuditLogs\Reports\WeeklyCompliance_2026-03-15.html"
```

---

## What Gets Recorded

Each approval captures:

| Field | Description |
|-------|-------------|
| `Timestamp` | UTC time of the approval |
| `ReportFile` | Name of the approved report |
| `ReportHash` | SHA256 hash of the report at approval time |
| `ReviewerName` | Name of the reviewer |
| `ReviewerRole` | `ISSM` or `FSO` |
| `Status` | `Approved`, `Rejected`, or `ConditionallyApproved` |
| `Comments` | Any notes or conditions |
| `ComputerName` | Machine where approval was recorded |
| `UserAccount` | Windows account of the reviewer |

## Tamper Detection

The SHA256 hash in the approval record is computed from the report file at the
time of signing. If the report is modified after approval, the hash will no
longer match — indicating the approved content has been altered.

To verify integrity, compare the stored hash against the current file:

```powershell
$approval = Get-Content "C:\AuditLogs\Reports\WeeklyCompliance_2026-03-15.approval.json" | ConvertFrom-Json
$currentHash = (Get-FileHash "C:\AuditLogs\Reports\WeeklyCompliance_2026-03-15.html" -Algorithm SHA256).Hash

if ($approval.ReportHash -eq $currentHash) {
    Write-Host "Report is unmodified since approval." -ForegroundColor Green
} else {
    Write-Host "WARNING: Report has been modified after approval!" -ForegroundColor Red
}
```
