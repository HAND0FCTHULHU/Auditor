# DCSA Auditor Quick Start Guide

This guide gets you up and running in 10 minutes. For the DCSA audit account user.

---

## First-Time Setup (Run Once)

### Step 1: Open PowerShell as Administrator
- Right-click the Start button
- Select "Windows Terminal (Admin)" or "PowerShell (Admin)"

### Step 2: Navigate to the Auditor folder
```powershell
cd "C:\Path\To\Auditor"
```

### Step 3: Run Pre-Flight Check
```powershell
.\scripts\Test-AuditorSetup.ps1
```
All items should show `[PASS]`. Fix any `[FAIL]` items before continuing.

### Step 4: Install the Auditor
```powershell
.\Install-Auditor.ps1 -RegisterScheduledTask -ConfigureAuditPolicy
```
Type `y` when prompted to confirm.

### Step 5: Create Initial Baseline
```powershell
.\Start-Auditor.ps1 -Mode Interactive
```
Select option `8` to create the system baseline.

---

## Daily Operations

### Starting the Auditor

**Option A - Automatic (Recommended)**
The auditor starts automatically at boot if you installed with `-RegisterScheduledTask`.

**Option B - Manual Start**
```powershell
.\Start-Auditor.ps1
```

### Checking Status
```powershell
.\scripts\Get-AuditStatus.ps1
```

### Viewing the Interactive Dashboard
```powershell
.\Start-Auditor.ps1 -Mode Interactive
```

---

## Weekly Tasks

### Generate Weekly Compliance Report
```powershell
.\scripts\Generate-ComplianceReport.ps1 -ReportType Weekly
```

### Approve the Report (ISSM/FSO)
```powershell
.\scripts\Approve-ComplianceReport.ps1 -ReviewerName "Your Name" -ReviewerRole ISSM -Status Approved
```

Or use the interactive menu:
1. Run `.\Start-Auditor.ps1 -Mode Interactive`
2. Select option `9` (Approve Compliance Report)
3. Follow the prompts

---

## Interactive Menu Quick Reference

| Option | Action |
|--------|--------|
| 1 | View current status |
| 2 | Generate daily report |
| 3 | Generate weekly compliance report |
| 4 | Verify log integrity (check for tampering) |
| 5 | Check for configuration changes since baseline |
| 6 | View connected USB/removable devices |
| 7 | View security-sensitive running processes |
| 8 | Create new system baseline |
| 9 | Approve a compliance report |
| 10 | Exit |

---

## Key File Locations

| What | Where |
|------|-------|
| Audit Logs | `C:\AuditLogs\` |
| Reports | `C:\AuditLogs\Reports\` |
| Approvals | `C:\AuditLogs\Approvals\` |
| Configuration | `src\config\AuditConfig.psd1` |
| Baselines | `baselines\` |

---

## Troubleshooting

### "No reports found"
Generate a report first:
```powershell
.\scripts\Generate-ComplianceReport.ps1 -ReportType Daily
```

### "Access denied" errors
Make sure you're running PowerShell as Administrator.

### Auditor not starting at boot
Re-register the scheduled task:
```powershell
.\Install-Auditor.ps1 -RegisterScheduledTask
```

### Log integrity shows "COMPROMISED"
1. Do NOT delete the compromised logs
2. Report to your ISSM immediately
3. The compromised files are evidence

---

## Before the DCSA Audit

1. **Generate fresh reports**
   ```powershell
   .\scripts\Generate-ComplianceReport.ps1 -ReportType Weekly
   ```

2. **Approve all pending reports**
   ```powershell
   .\Start-Auditor.ps1 -Mode Interactive
   # Select option 9, approve each report
   ```

3. **Verify log integrity**
   ```powershell
   .\scripts\Verify-LogIntegrity.ps1
   ```
   Should show "ALL LOGS VERIFIED - NO TAMPERING DETECTED"

4. **Check baseline compliance**
   ```powershell
   .\Start-Auditor.ps1 -Mode Interactive
   # Select option 5
   ```
   Should show "No baseline deviations detected"

5. **Print/export reports** from `C:\AuditLogs\Reports\` for the auditor

---

## Emergency Contacts

| Role | Responsibility |
|------|----------------|
| ISSM | Primary security authority - report all incidents |
| FSO | Facility oversight - backup approval authority |

---

**Remember**: All actions are logged. The auditor can see what you've been doing!
