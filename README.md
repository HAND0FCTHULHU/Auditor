# Windows 11 Security Auditing Software for DCSA-Accredited Systems

## Overview

This auditing software is designed for standalone Windows 11 machines accredited by the Defense Counterintelligence and Security Agency (DCSA). It provides comprehensive security event monitoring, logging, and reporting capabilities required for classified system compliance.

## Features

- **Security Event Collection**: Captures Windows Security events (logon/logoff, privilege use, policy changes)
- **User Activity Monitoring**: Tracks user sessions, authentication attempts, and account modifications
- **File System Auditing**: Monitors access to sensitive files and directories
- **USB/Removable Media Tracking**: Logs all removable storage device connections and data transfers
- **Process Execution Monitoring**: Records all application and process execution
- **Configuration Baseline Monitoring**: Detects unauthorized system configuration changes
- **Audit Log Protection**: Implements integrity verification to prevent log tampering
- **Compliance Reporting**: Generates reports for security reviews and audits

## Requirements

- Windows 11 Professional or Enterprise
- PowerShell 5.1 or later (included with Windows 11)
- Administrator privileges for installation and configuration
- Local audit policies must be configured (installer will configure these)

## Installation

1. Open PowerShell as Administrator
2. Navigate to the Auditor directory
3. Run the installer:
   ```powershell
   .\Install-Auditor.ps1
   ```

## Directory Structure

```
Auditor/
├── src/
│   ├── modules/           # Core auditing modules
│   ├── config/            # Configuration files
│   └── utils/             # Utility functions
├── logs/                  # Audit log storage
├── reports/               # Generated compliance reports
├── baselines/             # System configuration baselines
└── scripts/               # Maintenance and utility scripts
```

## Configuration

Edit `src/config/AuditConfig.psd1` to customize:
- Log retention periods
- Monitored directories
- Alert thresholds
- Report schedules

## Usage

### Start Auditing Service
```powershell
.\Start-Auditor.ps1
```

### Generate Compliance Report
```powershell
.\scripts\Generate-ComplianceReport.ps1
```

### View Current Audit Status
```powershell
.\scripts\Get-AuditStatus.ps1
```

## DCSA Compliance Notes

This software supports the following NISPOM/32 CFR Part 117 requirements:
- Chapter 9: Classified Information System Security
- Continuous monitoring and auditing requirements
- Audit trail retention (minimum 1 year recommended)
- Tamper-evident logging

## Security Considerations

- Audit logs are protected with cryptographic hashes
- Log files are stored with restricted ACLs
- Configuration changes are logged
- All timestamps use UTC for consistency

## License

For authorized use on DCSA-accredited systems only.
