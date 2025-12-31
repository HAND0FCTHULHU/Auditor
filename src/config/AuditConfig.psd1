@{
    # General Settings
    General = @{
        # Organization identifier for reports
        OrganizationName = "DCSA Accredited System"

        # System classification level
        ClassificationLevel = "CLASSIFIED"

        # Audit software version
        Version = "1.0.0"

        # Enable verbose logging for troubleshooting
        VerboseLogging = $false

        # UTC timestamps for all logs
        UseUTCTime = $true
    }

    # Log Storage Settings
    LogStorage = @{
        # Base path for audit logs
        BasePath = "C:\AuditLogs"

        # Log retention in days (DCSA recommends minimum 365 days)
        RetentionDays = 365

        # Maximum log file size in MB before rotation
        MaxLogSizeMB = 100

        # Enable log compression for archived logs
        CompressArchivedLogs = $true

        # Hash algorithm for log integrity (SHA256 recommended)
        HashAlgorithm = "SHA256"
    }

    # Security Event Collection
    SecurityEvents = @{
        # Enable security event collection
        Enabled = $true

        # Event IDs to monitor (critical security events)
        MonitoredEventIDs = @(
            # Logon Events
            4624,   # Successful logon
            4625,   # Failed logon
            4634,   # Logoff
            4647,   # User initiated logoff
            4648,   # Logon using explicit credentials
            4672,   # Special privileges assigned

            # Account Management
            4720,   # User account created
            4722,   # User account enabled
            4723,   # Password change attempt
            4724,   # Password reset attempt
            4725,   # User account disabled
            4726,   # User account deleted
            4738,   # User account changed
            4740,   # User account locked out

            # Security Policy Changes
            4704,   # User right assigned
            4705,   # User right removed
            4706,   # Trust created
            4713,   # Kerberos policy changed
            4719,   # System audit policy changed

            # Object Access
            4656,   # Handle to object requested
            4658,   # Handle to object closed
            4660,   # Object deleted
            4663,   # Object access attempt
            4670,   # Permissions changed

            # Privilege Use
            4673,   # Privileged service called
            4674,   # Operation attempted on privileged object

            # System Events
            4608,   # Windows starting up
            4609,   # Windows shutting down
            4616,   # System time changed

            # Audit Policy
            4902,   # Per-user audit policy table created
            4906,   # CrashOnAuditFail value changed
            4907,   # Auditing settings changed
            4912    # Per-user audit policy changed
        )

        # Poll interval in seconds
        PollIntervalSeconds = 30
    }

    # User Activity Monitoring
    UserActivity = @{
        # Enable user activity monitoring
        Enabled = $true

        # Track session duration
        TrackSessionDuration = $true

        # Track idle time
        TrackIdleTime = $true

        # Idle timeout threshold in minutes
        IdleTimeoutMinutes = 15

        # Log screen lock/unlock events
        LogScreenLock = $true
    }

    # File System Auditing
    FileSystem = @{
        # Enable file system auditing
        Enabled = $true

        # Directories to monitor (add classified file locations)
        MonitoredPaths = @(
            "C:\ClassifiedData",
            "C:\Users\*\Documents",
            "C:\Users\*\Desktop",
            "C:\ProgramData"
        )

        # File extensions to monitor closely
        SensitiveExtensions = @(
            ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
            ".pdf", ".txt", ".rtf", ".csv",
            ".zip", ".7z", ".rar",
            ".exe", ".msi", ".bat", ".ps1", ".cmd"
        )

        # Operations to audit
        AuditOperations = @(
            "Read",
            "Write",
            "Delete",
            "Rename",
            "PermissionChange"
        )
    }

    # USB/Removable Media Monitoring
    RemovableMedia = @{
        # Enable removable media monitoring
        Enabled = $true

        # Log device connections
        LogDeviceConnections = $true

        # Log file transfers to/from removable media
        LogFileTransfers = $true

        # Alert on unauthorized devices
        AlertOnUnauthorized = $true

        # List of authorized device IDs (empty = log all)
        AuthorizedDevices = @()
    }

    # Process Execution Monitoring
    ProcessMonitoring = @{
        # Enable process monitoring
        Enabled = $true

        # Log all process starts
        LogProcessStart = $true

        # Log process termination
        LogProcessEnd = $true

        # Log command line arguments
        LogCommandLine = $true

        # Processes to always monitor
        WatchedProcesses = @(
            "cmd.exe",
            "powershell.exe",
            "pwsh.exe",
            "wscript.exe",
            "cscript.exe",
            "mshta.exe",
            "reg.exe",
            "regedit.exe",
            "mmc.exe",
            "taskmgr.exe"
        )
    }

    # Configuration Baseline Monitoring
    BaselineMonitoring = @{
        # Enable baseline monitoring
        Enabled = $true

        # Check interval in minutes
        CheckIntervalMinutes = 60

        # Items to include in baseline
        BaselineItems = @(
            "LocalUsers",
            "LocalGroups",
            "Services",
            "ScheduledTasks",
            "InstalledSoftware",
            "NetworkConfiguration",
            "FirewallRules",
            "AuditPolicy",
            "SecurityPolicy"
        )

        # Alert on baseline deviation
        AlertOnDeviation = $true
    }

    # Reporting Settings
    Reporting = @{
        # Report output path
        OutputPath = "C:\AuditLogs\Reports"

        # Generate daily summary
        DailySummary = $true

        # Generate weekly compliance report
        WeeklyComplianceReport = $true

        # Report formats to generate
        Formats = @("HTML", "CSV")

        # Email notifications (if configured)
        EmailNotifications = $false
        SMTPServer = ""
        EmailRecipients = @()
    }

    # Alerting Settings
    Alerting = @{
        # Enable real-time alerts
        Enabled = $true

        # Failed logon threshold (alert after N failures)
        FailedLogonThreshold = 3

        # Time window for failed logon threshold (minutes)
        FailedLogonWindowMinutes = 15

        # Alert on after-hours activity
        AfterHoursAlerts = $true

        # Business hours (24-hour format)
        BusinessHoursStart = 6
        BusinessHoursEnd = 18

        # Write alerts to Windows Event Log
        WriteToEventLog = $true

        # Custom event log name
        EventLogName = "DCSA-Auditor"
    }
}
