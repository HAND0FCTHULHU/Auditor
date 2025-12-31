#Requires -Version 5.1
<#
.SYNOPSIS
    Report Generator Module for DCSA Auditing Software

.DESCRIPTION
    Generates comprehensive compliance reports including daily summaries,
    weekly reports, and on-demand audit reports for security reviews.
#>

# Import utilities
$modulePath = Split-Path -Parent $PSScriptRoot
Import-Module "$modulePath\utils\AuditUtilities.psm1" -Force

function New-DailySummaryReport {
    <#
    .SYNOPSIS
        Generates a daily summary report of all audit activity
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [datetime]$Date = (Get-Date).Date,

        [Parameter()]
        [string[]]$Formats = @("HTML", "CSV")
    )

    $config = Get-AuditConfig
    $reportPath = $config.Reporting.OutputPath

    if (-not (Test-Path $reportPath)) {
        New-Item -Path $reportPath -ItemType Directory -Force | Out-Null
    }

    $startTime = $Date
    $endTime = $Date.AddDays(1).AddSeconds(-1)

    Write-AuditLog -Category "System" -Message "Generating daily summary report for $($Date.ToString('yyyy-MM-dd'))" -Severity "Information"

    # Collect data from all modules
    $reportData = @{
        ReportType = "Daily Summary"
        GeneratedAt = Get-AuditTimestamp
        ReportDate = $Date.ToString("yyyy-MM-dd")
        ComputerName = $env:COMPUTERNAME
        Organization = $config.General.OrganizationName
        Classification = $config.General.ClassificationLevel
        Sections = @{}
    }

    # Security Events Summary
    try {
        Import-Module "$modulePath\modules\SecurityEventCollector.psm1" -Force -ErrorAction SilentlyContinue
        $securitySummary = Get-SecurityEventSummary -StartTime $startTime -EndTime $endTime
        $reportData.Sections["SecurityEvents"] = $securitySummary
    } catch { }

    # User Activity Summary
    try {
        Import-Module "$modulePath\modules\UserActivityMonitor.psm1" -Force -ErrorAction SilentlyContinue
        $userSummary = Get-UserActivitySummary -StartTime $startTime -EndTime $endTime
        $reportData.Sections["UserActivity"] = $userSummary
    } catch { }

    # File System Summary
    try {
        Import-Module "$modulePath\modules\FileSystemAuditor.psm1" -Force -ErrorAction SilentlyContinue
        $fileSummary = Get-FileSystemAuditSummary -StartTime $startTime -EndTime $endTime
        $reportData.Sections["FileSystem"] = $fileSummary
    } catch { }

    # Removable Media Summary
    try {
        Import-Module "$modulePath\modules\RemovableMediaMonitor.psm1" -Force -ErrorAction SilentlyContinue
        $mediaSummary = Get-RemovableMediaSummary -StartTime $startTime -EndTime $endTime
        $reportData.Sections["RemovableMedia"] = $mediaSummary
    } catch { }

    # Process Summary
    try {
        Import-Module "$modulePath\modules\ProcessMonitor.psm1" -Force -ErrorAction SilentlyContinue
        $processSummary = Get-ProcessSummary -StartTime $startTime -EndTime $endTime
        $reportData.Sections["Processes"] = $processSummary
    } catch { }

    # Baseline Status
    try {
        Import-Module "$modulePath\modules\BaselineMonitor.psm1" -Force -ErrorAction SilentlyContinue
        $baselineSummary = Get-BaselineSummary
        $reportData.Sections["Baseline"] = $baselineSummary
    } catch { }

    # Log Integrity Status
    try {
        $integrityResults = Verify-LogIntegrity
        $reportData.Sections["LogIntegrity"] = @{
            TotalFiles = $integrityResults.Count
            ValidFiles = ($integrityResults | Where-Object { $_.IntegrityStatus -eq "VALID" }).Count
            CompromisedFiles = ($integrityResults | Where-Object { $_.IntegrityStatus -eq "COMPROMISED" }).Count
        }
    } catch { }

    # Generate reports in requested formats
    $dateStr = $Date.ToString("yyyy-MM-dd")

    foreach ($format in $Formats) {
        $outputFile = "$reportPath\DailySummary_$dateStr.$($format.ToLower())"

        switch ($format.ToUpper()) {
            "HTML" {
                New-HtmlReport -ReportData $reportData -OutputPath $outputFile
            }
            "CSV" {
                New-CsvReport -ReportData $reportData -OutputPath $outputFile
            }
            "JSON" {
                $reportData | ConvertTo-Json -Depth 10 | Out-File -FilePath $outputFile -Encoding UTF8
            }
        }

        Write-AuditLog -Category "System" -Message "Daily report generated: $outputFile" -Severity "Information"
    }

    return $reportData
}

function New-WeeklyComplianceReport {
    <#
    .SYNOPSIS
        Generates a weekly compliance report for security reviews
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [datetime]$WeekEndDate = (Get-Date).Date,

        [Parameter()]
        [string[]]$Formats = @("HTML")
    )

    $config = Get-AuditConfig
    $reportPath = $config.Reporting.OutputPath

    if (-not (Test-Path $reportPath)) {
        New-Item -Path $reportPath -ItemType Directory -Force | Out-Null
    }

    $startTime = $WeekEndDate.AddDays(-7)
    $endTime = $WeekEndDate.AddDays(1).AddSeconds(-1)

    Write-AuditLog -Category "System" -Message "Generating weekly compliance report" -Severity "Information"

    $reportData = @{
        ReportType = "Weekly Compliance Report"
        GeneratedAt = Get-AuditTimestamp
        ReportPeriod = @{
            Start = $startTime.ToString("yyyy-MM-dd")
            End = $WeekEndDate.ToString("yyyy-MM-dd")
        }
        ComputerName = $env:COMPUTERNAME
        Organization = $config.General.OrganizationName
        Classification = $config.General.ClassificationLevel
        ComplianceStatus = "PENDING REVIEW"
        Sections = @{}
        Alerts = @()
        Findings = @()
    }

    # Collect comprehensive data
    try {
        Import-Module "$modulePath\modules\SecurityEventCollector.psm1" -Force -ErrorAction SilentlyContinue
        $securitySummary = Get-SecurityEventSummary -StartTime $startTime -EndTime $endTime
        $reportData.Sections["SecurityEvents"] = $securitySummary

        # Flag findings
        if ($securitySummary.FailedLogons -gt 50) {
            $reportData.Findings += @{
                Category = "Security"
                Severity = "Warning"
                Finding = "High number of failed logon attempts: $($securitySummary.FailedLogons)"
                Recommendation = "Review failed logon events for potential brute force attempts"
            }
        }
        if ($securitySummary.PolicyChanges -gt 0) {
            $reportData.Findings += @{
                Category = "Security"
                Severity = "Information"
                Finding = "Security policy changes detected: $($securitySummary.PolicyChanges)"
                Recommendation = "Verify all policy changes were authorized"
            }
        }
    } catch { }

    # User Activity
    try {
        Import-Module "$modulePath\modules\UserActivityMonitor.psm1" -Force -ErrorAction SilentlyContinue
        $userSummary = Get-UserActivitySummary -StartTime $startTime -EndTime $endTime
        $reportData.Sections["UserActivity"] = $userSummary
    } catch { }

    # Removable Media
    try {
        Import-Module "$modulePath\modules\RemovableMediaMonitor.psm1" -Force -ErrorAction SilentlyContinue
        $mediaSummary = Get-RemovableMediaSummary -StartTime $startTime -EndTime $endTime
        $reportData.Sections["RemovableMedia"] = $mediaSummary

        if ($mediaSummary.UnauthorizedDevices -gt 0) {
            $reportData.Findings += @{
                Category = "RemovableMedia"
                Severity = "Critical"
                Finding = "Unauthorized removable devices detected: $($mediaSummary.UnauthorizedDevices)"
                Recommendation = "Investigate all unauthorized device connections immediately"
            }
        }
    } catch { }

    # Baseline Compliance
    try {
        Import-Module "$modulePath\modules\BaselineMonitor.psm1" -Force -ErrorAction SilentlyContinue
        $deviations = Compare-SystemToBaseline
        $reportData.Sections["BaselineDeviations"] = @{
            DeviationCount = $deviations.Count
            Deviations = $deviations
        }

        if ($deviations.Count -gt 0) {
            $reportData.Findings += @{
                Category = "Baseline"
                Severity = "Warning"
                Finding = "Configuration baseline deviations detected: $($deviations.Count)"
                Recommendation = "Review and authorize all configuration changes or restore baseline"
            }
        }
    } catch { }

    # Log Integrity
    try {
        $integrityResults = Verify-LogIntegrity
        $compromisedLogs = $integrityResults | Where-Object { $_.IntegrityStatus -eq "COMPROMISED" }

        $reportData.Sections["LogIntegrity"] = @{
            TotalFiles = $integrityResults.Count
            ValidFiles = ($integrityResults | Where-Object { $_.IntegrityStatus -eq "VALID" }).Count
            CompromisedFiles = $compromisedLogs.Count
        }

        if ($compromisedLogs.Count -gt 0) {
            $reportData.Findings += @{
                Category = "LogIntegrity"
                Severity = "Critical"
                Finding = "Compromised audit log files detected: $($compromisedLogs.Count)"
                Recommendation = "Investigate potential log tampering immediately"
            }
        }
    } catch { }

    # Get alerts from the week
    $alertLogPath = "$($config.LogStorage.BasePath)\Alert"
    if (Test-Path $alertLogPath) {
        $alertFiles = Get-ChildItem -Path $alertLogPath -Filter "*.log" -ErrorAction SilentlyContinue
        foreach ($file in $alertFiles) {
            $lines = Get-Content -Path $file.FullName -ErrorAction SilentlyContinue
            foreach ($line in $lines) {
                if ($line -match '^(.+)\|HASH:') {
                    try {
                        $entry = $Matches[1] | ConvertFrom-Json
                        $eventTime = [datetime]::Parse($entry.Timestamp)
                        if ($eventTime -ge $startTime -and $eventTime -le $endTime) {
                            $reportData.Alerts += $entry
                        }
                    } catch { }
                }
            }
        }
    }

    # Determine overall compliance status
    $criticalFindings = $reportData.Findings | Where-Object { $_.Severity -eq "Critical" }
    if ($criticalFindings.Count -gt 0) {
        $reportData.ComplianceStatus = "NON-COMPLIANT - CRITICAL FINDINGS"
    } elseif ($reportData.Findings.Count -gt 0) {
        $reportData.ComplianceStatus = "REQUIRES ATTENTION"
    } else {
        $reportData.ComplianceStatus = "COMPLIANT"
    }

    # Generate reports
    $weekStr = $WeekEndDate.ToString("yyyy-MM-dd")

    foreach ($format in $Formats) {
        $outputFile = "$reportPath\WeeklyCompliance_$weekStr.$($format.ToLower())"

        switch ($format.ToUpper()) {
            "HTML" {
                New-ComplianceHtmlReport -ReportData $reportData -OutputPath $outputFile
            }
            "CSV" {
                New-CsvReport -ReportData $reportData -OutputPath $outputFile
            }
            "JSON" {
                $reportData | ConvertTo-Json -Depth 10 | Out-File -FilePath $outputFile -Encoding UTF8
            }
        }

        Write-AuditLog -Category "System" -Message "Weekly compliance report generated: $outputFile" -Severity "Information"
    }

    return $reportData
}

function New-HtmlReport {
    <#
    .SYNOPSIS
        Generates an HTML report from report data
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$ReportData,

        [Parameter(Mandatory)]
        [string]$OutputPath
    )

    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>$($ReportData.ReportType) - $($ReportData.ComputerName)</title>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; margin: 0; padding: 0; background-color: #f5f5f5; }
        .classification-banner { background-color: #c53030; color: white; padding: 10px; text-align: center; font-weight: bold; font-size: 14px; }
        .header { background-color: #1a365d; color: white; padding: 30px; }
        .header h1 { margin: 0 0 10px 0; }
        .header p { margin: 5px 0; opacity: 0.9; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .section { background: white; border-radius: 8px; padding: 20px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .section h2 { color: #2c5282; margin-top: 0; border-bottom: 2px solid #e2e8f0; padding-bottom: 10px; }
        .metric-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; }
        .metric-card { background: #f7fafc; border-radius: 6px; padding: 15px; text-align: center; }
        .metric-value { font-size: 32px; font-weight: bold; color: #2c5282; }
        .metric-label { color: #718096; font-size: 14px; }
        table { width: 100%; border-collapse: collapse; margin-top: 15px; }
        th { background-color: #2c5282; color: white; padding: 12px; text-align: left; }
        td { padding: 10px; border-bottom: 1px solid #e2e8f0; }
        tr:hover { background-color: #f7fafc; }
        .severity-Critical { color: #c53030; font-weight: bold; }
        .severity-Warning { color: #dd6b20; }
        .severity-Information { color: #2b6cb0; }
        .status-compliant { color: #38a169; font-weight: bold; }
        .status-attention { color: #dd6b20; font-weight: bold; }
        .status-noncompliant { color: #c53030; font-weight: bold; }
        .footer { text-align: center; padding: 20px; color: #718096; font-size: 12px; }
    </style>
</head>
<body>
    <div class="classification-banner">$($ReportData.Classification)</div>
    <div class="header">
        <div class="container">
            <h1>$($ReportData.ReportType)</h1>
            <p>System: $($ReportData.ComputerName) | Organization: $($ReportData.Organization)</p>
            <p>Generated: $($ReportData.GeneratedAt)</p>
            $(if ($ReportData.ReportDate) { "<p>Report Date: $($ReportData.ReportDate)</p>" })
            $(if ($ReportData.ReportPeriod) { "<p>Period: $($ReportData.ReportPeriod.Start) to $($ReportData.ReportPeriod.End)</p>" })
        </div>
    </div>
    <div class="container">
"@

    # Add sections based on data
    if ($ReportData.Sections.SecurityEvents) {
        $sec = $ReportData.Sections.SecurityEvents
        $html += @"
        <div class="section">
            <h2>Security Events</h2>
            <div class="metric-grid">
                <div class="metric-card">
                    <div class="metric-value">$($sec.TotalEvents)</div>
                    <div class="metric-label">Total Events</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value">$($sec.SuccessfulLogons)</div>
                    <div class="metric-label">Successful Logons</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value" style="color: $(if ($sec.FailedLogons -gt 10) { '#c53030' } else { '#2c5282' })">$($sec.FailedLogons)</div>
                    <div class="metric-label">Failed Logons</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value">$($sec.PrivilegeUse)</div>
                    <div class="metric-label">Privilege Use Events</div>
                </div>
            </div>
        </div>
"@
    }

    if ($ReportData.Sections.UserActivity) {
        $ua = $ReportData.Sections.UserActivity
        $html += @"
        <div class="section">
            <h2>User Activity</h2>
            <div class="metric-grid">
                <div class="metric-card">
                    <div class="metric-value">$($ua.TotalLogons)</div>
                    <div class="metric-label">Total Logons</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value">$($ua.UniqueUsers)</div>
                    <div class="metric-label">Unique Users</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value" style="color: $(if ($ua.FailedLogons -gt 10) { '#c53030' } else { '#2c5282' })">$($ua.FailedLogons)</div>
                    <div class="metric-label">Failed Logons</div>
                </div>
            </div>
        </div>
"@
    }

    if ($ReportData.Sections.RemovableMedia) {
        $rm = $ReportData.Sections.RemovableMedia
        $html += @"
        <div class="section">
            <h2>Removable Media Activity</h2>
            <div class="metric-grid">
                <div class="metric-card">
                    <div class="metric-value">$($rm.DeviceConnections)</div>
                    <div class="metric-label">Device Connections</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value">$($rm.UniqueDevices)</div>
                    <div class="metric-label">Unique Devices</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value" style="color: $(if ($rm.UnauthorizedDevices -gt 0) { '#c53030' } else { '#38a169' })">$($rm.UnauthorizedDevices)</div>
                    <div class="metric-label">Unauthorized Devices</div>
                </div>
            </div>
        </div>
"@
    }

    if ($ReportData.Sections.LogIntegrity) {
        $li = $ReportData.Sections.LogIntegrity
        $html += @"
        <div class="section">
            <h2>Log Integrity</h2>
            <div class="metric-grid">
                <div class="metric-card">
                    <div class="metric-value">$($li.TotalFiles)</div>
                    <div class="metric-label">Total Log Files</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value" style="color: #38a169">$($li.ValidFiles)</div>
                    <div class="metric-label">Valid Files</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value" style="color: $(if ($li.CompromisedFiles -gt 0) { '#c53030' } else { '#38a169' })">$($li.CompromisedFiles)</div>
                    <div class="metric-label">Compromised Files</div>
                </div>
            </div>
        </div>
"@
    }

    $html += @"
    </div>
    <div class="footer">
        <p>DCSA Auditor | This report contains security-sensitive information</p>
    </div>
    <div class="classification-banner">$($ReportData.Classification)</div>
</body>
</html>
"@

    $html | Out-File -FilePath $OutputPath -Encoding UTF8
}

function New-ComplianceHtmlReport {
    <#
    .SYNOPSIS
        Generates a compliance-focused HTML report
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$ReportData,

        [Parameter(Mandatory)]
        [string]$OutputPath
    )

    $statusClass = switch -Wildcard ($ReportData.ComplianceStatus) {
        "*COMPLIANT*" { if ($ReportData.ComplianceStatus -match "NON-COMPLIANT") { "status-noncompliant" } else { "status-compliant" } }
        "*ATTENTION*" { "status-attention" }
        default { "status-attention" }
    }

    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Weekly Compliance Report - $($ReportData.ComputerName)</title>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; margin: 0; padding: 0; background-color: #f5f5f5; }
        .classification-banner { background-color: #c53030; color: white; padding: 10px; text-align: center; font-weight: bold; font-size: 14px; }
        .header { background-color: #1a365d; color: white; padding: 30px; }
        .header h1 { margin: 0 0 10px 0; }
        .header p { margin: 5px 0; opacity: 0.9; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .compliance-status { font-size: 24px; padding: 20px; border-radius: 8px; text-align: center; margin-bottom: 20px; }
        .status-compliant { background-color: #c6f6d5; color: #22543d; }
        .status-attention { background-color: #feebc8; color: #744210; }
        .status-noncompliant { background-color: #fed7d7; color: #742a2a; }
        .section { background: white; border-radius: 8px; padding: 20px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .section h2 { color: #2c5282; margin-top: 0; border-bottom: 2px solid #e2e8f0; padding-bottom: 10px; }
        .finding { padding: 15px; border-left: 4px solid; margin-bottom: 10px; background: #f7fafc; }
        .finding-critical { border-color: #c53030; }
        .finding-warning { border-color: #dd6b20; }
        .finding-info { border-color: #2b6cb0; }
        .finding h4 { margin: 0 0 5px 0; }
        .finding p { margin: 5px 0; }
        table { width: 100%; border-collapse: collapse; margin-top: 15px; }
        th { background-color: #2c5282; color: white; padding: 12px; text-align: left; }
        td { padding: 10px; border-bottom: 1px solid #e2e8f0; }
        .footer { text-align: center; padding: 20px; color: #718096; font-size: 12px; }
        .signature-block { margin-top: 40px; border-top: 1px solid #e2e8f0; padding-top: 20px; }
        .signature-line { border-bottom: 1px solid #000; width: 300px; margin: 30px 0 5px 0; }
    </style>
</head>
<body>
    <div class="classification-banner">$($ReportData.Classification)</div>
    <div class="header">
        <div class="container">
            <h1>Weekly Compliance Report</h1>
            <p>System: $($ReportData.ComputerName) | Organization: $($ReportData.Organization)</p>
            <p>Report Period: $($ReportData.ReportPeriod.Start) to $($ReportData.ReportPeriod.End)</p>
            <p>Generated: $($ReportData.GeneratedAt)</p>
        </div>
    </div>
    <div class="container">
        <div class="compliance-status $statusClass">
            <strong>Compliance Status:</strong> $($ReportData.ComplianceStatus)
        </div>
"@

    # Findings section
    if ($ReportData.Findings.Count -gt 0) {
        $html += @"
        <div class="section">
            <h2>Findings ($($ReportData.Findings.Count))</h2>
"@
        foreach ($finding in $ReportData.Findings) {
            $findingClass = switch ($finding.Severity) {
                "Critical" { "finding-critical" }
                "Warning" { "finding-warning" }
                default { "finding-info" }
            }
            $html += @"
            <div class="finding $findingClass">
                <h4>[$($finding.Severity)] $($finding.Category)</h4>
                <p><strong>Finding:</strong> $($finding.Finding)</p>
                <p><strong>Recommendation:</strong> $($finding.Recommendation)</p>
            </div>
"@
        }
        $html += "</div>"
    }

    # Alerts section
    if ($ReportData.Alerts.Count -gt 0) {
        $html += @"
        <div class="section">
            <h2>Alerts ($($ReportData.Alerts.Count))</h2>
            <table>
                <tr><th>Time</th><th>Severity</th><th>Message</th></tr>
"@
        foreach ($alert in ($ReportData.Alerts | Select-Object -First 50)) {
            $html += "<tr><td>$($alert.Timestamp)</td><td>$($alert.Severity)</td><td>$($alert.Message)</td></tr>"
        }
        $html += "</table></div>"
    }

    # Signature block
    $html += @"
        <div class="section">
            <h2>Review Certification</h2>
            <p>I have reviewed this security audit report and the findings contained herein.</p>
            <div class="signature-block">
                <div class="signature-line"></div>
                <p>Information System Security Manager (ISSM) Signature / Date</p>
                <div class="signature-line"></div>
                <p>Facility Security Officer (FSO) Signature / Date (if applicable)</p>
            </div>
        </div>
    </div>
    <div class="footer">
        <p>DCSA Auditor v$((Get-AuditConfig).General.Version) | This report contains security-sensitive information</p>
    </div>
    <div class="classification-banner">$($ReportData.Classification)</div>
</body>
</html>
"@

    $html | Out-File -FilePath $OutputPath -Encoding UTF8
}

function New-CsvReport {
    <#
    .SYNOPSIS
        Generates CSV exports of report data
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$ReportData,

        [Parameter(Mandatory)]
        [string]$OutputPath
    )

    $basePath = [System.IO.Path]::GetDirectoryName($OutputPath)
    $baseName = [System.IO.Path]::GetFileNameWithoutExtension($OutputPath)

    # Export each section as a separate CSV
    foreach ($sectionName in $ReportData.Sections.Keys) {
        $sectionData = $ReportData.Sections[$sectionName]
        $csvPath = "$basePath\$($baseName)_$sectionName.csv"

        if ($sectionData -is [array]) {
            $sectionData | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
        } elseif ($sectionData -is [hashtable] -or $sectionData -is [PSCustomObject]) {
            [PSCustomObject]$sectionData | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
        }
    }

    # Export findings if present
    if ($ReportData.Findings) {
        $ReportData.Findings | Export-Csv -Path "$basePath\$($baseName)_Findings.csv" -NoTypeInformation -Encoding UTF8
    }

    # Export alerts if present
    if ($ReportData.Alerts) {
        $ReportData.Alerts | Export-Csv -Path "$basePath\$($baseName)_Alerts.csv" -NoTypeInformation -Encoding UTF8
    }
}

function Get-AuditReportList {
    <#
    .SYNOPSIS
        Lists all generated audit reports
    #>
    [CmdletBinding()]
    param()

    $config = Get-AuditConfig
    $reportPath = $config.Reporting.OutputPath

    if (-not (Test-Path $reportPath)) {
        return @()
    }

    Get-ChildItem -Path $reportPath -File | ForEach-Object {
        [PSCustomObject]@{
            Name = $_.Name
            Type = if ($_.Name -match "Daily") { "Daily Summary" } elseif ($_.Name -match "Weekly") { "Weekly Compliance" } else { "Other" }
            Format = $_.Extension.TrimStart(".")
            Size = $_.Length
            Created = $_.CreationTime
            Path = $_.FullName
        }
    } | Sort-Object Created -Descending
}

# Export functions
Export-ModuleMember -Function @(
    'New-DailySummaryReport',
    'New-WeeklyComplianceReport',
    'New-HtmlReport',
    'New-ComplianceHtmlReport',
    'New-CsvReport',
    'Get-AuditReportList'
)
