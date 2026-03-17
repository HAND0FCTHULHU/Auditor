#Requires -Version 5.1
<#
.SYNOPSIS
    Verifies the integrity of audit log files

.DESCRIPTION
    Checks all audit log files for tampering by validating cryptographic hashes.

.PARAMETER Detailed
    Show detailed information including specific tampered lines

.EXAMPLE
    .\Verify-LogIntegrity.ps1 -Detailed
#>

[CmdletBinding()]
param(
    [Parameter()]
    [switch]$Detailed
)

$scriptRoot = Split-Path -Parent $PSScriptRoot
Import-Module "$scriptRoot\src\utils\AuditUtilities.psm1" -Force

Write-Host "`n=== DCSA AUDITOR - LOG INTEGRITY VERIFICATION ===" -ForegroundColor Cyan
Write-Host "Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray

$config = Get-AuditConfig
Write-Host "Log Path: $($config.LogStorage.BasePath)" -ForegroundColor Gray
Write-Host "Hash Algorithm: $($config.LogStorage.HashAlgorithm)" -ForegroundColor Gray

Write-Host "`nVerifying log files..." -ForegroundColor Yellow

$results = Verify-LogIntegrity -Detailed:$Detailed

$noLogsCount = ($results | Where-Object { $_.IntegrityStatus -in @("NO_LOGS", "EMPTY") }).Count
$validCount = ($results | Where-Object { $_.IntegrityStatus -eq "VALID" }).Count
$compromisedCount = ($results | Where-Object { $_.IntegrityStatus -eq "COMPROMISED" }).Count
$totalCount = $results.Count
$actualLogCount = $totalCount - $noLogsCount

Write-Host "`n--- Results ---" -ForegroundColor Yellow

if ($noLogsCount -eq $totalCount) {
    Write-Host "Status: No audit logs found yet" -ForegroundColor Cyan
    Write-Host "This is normal on first run. Logs will be created as events occur." -ForegroundColor Gray
} else {
    Write-Host "Total Log Files: $actualLogCount"
    Write-Host "Valid Files: $validCount" -ForegroundColor Green
    if ($compromisedCount -gt 0) {
        Write-Host "Compromised Files: $compromisedCount" -ForegroundColor Red
    } else {
        Write-Host "Compromised Files: $compromisedCount" -ForegroundColor Green
    }
    if ($noLogsCount -gt 0) {
        Write-Host "Empty/Pending: $noLogsCount" -ForegroundColor Gray
    }

    Write-Host "`n--- File Details ---" -ForegroundColor Yellow
    foreach ($result in $results) {
        # Skip NO_LOGS placeholder entries
        if ($result.IntegrityStatus -in @("NO_LOGS")) { continue }

        $statusColor = switch ($result.IntegrityStatus) {
            "VALID" { "Green" }
            "EMPTY" { "Gray" }
            "COMPROMISED" { "Red" }
            default { "Yellow" }
        }
        $fileName = Split-Path $result.FilePath -Leaf

        Write-Host "[$($result.IntegrityStatus)] $fileName" -ForegroundColor $statusColor

        if ($result.IntegrityStatus -notin @("EMPTY", "NO_LOGS")) {
            Write-Host "    Total Lines: $($result.TotalLines) | Valid: $($result.ValidLines) | Invalid: $($result.InvalidLines)"
        }

        if ($Detailed -and $result.TamperedLines.Count -gt 0) {
            Write-Host "    Tampered Lines:" -ForegroundColor Red
            foreach ($line in $result.TamperedLines | Select-Object -First 5) {
                $content = if ($line.Content.Length -gt 80) { $line.Content.Substring(0, 80) + "..." } else { $line.Content }
                Write-Host "      Line $($line.LineNumber): $content" -ForegroundColor Red
            }
            if ($result.TamperedLines.Count -gt 5) {
                Write-Host "      ... and $($result.TamperedLines.Count - 5) more" -ForegroundColor Red
            }
        }
    }
}

Write-Host "`n--- Summary ---" -ForegroundColor Yellow
if ($noLogsCount -eq $totalCount) {
    Write-Host "RESULT: NO LOGS TO VERIFY (first run)" -ForegroundColor Cyan
} elseif ($compromisedCount -eq 0) {
    Write-Host "RESULT: ALL LOGS VERIFIED - NO TAMPERING DETECTED" -ForegroundColor Green
} else {
    Write-Host "RESULT: LOG TAMPERING DETECTED - INVESTIGATION REQUIRED" -ForegroundColor Red
    Write-Host "`nRecommended Actions:" -ForegroundColor Yellow
    Write-Host "1. Preserve compromised log files as evidence"
    Write-Host "2. Report incident to ISSM/FSO immediately"
    Write-Host "3. Check system for unauthorized access"
    Write-Host "4. Review security events around the modification times"
}

Write-Host "`n=== END VERIFICATION ===" -ForegroundColor Cyan
