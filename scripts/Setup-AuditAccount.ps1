#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Sets up a dedicated audit account for DCSA compliance

.DESCRIPTION
    Creates or configures a local user account with appropriate permissions
    to run the DCSA Auditor. The account is granted:
    - Administrator rights (required for audit policy access)
    - Read access to Security Event Log
    - Access to audit log directories

.PARAMETER AccountName
    Name for the audit account. Default: AuditAdmin

.PARAMETER Description
    Description for the account. Default: DCSA Auditor Service Account

.PARAMETER ExistingAccount
    If specified, configures an existing account instead of creating a new one

.EXAMPLE
    .\Setup-AuditAccount.ps1
    Creates a new AuditAdmin account

.EXAMPLE
    .\Setup-AuditAccount.ps1 -AccountName "DCSSAuditor" -ExistingAccount
    Configures an existing account named DCSSAuditor
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$AccountName = "AuditAdmin",

    [Parameter()]
    [string]$Description = "DCSA Auditor Service Account",

    [Parameter()]
    [switch]$ExistingAccount
)

Write-Host "`n=== DCSA AUDITOR - AUDIT ACCOUNT SETUP ===" -ForegroundColor Cyan

# Check if running as admin
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[ERROR] This script must be run as Administrator" -ForegroundColor Red
    exit 1
}

# Check if account exists
$existingUser = Get-LocalUser -Name $AccountName -ErrorAction SilentlyContinue

if ($ExistingAccount) {
    if (-not $existingUser) {
        Write-Host "[ERROR] Account '$AccountName' does not exist" -ForegroundColor Red
        exit 1
    }
    Write-Host "[INFO] Configuring existing account: $AccountName" -ForegroundColor Cyan
} else {
    if ($existingUser) {
        Write-Host "[ERROR] Account '$AccountName' already exists. Use -ExistingAccount to configure it." -ForegroundColor Red
        exit 1
    }

    # Create the account
    Write-Host "[*] Creating local account: $AccountName" -ForegroundColor Yellow

    # Generate a secure random password
    Add-Type -AssemblyName System.Web
    $password = [System.Web.Security.Membership]::GeneratePassword(16, 4)
    $securePassword = ConvertTo-SecureString $password -AsPlainText -Force

    try {
        New-LocalUser -Name $AccountName -Password $securePassword -Description $Description -PasswordNeverExpires -UserMayNotChangePassword -ErrorAction Stop | Out-Null
        Write-Host "[+] Account created successfully" -ForegroundColor Green

        Write-Host "`n" + "=" * 50 -ForegroundColor Yellow
        Write-Host "IMPORTANT: Save this password securely!" -ForegroundColor Red
        Write-Host "Account: $AccountName" -ForegroundColor Cyan
        Write-Host "Password: $password" -ForegroundColor Cyan
        Write-Host "=" * 50 -ForegroundColor Yellow
        Write-Host "This password will NOT be shown again.`n" -ForegroundColor Red
    } catch {
        Write-Host "[ERROR] Failed to create account: $_" -ForegroundColor Red
        exit 1
    }
}

# Add to Administrators group
Write-Host "[*] Adding to Administrators group..." -ForegroundColor Yellow
try {
    $adminGroup = Get-LocalGroup -Name "Administrators"
    $isMember = Get-LocalGroupMember -Group $adminGroup -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "*\$AccountName" }

    if (-not $isMember) {
        Add-LocalGroupMember -Group "Administrators" -Member $AccountName -ErrorAction Stop
        Write-Host "[+] Added to Administrators group" -ForegroundColor Green
    } else {
        Write-Host "[+] Already a member of Administrators group" -ForegroundColor Green
    }
} catch {
    Write-Host "[ERROR] Failed to add to Administrators group: $_" -ForegroundColor Red
}

# Add to Event Log Readers group
Write-Host "[*] Adding to Event Log Readers group..." -ForegroundColor Yellow
try {
    $eventLogGroup = Get-LocalGroup -Name "Event Log Readers" -ErrorAction SilentlyContinue
    if ($eventLogGroup) {
        $isMember = Get-LocalGroupMember -Group $eventLogGroup -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "*\$AccountName" }
        if (-not $isMember) {
            Add-LocalGroupMember -Group "Event Log Readers" -Member $AccountName -ErrorAction Stop
            Write-Host "[+] Added to Event Log Readers group" -ForegroundColor Green
        } else {
            Write-Host "[+] Already a member of Event Log Readers group" -ForegroundColor Green
        }
    }
} catch {
    Write-Host "[WARN] Could not add to Event Log Readers group (may not exist): $_" -ForegroundColor Yellow
}

# Grant Logon as a batch job right (for scheduled tasks)
Write-Host "[*] Granting 'Log on as a batch job' right..." -ForegroundColor Yellow
try {
    $tempFile = [System.IO.Path]::GetTempFileName()
    secedit /export /cfg $tempFile /quiet

    $content = Get-Content $tempFile -Raw
    if ($content -match 'SeBatchLogonRight\s*=\s*(.*)') {
        $currentValue = $Matches[1]
        if ($currentValue -notmatch $AccountName) {
            $newValue = "$currentValue,$AccountName"
            $content = $content -replace "SeBatchLogonRight\s*=\s*.*", "SeBatchLogonRight = $newValue"
        }
    } else {
        $content += "`nSeBatchLogonRight = $AccountName"
    }

    $content | Set-Content $tempFile
    secedit /configure /db secedit.sdb /cfg $tempFile /quiet
    Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
    Remove-Item "secedit.sdb" -Force -ErrorAction SilentlyContinue

    Write-Host "[+] Batch logon right granted" -ForegroundColor Green
} catch {
    Write-Host "[WARN] Could not grant batch logon right: $_" -ForegroundColor Yellow
}

# Set permissions on audit directories
Write-Host "[*] Setting permissions on audit directories..." -ForegroundColor Yellow
$auditDirs = @(
    "C:\AuditLogs",
    "C:\Program Files\DCSA-Auditor"
)

foreach ($dir in $auditDirs) {
    if (Test-Path $dir) {
        try {
            $acl = Get-Acl -Path $dir
            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                $AccountName,
                "FullControl",
                "ContainerInherit,ObjectInherit",
                "None",
                "Allow"
            )
            $acl.AddAccessRule($rule)
            Set-Acl -Path $dir -AclObject $acl
            Write-Host "[+] Permissions set on: $dir" -ForegroundColor Green
        } catch {
            Write-Host "[WARN] Could not set permissions on $dir : $_" -ForegroundColor Yellow
        }
    } else {
        Write-Host "[INFO] Directory not found (will be created during install): $dir" -ForegroundColor Gray
    }
}

# Update scheduled task to run as this account (if exists)
Write-Host "[*] Checking scheduled task..." -ForegroundColor Yellow
$task = Get-ScheduledTask -TaskName "DCSA-SecurityAuditor" -ErrorAction SilentlyContinue
if ($task) {
    Write-Host "[INFO] Scheduled task found. To update it to run as $AccountName, run:" -ForegroundColor Cyan
    Write-Host "       Set-ScheduledTask -TaskName 'DCSA-SecurityAuditor' -User '$AccountName'" -ForegroundColor Gray
} else {
    Write-Host "[INFO] No scheduled task found. It will be created during installation." -ForegroundColor Gray
}

Write-Host "`n=== SETUP COMPLETE ===" -ForegroundColor Green
Write-Host "`nNext steps:" -ForegroundColor Yellow
Write-Host "1. Log in as '$AccountName' to verify the account works"
Write-Host "2. Run the installer: .\Install-Auditor.ps1 -RegisterScheduledTask -ConfigureAuditPolicy"
Write-Host "3. Start the auditor: .\Start-Auditor.ps1"

if (-not $ExistingAccount) {
    Write-Host "`nREMINDER: The password was shown above. Make sure it's stored securely!" -ForegroundColor Red
}
