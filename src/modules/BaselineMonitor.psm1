#Requires -Version 5.1
<#
.SYNOPSIS
    Configuration Baseline Monitor Module for DCSA Auditing Software

.DESCRIPTION
    Creates and monitors system configuration baselines to detect
    unauthorized changes to users, groups, services, software,
    network configuration, and security policies.
#>

# Import utilities
$modulePath = Split-Path -Parent $PSScriptRoot
Import-Module "$modulePath\utils\AuditUtilities.psm1" -Force

# Script-level variables
$script:CurrentBaseline = $null
$script:BaselinePath = $null

function Initialize-BaselineMonitoring {
    <#
    .SYNOPSIS
        Initializes baseline monitoring and sets up baseline storage
    #>
    [CmdletBinding()]
    param()

    $config = Get-AuditConfig
    $script:BaselinePath = "$($config.LogStorage.BasePath)\..\baselines"

    if (-not (Test-Path $script:BaselinePath)) {
        New-Item -Path $script:BaselinePath -ItemType Directory -Force | Out-Null
    }

    # Load or create baseline
    $baselineFile = "$($script:BaselinePath)\current_baseline.json"
    if (Test-Path $baselineFile) {
        $script:CurrentBaseline = Get-Content -Path $baselineFile -Raw | ConvertFrom-Json -AsHashtable
        Write-AuditLog -Category "Baseline" -Message "Existing baseline loaded" -Severity "Information"
    } else {
        Write-AuditLog -Category "Baseline" -Message "No existing baseline found - creating new baseline" -Severity "Information"
        New-SystemBaseline
    }
}

function Start-BaselineMonitoring {
    <#
    .SYNOPSIS
        Starts continuous baseline monitoring
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [switch]$AsJob
    )

    $config = Get-AuditConfig

    if (-not $config.BaselineMonitoring.Enabled) {
        Write-Warning "Baseline monitoring is disabled in configuration"
        return
    }

    Initialize-BaselineMonitoring

    Write-AuditLog -Category "Baseline" -Message "Baseline monitoring started" -Severity "Information"

    if ($AsJob) {
        $job = Start-Job -ScriptBlock {
            param($ModulePath, $Config)
            Import-Module "$ModulePath\utils\AuditUtilities.psm1" -Force
            Import-Module "$ModulePath\modules\BaselineMonitor.psm1" -Force

            Initialize-BaselineMonitoring

            while ($true) {
                Compare-SystemToBaseline
                Start-Sleep -Seconds ($Config.BaselineMonitoring.CheckIntervalMinutes * 60)
            }
        } -ArgumentList $modulePath, $config

        return $job
    } else {
        while ($true) {
            Compare-SystemToBaseline
            Start-Sleep -Seconds ($config.BaselineMonitoring.CheckIntervalMinutes * 60)
        }
    }
}

function New-SystemBaseline {
    <#
    .SYNOPSIS
        Creates a new system configuration baseline
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [switch]$Force
    )

    $config = Get-AuditConfig
    $baselineItems = $config.BaselineMonitoring.BaselineItems

    $baselineFile = "$($script:BaselinePath)\current_baseline.json"

    if ((Test-Path $baselineFile) -and -not $Force) {
        # Archive existing baseline
        $archivePath = "$($script:BaselinePath)\archive"
        if (-not (Test-Path $archivePath)) {
            New-Item -Path $archivePath -ItemType Directory -Force | Out-Null
        }
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        Move-Item -Path $baselineFile -Destination "$archivePath\baseline_$timestamp.json" -Force
    }

    $baseline = @{
        CreatedAt = (Get-AuditTimestamp)
        ComputerName = $env:COMPUTERNAME
        Version = "1.0"
        Items = @{}
    }

    foreach ($item in $baselineItems) {
        Write-Verbose "Collecting baseline for: $item"

        switch ($item) {
            "LocalUsers" {
                $baseline.Items[$item] = Get-BaselineLocalUsers
            }
            "LocalGroups" {
                $baseline.Items[$item] = Get-BaselineLocalGroups
            }
            "Services" {
                $baseline.Items[$item] = Get-BaselineServices
            }
            "ScheduledTasks" {
                $baseline.Items[$item] = Get-BaselineScheduledTasks
            }
            "InstalledSoftware" {
                $baseline.Items[$item] = Get-BaselineInstalledSoftware
            }
            "NetworkConfiguration" {
                $baseline.Items[$item] = Get-BaselineNetworkConfiguration
            }
            "FirewallRules" {
                $baseline.Items[$item] = Get-BaselineFirewallRules
            }
            "AuditPolicy" {
                $baseline.Items[$item] = Get-BaselineAuditPolicy
            }
            "SecurityPolicy" {
                $baseline.Items[$item] = Get-BaselineSecurityPolicy
            }
        }
    }

    # Calculate baseline hash
    $baselineJson = $baseline | ConvertTo-Json -Depth 10
    $baseline["Hash"] = Get-StringHash -InputString $baselineJson

    # Save baseline
    $baselineJson = $baseline | ConvertTo-Json -Depth 10
    $baselineJson | Out-File -FilePath $baselineFile -Encoding UTF8

    $script:CurrentBaseline = $baseline

    Write-AuditLog -Category "Baseline" -Message "New system baseline created with $($baselineItems.Count) components" -Severity "Information" -AdditionalData @{
        Components = $baselineItems -join ", "
        Hash = $baseline.Hash
    }

    return $baseline
}

function Get-BaselineLocalUsers {
    <#
    .SYNOPSIS
        Gets local user accounts for baseline
    #>
    [CmdletBinding()]
    param()

    $users = Get-LocalUser -ErrorAction SilentlyContinue | ForEach-Object {
        @{
            Name = $_.Name
            Enabled = $_.Enabled
            Description = $_.Description
            PasswordRequired = $_.PasswordRequired
            PasswordChangeableDate = if ($_.PasswordChangeableDate) { $_.PasswordChangeableDate.ToString("o") } else { $null }
            SID = $_.SID.Value
        }
    }

    return @($users)
}

function Get-BaselineLocalGroups {
    <#
    .SYNOPSIS
        Gets local groups and their members for baseline
    #>
    [CmdletBinding()]
    param()

    $groups = Get-LocalGroup -ErrorAction SilentlyContinue | ForEach-Object {
        $groupName = $_.Name
        $members = @()

        try {
            $members = Get-LocalGroupMember -Group $groupName -ErrorAction SilentlyContinue | ForEach-Object {
                @{
                    Name = $_.Name
                    ObjectClass = $_.ObjectClass
                    SID = $_.SID.Value
                }
            }
        } catch { }

        @{
            Name = $groupName
            Description = $_.Description
            SID = $_.SID.Value
            Members = @($members)
        }
    }

    return @($groups)
}

function Get-BaselineServices {
    <#
    .SYNOPSIS
        Gets Windows services for baseline
    #>
    [CmdletBinding()]
    param()

    $services = Get-Service -ErrorAction SilentlyContinue | ForEach-Object {
        $serviceConfig = Get-CimInstance -ClassName Win32_Service -Filter "Name='$($_.Name)'" -ErrorAction SilentlyContinue

        @{
            Name = $_.Name
            DisplayName = $_.DisplayName
            Status = $_.Status.ToString()
            StartType = $_.StartType.ToString()
            PathName = $serviceConfig.PathName
            StartName = $serviceConfig.StartName
        }
    }

    return @($services)
}

function Get-BaselineScheduledTasks {
    <#
    .SYNOPSIS
        Gets scheduled tasks for baseline
    #>
    [CmdletBinding()]
    param()

    $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskPath -notlike '\Microsoft\*' } | ForEach-Object {
        $taskInfo = Get-ScheduledTaskInfo -TaskName $_.TaskName -TaskPath $_.TaskPath -ErrorAction SilentlyContinue

        @{
            TaskName = $_.TaskName
            TaskPath = $_.TaskPath
            State = $_.State.ToString()
            Author = $_.Author
            Description = $_.Description
            LastRunTime = if ($taskInfo.LastRunTime) { $taskInfo.LastRunTime.ToString("o") } else { $null }
            NextRunTime = if ($taskInfo.NextRunTime) { $taskInfo.NextRunTime.ToString("o") } else { $null }
            Actions = @($_.Actions | ForEach-Object { $_.Execute })
        }
    }

    return @($tasks)
}

function Get-BaselineInstalledSoftware {
    <#
    .SYNOPSIS
        Gets installed software for baseline
    #>
    [CmdletBinding()]
    param()

    $software = @()

    # 64-bit software
    $regPath64 = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
    $software += Get-ItemProperty -Path $regPath64 -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName } |
        ForEach-Object {
            @{
                Name = $_.DisplayName
                Version = $_.DisplayVersion
                Publisher = $_.Publisher
                InstallDate = $_.InstallDate
                InstallLocation = $_.InstallLocation
            }
        }

    # 32-bit software on 64-bit systems
    $regPath32 = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    if (Test-Path $regPath32) {
        $software += Get-ItemProperty -Path $regPath32 -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName } |
            ForEach-Object {
                @{
                    Name = $_.DisplayName
                    Version = $_.DisplayVersion
                    Publisher = $_.Publisher
                    InstallDate = $_.InstallDate
                    InstallLocation = $_.InstallLocation
                }
            }
    }

    return @($software | Sort-Object { $_.Name })
}

function Get-BaselineNetworkConfiguration {
    <#
    .SYNOPSIS
        Gets network configuration for baseline
    #>
    [CmdletBinding()]
    param()

    $networkConfig = @{
        Adapters = @()
        DNSServers = @()
        Routes = @()
    }

    # Network adapters
    $adapters = Get-NetAdapter -ErrorAction SilentlyContinue | ForEach-Object {
        $ipConfig = Get-NetIPConfiguration -InterfaceIndex $_.ifIndex -ErrorAction SilentlyContinue

        @{
            Name = $_.Name
            InterfaceDescription = $_.InterfaceDescription
            Status = $_.Status.ToString()
            MacAddress = $_.MacAddress
            IPAddresses = @($ipConfig.IPv4Address.IPAddress)
            DefaultGateway = $ipConfig.IPv4DefaultGateway.NextHop
        }
    }
    $networkConfig.Adapters = @($adapters)

    # DNS servers
    $dnsServers = Get-DnsClientServerAddress -ErrorAction SilentlyContinue |
        Where-Object { $_.ServerAddresses } |
        ForEach-Object { $_.ServerAddresses } |
        Select-Object -Unique
    $networkConfig.DNSServers = @($dnsServers)

    return $networkConfig
}

function Get-BaselineFirewallRules {
    <#
    .SYNOPSIS
        Gets Windows Firewall rules for baseline
    #>
    [CmdletBinding()]
    param()

    # Only get enabled rules to keep baseline manageable
    $rules = Get-NetFirewallRule -Enabled True -ErrorAction SilentlyContinue | ForEach-Object {
        @{
            Name = $_.Name
            DisplayName = $_.DisplayName
            Direction = $_.Direction.ToString()
            Action = $_.Action.ToString()
            Profile = $_.Profile.ToString()
            Enabled = $_.Enabled.ToString()
        }
    }

    return @($rules)
}

function Get-BaselineAuditPolicy {
    <#
    .SYNOPSIS
        Gets audit policy settings for baseline
    #>
    [CmdletBinding()]
    param()

    $auditPolicy = @{}

    try {
        $auditpolOutput = auditpol /get /category:* 2>$null

        foreach ($line in $auditpolOutput) {
            if ($line -match '^\s{2}(.+?)\s{2,}(Success|Failure|Success and Failure|No Auditing)') {
                $subcategory = $Matches[1].Trim()
                $setting = $Matches[2].Trim()
                $auditPolicy[$subcategory] = $setting
            }
        }
    } catch {
        Write-AuditLog -Category "System" -Message "Error collecting audit policy: $_" -Severity "Warning"
    }

    return $auditPolicy
}

function Get-BaselineSecurityPolicy {
    <#
    .SYNOPSIS
        Gets security policy settings for baseline
    #>
    [CmdletBinding()]
    param()

    $securityPolicy = @{
        PasswordPolicy = @{}
        LockoutPolicy = @{}
        UserRights = @{}
    }

    try {
        # Export security policy to temp file
        $tempFile = [System.IO.Path]::GetTempFileName()
        $null = secedit /export /cfg $tempFile /quiet 2>$null

        if (Test-Path $tempFile) {
            $content = Get-Content -Path $tempFile -Raw

            # Parse password policy
            if ($content -match 'MinimumPasswordAge\s*=\s*(\d+)') { $securityPolicy.PasswordPolicy['MinimumPasswordAge'] = $Matches[1] }
            if ($content -match 'MaximumPasswordAge\s*=\s*(\d+)') { $securityPolicy.PasswordPolicy['MaximumPasswordAge'] = $Matches[1] }
            if ($content -match 'MinimumPasswordLength\s*=\s*(\d+)') { $securityPolicy.PasswordPolicy['MinimumPasswordLength'] = $Matches[1] }
            if ($content -match 'PasswordComplexity\s*=\s*(\d+)') { $securityPolicy.PasswordPolicy['PasswordComplexity'] = $Matches[1] }
            if ($content -match 'PasswordHistorySize\s*=\s*(\d+)') { $securityPolicy.PasswordPolicy['PasswordHistorySize'] = $Matches[1] }

            # Parse lockout policy
            if ($content -match 'LockoutBadCount\s*=\s*(\d+)') { $securityPolicy.LockoutPolicy['LockoutBadCount'] = $Matches[1] }
            if ($content -match 'LockoutDuration\s*=\s*(\d+)') { $securityPolicy.LockoutPolicy['LockoutDuration'] = $Matches[1] }
            if ($content -match 'ResetLockoutCount\s*=\s*(\d+)') { $securityPolicy.LockoutPolicy['ResetLockoutCount'] = $Matches[1] }

            Remove-Item -Path $tempFile -Force -ErrorAction SilentlyContinue
        }
    } catch {
        Write-AuditLog -Category "System" -Message "Error collecting security policy: $_" -Severity "Warning"
    }

    return $securityPolicy
}

function Compare-SystemToBaseline {
    <#
    .SYNOPSIS
        Compares current system state to baseline and reports differences
    #>
    [CmdletBinding()]
    param()

    if ($null -eq $script:CurrentBaseline) {
        Write-Warning "No baseline loaded. Run Initialize-BaselineMonitoring first."
        return
    }

    $config = Get-AuditConfig
    $differences = @()

    foreach ($item in $script:CurrentBaseline.Items.Keys) {
        $baselineData = $script:CurrentBaseline.Items[$item]
        $currentData = $null

        # Get current state
        switch ($item) {
            "LocalUsers" { $currentData = Get-BaselineLocalUsers }
            "LocalGroups" { $currentData = Get-BaselineLocalGroups }
            "Services" { $currentData = Get-BaselineServices }
            "ScheduledTasks" { $currentData = Get-BaselineScheduledTasks }
            "InstalledSoftware" { $currentData = Get-BaselineInstalledSoftware }
            "NetworkConfiguration" { $currentData = Get-BaselineNetworkConfiguration }
            "FirewallRules" { $currentData = Get-BaselineFirewallRules }
            "AuditPolicy" { $currentData = Get-BaselineAuditPolicy }
            "SecurityPolicy" { $currentData = Get-BaselineSecurityPolicy }
        }

        if ($currentData) {
            $itemDiffs = Compare-BaselineItem -ItemType $item -Baseline $baselineData -Current $currentData
            $differences += $itemDiffs
        }
    }

    if ($differences.Count -gt 0) {
        Write-AuditLog -Category "Baseline" -Message "Baseline deviation detected: $($differences.Count) change(s)" -Severity "Warning" -AdditionalData @{
            ChangeCount = $differences.Count
        }

        foreach ($diff in $differences) {
            $severity = switch ($diff.ItemType) {
                { $_ -in @("LocalUsers", "LocalGroups", "SecurityPolicy", "AuditPolicy") } { "Critical" }
                { $_ -in @("Services", "ScheduledTasks", "FirewallRules") } { "Warning" }
                default { "Information" }
            }

            Write-AuditLog -Category "Baseline" -Message "Baseline change: $($diff.ItemType) - $($diff.ChangeType) - $($diff.ItemName)" -Severity $severity -AdditionalData @{
                ItemType = $diff.ItemType
                ChangeType = $diff.ChangeType
                ItemName = $diff.ItemName
                Details = $diff.Details
            }

            if ($config.BaselineMonitoring.AlertOnDeviation) {
                Write-AuditLog -Category "Alert" -Message "ALERT: Configuration baseline deviation - $($diff.ItemType): $($diff.ItemName) ($($diff.ChangeType))" -Severity $severity -AdditionalData @{
                    AlertType = "BaselineDeviation"
                    ItemType = $diff.ItemType
                    ChangeType = $diff.ChangeType
                    ItemName = $diff.ItemName
                }
            }
        }
    } else {
        Write-AuditLog -Category "Baseline" -Message "Baseline check completed - no deviations detected" -Severity "Information"
    }

    return $differences
}

function Compare-BaselineItem {
    <#
    .SYNOPSIS
        Compares a specific baseline item type
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ItemType,

        [Parameter(Mandatory)]
        $Baseline,

        [Parameter(Mandatory)]
        $Current
    )

    $differences = @()

    switch ($ItemType) {
        "LocalUsers" {
            $baselineNames = $Baseline | ForEach-Object { $_.Name }
            $currentNames = $Current | ForEach-Object { $_.Name }

            # New users
            $currentNames | Where-Object { $_ -notin $baselineNames } | ForEach-Object {
                $differences += @{
                    ItemType = $ItemType
                    ChangeType = "Added"
                    ItemName = $_
                    Details = "New user account created"
                }
            }

            # Removed users
            $baselineNames | Where-Object { $_ -notin $currentNames } | ForEach-Object {
                $differences += @{
                    ItemType = $ItemType
                    ChangeType = "Removed"
                    ItemName = $_
                    Details = "User account removed"
                }
            }

            # Modified users
            foreach ($baseUser in $Baseline) {
                $currUser = $Current | Where-Object { $_.Name -eq $baseUser.Name }
                if ($currUser -and $currUser.Enabled -ne $baseUser.Enabled) {
                    $differences += @{
                        ItemType = $ItemType
                        ChangeType = "Modified"
                        ItemName = $baseUser.Name
                        Details = "Enabled state changed from $($baseUser.Enabled) to $($currUser.Enabled)"
                    }
                }
            }
        }

        "LocalGroups" {
            $baselineNames = $Baseline | ForEach-Object { $_.Name }
            $currentNames = $Current | ForEach-Object { $_.Name }

            # New groups
            $currentNames | Where-Object { $_ -notin $baselineNames } | ForEach-Object {
                $differences += @{
                    ItemType = $ItemType
                    ChangeType = "Added"
                    ItemName = $_
                    Details = "New group created"
                }
            }

            # Check for membership changes in existing groups
            foreach ($baseGroup in $Baseline) {
                $currGroup = $Current | Where-Object { $_.Name -eq $baseGroup.Name }
                if ($currGroup) {
                    $baseMembers = $baseGroup.Members | ForEach-Object { $_.Name }
                    $currMembers = $currGroup.Members | ForEach-Object { $_.Name }

                    $addedMembers = $currMembers | Where-Object { $_ -notin $baseMembers }
                    $removedMembers = $baseMembers | Where-Object { $_ -notin $currMembers }

                    if ($addedMembers) {
                        $differences += @{
                            ItemType = $ItemType
                            ChangeType = "MemberAdded"
                            ItemName = $baseGroup.Name
                            Details = "New members: $($addedMembers -join ', ')"
                        }
                    }
                    if ($removedMembers) {
                        $differences += @{
                            ItemType = $ItemType
                            ChangeType = "MemberRemoved"
                            ItemName = $baseGroup.Name
                            Details = "Removed members: $($removedMembers -join ', ')"
                        }
                    }
                }
            }
        }

        "Services" {
            foreach ($baseSvc in $Baseline) {
                $currSvc = $Current | Where-Object { $_.Name -eq $baseSvc.Name }
                if ($currSvc) {
                    if ($currSvc.StartType -ne $baseSvc.StartType) {
                        $differences += @{
                            ItemType = $ItemType
                            ChangeType = "Modified"
                            ItemName = $baseSvc.Name
                            Details = "StartType changed from $($baseSvc.StartType) to $($currSvc.StartType)"
                        }
                    }
                }
            }

            # New services
            $baselineNames = $Baseline | ForEach-Object { $_.Name }
            $currentNames = $Current | ForEach-Object { $_.Name }
            $currentNames | Where-Object { $_ -notin $baselineNames } | ForEach-Object {
                $differences += @{
                    ItemType = $ItemType
                    ChangeType = "Added"
                    ItemName = $_
                    Details = "New service installed"
                }
            }
        }

        "InstalledSoftware" {
            $baselineNames = $Baseline | ForEach-Object { $_.Name }
            $currentNames = $Current | ForEach-Object { $_.Name }

            # New software
            $currentNames | Where-Object { $_ -notin $baselineNames } | ForEach-Object {
                $differences += @{
                    ItemType = $ItemType
                    ChangeType = "Added"
                    ItemName = $_
                    Details = "New software installed"
                }
            }

            # Removed software
            $baselineNames | Where-Object { $_ -notin $currentNames } | ForEach-Object {
                $differences += @{
                    ItemType = $ItemType
                    ChangeType = "Removed"
                    ItemName = $_
                    Details = "Software removed"
                }
            }
        }

        "AuditPolicy" {
            foreach ($key in $Baseline.Keys) {
                if ($Current.ContainsKey($key) -and $Current[$key] -ne $Baseline[$key]) {
                    $differences += @{
                        ItemType = $ItemType
                        ChangeType = "Modified"
                        ItemName = $key
                        Details = "Changed from '$($Baseline[$key])' to '$($Current[$key])'"
                    }
                }
            }
        }

        "SecurityPolicy" {
            # Compare password policy
            foreach ($key in $Baseline.PasswordPolicy.Keys) {
                if ($Current.PasswordPolicy.ContainsKey($key) -and $Current.PasswordPolicy[$key] -ne $Baseline.PasswordPolicy[$key]) {
                    $differences += @{
                        ItemType = $ItemType
                        ChangeType = "Modified"
                        ItemName = "PasswordPolicy.$key"
                        Details = "Changed from '$($Baseline.PasswordPolicy[$key])' to '$($Current.PasswordPolicy[$key])'"
                    }
                }
            }

            # Compare lockout policy
            foreach ($key in $Baseline.LockoutPolicy.Keys) {
                if ($Current.LockoutPolicy.ContainsKey($key) -and $Current.LockoutPolicy[$key] -ne $Baseline.LockoutPolicy[$key]) {
                    $differences += @{
                        ItemType = $ItemType
                        ChangeType = "Modified"
                        ItemName = "LockoutPolicy.$key"
                        Details = "Changed from '$($Baseline.LockoutPolicy[$key])' to '$($Current.LockoutPolicy[$key])'"
                    }
                }
            }
        }
    }

    return $differences
}

function Get-BaselineSummary {
    <#
    .SYNOPSIS
        Returns a summary of the current baseline
    #>
    [CmdletBinding()]
    param()

    if ($null -eq $script:CurrentBaseline) {
        Initialize-BaselineMonitoring
    }

    return [PSCustomObject]@{
        CreatedAt = $script:CurrentBaseline.CreatedAt
        ComputerName = $script:CurrentBaseline.ComputerName
        Hash = $script:CurrentBaseline.Hash
        Components = $script:CurrentBaseline.Items.Keys -join ", "
        UserCount = $script:CurrentBaseline.Items.LocalUsers.Count
        GroupCount = $script:CurrentBaseline.Items.LocalGroups.Count
        ServiceCount = $script:CurrentBaseline.Items.Services.Count
        SoftwareCount = $script:CurrentBaseline.Items.InstalledSoftware.Count
    }
}

# Export functions
Export-ModuleMember -Function @(
    'Initialize-BaselineMonitoring',
    'Start-BaselineMonitoring',
    'New-SystemBaseline',
    'Get-BaselineLocalUsers',
    'Get-BaselineLocalGroups',
    'Get-BaselineServices',
    'Get-BaselineScheduledTasks',
    'Get-BaselineInstalledSoftware',
    'Get-BaselineNetworkConfiguration',
    'Get-BaselineFirewallRules',
    'Get-BaselineAuditPolicy',
    'Get-BaselineSecurityPolicy',
    'Compare-SystemToBaseline',
    'Compare-BaselineItem',
    'Get-BaselineSummary'
)
