<#
Windows 11 Privacy / Debloat Script
Filename: win11_privacy_debloater.ps1

What it does (APPLY mode — default):
  - Stops & disables telemetry services (DiagTrack, dmwappushservice)
  - Deletes Feedback scheduled tasks
  - Sets registry policies to disable telemetry, tailored experiences, activity history, location
  - Disables Advertising ID, clipboard cloud sync, typing personalization
  - Adds common Microsoft telemetry endpoints to hosts (backs up existing hosts)
  - Disables Copilot, Widgets, Bing search suggestions via policy keys
  - Disables Microsoft Edge background tasks & autostart entries (where reasonable)
  - Disables OneDrive autostart, optionally uninstalls OneDrive
  - Adjusts Defender cloud submission / sample submission settings to favor local-only (not disabling Defender itself)
  - Backs up modified state to a timestamped folder under %ProgramData%\Win11PrivacyBackup\

What it does (RESTORE mode - pass -Restore):
  - Attempts to restore services start types, scheduled tasks from backup, hosts file, and registry keys changed by this script.

IMPORTANT:
  - Run PowerShell as Administrator.
  - Review the script before executing. The script makes persistent system changes.
  - This script aims to be conservative and reversible. However, keep a system restore point and backup important data before running.

Usage:
  - To apply:   Right-click -> Run with PowerShell (Admin) or: .\win11_privacy_debloater.ps1
  - To restore: .\win11_privacy_debloater.ps1 -Restore

#>

param(
    [switch]$Restore
)

# --- Helper functions ------------------------------------------------------
function Timestamp { Get-Date -Format "yyyyMMdd_HHmmss" }

function Ensure-Admin {
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Error "This script must be run as Administrator. Exiting."
        exit 1
    }
}

function Backup-File($Path, $BackupDir) {
    if (Test-Path $Path) {
        $base = Split-Path $Path -Leaf
        $dest = Join-Path $BackupDir $base
        Copy-Item -Path $Path -Destination $dest -Force
        Write-Verbose "Backed up $Path -> $dest"
    }
}

function Backup-RegistryKey($KeyPath, $BackupDir) {
    try {
        $safeName = $KeyPath -replace '[\\: ]','_' -replace '[^a-zA-Z0-9_\-]',''
        $exportPath = Join-Path $BackupDir "$safeName.reg"
        reg export "$KeyPath" "$exportPath" /y | Out-Null
        Write-Verbose "Exported $KeyPath -> $exportPath"
    } catch {
        Write-Verbose "Could not export registry key $KeyPath: $_"
    }
}

function Backup-Service($ServiceName, $BackupDir) {
    try {
        $svc = Get-Service -Name $ServiceName -ErrorAction Stop
        $info = @{Name=$svc.Name; Status=$svc.Status; StartType=(Get-WmiObject -Class Win32_Service -Filter "Name='$($svc.Name)'").StartMode}
        $out = (ConvertTo-Json $info -Depth 3)
        $out | Out-File (Join-Path $BackupDir "$($ServiceName)_service.json") -Force
        Write-Verbose "Backed up service $ServiceName"
    } catch {
        Write-Verbose "Service $ServiceName not found or could not back up: $_"
    }
}

function Backup-ScheduledTask($TaskPath, $BackupDir) {
    try {
        $safeName = ($TaskPath -replace '[\\/ :]','_')
        $exportPath = Join-Path $BackupDir "$safeName.xml"
        schtasks /Query /TN "$TaskPath" > $null 2>&1
        if ($LASTEXITCODE -eq 0) {
            schtasks /Query /TN "$TaskPath" /XML > $exportPath 2>$null
            Write-Verbose "Exported scheduled task $TaskPath -> $exportPath"
        }
    } catch {
        Write-Verbose "Could not export scheduled task $TaskPath: $_"
    }
}

# --- Begin ---------------------------------------------------------------
Ensure-Admin

$BackupRoot = Join-Path $env:ProgramData "Win11PrivacyBackup"
$Time = Timestamp
$ThisBackup = Join-Path $BackupRoot $Time
New-Item -Path $ThisBackup -ItemType Directory -Force | Out-Null
Write-Output "Backup directory: $ThisBackup"

# Common targets
$ServicesToDisable = @('DiagTrack','dmwappushservice')
$FeedbackTasks = @("\Microsoft\Windows\Feedback\Siuf\DmClient","\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload")
$RegistryKeysToBackup = @(
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection",
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\System",
    "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo",
    "HKCU\Software\Microsoft\Siuf\Rules",
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer",
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search",
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent",
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate",
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Defender",
    "HKLM\SOFTWARE\Policies\Microsoft\Edge",
    "HKCU\Software\Microsoft\Clipboard",
    "HKCU\Software\Microsoft\InputPersonalization"
)

# Backup files
Backup-File -Path "$env:SystemRoot\System32\drivers\etc\hosts" -BackupDir $ThisBackup

# Backup registry keys we will change (best-effort)
foreach ($k in $RegistryKeysToBackup) { Backup-RegistryKey -KeyPath $k -BackupDir $ThisBackup }

# Backup services
foreach ($s in $ServicesToDisable) { Backup-Service -ServiceName $s -BackupDir $ThisBackup }

# Backup scheduled tasks
foreach ($t in $FeedbackTasks) { Backup-ScheduledTask -TaskPath $t -BackupDir $ThisBackup }

# Create system restore point (best-effort)
try {
    Write-Output "Attempting to create a System Restore point..."
    Checkpoint-Computer -Description "Win11PrivacyBackup_$Time" -RestorePointType "MODIFY_SETTINGS" -ErrorAction Stop
    Write-Output "System restore point created."
} catch {
    Write-Verbose "Could not create system restore point: $_"
}

if ($Restore) {
    Write-Output "RESTORE mode: attempting to revert changes from backup: $ThisBackup"

    # Restore hosts
    $hostBackup = Join-Path $ThisBackup "hosts"
    if (Test-Path $hostBackup) {
        Copy-Item -Path $hostBackup -Destination "$env:SystemRoot\System32\drivers\etc\hosts" -Force
        Write-Output "Restored hosts file."
    } else { Write-Output "Hosts backup not found; skipping hosts restore." }

    # Restore exported registry keys
    $regFiles = Get-ChildItem -Path $ThisBackup -Filter *.reg -ErrorAction SilentlyContinue
    foreach ($r in $regFiles) {
        try {
            reg import "$($r.FullName)" | Out-Null
            Write-Output "Imported registry backup: $($r.Name)"
        } catch { Write-Verbose "Failed to import $($r.Name): $_" }
    }

    # Restore scheduled tasks (XML restore isn't always available; try re-create via schtasks)
    $xmls = Get-ChildItem -Path $ThisBackup -Filter *.xml -ErrorAction SilentlyContinue
    foreach ($x in $xmls) {
        try {
            $taskname = '/' + ($x.BaseName -replace '^_','')
            schtasks /Create /TN $taskname /XML "$($x.FullName)" /F | Out-Null
            Write-Output "Restored scheduled task from $($x.Name)"
        } catch { Write-Verbose "Failed to restore task $($x.Name): $_" }
    }

    # Restore service start types
    $svcJsons = Get-ChildItem -Path $ThisBackup -Filter *_service.json -ErrorAction SilentlyContinue
    foreach ($j in $svcJsons) {
        try {
            $data = Get-Content $j.FullName | ConvertFrom-Json
            $name = $data.Name
            $desired = $data.StartType
            if ($desired -and (Get-Service -Name $name -ErrorAction SilentlyContinue)) {
                Set-Service -Name $name -StartupType $desired -ErrorAction SilentlyContinue
                Write-Output "Restored service $name start type to $desired"
            }
        } catch { Write-Verbose "Failed to restore service from $($j.Name): $_" }
    }

    Write-Output "Restore complete. Reboot is recommended."
    exit 0
}

# ---------------- Apply changes -------------------------------------------
Write-Output "Applying privacy hardening..."

# 1) Stop & disable telemetry services
foreach ($s in $ServicesToDisable) {
    try {
        if (Get-Service -Name $s -ErrorAction SilentlyContinue) {
            Stop-Service -Name $s -Force -ErrorAction SilentlyContinue
            sc.exe config $s start= disabled | Out-Null
            Write-Output "Service $s stopped and disabled."
        }
    } catch { Write-Verbose "Error disabling service $s: $_" }
}

# 2) Remove feedback scheduled tasks (if present)
foreach ($t in $FeedbackTasks) {
    schtasks /Query /TN "$t" > $null 2>&1
    if ($LASTEXITCODE -eq 0) {
        schtasks /Delete /TN "$t" /F
        Write-Output "Deleted scheduled task $t"
    } else {
        Write-Verbose "Task $t not present"
    }
}

# 3) Registry tweaks (telemetry, tailored experiences, search, activity, location)
# DataCollection AllowTelemetry = 0
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\" -Name "DataCollection" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0 -Type DWord -Force

# Disable Activity Feed + UploadUserActivities
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Value 0 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Value 0 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Value 0 -Type DWord -Force

# Disable Advertising ID for current user
New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\" -Name "AdvertisingInfo" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Value 0 -Type DWord -Force

# Disable Tailored experiences
New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy" -Name "TailoredExperiencesWithDiagnosticDataEnabled" -Value 0 -Type DWord -Force

# Disable Feedback prompts
New-Item -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Value 0 -Type DWord -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Name "PeriodInNanoSeconds" -Value 0 -Type DWord -Force

# Disable Search suggestions / Bing integration
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "DisableSearchBoxSuggestions" -Value 1 -Type DWord -Force
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "ConnectedSearchUseWeb" -Value 0 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "ConnectedSearchUseWebOverMeteredConnections" -Value 0 -Type DWord -Force

# Disable Location
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocation" -Value 1 -Type DWord -Force

# Disable Clipboard cloud sync
New-Item -Path "HKCU:\Software\Microsoft\Clipboard" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Clipboard" -Name "EnableCloudClipboard" -Value 0 -Type DWord -Force

# Disable typing personalization (text & ink collection)
New-Item -Path "HKCU:\Software\Microsoft\InputPersonalization" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Value 1 -Type DWord -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Value 1 -Type DWord -Force

# 4) Block common telemetry endpoints by appending to hosts (preserve original hosts by backup)
$HostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
$HostsBackup = Join-Path $ThisBackup "hosts"
if (Test-Path $HostsPath) { Copy-Item $HostsPath $HostsBackup -Force }

$TelemetryHosts = @(
    '0.0.0.0 settings-win.data.microsoft.com',
    '0.0.0.0 vortex.data.microsoft.com',
    '0.0.0.0 telemetry.microsoft.com',
    '0.0.0.0 watson.telemetry.microsoft.com',
    '0.0.0.0 browser.events.data.msn.com',
    '0.0.0.0 geo-prod.do.dsp.mp.microsoft.com',
    '0.0.0.0 watson.ppe.telemetry.microsoft.com',
    '0.0.0.0 choice.microsoft.com',
    '0.0.0.0 telemetry.apozon.com'
)

# Append if not already present
$existing = Get-Content $HostsPath -ErrorAction SilentlyContinue
foreach ($line in $TelemetryHosts) {
    if ($existing -notcontains $line) {
        Add-Content -Path $HostsPath -Value $line
        Write-Output "Added hosts entry: $line"
    }
}

# 5) Disable Copilot & Widgets via policy keys
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\" -Name "CloudContent" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableCloudOptimizedContent" -Value 1 -Type DWord -Force

# Widgets: disable via user policy
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "DisableEdgeSwizzling" -Value 1 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "DisableWidgets" -Value 1 -Type DWord -Force

# Copilot (policy may vary by build) - best-effort
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsFeatures" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsFeatures" -Name "HideCopilotButton" -Value 1 -Type DWord -Force

# 6) Disable Edge background tasks & prelaunch (best-effort)
# Block prelaunch/preload via registry policy
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "BackgroundModeEnabled" -Value 0 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "PrelaunchEnabled" -Value 0 -Type DWord -Force

# Remove Edge scheduled tasks (best-effort) - many names per build
$edgeTasks = @(
    "\Microsoft\EdgeUpdate\Edge Update",
    "\Microsoft\EdgeUpdate\Edge Update OnLogon"
)
foreach ($et in $edgeTasks) {
    schtasks /Query /TN "$et" > $null 2>&1
    if ($LASTEXITCODE -eq 0) { schtasks /Delete /TN "$et" /F; Write-Output "Deleted $et" }
}

# 7) OneDrive: disable autostart and stop syncing (do not forcibly delete user files)
# Remove OneDrive from Startup
$OneDriveStartup = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
try {
    if (Get-ItemProperty -Path $OneDriveStartup -Name "OneDrive" -ErrorAction SilentlyContinue) {
        Remove-ItemProperty -Path $OneDriveStartup -Name "OneDrive" -ErrorAction SilentlyContinue
        Write-Output "Removed OneDrive from current user's startup."
    }
} catch { Write-Verbose "Could not modify OneDrive startup: $_" }

# Attempt to stop OneDrive process and optionally uninstall (commented out; leave user choice):
$odPath = "$env:LOCALAPPDATA\Microsoft\OneDrive\OneDrive.exe"
if (Test-Path $odPath) {
    Stop-Process -Name OneDrive -Force -ErrorAction SilentlyContinue
    Write-Output "Stopped OneDrive process."
    # To uninstall silently uncomment the following lines (NOTE: will remove OneDrive)
    # Start-Process -FilePath "$env:SystemRoot\SysWOW64\OneDriveSetup.exe" -ArgumentList '/uninstall' -Wait
    # Write-Output "Uninstalled OneDrive."
}

# 8) Windows Defender - reduce cloud sample submission and automatic sample submission
# NOTE: This keeps Defender running but sets cloud-based protection controls to more conservative settings.
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "AllowCloudProtection" -Value 0 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "SubmitSamplesConsent" -Value 2 -Type DWord -Force

# 9) Disable telemetry tasks (additional scheduled tasks under Windows)
$possibleTelemetryTasks = @(
    "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
    "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
    "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip"
)
foreach ($pt in $possibleTelemetryTasks) {
    schtasks /Query /TN "$pt" > $null 2>&1
    if ($LASTEXITCODE -eq 0) {
        schtasks /Delete /TN "$pt" /F
        Write-Output "Deleted telemetry-related task: $pt"
    }
}

# 10) Optionally remove some consumer apps (safe ones)
$packagesToRemove = @(
    '*Xbox*', '*Microsoft.XboxGamingOverlay*', '*ZuneMusic*', '*ZuneVideo*', '*Microsoft.Bing*', '*Microsoft.Xbox*', '*XboxGameOverlay*', '*Microsoft.GetHelp*', '*Microsoft.Getstarted*'
)
foreach ($p in $packagesToRemove) {
    try {
        Get-AppxPackage -Name $p -AllUsers | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
        Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $p | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName } -ErrorAction SilentlyContinue
        Write-Verbose "Attempted remove Appx packages pattern: $p"
    } catch { Write-Verbose "Error removing appx $p: $_" }
}

# 11) Final verification
Get-Service DiagTrack, dmwappushservice | Select-Object Name, Status
Write-Output "Feedback tasks remaining (if any):"
schtasks | findstr /i "feedback" | ForEach-Object { Write-Output $_ }

Write-Output "Hosts file modifications appended. Hosts backup saved to: $ThisBackup"
Write-Output "Registry and other backups saved to: $ThisBackup"
Write-Output "Privacy hardening applied. Reboot recommended."

# End of script
