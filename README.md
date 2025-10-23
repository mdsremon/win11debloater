Windows 11 Privacy / Debloat Script
Filename: win11_privacy_debloater.ps1

To run the file without downloading run bellow command in admin powershell window

`iwr -useb https://github.com/mdsremon/win11debloater/blob/main/win11_privacy_debloater.ps1 | iex`

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


How to use it:

Open PowerShell as Administrator.

Save the canvas file as win11_privacy_debloater.ps1 (it’s already available in the canvas panel).

To apply the privacy hardening, run:

`.\win11_privacy_debloater.ps1`


To restore changes made by the script, run:

`.\win11_privacy_debloater.ps1 -Restore`


Notes:

The script creates a timestamped backup under %ProgramData%\Win11PrivacyBackup\ before making changes and attempts to restore from that backup when run with -Restore.

Review the script once (it’s in the canvas) before running. I included conservative defaults and comments where potentially destructive actions (like uninstalling OneDrive) are intentionally left commented out for safety.

Reboot after running for all changes to take effe
