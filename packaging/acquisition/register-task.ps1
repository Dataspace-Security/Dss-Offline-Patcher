<#
  Registers a Windows scheduled task that runs `pmctl auto` daily at 03:00 on
  the acquisition host. Daily is cheap (a run with nothing new sends nothing)
  and also catches out-of-band Microsoft releases and vendor updates.

    .\register-task.ps1 -Pmctl C:\offpatch-acq\pmctl.exe -Config C:\offpatch-acq\acquire.json

  Exit codes: 0 = ok (sent or nothing new), 2 = some items failed (retried
  next run), 1 = run failed. Watch "Last Run Result" in Task Scheduler or
  forward event ID 201 results to your monitoring.
#>
param(
  [Parameter(Mandatory = $true)][string]$Pmctl,
  [Parameter(Mandatory = $true)][string]$Config,
  [string]$At = "03:00",
  [string]$TaskName = "offpatch-acquire"
)
$ErrorActionPreference = "Stop"
$logDir = Join-Path (Split-Path $Config) "logs"
New-Item -ItemType Directory -Force $logDir | Out-Null
$cmd = "/c `"`"$Pmctl`" auto -config `"$Config`" >> `"$logDir\auto.log`" 2>&1`""
$action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument $cmd
$trigger = New-ScheduledTaskTrigger -Daily -At $At
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Hours 7) -MultipleInstances IgnoreNew
# Runs as SYSTEM so it works without a logged-on user. If the signing key is
# in an HSM, run as the service account that can reach it instead (-User).
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -User "SYSTEM" -RunLevel Highest -Force
Write-Host "registered $TaskName (daily at $At). Test now with: Start-ScheduledTask -TaskName $TaskName"
