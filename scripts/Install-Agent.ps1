#requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $AgentExe,
    [Parameter(Mandatory)] [string] $LGPOExe,
    [Parameter(Mandatory)] [string] $ServerUrl,
    [Parameter(Mandatory)] [string] $Profile,
    [Parameter(Mandatory)] [string] $ClientToken,
    [Parameter(Mandatory)] [string] $SigningKey,
    [ValidateRange(1, 1440)] [int] $IntervalMinutes = 15,
    [string] $InstallDir = "$env:ProgramFiles\GPO-Distributor",
    [string] $StateDir = "$env:ProgramData\GPO-Distributor",
    [switch] $InsecureSkipVerify
)

$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $AgentExe -PathType Leaf)) { throw "Agent executable not found: $AgentExe" }
if (-not (Test-Path -LiteralPath $LGPOExe -PathType Leaf)) { throw "LGPO.exe not found: $LGPOExe" }

New-Item -ItemType Directory -Force -Path $InstallDir, $StateDir | Out-Null
$agentTarget = Join-Path $InstallDir 'gpo-agent.exe'
$lgpoTarget = Join-Path $InstallDir 'LGPO.exe'
Copy-Item -LiteralPath $AgentExe -Destination $agentTarget -Force
Copy-Item -LiteralPath $LGPOExe -Destination $lgpoTarget -Force

$config = [ordered]@{
    server_url          = $ServerUrl.TrimEnd('/')
    profile             = $Profile
    client_token        = $ClientToken
    signing_key         = $SigningKey
    lgpo_path           = $lgpoTarget
    state_dir           = $StateDir
    poll_interval       = "${IntervalMinutes}m"
    request_timeout     = '15m'
    insecure_skip_verify = [bool]$InsecureSkipVerify
}
$configPath = Join-Path $StateDir 'agent.json'
$config | ConvertTo-Json | Set-Content -LiteralPath $configPath -Encoding UTF8

# Restrict secrets and cached policy bundles to SYSTEM and local Administrators.
& icacls.exe $InstallDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
& icacls.exe $StateDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null

$action = New-ScheduledTaskAction -Execute $agentTarget -Argument "-config `"$configPath`" -once"
$startupTrigger = New-ScheduledTaskTrigger -AtStartup
$periodicTrigger = New-ScheduledTaskTrigger -Once -At ((Get-Date).AddMinutes(2)) -RepetitionInterval (New-TimeSpan -Minutes $IntervalMinutes)
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 30)
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName 'GPO Distributor Agent' -Action $action -Trigger @($startupTrigger, $periodicTrigger) -Settings $settings -Principal $principal -Force | Out-Null

Start-ScheduledTask -TaskName 'GPO Distributor Agent'
Write-Host "Installed. Configuration: $configPath"
