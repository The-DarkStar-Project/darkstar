param(
    [string]$Url,

    [string]$Org,

    [string]$EnrollmentToken,

    [int]$IntervalSeconds = 3600,

    [string]$ServiceName = "DarkstarEndpointAgent"
)

$ErrorActionPreference = "Stop"

$installDir = Join-Path $env:ProgramFiles "Darkstar\EndpointAgent"
$programDataDir = Join-Path $env:ProgramData "Darkstar\EndpointAgent"
$sourceExe = Join-Path $PSScriptRoot "darkstar-agent.exe"
$targetExe = Join-Path $installDir "darkstar-agent.exe"

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this installer from an elevated PowerShell session."
}

if (-not (Test-Path $sourceExe)) {
    throw "darkstar-agent.exe was not found next to install.ps1"
}

New-Item -ItemType Directory -Force -Path $installDir | Out-Null
New-Item -ItemType Directory -Force -Path $programDataDir | Out-Null

$existingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existingService) {
    if ($existingService.Status -ne "Stopped") {
        Stop-Service -Name $ServiceName -Force
        $existingService.WaitForStatus("Stopped", "00:00:30")
    }

    Copy-Item -Force $sourceExe $targetExe
    Start-Service -Name $ServiceName

    Write-Host "Darkstar endpoint agent updated and restarted as service '$ServiceName'."
    exit 0
}

if (-not $Url -or -not $Org -or -not $EnrollmentToken) {
    throw "Fresh install requires -Url, -Org and -EnrollmentToken. Existing services can be updated without enrollment parameters."
}

Copy-Item -Force $sourceExe $targetExe

& $targetExe install `
    --url $Url `
    --org $Org `
    --enrollment-token $EnrollmentToken `
    --interval $IntervalSeconds `
    --service-name $ServiceName

& $targetExe start --service-name $ServiceName

Write-Host "Darkstar endpoint agent installed and started as service '$ServiceName'."
