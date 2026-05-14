param(
    [Parameter(Mandatory = $true)]
    [string]$Url,

    [Parameter(Mandatory = $true)]
    [string]$Org,

    [Parameter(Mandatory = $true)]
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
Copy-Item -Force $sourceExe $targetExe

& $targetExe install `
    --url $Url `
    --org $Org `
    --enrollment-token $EnrollmentToken `
    --interval $IntervalSeconds `
    --service-name $ServiceName

& $targetExe start --service-name $ServiceName

Write-Host "Darkstar endpoint agent installed and started as service '$ServiceName'."
