# SFTPxy Windows Installation Script
# Run this script as Administrator

param(
    [string]$InstallPath = "C:\Program Files\SFTPxy",
    [string]$DataPath = "C:\ProgramData\SFTPxy",
    [string]$ConfigPath = "$DataPath\config.yaml"
)

function Ensure-Directory {
    param([string]$Path)

    if (-Not (Test-Path $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
        Write-Host "  Created: $Path" -ForegroundColor Green
    } else {
        Write-Host "  Already exists: $Path" -ForegroundColor Gray
    }
}

function Copy-Tree {
    param(
        [string]$Source,
        [string]$Destination
    )

    if (-Not (Test-Path $Source)) {
        return $false
    }

    $Parent = Split-Path -Parent $Destination
    if ($Parent) {
        New-Item -ItemType Directory -Path $Parent -Force | Out-Null
    }
    if (Test-Path $Destination) {
        Remove-Item -Path $Destination -Recurse -Force
    }
    Copy-Item -Path $Source -Destination $Destination -Recurse -Force
    return $true
}

function Convert-ToYamlPath {
    param([string]$Path)

    return ($Path -replace "\\", "/")
}

if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "This script must be run as Administrator. Please right-click and select 'Run as Administrator'."
    exit 1
}

Write-Host "SFTPxy Windows Installation" -ForegroundColor Cyan
Write-Host "=========================" -ForegroundColor Cyan
Write-Host ""

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = (Resolve-Path (Join-Path $ScriptDir "..\..")).Path

$SourceBinary = Join-Path $RepoRoot "bin\sftpxy.exe"
$SourceServiceBinary = Join-Path $RepoRoot "bin\sftpxy-service.exe"
$SourceMigrations = Join-Path $RepoRoot "migrations"
$SourceWebDist = Join-Path $RepoRoot "web\dist"
$ExampleConfig = Join-Path $RepoRoot "config.yaml.example"

$DestBinary = Join-Path $InstallPath "sftpxy.exe"
$DestServiceBinary = Join-Path $InstallPath "sftpxy-service.exe"
$DestMigrations = Join-Path $InstallPath "migrations"
$DestWebDist = Join-Path $InstallPath "web\dist"

$ConfigDir = Split-Path -Parent $ConfigPath
$DatabasePath = Join-Path $DataPath "data\sftpxy.db"
$LogPath = Join-Path $DataPath "logs\sftpxy.log"
$TempPath = Join-Path $DataPath "tmp"
$PluginPath = Join-Path $DataPath "plugins"
$KeyPath = Join-Path $DataPath "keys\kms.key"
$HookPath = Join-Path $InstallPath "hooks\sftpxy-hook.exe"

if (-Not (Test-Path $SourceBinary)) {
    Write-Error "Binary not found at: $SourceBinary. Please build first with: go build -o bin/sftpxy.exe ./cmd/sftpxy"
    exit 1
}

if (-Not (Test-Path $SourceServiceBinary)) {
    $GoCommand = Get-Command go -ErrorAction SilentlyContinue
    if ($null -eq $GoCommand) {
        Write-Error "Service wrapper not found at: $SourceServiceBinary, and 'go' is not available to build it."
        exit 1
    }

    Write-Host "Building Windows service wrapper..." -ForegroundColor Yellow
    Push-Location $RepoRoot
    & $GoCommand.Source build -o "bin\sftpxy-service.exe" ".\deploy\windows"
    $BuildExitCode = $LASTEXITCODE
    Pop-Location
    if ($BuildExitCode -ne 0 -or -Not (Test-Path $SourceServiceBinary)) {
        Write-Error "Failed to build service wrapper binary."
        exit 1
    }
}

Write-Host "Creating installation directory: $InstallPath" -ForegroundColor Yellow
Ensure-Directory -Path $InstallPath

Write-Host "Creating data directory: $DataPath" -ForegroundColor Yellow
Ensure-Directory -Path $DataPath
Ensure-Directory -Path (Join-Path $DataPath "data")
Ensure-Directory -Path (Join-Path $DataPath "logs")
Ensure-Directory -Path $TempPath
Ensure-Directory -Path $PluginPath
Ensure-Directory -Path (Split-Path -Parent $KeyPath)
Ensure-Directory -Path $ConfigDir

Write-Host "Copying runtime binaries..." -ForegroundColor Yellow
Copy-Item -Path $SourceBinary -Destination $DestBinary -Force
Copy-Item -Path $SourceServiceBinary -Destination $DestServiceBinary -Force
Write-Host "  Installed: $DestBinary" -ForegroundColor Green
Write-Host "  Installed: $DestServiceBinary" -ForegroundColor Green

Write-Host "Copying migrations..." -ForegroundColor Yellow
if (Copy-Tree -Source $SourceMigrations -Destination $DestMigrations) {
    Write-Host "  Installed: $DestMigrations" -ForegroundColor Green
} else {
    Write-Error "Migrations directory not found at: $SourceMigrations"
    exit 1
}

Write-Host "Copying web assets..." -ForegroundColor Yellow
if (Copy-Tree -Source $SourceWebDist -Destination $DestWebDist) {
    Write-Host "  Installed: $DestWebDist" -ForegroundColor Green
} else {
    Write-Warning "web\dist not found; HTTP static assets were not copied"
}

if (-Not (Test-Path $ConfigPath)) {
    if (-Not (Test-Path $ExampleConfig)) {
        Write-Error "Example config not found at: $ExampleConfig"
        exit 1
    }

    Write-Host "Generating deployment configuration: $ConfigPath" -ForegroundColor Yellow
    $ConfigContent = Get-Content -Path $ExampleConfig -Raw
    $ConfigReplacements = [ordered]@{
        "./logs/sftpxy.log" = (Convert-ToYamlPath $LogPath)
        "./data/tmp" = (Convert-ToYamlPath $TempPath)
        "./plugins" = (Convert-ToYamlPath $PluginPath)
        "./web/dist" = (Convert-ToYamlPath $DestWebDist)
        "./data/sftpxy.db" = (Convert-ToYamlPath $DatabasePath)
        "./keys/kms.key" = (Convert-ToYamlPath $KeyPath)
        "/usr/local/bin/sftpxy-hook" = (Convert-ToYamlPath $HookPath)
    }

    foreach ($Entry in $ConfigReplacements.GetEnumerator()) {
        $ConfigContent = $ConfigContent.Replace($Entry.Key, $Entry.Value)
    }

    Set-Content -Path $ConfigPath -Value $ConfigContent -Encoding UTF8
    Write-Host "  Config created. Review session secrets and listener ports before production use." -ForegroundColor Green
} else {
    Write-Host "Configuration already exists: $ConfigPath" -ForegroundColor Gray
}

Write-Host ""
Write-Host "Installing Windows service wrapper..." -ForegroundColor Yellow
& $DestServiceBinary install --binary $DestBinary --config $ConfigPath --workdir $InstallPath
if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to install service. Exit code: $LASTEXITCODE"
    exit $LASTEXITCODE
}

Write-Host "Starting Windows service..." -ForegroundColor Yellow
& $DestServiceBinary start
if ($LASTEXITCODE -ne 0) {
    Write-Error "Service installed, but failed to start. Exit code: $LASTEXITCODE"
    exit $LASTEXITCODE
}

Write-Host ""
Write-Host "Installation complete!" -ForegroundColor Green
Write-Host ""
Write-Host "Installed files:" -ForegroundColor Cyan
Write-Host "  Binary: $DestBinary" -ForegroundColor White
Write-Host "  Service wrapper: $DestServiceBinary" -ForegroundColor White
Write-Host "  Config: $ConfigPath" -ForegroundColor White
Write-Host "  WorkDir: $InstallPath" -ForegroundColor White
Write-Host "  Data: $DataPath" -ForegroundColor White
Write-Host ""
Write-Host "Useful commands:" -ForegroundColor Cyan
Write-Host "  & '$DestServiceBinary' stop" -ForegroundColor White
Write-Host "  & '$DestServiceBinary' start" -ForegroundColor White
Write-Host "  Get-Service SFTPxy" -ForegroundColor White
