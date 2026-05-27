# SFTPxy Windows Installation Script
# Run this script as Administrator

param(
    [string]$InstallPath = "C:\Program Files\SFTPxy",
    [string]$DataPath = "C:\ProgramData\SFTPxy",
    [string]$ConfigPath = "$InstallPath\config.yaml"
)

# Check if running as Administrator
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "This script must be run as Administrator. Please right-click and select 'Run as Administrator'."
    exit 1
}

Write-Host "SFTPxy Windows Installation" -ForegroundColor Cyan
Write-Host "=========================" -ForegroundColor Cyan
Write-Host ""

# Create installation directory
Write-Host "Creating installation directory: $InstallPath" -ForegroundColor Yellow
if (-Not (Test-Path $InstallPath)) {
    New-Item -ItemType Directory -Path $InstallPath -Force | Out-Null
    Write-Host "  Created: $InstallPath" -ForegroundColor Green
} else {
    Write-Host "  Already exists: $InstallPath" -ForegroundColor Gray
}

# Create data directory
Write-Host "Creating data directory: $DataPath" -ForegroundColor Yellow
if (-Not (Test-Path $DataPath)) {
    New-Item -ItemType Directory -Path $DataPath -Force | Out-Null
    Write-Host "  Created: $DataPath" -ForegroundColor Green
} else {
    Write-Host "  Already exists: $DataPath" -ForegroundColor Gray
}

# Copy binary
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$SourceBinary = Join-Path $ScriptDir "..\..\bin\sftpxy.exe"
$DestBinary = Join-Path $InstallPath "sftpxy.exe"

if (Test-Path $SourceBinary) {
    Write-Host "Copying binary to: $DestBinary" -ForegroundColor Yellow
    Copy-Item -Path $SourceBinary -Destination $DestBinary -Force
    Write-Host "  Binary copied successfully" -ForegroundColor Green
} else {
    Write-Warning "Binary not found at: $SourceBinary"
    Write-Warning "Please build the binary first using: go build -o bin/sftpxy.exe ./cmd/sftpxy"
}

# Copy example config if config doesn't exist
if (-Not (Test-Path $ConfigPath)) {
    $ExampleConfig = Join-Path $ScriptDir "..\..\config.yaml.example"
    if (Test-Path $ExampleConfig) {
        Write-Host "Copying example configuration to: $ConfigPath" -ForegroundColor Yellow
        Copy-Item -Path $ExampleConfig -Destination $ConfigPath
        Write-Host "  Config copied. Please edit $ConfigPath to customize settings" -ForegroundColor Green
    }
} else {
    Write-Host "Configuration already exists: $ConfigPath" -ForegroundColor Gray
}

# Install Windows service
Write-Host ""
Write-Host "Installing Windows service..." -ForegroundColor Yellow
& "$DestBinary" install

if ($LASTEXITCODE -eq 0) {
    Write-Host "Service installed successfully!" -ForegroundColor Green
    Write-Host ""
    Write-Host "To start the service, run:" -ForegroundColor Cyan
    Write-Host "  sftpxy.exe start" -ForegroundColor White
    Write-Host ""
    Write-Host "Or use Services Manager (services.msc) to manage the service." -ForegroundColor Cyan
} else {
    Write-Error "Failed to install service. Exit code: $LASTEXITCODE"
}

Write-Host ""
Write-Host "Installation complete!" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "  1. Edit configuration: $ConfigPath" -ForegroundColor White
Write-Host "  2. Start service: & '$InstallPath\sftpxy.exe' start" -ForegroundColor White
Write-Host "  3. Check service status in Services Manager" -ForegroundColor White
Write-Host ""
