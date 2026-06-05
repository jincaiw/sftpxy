# SFTPxy Windows Uninstallation Script
# Run this script as Administrator

param(
    [string]$InstallPath = "C:\Program Files\SFTPxy",
    [string]$DataPath = "C:\ProgramData\SFTPxy"
)

# Check if running as Administrator
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "This script must be run as Administrator. Please right-click and select 'Run as Administrator'."
    exit 1
}

Write-Host "SFTPxy Windows Uninstallation" -ForegroundColor Cyan
Write-Host "=============================" -ForegroundColor Cyan
Write-Host ""

# Stop service first
Write-Host "Stopping SFTPxy service..." -ForegroundColor Yellow
$ServiceBinary = Join-Path $InstallPath "sftpxy-service.exe"
if (Test-Path $ServiceBinary) {
    & $ServiceBinary stop 2>$null
    Start-Sleep -Seconds 2
}

# Remove Windows service
Write-Host "Removing Windows service..." -ForegroundColor Yellow
if (Test-Path $ServiceBinary) {
    & $ServiceBinary remove
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  Service removed successfully" -ForegroundColor Green
    } else {
        Write-Warning "  Failed to remove service (it may not be installed)"
    }
} else {
    Write-Warning "  Binary not found at: $ServiceBinary"
}

# Ask before deleting data
Write-Host ""
$DeleteData = Read-Host "Do you want to delete all data? (yes/no)"
if ($DeleteData -eq "yes") {
    if (Test-Path $DataPath) {
        Write-Host "Deleting data directory: $DataPath" -ForegroundColor Yellow
        Remove-Item -Path $DataPath -Recurse -Force
        Write-Host "  Data deleted" -ForegroundColor Green
    } else {
        Write-Host "  Data directory does not exist: $DataPath" -ForegroundColor Gray
    }
} else {
    Write-Host "  Keeping data directory: $DataPath" -ForegroundColor Gray
}

# Remove installation directory
Write-Host ""
$ConfirmRemove = Read-Host "Do you want to remove the installation directory? (yes/no)"
if ($ConfirmRemove -eq "yes") {
    if (Test-Path $InstallPath) {
        Write-Host "Removing installation directory: $InstallPath" -ForegroundColor Yellow
        Remove-Item -Path $InstallPath -Recurse -Force
        Write-Host "  Installation directory removed" -ForegroundColor Green
    } else {
        Write-Host "  Installation directory does not exist: $InstallPath" -ForegroundColor Gray
    }
} else {
    Write-Host "  Keeping installation directory: $InstallPath" -ForegroundColor Gray
}

Write-Host ""
Write-Host "Uninstallation complete!" -ForegroundColor Green
Write-Host ""
