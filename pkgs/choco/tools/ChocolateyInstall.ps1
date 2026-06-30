$ErrorActionPreference  = 'Stop'
$packageName    = 'SFTPxy'
$softwareName   = 'SFTPxy'
$url            = 'https://github.com/jincaiw/sftpxy/releases/download/v0.2.2/SFTPxy_v0.2.2_windows_x86_64.exe'
$checksum       = ''
$silentArgs     = '/VERYSILENT'
$validExitCodes = @(0)

$packageArgs = @{
  packageName   = $packageName
  fileType      = 'exe'
  file          = $fileLocation
  url           = $url
  checksum      = $checksum
  checksumType  = 'sha256'
  silentArgs    = $silentArgs
  validExitCodes= $validExitCodes
  softwareName  = $softwareName
}

Install-ChocolateyPackage @packageArgs

$DefaultDataPath = Join-Path -Path $ENV:ProgramData -ChildPath "SFTPxy"
$DefaultConfigurationFilePath = Join-Path -Path $DefaultDataPath -ChildPath "SFTPxy.json"
$EnvDirPath = Join-Path -Path $DefaultDataPath -ChildPath "env.d"

# `t = tab
Write-Output "---------------------------"
Write-Output ""
Write-Output "If you have never used SFTPxy before, the web administration panel is located here:"
Write-Output "`thttp://localhost:30080/"
Write-Output ""
Write-Output "Default web administration port:"
Write-Output "`t30080"
Write-Output "Default web client port:"
Write-Output "`t30081"
Write-Output "Default SFTP port:"
Write-Output "`t30082"
Write-Output ""
Write-Output "Default data location:"
Write-Output "`t$DefaultDataPath"
Write-Output "Default configuration file location:"
Write-Output "`t$DefaultConfigurationFilePath"
Write-Output "Directory to create environment variable files to set custom configurations:"
Write-Output "`t$EnvDirPath"
Write-Output "If the SFTPxy service does not start, make sure that TCP ports 30080, 30081, 30082 and 30085-30088 are"
Write-Output "not used by other services or change the SFTPxy configuration to suit your needs."
Write-Output ""
Write-Output "Source:"
Write-Output "`thttps://github.com/jincaiw/sftpxy"
Write-Output "Documentation:"
Write-Output "`thttps://sftp.mujizi.com/"
Write-Output ""
Write-Output "---------------------------"
