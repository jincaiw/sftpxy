#define MyAppName "SFTPxy"
#if GetEnv("SFTPXY_ISS_VERSION") != ""
    #define MyAppVersion GetEnv("SFTPXY_ISS_VERSION")
#else
    #define MyAppVersion GetEnv("SFTPXY_ISS_DEV_VERSION")
#endif
#if GetEnv("SFTPXY_ISS_ARCH") != ""
    #define MyAppArch GetEnv("SFTPXY_ISS_ARCH")
    #define MySetupName "SFTPxy_windows_" + MyAppArch
    #if MyAppArch == "x86"
        #define MyAppArch64 ""
    #else
        #define MyAppArch64 GetEnv("SFTPXY_ISS_ARCH")
    #endif
#else
    #define MyAppArch "x64"
    #define MyAppArch64 "x64"
    #define MySetupName "SFTPxy_windows_x86_64"
#endif
#define MyAppURL "https://github.com/jincaiw/sftpxy"
#define MyVersionInfo StringChange(MyAppVersion,"v","")
#define DocURL "https://sftp.mujizi.com/"
#define MyAppExeName "SFTPxy.exe"
#define MyAppDir "..\output"
#define MyOutputDir ".."

[Setup]
AppId={{1FB9D57F-00DD-4B1B-8798-1138E5CE995D}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher=jincaiw
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
AppCopyright=2026 jincaiw
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
LicenseFile=LICENSE_with_NOTICE.txt
OutputDir={#MyOutputDir}
OutputBaseFilename={#MySetupName}
SetupIconFile=icon.ico
SolidCompression=yes
UninstallDisplayIcon={app}\SFTPxy.exe
WizardStyle=modern
ArchitecturesInstallIn64BitMode={#MyAppArch64}
PrivilegesRequired=admin
ArchitecturesAllowed={#MyAppArch}
MinVersion=10.0.14393
VersionInfoVersion={#MyVersionInfo}
VersionInfoCopyright=2026 jincaiw

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Files]
Source: "{#MyAppDir}\SFTPxy.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#MyAppDir}\SFTPxy.db"; DestDir: "{commonappdata}\{#MyAppName}"; Flags: onlyifdoesntexist uninsneveruninstall
Source: "{#MyAppDir}\LICENSE.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#MyAppDir}\NOTICE.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#MyAppDir}\SFTPxy.json"; DestDir: "{commonappdata}\{#MyAppName}"; Flags: onlyifdoesntexist uninsneveruninstall
Source: "{#MyAppDir}\SFTPxy.json"; DestDir: "{commonappdata}\{#MyAppName}"; DestName: "SFTPxy_default.json"; Flags: ignoreversion
Source: "{#MyAppDir}\templates\*"; DestDir: "{commonappdata}\{#MyAppName}\templates"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#MyAppDir}\static\*"; DestDir: "{commonappdata}\{#MyAppName}\static"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#MyAppDir}\openapi\*"; DestDir: "{commonappdata}\{#MyAppName}\openapi"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "README.txt"; DestDir: "{app}"; Flags: ignoreversion isreadme

[Dirs]
Name: "{commonappdata}\{#MyAppName}\logs"; Permissions: everyone-full
Name: "{commonappdata}\{#MyAppName}\backups"; Permissions: everyone-full
Name: "{commonappdata}\{#MyAppName}\env.d"; Permissions: everyone-full
Name: "{commonappdata}\{#MyAppName}\certs"; Permissions: everyone-full

[Icons]
Name: "{group}\Web Admin"; Filename: "http://localhost:30080/web/admin/login";
Name: "{group}\Web Client"; Filename: "http://localhost:30081/web/client/login";
Name: "{group}\OpenAPI"; Filename: "http://localhost:30080/openapi/";
Name: "{group}\Service Control";  WorkingDir: "{app}"; Filename: "powershell.exe"; Parameters: "-Command ""Start-Process cmd \""/k cd {app} & {#MyAppExeName} service --help\"" -Verb RunAs"; Comment: "Manage SFTPxy Service"
Name: "{group}\Documentation"; Filename: "{#DocURL}";
Name: "{group}\{cm:UninstallProgram,{#MyAppName}}"; Filename: "{uninstallexe}"

[Run]
Filename: "netsh"; Parameters: "advfirewall firewall delete rule name=""SFTPxy Service"""; Flags: runhidden
Filename: "netsh"; Parameters: "advfirewall firewall add rule name=""SFTPxy Service"" dir=in action=allow program=""{app}\{#MyAppExeName}"""; Flags: runhidden
Filename: "{app}\{#MyAppExeName}"; Parameters: "service stop"; Flags: runhidden
Filename: "{app}\{#MyAppExeName}"; Parameters: "service uninstall"; Flags: runhidden
Filename: "{app}\{#MyAppExeName}"; Parameters: "service install -c ""{commonappdata}\{#MyAppName}"" -l ""logs\SFTPxy.log"""; Description: "Install SFTPxy Windows Service"; Flags: runhidden
Filename: "{app}\{#MyAppExeName}"; Parameters: "service start";  Description: "Start SFTPxy Windows Service"; Flags: runhidden

[UninstallRun]
Filename: "{app}\{#MyAppExeName}"; Parameters: "service stop"; Flags: runhidden; RunOnceId: "Stop SFTPxy service"
Filename: "{app}\{#MyAppExeName}"; Parameters: "service uninstall"; Flags: runhidden; RunOnceId: "Uninstall SFTPxy service"
Filename: "netsh"; Parameters: "advfirewall firewall delete rule name=""SFTPxy Service"""; Flags: runhidden; RunOnceId: "Remove SFTPxy firewall rule"

[Messages]
FinishedLabel=Setup has finished installing SFTPxy on your computer. SFTPxy should already be running as a Windows service. By default it uses TCP port 30080 for WebAdmin and REST/OpenAPI, 30081 for WebClient, 30082 for SFTP, and 30085-30088 for passive FTP. Make sure these ports are not used by other services or edit the configuration according to your needs.

[Code]

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  Code: Integer;
begin
  if (FileExists(ExpandConstant('{app}\{#MyAppExeName}'))) then
  begin
    Exec(ExpandConstant('{app}\{#MyAppExeName}'), 'service stop', '', SW_HIDE, ewWaitUntilTerminated, Code);
  end
end;
