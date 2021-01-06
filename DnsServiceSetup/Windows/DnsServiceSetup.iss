#define PRODUCT_NAME "DNS Server"
#define APPID "{{9B86AC7F-53B3-4E31-B245-D4602D16F5C8}"
#define PRODUCT_VERSION "5.6"
#define COMPANY "Technitium"
#define TITLE "Technitium DNS Server"
#define FILES_LOCATION "..\..\DnsService\bin\Release"
#define TRAYAPP_LOCATION "..\..\DnsServerSystemTrayApp\obj\Release"
#define TRAYAPP_FILENAME "DnsServerSystemTrayApp.exe"

[Setup]
PrivilegesRequired=admin
AppName={#TITLE}
AppVersion={#PRODUCT_VERSION}
AppId={#APPID}
DefaultDirName={commonpf}\{#COMPANY}\{#PRODUCT_NAME}
DefaultGroupName={#COMPANY}
DisableProgramGroupPage=yes
AppCopyright=Copyright (c) 2021 {#COMPANY}
AppPublisher={#COMPANY}
OutputDir=..\Release
OutputBaseFilename=DnsServiceSetup
CloseApplications=no
Compression=lzma2/max
SetupIconFile=logo.ico
WizardSmallImageFile=logo.bmp

[Files]
Source: "{#TRAYAPP_LOCATION}\{#TRAYAPP_FILENAME}"; DestDir: "{app}"; BeforeInstall: KillTrayApp;
Source: "{#FILES_LOCATION}\*.*"; Excludes: "*.pdb,DnsService.exe"; DestDir: "{app}"; Flags: recursesubdirs;
Source: "{#FILES_LOCATION}\DnsService.exe"; DestDir: "{app}"; Flags: recursesubdirs; BeforeInstall: DoRemoveService; AfterInstall: DoInstallService;

[Tasks]
Name: "desktopicon"; Description: "Create an icon on the &desktop";

[CustomMessages]
ServiceName=DnsService
ServiceDisplayName=Technitium DNS Server
ServiceInstallFailure=The DNS Service could not be installed. %1
ServiceManagerUnavailable=The Service Manager is not available!
DependenciesDir=.

[Registry]
Root: HKLM; Subkey: "Software\{#COMPANY}"; Flags: uninsdeletekeyifempty
Root: HKCU; Subkey: "Software\{#COMPANY}"; Flags: uninsdeletekeyifempty

[Icons]
Name: "{userprograms}\Technitium DNS Server"; Comment: "DNS Server Tray App"; Filename: "{app}\DnsServerSystemTrayApp.exe"; WorkingDir: "{app}\"; Flags: createonlyiffileexists
Name: "{userdesktop}\Technitium DNS Server"; Filename: "{app}\DnsServerSystemTrayApp.exe"; WorkingDir: "{app}\"; Flags: createonlyiffileexists; Tasks: desktopicon

#include "depend\lang\english.iss"
#include "depend\products.iss"
#include "depend\products\dotnet5.iss"

[Code]
#include "DnsServiceSetup.pas"