#define PRODUCT_NAME "DNS Server"
#define APPID "{{9B86AC7F-53B3-4E31-B245-D4602D16F5C8}"
#define PRODUCT_VERSION "5.6"
#define COMPANY "Technitium"
#define TITLE "Technitium DNS Server"

#define FILES_LOCATION "..\..\DnsService\bin\Release"
#define TRAYAPP_LOCATION "..\..\DnsServerSystemTrayApp\obj\Release"
#define TRAYAPP_FILENAME "DnsServerSystemTrayApp.exe"

#define SERVICE_NAME "DnsService"
#define SERVICE_FILE "DnsService.exe"
#define SERVICE_DISPLAY_NAME "Technitium DNS Server"
#define SERVICE_DESCRIPTION "Technitium DNS Server"
#define CONFIG_FOLDER "{app}\config"

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
Source: "{#TRAYAPP_LOCATION}\{#TRAYAPP_FILENAME}"; DestDir: "{app}";
Source: "{#FILES_LOCATION}\*.*"; Excludes: "*.pdb"; DestDir: "{app}"; Flags: recursesubdirs;

[Tasks]
Name: "desktopicon"; Description: "Create an icon on the &desktop";

[CustomMessages]
RemoveConfig=Do you want to remove the configuration files?%n%nClick No to keep your settings.
RemoveConfigFail=Some configuration files could not be automatically removed.
ServiceInstallFailure=The DNS Service could not be installed. %1
ServiceManagerUnavailable=The Service Manager is not available!
DependenciesDir=.

[Registry]
Root: HKLM; Subkey: "Software\{#COMPANY}"; Flags: uninsdeletekeyifempty
Root: HKCU; Subkey: "Software\{#COMPANY}"; Flags: uninsdeletekeyifempty

[Icons]
Name: "{userprograms}\Technitium DNS Server"; Comment: "DNS Server Tray App"; Filename: "{app}\DnsServerSystemTrayApp.exe"; WorkingDir: "{app}\"; Flags: createonlyiffileexists
Name: "{userdesktop}\Technitium DNS Server"; Filename: "{app}\DnsServerSystemTrayApp.exe"; WorkingDir: "{app}\"; Flags: createonlyiffileexists; Tasks: desktopicon

[Run]
Filename: "{app}\DnsServerSystemTrayApp.exe"; Description: "Run the Tray App"; Flags: postinstall nowait

;Include the dependency code 
#include "depend\lang\english.iss"
#include "depend\products.iss"
#include "depend\products\dotnet5.iss"

[Code]
//Include the setup code
#include "DnsServiceSetup.pas"