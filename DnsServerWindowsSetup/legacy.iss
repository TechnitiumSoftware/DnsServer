#define LEGACY_INSTALLER_APPID "{9B86AC7F-53B3-4E31-B245-D4602D16F5C8}"

[Code]

{
    Legacy Installer Functionality
}

{
    Checks if the MSI Installer is installed
}
function IsLegacyInstallerInstalled: Boolean;
var
  Value: string;
  UninstallKey1, UninstallKey2: string;
begin
  UninstallKey1 := 'Software\Microsoft\Windows\CurrentVersion\Uninstall\{#LEGACY_INSTALLER_APPID}';
  UninstallKey2 := 'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{#LEGACY_INSTALLER_APPID}';
  Result := (
    RegQueryStringValue(HKLM, UninstallKey1, 'UninstallString', Value) or
    RegQueryStringValue(HKCU, UninstallKey1, 'UninstallString', Value) or
    RegQueryStringValue(HKLM, UninstallKey2, 'UninstallString', Value)
    ) and (Value <> '');
end;

{
    Uninstalls Legacy Installer
}
procedure UninstallLegacyInstaller;
var
  ResultCode: Integer;
begin
    Log('Uninstall MSI installer item');
    ResultCode := MsiExecUnins('{#LEGACY_INSTALLER_APPID}');
    Log('Result code ' + IntToStr(ResultCode));
end;
