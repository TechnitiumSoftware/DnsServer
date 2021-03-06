{
    Legacy Installer Functionality
}

{
    Checks if the MSI Installer is installed
}
function IsLegacyInstallerInstalled: Boolean;
var
  Value: string;
  UninstallKey: string;
begin
  UninstallKey := 'Software\Microsoft\Windows\CurrentVersion\Uninstall\{#LEGACY_INSTALLER_APPID}';
  Result := (RegQueryStringValue(HKLM, UninstallKey, 'UninstallString', Value) or
    RegQueryStringValue(HKCU, UninstallKey, 'UninstallString', Value)) and (Value <> '');
end;

{
    Checks if Configuration exists in the old location.
}
function IsLegacyConfigAvailable: Boolean;
var
  Value: string;
begin
  Result := DirExists(ExpandConstant('{#LEGACY_INSTALLER_CONFIG_PATH}'));
end;

{
    Uninstalls Legacy Installer
}
procedure UninstallLegacyInstaller;
var
  ResultCode: Integer;
begin
  if IsLegacyInstallerInstalled then begin
    Log('Uninstall MSI installer item');
    ResultCode := MsiExecUnins('{#LEGACY_INSTALLER_APPID}');
    Log('Result code ' + IntToStr(ResultCode));
  end;
end;

{
    Migrates the Configuration to the new location
}
procedure MigrateConfiguration();
var
  ConfigDirExists : Boolean;
begin

  if IsLegacyConfigAvailable then begin 
    Log('Begin Configuration Migration');

    ConfigDirExists := DirExists(ExpandConstant('{#CONFIG_FOLDER_COMPANY}'));

    if not ConfigDirExists then begin
      Log('Create config folder company');
      CreateDir(ExpandConstant('{#CONFIG_FOLDER_COMPANY}'));
    end;

      ConfigDirExists := DirExists(ExpandConstant('{#CONFIG_FOLDER_FULL}'));

    if not ConfigDirExists then begin
      Log('Create config folder program');
      CreateDir(ExpandConstant('{#CONFIG_FOLDER_FULL}'));
    end;

    DirectoryCopy(ExpandConstant('{#LEGACY_INSTALLER_CONFIG_PATH}'), ExpandConstant('{#CONFIG_FOLDER_FULL}'));

    DelTree(ExpandConstant('{#LEGACY_INSTALLER_CONFIG_PATH}'), true, true, true);

    Log('Complete Configuration Migration');
  end;
end;