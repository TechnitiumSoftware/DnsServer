[Code]
{
    Helper functions
}

{
    Checks to see if the installer is an 'upgrade'
}
function IsUpgrade: Boolean;
var
    Value: string;
    UninstallKey: string;
begin
    UninstallKey := 'Software\Microsoft\Windows\CurrentVersion\Uninstall\' +
        ExpandConstant('{#SetupSetting("AppId")}') + '_is1';
    Result := (RegQueryStringValue(HKLM, UninstallKey, 'UninstallString', Value) or
        RegQueryStringValue(HKCU, UninstallKey, 'UninstallString', Value)) and (Value <> '');
end;

{
    Kills a running program by its filename
}
procedure TaskKill(fileName: String);
var
    ResultCode: Integer;
begin
    Exec(ExpandConstant('taskkill.exe'), '/f /im ' + '"' + fileName + '"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;


{
    Executes the MSI Uninstall by GUID functionality
}
function MsiExecUnins(appId: String): Integer;
var 
  ResultCode: Integer;
begin
  ShellExec('', 'msiexec.exe', '/x ' + appId + ' /norestart /qb', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Result := ResultCode;
end;
