#include "service.pas"
//Include the sc functionality

function IsUpgrade: Boolean; //Check to see if the install is an upgrade
var
    Value: string;
    UninstallKey: string;
begin
    UninstallKey := 'Software\Microsoft\Windows\CurrentVersion\Uninstall\' +
        ExpandConstant('{#SetupSetting("AppId")}') + '_is1';
    Result := (RegQueryStringValue(HKLM, UninstallKey, 'UninstallString', Value) or
        RegQueryStringValue(HKCU, UninstallKey, 'UninstallString', Value)) and (Value <> '');
end;

//Skips the Task selection screen if an upgrade install
function ShouldSkipPage(PageID: Integer): Boolean;
begin
  Result := (PageID = wpSelectTasks) and IsUpgrade;
end;

function InitializeSetup(): boolean;
begin
  //Specify the dependencies to install here
  dotnet_5_desktop(); 
  Result := true;
end;

procedure DoRemoveService(); //Removes the dns service from the scm
begin
  if IsServiceInstalled(ExpandConstant('{cm:ServiceName}')) then begin
    Log('Service: Already installed');
    if IsServiceRunning(ExpandConstant('{cm:ServiceName}')) then begin
      Log('Service: Already running');
      StopService(ExpandConstant('{cm:ServiceName}'));
      Sleep(5000);
    end;

    Log('Service: Remove');
    RemoveService(ExpandConstant('{cm:ServiceName}')) 
  end;
end;

procedure DoInstallService(); //Adds the dns service to the scm
var
  InstallSuccess: Boolean;
  MsgResult: Integer;
begin
  Log('Service: Begin Install');
  InstallSuccess := InstallService(ExpandConstant('{app}\DnsService.exe'), ExpandConstant('{cm:ServiceName}'), ExpandConstant('{cm:ServiceDisplayName}'), ExpandConstant('{cm:ServiceDisplayName}'), SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START);
  if not InstallSuccess then
  begin
    Log('Service: Install Fail ' + ServiceErrorToMessage(GetLastError()));
    SuppressibleMsgBox(ExpandConstant('{cm:ServiceInstallFailure,' + ServiceErrorToMessage(GetLastError()) + '}'), mbCriticalError, MB_OK, IDOK);
  end else begin
    Log('Service: Install Success, Starting');
    StartService(ExpandConstant('{cm:ServiceName}'));
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usUninstall then
  begin
    DoRemoveService();
  end;
end;