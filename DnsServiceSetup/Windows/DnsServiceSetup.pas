//Include the sc functionality
#include "service.pas"

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

procedure TaskKill(fileName: String); //Kills an app by its filename
var
    ResultCode: Integer;
begin
    Exec(ExpandConstant('taskkill.exe'), '/f /im ' + '"' + fileName + '"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

procedure KillTrayApp; //Kill the tray app. Inno Setup cannot seem to close it through the "Close Applications" dialog.
begin
  TaskKill('{#TRAYAPP_FILENAME}');
end;

procedure DoRemoveService(); //Removes the dns service from the scm
begin
  if IsServiceInstalled('{#SERVICE_NAME}') then begin
    Log('Service: Already installed');
    if IsServiceRunning('{#SERVICE_NAME}') then begin
      Log('Service: Already running');
      StopService('{#SERVICE_NAME}');
      Sleep(3000);
    end;

    Log('Service: Remove');
    RemoveService('{#SERVICE_NAME}');
    Sleep(3000);
  end;
end;

procedure DoInstallService(); //Adds the dns service to the scm
var
  InstallSuccess: Boolean;
  MsgResult: Integer;
begin
  Log('Service: Begin Install');
  InstallSuccess := InstallService(ExpandConstant('{app}\DnsService.exe'), '{#SERVICE_NAME}', '{#SERVICE_DISPLAY_NAME}', '{#SERVICE_DESCRIPTION}', SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START);
  if not InstallSuccess then
  begin
    Log('Service: Install Fail ' + ServiceErrorToMessage(GetLastError()));
    SuppressibleMsgBox(ExpandConstant('{cm:ServiceInstallFailure,' + ServiceErrorToMessage(GetLastError()) + '}'), mbCriticalError, MB_OK, IDOK);
  end else begin
    Log('Service: Install Success, Starting');
    StartService('{#SERVICE_NAME}');
  end;
end;

procedure RemoveConfiguration(); //Removes the configuration left by the DNS Server
var 
  DeleteSuccess: Boolean;
begin
    Log('Delete configuration folder');
    DeleteSuccess := DelTree(ExpandConstant('{#CONFIG_FOLDER}'), True, True, True);
    if not DeleteSuccess then
    begin
      Log('Not all configuration files were deleted succesfully in ' + ExpandConstant('{#CONFIG_FOLDER}'));
      SuppressibleMsgBox(ExpandConstant('{cm:RemoveConfigFail}'), mbError, MB_OK, IDOK);
    end;
end;

procedure PromptRemoveConfiguration(); //Asks users if they want their config removed. On unattended installs, will keep config unless /removeconfig=true is supplied
begin
  case ExpandConstant('{param:removeconfig|prompt}') of
  'prompt': 
    if SuppressibleMsgBox(ExpandConstant('{cm:RemoveConfig}'),  mbConfirmation, MB_YESNO or MB_DEFBUTTON2, IDNO) = IDYES then
    begin
      RemoveConfiguration();
    end;
  'true':
    RemoveConfiguration();
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usUninstall then
  begin
    KillTrayApp();
    DoRemoveService();
    PromptRemoveConfiguration();
  end;
end;