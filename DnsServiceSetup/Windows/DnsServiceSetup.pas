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

procedure DoStopService(); //Stops the dns service in the scm to allow it to update
var
  stopCounter: Integer;
  serviceStopped: Boolean;
begin
  stopCounter := 0;
  if IsServiceInstalled('{#SERVICE_NAME}') then begin
    Log('Service: Already installed');
    if IsServiceRunning('{#SERVICE_NAME}') then begin
      Log('Service: Already running, stopping service...');
      StopService('{#SERVICE_NAME}');

      while IsServiceRunning('{#SERVICE_NAME}') do
      begin
       if stopCounter > 2 then begin
         Log('Service: Waited too long to stop, killing task...');
         TaskKill('{#SERVICE_FILE}');
         Log('Service: Task killed');
         break;
       end else begin
         Log('Service: Waiting for stop');
         Sleep(2000);
         stopCounter := stopCounter + 1
       end;
      end;
      if stopCounter < 3 then Log('Service: Stopped');
    end;
  end;
end;

procedure DoRemoveService(); //Removes the dns service from the scm
var
  stopCounter: Integer;
begin
  stopCounter := 0;
  if IsServiceInstalled('{#SERVICE_NAME}') then begin
    Log('Service: Already installed, begin remove...');
    if IsServiceRunning('{#SERVICE_NAME}') then begin
      Log('Service: Already running, stopping...');
      StopService('{#SERVICE_NAME}');
      while IsServiceRunning('{#SERVICE_NAME}') do
      begin
        if stopCounter > 2 then begin
          Log('Service: Waited too long to stop, killing task...');
          TaskKill('{#SERVICE_FILE}');
          Log('Service: Task killed');
          break;
        end else begin
          Log('Service: Waiting for stop');
          Sleep(2000);
          stopCounter := stopCounter + 1
        end;
      end;
    end;

    stopCounter := 0;
    Log('Service: Removing...');
    RemoveService('{#SERVICE_NAME}');
    while IsServiceInstalled('{#SERVICE_NAME}') do
    begin
      if stopCounter > 2 then begin
        Log('Service: Waited too long to remove, continuing');
        break;
      end else begin
        Log('Service: Waiting for removal');
        Sleep(2000);
        stopCounter := stopCounter + 1
      end;
    end;
    if stopCounter < 3 then Log('Service: Removed');
  end;
end;

procedure DoInstallService(); //Adds the dns service to the scm if not already installed
var
  InstallSuccess: Boolean;
  StartServiceSuccess: Boolean;
  MsgResult: Integer;
  stopCounter: Integer;
begin
  stopCounter := 0;
  if IsServiceInstalled('{#SERVICE_NAME}') then begin
    Log('Service: Already installed, skip install service');
  end else begin 
    Log('Service: Begin Install');
    InstallSuccess := InstallService(ExpandConstant('{app}\DnsService.exe'), '{#SERVICE_NAME}', '{#SERVICE_DISPLAY_NAME}', '{#SERVICE_DESCRIPTION}', SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START);
    if not InstallSuccess then
    begin
      Log('Service: Install Fail ' + ServiceErrorToMessage(GetLastError()));
      SuppressibleMsgBox(ExpandConstant('{cm:ServiceInstallFailure,' + ServiceErrorToMessage(GetLastError()) + '}'), mbCriticalError, MB_OK, IDOK);
    end else begin
      Log('Service: Install Success, Starting...');
      StartService('{#SERVICE_NAME}');

      while IsServiceRunning('{#SERVICE_NAME}') <> true do
      begin
        if stopCounter > 3 then begin
          Log('Service: Waited too long to start, continue');
          break;
        end else begin
          Log('Service: still starting')
          Sleep(2000);
          stopCounter := stopCounter + 1
        end;
      end;
      if stopCounter < 4 then Log('Service: Started');
    end;
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

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssInstall then begin //Step happens just before installing files
    KillTrayApp(); //Stop the tray app if running
    DoRemoveService(); //Stop and remove the service if installed
  end;
  if CurStep = ssPostInstall then begin //Step happens just after installing files
    DoInstallService(); //Install service after all files installed
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usUninstall then //Step happens before processing uninstall log
  begin
    KillTrayApp(); //Stop the tray app if running
    DoRemoveService(); //Stop and remove the service
  end;
  if CurUninstallStep = usPostUninstall then //Step happens after processing uninstall log
  begin
    PromptRemoveConfiguration(); //Ask to remove any left over configuration files
  end;
end;