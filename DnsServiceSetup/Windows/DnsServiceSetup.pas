//Include the sc functionality
#include "service.pas"
#include "helper.pas"
#include "legacy.pas"

{
  Skips the tasks page if it is an upgrade install
}
function ShouldSkipPage(PageID: Integer): Boolean;
begin
  Result := (PageID = wpSelectTasks) and IsUpgrade;
end;

function InitializeSetup(): boolean;
begin
  //Specify the dependencies to install here
  dotnet_5_desktop(); 
  if IsLegacyInstallerInstalled or IsLegacyConfigAvailable then begin
   AdditionalMemo := AdditionalMemo + #13#10 + #13#10 + 'Previous Version:';
  end;
  if IsLegacyInstallerInstalled then begin 
    AdditionalMemo := AdditionalMemo + #13#10 + '      Remove Legacy Installer';
  end;
  if IsLegacyConfigAvailable then begin 
    AdditionalMemo := AdditionalMemo + #13#10 + '      Migrate Configuration';
  end;
  Result := true;
end;

{
  Kills the tray app
}
procedure KillTrayApp;
begin
  TaskKill('{#TRAYAPP_FILENAME}');
end;

{
  Stops the service
}
procedure DoStopService();
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

{
  Removes the service from the computer
}
procedure DoRemoveService();
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

{
  Installs the service onto the computer
}
procedure DoInstallService();
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

{
  Removes the generated configuration
}
procedure RemoveConfiguration();
var 
  DeleteSuccess: Boolean;
begin
    Log('Delete configuration folder');
    DeleteSuccess := DelTree(ExpandConstant('{#CONFIG_FOLDER_FULL}'), True, True, True);
    if not DeleteSuccess then
    begin
      Log('Not all configuration files were deleted succesfully in ' + ExpandConstant('{#CONFIG_FOLDER_FULL}'));
      SuppressibleMsgBox(ExpandConstant('{cm:RemoveConfigFail}'), mbError, MB_OK, IDOK);
    end;
end;

{
  Prompts to remove the configuration
  On unattended installs, will keep config unless /removeconfig=true is supplied
}
procedure PromptRemoveConfiguration();
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
    WizardForm.StatusLabel.Caption := 'Stopping Tray App...';
    KillTrayApp(); //Stop the tray app if running

    if IsLegacyInstallerInstalled or IsLegacyConfigAvailable then begin
      WizardForm.StatusLabel.Caption := 'Stopping Service...';
      DoStopService(); //Stop the service if running  

      WizardForm.StatusLabel.Caption := 'Removing Legacy Installer...';
      UninstallLegacyInstaller(); //Uninstall Legacy Installer if Installed already
      
      WizardForm.StatusLabel.Caption := 'Migrating Configuration...';
      MigrateConfiguration(); //Shift configuration into correct path
    end else begin
      WizardForm.StatusLabel.Caption := 'Uninstalling Service...';
      DoRemoveService(); //Stop and remove the service if installed
    end;
  end;
  if CurStep = ssPostInstall then begin //Step happens just after installing files
    WizardForm.StatusLabel.Caption := 'Installing Service...';
    DoInstallService(); //Install service after all files installed, if not a portable install
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usUninstall then //Step happens before processing uninstall log
  begin
    UninstallProgressForm.StatusLabel.Caption := 'Stopping Tray App...';
    KillTrayApp(); //Stop the tray app if running
    UninstallProgressForm.StatusLabel.Caption := 'Uninstalling Service...';
    DoRemoveService(); //Stop and remove the service
  end;
  if CurUninstallStep = usPostUninstall then //Step happens after processing uninstall log
  begin
    PromptRemoveConfiguration(); //Ask to remove any left over configuration files
  end;
end;