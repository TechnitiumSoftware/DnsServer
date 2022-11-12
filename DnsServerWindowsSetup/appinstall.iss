
#include "service.iss"

#define SERVICE_NAME "DnsService"
#define SERVICE_FILE "DnsService.exe"
#define SERVICE_DISPLAY_NAME "Technitium DNS Server"
#define SERVICE_DESCRIPTION "Technitium DNS Server"
#define TRAYAPP_FILENAME "DnsServerSystemTrayApp.exe"

[Code]
{
  Kills the tray app
}
procedure KillTrayApp;
begin
  TaskKill('{#TRAYAPP_FILENAME}');
end;

{
    Resets Network DNS to default
}
procedure ResetNetworkDNS;
var
    ResultCode: Integer;
begin
    Exec(ExpandConstant('{app}\{#TRAYAPP_FILENAME}'), '--network-dns-default-exit', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

{
  Stops the service
}
procedure DoStopService();
var
  stopCounter: Integer;
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
          Sleep(5000);
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
        Sleep(5000);
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
  stopCounter: Integer;
begin
  stopCounter := 0;
  if IsServiceInstalled('{#SERVICE_NAME}') then begin
    Log('Service: Already installed, skip install service');
  end else begin 
    Log('Service: Begin Install');
    InstallSuccess := InstallService(ExpandConstant('"{app}\DnsService.exe"'), '{#SERVICE_NAME}', '{#SERVICE_DISPLAY_NAME}', '{#SERVICE_DESCRIPTION}', SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START);
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
          Sleep(5000);
          stopCounter := stopCounter + 1
        end;
      end;
      if stopCounter < 4 then Log('Service: Started');
    end;
  end;
end;
