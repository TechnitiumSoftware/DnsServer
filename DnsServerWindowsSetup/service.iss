[Code]

type
	SERVICE_STATUS = record
    	dwServiceType				: cardinal;
    	dwCurrentState				: cardinal;
    	dwControlsAccepted			: cardinal;
    	dwWin32ExitCode				: cardinal;
    	dwServiceSpecificExitCode	: cardinal;
    	dwCheckPoint				: cardinal;
    	dwWaitHint					: cardinal;
	end;
	HANDLE = cardinal;

const
	SERVICE_QUERY_CONFIG		= $1;
	SERVICE_CHANGE_CONFIG		= $2;
	SERVICE_QUERY_STATUS		= $4;
	SERVICE_START				= $10;
	SERVICE_STOP				= $20;
	SERVICE_ALL_ACCESS			= $f01ff;
	SC_MANAGER_ALL_ACCESS		= $f003f;
	SERVICE_WIN32_OWN_PROCESS	= $10;
	SERVICE_WIN32_SHARE_PROCESS	= $20;
	SERVICE_WIN32				= $30;
	SERVICE_INTERACTIVE_PROCESS = $100;
	SERVICE_BOOT_START          = $0;
	SERVICE_SYSTEM_START        = $1;
	SERVICE_AUTO_START          = $2;
	SERVICE_DEMAND_START        = $3;
	SERVICE_DISABLED            = $4;
	SERVICE_DELETE              = $10000;
	SERVICE_CONTROL_STOP		= $1;
	SERVICE_CONTROL_PAUSE		= $2;
	SERVICE_CONTROL_CONTINUE	= $3;
	SERVICE_CONTROL_INTERROGATE = $4;
	SERVICE_STOPPED				= $1;
	SERVICE_START_PENDING       = $2;
	SERVICE_STOP_PENDING        = $3;
	SERVICE_RUNNING             = $4;
	SERVICE_CONTINUE_PENDING    = $5;
	SERVICE_PAUSE_PENDING       = $6;
	SERVICE_PAUSED              = $7;


	ERROR_ACCESS_DENIED               = 5;
	ERROR_CIRCULAR_DEPENDENCY         = 1059;
	ERROR_DUPLICATE_SERVICE_NAME      = 1078;
	ERROR_INVALID_HANDLE              = 6;
	ERROR_INVALID_NAME                = 123;
	ERROR_INVALID_PARAMETER           = 87;
	ERROR_INVALID_SERVICE_ACCOUNT     = 1057;
	ERROR_SERVICE_EXISTS              = 1073;
	ERROR_SERVICE_MARKED_FOR_DELETE   = 1072;
	
// #######################################################################################
// nt based service utilities
// #######################################################################################
function OpenSCManager(lpMachineName, lpDatabaseName: string; dwDesiredAccess :cardinal): HANDLE;
external 'OpenSCManagerW@advapi32.dll stdcall';

function OpenService(hSCManager :HANDLE;lpServiceName: string; dwDesiredAccess :cardinal): HANDLE;
external 'OpenServiceW@advapi32.dll stdcall';

function CloseServiceHandle(hSCObject :HANDLE): boolean;
external 'CloseServiceHandle@advapi32.dll stdcall';

function CreateService(hSCManager :HANDLE;lpServiceName, lpDisplayName: string;dwDesiredAccess,dwServiceType,dwStartType,dwErrorControl: cardinal;lpBinaryPathName,lpLoadOrderGroup: String; lpdwTagId : cardinal;lpDependencies,lpServiceStartName,lpPassword :string): cardinal;
external 'CreateServiceW@advapi32.dll stdcall';

function DeleteService(hService :HANDLE): boolean;
external 'DeleteService@advapi32.dll stdcall';

function StartNTService(hService :HANDLE;dwNumServiceArgs : cardinal;lpServiceArgVectors : cardinal) : boolean;
external 'StartServiceW@advapi32.dll stdcall';

function ControlService(hService :HANDLE; dwControl :cardinal;var ServiceStatus :SERVICE_STATUS) : boolean;
external 'ControlService@advapi32.dll stdcall';

function QueryServiceStatus(hService :HANDLE;var ServiceStatus :SERVICE_STATUS) : boolean;
external 'QueryServiceStatus@advapi32.dll stdcall';

function QueryServiceStatusEx(hService :HANDLE;ServiceStatus :SERVICE_STATUS) : boolean;
external 'QueryServiceStatus@advapi32.dll stdcall';

function GetLastError(): dword;
external 'GetLastError@kernel32.dll stdcall';

function OpenServiceManager(): HANDLE;
begin
	if UsingWinNT() = true then begin
		Result := OpenSCManager('', 'ServicesActive', SC_MANAGER_ALL_ACCESS);
		if Result = 0 then
			MsgBox(ExpandConstant('{cm:ServiceManagerUnavailable}'), mbError, MB_OK);
	end
	else begin
        MsgBox('only nt based systems support services', mbError, MB_OK);
        Result := 0;
	end
end;

function IsServiceInstalled(ServiceName: string): boolean;
var
	hSCM	: HANDLE;
	hService: HANDLE;
begin
	hSCM := OpenServiceManager();
	Result := false;
	if hSCM <> 0 then begin
		hService := OpenService(hSCM, ServiceName, SERVICE_QUERY_CONFIG);
        if hService <> 0 then begin
            Result := true;
            CloseServiceHandle(hService);
		end;
        CloseServiceHandle(hSCM);
	end
end;

function InstallService(FileName, ServiceName, DisplayName, Description: string; ServiceType, StartType: cardinal): boolean;
var
	hSCM	: HANDLE;
	hService: HANDLE;
begin
	hSCM := OpenServiceManager();
	Result := false;
	if hSCM <> 0 then begin
		hService := CreateService(hSCM, ServiceName, DisplayName, SERVICE_ALL_ACCESS, ServiceType, StartType, 0, FileName,'', 0, '', '', '');
		if hService <> 0 then begin
			Result := true;
			// Win2K & WinXP supports aditional description text for services
			if Description <> '' then
				RegWriteStringValue(HKLM,'System\CurrentControlSet\Services\' + ServiceName, 'Description', Description);
			CloseServiceHandle(hService);
		end;
        CloseServiceHandle(hSCM);
	end;
end;

function RemoveService(ServiceName: string): boolean;
var
	hSCM	: HANDLE;
	hService: HANDLE;
begin
	hSCM := OpenServiceManager();
	Result := false;
	if hSCM <> 0 then begin
		hService := OpenService(hSCM, ServiceName, SERVICE_DELETE);
        if hService <> 0 then begin
            Result := DeleteService(hService);
            CloseServiceHandle(hService);
		end;
        CloseServiceHandle(hSCM);
	end;
end;

function StartService(ServiceName: string): boolean;
var
	hSCM	: HANDLE;
	hService: HANDLE;
begin
	hSCM := OpenServiceManager();
	Result := false;
	if hSCM <> 0 then begin
		hService := OpenService(hSCM, ServiceName, SERVICE_START);
        if hService <> 0 then begin
        	Result := StartNTService(hService, 0, 0);
            CloseServiceHandle(hService);
		end;
        CloseServiceHandle(hSCM);
	end;
end;

function StopService(ServiceName: string): boolean;
var
	hSCM	: HANDLE;
	hService: HANDLE;
	Status	: SERVICE_STATUS;
begin
	hSCM := OpenServiceManager();
	Result := false;
	if hSCM <> 0 then begin
		hService := OpenService(hSCM, ServiceName, SERVICE_STOP);
        if hService <> 0 then begin
        	Result := ControlService(hService, SERVICE_CONTROL_STOP, Status);
            CloseServiceHandle(hService);
		end;
        CloseServiceHandle(hSCM);
	end;
end;

function IsServiceRunning(ServiceName: string): boolean;
var
	hSCM	: HANDLE;
	hService: HANDLE;
	Status	: SERVICE_STATUS;
begin
	hSCM := OpenServiceManager();
	Result := false;
	if hSCM <> 0 then begin
		hService := OpenService(hSCM, ServiceName, SERVICE_QUERY_STATUS);
    	if hService <> 0 then begin
			if QueryServiceStatus(hService, Status) then begin
				Result :=(Status.dwCurrentState = SERVICE_RUNNING);
        	end;
            CloseServiceHandle(hService);
		end;
        CloseServiceHandle(hSCM);
	end
end;

function ServiceErrorToMessage(Error: word): string;
begin
	case Error of 
		ERROR_ACCESS_DENIED: Result := 'Access Denied';
		ERROR_CIRCULAR_DEPENDENCY: Result := 'Circular Dependency';
		ERROR_DUPLICATE_SERVICE_NAME: Result := 'Duplicate Service Name';
		ERROR_INVALID_HANDLE: Result := 'Invalid Handle';
		ERROR_INVALID_NAME: Result := 'Invalid Name';
		ERROR_INVALID_PARAMETER: Result := 'Invalid Parameter';
		ERROR_INVALID_SERVICE_ACCOUNT: Result := 'Invalid Service Account';
		ERROR_SERVICE_EXISTS: Result := 'Service Exists';
		ERROR_SERVICE_MARKED_FOR_DELETE: Result := 'Service Marked For Deletion';
	else
		Result := 'Unknown error: ' + IntToStr(Error);
	end;
end;