const
  NoInstallNet = '{param:skipnet|false}'; //if this parameter is supplied on the command line then skip installing .NET dependencies

{ .NET 5.0.1 }

function DotNet_501_Desktop_Installed: Boolean;
var
  ResultCode: Integer;
begin
  Result := false;
  Exec('cmd.exe', '/c dotnet --list-runtimes | find /n "Microsoft.WindowsDesktop.App 5.0.1"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  if ResultCode = 0 then 
  begin 
    Result := true;
  end;
end;

function DotNet_501_Runtime_Installed: Boolean;
var
  ResultCode: Integer;
begin
  Result := false;
  Exec('cmd.exe', '/c dotnet --list-runtimes | find /n "Microsoft.NETCore.App 5.0.1"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  if ResultCode = 0 then 
  begin 
    Result := true;
  end;
end;

procedure dotnet_501_desktop;
begin
  if ExpandConstant(NoInstallNet) = 'false' then
  begin
    if not DotNet_501_Desktop_Installed() then
      AddProduct('windowsdesktop-runtime-5.0.1-win' + GetArchitectureString(true) + '.exe',
        '/install /quiet /norestart',
        GetString(CustomMessage('dotnet_501_desktop_title'), CustomMessage('dotnet_501_desktop_title_x64'), true),
        GetString(CustomMessage('dotnet_501_desktop_size'), CustomMessage('dotnet_501_desktop_size_x64'), true),
        GetString(CustomMessage('dotnet_501_desktop_url'), CustomMessage('dotnet_501_desktop_url_x64'), true),
        false, false, false);
  end;
end;

procedure dotnet_501_runtime;
begin
  if ExpandConstant(NoInstallNet) = 'false' then
  begin
	  if not DotNet_501_Runtime_Installed() then
		  AddProduct('dotnet-runtime-5.0.0-win' + GetArchitectureString(true) + '.exe',
			  '/install /quiet /norestart',
			  GetString(CustomMessage('dotnet_500_runtime_title'), CustomMessage('dotnet_500_runtime_title_x64'), true),
			  GetString(CustomMessage('dotnet_500_runtime_size'), CustomMessage('dotnet_500_runtime_size_x64'), true),
			  GetString(CustomMessage('dotnet_500_runtime_url'), CustomMessage('dotnet_500_runtime_url_x64'), true),
			  false, false, false);
  end;
end;

{ .NET 5.0.0 }

function DotNet_500_Desktop_Installed: Boolean;
var
  ResultCode: Integer;
begin
  Result := false;
  Exec('cmd.exe', '/c dotnet --list-runtimes | find /n "Microsoft.WindowsDesktop.App 5.0.0"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  if ResultCode = 0 then 
  begin 
    Result := true;
  end;
end;

function DotNet_500_Runtime_Installed: Boolean;
var
  ResultCode: Integer;
begin
  Result := false;
  Exec('cmd.exe', '/c dotnet --list-runtimes | find /n "Microsoft.NETCore.App 5.0.0"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  if ResultCode = 0 then 
  begin 
    Result := true;
  end;
end;

procedure dotnet_500_desktop;
begin
  if ExpandConstant(NoInstallNet) = 'false' then
  begin
    if not DotNet_500_Desktop_Installed() then
      AddProduct('windowsdesktop-runtime-5.0.0-win' + GetArchitectureString(true) + '.exe',
        '/install /quiet /norestart',
        GetString(CustomMessage('dotnet_500_desktop_title'), CustomMessage('dotnet_500_desktop_title_x64'), true),
        GetString(CustomMessage('dotnet_500_desktop_size'), CustomMessage('dotnet_500_desktop_size_x64'), true),
        GetString(CustomMessage('dotnet_500_desktop_url'), CustomMessage('dotnet_500_desktop_url_x64'), true),
        false, false, false);
  end;
end;

procedure dotnet_500_runtime;
begin
  if ExpandConstant(NoInstallNet) = 'false' then
  begin
    if not DotNet_500_Runtime_Installed() then
      AddProduct('dotnet-runtime-5.0.0-win' + GetArchitectureString(true) + '.exe',
        '/install /quiet /norestart',
        GetString(CustomMessage('dotnet_500_runtime_title'), CustomMessage('dotnet_500_runtime_title_x64'), true),
        GetString(CustomMessage('dotnet_500_runtime_size'), CustomMessage('dotnet_500_runtime_size_x64'), true),
        GetString(CustomMessage('dotnet_500_runtime_url'), CustomMessage('dotnet_500_runtime_url_x64'), true),
        false, false, false);
  end;
end;

{ 
any .NET 5

Checks for any version of .NET 5 and if none exists, installs latest
}

function DotNet_5_Desktop_Installed: Boolean;
var
  ResultCode: Integer;
begin
  Result := false;
  Exec('cmd.exe', '/c dotnet --list-runtimes | find /n "Microsoft.WindowsDesktop.App 5"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  // Only check for the 5 version number
  if ResultCode = 0 then 
  begin 
    Result := true;
  end;
end;

function DotNet_5_Runtime_Installed: Boolean;
var
  ResultCode: Integer;
begin
  Result := false;
  Exec('cmd.exe', '/c dotnet --list-runtimes | find /n "Microsoft.NETCore.App 5"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  // Only check for the 5 version number
  if ResultCode = 0 then 
  begin 
    Result := true;
  end;
end;

procedure dotnet_5_desktop;
begin
  if not DotNet_5_Desktop_Installed() then
  begin
    dotnet_501_desktop();
    { if no .NET 5 version installed then install the one above }
  end;
end;

procedure dotnet_5_runtime;
begin
  if not DotNet_5_Runtime_Installed() then
  begin
    dotnet_501_runtime();
    { if no .NET 5 version installed then install the one above }
  end;
end;