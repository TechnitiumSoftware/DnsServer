const
  NoInstallNet = '{param:skipnet|false}'; //if this parameter is supplied on the command line then skip installing .NET dependencies

{ .NET Framework 4.8 }

function DotNet_Framework_48_Installed: Boolean;
var
  KeyResult: String;
  VersionParts: TArrayOfString;
  RegVersion, MinVer: Int64;
  VerDiff: Integer;
begin
  Result := false;
  
  RegQueryStringValue(HKLM, 'Software\Microsoft\NET Framework Setup\NDP\v4\Full', 'Version', KeyResult);
  VersionParts := StrSplit(KeyResult, '.');
  RegVersion := PackVersionComponents(StrToInt(VersionParts[0]), StrToInt(VersionParts[1]), StrToInt(VersionParts[2]), 0);
  MinVer := PackVersionComponents(4, 8, 0, 0);

  VerDiff := ComparePackedVersion(RegVersion, MinVer);

  if VerDiff > -1 then
  begin
    Result := true;
  end;
end;

procedure dotnet_framework_48();
begin
  if ExpandConstant(NoInstallNet) = 'false' then
  begin
    if not DotNet_Framework_48_Installed() then
      AddProduct('ndp48-x86-x64-allos-enu.exe',
        '/install /quiet /norestart',
        CustomMessage('dotnet_fw48_title'),
        CustomMessage('dotnet_fw48_size'),
        CustomMessage('dotnet_fw48_url'),
        false, false, false);
  end;
end;