#!/usr/bin/env pwsh

param(
  [Parameter(Mandatory = $true)]
  [string]
  $outputFolder
)

$here = Split-Path -Parent $PSCommandPath

if ($IsMacOS)
{
  $runtime = 'osx-x64'
}
elseif ($IsLinux)
{
  $runtime = 'linux-x64'
}
elseif ($IsWindows)
{
  $runtime = 'win-x64'
}
else
{
  throw 'Unable to figure out runtime to use'
}

if (!(Test-Path $here/../../TechnitiumLibrary -PathType Container))
{
  git clone https://github.com/TechnitiumSoftware/TechnitiumLibrary.git $here/../../TechnitiumLibrary
  Push-Location $here/../../TechnitiumLibrary
  dotnet publish -c Release
  Pop-Location
}

dotnet publish $here `
  --configuration Release `
  --runtime $runtime `
  --self-contained true `
  -p:PublishSingleFile=true `
  --output $outputFolder

Remove-Item $outputFolder/DnsServerApp.pdb
