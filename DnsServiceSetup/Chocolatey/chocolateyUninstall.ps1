$ErrorActionPreference = 'Stop';

$packageName = 'technitiumdnsserver'
$softwareName = 'Technitium DNS Server*'
$installerType = 'EXE'

$silentArgs = "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP- /LOG=`"$($env:TEMP)\$($env:chocolateyPackageName).$($env:chocolateyPackageVersion).Uninstall.log`""
$validExitCodes = @(0)

$uninstalled = $false
[array]$key = Get-UninstallRegistryKey -SoftwareName $softwareName

if ($key.Count -eq 1) {
	$key | ForEach-Object {
		$file = "$($_.UninstallString.Trim('"'))"

	Uninstall-ChocolateyPackage `
		-PackageName $packageName `
		-FileType $installerType `
		-SilentArgs "$silentArgs" `
		-ValidExitCodes $validExitCodes `
		-File "$file"
	}
} elseif ($key.Count -eq 0) {
	Write-Warning "$packageName has already been uninstalled by other means."
} elseif ($key.Count -gt 1) {
	Write-Warning "$key.Count matches found!"
	Write-Warning "To prevent accidental data loss, no programs will be uninstalled."
	Write-Warning "Please alert package maintainer the following keys were matched:"
	$key | ForEach-Object {Write-Warning "- $_.DisplayName"}
}