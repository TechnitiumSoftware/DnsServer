$buildfolder = "build/"
$installerfilename = "dnsserverinstall"
Write-Host "DNS Server Chocolatey Package Builder"
Write-Host "-------------------------------------"
Write-Host "Create build folders..."
New-Item -ItemType Directory -Path "${buildfolder}" -ErrorAction Ignore | Out-Null
New-Item -ItemType Directory -Path "${buildfolder}/tools" -ErrorAction Ignore | Out-Null

Write-Host "Building Setup..."
iscc "/O./${buildfolder}/tools" "/F$installerfilename" ..\Windows\DnsServiceSetup.iss | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Host "Error: Inno Setup Compile Failed!"
    return
} else {
    Write-Host "Build Success!"
}

$installerfilename = "${installerfilename}.exe"
$version = [System.Diagnostics.FileVersionInfo]::GetVersionInfo("./${buildfolder}/tools/${installerfilename}").ProductVersion
Write-Host "Version: $version"
if (!$version) {
    Write-Host "Error: Could not get Product Version from Installer File"
    return
}
Write-Host "Copying files..."

$nuspecfilename = ""

$files = Get-ChildItem -Path .
foreach ($file in $files) {
    if ($file.Name.StartsWith("build")) {
        #Skip any build files starting with the word build (ie: build.ps1)
        continue
    }

    if ($file.Name.EndsWith(".template")) {
        Write-Host "Build $($file.Name)"
        $outfilename = ($file.Name -replace ".{9}$")
        $templater = Get-Content "$($file.Name)" -Raw

        $templater = $templater -replace "%fileversion%", "$version"
        $templater = $templater -replace "%installfile%", "$installerfilename"

        $outpath = "${buildfolder}/"
        if (!$outfilename.EndsWith(".nuspec")) {
            $outpath = "${outpath}/tools/"
        } else {
            $nuspecfilename = $outfilename
        }

        $templater | Out-File "${outpath}/${outfilename}"
    } else {
        Write-Host "Copy $($file.Name)"

        $outpath = "${buildfolder}/"
        if (!$file.Name.EndsWith(".nuspec")) {
            $outpath = "${outpath}/tools/"
        } else {
            $nuspecfilename = $file.Name
        }

        Copy-Item "$($file.Name)" "${outpath}/$($file.Name)"
    }
}

Write-Host "Create Package..."
cpack ${buildfolder}/${nuspecfilename} --out ../Release
Write-Host "Remove Build Folder"
Remove-Item -Path "${buildfolder}" -Recurse
Write-Host "COMPLETE!"