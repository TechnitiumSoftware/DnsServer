$buildfolder = "build/"
$installerfilename = "dnsserverinstall"
Write-Host "Chocolatey Package Builder"
Write-Host "--------------------------"
Write-Host "Building Inno Setup..."
iscc "/O." "/F$installerfilename" ..\Windows\DnsServiceSetup.iss

$installerfilename = "${installerfilename}.exe"
$version = [System.Diagnostics.FileVersionInfo]::GetVersionInfo("./${installerfilename}").ProductVersion
Write-Host "Version: $version"
Write-Host "Copying files..."
New-Item -ItemType Directory -Path "${buildfolder}" -ErrorAction Ignore | Out-Null
New-Item -ItemType Directory -Path "${buildfolder}/tools" -ErrorAction Ignore | Out-Null

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

Write-Host "Create Package"
cpack ${buildfolder}/${nuspecfilename} --out ../Release