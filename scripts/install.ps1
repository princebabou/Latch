[CmdletBinding()]
param(
    [string]$Version = $(if ($env:LATCH_VERSION) { $env:LATCH_VERSION } else { "latest" }),
    [string]$InstallDir = $(if ($env:LATCH_INSTALL_DIR) { $env:LATCH_INSTALL_DIR } else { Join-Path $HOME ".local\bin" }),
    [string]$Repository = $(if ($env:LATCH_REPOSITORY) { $env:LATCH_REPOSITORY } else { "princebabou/Latch" })
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$architecture = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
switch ($architecture) {
    "X64" { $releaseArchitecture = "amd64" }
    "Arm64" { $releaseArchitecture = "arm64" }
    default { throw "latch installer: unsupported architecture: $architecture" }
}

if ($Version -eq "latest") {
    $releaseApi = "https://api.github.com/repos/$Repository/releases/latest"
} else {
    $releaseTag = if ($Version.StartsWith("v")) { $Version } else { "v$Version" }
    $releaseApi = "https://api.github.com/repos/$Repository/releases/tags/$releaseTag"
}

$headers = @{
    Accept = "application/vnd.github+json"
    "X-GitHub-Api-Version" = "2022-11-28"
}
$release = Invoke-RestMethod -Uri $releaseApi -Headers $headers
$archive = $release.assets |
    Where-Object { $_.name -match "_Windows_${releaseArchitecture}\.zip$" } |
    Select-Object -First 1
$checksums = $release.assets |
    Where-Object { $_.name -eq "checksums.txt" } |
    Select-Object -First 1

if (-not $archive -or -not $checksums) {
    throw "latch installer: release has no verified archive for Windows/$releaseArchitecture"
}

$temporaryDirectory = Join-Path ([System.IO.Path]::GetTempPath()) ("latch-install-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $temporaryDirectory | Out-Null

try {
    $archivePath = Join-Path $temporaryDirectory $archive.name
    $checksumsPath = Join-Path $temporaryDirectory "checksums.txt"
    Invoke-WebRequest -Uri $archive.browser_download_url -OutFile $archivePath
    Invoke-WebRequest -Uri $checksums.browser_download_url -OutFile $checksumsPath

    $archivePattern = [regex]::Escape($archive.name)
    $checksumLine = Get-Content -LiteralPath $checksumsPath |
        Where-Object { $_ -match "^[A-Fa-f0-9]{64}\s+\*?$archivePattern$" } |
        Select-Object -First 1
    if (-not $checksumLine) {
        throw "latch installer: archive is missing from checksums.txt"
    }

    $expected = ($checksumLine -split "\s+")[0].ToLowerInvariant()
    $actual = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $expected) {
        throw "latch installer: checksum verification failed"
    }

    $unpacked = Join-Path $temporaryDirectory "unpacked"
    Expand-Archive -LiteralPath $archivePath -DestinationPath $unpacked
    $binary = Get-ChildItem -LiteralPath $unpacked -Recurse -File -Filter "latch.exe" |
        Select-Object -First 1
    if (-not $binary) {
        throw "latch installer: archive did not contain latch.exe"
    }

    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    $destination = Join-Path $InstallDir "latch.exe"
    Copy-Item -LiteralPath $binary.FullName -Destination $destination -Force

    Write-Host "Installed latch to $destination"
    $pathEntries = $env:PATH -split [System.IO.Path]::PathSeparator
    if ($pathEntries -notcontains $InstallDir) {
        Write-Host "Add $InstallDir to PATH to run latch from any directory."
    }
}
finally {
    if (Test-Path -LiteralPath $temporaryDirectory) {
        Remove-Item -LiteralPath $temporaryDirectory -Recurse -Force
    }
}
