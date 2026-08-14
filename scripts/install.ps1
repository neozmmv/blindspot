$ErrorActionPreference = "Stop"

$Base    = "https://github.com/neozmmv/blindspot/releases/latest/download"
$RawIcon = "https://raw.githubusercontent.com/neozmmv/blindspot/master/public/BLINDSPOT.ico"
# WindowsApps is already on PATH; both binaries live here, side by side, so the tray
# can find and shell out to the CLI.
$Dir     = "$env:LOCALAPPDATA\Microsoft\WindowsApps"

Write-Host "Downloading Blindspot (CLI + tray)..."
Invoke-WebRequest -Uri "$Base/blindspot.exe"      -OutFile "$Dir\blindspot.exe"
Invoke-WebRequest -Uri "$Base/blindspot-tray.exe" -OutFile "$Dir\blindspot-tray.exe"

# Icon for the Start Menu shortcut. The binaries carry no embedded icon by design,
# so fetch the .ico separately; the shortcut still works if this fails.
$IconPath = "$Dir\blindspot.ico"
try {
    Invoke-WebRequest -Uri $RawIcon -OutFile $IconPath -ErrorAction Stop
} catch {
    $IconPath = $null
}

# Start Menu shortcut that launches the tray.
$Shortcut = Join-Path ([Environment]::GetFolderPath("Programs")) "Blindspot.lnk"
$Shell = New-Object -ComObject WScript.Shell
$Link = $Shell.CreateShortcut($Shortcut)
$Link.TargetPath       = "$Dir\blindspot-tray.exe"
$Link.WorkingDirectory = $Dir
$Link.Description       = "Blindspot - P2P VPN tray"
if ($IconPath) { $Link.IconLocation = "$IconPath,0" }
$Link.Save()

# --- Tor ---------------------------------------------------------------------
#
# 'blindspot connect' and 'blindspot chat' run Tor as a subprocess to reach a
# room's onion service.
# Windows has no package manager that reliably carries Tor, so fetch the Tor
# Project's official Expert Bundle and drop tor.exe beside the CLI, at
# "$Dir\tor\tor.exe" — the location blindspot checks before falling back to PATH.
#
# The Windows tor.exe is statically linked, so it needs no DLLs alongside it.
#
# 'blindspot rendezvous' does not need Tor, so failures here are warnings.

function Get-LatestTorVersion {
    # The Expert Bundle has no "latest" alias, so read the version directories
    # out of the distribution index and take the highest. The pattern skips
    # alpha directories such as "16.0a9/".
    #
    # @() around the pipeline is load-bearing. The index lists only the current
    # stable and the current alpha, so exactly one directory matches. Without
    # @() a single match stays a bare string rather than an array, and indexing
    # a string yields its first character — "1" — which builds a download URL
    # that 404s.
    try {
        $index = Invoke-WebRequest -Uri "https://dist.torproject.org/torbrowser/" -UseBasicParsing -ErrorAction Stop
        $versions = @([regex]::Matches($index.Content, '>(\d+\.\d+(\.\d+)?)/<') |
            ForEach-Object { $_.Groups[1].Value } |
            Sort-Object { [version]$_ } -Descending)
        if ($versions.Count -gt 0) { return $versions[0] }
    } catch { }
    return $null
}

$TorExe = "$Dir\tor\tor.exe"
if (Test-Path $TorExe) {
    Write-Host "Tor already present at $TorExe"
} elseif (Get-Command tor -ErrorAction SilentlyContinue) {
    Write-Host "Tor already on PATH; leaving it alone."
} else {
    Write-Host ""
    Write-Host "'blindspot connect' needs Tor; downloading the Tor Expert Bundle..."
    try {
        $ver = Get-LatestTorVersion
        if (-not $ver) { throw "could not determine the latest Tor version" }
        # Guards against a parse that "succeeded" but produced nonsense, which is
        # otherwise only visible as a 404 several steps later.
        if ($ver -notmatch '^\d+\.\d+') { throw "unexpected Tor version '$ver' in the distribution index" }

        $arch = if ([Environment]::Is64BitOperatingSystem) { "x86_64" } else { "i686" }
        $url  = "https://dist.torproject.org/torbrowser/$ver/tor-expert-bundle-windows-$arch-$ver.tar.gz"

        $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("tor-" + [guid]::NewGuid())
        New-Item -ItemType Directory -Path $tmp -Force | Out-Null
        $tarball = Join-Path $tmp "teb.tar.gz"

        # The URL goes in the message: a download failure is almost always a
        # wrong URL, and without it the error says only "404".
        try {
            Invoke-WebRequest -Uri $url -OutFile $tarball -ErrorAction Stop
        } catch {
            throw "downloading $url failed: $($_.Exception.Message)"
        }
        # tar ships with Windows 10 1803 and later.
        tar -xzf $tarball -C $tmp
        if ($LASTEXITCODE -ne 0) { throw "extracting the bundle failed" }

        $src = Join-Path $tmp "tor\tor.exe"
        if (-not (Test-Path $src)) { throw "tor.exe not found in the bundle" }

        New-Item -ItemType Directory -Path "$Dir\tor" -Force | Out-Null
        Copy-Item $src $TorExe -Force
        # Ship the licence alongside it: Tor is 3-clause BSD, which requires the
        # notice to travel with any redistributed binary.
        $license = Join-Path $tmp "docs\tor.txt"
        if (Test-Path $license) { Copy-Item $license "$Dir\tor\LICENSE-tor.txt" -Force }

        Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "Tor $ver installed to $TorExe"
    } catch {
        Write-Host "warning: could not install Tor automatically ($($_.Exception.Message))."
        Write-Host "         'blindspot connect' and 'blindspot chat' will not work"
        Write-Host "         until Tor is available; 'blindspot rendezvous' works without it."
    }
}

Write-Host ""
Write-Host "Installed to $Dir"
Write-Host "  - CLI:  run 'blindspot' from any terminal"
Write-Host "  - Tray: launch 'Blindspot' from the Start Menu"
