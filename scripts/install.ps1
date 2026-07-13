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

Write-Host ""
Write-Host "Installed to $Dir"
Write-Host "  - CLI:  run 'blindspot' from any terminal"
Write-Host "  - Tray: launch 'Blindspot' from the Start Menu"
