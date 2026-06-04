$ErrorActionPreference = "Stop"

$Url  = "https://github.com/neozmmv/blindspot/releases/latest/download/blindspot.exe"
$Dest = "$env:LOCALAPPDATA\Microsoft\WindowsApps\blindspot.exe"

Write-Host "Downloading latest blindspot..."
Invoke-WebRequest -Uri $Url -OutFile $Dest

Write-Host "Installed to $Dest"
Write-Host "Run 'blindspot' from any terminal."
