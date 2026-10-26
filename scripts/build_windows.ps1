
param(
    [switch]$Console
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ($env:OS -ne "Windows_NT") {
    throw "SyncBridge Windows executables must be built on Windows."
}

$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$python = Join-Path $root ".venv\Scripts\python.exe"

if (-not (Test-Path $python)) {
    throw "Python virtual environment not found. Create .venv first."
}

& $python -c "import cryptography, PyInstaller, PySide6, syncbridge"
if ($LASTEXITCODE -ne 0) {
    throw 'Dependencies missing. Run: python -m pip install -e ".[dev,build]"'
}

$build = Join-Path $root "build"
$dist = Join-Path $root "dist"
$entry = Join-Path $root "scripts\desktop_qt.py"
New-Item -ItemType Directory -Path $build -Force | Out-Null

$mode = if ($Console) { "--console" } else { "--windowed" }

& $python -m PyInstaller `
    --noconfirm `
    --clean `
    --onedir `
    $mode `
    --name SyncBridge `
    --paths (Join-Path $root "src") `
    --distpath $dist `
    --workpath (Join-Path $build "pyinstaller") `
    --specpath $build `
    $entry

if ($LASTEXITCODE -ne 0) {
    throw "The SyncBridge executable build failed."
}

$executable = Join-Path $dist "SyncBridge\SyncBridge.exe"
if (-not (Test-Path $executable)) {
    throw "Build completed without the expected SyncBridge.exe."
}

Write-Host "Build complete: $executable"
Write-Host "Copy the entire dist\SyncBridge folder to the second Windows laptop."
