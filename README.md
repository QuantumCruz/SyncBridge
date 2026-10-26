
# SyncBridge

SyncBridge is a Windows desktop application for securely synchronizing
selected folders between two paired computers.

The current application uses explicit pairing, mutual connection approval,
manual preview and synchronization, and guarded file transfers.

## Development setup

Use Python 3.12 or a compatible supported version.

Open PowerShell from the repository root:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev,build]"
```

Start the desktop application:

```powershell
python scripts/desktop_qt.py
```

The application saves its ordinary Windows configuration under:

`%LOCALAPPDATA%\SyncBridge`

## Tests

Run the complete suite:

```powershell
python -m pytest -q
```

Test the new desktop file refresh specifically:

```powershell
python -m pytest tests/integration/test_qt_local_refresh_mutual.py -q
```

## Build a Windows executable

Build on Windows. PyInstaller does not cross-compile Windows executables
from Linux or macOS.

For a diagnostic build with a visible console:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build_windows.ps1 -Console
```

For a normal desktop build:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build_windows.ps1
```

The executable will be created at:

`dist\SyncBridge\SyncBridge.exe`

The entire `dist\SyncBridge` directory must stay together.
Do not copy only the `.exe` file.

## Testing on two Windows computers

1. Copy the complete generated `SyncBridge` folder to each computer.
2. Start `SyncBridge.exe` separately on both computers.
3. Connect both computers to a mutually reachable LAN or virtual LAN.
4. Use **Find computer** to discover and pair the devices.
5. Approve pairing and choose a folder on each computer.
6. Establish a mutually approved connection.
7. Preview the differences before synchronizing.
8. Verify the files on both computers.

Windows Firewall may request permission for SyncBridge to communicate
on private networks. Only allow it on networks you trust.

Pairing is persistent, but live connection approval is required for
new sessions. Disconnecting does not delete synchronized files.

The application does not require paid cloud hosting or a subscription.

## Safety

Use separate test folders when evaluating a new build.

Preview file changes before synchronizing. Conflicts and deletions
require careful review.

Do not package development profiles, private identity keys, trust
files, or synchronized user folders with a release.

## Current development status

SyncBridge is undergoing Windows distribution and real-device testing.
A successful executable build does not by itself constitute a tested
production release.
