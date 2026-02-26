"""
Auto-Update for ELM327 Gateway.

Checks GitHub Releases for a newer version, downloads the new EXE
with a versioned filename, and launches it — no file replacement needed.

The shop laptop runs ONLY the compiled ELM327_Gateway.exe binary.
This module lets it self-update without manual file replacement.

Strategy (avoids ALL Windows file-locking issues):
    1. GET GitHub API /releases/latest → compare tag with __version__
    2. If newer, download to e.g. ELM327_Gateway_v1.2.38.exe (final name)
    3. Write a small updater script that:
       a. Waits for the current process to exit
       b. Updates the desktop shortcut to point to the new EXE
       c. Launches the new EXE
       (Old version is left on disk as a fallback — no rename/delete needed)
    4. Launch the updater script and exit
"""

import asyncio
import logging
import os
import platform
import subprocess
import sys
from pathlib import Path
from typing import Optional, Tuple

logger = logging.getLogger("gateway_app.updater")

# GitHub repo for release checks
GITHUB_REPO = "DRawson5570/autotech_ai_scantool"
GITHUB_API_URL = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"
ASSET_NAME = "ELM327_Gateway.exe"

# How often to check for updates (seconds)
UPDATE_CHECK_INTERVAL = 6 * 60 * 60  # 6 hours


def _strip_motw(file_path: Path) -> None:
    """Remove the Mark of the Web (MOTW) from a downloaded file.

    Windows stores MOTW as an NTFS Alternate Data Stream (ADS)
    named 'Zone.Identifier'.  If present, SmartScreen will show
    'Windows protected your PC' when the EXE is launched.
    """
    try:
        ads_path = str(file_path) + ":Zone.Identifier"
        try:
            os.remove(ads_path)
            logger.debug(f"Stripped MOTW via os.remove: {file_path.name}")
            return
        except (OSError, PermissionError):
            pass

        try:
            import ctypes
            if ctypes.windll.kernel32.DeleteFileW(ads_path):
                logger.debug(f"Stripped MOTW via DeleteFileW: {file_path.name}")
                return
        except Exception:
            pass

        try:
            subprocess.run(
                ["powershell", "-Command", f'Unblock-File -Path "{file_path}"'],
                capture_output=True, timeout=10,
            )
            logger.debug(f"Stripped MOTW via Unblock-File: {file_path.name}")
        except Exception:
            pass

    except Exception as e:
        logger.debug(f"MOTW strip failed (non-fatal): {e}")


def get_current_version() -> str:
    """Get the current gateway version."""
    try:
        from elm327_gateway import __version__
        return __version__
    except ImportError:
        return "0.0.0"


def _parse_version(tag: str) -> Tuple[int, ...]:
    """Parse a version tag like 'v1.2.31' into a comparable tuple (1, 2, 31)."""
    clean = tag.lstrip("vV").strip()
    parts = []
    for p in clean.split("."):
        try:
            parts.append(int(p))
        except ValueError:
            parts.append(0)
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts)


def is_newer(remote_tag: str, local_version: str) -> bool:
    """Check if remote_tag is newer than local_version."""
    return _parse_version(remote_tag) > _parse_version(local_version)


def get_exe_path() -> Optional[Path]:
    """Get the path to the currently running executable.

    Returns None if running from Python source (not frozen).
    """
    if getattr(sys, 'frozen', False):
        return Path(sys.executable)
    return None


async def check_for_update() -> Optional[dict]:
    """Check GitHub Releases for a newer version.

    Returns:
        Dict with 'tag', 'download_url', 'size' if update available,
        None if current version is up to date or check fails.
    """
    import aiohttp

    current = get_current_version()
    logger.info(f"Checking for updates (current: v{current})...")

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                GITHUB_API_URL,
                headers={"Accept": "application/vnd.github+json"},
                timeout=aiohttp.ClientTimeout(total=15),
            ) as resp:
                if resp.status != 200:
                    logger.warning(f"Update check failed: HTTP {resp.status}")
                    return None

                data = await resp.json()

        tag = data.get("tag_name", "")
        if not tag:
            logger.warning("No tag_name in release response")
            return None

        if not is_newer(tag, current):
            logger.info(f"Up to date (latest: {tag}, current: v{current})")
            return None

        # Find the EXE asset
        assets = data.get("assets", [])
        download_url = None
        size = 0
        for asset in assets:
            if asset.get("name", "").lower() == ASSET_NAME.lower():
                download_url = asset.get("browser_download_url")
                size = asset.get("size", 0)
                break

        if not download_url:
            logger.warning(f"Release {tag} found but no {ASSET_NAME} asset")
            return None

        logger.info(
            f"Update available: {tag} (current: v{current}, "
            f"size: {size / 1024 / 1024:.1f} MB)"
        )
        return {
            "tag": tag,
            "download_url": download_url,
            "size": size,
            "release_name": data.get("name", tag),
        }

    except Exception as e:
        logger.warning(f"Update check failed: {e}")
        return None


async def download_update(download_url: str, dest_path: Path) -> bool:
    """Download the new EXE to dest_path.

    Shows progress in the log.
    Returns True if download succeeded.
    """
    import aiohttp

    logger.info(f"Downloading update to {dest_path.name}...")

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                download_url,
                timeout=aiohttp.ClientTimeout(total=300),
            ) as resp:
                if resp.status != 200:
                    logger.error(f"Download failed: HTTP {resp.status}")
                    return False

                total = int(resp.headers.get("Content-Length", 0))
                downloaded = 0

                with open(dest_path, "wb") as f:
                    async for chunk in resp.content.iter_chunked(64 * 1024):
                        f.write(chunk)
                        downloaded += len(chunk)
                        if total > 0:
                            pct = downloaded * 100 // total
                            if pct % 25 == 0:
                                logger.info(
                                    f"  Download progress: {pct}% "
                                    f"({downloaded // 1024 // 1024}/"
                                    f"{total // 1024 // 1024} MB)"
                                )

        actual_size = dest_path.stat().st_size
        if actual_size < 1_000_000:
            logger.error(f"Downloaded file too small ({actual_size} bytes), aborting")
            dest_path.unlink(missing_ok=True)
            return False

        if platform.system() == "Windows":
            _strip_motw(dest_path)

        logger.info(f"Download complete: {actual_size / 1024 / 1024:.1f} MB")
        return True

    except Exception as e:
        logger.error(f"Download failed: {e}")
        dest_path.unlink(missing_ok=True)
        return False


def _find_desktop_shortcuts(exe_name: str) -> list:
    """Find all .lnk shortcuts on the Desktop that point to an EXE name pattern.

    Searches for shortcuts whose target contains 'ELM327_Gateway' in the name.
    Returns list of shortcut file paths.
    """
    shortcuts = []
    try:
        desktop = Path.home() / "Desktop"
        if not desktop.exists():
            # Try OneDrive Desktop
            onedrive = Path.home() / "OneDrive" / "Desktop"
            if onedrive.exists():
                desktop = onedrive
            else:
                return []

        for lnk in desktop.glob("*.lnk"):
            # Read the shortcut target via PowerShell
            try:
                result = subprocess.run(
                    [
                        "powershell", "-Command",
                        f'(New-Object -ComObject WScript.Shell)'
                        f'.CreateShortcut("{lnk}").TargetPath'
                    ],
                    capture_output=True, text=True, timeout=5,
                )
                target = result.stdout.strip()
                if "ELM327_Gateway" in target or "elm327_gateway" in target.lower():
                    shortcuts.append(str(lnk))
            except Exception:
                continue
    except Exception as e:
        logger.debug(f"Shortcut search failed: {e}")

    return shortcuts


def apply_update_windows(new_exe_path: Path, current_exe_path: Path) -> bool:
    """Apply update on Windows using a batch script.

    New approach — no file replacement needed:
    1. New EXE is already saved with versioned name (e.g. ELM327_Gateway_v1.2.38.exe)
    2. Batch script waits for old process to exit
    3. Updates any desktop shortcuts to point to new EXE
    4. Launches new EXE
    5. Old version stays on disk as fallback

    Returns True if the updater script was launched successfully.
    """
    pid = os.getpid()
    bat_path = current_exe_path.parent / "_gateway_updater.bat"

    # Find desktop shortcuts to update
    shortcuts = _find_desktop_shortcuts("ELM327_Gateway")
    shortcut_cmds = ""
    for lnk in shortcuts:
        # PowerShell to update shortcut target
        shortcut_cmds += f'''
echo Updating shortcut: {Path(lnk).name}
powershell -Command "$s = (New-Object -ComObject WScript.Shell).CreateShortcut('{lnk}'); $s.TargetPath = '{new_exe_path}'; $s.WorkingDirectory = '{new_exe_path.parent}'; $s.Save()"
'''

    bat_content = f'''@echo off
setlocal
echo ============================================
echo   ELM327 Gateway Auto-Update
echo ============================================
echo.
echo Waiting for gateway to exit (PID {pid})...
:wait_loop
tasklist /FI "PID eq {pid}" 2>NUL | find /I "{pid}" >NUL
if %ERRORLEVEL%==0 (
    timeout /t 1 /nobreak >NUL
    goto wait_loop
)
echo Gateway process exited.
echo.
echo New version: {new_exe_path.name}
{shortcut_cmds}
echo.
echo Launching new version...
start "" "{new_exe_path}"
echo.
echo Update complete!
echo Old version kept at: {current_exe_path.name}
timeout /t 3 /nobreak >NUL
(goto) 2>nul & del "%~f0"
'''

    try:
        bat_path.write_text(bat_content, encoding="utf-8")
        subprocess.Popen(
            ["cmd.exe", "/c", str(bat_path)],
            creationflags=subprocess.CREATE_NEW_CONSOLE,
            close_fds=True,
        )
        logger.info(f"Updater script launched: {bat_path}")
        return True
    except Exception as e:
        logger.error(f"Failed to launch updater: {e}")
        return False


def apply_update_unix(new_exe_path: Path, current_exe_path: Path) -> bool:
    """Apply update on Linux/Mac — same approach, no replacement.

    Returns True if the updater script was launched successfully.
    """
    pid = os.getpid()
    sh_path = current_exe_path.parent / "_gateway_updater.sh"

    sh_content = f'''#!/bin/bash
echo "ELM327 Gateway Auto-Update"
echo "Waiting for gateway to exit (PID {pid})..."
while kill -0 {pid} 2>/dev/null; do
    sleep 1
done
echo "Gateway process exited."
echo "Launching new version: {new_exe_path.name}..."
chmod +x "{new_exe_path}"
nohup "{new_exe_path}" &
echo "Old version kept at: {current_exe_path.name}"
rm -f "$0"
'''

    try:
        sh_path.write_text(sh_content, encoding="utf-8")
        sh_path.chmod(0o755)
        subprocess.Popen(
            ["bash", str(sh_path)],
            close_fds=True,
            start_new_session=True,
        )
        logger.info(f"Updater script launched: {sh_path}")
        return True
    except Exception as e:
        logger.error(f"Failed to launch updater: {e}")
        return False


async def check_and_apply_update(on_status=None) -> bool:
    """Full auto-update flow: check → download → launch new version.

    Args:
        on_status: Optional callback(message: str) for status updates.

    Returns:
        True if an update was applied (caller should exit),
        False if no update or update failed.
    """
    def status(msg):
        logger.info(msg)
        if on_status:
            try:
                on_status(msg)
            except Exception:
                pass

    # Only auto-update frozen executables
    exe_path = get_exe_path()
    if exe_path is None:
        logger.debug("Not a frozen executable, skipping auto-update")
        return False

    # Check for update
    update_info = await check_for_update()
    if not update_info:
        return False

    tag = update_info["tag"]
    status(f"[UPDATE] Downloading {tag}...")

    # Download as versioned filename (final name, not temp)
    # e.g. C:\ELM Gateway\ELM327_Gateway_v1.2.38.exe
    new_exe = exe_path.parent / f"ELM327_Gateway_{tag}.exe"

    # Skip download if already exists (e.g. previous failed launch)
    if new_exe.exists() and new_exe.stat().st_size > 1_000_000:
        logger.info(f"New version already downloaded: {new_exe.name}")
    else:
        if not await download_update(update_info["download_url"], new_exe):
            status("[UPDATE] Download failed, continuing with current version")
            return False

    status(f"[UPDATE] Launching {tag}...")

    # Apply update (launch new, update shortcuts)
    if platform.system() == "Windows":
        success = apply_update_windows(new_exe, exe_path)
    else:
        success = apply_update_unix(new_exe, exe_path)

    if success:
        status(f"[UPDATE] {tag} ready — restarting...")
        return True
    else:
        status("[UPDATE] Launch failed, continuing with current version")
        return False


async def periodic_update_check(on_status=None, on_exit=None):
    """Background task that checks for updates periodically.

    If an update is found, downloads the new version and exits
    so the updater script can launch it.

    Args:
        on_status: Optional callback(message: str) for status updates.
        on_exit: Optional callback to cleanly shut down (stop tray, etc.)
                 before exiting. Falls back to os._exit(0) if not provided.
    """
    # Wait a bit after startup before first check
    await asyncio.sleep(60)

    while True:
        try:
            should_exit = await check_and_apply_update(on_status=on_status)
            if should_exit:
                logger.info("Update applied, exiting for restart...")
                await asyncio.sleep(2)
                if on_exit:
                    on_exit()
                else:
                    os._exit(0)
        except Exception as e:
            logger.error(f"Periodic update check failed: {e}", exc_info=True)

        await asyncio.sleep(UPDATE_CHECK_INTERVAL)
