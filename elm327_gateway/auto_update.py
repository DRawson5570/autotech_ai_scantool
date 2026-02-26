"""
Auto-Update for ELM327 Gateway.

Checks GitHub Releases for a newer version, downloads the new EXE,
and replaces itself via a temporary batch script (Windows) or shell
script (Linux/Mac).

The shop laptop runs ONLY the compiled ELM327_Gateway.exe binary.
This module lets it self-update without manual file replacement.

Flow:
    1. GET GitHub API /releases/latest → compare tag with __version__
    2. If newer, download the EXE asset to a temp file
    3. Write a small updater script that:
       a. Waits for the current process to exit
       b. Replaces the EXE
       c. Relaunches the new EXE
    4. Launch the updater script and exit
"""

import asyncio
import logging
import os
import platform
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Optional, Tuple

logger = logging.getLogger("gateway_app.updater")

# GitHub repo for release checks
GITHUB_REPO = "DRawson5570/autotech_ai_scantool"
GITHUB_API_URL = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"
ASSET_NAME = "ELM327_Gateway.exe"

# How often to check for updates (seconds)
UPDATE_CHECK_INTERVAL = 6 * 60 * 60  # 6 hours


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
    # Pad to at least 3 elements
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
        # PyInstaller frozen executable
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

    logger.info(f"Downloading update from {download_url}...")

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
                            if pct % 25 == 0:  # Log at 0%, 25%, 50%, 75%, 100%
                                logger.info(
                                    f"  Download progress: {pct}% "
                                    f"({downloaded // 1024 // 1024}/"
                                    f"{total // 1024 // 1024} MB)"
                                )

        # Verify the file is non-trivial
        actual_size = dest_path.stat().st_size
        if actual_size < 1_000_000:  # Less than 1MB is suspicious
            logger.error(f"Downloaded file too small ({actual_size} bytes), aborting")
            dest_path.unlink(missing_ok=True)
            return False

        logger.info(f"Download complete: {actual_size / 1024 / 1024:.1f} MB")
        return True

    except Exception as e:
        logger.error(f"Download failed: {e}")
        dest_path.unlink(missing_ok=True)
        return False


def apply_update_windows(new_exe_path: Path, current_exe_path: Path) -> bool:
    """Apply update on Windows using a batch script.

    The batch script:
    1. Waits for the current process to exit (taskkill + timeout)
    2. Replaces the old EXE with the new one
    3. Starts the new EXE
    4. Deletes itself

    Returns True if the updater script was launched successfully.
    """
    pid = os.getpid()
    bat_path = current_exe_path.parent / "_gateway_updater.bat"

    # Use short paths to avoid quoting issues
    bat_content = f'''@echo off
echo ELM327 Gateway Auto-Update
echo Waiting for gateway to exit (PID {pid})...
:wait_loop
tasklist /FI "PID eq {pid}" 2>NUL | find /I "{pid}" >NUL
if %ERRORLEVEL%==0 (
    timeout /t 1 /nobreak >NUL
    goto wait_loop
)
echo Gateway process exited.
echo Replacing executable...
copy /Y "{new_exe_path}" "{current_exe_path}"
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Failed to replace executable!
    echo The new version is saved at: {new_exe_path}
    pause
    exit /b 1
)
echo Update complete. Starting new version...
start "" "{current_exe_path}"
echo Cleaning up...
del "{new_exe_path}" 2>NUL
(goto) 2>nul & del "%~f0"
'''

    try:
        bat_path.write_text(bat_content, encoding="utf-8")
        # Launch the batch script in a new console window
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
    """Apply update on Linux/Mac using a shell script.

    Similar to Windows but uses bash and kill -0 for process check.

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
echo "Replacing executable..."
cp -f "{new_exe_path}" "{current_exe_path}"
chmod +x "{current_exe_path}"
echo "Update complete. Starting new version..."
nohup "{current_exe_path}" &
rm -f "{new_exe_path}"
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
    """Full auto-update flow: check → download → apply → exit.

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

    # Download to temp file next to current exe
    temp_dir = exe_path.parent
    new_exe = temp_dir / f"ELM327_Gateway_{tag}.exe.tmp"

    if not await download_update(update_info["download_url"], new_exe):
        status("[UPDATE] Download failed, continuing with current version")
        return False

    status(f"[UPDATE] Installing {tag}...")

    # Apply update
    if platform.system() == "Windows":
        success = apply_update_windows(new_exe, exe_path)
    else:
        success = apply_update_unix(new_exe, exe_path)

    if success:
        status(f"[UPDATE] {tag} installed — restarting...")
        return True
    else:
        status("[UPDATE] Install failed, continuing with current version")
        new_exe.unlink(missing_ok=True)
        return False


async def periodic_update_check(on_status=None):
    """Background task that checks for updates periodically.

    If an update is found, it's applied and the process exits
    (the updater script will restart it).
    """
    # Wait a bit after startup before first check
    await asyncio.sleep(60)

    while True:
        try:
            should_exit = await check_and_apply_update(on_status=on_status)
            if should_exit:
                logger.info("Update applied, exiting for restart...")
                # Give the updater script time to start monitoring our PID
                await asyncio.sleep(2)
                os._exit(0)
        except Exception as e:
            logger.error(f"Periodic update check failed: {e}", exc_info=True)

        await asyncio.sleep(UPDATE_CHECK_INTERVAL)
