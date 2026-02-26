"""
ELM327 Gateway App - One-click Windows/Mac/Linux tray application.

Runs in the system tray. Auto-detects ELM327 adapters,
starts the gateway server, and tunnels to the Autotech AI server.

Install once, forget about it.

Usage:
    python -m elm327_gateway.app

Or as a frozen exe (PyInstaller):
    gateway_app.exe
"""

import asyncio
import json
import logging
import os
import platform
import signal
import sys
import threading
from pathlib import Path
from typing import Optional

from elm327_gateway import __version__
from elm327_gateway.auto_update import (
    check_and_apply_update,
    periodic_update_check,
)

# Configure logging before anything else
LOG_DIR = Path.home() / ".autotech_gateway"
LOG_DIR.mkdir(exist_ok=True)
LOG_FILE = LOG_DIR / "gateway.log"
CONFIG_FILE = LOG_DIR / "config.json"

# When running as a windowed app (console=False), sys.stdout/stderr are None.
# Redirect them to devnull so libraries (uvicorn, aiohttp, etc.) don't crash.
if sys.stdout is None:
    sys.stdout = open(os.devnull, "w")
if sys.stderr is None:
    sys.stderr = open(os.devnull, "w")

# Use UTF-8 for file, and errors='replace' on console to avoid
# UnicodeEncodeError on Windows cp1252 consoles with emoji/unicode.
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler(
            open(sys.stdout.fileno(), mode='w', encoding='utf-8', errors='replace', closefd=False)
        ),
    ]
)
logger = logging.getLogger("gateway_app")

# ============================================================================
# Configuration
# ============================================================================

DEFAULT_CONFIG = {
    "server_url": "https://automotive.aurora-sentient.net",
    "shop_id": "",
    "api_key": "",
    "adapter_port": "",  # Empty = auto-detect
    "adapter_type": "serial",
    "gateway_port": 8327,
    "auto_start": True,
}


def load_config() -> dict:
    """Load config from disk, or return defaults."""
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE) as f:
                saved = json.load(f)
            # Merge with defaults (in case new fields were added)
            config = {**DEFAULT_CONFIG, **saved}
            return config
        except Exception as e:
            logger.warning(f"Error loading config: {e}")
    return DEFAULT_CONFIG.copy()


def save_config(config: dict):
    """Save config to disk."""
    try:
        with open(CONFIG_FILE, "w") as f:
            json.dump(config, f, indent=2)
    except Exception as e:
        logger.error(f"Error saving config: {e}")


# ============================================================================
# Main Gateway App
# ============================================================================

class GatewayApp:
    """
    Main application that manages:
    1. Auto-detection of ELM327 adapter
    2. Local gateway HTTP server
    3. Reverse WebSocket tunnel to Autotech AI server
    """
    
    def __init__(self):
        self.config = load_config()
        self.status = "Starting..."
        self.adapter_name = None
        self.adapter_port = None
        self._server_process = None
        self._tunnel = None
        self._tray = None
        self._loop = None
    
    def _update_status(self, msg: str):
        """Update status and tray tooltip."""
        self.status = msg
        logger.info(f"Status: {msg}")
        if self._tray:
            try:
                self._tray.title = f"ELM327 Gateway - {msg}"
            except:
                pass
    
    async def _detect_adapter(self) -> Optional[str]:
        """Auto-detect the ELM327 adapter port."""
        self._update_status("Scanning for ELM327...")
        
        try:
            from elm327_gateway.autodetect import detect_and_pick
            adapter = await detect_and_pick()
            
            if adapter:
                self.adapter_name = adapter.name
                self.adapter_port = adapter.port
                self._update_status(f"Found {adapter.name} on {adapter.port}")
                return adapter.port
            else:
                self._update_status("[ERR] No ELM327 found")
                return None
        except Exception as e:
            logger.error(f"Auto-detect error: {e}")
            self._update_status(f"Detect error: {e}")
            return None
    
    async def _start_gateway_server(self):
        """Start the local gateway HTTP server."""
        import uvicorn
        from elm327_gateway.server import app
        
        port = self.config.get("gateway_port", 8327)
        
        config = uvicorn.Config(
            app,
            host="127.0.0.1",  # Only local access
            port=port,
            log_level="warning",
        )
        server = uvicorn.Server(config)
        
        self._update_status(f"Gateway server on port {port}")
        try:
            await server.serve()
        except Exception as e:
            logger.error(f"Gateway server crashed: {e}", exc_info=True)
            self._update_status(f"[ERR] Server crashed: {e}")
    
    async def _start_tunnel(self):
        """Start the reverse WebSocket tunnel."""
        from elm327_gateway.reverse_tunnel import GatewayTunnel
        
        server_url = self.config.get("server_url", DEFAULT_CONFIG["server_url"])
        shop_id = self.config.get("shop_id")
        api_key = self.config.get("api_key", "")
        
        if not shop_id:
            self._update_status("[WARN] No shop ID configured")
            return
        
        self._tunnel = GatewayTunnel(
            server_url=server_url,
            shop_id=shop_id,
            api_key=api_key,
            local_gateway_port=self.config.get("gateway_port", 8327),
            on_status_change=self._update_status,
        )
        
        await self._tunnel.run()
    
    async def _auto_connect(self):
        """Auto-detect adapter and connect."""
        port = self.config.get("adapter_port")
        
        if not port:
            # Auto-detect
            port = await self._detect_adapter()
            if not port:
                self._update_status("[WARN] No adapter - will retry in 30s")
                await asyncio.sleep(30)
                return
        
        # Connect the local gateway to the adapter
        try:
            import aiohttp
            
            gw_port = self.config.get("gateway_port", 8327)
            adapter_type = self.config.get("adapter_type", "serial")
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"http://localhost:{gw_port}/connect",
                    json={
                        "connection_type": adapter_type,
                        "address": port,
                    },
                    timeout=aiohttp.ClientTimeout(total=15),
                ) as resp:
                    if resp.status == 200:
                        result = await resp.json()
                        vin = result.get("vin", "N/A")
                        self._update_status(f"[OK] Connected - VIN: {vin}")
                    else:
                        error = await resp.text()
                        self._update_status(f"[ERR] Connect failed: {error[:50]}")
        except Exception as e:
            self._update_status(f"[ERR] Connect error: {e}")
    
    async def run_async(self):
        """Main async entry point."""
        self._loop = asyncio.get_event_loop()
        
        # --- Auto-update check on startup ---
        self._update_status(f"ELM327 Gateway v{__version__}")
        try:
            should_restart = await check_and_apply_update(
                on_status=self._update_status
            )
            if should_restart:
                self._update_status("[UPDATE] Restarting...")
                await asyncio.sleep(2)
                os._exit(0)
        except Exception as e:
            logger.warning(f"Startup update check failed: {e}")
        
        # Start gateway server in background
        server_task = asyncio.create_task(self._start_gateway_server())
        
        # Wait a moment for server to start
        await asyncio.sleep(2)
        
        # Auto-connect to adapter
        await self._auto_connect()
        
        # Start tunnel (runs forever with reconnection)
        tunnel_task = asyncio.create_task(self._start_tunnel())
        
        # Periodic update check in background (every 6 hours)
        update_task = asyncio.create_task(
            periodic_update_check(on_status=self._update_status)
        )
        
        # Wait for all (they run forever)
        await asyncio.gather(
            server_task, tunnel_task, update_task,
            return_exceptions=True
        )
    
    def run_with_tray(self):
        """Run with system tray icon."""
        try:
            import pystray
            from PIL import Image, ImageDraw
        except ImportError:
            logger.warning("pystray/pillow not installed, running without tray icon")
            logger.warning("Install with: pip install pystray pillow")
            asyncio.run(self.run_async())
            return
        
        # Create a simple tray icon (green car emoji equivalent)
        def create_icon():
            img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
            draw = ImageDraw.Draw(img)
            # Green circle background
            draw.ellipse([4, 4, 60, 60], fill=(6, 214, 160, 255))
            # Simple car shape
            draw.rectangle([16, 28, 48, 42], fill=(26, 26, 46, 255))
            draw.rectangle([12, 36, 52, 48], fill=(26, 26, 46, 255))
            # Wheels
            draw.ellipse([14, 44, 24, 54], fill=(100, 100, 100, 255))
            draw.ellipse([40, 44, 50, 54], fill=(100, 100, 100, 255))
            return img
        
        def on_configure(icon, item):
            """Open configuration."""
            self._show_config_dialog()
        
        def on_status(icon, item):
            """Show status."""
            logger.info(f"Current status: {self.status}")
        
        def on_quit(icon, item):
            """Quit the application."""
            icon.stop()
            if self._tunnel:
                asyncio.run_coroutine_threadsafe(self._tunnel.stop(), self._loop)
            os._exit(0)
        
        def on_check_update(icon, item):
            """Trigger an update check from tray menu."""
            def _check():
                loop = asyncio.new_event_loop()
                try:
                    result = loop.run_until_complete(
                        check_and_apply_update(on_status=self._update_status)
                    )
                    if result:
                        self._update_status("[UPDATE] Restarting...")
                        import time; time.sleep(2)
                        os._exit(0)
                    else:
                        self._update_status(f"Up to date (v{__version__})")
                except Exception as e:
                    self._update_status(f"Update check failed: {e}")
                finally:
                    loop.close()
            threading.Thread(target=_check, daemon=True).start()
        
        menu = pystray.Menu(
            pystray.MenuItem(lambda text: f"Status: {self.status}", on_status, enabled=False),
            pystray.MenuItem(lambda text: f"Version: {__version__}", on_status, enabled=False),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Check for Updates...", on_check_update),
            pystray.MenuItem("Configure...", on_configure),
            pystray.MenuItem("View Logs", lambda: os.startfile(str(LOG_FILE)) if platform.system() == "Windows" else None),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Quit", on_quit),
        )
        
        self._tray = pystray.Icon(
            "elm327_gateway",
            create_icon(),
            f"ELM327 Gateway - {self.status}",
            menu,
        )
        
        # Run asyncio in a separate thread
        def run_async_thread():
            asyncio.run(self.run_async())
        
        threading.Thread(target=run_async_thread, daemon=True).start()
        
        # Run tray icon on main thread (required on macOS/Windows)
        self._tray.run()
    
    def _show_config_dialog(self):
        """Show a simple configuration dialog."""
        try:
            if platform.system() == "Windows":
                import ctypes
                # Simple Windows message box with current config
                msg = (
                    f"Shop ID: {self.config.get('shop_id', '(not set)')}\n"
                    f"Server: {self.config.get('server_url')}\n"
                    f"Adapter: {self.adapter_port or 'auto-detect'}\n"
                    f"Status: {self.status}\n\n"
                    f"Config file: {CONFIG_FILE}\n"
                    f"Log file: {LOG_FILE}"
                )
                ctypes.windll.user32.MessageBoxW(0, msg, "ELM327 Gateway Config", 0x40)
            else:
                logger.info(f"Config: {json.dumps(self.config, indent=2)}")
        except Exception as e:
            logger.error(f"Config dialog error: {e}")


# ============================================================================
# First-Run Setup
# ============================================================================

def first_run_setup() -> dict:
    """Interactive first-run setup (console)."""
    print()
    print("=" * 60)
    print("  Autotech AI - ELM327 Gateway Setup")
    print("=" * 60)
    print()
    print("This gateway connects your ELM327 OBD-II adapter to")
    print("Autotech AI's diagnostic server.")
    print()
    
    config = DEFAULT_CONFIG.copy()
    
    # Shop ID
    shop_id = input("Enter your Shop ID (provided by Autotech AI): ").strip()
    if not shop_id:
        print("[ERR] Shop ID is required")
        sys.exit(1)
    config["shop_id"] = shop_id
    
    # API Key
    api_key = input("Enter your API Key (provided by Autotech AI): ").strip()
    config["api_key"] = api_key
    
    # Adapter port
    print()
    print("Adapter port (leave blank for auto-detect):")
    print("  Windows: COM3, COM4, COM5, etc.")
    print("  Linux:   /dev/rfcomm0")
    adapter = input("Adapter port [auto-detect]: ").strip()
    if adapter:
        config["adapter_port"] = adapter
    
    # Save
    save_config(config)
    print()
    print(f"[OK] Configuration saved to {CONFIG_FILE}")
    print()
    
    return config


# ============================================================================
# Entry Point
# ============================================================================

def main():
    """Main entry point."""
    # Check for first run
    config = load_config()
    
    if not config.get("shop_id"):
        # First run - interactive setup
        config = first_run_setup()
    
    # Parse command-line args
    headless = "--headless" in sys.argv or "--no-tray" in sys.argv
    
    app = GatewayApp()
    app.config = config
    
    if headless:
        logger.info("Running in headless mode (no tray icon)")
        asyncio.run(app.run_async())
    else:
        app.run_with_tray()


if __name__ == "__main__":
    main()
