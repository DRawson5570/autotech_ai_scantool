#!/usr/bin/env python3
"""
ELM327 Bluetooth Gateway Server

Runs on a Linux/Windows machine with Bluetooth, exposes REST API for remote clients.
Allows phones/tablets to use ELM327 without direct Bluetooth pairing.

Features:
- Auto-discovery via Bonjour/mDNS (iPhone finds it automatically)
- Device detection (shows appropriate UI for iPhone/Android/Desktop)
- QR code for easy phone connection
- REST API + WebSocket for real-time data

Usage:
    python -m addons.scan_tool.gateway.server --port 8327

iPhone connects to: http://<hostname>.local:8327/ui
"""

import asyncio
import logging
import os
import platform
import socket
import time
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

# Import our ELM327 service
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from .service import ELM327Service
from .session import get_session, reset_session, DiagnosticSession
from .can_sniffer import (
    parse_stma_line,
    extract_uds_exchanges,
    SnifferCapture,
    CANFrame,
    module_name_for_addr,
)
from .dbc_decoder import (
    LiveBroadcastDecoder, load_dbc_for_vin, load_dbc_for_oem,
    DBCDatabase, clear_dbc_cache,
)
from .auto_update import (
    check_for_update,
    check_and_apply_update,
    get_current_version,
    get_exe_path,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Global ELM327 service instance
_elm: Optional[ELM327Service] = None
_connected_at: Optional[datetime] = None
_keepalive_task: Optional[asyncio.Task] = None

# Sniffer state
_sniff_capture: Optional[SnifferCapture] = None
_sniff_task: Optional[asyncio.Task] = None
_sniff_running: bool = False

# DBC broadcast decoder (populated when sniff starts with VIN/make)
_broadcast_decoder: Optional[LiveBroadcastDecoder] = None
_adapter_caps = None  # Set by connect if adapter detection is available

# Keepalive settings
KEEPALIVE_INTERVAL = 25  # seconds between pings
KEEPALIVE_IDLE_THRESHOLD = 15  # only ping if idle for this many seconds

# mDNS/Bonjour service for auto-discovery
_mdns_service = None


async def _keepalive_loop():
    """
    Background task that pings the ELM327 adapter to prevent idle disconnects.
    
    Sends ATRV (read voltage) every KEEPALIVE_INTERVAL seconds, but only
    when the connection has been idle for KEEPALIVE_IDLE_THRESHOLD seconds.
    ATRV is lightweight and harmless — it just reads battery voltage.
    The connection lock prevents collisions with real commands.
    """
    logger.info(f"Keepalive started (interval={KEEPALIVE_INTERVAL}s, idle_threshold={KEEPALIVE_IDLE_THRESHOLD}s)")
    try:
        while True:
            await asyncio.sleep(KEEPALIVE_INTERVAL)
            
            if not _elm or not _elm.connected:
                logger.debug("Keepalive: not connected, stopping")
                break
            
            # Check if the connection has been idle long enough
            conn = _elm._connection
            if conn and conn._last_activity:
                idle_time = time.monotonic() - conn._last_activity
                if idle_time < KEEPALIVE_IDLE_THRESHOLD:
                    logger.debug(f"Keepalive: skip (idle {idle_time:.0f}s < {KEEPALIVE_IDLE_THRESHOLD}s)")
                    continue
            
            # Send keepalive command (ATRV = read voltage, fast and harmless)
            try:
                response = await conn.send_command("ATRV", timeout=3.0)
                logger.debug(f"Keepalive ping OK: {response.strip()}")
            except ConnectionError:
                logger.warning("Keepalive: connection lost")
                break
            except asyncio.TimeoutError:
                logger.warning("Keepalive: timeout (adapter may be unresponsive)")
            except Exception as e:
                logger.warning(f"Keepalive: error: {e}")
    except asyncio.CancelledError:
        logger.info("Keepalive task cancelled")
    except Exception as e:
        logger.error(f"Keepalive loop crashed: {e}", exc_info=True)
    logger.info("Keepalive stopped")


def _start_keepalive():
    """Start the keepalive background task."""
    global _keepalive_task
    _stop_keepalive()  # Cancel any existing task
    _keepalive_task = asyncio.create_task(_keepalive_loop())


def _stop_keepalive():
    """Stop the keepalive background task."""
    global _keepalive_task
    if _keepalive_task and not _keepalive_task.done():
        _keepalive_task.cancel()
    _keepalive_task = None


def get_local_ip():
    """Get the local IP address for display."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"


def start_mdns_service(port: int):
    """Start mDNS/Bonjour service for auto-discovery by iPhones."""
    global _mdns_service
    try:
        from zeroconf import ServiceInfo, Zeroconf
        
        local_ip = get_local_ip()
        hostname = socket.gethostname()
        
        # Register as HTTP service (Safari can find it)
        _mdns_service = {
            'zeroconf': Zeroconf(),
            'info': ServiceInfo(
                "_http._tcp.local.",
                f"ELM327 Gateway._http._tcp.local.",
                addresses=[socket.inet_aton(local_ip)],
                port=port,
                properties={
                    'path': '/ui',
                    'name': 'ELM327 OBD-II Gateway',
                    'hostname': hostname,
                },
                server=f"{hostname}.local.",
            )
        }
        _mdns_service['zeroconf'].register_service(_mdns_service['info'])
        logger.info(f"mDNS service registered: http://{hostname}.local:{port}/ui")
        return True
    except ImportError:
        logger.warning("zeroconf not installed - mDNS discovery disabled")
        logger.warning("Install with: pip install zeroconf")
        return False
    except Exception as e:
        logger.warning(f"Could not start mDNS: {e}")
        return False


def stop_mdns_service():
    """Stop mDNS service."""
    global _mdns_service
    if _mdns_service:
        try:
            _mdns_service['zeroconf'].unregister_service(_mdns_service['info'])
            _mdns_service['zeroconf'].close()
        except:
            pass
        _mdns_service = None


# =============================================================================
# Pydantic Models
# =============================================================================

class ConnectRequest(BaseModel):
    connection_type: str = "bluetooth"  # bluetooth, wifi, usb
    address: str  # /dev/rfcomm0, 192.168.0.10:35000, etc.

class PIDRequest(BaseModel):
    pids: str  # Comma-separated: "RPM, COOLANT_TEMP, LOAD"

class MonitorRequest(BaseModel):
    pids: str
    duration: float = 10.0
    interval: float = 1.0

class WaitConditionRequest(BaseModel):
    pid: str
    operator: str  # >, <, >=, <=, ==, equals
    value: float
    timeout: float = 30.0
    tolerance: Optional[float] = None

class SymptomRequest(BaseModel):
    symptom: str

class ObservationRequest(BaseModel):
    observation: str

class HypothesisRequest(BaseModel):
    diagnosis: str
    confidence: float
    reasoning: str

class ActuatorRequest(BaseModel):
    actuator: str  # cooling_fan, evap_purge, evap_vent, ac_clutch, fuel_pump, etc.
    state: str = "on"  # on, off, default
    duration: float = 5.0  # Auto-release after seconds

class ReadDIDRequest(BaseModel):
    module_addr: str  # Hex string like "0x760" or "760" or decimal
    dids: str  # Comma-separated hex DIDs: "F190, F187, 4001"
    bus: str = "HS-CAN"  # "HS-CAN" or "MS-CAN"

class SniffStartRequest(BaseModel):
    bus: str = "HS-CAN"
    filter_addr: Optional[str] = None
    vin: str = ""
    make: str = ""

class SniffLabelRequest(BaseModel):
    module: str
    did: str
    label: str


# =============================================================================
# FastAPI App
# =============================================================================

# Store the port globally for mDNS
_server_port = 8327

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup/shutdown lifecycle."""
    from elm327_gateway import __version__ as _ver
    logger.info(f"🚗 ELM327 Gateway v{_ver} starting...")
    start_mdns_service(_server_port)
    yield
    # Cleanup on shutdown
    global _elm
    _stop_keepalive()
    stop_mdns_service()
    if _elm and _elm.connected:
        await _elm.disconnect()
        logger.info("Disconnected ELM327 on shutdown")

from elm327_gateway import __version__ as _gw_version

app = FastAPI(
    title="ELM327 Gateway",
    description="Bluetooth-to-HTTP bridge for ELM327 OBD-II adapters",
    version=_gw_version,
    lifespan=lifespan
)

# Allow CORS for iPhone access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, restrict to your network
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =============================================================================
# Device Detection & Discovery
# =============================================================================

def detect_device(request: Request) -> dict:
    """Detect the client device type from User-Agent."""
    ua = request.headers.get("user-agent", "").lower()
    
    if "iphone" in ua or "ipad" in ua:
        return {"type": "ios", "name": "iPhone/iPad", "icon": "📱"}
    elif "android" in ua:
        return {"type": "android", "name": "Android", "icon": "📱"}
    elif "macintosh" in ua or "mac os" in ua:
        return {"type": "macos", "name": "Mac", "icon": "💻"}
    elif "windows" in ua:
        return {"type": "windows", "name": "Windows", "icon": "🖥️"}
    elif "linux" in ua:
        return {"type": "linux", "name": "Linux", "icon": "🐧"}
    else:
        return {"type": "unknown", "name": "Unknown", "icon": "🌐"}


@app.get("/discovery")
async def discovery_info(request: Request):
    """Return discovery information for clients."""
    device = detect_device(request)
    hostname = socket.gethostname()
    local_ip = get_local_ip()
    
    return {
        "client_device": device,
        "gateway": {
            "hostname": hostname,
            "local_url": f"http://{hostname}.local:{_server_port}/ui",
            "ip_url": f"http://{local_ip}:{_server_port}/ui",
            "ip": local_ip,
            "port": _server_port,
        },
        "mdns_enabled": _mdns_service is not None,
        "instructions": {
            "ios": "On iPhone, this gateway is discoverable via Bonjour. You can also bookmark this page.",
            "android": f"Bookmark http://{local_ip}:{_server_port}/ui",
            "desktop": f"Access via http://{hostname}.local:{_server_port}/ui or http://{local_ip}:{_server_port}/ui"
        }
    }


@app.get("/qr")
async def qr_code():
    """Generate QR code for easy phone scanning."""
    local_ip = get_local_ip()
    url = f"http://{local_ip}:{_server_port}/ui"
    
    try:
        import qrcode
        import qrcode.image.svg
        from io import BytesIO
        
        qr = qrcode.QRCode(version=1, box_size=10, border=2)
        qr.add_data(url)
        qr.make(fit=True)
        
        # Generate SVG
        factory = qrcode.image.svg.SvgPathImage
        img = qr.make_image(fill_color="black", back_color="white", image_factory=factory)
        
        buffer = BytesIO()
        img.save(buffer)
        svg_data = buffer.getvalue().decode()
        
        return HTMLResponse(content=f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <title>Scan to Connect</title>
            <style>
                body {{ font-family: -apple-system, sans-serif; text-align: center; padding: 40px; background: #1a1a2e; color: white; }}
                .qr {{ background: white; padding: 20px; border-radius: 20px; display: inline-block; margin: 20px; }}
                .url {{ font-family: monospace; background: #16213e; padding: 10px 20px; border-radius: 8px; margin: 20px; display: inline-block; }}
            </style>
        </head>
        <body>
            <h1>📱 Scan with your Phone</h1>
            <div class="qr">{svg_data}</div>
            <p>Or open this URL:</p>
            <div class="url">{url}</div>
            <p><a href="/ui" style="color: #4361ee;">← Back to Gateway</a></p>
        </body>
        </html>
        """)
    except ImportError:
        return HTMLResponse(content=f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <title>Connect URL</title>
            <style>
                body {{ font-family: -apple-system, sans-serif; text-align: center; padding: 40px; background: #1a1a2e; color: white; }}
                .url {{ font-family: monospace; background: #16213e; padding: 20px 30px; border-radius: 8px; margin: 20px; display: inline-block; font-size: 18px; }}
            </style>
        </head>
        <body>
            <h1>📱 Connect from your Phone</h1>
            <p>Open this URL on your phone:</p>
            <div class="url">{url}</div>
            <p style="color: #888; margin-top: 30px;">
                QR code not available. Install qrcode package:<br>
                <code>pip install qrcode[pil]</code>
            </p>
            <p><a href="/ui" style="color: #4361ee;">← Back to Gateway</a></p>
        </body>
        </html>
        """)


# =============================================================================
# Connection Endpoints
# =============================================================================

@app.get("/ports")
async def list_ports():
    """List available serial ports (for Windows COM port discovery)."""
    ports = []
    
    if platform.system() == "Windows":
        # Windows: Try COM1-COM20
        import serial
        for i in range(1, 21):
            port = f"COM{i}"
            try:
                s = serial.Serial(port)
                s.close()
                ports.append({"port": port, "type": "serial", "available": True})
            except:
                pass
    else:
        # Linux/Mac: Check /dev
        from pathlib import Path
        # Bluetooth serial
        for p in Path("/dev").glob("rfcomm*"):
            ports.append({"port": str(p), "type": "bluetooth", "available": True})
        # USB serial
        for p in Path("/dev").glob("ttyUSB*"):
            ports.append({"port": str(p), "type": "usb", "available": True})
        for p in Path("/dev").glob("ttyACM*"):
            ports.append({"port": str(p), "type": "usb", "available": True})
        # Mac
        for p in Path("/dev").glob("tty.OBD*"):
            ports.append({"port": str(p), "type": "bluetooth", "available": True})
        for p in Path("/dev").glob("tty.SLAB*"):
            ports.append({"port": str(p), "type": "usb", "available": True})
    
    return {
        "platform": platform.system(),
        "ports": ports,
        "hint": "Windows: COMx | Linux: /dev/rfcomm0 | WiFi: 192.168.0.10:35000"
    }


@app.get("/")
async def root():
    """Gateway status page."""
    global _elm, _connected_at
    
    connected = _elm and _elm.connected
    uptime = None
    if connected and _connected_at:
        uptime = str(datetime.now() - _connected_at).split('.')[0]
    
    return {
        "service": "ELM327 Gateway",
        "connected": connected,
        "uptime": uptime,
        "vin": _elm.vin if connected else None,
        "endpoints": {
            "ports": "GET /ports",
            "connect": "POST /connect",
            "disconnect": "POST /disconnect",
            "dtcs": "GET /dtcs",
            "pids": "POST /pids",
            "vin": "GET /vin",
            "monitor": "POST /monitor",
            "clear_dtcs": "POST /clear-dtcs",
            "session": "GET /session",
            "websocket": "WS /ws"
        }
    }


@app.post("/connect")
async def connect(req: ConnectRequest):
    """Connect to ELM327 adapter."""
    global _elm, _connected_at
    
    try:
        # If already connected, verify the link is alive and check for vehicle swap
        if _elm and _elm.connected:
            old_vin = _elm.vin
            
            # 1. Test the connection with a quick AT command
            link_alive = False
            try:
                resp = await _elm._connection.send_command("ATRV", timeout=3.0)
                if resp:
                    link_alive = True
            except Exception as e:
                logger.warning(f"Connection test failed: {e}")
            
            if link_alive:
                # 2. Re-read VIN to detect vehicle swap
                new_vin = None
                try:
                    new_vin = await _elm.read_vin()
                except Exception:
                    pass
                
                if new_vin and old_vin and new_vin == old_vin:
                    # Same vehicle, same link — nothing to do
                    supported = await _elm.get_supported_pids()
                    logger.info(f"Already connected to same vehicle (VIN: {old_vin})")
                    return {
                        "status": "connected",
                        "vin": old_vin,
                        "supported_pids": len(supported),
                        "address": req.address
                    }
                else:
                    # VIN changed (or couldn't read it) — vehicle swapped
                    logger.info(
                        f"Vehicle swap detected: {old_vin} → {new_vin}. "
                        f"Re-initializing..."
                    )
            else:
                logger.info("Connection dead. Reconnecting...")
            
            # Disconnect stale connection before reconnecting
            _stop_keepalive()
            try:
                await _elm.disconnect()
            except Exception:
                pass
            _elm = None
            _connected_at = None
        
        _elm = ELM327Service()
        success = await _elm.connect(req.connection_type, req.address)
        
        if not success and platform.system() == "Windows" and req.address.upper().startswith("COM"):
            # COM port failed - try other available Bluetooth COM ports
            logger.info(f"Primary port {req.address} failed, scanning other COM ports...")
            import serial
            for i in range(1, 21):
                port = f"COM{i}"
                if port.upper() == req.address.upper():
                    continue  # Skip the one we already tried
                try:
                    s = serial.Serial(port)
                    s.close()
                    logger.info(f"Trying alternate port: {port}")
                    _elm = ELM327Service()
                    success = await _elm.connect(req.connection_type, port)
                    if success:
                        logger.info(f"Connected on alternate port: {port}")
                        break
                except:
                    pass
        
        if success:
            _connected_at = datetime.now()
            _start_keepalive()
            supported = await _elm.get_supported_pids()
            return {
                "status": "connected",
                "vin": _elm.vin,
                "supported_pids": len(supported),
                "address": req.address
            }
        else:
            raise HTTPException(status_code=500, detail="Connection failed")
            
    except Exception as e:
        logger.error(f"Connection error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/disconnect")
async def disconnect():
    """Disconnect from ELM327."""
    global _elm, _connected_at
    
    _stop_keepalive()
    
    if _elm:
        await _elm.disconnect()
        _elm = None
        _connected_at = None
        return {"status": "disconnected"}
    
    return {"status": "already disconnected"}


def _require_connection():
    """Check ELM327 is connected."""
    if not _elm or not _elm.connected:
        raise HTTPException(status_code=400, detail="Not connected. POST /connect first.")


# =============================================================================
# Data Reading Endpoints
# =============================================================================

@app.get("/vin")
async def read_vin():
    """Read Vehicle Identification Number."""
    _require_connection()
    
    try:
        vin = await _elm.read_vin()
        return {"vin": vin}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/dtcs")
async def read_dtcs(user_id: str = "default"):
    """Read all Diagnostic Trouble Codes."""
    _require_connection()
    
    try:
        all_dtcs = await _elm.read_all_dtcs()
        session = get_session(user_id)
        
        result = {
            "stored": [],
            "pending": [],
            "permanent": []
        }
        
        for dtc in all_dtcs.get('stored', []):
            result["stored"].append({
                "code": dtc.code,
                "description": dtc.description
            })
            session.add_dtc(dtc.code, dtc.description)
        
        for dtc in all_dtcs.get('pending', []):
            result["pending"].append({
                "code": dtc.code,
                "description": dtc.description
            })
        
        for dtc in all_dtcs.get('permanent', []):
            result["permanent"].append({
                "code": dtc.code,
                "description": dtc.description
            })
        
        return result
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/supported_pids")
async def get_supported_pids_list():
    """Return the list of PIDs supported by the connected vehicle."""
    _require_connection()
    
    try:
        supported = await _elm.get_supported_pids()
        
        # PID bitmaps (0x00, 0x20, 0x40, 0x60, 0x80, 0xA0, 0xC0, 0xE0) are
        # "supported PIDs" queries, not real data. Filter them out.
        BITMAP_PIDS = {0x00, 0x20, 0x40, 0x60, 0x80, 0xA0, 0xC0, 0xE0}
        supported = [p for p in supported if p not in BITMAP_PIDS]
        
        # Resolve PID numbers to names
        from .pids import PIDRegistry
        pid_names = []
        for pid_num in sorted(supported):
            defn = PIDRegistry.get(pid_num)
            if defn:
                pid_names.append({
                    "pid": pid_num,
                    "name": defn.name,
                    "description": defn.description,
                    "unit": defn.unit,
                    "category": defn.category.value if defn.category else "unknown"
                })
            else:
                pid_names.append({
                    "pid": pid_num,
                    "name": f"PID_0x{pid_num:02X}",
                    "description": f"Unknown PID 0x{pid_num:02X}",
                    "unit": "",
                    "category": "unknown"
                })
        
        return {
            "supported_pids": pid_names,
            "count": len(pid_names),
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/modules")
async def scan_modules():
    """Discover all ECU modules on the CAN bus and list their supported PIDs."""
    _require_connection()
    
    try:
        modules = await _elm.scan_modules()
        
        result = []
        for mod in modules:
            result.append({
                "name": mod.name,
                "description": mod.description,
                "response_addr": f"0x{mod.response_addr:03X}",
                "request_addr": f"0x{mod.request_addr:03X}",
                "bus": getattr(mod, 'bus', 'HS-CAN'),
                "module_info": getattr(mod, 'module_info', {}),
                "supported_pids": [
                    {"pid": pid, "name": name}
                    for pid, name in zip(mod.supported_pids, mod.pid_names)
                ],
                "pid_count": len(mod.supported_pids),
            })
        
        return {
            "modules": result,
            "module_count": len(result),
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/read-did")
async def read_did(req: ReadDIDRequest):
    """Read UDS DIDs from a specific ECU module."""
    _require_connection()
    
    try:
        # Parse module address (hex string like "0x760" or "760")
        addr_str = req.module_addr.strip().lower().replace("0x", "")
        module_addr = int(addr_str, 16)
        
        # Parse DIDs (comma-separated hex: "F190, F187, 4001")
        did_strs = [d.strip().lower().replace("0x", "") for d in req.dids.split(",")]
        dids = [int(d, 16) for d in did_strs if d]
        
        if not dids:
            raise HTTPException(status_code=400, detail="No valid DIDs provided")
        
        results = await _elm.read_dids(module_addr, dids, bus=req.bus)
        
        return {
            "module_addr": f"0x{module_addr:03X}",
            "bus": req.bus,
            "dids": results,
            "did_count": len(results),
            "timestamp": datetime.now().isoformat()
        }
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid address or DID format: {e}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/reset-adapter")
async def reset_adapter():
    """
    Reset the ELM327 adapter (ATZ) to clear stale data buffers.
    
    Use this when PID readings appear stale or inconsistent.
    The adapter will be reinitialized but the connection stays alive.
    """
    _require_connection()
    
    try:
        conn = _elm._connection
        logger.info("Resetting ELM327 adapter (ATZ)...")
        await conn.send_command("ATZ", timeout=5.0)
        await asyncio.sleep(1.0)  # Give adapter time to reset
        # Re-initialize settings
        await conn.send_command("ATE0")  # Echo off
        await conn.send_command("ATL0")  # Linefeeds off
        await conn.send_command("ATS0")  # Spaces off
        await conn.send_command("ATSP0")  # Auto protocol
        logger.info("ELM327 adapter reset complete")
        return {"status": "reset", "timestamp": datetime.now().isoformat()}
    except Exception as e:
        logger.error(f"Adapter reset failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/pids")
async def read_pids(req: PIDRequest, user_id: str = "default"):
    """Read specific PIDs."""
    _require_connection()
    
    try:
        pid_names = [p.strip() for p in req.pids.split(',')]
        session = get_session(user_id)
        
        results = {}
        for pid_name in pid_names:
            reading = await _elm.read_pid(pid_name)
            if reading:
                results[pid_name] = {
                    "value": reading.value,
                    "unit": reading.unit
                }
        
        return {"pids": results, "timestamp": datetime.now().isoformat()}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/fuel_trims")
async def read_fuel_trims(user_id: str = "default"):
    """Read fuel trim values - common diagnostic data."""
    _require_connection()
    
    try:
        # Read all fuel trim PIDs
        trim_pids = ['STFT1', 'LTFT1', 'STFT2', 'LTFT2']
        results = {}
        
        for pid_name in trim_pids:
            reading = await _elm.read_pid(pid_name)
            if reading:
                results[pid_name] = {
                    "value": reading.value,
                    "unit": reading.unit
                }
        
        return {"fuel_trims": results, "timestamp": datetime.now().isoformat()}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/actuators")
async def list_actuators():
    """List available actuators and probe which ones the vehicle supports."""
    _require_connection()
    
    try:
        if _elm._actuator_control:
            supported = await _elm._actuator_control.get_supported_actuators()
        else:
            supported = []
        
        from .bidirectional import STANDARD_ACTUATORS, ActuatorType
        
        actuators = []
        for act_type, defn in STANDARD_ACTUATORS.items():
            actuators.append({
                "id": act_type.value,
                "name": defn.name,
                "description": defn.description,
                "supported": act_type in supported,
                "states": [s.value for s in defn.supported_states]
            })
        
        return {
            "actuators": actuators,
            "supported_count": len(supported),
            "total_count": len(actuators),
            "warning": "Actuator control directly commands vehicle components. Use with caution."
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/actuator")
async def control_actuator(req: ActuatorRequest):
    """Control a vehicle actuator (bidirectional control)."""
    _require_connection()
    
    try:
        success = await _elm.actuator_test(req.actuator, req.state, req.duration)
        
        if success:
            return {
                "status": "success",
                "actuator": req.actuator,
                "state": req.state,
                "duration": req.duration,
                "message": f"{req.actuator} commanded {req.state.upper()} for {req.duration}s. Verify operation physically."
            }
        else:
            return {
                "status": "unsupported",
                "actuator": req.actuator,
                "message": f"{req.actuator} actuator test not supported on this vehicle (Mode $08 may not be available)"
            }
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/monitor")
async def monitor_pids(req: MonitorRequest, user_id: str = "default"):
    """Monitor PIDs over time."""
    _require_connection()
    
    try:
        pid_names = [p.strip() for p in req.pids.split(',')]
        
        # Collect samples
        samples = []
        start = datetime.now()
        
        while (datetime.now() - start).total_seconds() < req.duration:
            sample = {"timestamp": datetime.now().isoformat()}
            for pid_name in pid_names:
                reading = await _elm.read_pid(pid_name)
                if reading:
                    sample[pid_name] = reading.value
            samples.append(sample)
            await asyncio.sleep(req.interval)
        
        # Calculate stats
        stats = {}
        for pid_name in pid_names:
            values = [s.get(pid_name) for s in samples if s.get(pid_name) is not None]
            if values:
                stats[pid_name] = {
                    "min": min(values),
                    "max": max(values),
                    "avg": sum(values) / len(values),
                    "samples": len(values)
                }
        
        return {
            "samples": samples,
            "stats": stats,
            "duration": req.duration
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/wait-condition")
async def wait_for_condition(req: WaitConditionRequest):
    """Wait for a PID to meet a condition."""
    _require_connection()
    
    # Build condition function
    op = req.operator.lower().strip()
    value = req.value
    tol = req.tolerance if req.tolerance is not None else abs(value * 0.1)
    
    if op in ('==', 'equals', 'eq', '='):
        condition = lambda v: abs(v - value) <= tol
    elif op in ('>', 'gt', 'above'):
        condition = lambda v: v > value
    elif op in ('<', 'lt', 'below'):
        condition = lambda v: v < value
    elif op in ('>=', 'gte'):
        condition = lambda v: v >= value
    elif op in ('<=', 'lte'):
        condition = lambda v: v <= value
    else:
        raise HTTPException(status_code=400, detail=f"Unknown operator: {req.operator}")
    
    try:
        result = await _elm.wait_for_condition(
            req.pid,
            condition,
            timeout=req.timeout
        )
        
        if result:
            return {
                "success": True,
                "pid": req.pid,
                "value": result.value,
                "unit": result.unit
            }
        else:
            return {
                "success": False,
                "pid": req.pid,
                "message": f"Timeout after {req.timeout}s"
            }
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/clear-dtcs")
async def clear_dtcs(user_id: str = "default"):
    """Clear all DTCs (Mode $04)."""
    _require_connection()
    
    try:
        success = await _elm.clear_dtcs()
        if success:
            session = get_session(user_id)
            session.log_action("Cleared DTCs via gateway")
            return {"status": "cleared"}
        else:
            return {"status": "failed", "message": "Clear command not acknowledged"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# CAN Sniffer Endpoints — Passive traffic capture (Y-Splitter mode)
# =============================================================================

async def _sniff_loop(bus: str, filter_addr: Optional[int] = None):
    """Background task: put adapter into STMA mode and capture frames."""
    import time as _time
    global _sniff_capture, _sniff_running

    try:
        await _elm.send_raw_command("ATH1")
        await _elm.send_raw_command("ATS1")

        if bus == "MS-CAN":
            await _elm.send_raw_command("STPBR 125000")
            await _elm.send_raw_command("ATSP 6")

        if filter_addr:
            await _elm.send_raw_command(f"ATCF {filter_addr:03X}")
            await _elm.send_raw_command("ATCM 7FF")

        logger.info(f"Starting STMA on {bus}" + (f" filter=0x{filter_addr:03X}" if filter_addr else ""))
        await _elm.send_raw_command("STMA")

        while _sniff_running:
            try:
                line = await asyncio.wait_for(
                    _elm.send_raw_command(""),
                    timeout=0.5,
                )
                if line:
                    for raw_line in line.splitlines():
                        raw_line = raw_line.strip()
                        if not raw_line or raw_line == ">" or raw_line.startswith("STMA"):
                            continue
                        frame = parse_stma_line(raw_line, timestamp=_time.monotonic())
                        if frame:
                            if filter_addr and frame.arb_id != filter_addr and frame.arb_id != (filter_addr + 8):
                                continue
                            _sniff_capture.frames.append(frame)
                            # Auto-decode broadcast frames via DBC
                            if _broadcast_decoder is not None:
                                _broadcast_decoder.decode_frame(
                                    frame.arb_id, frame.data, frame.timestamp
                                )
            except asyncio.TimeoutError:
                pass
            except Exception as e:
                logger.debug(f"Sniff read error: {e}")

            await asyncio.sleep(0.01)

    except Exception as e:
        logger.error(f"Sniff loop error: {e}")
    finally:
        try:
            await _elm.send_raw_command("\r")
            await asyncio.sleep(0.3)
            await _elm.send_raw_command("ATH0")
            await _elm.send_raw_command("ATS0")
            if bus == "MS-CAN":
                await _elm.send_raw_command("STPBR 500000")
                await _elm.send_raw_command("ATSP 0")
        except Exception:
            pass
        _sniff_running = False
        logger.info("Sniff loop stopped")


@app.post("/sniff/start")
async def sniff_start(req: SniffStartRequest):
    """Start passive CAN bus monitoring (sniffer mode)."""
    global _sniff_capture, _sniff_task, _sniff_running, _broadcast_decoder

    _require_connection()

    if _sniff_running:
        raise HTTPException(status_code=409, detail="Sniffer already running.")

    if _adapter_caps and not _adapter_caps.supports_monitor_mode:
        raise HTTPException(status_code=400, detail="Adapter does not support STMA.")

    filter_addr = None
    if req.filter_addr:
        filter_addr = int(req.filter_addr.strip().replace("0x", ""), 16)

    # Load DBC database for broadcast decoding
    dbc_db: Optional[DBCDatabase] = None
    dbc_source = ""
    if req.vin:
        dbc_db = load_dbc_for_vin(req.vin)
        dbc_source = f"VIN {req.vin}"
    elif req.make:
        dbc_db = load_dbc_for_oem(req.make)
        dbc_source = f"make {req.make}"
    elif _elm and _elm.vin:
        dbc_db = load_dbc_for_vin(_elm.vin)
        dbc_source = f"cached VIN {_elm.vin}"

    if dbc_db and dbc_db.total_messages > 0:
        _broadcast_decoder = LiveBroadcastDecoder(dbc_db)
        logger.info("DBC decoder loaded from %s: %d messages, %d signals",
                    dbc_source, dbc_db.total_messages, dbc_db.total_signals)
    else:
        _broadcast_decoder = None
        logger.info("No DBC files loaded — broadcast frames will not be decoded")

    _sniff_capture = SnifferCapture(
        started_at=time.monotonic(),
        bus=req.bus,
    )
    _sniff_running = True
    _sniff_task = asyncio.create_task(_sniff_loop(req.bus, filter_addr))

    return {
        "status": "started",
        "bus": req.bus,
        "filter": req.filter_addr or None,
        "dbc_loaded": _broadcast_decoder is not None,
        "dbc_info": _broadcast_decoder.get_stats() if _broadcast_decoder else None,
        "message": "Sniffer running. Adapter is in passive listen mode."
                   + (f" DBC decoder active ({dbc_source})." if _broadcast_decoder else ""),
    }


@app.post("/sniff/stop")
async def sniff_stop():
    """Stop passive CAN monitoring and return captured UDS exchanges."""
    global _sniff_capture, _sniff_task, _sniff_running

    if not _sniff_running and not _sniff_capture:
        raise HTTPException(status_code=400, detail="No active sniffer session.")

    _sniff_running = False

    if _sniff_task:
        try:
            await asyncio.wait_for(_sniff_task, timeout=5.0)
        except asyncio.TimeoutError:
            _sniff_task.cancel()
        _sniff_task = None

    if not _sniff_capture:
        return {"status": "stopped", "frames": 0, "exchanges": 0}

    _sniff_capture.exchanges = extract_uds_exchanges(_sniff_capture.frames)

    summary = _sniff_capture.to_summary()
    did_data = _sniff_capture.get_did_data()

    result = {
        "status": "stopped",
        **summary,
        "did_data": did_data,
        "labels": {f"{k[0]}:{k[1]}": v for k, v in _sniff_capture.labels.items()},
    }

    # Include final DBC-decoded broadcast snapshot
    if _broadcast_decoder:
        result["broadcast"] = {
            "key_signals": _broadcast_decoder.get_key_signals(),
            "all_signals": _broadcast_decoder.get_snapshot(),
            "stats": _broadcast_decoder.get_stats(),
        }

    return result


@app.get("/sniff/frames")
async def sniff_frames():
    """Get live capture status and discovered DIDs so far."""
    if not _sniff_capture:
        raise HTTPException(status_code=400, detail="No active sniffer session.")

    exchanges = extract_uds_exchanges(_sniff_capture.frames)
    _sniff_capture.exchanges = exchanges

    summary = _sniff_capture.to_summary()
    did_data = _sniff_capture.get_did_data()

    result = {
        "running": _sniff_running,
        **summary,
        "did_data": did_data,
        "labels": {f"{k[0]}:{k[1]}": v for k, v in _sniff_capture.labels.items()},
    }

    # Include DBC-decoded broadcast data if decoder is active
    if _broadcast_decoder:
        result["broadcast"] = {
            "key_signals": _broadcast_decoder.get_key_signals(),
            "stats": _broadcast_decoder.get_stats(),
        }

    return result


@app.get("/sniff/live")
async def sniff_live():
    """Get live decoded broadcast data from the CAN bus.

    Returns DBC-decoded signal values from broadcast CAN traffic.
    This is the primary endpoint for the AI to read real-time vehicle state
    without relying on the tech to narrate scan tool readings.

    Only returns data while the sniffer is running with DBC files loaded.
    """
    if not _sniff_capture:
        raise HTTPException(status_code=400, detail="No active sniffer session.")

    if not _broadcast_decoder:
        raise HTTPException(
            status_code=400,
            detail="No DBC decoder loaded. Start sniffer with VIN or make for broadcast decoding."
        )

    return {
        "running": _sniff_running,
        "key_signals": _broadcast_decoder.get_key_signals(),
        "all_signals": _broadcast_decoder.get_snapshot(),
        "stats": _broadcast_decoder.get_stats(),
    }


@app.post("/sniff/label")
async def sniff_label(req: SniffLabelRequest):
    """Label a captured DID with a human-readable name."""
    if not _sniff_capture:
        raise HTTPException(status_code=400, detail="No active sniffer session.")

    module = req.module.strip().upper().replace("0X", "0x")
    if not module.startswith("0x"):
        module = f"0x{module}"
    did = req.did.strip().upper()
    label = req.label.strip()

    _sniff_capture.labels[(module, did)] = label

    return {
        "status": "labeled",
        "module": module,
        "did": did,
        "label": label,
        "total_labels": len(_sniff_capture.labels),
    }


@app.get("/snapshot")
async def diagnostic_snapshot():
    """Capture comprehensive diagnostic snapshot."""
    _require_connection()
    
    try:
        snapshot = await _elm.capture_diagnostic_snapshot()
        
        return {
            "timestamp": snapshot.timestamp.isoformat(),
            "vin": snapshot.vin,
            "dtcs": [{"code": d.code, "description": d.description} for d in snapshot.dtcs],
            "pending_dtcs": [{"code": d.code, "description": d.description} for d in snapshot.pending_dtcs],
            "pids": {
                name: {"value": r.value, "unit": r.unit}
                for name, r in snapshot.pids.items()
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# Update & Version Endpoints
# =============================================================================

@app.get("/version")
async def get_version():
    """Return the current gateway version."""
    return {
        "version": get_current_version(),
        "frozen": get_exe_path() is not None,
    }


@app.post("/check-update")
async def trigger_update_check():
    """Remotely trigger an update check.

    If a newer version is available, downloads it and exits so the
    updater script can launch the new version.

    Returns:
        {"status": "up-to-date"} if current version is latest.
        {"status": "updating", "tag": "v1.2.XX"} if update found & applied.
        {"status": "update-failed", ...} if download/apply failed.
        {"status": "not-frozen"} if running from source (no exe to update).
    """
    current = get_current_version()
    logger.info(f"Remote update check triggered (current: v{current})")

    if get_exe_path() is None:
        return {"status": "not-frozen", "version": current}

    update_info = await check_for_update()
    if not update_info:
        return {"status": "up-to-date", "version": current}

    tag = update_info["tag"]
    logger.info(f"Remote update: {tag} available, applying...")

    # Run the full update flow in the background so we can respond first
    async def _do_update():
        await asyncio.sleep(1)  # Let the HTTP response go out
        should_exit = await check_and_apply_update()
        if should_exit:
            logger.info(f"Update to {tag} applied, exiting for restart...")
            await asyncio.sleep(2)
            os._exit(0)

    asyncio.create_task(_do_update())

    return {
        "status": "updating",
        "from_version": current,
        "to_version": tag,
        "message": f"Downloading {tag}, gateway will restart shortly",
    }


# =============================================================================
# Session Endpoints
# =============================================================================

@app.get("/session")
async def get_session_status(user_id: str = "default"):
    """Get diagnostic session status."""
    session = get_session(user_id)
    
    return {
        "session_id": session.session_id,
        "phase": session.phase.value if hasattr(session.phase, 'value') else str(session.phase),
        "vehicle": {
            "vin": session.vehicle_vin,
            "year": session.vehicle_year,
            "make": session.vehicle_make,
            "model": session.vehicle_model
        },
        "dtcs": [{"code": d.code, "description": d.description} for d in session.dtcs],
        "symptoms": session.symptoms,
        "observations": session.observations,
        "hypotheses": [
            {"diagnosis": h.diagnosis, "confidence": h.confidence, "reasoning": h.reasoning}
            for h in session.hypotheses
        ],
        "next_steps": session.next_steps,
        "action_log": session.action_log[-10:]  # Last 10 actions
    }


@app.post("/session/reset")
async def reset_session_endpoint(user_id: str = "default"):
    """Reset/start new diagnostic session."""
    session = reset_session(user_id)
    return {"status": "reset", "session_id": session.session_id}


@app.post("/session/symptom")
async def add_symptom(req: SymptomRequest, user_id: str = "default"):
    """Add a symptom to the session."""
    session = get_session(user_id)
    session.add_symptom(req.symptom)
    return {"status": "added", "symptoms": session.symptoms}


@app.post("/session/observation")
async def add_observation(req: ObservationRequest, user_id: str = "default"):
    """Add an observation to the session."""
    session = get_session(user_id)
    session.add_observation(req.observation)
    return {"status": "added", "observations": session.observations}


@app.post("/session/hypothesis")
async def add_hypothesis(req: HypothesisRequest, user_id: str = "default"):
    """Add a diagnostic hypothesis."""
    session = get_session(user_id)
    session.add_hypothesis(req.diagnosis, req.confidence, req.reasoning)
    return {"status": "added", "hypotheses_count": len(session.hypotheses)}


# =============================================================================
# WebSocket for Real-Time Streaming
# =============================================================================

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """
    WebSocket for real-time PID streaming.
    
    Send: {"action": "subscribe", "pids": ["RPM", "COOLANT_TEMP"]}
    Receive: {"RPM": 850, "COOLANT_TEMP": 195, "timestamp": "..."}
    """
    await websocket.accept()
    logger.info("WebSocket client connected")
    
    subscribed_pids = []
    streaming = False
    
    try:
        while True:
            # Check for incoming messages (non-blocking)
            try:
                data = await asyncio.wait_for(websocket.receive_json(), timeout=0.1)
                
                action = data.get("action")
                
                if action == "subscribe":
                    subscribed_pids = data.get("pids", [])
                    streaming = True
                    await websocket.send_json({
                        "status": "subscribed",
                        "pids": subscribed_pids
                    })
                    
                elif action == "unsubscribe":
                    streaming = False
                    await websocket.send_json({"status": "unsubscribed"})
                    
                elif action == "read":
                    # One-shot read
                    pids = data.get("pids", [])
                    if _elm and _elm.connected:
                        result = {"timestamp": datetime.now().isoformat()}
                        for pid in pids:
                            reading = await _elm.read_pid(pid)
                            if reading:
                                result[pid] = reading.value
                        await websocket.send_json(result)
                    else:
                        await websocket.send_json({"error": "Not connected"})
                        
            except asyncio.TimeoutError:
                pass  # No message, continue streaming
            
            # Stream subscribed PIDs
            if streaming and subscribed_pids and _elm and _elm.connected:
                result = {"timestamp": datetime.now().isoformat()}
                for pid in subscribed_pids:
                    try:
                        reading = await _elm.read_pid(pid)
                        if reading:
                            result[pid] = reading.value
                    except:
                        pass
                await websocket.send_json(result)
                await asyncio.sleep(0.5)  # 2 Hz update rate
            else:
                await asyncio.sleep(0.1)
                
    except WebSocketDisconnect:
        logger.info("WebSocket client disconnected")


# =============================================================================
# Simple Web UI (for testing from phone browser)
# =============================================================================

@app.get("/ui", response_class=HTMLResponse)
async def web_ui(request: Request):
    """Simple web UI for testing from phone browser."""
    device = detect_device(request)
    hostname = socket.gethostname()
    local_ip = get_local_ip()
    
    return f"""
<!DOCTYPE html>
<html>
<head>
    <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no">
    <meta name="apple-mobile-web-app-capable" content="yes">
    <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
    <meta name="apple-mobile-web-app-title" content="ELM327">
    <link rel="apple-touch-icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🚗</text></svg>">
    <title>ELM327 Gateway</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, sans-serif; padding: 20px; max-width: 600px; margin: 0 auto; background: #1a1a2e; color: #eee; -webkit-tap-highlight-color: transparent; }}
        button {{ padding: 15px 30px; font-size: 18px; margin: 5px; border-radius: 8px; border: none; cursor: pointer; -webkit-appearance: none; }}
        button:active {{ transform: scale(0.98); opacity: 0.9; }}
        .btn-primary {{ background: #4361ee; color: white; }}
        .btn-danger {{ background: #ef476f; color: white; }}
        .btn-success {{ background: #06d6a0; color: #1a1a2e; }}
        .btn-small {{ padding: 8px 16px; font-size: 14px; }}
        .connected {{ background: #06d6a0; color: #1a1a2e; }}
        .disconnected {{ background: #ef476f; color: white; }}
        .data {{ background: #16213e; padding: 15px; border-radius: 8px; margin: 10px 0; font-family: monospace; white-space: pre-wrap; word-break: break-all; font-size: 14px; }}
        h1 {{ font-size: 28px; text-align: center; margin-bottom: 5px; }}
        h3 {{ color: #4361ee; margin-top: 20px; margin-bottom: 10px; }}
        .subtitle {{ text-align: center; color: #888; margin-bottom: 20px; font-size: 14px; }}
        .status {{ padding: 15px; border-radius: 8px; margin: 10px 0; text-align: center; font-weight: bold; }}
        input, select {{ padding: 12px; font-size: 16px; width: 100%; box-sizing: border-box; margin: 5px 0; border-radius: 8px; border: 1px solid #4361ee; background: #16213e; color: #eee; -webkit-appearance: none; }}
        .port-list {{ display: flex; flex-wrap: wrap; gap: 8px; margin: 10px 0; }}
        .port-btn {{ padding: 8px 16px; font-size: 14px; background: #16213e; border: 1px solid #4361ee; color: #4361ee; border-radius: 20px; cursor: pointer; }}
        .port-btn:hover, .port-btn:active {{ background: #4361ee; color: white; }}
        .section {{ background: #16213e; padding: 15px; border-radius: 12px; margin: 15px 0; }}
        .btn-row {{ display: flex; flex-wrap: wrap; gap: 10px; }}
        .stream-data {{ font-size: 24px; text-align: center; }}
        .stream-data b {{ color: #4361ee; }}
        .device-info {{ background: #0f3460; padding: 10px 15px; border-radius: 8px; margin-bottom: 15px; font-size: 13px; display: flex; justify-content: space-between; align-items: center; }}
        .device-info a {{ color: #4361ee; text-decoration: none; }}
        .add-to-home {{ background: #4361ee; color: white; padding: 12px; border-radius: 8px; text-align: center; margin: 15px 0; display: none; }}
        .ios .add-to-home {{ display: block; }}
    </style>
</head>
<body class="{device['type']}">
    <h1>🚗 ELM327 Gateway</h1>
    <div class="subtitle">{device['icon']} Connected from {device['name']}</div>
    
    <div class="device-info">
        <span>Gateway: {hostname}</span>
        <a href="/qr">📱 QR Code</a>
    </div>
    
    <div class="add-to-home">
        💡 <b>Tip:</b> Tap Share → "Add to Home Screen" for quick access
    </div>
    
    <div id="status" class="status disconnected">Disconnected from ELM327</div>
    
    <div class="section">
        <h3>📡 Connect to ELM327</h3>
        <div id="portList" class="port-list">
            <span style="color: #888;">Detecting ports on gateway...</span>
        </div>
        <input id="address" placeholder="Device address">
        <select id="connType">
            <option value="bluetooth">Bluetooth (Linux: /dev/rfcomm0)</option>
            <option value="usb">USB Serial (Windows: COMx)</option>
            <option value="wifi">WiFi (192.168.0.10:35000)</option>
        </select>
        <div class="btn-row">
            <button class="btn-success" onclick="connect()">🔌 Connect</button>
            <button class="btn-danger" onclick="disconnect()">Disconnect</button>
            <button class="btn-primary btn-small" onclick="detectPorts()">🔍 Refresh</button>
        </div>
    </div>
    
    <!-- Android Direct Bluetooth Option -->
    <div id="androidDirect" class="section" style="display: none;">
        <h3>📲 Direct Bluetooth (Android Only)</h3>
        <p style="font-size: 13px; color: #888; margin-bottom: 10px;">
            Connect directly from your phone without the gateway. Requires Chrome and may be less stable.
        </p>
        <div class="btn-row">
            <button class="btn-primary" onclick="webBluetoothConnect()">🔵 Connect via Web Bluetooth</button>
        </div>
        <div id="webBtStatus" style="margin-top: 10px; font-size: 13px; color: #888;"></div>
    </div>
    
    <div class="section">
        <h3>📊 Read Data</h3>
        <div class="btn-row">
            <button class="btn-primary" onclick="readDTCs()">🔍 DTCs</button>
            <button class="btn-primary" onclick="readVIN()">🚗 VIN</button>
            <button class="btn-primary" onclick="readPIDs()">📊 Live</button>
            <button class="btn-primary" onclick="snapshot()">📋 Snapshot</button>
        </div>
    </div>
    
    <div class="section">
        <h3>📋 Results</h3>
        <div id="results" class="data">Tap a button above...</div>
    </div>
    
    <div class="section">
        <h3>📈 Live Stream</h3>
        <div class="btn-row">
            <button class="btn-success" onclick="startStream()">▶ Start</button>
            <button class="btn-danger" onclick="stopStream()">⏹ Stop</button>
        </div>
        <div id="stream" class="data stream-data">--</div>
    </div>

    <script>
        const API = '';
        let ws = null;
        
        async function api(method, endpoint, body = null) {{
            const opts = {{ method, headers: {{'Content-Type': 'application/json'}} }};
            if (body) opts.body = JSON.stringify(body);
            try {{
                const res = await fetch(API + endpoint, opts);
                return res.json();
            }} catch(e) {{
                return {{error: e.message}};
            }}
        }}
        
        async function detectPorts() {{
            const res = await api('GET', '/ports');
            const container = document.getElementById('portList');
            
            if (res.ports && res.ports.length > 0) {{
                container.innerHTML = res.ports.map(p => 
                    `<button class="port-btn" onclick="selectPort('${{p.port}}', '${{p.type}}')">${{p.port}}</button>`
                ).join('');
            }} else {{
                container.innerHTML = '<span style="color: #888;">No ports detected. ' + 
                    (res.platform === 'Windows' ? 'Check Device Manager for COM ports.' : 'Run setup_bluetooth.sh first.') + 
                    '</span>';
            }}
            
            // Set default based on platform
            const addr = document.getElementById('address');
            if (!addr.value) {{
                if (res.ports && res.ports.length > 0) {{
                    selectPort(res.ports[0].port, res.ports[0].type);
                }} else if (res.platform === 'Windows') {{
                    addr.value = 'COM5';
                    addr.placeholder = 'e.g., COM5, COM6...';
                }} else {{
                    addr.value = '/dev/rfcomm0';
                }}
            }}
        }}
        
        function selectPort(port, type) {{
            document.getElementById('address').value = port;
            const connType = document.getElementById('connType');
            if (type === 'bluetooth') connType.value = 'bluetooth';
            else if (type === 'usb') connType.value = 'usb';
            else if (type === 'wifi') connType.value = 'wifi';
        }}
        
        async function connect() {{
            document.getElementById('results').textContent = 'Connecting...';
            const address = document.getElementById('address').value;
            const connType = document.getElementById('connType').value;
            const res = await api('POST', '/connect', {{connection_type: connType, address}});
            document.getElementById('results').textContent = JSON.stringify(res, null, 2);
            if (res.status === 'connected') {{
                document.getElementById('status').className = 'status connected';
                document.getElementById('status').textContent = '✅ Connected - VIN: ' + (res.vin || 'N/A');
            }} else {{
                document.getElementById('status').className = 'status disconnected';
                document.getElementById('status').textContent = '❌ ' + (res.detail || res.error || 'Connection failed');
            }}
        }}
        
        async function disconnect() {{
            const res = await api('POST', '/disconnect');
            document.getElementById('results').textContent = JSON.stringify(res, null, 2);
            document.getElementById('status').className = 'status disconnected';
            document.getElementById('status').textContent = 'Disconnected';
        }}
        
        async function readDTCs() {{
            document.getElementById('results').textContent = 'Reading DTCs...';
            const res = await api('GET', '/dtcs');
            let output = '';
            if (res.stored && res.stored.length > 0) {{
                output += '🔴 STORED DTCs:\\n';
                res.stored.forEach(d => output += `  ${{d.code}}: ${{d.description}}\\n`);
            }} else {{
                output += '✅ No stored DTCs\\n';
            }}
            if (res.pending && res.pending.length > 0) {{
                output += '\\n🟡 PENDING DTCs:\\n';
                res.pending.forEach(d => output += `  ${{d.code}}: ${{d.description}}\\n`);
            }}
            document.getElementById('results').textContent = output || JSON.stringify(res, null, 2);
        }}
        
        async function readVIN() {{
            document.getElementById('results').textContent = 'Reading VIN...';
            const res = await api('GET', '/vin');
            document.getElementById('results').textContent = res.vin ? '🚗 VIN: ' + res.vin : JSON.stringify(res, null, 2);
        }}
        
        async function readPIDs() {{
            document.getElementById('results').textContent = 'Reading PIDs...';
            const res = await api('POST', '/pids', {{pids: 'RPM, COOLANT_TEMP, LOAD, STFT_B1, LTFT_B1, SPEED'}});
            if (res.pids) {{
                let output = '📊 Live Data:\\n';
                for (const [name, data] of Object.entries(res.pids)) {{
                    output += `  ${{name}}: ${{data.value}} ${{data.unit}}\\n`;
                }}
                document.getElementById('results').textContent = output;
            }} else {{
                document.getElementById('results').textContent = JSON.stringify(res, null, 2);
            }}
        }}
        
        async function snapshot() {{
            document.getElementById('results').textContent = 'Capturing snapshot...';
            const res = await api('GET', '/snapshot');
            document.getElementById('results').textContent = JSON.stringify(res, null, 2);
        }}
        
        function startStream() {{
            const wsUrl = 'ws://' + window.location.host + '/ws';
            ws = new WebSocket(wsUrl);
            ws.onopen = () => {{
                ws.send(JSON.stringify({{action: 'subscribe', pids: ['RPM', 'COOLANT_TEMP', 'SPEED']}}));
            }};
            ws.onmessage = (e) => {{
                const data = JSON.parse(e.data);
                if (data.RPM !== undefined || data.COOLANT_TEMP !== undefined) {{
                    document.getElementById('stream').innerHTML = 
                        '<b>RPM:</b> ' + (data.RPM?.toFixed(0) || '--') + '<br>' +
                        '<b>Coolant:</b> ' + (data.COOLANT_TEMP?.toFixed(1) || '--') + '°F<br>' +
                        '<b>Speed:</b> ' + (data.SPEED?.toFixed(0) || '--') + ' mph';
                }}
            }};
            ws.onerror = () => {{
                document.getElementById('stream').textContent = 'WebSocket error';
            }};
        }}
        
        function stopStream() {{
            if (ws) {{
                ws.send(JSON.stringify({{action: 'unsubscribe'}}));
                ws.close();
                ws = null;
            }}
            document.getElementById('stream').textContent = '--';
        }}
        
        // =====================================================
        // Web Bluetooth Direct Connection (Android Chrome)
        // =====================================================
        let webBtDevice = null;
        let webBtChar = null;
        
        // Check if Web Bluetooth is available and show Android option
        function checkWebBluetooth() {{
            const ua = navigator.userAgent.toLowerCase();
            const isAndroid = ua.includes('android');
            const hasWebBt = 'bluetooth' in navigator;
            
            if (isAndroid && hasWebBt) {{
                document.getElementById('androidDirect').style.display = 'block';
            }}
        }}
        
        async function webBluetoothConnect() {{
            const statusEl = document.getElementById('webBtStatus');
            
            if (!navigator.bluetooth) {{
                statusEl.innerHTML = '❌ Web Bluetooth not supported. Use Chrome on Android.';
                return;
            }}
            
            try {{
                statusEl.innerHTML = '🔍 Scanning for ELM327...';
                
                // Request Bluetooth device - ELM327 uses Serial Port Profile
                webBtDevice = await navigator.bluetooth.requestDevice({{
                    acceptAllDevices: true,
                    optionalServices: ['0000fff0-0000-1000-8000-00805f9b34fb', '0000ffe0-0000-1000-8000-00805f9b34fb']
                }});
                
                statusEl.innerHTML = '📡 Connecting to ' + webBtDevice.name + '...';
                
                const server = await webBtDevice.gatt.connect();
                
                // Try common ELM327 BLE services
                let service;
                try {{
                    service = await server.getPrimaryService('0000fff0-0000-1000-8000-00805f9b34fb');
                }} catch {{
                    service = await server.getPrimaryService('0000ffe0-0000-1000-8000-00805f9b34fb');
                }}
                
                // Get characteristic for read/write
                const chars = await service.getCharacteristics();
                webBtChar = chars.find(c => c.properties.write || c.properties.writeWithoutResponse);
                
                if (webBtChar) {{
                    // Subscribe to notifications
                    const notifyChar = chars.find(c => c.properties.notify);
                    if (notifyChar) {{
                        await notifyChar.startNotifications();
                        notifyChar.addEventListener('characteristicvaluechanged', handleWebBtData);
                    }}
                    
                    statusEl.innerHTML = '✅ Connected to ' + webBtDevice.name + ' via Web Bluetooth!<br>' +
                        '<span style="color: #06d6a0;">Direct phone connection - no gateway needed</span>';
                    
                    // Send ATZ to initialize
                    await webBtSend('ATZ\\r');
                }} else {{
                    statusEl.innerHTML = '❌ No writable characteristic found';
                }}
                
            }} catch (err) {{
                statusEl.innerHTML = '❌ ' + err.message + '<br>' +
                    '<span style="color: #888;">Try: Gateway connection (more reliable)</span>';
            }}
        }}
        
        async function webBtSend(cmd) {{
            if (!webBtChar) return;
            const encoder = new TextEncoder();
            const data = encoder.encode(cmd);
            try {{
                if (webBtChar.properties.writeWithoutResponse) {{
                    await webBtChar.writeValueWithoutResponse(data);
                }} else {{
                    await webBtChar.writeValue(data);
                }}
            }} catch (e) {{
                console.error('Web BT write error:', e);
            }}
        }}
        
        function handleWebBtData(event) {{
            const decoder = new TextDecoder();
            const value = decoder.decode(event.target.value);
            console.log('Web BT data:', value);
            // Could parse OBD responses here for direct mode
        }}
        
        // Init
        api('GET', '/').then(res => {{
            if (res.connected) {{
                document.getElementById('status').className = 'status connected';
                document.getElementById('status').textContent = '✅ Connected - VIN: ' + (res.vin || 'N/A');
            }}
        }});
        detectPorts();
        checkWebBluetooth();
    </script>
</body>
</html>
"""


# =============================================================================
# Main Entry Point
# =============================================================================

if __name__ == "__main__":
    import argparse
    import uvicorn
    
    parser = argparse.ArgumentParser(description="ELM327 Bluetooth Gateway")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    parser.add_argument("--port", type=int, default=8327, help="Port to listen on")
    args = parser.parse_args()
    
    # Set global port for mDNS
    _server_port = args.port
    
    local_ip = get_local_ip()
    hostname = socket.gethostname()
    
    print(f"""
╔══════════════════════════════════════════════════════════════╗
║                    ELM327 Gateway Server                     ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║  📱 iPhone/iPad (Bonjour auto-discovery):                    ║
║     http://{hostname}.local:{args.port}/ui{' ' * (27 - len(hostname) - len(str(args.port)))}║
║                                                              ║
║  📱 Any device (direct IP):                                  ║
║     http://{local_ip}:{args.port}/ui{' ' * (33 - len(local_ip) - len(str(args.port)))}║
║                                                              ║
║  📷 Scan QR code:                                            ║
║     http://{local_ip}:{args.port}/qr{' ' * (33 - len(local_ip) - len(str(args.port)))}║
║                                                              ║
╠══════════════════════════════════════════════════════════════╣
║  Windows: Use COMx port (check Device Manager)               ║
║  Linux:   Use /dev/rfcomm0 (run setup_bluetooth.sh first)    ║
║  WiFi:    Use 192.168.0.10:35000                             ║
╚══════════════════════════════════════════════════════════════╝
""")
    
    uvicorn.run(app, host=args.host, port=args.port)
