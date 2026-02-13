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
    python -m elm327_gateway.server --port 8327

iPhone connects to: http://<hostname>.local:8327/ui
"""

import asyncio
import logging
import platform
import socket
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

# Import our ELM327 service

from elm327_gateway.service import ELM327Service
from elm327_gateway.session import get_session, reset_session, DiagnosticSession

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Global ELM327 service instance
_elm: Optional[ELM327Service] = None
_connected_at: Optional[datetime] = None

# mDNS/Bonjour service for auto-discovery
_mdns_service = None


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


# =============================================================================
# FastAPI App
# =============================================================================

# Store the port globally for mDNS
_server_port = 8327

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup/shutdown lifecycle."""
    logger.info("ELM327 Gateway starting...")
    start_mdns_service(_server_port)
    yield
    # Cleanup on shutdown
    global _elm
    stop_mdns_service()
    if _elm and _elm.connected:
        await _elm.disconnect()
        logger.info("Disconnected ELM327 on shutdown")

app = FastAPI(
    title="ELM327 Gateway",
    description="Bluetooth-to-HTTP bridge for ELM327 OBD-II adapters",
    version="1.0.0",
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
        # If already connected to the same address, skip reconnection
        if _elm and _elm.connected:
            vin = _elm.vin
            supported = await _elm.get_supported_pids()
            logger.info(f"Already connected, skipping reconnection (VIN: {vin})")
            return {
                "status": "connected",
                "vin": vin,
                "supported_pids": len(supported),
                "address": req.address
            }
        
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
                "description": dtc.description,
                "severity": dtc.severity
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
+==============================================================+
|                    ELM327 Gateway Server                     |
+==============================================================+
|                                                              |
|  iPhone/iPad (Bonjour auto-discovery):                       |
|     http://{hostname}.local:{args.port}/ui{' ' * (27 - len(hostname) - len(str(args.port)))}|
|                                                              |
|  Any device (direct IP):                                     |
|     http://{local_ip}:{args.port}/ui{' ' * (33 - len(local_ip) - len(str(args.port)))}|
|                                                              |
|  Scan QR code:                                               |
|     http://{local_ip}:{args.port}/qr{' ' * (33 - len(local_ip) - len(str(args.port)))}|
|                                                              |
+==============================================================+
|  Windows: Use COMx port (check Device Manager)               |
|  Linux:   Use /dev/rfcomm0 (run setup_bluetooth.sh first)    |
|  WiFi:    Use 192.168.0.10:35000                             |
+==============================================================+
""")
    
    uvicorn.run(app, host=args.host, port=args.port)
