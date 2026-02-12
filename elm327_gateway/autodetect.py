"""
Auto-detect OBDLink MX+ and other ELM327 adapters.

Scans available COM ports (Windows) or /dev entries (Linux/Mac),
sends ATZ to each, and identifies ELM327-compatible devices.
"""

import asyncio
import logging
import platform
import re
from dataclasses import dataclass
from typing import List, Optional

logger = logging.getLogger(__name__)


@dataclass
class DetectedAdapter:
    """A detected ELM327 adapter."""
    port: str           # COM4, /dev/rfcomm0, etc.
    name: str           # "OBDLink MX+" or "ELM327 v1.5"
    version: str        # Raw version string from ATZ
    port_type: str      # "bluetooth", "usb", "unknown"


def _guess_port_type(port: str, description: str = "") -> str:
    """Guess the port type from port name and description."""
    desc_lower = (description or "").lower()
    port_lower = port.lower()
    
    if "bluetooth" in desc_lower or "rfcomm" in port_lower:
        return "bluetooth"
    elif "usb" in desc_lower or "ttyusb" in port_lower or "ttyacm" in port_lower:
        return "usb"
    elif "serial" in desc_lower:
        return "serial"
    return "unknown"


def _get_candidate_ports() -> List[dict]:
    """Get list of candidate serial ports to scan."""
    ports = []
    
    try:
        import serial.tools.list_ports
        for p in serial.tools.list_ports.comports():
            ports.append({
                "port": p.device,
                "description": p.description or "",
                "hwid": p.hwid or "",
            })
    except ImportError:
        # Fallback: brute-force common ports
        if platform.system() == "Windows":
            for i in range(1, 21):
                ports.append({"port": f"COM{i}", "description": "", "hwid": ""})
        else:
            import glob
            for pattern in ["/dev/rfcomm*", "/dev/ttyUSB*", "/dev/ttyACM*", "/dev/tty.OBD*"]:
                for path in glob.glob(pattern):
                    ports.append({"port": path, "description": "", "hwid": ""})
    
    return ports


async def _probe_port(port: str, timeout: float = 3.0) -> Optional[DetectedAdapter]:
    """
    Send ATZ to a port and check if it responds like an ELM327.
    
    Returns DetectedAdapter if found, None otherwise.
    """
    try:
        import serial
    except ImportError:
        logger.error("pyserial not installed")
        return None
    
    try:
        ser = serial.Serial(
            port=port,
            baudrate=38400,
            timeout=timeout,
            write_timeout=timeout,
        )
    except (serial.SerialException, OSError, PermissionError) as e:
        logger.debug(f"Cannot open {port}: {e}")
        return None
    
    try:
        # Send ATZ (reset) command
        ser.write(b"ATZ\r")
        await asyncio.sleep(1.5)  # ELM327 takes ~1s to reset
        
        response = b""
        while ser.in_waiting:
            response += ser.read(ser.in_waiting)
            await asyncio.sleep(0.1)
        
        text = response.decode("ascii", errors="ignore").strip()
        logger.debug(f"{port} responded: {text!r}")
        
        # Look for ELM327 or OBDLink in response
        if "ELM327" in text or "ELM329" in text or "OBDLink" in text or "STN" in text:
            # Extract version/name
            name = "ELM327"
            version = text
            
            if "OBDLink" in text:
                match = re.search(r"(OBDLink\s+\w+)", text)
                name = match.group(1) if match else "OBDLink"
            elif "STN" in text:
                name = "STN-based adapter"
            
            version_match = re.search(r"v[\d.]+", text)
            if version_match:
                version = version_match.group(0)
            
            return DetectedAdapter(
                port=port,
                name=name,
                version=version,
                port_type="unknown",  # Will be refined by caller
            )
        
        return None
        
    except Exception as e:
        logger.debug(f"Error probing {port}: {e}")
        return None
    finally:
        try:
            ser.close()
        except:
            pass


async def detect_elm327(timeout_per_port: float = 3.0) -> List[DetectedAdapter]:
    """
    Scan all available ports for ELM327 adapters.
    
    Returns list of detected adapters, sorted by most likely.
    """
    candidates = _get_candidate_ports()
    
    if not candidates:
        logger.info("No candidate ports found")
        return []
    
    logger.info(f"Scanning {len(candidates)} ports for ELM327...")
    
    detected = []
    
    for candidate in candidates:
        port = candidate["port"]
        logger.debug(f"Probing {port}...")
        
        adapter = await _probe_port(port, timeout=timeout_per_port)
        
        if adapter:
            # Refine port type from description
            adapter.port_type = _guess_port_type(port, candidate.get("description", ""))
            detected.append(adapter)
            logger.info(f"Found {adapter.name} on {port} ({adapter.port_type})")
    
    if not detected:
        logger.info("No ELM327 adapters found")
    
    # Sort: bluetooth first (likely OBDLink MX+), then USB, then others
    priority = {"bluetooth": 0, "usb": 1, "serial": 2, "unknown": 3}
    detected.sort(key=lambda a: priority.get(a.port_type, 99))
    
    return detected


async def detect_and_pick() -> Optional[DetectedAdapter]:
    """Detect adapters and return the best one, or None."""
    adapters = await detect_elm327()
    if adapters:
        best = adapters[0]
        logger.info(f"Selected: {best.name} on {best.port}")
        return best
    return None


# CLI entry point for testing
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    async def main():
        print("Scanning for ELM327 adapters...")
        adapters = await detect_elm327()
        
        if adapters:
            print(f"\n[OK] Found {len(adapters)} adapter(s):")
            for a in adapters:
                print(f"  • {a.name} ({a.version}) on {a.port} [{a.port_type}]")
        else:
            print("\n[ERR] No adapters found")
            print("Make sure:")
            print("  - OBDLink MX+ is plugged into the car")
            print("  - Ignition is ON")
            print("  - Bluetooth is paired in Windows settings")
    
    asyncio.run(main())
