"""
OBD-II Protocol Implementation

Handles OBD-II modes and message parsing for ELM327 communication.

OBD-II Modes:
    Mode 01: Show current data (live PIDs)
    Mode 02: Show freeze frame data
    Mode 03: Show stored DTCs
    Mode 04: Clear DTCs and freeze frame
    Mode 05: Test results, oxygen sensor monitoring
    Mode 06: Test results, other component monitoring
    Mode 07: Show pending DTCs (current drive cycle)
    Mode 08: Control on-board system, test, or component
    Mode 09: Request vehicle information (VIN, calibration IDs)
    Mode 0A: Permanent DTCs (survived clear)
"""

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class OBDMode(Enum):
    """OBD-II service modes."""
    CURRENT_DATA = 0x01
    FREEZE_FRAME = 0x02
    STORED_DTCS = 0x03
    CLEAR_DTCS = 0x04
    O2_MONITORING = 0x05
    OTHER_MONITORING = 0x06
    PENDING_DTCS = 0x07
    CONTROL_OPERATION = 0x08
    VEHICLE_INFO = 0x09
    PERMANENT_DTCS = 0x0A


class DTCType(Enum):
    """DTC category types."""
    POWERTRAIN = "P"  # P0xxx, P1xxx, P2xxx, P3xxx
    CHASSIS = "C"     # C0xxx, C1xxx, C2xxx, C3xxx
    BODY = "B"        # B0xxx, B1xxx, B2xxx, B3xxx
    NETWORK = "U"     # U0xxx, U1xxx, U2xxx, U3xxx


@dataclass
class DTC:
    """Diagnostic Trouble Code."""
    code: str  # e.g., "P0171"
    status: str = "stored"  # stored, pending, permanent
    description: str = ""
    
    @property
    def type(self) -> DTCType:
        """Get DTC type from code prefix."""
        prefix = self.code[0].upper()
        return DTCType(prefix)
    
    @property
    def is_manufacturer_specific(self) -> bool:
        """Check if DTC is manufacturer-specific (P1xxx, etc.)."""
        if len(self.code) >= 2:
            return self.code[1] in ('1', '3')
        return False


@dataclass
class FreezeFrame:
    """Freeze frame data captured at time of DTC."""
    dtc: str
    data: Dict[str, float] = field(default_factory=dict)


class OBDProtocol:
    """OBD-II protocol handler for ELM327."""
    
    def __init__(self, connection):
        """
        Initialize protocol handler.
        
        Args:
            connection: ELM327Connection instance
        """
        self.connection = connection
        self._supported_pids: Dict[int, List[int]] = {}  # mode -> list of PIDs
    
    # -------------------------------------------------------------------------
    # Mode 01: Current Data (Live PIDs)
    # -------------------------------------------------------------------------
    
    async def get_supported_pids(self) -> List[int]:
        """
        Get list of supported PIDs for Mode 01.
        
        Returns:
            List of supported PID numbers
        """
        supported = []
        
        # PIDs 00, 20, 40, 60, 80, A0, C0, E0 report which PIDs are supported
        for base_pid in [0x00, 0x20, 0x40, 0x60, 0x80, 0xA0, 0xC0, 0xE0]:
            try:
                response = await self.connection.send_command(f"01{base_pid:02X}")
                if "NO DATA" in response or "ERROR" in response:
                    break
                
                # Parse response: 41 XX YY YY YY YY
                data = self._parse_response(response)
                if data and len(data) >= 4:
                    # Each bit represents a PID
                    bitmap = (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3]
                    for i in range(32):
                        if bitmap & (1 << (31 - i)):
                            supported.append(base_pid + i + 1)
                    
                    # If bit 32 not set, no more PIDs to check
                    if not (bitmap & 1):
                        break
                else:
                    break
                    
            except Exception as e:
                logger.warning(f"Error checking PID {base_pid:02X}: {e}")
                break
        
        self._supported_pids[0x01] = supported
        return supported
    
    async def read_pid(self, pid: int) -> Optional[bytes]:
        """
        Read a single PID value.
        
        Args:
            pid: PID number (0x00-0xFF)
            
        Returns:
            Raw response bytes or None if failed
        """
        response = await self.connection.send_command(f"01{pid:02X}")
        
        if "NO DATA" in response or "ERROR" in response:
            return None
        
        data = self._parse_response(response)
        return bytes(data) if data else None
    
    async def read_pids(self, pids: List[int]) -> Dict[int, bytes]:
        """
        Read multiple PIDs.
        
        Args:
            pids: List of PID numbers
            
        Returns:
            Dict mapping PID to raw response bytes
        """
        results = {}
        for pid in pids:
            data = await self.read_pid(pid)
            if data:
                results[pid] = data
        return results
    
    # -------------------------------------------------------------------------
    # Mode 02: Freeze Frame Data
    # -------------------------------------------------------------------------
    
    async def read_freeze_frame(self, frame: int = 0) -> Dict[int, bytes]:
        """
        Read freeze frame data.
        
        Args:
            frame: Frame number (usually 0)
            
        Returns:
            Dict mapping PID to freeze frame data
        """
        results = {}
        
        # Common PIDs to read from freeze frame
        pids = [0x02, 0x04, 0x05, 0x06, 0x07, 0x0C, 0x0D, 0x0E, 0x0F, 0x11]
        
        for pid in pids:
            try:
                response = await self.connection.send_command(f"02{pid:02X}{frame:02X}")
                if "NO DATA" not in response and "ERROR" not in response:
                    data = self._parse_response(response)
                    if data:
                        results[pid] = bytes(data)
            except Exception as e:
                logger.debug(f"Freeze frame PID {pid:02X} not available: {e}")
        
        return results
    
    # -------------------------------------------------------------------------
    # Mode 03: Stored DTCs
    # -------------------------------------------------------------------------
    
    async def read_dtcs(self) -> List[DTC]:
        """
        Read stored DTCs.
        
        Returns:
            List of DTC objects
        """
        response = await self.connection.send_command("03")
        return self._parse_dtcs(response, status="stored")
    
    # -------------------------------------------------------------------------
    # Mode 04: Clear DTCs
    # -------------------------------------------------------------------------
    
    async def clear_dtcs(self) -> bool:
        """
        Clear stored DTCs and freeze frame.
        
        Returns:
            True if successful
        """
        response = await self.connection.send_command("04")
        # Response should be 44 for success
        return "44" in response or "OK" in response.upper()
    
    # -------------------------------------------------------------------------
    # Mode 07: Pending DTCs
    # -------------------------------------------------------------------------
    
    async def read_pending_dtcs(self) -> List[DTC]:
        """
        Read pending DTCs (current drive cycle).
        
        Returns:
            List of DTC objects
        """
        response = await self.connection.send_command("07")
        return self._parse_dtcs(response, status="pending")
    
    # -------------------------------------------------------------------------
    # Mode 08: Control Operations (Actuator Tests)
    # -------------------------------------------------------------------------
    
    async def control_test(self, tid: int, data: bytes = b'') -> bool:
        """
        Execute Mode 08 control operation.
        
        Args:
            tid: Test ID
            data: Optional test data
            
        Returns:
            True if successful
        """
        cmd = f"08{tid:02X}"
        if data:
            cmd += data.hex().upper()
        
        response = await self.connection.send_command(cmd)
        return "48" in response  # 48 = positive response for mode 08
    
    # -------------------------------------------------------------------------
    # Mode 09: Vehicle Information
    # -------------------------------------------------------------------------
    
    async def read_vin(self) -> Optional[str]:
        """
        Read Vehicle Identification Number.
        
        Returns:
            17-character VIN string or None
        """
        # Request VIN (InfoType 02)
        response = await self.connection.send_command("0902")
        
        if "NO DATA" in response or "ERROR" in response:
            return None
        
        # VIN response: 49 02 01 XX XX XX XX ... (multi-frame)
        # Need to extract ASCII characters
        data = self._parse_multiframe_response(response)
        if data and len(data) >= 17:
            # First byte is message count, skip it
            vin_bytes = data[1:18] if len(data) > 17 else data[:17]
            vin = ''.join(chr(b) for b in vin_bytes if 32 <= b <= 126)
            return vin if len(vin) == 17 else None
        
        return None
    
    async def read_calibration_id(self) -> Optional[str]:
        """Read ECU calibration ID."""
        response = await self.connection.send_command("0904")
        
        if "NO DATA" in response or "ERROR" in response:
            return None
        
        data = self._parse_multiframe_response(response)
        if data:
            cal_id = ''.join(chr(b) for b in data if 32 <= b <= 126)
            return cal_id.strip() if cal_id else None
        
        return None
    
    # -------------------------------------------------------------------------
    # Mode 0A: Permanent DTCs
    # -------------------------------------------------------------------------
    
    async def read_permanent_dtcs(self) -> List[DTC]:
        """
        Read permanent DTCs (survive clear).
        
        Returns:
            List of DTC objects
        """
        response = await self.connection.send_command("0A")
        return self._parse_dtcs(response, status="permanent")
    
    # -------------------------------------------------------------------------
    # Helper Methods
    # -------------------------------------------------------------------------
    
    def _parse_response(self, response: str) -> List[int]:
        """
        Parse OBD response hex bytes.
        
        Args:
            response: Raw response string
            
        Returns:
            List of byte values
        """
        # Remove whitespace and newlines
        cleaned = ''.join(response.split())
        
        # Remove response header (41, 43, 47, 49, 4A for modes 1,3,7,9,A)
        # Response format: 4X YY DD DD DD ...
        if len(cleaned) >= 4:
            # Skip mode byte and PID byte
            hex_data = cleaned[4:]  # Skip "41XX" or similar
        else:
            hex_data = cleaned
        
        # Convert hex pairs to bytes
        bytes_list = []
        for i in range(0, len(hex_data), 2):
            try:
                bytes_list.append(int(hex_data[i:i+2], 16))
            except ValueError:
                break
        
        return bytes_list
    
    def _parse_multiframe_response(self, response: str) -> List[int]:
        """
        Parse multi-frame OBD response (like VIN).
        
        Args:
            response: Raw multi-line response
            
        Returns:
            Combined data bytes
        """
        all_bytes = []
        
        for line in response.split('\n'):
            line = line.strip()
            if not line:
                continue
            
            # Remove any non-hex characters
            hex_str = ''.join(c for c in line if c in '0123456789ABCDEFabcdef')
            
            # Skip header bytes (49 02 XX for mode 09 responses)
            if hex_str.startswith('4902') or hex_str.startswith('4904'):
                hex_str = hex_str[6:]  # Skip "4902XX"
            
            # Convert to bytes
            for i in range(0, len(hex_str), 2):
                try:
                    all_bytes.append(int(hex_str[i:i+2], 16))
                except ValueError:
                    pass
        
        return all_bytes
    
    def _parse_dtcs(self, response: str, status: str = "stored") -> List[DTC]:
        """
        Parse DTC response into DTC objects.
        
        Args:
            response: Raw DTC response
            status: DTC status (stored, pending, permanent)
            
        Returns:
            List of DTC objects
        """
        dtcs = []
        
        # Clean response
        cleaned = ''.join(response.split())
        
        # Remove response header (43 for mode 03, 47 for mode 07, 4A for mode 0A)
        if cleaned.startswith('43') or cleaned.startswith('47') or cleaned.startswith('4A'):
            cleaned = cleaned[2:]
        
        # Each DTC is 4 hex characters (2 bytes)
        # Format: First nibble = type + first digit, remaining = rest of code
        # 0xxx = P0xxx, 4xxx = C0xxx, 8xxx = B0xxx, Cxxx = U0xxx
        
        for i in range(0, len(cleaned) - 3, 4):
            try:
                dtc_hex = cleaned[i:i+4]
                if dtc_hex == '0000':
                    continue  # No DTC
                
                dtc_code = self._decode_dtc(dtc_hex)
                if dtc_code:
                    dtcs.append(DTC(code=dtc_code, status=status))
            except Exception as e:
                logger.debug(f"Error parsing DTC at position {i}: {e}")
        
        return dtcs
    
    def _decode_dtc(self, hex_code: str) -> Optional[str]:
        """
        Decode 4-character hex DTC to standard format.
        
        Args:
            hex_code: 4 hex characters (e.g., "0171")
            
        Returns:
            DTC string (e.g., "P0171")
        """
        if len(hex_code) != 4:
            return None
        
        try:
            first_byte = int(hex_code[0], 16)
            
            # First nibble determines type and first digit
            # 0-3 = P, 4-7 = C, 8-B = B, C-F = U
            type_map = {
                0: 'P0', 1: 'P1', 2: 'P2', 3: 'P3',
                4: 'C0', 5: 'C1', 6: 'C2', 7: 'C3',
                8: 'B0', 9: 'B1', 10: 'B2', 11: 'B3',
                12: 'U0', 13: 'U1', 14: 'U2', 15: 'U3',
            }
            
            prefix = type_map.get(first_byte, 'P0')
            suffix = hex_code[1:4].upper()
            
            return f"{prefix}{suffix}"
            
        except Exception:
            return None


# DTC description database (common codes)
DTC_DESCRIPTIONS = {
    # Fuel system
    "P0171": "System Too Lean (Bank 1)",
    "P0172": "System Too Rich (Bank 1)",
    "P0174": "System Too Lean (Bank 2)",
    "P0175": "System Too Rich (Bank 2)",
    
    # Misfire
    "P0300": "Random/Multiple Cylinder Misfire Detected",
    "P0301": "Cylinder 1 Misfire Detected",
    "P0302": "Cylinder 2 Misfire Detected",
    "P0303": "Cylinder 3 Misfire Detected",
    "P0304": "Cylinder 4 Misfire Detected",
    "P0305": "Cylinder 5 Misfire Detected",
    "P0306": "Cylinder 6 Misfire Detected",
    "P0307": "Cylinder 7 Misfire Detected",
    "P0308": "Cylinder 8 Misfire Detected",
    
    # O2 sensors
    "P0130": "O2 Sensor Circuit (Bank 1, Sensor 1)",
    "P0131": "O2 Sensor Circuit Low Voltage (Bank 1, Sensor 1)",
    "P0132": "O2 Sensor Circuit High Voltage (Bank 1, Sensor 1)",
    "P0133": "O2 Sensor Circuit Slow Response (Bank 1, Sensor 1)",
    "P0134": "O2 Sensor Circuit No Activity (Bank 1, Sensor 1)",
    "P0135": "O2 Sensor Heater Circuit (Bank 1, Sensor 1)",
    
    # Cooling
    "P0115": "Engine Coolant Temperature Circuit",
    "P0116": "Engine Coolant Temperature Circuit Range/Performance",
    "P0117": "Engine Coolant Temperature Circuit Low",
    "P0118": "Engine Coolant Temperature Circuit High",
    "P0125": "Insufficient Coolant Temperature for Closed Loop",
    "P0128": "Coolant Thermostat (Coolant Temperature Below Thermostat Regulating Temperature)",
    
    # Catalyst
    "P0420": "Catalyst System Efficiency Below Threshold (Bank 1)",
    "P0430": "Catalyst System Efficiency Below Threshold (Bank 2)",
    
    # EVAP
    "P0440": "Evaporative Emission System Malfunction",
    "P0441": "Evaporative Emission System Incorrect Purge Flow",
    "P0442": "Evaporative Emission System Leak Detected (Small Leak)",
    "P0443": "Evaporative Emission System Purge Control Valve Circuit",
    "P0446": "Evaporative Emission System Vent Control Circuit",
    "P0455": "Evaporative Emission System Leak Detected (Large Leak)",
    
    # MAF/MAP
    "P0100": "Mass or Volume Air Flow Circuit",
    "P0101": "Mass or Volume Air Flow Circuit Range/Performance",
    "P0102": "Mass or Volume Air Flow Circuit Low",
    "P0103": "Mass or Volume Air Flow Circuit High",
    "P0105": "Manifold Absolute Pressure/Barometric Pressure Circuit",
    "P0106": "Manifold Absolute Pressure/Barometric Pressure Circuit Range/Performance",
    "P0107": "Manifold Absolute Pressure/Barometric Pressure Circuit Low",
    "P0108": "Manifold Absolute Pressure/Barometric Pressure Circuit High",
    
    # Throttle
    "P0120": "Throttle/Pedal Position Sensor/Switch A Circuit",
    "P0121": "Throttle/Pedal Position Sensor/Switch A Circuit Range/Performance",
    "P0122": "Throttle/Pedal Position Sensor/Switch A Circuit Low",
    "P0123": "Throttle/Pedal Position Sensor/Switch A Circuit High",
    
    # Camshaft/Crankshaft
    "P0335": "Crankshaft Position Sensor A Circuit",
    "P0336": "Crankshaft Position Sensor A Circuit Range/Performance",
    "P0340": "Camshaft Position Sensor A Circuit (Bank 1 or Single Sensor)",
    "P0341": "Camshaft Position Sensor A Circuit Range/Performance (Bank 1)",
    
    # VVT
    "P0010": "Camshaft Position Actuator Circuit (Bank 1)",
    "P0011": "Camshaft Position - Timing Over-Advanced (Bank 1)",
    "P0012": "Camshaft Position - Timing Over-Retarded (Bank 1)",
    
    # Transmission
    "P0700": "Transmission Control System Malfunction",
    "P0715": "Input/Turbine Speed Sensor Circuit",
    "P0720": "Output Speed Sensor Circuit",
    "P0730": "Incorrect Gear Ratio",
    "P0740": "Torque Converter Clutch Circuit Malfunction",
    "P0750": "Shift Solenoid A",
    "P0755": "Shift Solenoid B",
}


def get_dtc_description(dtc_code: str) -> str:
    """Get description for a DTC code."""
    return DTC_DESCRIPTIONS.get(dtc_code.upper(), "Unknown DTC")
