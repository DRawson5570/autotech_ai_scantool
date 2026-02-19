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


# Standard CAN OBD-II ECU address pairs (ISO 15765-4)
# Response addr → {request addr, name, description}
ECU_ADDRESSES = {
    0x7E8: {"request": 0x7E0, "name": "PCM", "description": "Powertrain Control Module"},
    0x7E9: {"request": 0x7E1, "name": "TCM", "description": "Transmission Control Module"},
    0x7EA: {"request": 0x7E2, "name": "ABS", "description": "Anti-lock Brake System"},
    0x7EB: {"request": 0x7E3, "name": "SRS", "description": "Supplemental Restraint System (Airbag)"},
    0x7EC: {"request": 0x7E4, "name": "BCM", "description": "Body Control Module"},
    0x7ED: {"request": 0x7E5, "name": "HVAC", "description": "Climate Control Module"},
    0x7EE: {"request": 0x7E6, "name": "ECU6", "description": "Module 6"},
    0x7EF: {"request": 0x7E7, "name": "ECU7", "description": "Module 7"},
}

# Ford MS-CAN module addresses (Medium Speed CAN, 125 kbps, pins 3+11)
# These modules are NOT on the standard HS-CAN OBD-II bus.
# Response addr → {request addr, name, description}
FORD_MS_CAN_ADDRESSES = {
    0x728: {"request": 0x720, "name": "PCM-MS", "description": "Powertrain Control Module (MS-CAN mirror)"},
    0x729: {"request": 0x721, "name": "TCM", "description": "Transmission Control Module"},
    0x72E: {"request": 0x726, "name": "APIM", "description": "Accessory Protocol Interface Module"},
    0x72F: {"request": 0x727, "name": "ACM", "description": "Audio Control Module"},
    0x739: {"request": 0x731, "name": "FCDIM", "description": "Front Camera Display Interface Module"},
    0x73B: {"request": 0x733, "name": "IPMA", "description": "Image Processing Module A"},
    0x748: {"request": 0x740, "name": "IPC", "description": "Instrument Panel Cluster"},
    0x74E: {"request": 0x746, "name": "SCCM", "description": "Steering Column Control Module"},
    0x758: {"request": 0x750, "name": "PAM", "description": "Parking Aid Module"},
    0x768: {"request": 0x760, "name": "GEM", "description": "Generic Electronic Module (BCM)"},
    0x76C: {"request": 0x764, "name": "RCM", "description": "Restraints Control Module (Airbag)"},
    0x76D: {"request": 0x765, "name": "ABS", "description": "Anti-lock Braking System"},
    0x7A8: {"request": 0x7A0, "name": "HVAC", "description": "HVAC Control Module"},
    0x7B8: {"request": 0x7B0, "name": "TPMS", "description": "Tire Pressure Monitoring System"},
    0x7C8: {"request": 0x7C0, "name": "PSCM", "description": "Power Steering Control Module"},
    0x7CC: {"request": 0x7C4, "name": "DDM", "description": "Driver Door Module"},
    0x7CD: {"request": 0x7C5, "name": "PDM", "description": "Passenger Door Module"},
    0x7D8: {"request": 0x7D0, "name": "AWD", "description": "All-Wheel Drive Module"},
}


# Standard UDS DIDs (Data Identifiers) for module identification
STANDARD_DIDS = {
    0xF187: "Part Number",
    0xF188: "ECU Software Number",
    0xF189: "Software Version",
    0xF18C: "ECU Serial Number",
    0xF190: "VIN",
    0xF191: "ECU Hardware Number",
    0xF1A0: "Supplier ID",
}


@dataclass
class ECUModule:
    """Represents a discovered ECU module on the CAN bus."""
    response_addr: int          # e.g. 0x7E8
    request_addr: int           # e.g. 0x7E0
    name: str                   # e.g. "PCM"
    description: str            # e.g. "Powertrain Control Module"
    supported_pids: List[int] = field(default_factory=list)
    pid_names: List[str] = field(default_factory=list)
    bus: str = "HS-CAN"         # "HS-CAN" (500 kbps) or "MS-CAN" (125 kbps)
    module_info: Dict[str, str] = field(default_factory=dict)  # UDS DID data


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
        Read stored DTCs from ALL ECUs (PCM, BCM, TCM, etc.).
        
        Temporarily enables CAN headers to distinguish responses
        from different modules on the bus.
        
        Returns:
            List of DTC objects
        """
        return await self._read_dtcs_all_modules("03", "stored")
    
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
        Read pending DTCs (current drive cycle) from ALL ECUs.
        
        Returns:
            List of DTC objects
        """
        return await self._read_dtcs_all_modules("07", "pending")
    
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
        response = await self.connection.send_command("0902", timeout=5.0)
        logger.info(f"VIN raw response: {repr(response)}")
        
        if not response or "NO DATA" in response or "ERROR" in response:
            return None
        
        # VIN response: 49 02 01 XX XX XX XX ... (multi-frame)
        # Need to extract ASCII characters
        data = self._parse_multiframe_response(response)
        logger.info(f"VIN parsed bytes ({len(data)}): {[hex(b) for b in data[:20]]}")
        if data and len(data) >= 17:
            # First byte is message count, skip it
            vin_bytes = data[1:18] if len(data) > 17 else data[:17]
            vin = ''.join(chr(b) for b in vin_bytes if 32 <= b <= 126)
            logger.info(f"VIN extracted: {vin} (len={len(vin)})")
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
        Read permanent DTCs (survive clear) from ALL ECUs.
        
        Returns:
            List of DTC objects
        """
        return await self._read_dtcs_all_modules("0A", "permanent")
    
    # -------------------------------------------------------------------------
    # Module Discovery & Per-Module PID Enumeration
    # -------------------------------------------------------------------------
    
    async def discover_modules(self) -> List[ECUModule]:
        """
        Discover all ECU modules on the CAN bus by probing each of the
        8 standard OBD-II addresses individually.
        
        Strategy:
        1. Probe each address 7E0-7E7 with UDS TesterPresent (3E 00)
           — works for ABS, SRS, BCM, HVAC, etc. that don't support Mode 01
        2. Also try Mode 01 PID 00 (0100) for OBD-II emission modules
        3. Any address that responds to either is a live module
        
        Returns:
            List of ECUModule objects for each responding module
        """
        modules = []
        seen_addrs = set()
        
        try:
            # Enable headers so we can confirm response source
            await self.connection.send_command("ATH1")
            await self.connection.send_command("ATS1")
            
            # Set timeout high for slow modules (ATSTFF = 255 * 4ms ≈ 1s)
            try:
                await self.connection.send_command("ATSTFF")
            except Exception:
                try:
                    await self.connection.send_command("AT ST FF")
                except Exception:
                    logger.debug("Could not set extended timeout")
            
            # --- Phase 1: Broadcast Mode 01 PID 00 ---
            # Fast: catches all emission-related modules (PCM, sometimes TCM)
            response = await self.connection.send_command("0100", timeout=5.0)
            logger.info(f"Module discovery broadcast response: {repr(response)}")
            
            if response and "NO DATA" not in response.upper() and "ERROR" not in response.upper():
                self._parse_module_response(response, seen_addrs, modules)
            
            # --- Phase 2: Probe each address individually ---
            # Catches non-emission modules (ABS, SRS, BCM, HVAC, etc.)
            # Uses multiple UDS services since not all modules support all services
            logger.info(f"Phase 2: Probing addresses 7E0-7E7 individually (skipping {[f'{a:03X}' for a in seen_addrs]})")
            
            for req_addr in range(0x7E0, 0x7E8):
                resp_addr = req_addr + 8  # 7E0→7E8, 7E1→7E9, etc.
                if resp_addr in seen_addrs:
                    logger.info(f"  {req_addr:03X}: skipping (already found)")
                    continue
                
                try:
                    # Target this specific address
                    sh_resp = await self.connection.send_command(f"ATSH{req_addr:03X}")
                    logger.info(f"  ATSH{req_addr:03X} -> {repr(sh_resp)}")
                    
                    # Also set CAN receive address filter to match expected response
                    cra_resp = await self.connection.send_command(f"ATCRA{resp_addr:03X}")
                    logger.info(f"  ATCRA{resp_addr:03X} -> {repr(cra_resp)}")
                    
                    found = False
                    
                    # --- Try 1: UDS TesterPresent (3E 00) ---
                    tp_response = await self.connection.send_command("3E00", timeout=3.0)
                    logger.info(f"  {req_addr:03X} TesterPresent(3E00) -> {repr(tp_response)}")
                    
                    if self._is_live_response(tp_response):
                        found = True
                        logger.info(f"  {req_addr:03X}: ALIVE via TesterPresent")
                    
                    # --- Try 2: UDS DiagnosticSessionControl (10 01) ---
                    if not found:
                        dsc_response = await self.connection.send_command("1001", timeout=3.0)
                        logger.info(f"  {req_addr:03X} DiagSessionCtrl(1001) -> {repr(dsc_response)}")
                        
                        if self._is_live_response(dsc_response):
                            found = True
                            logger.info(f"  {req_addr:03X}: ALIVE via DiagSessionControl")
                    
                    # --- Try 3: Mode 01 PID 00 targeted ---
                    if not found:
                        obd_response = await self.connection.send_command("0100", timeout=3.0)
                        logger.info(f"  {req_addr:03X} Mode01PID00(0100) -> {repr(obd_response)}")
                        
                        if self._is_live_response(obd_response):
                            found = True
                            logger.info(f"  {req_addr:03X}: ALIVE via targeted Mode 01")
                    
                    if found:
                        info = ECU_ADDRESSES.get(resp_addr, {
                            "request": req_addr,
                            "name": f"ECU-{resp_addr:03X}",
                            "description": f"Module at {resp_addr:03X}"
                        })
                        module = ECUModule(
                            response_addr=resp_addr,
                            request_addr=req_addr,
                            name=info["name"],
                            description=info["description"],
                        )
                        modules.append(module)
                        seen_addrs.add(resp_addr)
                        logger.info(f"  >>> Discovered: {info['name']} ({resp_addr:03X})")
                    else:
                        logger.info(f"  {req_addr:03X}: no response")
                    
                except Exception as e:
                    logger.info(f"  {req_addr:03X}: exception: {e}")
            
            # Reset CAN receive filter
            try:
                await self.connection.send_command("ATCRA")
            except Exception:
                pass
            
            # --- Phase 3: Probe MS-CAN (125 kbps) for body/comfort modules ---
            # Ford (and some other makes) put non-emission modules on a second,
            # slower CAN bus accessible via OBD-II pins 3+11.
            # OBDLink MX+ (STN2255) needs CAN channel 2 selection via STPBR/STPC
            # or ATPB with channel bit set (bit 5 of config byte).
            logger.info("Phase 3: Switching to MS-CAN (125 kbps, pins 3+11)...")
            
            ms_can_ok = False
            stn_device = False
            try:
                # --- Step 0: Identify the device ---
                ati_resp = await self.connection.send_command("ATI")
                logger.info(f"  ATI (device ID) -> {repr(ati_resp)}")
                
                sti_resp = await self.connection.send_command("STI")
                logger.info(f"  STI (STN device ID) -> {repr(sti_resp)}")
                
                stdi_resp = await self.connection.send_command("STDI")
                logger.info(f"  STDI (STN description) -> {repr(stdi_resp)}")
                
                # Check if this is an STN device
                if sti_resp and "?" not in sti_resp and "STN" in sti_resp.upper():
                    stn_device = True
                    logger.info(f"  Confirmed STN device: {sti_resp}")
                
                # --- Step 1: Try STN-specific MS-CAN switching methods ---
                if stn_device:
                    # STP33 is the proven working command on STN2255 (OBDLink MX+)
                    # It selects Ford MS-CAN (125 kbps, pins 3+11) directly
                    stn_methods = [
                        ("STP33", "STN Ford MS-CAN protocol"),
                        ("STPC2", "STN CAN channel 2"),
                        ("STCANSW 1", "STN CAN switch"),
                        ("STCSWM 2", "STN CAN switch mode"),
                        ("STPBR 125000", "STN baud rate 125k"),
                    ]
                    for cmd, desc in stn_methods:
                        resp = await self.connection.send_command(cmd)
                        logger.info(f"  {cmd} -> {repr(resp)}")
                        if resp and "?" not in resp:
                            ms_can_ok = True
                            logger.info(f"  MS-CAN via {desc}: {cmd}")
                            break
                
                # --- Step 2: Configure Protocol B for 125 kbps ---
                if not ms_can_ok:
                    # ATPB E0 04: E0 = ISO 15765-4 + 11-bit + CAN channel 2 (bit 5)
                    # This tells STN devices to use the secondary CAN transceiver
                    pb_resp = await self.connection.send_command("ATPBE004")
                    logger.info(f"  ATPB E0 04 (channel 2) -> {repr(pb_resp)}")
                    
                    if pb_resp and "?" not in pb_resp:
                        sp_resp = await self.connection.send_command("ATSPB")
                        logger.info(f"  AT SP B -> {repr(sp_resp)}")
                        if sp_resp and "?" not in sp_resp:
                            ms_can_ok = True
                            logger.info("  MS-CAN via ATPB E004 (channel 2)")
                    
                    # Fallback: C0 04 (channel 1 — won't work for MS-CAN on STN but
                    # might work on some generic adapters with pin 3+11 wired)
                    if not ms_can_ok:
                        pb_resp2 = await self.connection.send_command("ATPBC004")
                        logger.info(f"  ATPB C0 04 (channel 1 fallback) -> {repr(pb_resp2)}")
                        if pb_resp2 and "?" not in pb_resp2:
                            sp_resp2 = await self.connection.send_command("ATSPB")
                            logger.info(f"  AT SP B -> {repr(sp_resp2)}")
                            if sp_resp2 and "?" not in sp_resp2:
                                ms_can_ok = True
                                logger.info("  MS-CAN via ATPB C004 (channel 1 fallback)")
                
                if ms_can_ok:
                    # Enable headers for address identification
                    await self.connection.send_command("ATH1")
                    await self.connection.send_command("ATS1")
                    
                    # Set extended timeout for MS-CAN (slower bus)
                    try:
                        await self.connection.send_command("ATSTFF")
                    except Exception:
                        pass
                    
                    ms_can_found = 0
                    for resp_addr, info in FORD_MS_CAN_ADDRESSES.items():
                        req_addr = info["request"]
                        
                        try:
                            # Target this address
                            await self.connection.send_command(f"ATSH{req_addr:03X}")
                            await self.connection.send_command(f"ATCRA{resp_addr:03X}")
                            
                            # Try TesterPresent
                            tp_resp = await self.connection.send_command("3E00", timeout=3.0)
                            logger.info(f"  MS-CAN {req_addr:03X} TesterPresent -> {repr(tp_resp)}")
                            
                            if self._is_live_response(tp_resp):
                                module = ECUModule(
                                    response_addr=resp_addr,
                                    request_addr=req_addr,
                                    name=info["name"],
                                    description=info["description"],
                                    bus="MS-CAN",
                                )
                                modules.append(module)
                                ms_can_found += 1
                                logger.info(f"  >>> MS-CAN Discovered: {info['name']} ({resp_addr:03X})")
                                continue
                            
                            # Try DiagnosticSessionControl
                            dsc_resp = await self.connection.send_command("1001", timeout=3.0)
                            logger.info(f"  MS-CAN {req_addr:03X} DiagSessionCtrl -> {repr(dsc_resp)}")
                            
                            if self._is_live_response(dsc_resp):
                                module = ECUModule(
                                    response_addr=resp_addr,
                                    request_addr=req_addr,
                                    name=info["name"],
                                    description=info["description"],
                                    bus="MS-CAN",
                                )
                                modules.append(module)
                                ms_can_found += 1
                                logger.info(f"  >>> MS-CAN Discovered: {info['name']} ({resp_addr:03X})")
                            
                        except Exception as e:
                            logger.debug(f"  MS-CAN {req_addr:03X}: exception: {e}")
                    
                    logger.info(f"Phase 3 complete: found {ms_can_found} MS-CAN module(s)")
                    
                    # Read UDS DIDs for each discovered MS-CAN module
                    # (must do this while still on MS-CAN bus)
                    for mod in modules:
                        if mod.bus != "MS-CAN":
                            continue
                        try:
                            logger.info(f"  Reading DIDs for {mod.name} ({mod.request_addr:03X})...")
                            await self.connection.send_command(f"ATSH{mod.request_addr:03X}")
                            await self.connection.send_command(f"ATCRA{mod.response_addr:03X}")
                            mod.module_info = await self._read_module_dids(mod)
                            if mod.module_info:
                                logger.info(f"  {mod.name}: {len(mod.module_info)} DID(s) read")
                            else:
                                logger.info(f"  {mod.name}: no DIDs readable")
                        except Exception as e:
                            logger.debug(f"  {mod.name} DID read failed: {e}")
                    
                    # Reset CAN receive filter
                    try:
                        await self.connection.send_command("ATCRA")
                    except Exception:
                        pass
                else:
                    logger.info("Phase 3 skipped: ELM327 does not support user-defined CAN protocols")
                    
            except Exception as e:
                logger.warning(f"MS-CAN probing failed: {e}")
            
        except Exception as e:
            logger.error(f"Module discovery failed: {e}")
        finally:
            # Restore to HS-CAN (Protocol 6) and default settings
            try:
                # Switch CAN transceiver back to HS-CAN (pins 6+14)
                # STP6 resets STN to standard CAN 500k, STPC1 resets channel
                for cmd in ["STP6", "STPC1"]:
                    try:
                        await self.connection.send_command(cmd)
                    except Exception:
                        pass
                await self.connection.send_command("ATSP6")   # Back to ISO 15765-4 CAN 500k
                await self.connection.send_command("ATSH7DF")  # Reset to broadcast
                await self.connection.send_command("ATH0")
                await self.connection.send_command("ATS0")
                await self.connection.send_command("ATST32")   # Reset timeout
            except Exception as e:
                logger.warning(f"Failed to restore AT settings: {e}")
        
        # Sort by response address for consistent ordering
        modules.sort(key=lambda m: m.response_addr)
        return modules
    
    def _parse_module_response(self, response: str, seen_addrs: set, modules: list):
        """Parse a header-on response to extract responding CAN addresses."""
        for line in response.split('\n'):
            line = line.strip()
            if not line:
                continue
            
            parts = line.split()
            if len(parts) < 2:
                continue
            
            addr_str = parts[0].upper()
            if len(addr_str) != 3:
                continue
            try:
                resp_addr = int(addr_str, 16)
            except ValueError:
                continue
            
            if resp_addr < 0x7E8 or resp_addr > 0x7EF:
                continue
            if resp_addr in seen_addrs:
                continue
            
            seen_addrs.add(resp_addr)
            info = ECU_ADDRESSES.get(resp_addr, {
                "request": resp_addr - 8,
                "name": f"ECU-{addr_str}",
                "description": f"Unknown Module ({addr_str})"
            })
            module = ECUModule(
                response_addr=resp_addr,
                request_addr=info["request"],
                name=info["name"],
                description=info["description"],
            )
            modules.append(module)
            logger.info(f"Discovered module via broadcast: {info['name']} ({addr_str})")
    
    @staticmethod
    def _is_live_response(response: str) -> bool:
        """Check if ELM327 response indicates a live module (any non-error response)."""
        if not response:
            return False
        upper = response.upper().strip()
        if not upper:
            return False
        # These indicate NO module responded
        dead_patterns = ["NO DATA", "ERROR", "UNABLE", "CAN ERROR", "BUS", "STOPPED", "?"]
        for pat in dead_patterns:
            if pat in upper:
                return False
        return True
    
    async def _read_module_dids(self, module: 'ECUModule') -> Dict[str, str]:
        """
        Read standard UDS DIDs (Data Identifiers) from a module.
        
        Uses UDS Service 0x22 (ReadDataByIdentifier) to read
        part numbers, software versions, VIN, etc.
        
        IMPORTANT: Caller must have already set ATSH and ATCRA
        for this module, and be on the correct bus.
        
        Args:
            module: The ECUModule to read from
            
        Returns:
            Dict mapping DID name to string value
        """
        info = {}
        
        for did, label in STANDARD_DIDS.items():
            try:
                # UDS Service 0x22: ReadDataByIdentifier
                cmd = f"22{did:04X}"
                resp = await self.connection.send_command(cmd, timeout=3.0)
                
                if not resp or not self._is_live_response(resp):
                    continue
                
                # Positive response: 62 XX XX <data>
                # Strip any CAN header (e.g. "7E8 06 62 F1 90 ..." or "62 F1 90 ...")
                cleaned = resp.replace(' ', '').upper()
                
                # Find "62" + DID in response
                did_hex = f"{did:04X}"
                marker = f"62{did_hex}"
                idx = cleaned.find(marker)
                
                if idx < 0:
                    continue
                
                # Data starts after 62+DID (6 hex chars)
                data_hex = cleaned[idx + len(marker):]
                
                if not data_hex:
                    continue
                
                # Try decoding as ASCII text (most F1xx DIDs are text)
                try:
                    data_bytes = bytes.fromhex(data_hex)
                    # Filter to printable ASCII
                    text = ''.join(
                        chr(b) if 32 <= b < 127 else '' 
                        for b in data_bytes
                    ).strip()
                    if text:
                        info[label] = text
                    else:
                        # Show as hex if not printable
                        info[label] = data_hex
                except ValueError:
                    info[label] = data_hex
                    
                logger.info(f"  DID {did_hex} ({label}): {info.get(label, 'N/A')}")
                
            except Exception as e:
                logger.debug(f"  DID {did:04X} read failed: {e}")
        
        return info

    async def get_module_supported_pids(self, request_addr: int) -> List[int]:
        """
        Enumerate all supported Mode 01 PIDs for a specific ECU module.
        
        Targets the module directly using AT SH (set header) so only
        that module responds, then chains PID-supported bitmap requests.
        
        Args:
            request_addr: CAN request address (e.g. 0x7E0 for PCM)
            
        Returns:
            List of supported PID numbers for this module
        """
        supported = []
        
        try:
            # Target this specific module by setting the transmit header
            await self.connection.send_command(f"ATSH{request_addr:03X}")
            logger.info(f"Targeting module at request addr {request_addr:03X}")
            
            # Chain through PID-supported bitmaps: 0x00, 0x20, 0x40, ...
            for base_pid in [0x00, 0x20, 0x40, 0x60, 0x80, 0xA0, 0xC0, 0xE0]:
                try:
                    response = await self.connection.send_command(
                        f"01{base_pid:02X}", timeout=3.0
                    )
                    if not response or "NO DATA" in response or "ERROR" in response:
                        break
                    
                    # Parse: 41 XX YY YY YY YY
                    data = self._parse_response(response)
                    if data and len(data) >= 4:
                        bitmap = (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3]
                        for i in range(32):
                            if bitmap & (1 << (31 - i)):
                                supported.append(base_pid + i + 1)
                        
                        # If bit 32 (last) not set, no more ranges
                        if not (bitmap & 1):
                            break
                    else:
                        break
                        
                except Exception as e:
                    logger.warning(f"Error checking module {request_addr:03X} PID {base_pid:02X}: {e}")
                    break
            
        except Exception as e:
            logger.error(f"Module PID enumeration failed for {request_addr:03X}: {e}")
        finally:
            # Reset header back to default broadcast (7DF)
            try:
                await self.connection.send_command("ATSH7DF")
            except Exception as e:
                logger.warning(f"Failed to reset AT SH: {e}")
        
        return supported
    
    async def scan_all_modules(self) -> List[ECUModule]:
        """
        Full module scan: discover all ECUs and enumerate each one's
        supported PIDs. For modules that don't support Mode 01, reports
        them as present with UDS-only capability.
        
        Returns:
            List of ECUModule objects with supported_pids populated
        """
        from .pids import PIDRegistry
        
        # Step 1: Discover which modules are on the bus
        modules = await self.discover_modules()
        logger.info(f"Found {len(modules)} module(s), enumerating PIDs...")
        
        # Step 2: For each module, try to get its supported PIDs
        for module in modules:
            pids = await self.get_module_supported_pids(module.request_addr)
            # Filter out bitmap PIDs (0x00, 0x20, 0x40, 0x60, 0x80, 0xA0, 0xC0, 0xE0)
            bitmap_pids = {0x00, 0x20, 0x40, 0x60, 0x80, 0xA0, 0xC0, 0xE0}
            module.supported_pids = [p for p in pids if p not in bitmap_pids]
            
            # Resolve PID names
            for pid in module.supported_pids:
                defn = PIDRegistry.get(pid)
                if defn:
                    module.pid_names.append(defn.name)
                else:
                    module.pid_names.append(f"PID_0x{pid:02X}")
            
            if module.supported_pids:
                logger.info(
                    f"Module {module.name} ({module.request_addr:03X}): "
                    f"{len(module.supported_pids)} Mode 01 PIDs"
                )
            else:
                # Module responds to UDS but not Mode 01 — still valid
                logger.info(
                    f"Module {module.name} ({module.request_addr:03X}): "
                    f"UDS-only (no Mode 01 PIDs)"
                )
                # Read DIDs for HS-CAN UDS-only modules (MS-CAN already done in Phase 3)
                if module.bus == "HS-CAN" and not module.module_info:
                    try:
                        await self.connection.send_command(f"ATSH{module.request_addr:03X}")
                        await self.connection.send_command(f"ATCRA{module.response_addr:03X}")
                        module.module_info = await self._read_module_dids(module)
                        await self.connection.send_command("ATSH7DF")
                        await self.connection.send_command("ATCRA")
                    except Exception as e:
                        logger.debug(f"  {module.name} DID read failed: {e}")
        
        return modules
    
    async def _read_dtcs_all_modules(self, mode: str, status: str) -> List[DTC]:
        """
        Read DTCs with CAN headers enabled to capture responses from all ECUs.
        
        On CAN bus, broadcasting mode 03/07/0A to 7DF gets responses from
        every ECU (PCM=7E8, TCM=7E9, BCM=7EA, etc.). We temporarily enable
        headers to distinguish which module reported each DTC.
        
        Args:
            mode: OBD mode as hex string ("03", "07", "0A")
            status: DTC status label
            
        Returns:
            List of DTC objects
        """
        try:
            # Enable headers and spaces for reliable multi-ECU parsing
            await self.connection.send_command("ATH1")
            await self.connection.send_command("ATS1")
            
            response = await self.connection.send_command(mode)
            logger.info(f"DTC mode {mode} raw response (headers on): {repr(response)}")
            
            return self._parse_dtcs(response, status=status)
        finally:
            # Always restore original settings
            try:
                await self.connection.send_command("ATH0")
                await self.connection.send_command("ATS0")
            except Exception as e:
                logger.warning(f"Failed to restore AT settings: {e}")
    
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
        
        Handles both formats:
        - Standard: "49 02 01 31 34 33 34 ..."
        - CAN ISO-TP: "0:49020131343334\\n1:52444A44..."
        
        Args:
            response: Raw multi-line response
            
        Returns:
            Combined data bytes
        """
        all_bytes = []
        is_first_frame = True
        
        for line in response.split('\n'):
            line = line.strip()
            if not line:
                continue
            
            # Strip CAN ISO-TP frame index prefix (e.g., "0:", "1:", "2:")
            if len(line) > 2 and line[1] == ':' and line[0].isdigit():
                line = line[2:]
            # Also handle "0A:", "0B:" etc for frames > 9
            elif len(line) > 3 and line[2] == ':' and line[:2].isalnum():
                line = line[3:]
            
            # Remove any non-hex characters (spaces, colons, etc.)
            hex_str = ''.join(c for c in line if c in '0123456789ABCDEFabcdef')
            
            if not hex_str:
                continue
            
            # Skip header bytes on first frame (49 02 XX for mode 09 responses)
            if is_first_frame:
                if hex_str.startswith('4902') or hex_str.startswith('4904'):
                    hex_str = hex_str[6:]  # Skip "4902XX" (response + PID + count)
                is_first_frame = False
            
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
        
        Handles two response formats:
        1. With CAN headers (ATH1): "7E8 06 43 01 01 71 00 00"
           - 7E8 = PCM, 7E9 = TCM, 7EA = ABS, 7EB = BCM, etc.
        2. Without headers (ATH0): "43 01 71 00 00"
        
        Also detects phantom DTCs caused by adapters echoing the
        response header as padding bytes.
        
        Args:
            response: Raw DTC response (may have CAN headers)
            status: DTC status (stored, pending, permanent)
            
        Returns:
            List of DTC objects
        """
        dtcs = []
        
        if not response or "NO DATA" in response.upper() or "ERROR" in response.upper():
            return dtcs
        
        # Determine expected response header for the OBD mode
        header_map = {"stored": "43", "pending": "47", "permanent": "4A"}
        expected_header = header_map.get(status, "43").upper()
        
        # CAN ECU address names for logging
        ecu_names = {
            "7E8": "PCM", "7E9": "TCM", "7EA": "ABS",
            "7EB": "BCM", "7EC": "SRS", "7ED": "HVAC",
        }
        
        lines = [l.strip() for l in response.split('\n') if l.strip()]
        
        for line in lines:
            # Check if line has CAN header (3-char hex addr like 7E8)
            parts = line.split()
            ecu_addr = None
            data_str = line
            
            if parts and len(parts[0]) == 3:
                try:
                    int(parts[0], 16)
                    ecu_addr = parts[0].upper()
                    ecu_name = ecu_names.get(ecu_addr, f"ECU-{ecu_addr}")
                    # Data after address; skip length byte if CAN (2nd byte)
                    data_str = ' '.join(parts[1:])
                    logger.debug(f"DTC response from {ecu_name} ({ecu_addr}): {data_str}")
                except ValueError:
                    pass  # Not a CAN header
            
            # Remove spaces and normalize
            cleaned = ''.join(data_str.split()).upper()
            
            # For CAN frames, skip the length byte (first byte after address)
            # CAN: 7E8 06 43 01 01 71 00 00 → cleaned="064301017100 00"
            if ecu_addr and len(cleaned) >= 2:
                try:
                    frame_len = int(cleaned[:2], 16)
                    if 1 <= frame_len <= 7:  # Valid CAN single-frame length
                        cleaned = cleaned[2:]  # Remove length byte
                except ValueError:
                    pass
            
            # Strip the OBD response header (43/47/4A)
            if cleaned.startswith(expected_header):
                cleaned = cleaned[2:]
            else:
                continue  # Not a DTC response line
            
            # Now `cleaned` should be pairs of DTC bytes: "0171 0000" etc.
            # Each DTC is 4 hex characters (2 bytes)
            for i in range(0, len(cleaned) - 3, 4):
                try:
                    dtc_hex = cleaned[i:i+4]
                    if dtc_hex == '0000':
                        continue  # No DTC (padding)
                    
                    # Detect phantom DTC: adapter echoes response header as padding
                    if dtc_hex == f"00{expected_header}":
                        logger.warning(
                            f"Skipping phantom DTC 00{expected_header} "
                            f"(response header echo artifact from adapter)"
                        )
                        continue
                    
                    dtc_code = self._decode_dtc(dtc_hex)
                    if dtc_code:
                        # Include source ECU in description if known
                        dtc_obj = DTC(code=dtc_code, status=status)
                        if ecu_addr:
                            ecu_name = ecu_names.get(ecu_addr, ecu_addr)
                            dtc_obj.description = f"[{ecu_name}]"
                        dtcs.append(dtc_obj)
                        logger.info(f"Parsed DTC: {dtc_code} from {ecu_addr or 'unknown ECU'}")
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
