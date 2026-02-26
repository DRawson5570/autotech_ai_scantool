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


# Standard UDS DIDs (Data Identifiers) — ISO 14229-1:2020  §C.1
# Range 0xF180-0xF19F: Standardized identification DIDs
# These are universally readable from any UDS-compliant ECU (service 0x22)
STANDARD_DIDS = {
    # --- Boot / Application Software Identification ---
    0xF180: "Boot Software ID",
    0xF181: "Application Software ID",
    0xF182: "Application Data ID",
    # --- Fingerprints (who last flashed what) ---
    0xF183: "Boot Software Fingerprint",
    0xF184: "Application Software Fingerprint",
    0xF185: "Application Data Fingerprint",
    # --- Active Session ---
    0xF186: "Active Diagnostic Session",
    # --- Vehicle Manufacturer IDs ---
    0xF187: "Part Number",
    0xF188: "ECU Software Number",
    0xF189: "Software Version",
    0xF18A: "System Supplier ID",
    0xF18B: "ECU Manufacturing Date",
    0xF18C: "ECU Serial Number",
    0xF18D: "Supported Functional Units",
    0xF18E: "Kit Assembly Part Number",
    0xF18F: "Regulation Software ID Numbers",
    # --- Vehicle / Hardware IDs ---
    0xF190: "VIN",
    0xF191: "ECU Hardware Number",
    0xF192: "Supplier HW Number",
    0xF193: "Supplier HW Version",
    0xF194: "Supplier SW Number",
    0xF195: "Supplier SW Version",
    0xF196: "Exhaust Regulation Number",
    0xF197: "System Name / Engine Type",
    # --- Programming / Calibration History ---
    0xF198: "Repair Shop Code",
    0xF199: "Programming Date",
    0xF19A: "Calibration Shop Code",
    0xF19B: "Calibration Date",
    0xF19C: "Calibration Equipment SW Number",
    0xF19D: "ECU Installation Date",
    0xF19E: "ODX File Reference",
    0xF19F: "Entity Data ID",
    # --- UDS Protocol ---
    0xFF00: "UDS Version",
}

# Ford-specific identification DIDs
# Ford ECUs (especially MS-CAN modules like APIM, GEM, ABS) often DON'T
# respond to the F1xx standard identification DIDs. Instead, Ford uses
# manufacturer-specific DID ranges for identification and diagnostics.
# These are well-known from FORScan and empirical testing.
FORD_IDENTIFICATION_DIDS = {
    # --- Diagnostic Data (DDxx) — most commonly supported ---
    0xDD00: "Diagnostic Data 00",
    0xDD01: "Calibration ID / Odometer",
    0xDD02: "Calibration Verification Number",
    0xDD03: "Module Software Version",
    0xDD04: "Module Hardware Version",
    0xDD05: "Diagnostic Data 05",
    # --- Status/Config (DExx) ---
    0xDE00: "Module Configuration 00",
    0xDE01: "Module Configuration 01",
    0xDE02: "Module Configuration 02",
    0xDE03: "Module Configuration 03",
    # --- Common Ford F1xx that sometimes work ---
    0xF110: "ECU Part Number (Ford)",
    0xF111: "ECU Hardware Version (Ford)",
    0xF113: "Module Status (Ford)",
    0xF124: "Calibration Module ID",
    0xF125: "Ford Strategy Code",
}


# ──────────────────────────────────────────────────────
# UDS Negative Response Codes (NRC) — ISO 14229-1:2020 §A.1
# Service 0x7F returns: 7F <rejected-SID> <NRC>
# ISO 14229-1:2020 Negative Response Codes
# ──────────────────────────────────────────────────────
UDS_NRC_CODES: Dict[int, str] = {
    # --- General ---
    0x10: "generalReject",
    0x11: "serviceNotSupported",
    0x12: "subFunctionNotSupported",
    0x13: "incorrectMessageLengthOrInvalidFormat",
    0x14: "responseTooLong",
    # --- Timing ---
    0x21: "busyRepeatRequest",
    0x22: "conditionsNotCorrect",
    0x23: "routineNotComplete",
    0x24: "requestSequenceError",
    0x25: "noResponseFromSubnetComponent",
    0x26: "failurePreventsExecutionOfRequestedAction",
    # --- Data / Range ---
    0x31: "requestOutOfRange",
    # --- Security ---
    0x33: "securityAccessDenied",
    0x34: "authenticationRequired",
    0x35: "invalidKey",
    0x36: "exceededNumberOfAttempts",
    0x37: "requiredTimeDelayNotExpired",
    0x38: "secureDataTransmissionRequired",
    0x39: "secureDataTransmissionNotAllowed",
    0x3A: "secureDataVerificationFailed",
    # --- Certificate Verification (ISO 14229-1:2020) ---
    0x50: "certificateVerificationFailed_InvalidTimePeriod",
    0x51: "certificateVerificationFailed_InvalidSignature",
    0x52: "certificateVerificationFailed_InvalidChainOfTrust",
    0x53: "certificateVerificationFailed_InvalidType",
    0x54: "certificateVerificationFailed_InvalidFormat",
    0x55: "certificateVerificationFailed_InvalidContent",
    0x56: "certificateVerificationFailed_InvalidScope",
    0x57: "certificateVerificationFailed_InvalidCertificate",
    0x58: "ownershipVerificationFailed",
    0x59: "challengeCalculationFailed",
    0x5A: "settingAccessRightsFailed",
    0x5B: "sessionKeyCreationDerivationFailed",
    0x5C: "configurationDataUsageFailed",
    0x5D: "deAuthenticationFailed",
    # --- Upload / Download ---
    0x70: "uploadDownloadNotAccepted",
    0x71: "transferDataSuspended",
    0x72: "generalProgrammingFailure",
    0x73: "wrongBlockSequenceCounter",
    # --- Response Pending ---
    0x78: "requestCorrectlyReceivedResponsePending",
    # --- Sub-function ---
    0x7E: "subFunctionNotSupportedInActiveSession",
    0x7F: "serviceNotSupportedInActiveSession",
    # --- Vehicle Condition ---
    0x81: "rpmTooHigh",
    0x82: "rpmTooLow",
    0x83: "engineIsRunning",
    0x84: "engineIsNotRunning",
    0x85: "engineRunTimeTooLow",
    0x86: "temperatureTooHigh",
    0x87: "temperatureTooLow",
    0x88: "vehicleSpeedTooHigh",
    0x89: "vehicleSpeedTooLow",
    0x8A: "throttlePedalTooHigh",
    0x8B: "throttlePedalTooLow",
    0x8C: "transmissionRangeNotInNeutral",
    0x8D: "transmissionRangeNotInGear",
    0x8F: "brakeSwitchNotClosed",
    0x90: "shifterLeverNotInPark",
    0x91: "torqueConverterClutchLocked",
    # --- Voltage ---
    0x92: "voltageTooHigh",
    0x93: "voltageTooLow",
    # --- Resource ---
    0x94: "resourceTemporarilyNotAvailable",
}


def get_nrc_name(nrc_byte: int) -> str:
    """Return human-readable name for a UDS Negative Response Code."""
    return UDS_NRC_CODES.get(nrc_byte, f"unknownNRC_0x{nrc_byte:02X}")


def get_nrc_name_hex(nrc_hex: str) -> str:
    """Return human-readable name for a UDS NRC given a 2-char hex string."""
    try:
        return get_nrc_name(int(nrc_hex, 16))
    except (ValueError, TypeError):
        return f"NRC 0x{nrc_hex}"


# ──────────────────────────────────────────────────────
# UDS Diagnostic Session Types — ISO 14229-1:2020 §9.2
# Service 0x10 DiagnosticSessionControl sub-functions
# ──────────────────────────────────────────────────────
UDS_SESSION_DEFAULT = 0x01
UDS_SESSION_PROGRAMMING = 0x02
UDS_SESSION_EXTENDED = 0x03
UDS_SESSION_SAFETY_SYSTEM = 0x04

UDS_SESSION_TYPES: Dict[int, str] = {
    UDS_SESSION_DEFAULT: "Default",
    UDS_SESSION_PROGRAMMING: "Programming",
    UDS_SESSION_EXTENDED: "Extended Diagnostic",
    UDS_SESSION_SAFETY_SYSTEM: "Safety System Diagnostic",
    # 0x05-0x3F reserved by ISO
    # 0x40-0x5F vehicle-manufacturer specific
    # 0x60-0x7E system-supplier specific
}


# VIN WMI (chars 1-3) to secondary bus mapping
# Determines which vehicles have MS-CAN or other secondary buses
MANUFACTURER_BUS_CONFIG = {
    # Ford Motor Company — MS-CAN on pins 3+11 at 125 kbps
    "ford": {"bus": "MS-CAN", "addresses": "FORD_MS_CAN_ADDRESSES"},
}

# WMI prefix → manufacturer key (Ford has many WMIs)
WMI_TO_MANUFACTURER = {
    # Ford USA
    "1FA": "ford", "1FB": "ford", "1FC": "ford", "1FD": "ford",
    "1FM": "ford", "1FT": "ford", "1FV": "ford",
    # Ford Canada
    "2FA": "ford", "2FB": "ford", "2FC": "ford", "2FD": "ford",
    "2FM": "ford", "2FT": "ford",
    # Ford Mexico
    "3FA": "ford", "3FB": "ford", "3FC": "ford", "3FD": "ford",
    "3FM": "ford", "3FT": "ford",
    # Ford Turkey (Transit)
    "NM0": "ford",
    # Ford Europe
    "WF0": "ford", "WFD": "ford",
    # Ford Australia
    "6FP": "ford",
    # Lincoln
    "1LN": "ford", "2LN": "ford", "3LN": "ford",
    "5LM": "ford",
    # Mercury (discontinued but still on road)
    "1ME": "ford", "2ME": "ford", "4M2": "ford",
    # Ford trucks
    "1FT": "ford", "3FT": "ford",
    # --- Future: GM (GMLAN on pin 1, 33.3 kbps) ---
    # "1G1": "gm", "1G2": "gm", "1GC": "gm", "1GK": "gm",
    # "2G1": "gm", "2G2": "gm", "3G1": "gm", "3GK": "gm",
    # --- Future: Stellantis (CAN-IHS on pins 3+11) ---
    # "1C3": "stellantis", "1C4": "stellantis", "1C6": "stellantis",
    # "2C3": "stellantis", "2C4": "stellantis", "3C4": "stellantis",
    # "3D7": "stellantis",
}


def get_vehicle_bus_config(vin: str) -> dict:
    """
    Determine secondary bus configuration from VIN.
    
    Args:
        vin: 17-character VIN
        
    Returns:
        Dict with 'manufacturer', 'has_ms_can', 'bus_type' or empty dict if unknown
    """
    if not vin or len(vin) < 3:
        return {}
    
    wmi = vin[:3].upper()
    mfr = WMI_TO_MANUFACTURER.get(wmi)
    
    if not mfr:
        # Try first 2 chars (some WMI tables use 2-char prefix)
        for prefix_len in [2]:
            for key, val in WMI_TO_MANUFACTURER.items():
                if key[:prefix_len] == wmi[:prefix_len] and len(key) >= prefix_len:
                    mfr = val
                    break
            if mfr:
                break
    
    if mfr and mfr in MANUFACTURER_BUS_CONFIG:
        config = MANUFACTURER_BUS_CONFIG[mfr]
        return {
            "manufacturer": mfr,
            "has_ms_can": True,
            "bus_type": config["bus"],
        }
    
    return {"manufacturer": mfr or "unknown", "has_ms_can": False}


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
    
    async def discover_modules(self, vin: str = None) -> List[ECUModule]:
        """
        Discover all ECU modules on the CAN bus by probing each of the
        8 standard OBD-II addresses individually.
        
        Strategy:
        1. Probe each address 7E0-7E7 with UDS TesterPresent (3E 00)
           — works for ABS, SRS, BCM, HVAC, etc. that don't support Mode 01
        2. Also try Mode 01 PID 00 (0100) for OBD-II emission modules
        3. Any address that responds to either is a live module
        4. If VIN indicates Ford/Lincoln/Mercury, probe MS-CAN (Phase 3)
           Otherwise skip Phase 3 entirely (~60s saved)
        
        Args:
            vin: Optional 17-char VIN for manufacturer-aware bus detection
        
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
            # Only run if VIN indicates a manufacturer that uses MS-CAN,
            # or if no VIN is available (probe anyway to be safe).
            bus_config = get_vehicle_bus_config(vin) if vin else {}
            skip_ms_can = False
            
            if bus_config:
                mfr = bus_config.get('manufacturer', 'unknown')
                has_ms_can = bus_config.get('has_ms_can', False)
                if has_ms_can:
                    logger.info(f"Phase 3: VIN {vin[:3]} -> {mfr} (has MS-CAN, probing...)")
                else:
                    logger.info(f"Phase 3: VIN {vin[:3]} -> {mfr} (no MS-CAN, skipping Phase 3)")
                    skip_ms_can = True
            else:
                logger.info("Phase 3: No VIN available, probing MS-CAN as fallback...")
            
            if not skip_ms_can:
                logger.info("Switching to MS-CAN (125 kbps, pins 3+11)...")
                
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
                        # Determine manufacturer for fallback DID selection
                        _mfr = ""
                        if bus_config:
                            _mfr = bus_config.get('manufacturer', '')
                        for mod in modules:
                            if mod.bus != "MS-CAN":
                                continue
                            try:
                                logger.info(f"  Reading DIDs for {mod.name} ({mod.request_addr:03X})...")
                                await self.connection.send_command(f"ATSH{mod.request_addr:03X}")
                                await self.connection.send_command(f"ATCRA{mod.response_addr:03X}")
                                mod.module_info = await self._read_module_dids(
                                    mod,
                                    manufacturer=_mfr,
                                    try_extended_session=True,
                                )
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
    
    async def _read_module_dids(
        self,
        module: 'ECUModule',
        manufacturer: str = "",
        try_extended_session: bool = False,
    ) -> Dict[str, str]:
        """
        Read UDS DIDs (Data Identifiers) from a module.
        
        First tries standard ISO 14229 identification DIDs (F180-F19F).
        If those all fail and the manufacturer is known, falls back to
        manufacturer-specific DIDs (e.g. Ford DDxx/DExx range).
        
        Optionally enters extended diagnostic session (0x10 0x03) first,
        which some modules require before responding to 0x22.
        
        IMPORTANT: Caller must have already set ATSH and ATCRA
        for this module, and be on the correct bus.
        
        Args:
            module: The ECUModule to read from
            manufacturer: Manufacturer name (e.g. "ford") for fallback DIDs
            try_extended_session: If True, enter 0x10 0x03 before reading
            
        Returns:
            Dict mapping DID name to string value
        """
        info = {}
        
        # Optionally enter extended session first
        if try_extended_session:
            try:
                resp = await self.connection.send_command("1003", timeout=3.0)
                if resp and "50" in resp:
                    logger.info(f"  {module.name}: extended session active")
                else:
                    logger.debug(f"  {module.name}: extended session not accepted: {resp}")
            except Exception:
                pass
        
        # Phase A: Standard ISO 14229 identification DIDs
        info = await self._scan_did_list(STANDARD_DIDS)
        
        # Phase B: Manufacturer-specific fallback DIDs
        if not info and manufacturer.lower() == "ford":
            logger.info(f"  {module.name}: standard DIDs empty, trying Ford-specific DIDs...")
            
            # If we didn't try extended session yet, try now — Ford MS-CAN
            # modules often require it for any DID read at all
            if not try_extended_session:
                try:
                    resp = await self.connection.send_command("1003", timeout=3.0)
                    if resp and "50" in resp:
                        logger.info(f"  {module.name}: extended session active (auto)")
                except Exception:
                    pass
            
            info = await self._scan_did_list(FORD_IDENTIFICATION_DIDS)
        
        return info
    
    @staticmethod
    def _decode_did_value(data_bytes: bytes) -> str:
        """Decode raw DID response bytes into a human-readable string.

        Strategy:
        1. Strip trailing null bytes (UDS strings are often null-terminated).
        2. If ALL remaining bytes are printable ASCII (0x20-0x7E) and the
           result looks like genuine text (contains alphanumeric chars),
           return as decoded text.  Short strings (< 4 chars) must be
           mostly alphanumeric to avoid garbage like "y~" or "),".
        3. For binary data ≤ 4 bytes, show "0xHEX (decimal)".
        4. For longer binary data, show space-separated hex bytes.
        """
        if not data_bytes:
            return "(empty)"

        # Strip trailing null bytes (common UDS string terminator)
        trimmed = data_bytes.rstrip(b'\x00')
        if not trimmed:
            return "0x" + data_bytes.hex().upper()

        # Check if every byte is printable ASCII
        all_printable = all(0x20 <= b <= 0x7E for b in trimmed)

        if all_printable:
            text = trimmed.decode('ascii').strip()
            has_alnum = any(c.isalnum() for c in text) if text else False

            if text and has_alnum:
                # Longer strings (>= 4 chars) — trust if they have alphanumeric
                if len(text) >= 4:
                    return text
                # Short strings — only trust if mostly alphanumeric
                stripped = text.replace('-', '').replace('.', '').replace(' ', '')
                if stripped.isalnum():
                    return text

        # Binary data — format based on length (use original data_bytes)
        if len(data_bytes) == 1:
            return f"0x{data_bytes[0]:02X} ({data_bytes[0]})"
        elif len(data_bytes) <= 4:
            hex_str = data_bytes.hex().upper()
            int_val = int.from_bytes(data_bytes, 'big')
            return f"0x{hex_str} ({int_val})"
        else:
            return ' '.join(f'{b:02X}' for b in data_bytes)

    async def _scan_did_list(self, did_dict: Dict[int, str]) -> Dict[str, str]:
        """Read a list of DIDs and return those that respond positively.
        
        Args:
            did_dict: Mapping of DID number → human label
            
        Returns:
            Dict of label → decoded value for DIDs that responded
        """
        info = {}
        for did, label in did_dict.items():
            try:
                cmd = f"22{did:04X}"
                resp = await self.connection.send_command(cmd, timeout=3.0)
                
                if not resp or not self._is_live_response(resp):
                    continue
                
                cleaned = resp.replace(' ', '').upper()
                did_hex = f"{did:04X}"
                marker = f"62{did_hex}"
                idx = cleaned.find(marker)
                
                if idx < 0:
                    continue
                
                data_hex = cleaned[idx + len(marker):]
                if not data_hex:
                    continue
                
                try:
                    data_bytes = bytes.fromhex(data_hex)
                    info[label] = self._decode_did_value(data_bytes)
                except ValueError:
                    info[label] = data_hex
                    
                logger.info(f"  DID {did_hex} ({label}): {info.get(label, 'N/A')}")
                
            except Exception as e:
                logger.debug(f"  DID {did:04X} read failed: {e}")
        
        return info

    async def read_did(
        self,
        module_addr: int,
        did: int,
        bus: str = "HS-CAN",
    ) -> Optional[str]:
        """
        Read a single UDS DID from a specific module.
        
        Handles bus switching (MS-CAN ↔ HS-CAN) automatically.
        
        Args:
            module_addr: CAN request address (e.g. 0x760 for GEM)
            did: UDS DID number (e.g. 0xF190 for VIN, or 0x4001)
            bus: "HS-CAN" or "MS-CAN"
            
        Returns:
            DID value as string (ASCII if printable, hex otherwise), or None
        """
        switched_bus = False
        try:
            # Switch to MS-CAN if needed
            if bus.upper() == "MS-CAN":
                logger.info(f"Switching to MS-CAN for DID read...")
                # Try STP33 first (proven on OBDLink MX+/STN2255)
                resp = await self.connection.send_command("STP33")
                if resp and "?" not in resp:
                    switched_bus = True
                    logger.info(f"  MS-CAN via STP33: OK")
                else:
                    # Fallback to ELM327 Protocol B
                    for cmd in ["ATPB C004", "ATSP B"]:
                        await self.connection.send_command(cmd)
                    switched_bus = True
                    logger.info(f"  MS-CAN via ATPB/ATSP B: OK")
            
            # Compute response address for CAN filter
            # Standard: req + 8 (e.g. 0x7E0 → 0x7E8)
            # Ford MS-CAN: varies, check FORD_MS_CAN_ADDRESSES
            resp_addr = None
            for ra, info in FORD_MS_CAN_ADDRESSES.items():
                if info["request"] == module_addr:
                    resp_addr = ra
                    break
            if resp_addr is None:
                for ra, info in ECU_ADDRESSES.items():
                    if info["request"] == module_addr:
                        resp_addr = ra
                        break
            if resp_addr is None:
                resp_addr = module_addr + 8  # Default offset
            
            # Set up CAN filtering
            await self.connection.send_command("ATH1")
            await self.connection.send_command(f"ATSH{module_addr:03X}")
            await self.connection.send_command(f"ATCRA{resp_addr:03X}")
            
            # UDS Service 0x22: ReadDataByIdentifier
            cmd = f"22{did:04X}"
            resp = await self.connection.send_command(cmd, timeout=5.0)
            
            if not resp or not self._is_live_response(resp):
                logger.info(f"  DID {did:04X} from {module_addr:03X}: no response")
                return None
            
            # Parse positive response: 62 XX XX <data>
            cleaned = resp.replace(' ', '').upper()
            did_hex = f"{did:04X}"
            marker = f"62{did_hex}"
            idx = cleaned.find(marker)
            
            if idx < 0:
                # Check for negative response (7F 22 xx)
                if "7F22" in cleaned:
                    nrc_idx = cleaned.find("7F22") + 4
                    nrc = cleaned[nrc_idx:nrc_idx+2] if nrc_idx + 2 <= len(cleaned) else "??"
                    nrc_name = get_nrc_name_hex(nrc)
                    logger.info(f"  DID {did_hex}: negative response ({nrc_name})")
                    return None
                logger.info(f"  DID {did_hex}: unexpected response: {resp}")
                return None
            
            # Data starts after 62+DID (6 hex chars)
            data_hex = cleaned[idx + len(marker):]
            if not data_hex:
                return None
            
            # Decode response data intelligently
            try:
                data_bytes = bytes.fromhex(data_hex)
                result = self._decode_did_value(data_bytes)
            except ValueError:
                result = data_hex
            
            logger.info(f"  DID {did_hex} from {module_addr:03X}: {result}")
            return result
            
        except Exception as e:
            logger.error(f"read_did({module_addr:03X}, {did:04X}) failed: {e}")
            return None
        finally:
            # Restore bus and headers
            if switched_bus:
                for cmd in ["STP6", "STPC1"]:
                    try:
                        await self.connection.send_command(cmd)
                    except Exception:
                        pass
                try:
                    await self.connection.send_command("ATSP6")
                except Exception:
                    pass
            try:
                await self.connection.send_command("ATSH7DF")
                await self.connection.send_command("ATCRA")
                await self.connection.send_command("ATH0")
            except Exception:
                pass

    async def send_uds_raw(
        self,
        module_addr: int,
        hex_cmd: str,
        bus: str = "HS-CAN",
    ) -> str:
        """
        Send a raw UDS command to a specific module and return the raw response.

        Handles bus switching (MS-CAN ↔ HS-CAN) and CAN filter setup.
        This is the low-level transport for arbitrary UDS services like
        0x2F InputOutputControlByIdentifier.

        Args:
            module_addr: CAN request address (e.g. 0x726 for GEM)
            hex_cmd: Raw UDS command as hex string (e.g. "2FDE0003FF")
            bus: "HS-CAN" or "MS-CAN"

        Returns:
            Raw hex response string (e.g. "6FDE0003FF"), or empty string on failure.
        """
        switched_bus = False
        try:
            # Switch to MS-CAN if needed
            if bus.upper() == "MS-CAN":
                logger.info(f"send_uds_raw: Switching to MS-CAN")
                resp = await self.connection.send_command("STP33")
                if resp and "?" not in resp:
                    switched_bus = True
                else:
                    for cmd in ["ATPB C004", "ATSP B"]:
                        await self.connection.send_command(cmd)
                    switched_bus = True

            # Compute response address
            resp_addr = None
            for ra, info in FORD_MS_CAN_ADDRESSES.items():
                if info["request"] == module_addr:
                    resp_addr = ra
                    break
            if resp_addr is None:
                for ra, info in ECU_ADDRESSES.items():
                    if info["request"] == module_addr:
                        resp_addr = ra
                        break
            if resp_addr is None:
                resp_addr = module_addr + 8

            # Set up CAN filtering
            await self.connection.send_command("ATH1")
            await self.connection.send_command(f"ATSH{module_addr:03X}")
            await self.connection.send_command(f"ATCRA{resp_addr:03X}")

            # Send the raw UDS command
            resp = await self.connection.send_command(hex_cmd, timeout=5.0)

            if not resp or not self._is_live_response(resp):
                logger.info(f"send_uds_raw({module_addr:03X}, {hex_cmd}): no response")
                return ""

            # Clean and return raw hex response
            cleaned = resp.replace(' ', '').upper()
            # Strip CAN header if present (3-byte header like "726" at start)
            resp_hex = f"{resp_addr:03X}"
            if cleaned.startswith(resp_hex):
                cleaned = cleaned[len(resp_hex):]

            logger.info(f"send_uds_raw({module_addr:03X}, {hex_cmd}): {cleaned}")
            return cleaned

        except Exception as e:
            logger.error(f"send_uds_raw({module_addr:03X}, {hex_cmd}) failed: {e}")
            return ""
        finally:
            if switched_bus:
                for cmd in ["STP6", "STPC1"]:
                    try:
                        await self.connection.send_command(cmd)
                    except Exception:
                        pass
                try:
                    await self.connection.send_command("ATSP6")
                except Exception:
                    pass
            try:
                await self.connection.send_command("ATSH7DF")
                await self.connection.send_command("ATCRA")
                await self.connection.send_command("ATH0")
            except Exception:
                pass

    async def read_dids(
        self,
        module_addr: int,
        dids: List[int],
        bus: str = "HS-CAN",
    ) -> Dict[str, str]:
        """
        Read multiple UDS DIDs from a specific module (single bus switch).
        
        Args:
            module_addr: CAN request address
            dids: List of DID numbers to read
            bus: "HS-CAN" or "MS-CAN"
            
        Returns:
            Dict mapping "DID_XXXX" or known label to value string
        """
        results = {}
        switched_bus = False
        try:
            # Switch to MS-CAN if needed
            if bus.upper() == "MS-CAN":
                resp = await self.connection.send_command("STP33")
                if resp and "?" not in resp:
                    switched_bus = True
                else:
                    for cmd in ["ATPB C004", "ATSP B"]:
                        await self.connection.send_command(cmd)
                    switched_bus = True
            
            # Compute response address
            resp_addr = None
            for ra, info in FORD_MS_CAN_ADDRESSES.items():
                if info["request"] == module_addr:
                    resp_addr = ra
                    break
            if resp_addr is None:
                for ra, info in ECU_ADDRESSES.items():
                    if info["request"] == module_addr:
                        resp_addr = ra
                        break
            if resp_addr is None:
                resp_addr = module_addr + 8
            
            await self.connection.send_command("ATH1")
            await self.connection.send_command(f"ATSH{module_addr:03X}")
            await self.connection.send_command(f"ATCRA{resp_addr:03X}")
            
            for did in dids:
                try:
                    cmd = f"22{did:04X}"
                    resp = await self.connection.send_command(cmd, timeout=5.0)
                    
                    if not resp or not self._is_live_response(resp):
                        continue
                    
                    cleaned = resp.replace(' ', '').upper()
                    did_hex = f"{did:04X}"
                    marker = f"62{did_hex}"
                    idx = cleaned.find(marker)
                    
                    if idx < 0:
                        continue
                    
                    data_hex = cleaned[idx + len(marker):]
                    if not data_hex:
                        continue
                    
                    value = self._decode_did_value(data_hex)
                    
                    # Use known label or DID hex
                    label = STANDARD_DIDS.get(did, f"DID_{did_hex}")
                    results[label] = value
                    logger.info(f"  DID {did_hex}: {value}")
                    
                except Exception as e:
                    logger.debug(f"  DID {did:04X} failed: {e}")
            
        except Exception as e:
            logger.error(f"read_dids({module_addr:03X}) failed: {e}")
        finally:
            if switched_bus:
                for cmd in ["STP6", "STPC1"]:
                    try:
                        await self.connection.send_command(cmd)
                    except Exception:
                        pass
                try:
                    await self.connection.send_command("ATSP6")
                except Exception:
                    pass
            try:
                await self.connection.send_command("ATSH7DF")
                await self.connection.send_command("ATCRA")
                await self.connection.send_command("ATH0")
            except Exception:
                pass
        
        return results

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
    
    async def scan_all_modules(self, vin: str = None) -> List[ECUModule]:
        """
        Full module scan: discover all ECUs and enumerate each one's
        supported PIDs. For modules that don't support Mode 01, reports
        them as present with UDS-only capability.
        
        Args:
            vin: Optional 17-char VIN for manufacturer-aware bus detection
        
        Returns:
            List of ECUModule objects with supported_pids populated
        """
        from .pids import PIDRegistry
        
        # Step 1: Discover which modules are on the bus
        modules = await self.discover_modules(vin=vin)
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
                    # Determine manufacturer for fallback DID selection
                    _hs_mfr = ""
                    if vin:
                        _hs_bus_cfg = get_vehicle_bus_config(vin)
                        _hs_mfr = _hs_bus_cfg.get('manufacturer', '') if _hs_bus_cfg else ""
                    try:
                        await self.connection.send_command(f"ATSH{module.request_addr:03X}")
                        await self.connection.send_command(f"ATCRA{module.response_addr:03X}")
                        module.module_info = await self._read_module_dids(
                            module, manufacturer=_hs_mfr
                        )
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
                # On CAN (ISO 15765-4), first byte after SID is the DTC count — skip it
                # Without this, the count byte gets merged with the first DTC byte,
                # e.g. count=01 + DTC 12 89 → "0112" parsed as P0112 instead of P1289
                if ecu_addr and len(cleaned) >= 2:
                    dtc_count_byte = cleaned[:2]
                    cleaned = cleaned[2:]
                    logger.debug(f"CAN DTC count byte: {dtc_count_byte} (skipped)")
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
    # === Variable Valve Timing (P0010-P0025) ===
    "P0010": "Intake Camshaft Position Actuator Circuit (Bank 1)",
    "P0011": "Intake Camshaft Position Timing Over-Advanced (Bank 1)",
    "P0012": "Intake Camshaft Position Timing Over-Retarded (Bank 1)",
    "P0013": "Exhaust Camshaft Position Actuator Circuit (Bank 1)",
    "P0014": "Exhaust Camshaft Position Timing Over-Advanced (Bank 1)",
    "P0015": "Exhaust Camshaft Position Timing Over-Retarded (Bank 1)",
    "P0020": "Intake Camshaft Position Actuator Circuit (Bank 2)",
    "P0021": "Intake Camshaft Position Timing Over-Advanced (Bank 2)",
    "P0022": "Intake Camshaft Position Timing Over-Retarded (Bank 2)",
    "P0023": "Exhaust Camshaft Position Actuator Circuit (Bank 2)",
    "P0024": "Exhaust Camshaft Position Timing Over-Advanced (Bank 2)",
    "P0025": "Exhaust Camshaft Position Timing Over-Retarded (Bank 2)",

    # === Fuel System (P0080-P0099) ===
    "P0087": "Fuel Rail/System Pressure Too Low",
    "P0088": "Fuel Rail/System Pressure Too High",
    "P0089": "Fuel Pressure Regulator Performance",
    "P0093": "Fuel System Large Leak Detected",

    # === Fuel & Air Metering (P0100-P0199) ===
    "P0100": "Mass Air Flow (MAF) Circuit Malfunction",
    "P0101": "MAF Sensor Range/Performance",
    "P0102": "MAF Sensor Low Input",
    "P0103": "MAF Sensor High Input",
    "P0104": "MAF Circuit Intermittent",
    "P0105": "Manifold Absolute Pressure (MAP) Circuit Malfunction",
    "P0106": "MAP Sensor Range/Performance",
    "P0107": "MAP Sensor Low Input",
    "P0108": "MAP Sensor High Input",
    "P0110": "Intake Air Temperature (IAT) Circuit Malfunction",
    "P0111": "IAT Sensor Range/Performance",
    "P0112": "IAT Sensor Low Input",
    "P0113": "IAT Sensor High Input",
    "P0115": "Engine Coolant Temperature (ECT) Circuit Malfunction",
    "P0116": "ECT Sensor Range/Performance",
    "P0117": "ECT Sensor Low Input",
    "P0118": "ECT Sensor High Input",
    "P0119": "ECT Circuit Intermittent",
    "P0120": "Throttle Position Sensor (TPS) Circuit Malfunction",
    "P0121": "TPS Range/Performance",
    "P0122": "TPS Low Input",
    "P0123": "TPS High Input",
    "P0125": "Insufficient Coolant Temperature for Closed Loop",
    "P0128": "Coolant Thermostat Below Regulating Temperature",
    "P0130": "O2 Sensor Circuit Malfunction (Bank 1 Sensor 1)",
    "P0131": "O2 Sensor Low Voltage (B1S1)",
    "P0132": "O2 Sensor High Voltage (B1S1)",
    "P0133": "O2 Sensor Slow Response (B1S1)",
    "P0134": "O2 Sensor No Activity Detected (B1S1)",
    "P0135": "O2 Sensor Heater Circuit Malfunction (B1S1)",
    "P0136": "O2 Sensor Circuit Malfunction (B1S2)",
    "P0137": "O2 Sensor Low Voltage (B1S2)",
    "P0138": "O2 Sensor High Voltage (B1S2)",
    "P0139": "O2 Sensor Slow Response (B1S2)",
    "P0140": "O2 Sensor No Activity Detected (B1S2)",
    "P0141": "O2 Sensor Heater Circuit Malfunction (B1S2)",
    "P0150": "O2 Sensor Circuit Malfunction (B2S1)",
    "P0151": "O2 Sensor Low Voltage (B2S1)",
    "P0152": "O2 Sensor High Voltage (B2S1)",
    "P0153": "O2 Sensor Slow Response (B2S1)",
    "P0154": "O2 Sensor No Activity Detected (B2S1)",
    "P0155": "O2 Sensor Heater Circuit Malfunction (B2S1)",
    "P0156": "O2 Sensor Circuit Malfunction (B2S2)",
    "P0157": "O2 Sensor Low Voltage (B2S2)",
    "P0158": "O2 Sensor High Voltage (B2S2)",
    "P0170": "Fuel Trim Malfunction (Bank 1)",
    "P0171": "System Too Lean (Bank 1)",
    "P0172": "System Too Rich (Bank 1)",
    "P0173": "Fuel Trim Malfunction (Bank 2)",
    "P0174": "System Too Lean (Bank 2)",
    "P0175": "System Too Rich (Bank 2)",
    "P0190": "Fuel Rail Pressure Sensor Circuit Malfunction",
    "P0191": "Fuel Rail Pressure Sensor Range/Performance",
    "P0192": "Fuel Rail Pressure Sensor Low Input",
    "P0193": "Fuel Rail Pressure Sensor High Input",

    # === Fuel & Air Metering (P0200-P0299) ===
    "P0201": "Injector Circuit Malfunction - Cylinder 1",
    "P0202": "Injector Circuit Malfunction - Cylinder 2",
    "P0203": "Injector Circuit Malfunction - Cylinder 3",
    "P0204": "Injector Circuit Malfunction - Cylinder 4",
    "P0205": "Injector Circuit Malfunction - Cylinder 5",
    "P0206": "Injector Circuit Malfunction - Cylinder 6",
    "P0207": "Injector Circuit Malfunction - Cylinder 7",
    "P0208": "Injector Circuit Malfunction - Cylinder 8",
    "P0217": "Engine Overtemperature Condition",
    "P0220": "Throttle Position Sensor B Circuit Malfunction",
    "P0221": "TPS B Range/Performance",
    "P0222": "TPS B Low Input",
    "P0223": "TPS B High Input",
    "P0230": "Fuel Pump Primary Circuit Malfunction",
    "P0231": "Fuel Pump Secondary Circuit Low",
    "P0232": "Fuel Pump Secondary Circuit High",
    "P0234": "Turbo/Supercharger Overboost Condition",
    "P0261": "Cylinder 1 Injector Circuit Low",
    "P0264": "Cylinder 2 Injector Circuit Low",
    "P0267": "Cylinder 3 Injector Circuit Low",
    "P0270": "Cylinder 4 Injector Circuit Low",
    "P0299": "Turbo/Supercharger Underboost Condition",

    # === Ignition System (P0300-P0399) ===
    "P0300": "Random/Multiple Cylinder Misfire Detected",
    "P0301": "Cylinder 1 Misfire Detected",
    "P0302": "Cylinder 2 Misfire Detected",
    "P0303": "Cylinder 3 Misfire Detected",
    "P0304": "Cylinder 4 Misfire Detected",
    "P0305": "Cylinder 5 Misfire Detected",
    "P0306": "Cylinder 6 Misfire Detected",
    "P0307": "Cylinder 7 Misfire Detected",
    "P0308": "Cylinder 8 Misfire Detected",
    "P0325": "Knock Sensor 1 Circuit Malfunction",
    "P0326": "Knock Sensor 1 Range/Performance",
    "P0327": "Knock Sensor 1 Low Input",
    "P0328": "Knock Sensor 1 High Input",
    "P0330": "Knock Sensor 2 Circuit Malfunction",
    "P0335": "Crankshaft Position Sensor A Circuit Malfunction",
    "P0336": "Crankshaft Position Sensor A Range/Performance",
    "P0337": "Crankshaft Position Sensor A Low Input",
    "P0338": "Crankshaft Position Sensor A High Input",
    "P0340": "Camshaft Position Sensor Circuit Malfunction (Bank 1)",
    "P0341": "Camshaft Position Sensor Range/Performance",
    "P0345": "Camshaft Position Sensor Circuit Malfunction (Bank 2)",
    "P0351": "Ignition Coil A Primary/Secondary Circuit Malfunction",
    "P0352": "Ignition Coil B Primary/Secondary Circuit Malfunction",
    "P0353": "Ignition Coil C Primary/Secondary Circuit Malfunction",
    "P0354": "Ignition Coil D Primary/Secondary Circuit Malfunction",
    "P0355": "Ignition Coil E Primary/Secondary Circuit Malfunction",
    "P0356": "Ignition Coil F Primary/Secondary Circuit Malfunction",
    "P0357": "Ignition Coil G Primary/Secondary Circuit Malfunction",
    "P0358": "Ignition Coil H Primary/Secondary Circuit Malfunction",

    # === Emissions Controls (P0400-P0499) ===
    "P0400": "Exhaust Gas Recirculation (EGR) Flow Malfunction",
    "P0401": "EGR Insufficient Flow Detected",
    "P0402": "EGR Excessive Flow Detected",
    "P0403": "EGR Circuit Malfunction",
    "P0404": "EGR Range/Performance",
    "P0405": "EGR Sensor A Low",
    "P0406": "EGR Sensor A High",
    "P0420": "Catalyst System Efficiency Below Threshold (Bank 1)",
    "P0421": "Warm Up Catalyst Efficiency Below Threshold (Bank 1)",
    "P0430": "Catalyst System Efficiency Below Threshold (Bank 2)",
    "P0431": "Warm Up Catalyst Efficiency Below Threshold (Bank 2)",
    "P0440": "Evaporative Emission (EVAP) System Malfunction",
    "P0441": "EVAP System Incorrect Purge Flow",
    "P0442": "EVAP System Small Leak Detected",
    "P0443": "EVAP Purge Control Valve Circuit Malfunction",
    "P0444": "EVAP Purge Control Valve Circuit Open",
    "P0445": "EVAP Purge Control Valve Circuit Shorted",
    "P0446": "EVAP Vent Control Circuit Malfunction",
    "P0447": "EVAP Vent Control Circuit Open",
    "P0448": "EVAP Vent Control Circuit Shorted",
    "P0449": "EVAP Vent Valve/Solenoid Circuit Malfunction",
    "P0450": "EVAP Pressure Sensor Malfunction",
    "P0451": "EVAP Pressure Sensor Range/Performance",
    "P0452": "EVAP Pressure Sensor Low Input",
    "P0453": "EVAP Pressure Sensor High Input",
    "P0455": "EVAP System Large Leak Detected",
    "P0456": "EVAP System Very Small Leak Detected",
    "P0457": "EVAP System Leak Detected (Fuel Cap Loose/Off)",
    "P0480": "Cooling Fan 1 Control Circuit Malfunction",
    "P0481": "Cooling Fan 2 Control Circuit Malfunction",

    # === Vehicle Speed & Idle Control (P0500-P0599) ===
    "P0505": "Idle Air Control System Malfunction",
    "P0506": "Idle Control System RPM Lower Than Expected",
    "P0507": "Idle Control System RPM Higher Than Expected",
    "P0508": "Idle Air Control Low",
    "P0509": "Idle Air Control High",
    "P0560": "System Voltage Malfunction",
    "P0561": "System Voltage Unstable",
    "P0562": "System Voltage Low",
    "P0563": "System Voltage High",

    # === Transmission (P0700-P0899) ===
    "P0700": "Transmission Control System Malfunction",
    "P0705": "Transmission Range Sensor Circuit Malfunction",
    "P0706": "Transmission Range Sensor Range/Performance",
    "P0710": "Transmission Fluid Temperature Sensor Circuit Malfunction",
    "P0711": "Trans Fluid Temp Sensor Range/Performance",
    "P0715": "Input/Turbine Speed Sensor Circuit Malfunction",
    "P0716": "Input Speed Sensor Range/Performance",
    "P0717": "Input Speed Sensor No Signal",
    "P0720": "Output Speed Sensor Circuit Malfunction",
    "P0721": "Output Speed Sensor Range/Performance",
    "P0722": "Output Speed Sensor No Signal",
    "P0725": "Engine Speed Input Circuit Malfunction",
    "P0730": "Incorrect Gear Ratio",
    "P0731": "Gear 1 Incorrect Ratio",
    "P0732": "Gear 2 Incorrect Ratio",
    "P0733": "Gear 3 Incorrect Ratio",
    "P0734": "Gear 4 Incorrect Ratio",
    "P0735": "Gear 5 Incorrect Ratio",
    "P0740": "Torque Converter Clutch Circuit Malfunction",
    "P0741": "Torque Converter Clutch Stuck Off",
    "P0742": "Torque Converter Clutch Stuck On",
    "P0743": "Torque Converter Clutch Circuit Electrical",
    "P0744": "Torque Converter Clutch Circuit Intermittent",
    "P0750": "Shift Solenoid A Malfunction",
    "P0751": "Shift Solenoid A Performance/Stuck Off",
    "P0752": "Shift Solenoid A Stuck On",
    "P0753": "Shift Solenoid A Electrical",
    "P0755": "Shift Solenoid B Malfunction",
    "P0756": "Shift Solenoid B Performance/Stuck Off",
    "P0757": "Shift Solenoid B Stuck On",
    "P0758": "Shift Solenoid B Electrical",
    "P0760": "Shift Solenoid C Malfunction",
    "P0765": "Shift Solenoid D Malfunction",
    "P0770": "Shift Solenoid E Malfunction",
    "P0780": "Shift Malfunction",
    "P0781": "1-2 Shift Malfunction",
    "P0782": "2-3 Shift Malfunction",
    "P0783": "3-4 Shift Malfunction",
    "P0784": "4-5 Shift Malfunction",

    # === Additional P2xxx Codes ===
    "P2135": "Throttle/Pedal Position Sensor A/B Voltage Correlation",
    "P2138": "Throttle/Pedal Position Sensor D/E Voltage Correlation",

    # === Chassis Codes (C0xxx) - ABS/Traction Control ===
    "C0035": "Left Front Wheel Speed Sensor Circuit",
    "C0040": "Right Front Wheel Speed Sensor Circuit",
    "C0045": "Left Rear Wheel Speed Sensor Circuit",
    "C0050": "Right Rear Wheel Speed Sensor Circuit",
    "C0055": "Rear Wheel Speed Sensor Circuit",
    "C0060": "Left Front ABS Solenoid Circuit",
    "C0065": "Right Front ABS Solenoid Circuit",
    "C0070": "Left Rear ABS Solenoid Circuit",
    "C0075": "Right Rear ABS Solenoid Circuit",
    "C0080": "ABS Solenoid Circuit Malfunction",
    "C0110": "ABS Pump Motor Circuit",
    "C0121": "Traction Control Valve Circuit",
    "C0161": "ABS/TCS Brake Switch Circuit",
    "C0265": "EBCM Relay Circuit",

    # === Chassis Codes - Steering ===
    "C0455": "Steering Wheel Position Sensor",
    "C0460": "Steering Position Sensor Range/Performance",
    "C0545": "Electric Power Steering Motor Circuit",
    "C0550": "Electronic Power Steering Control Module",

    # === Network Codes (U0xxx) ===
    "U0100": "Lost Communication With ECM/PCM",
    "U0101": "Lost Communication With TCM",
    "U0121": "Lost Communication With ABS Module",
    "U0140": "Lost Communication With BCM",
    "U0151": "Lost Communication With Restraints Control Module",
    "U0155": "Lost Communication With Instrument Cluster",
    "U0164": "Lost Communication With HVAC Control Module",
    "U0168": "Lost Communication With Parking Assist Control Module",
    "U0184": "Lost Communication With Radio/Audio Module",
    "U0199": "Lost Communication With Door Control Module A",
    "U0300": "Internal Control Module Software Incompatibility",
    "U0401": "Invalid Data Received From ECM/PCM",
    "U0402": "Invalid Data Received From TCM",
    "U0415": "Invalid Data Received From ABS Module",
    "U0422": "Invalid Data Received From BCM",

    # === Body Codes (B0xxx) — SAE Standard ===
    "B0001": "Driver Frontal Stage 1 Deployment Control",
    "B0002": "Driver Frontal Stage 2 Deployment Control",
    "B0003": "Passenger Frontal Stage 1 Deployment Control",
    "B0004": "Passenger Frontal Stage 2 Deployment Control",
    "B0010": "Driver Side Deployment Control",
    "B0012": "Passenger Side Deployment Control",
    "B0020": "Driver Side Curtain Deployment Control",
    "B0022": "Passenger Side Curtain Deployment Control",
    "B0028": "Driver Knee Deployment Control",
    "B0051": "Driver Seat Position Sensor Circuit",
    "B0071": "Passenger Seat Position Sensor Circuit",
    "B0081": "Occupant Classification System Sensor",
    "B0092": "Seat Belt Tension Sensor Circuit",
    "B0100": "Electronic Frontal Sensor 1",
    "B0101": "Electronic Frontal Sensor 2",
    "B0102": "Electronic Side Sensor — Left Front",
    "B0103": "Electronic Side Sensor — Right Front",

    # === Body Codes (B1xxx-B2xxx) — Common OEM Codes ===
    "B1200": "Climate Control Pushbutton Circuit",
    "B1201": "Fuel Sender Circuit Open",
    "B1213": "Anti-Theft Number of Programmed Keys Is Below Minimum",
    "B1232": "Antenna Not Connected",
    "B1317": "Battery Voltage High",
    "B1318": "Battery Voltage Low",
    "B1342": "ECU Is Faulted",
    "B1352": "Ignition Key-in Circuit Failure",
    "B1359": "Ignition Run/Accessory Circuit Failure",
    "B1480": "Headlamp Switch Circuit",
    "B1485": "Brake Pedal Input Circuit Open",
    "B1595": "Ignition Switch Circuit Malfunction",
    "B1600": "PATS Received Incorrect Key Code (Unprogrammed Key)",
    "B1601": "PATS Received Invalid Format / Key Code",
    "B1602": "PATS Received Invalid Key (Wrong Key)",
    "B1681": "PATS Transceiver / Module Signal Not Received",
    "B2477": "Module Configuration Failure",
}


def get_dtc_description(dtc_code: str) -> str:
    """Get description for a DTC code.

    Lookup order:
    1. protocol.py DTC_DESCRIPTIONS (curated overlay, 269 entries)
    2. dtc_database.py comprehensive database (~12,000 generic + 6,700 manufacturer-specific)
    3. Fallback message for manufacturer-specific or unknown codes
    """
    code = dtc_code.upper()
    # 1. Check curated overlay first (our custom descriptions may be better)
    desc = DTC_DESCRIPTIONS.get(code)
    if desc:
        return desc
    # 2. Check comprehensive database
    try:
        from .dtc_database import describe_dtc as _db_describe
        desc = _db_describe(code)
        if desc:
            return desc
    except ImportError:
        pass
    # 3. Fallback for manufacturer-specific codes
    if len(code) == 5 and code[0] == 'P' and code[1] in ('1', '2', '3'):
        return f"Manufacturer-specific code (look up {code} definition in your DTC Codes knowledge for this vehicle make)"
    if len(code) == 5 and code[0] in ('B', 'C', 'U') and code[1] in ('1', '2', '3'):
        return f"Manufacturer-specific code (look up {code} definition in your DTC Codes knowledge for this vehicle make)"
    return f"Code not in scan tool database (look up {code} in your DTC Codes knowledge)"
