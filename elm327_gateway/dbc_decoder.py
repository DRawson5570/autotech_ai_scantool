"""
DBC File Decoder — Parse CAN database files and decode broadcast CAN frames.

Loads DBC files from the opendbc project (MIT-licensed) to auto-decode
raw CAN bus broadcast traffic into named signals with engineering units.

DBC Format Reference:
    BO_ <CAN_ID> <MessageName>: <DLC> <Transmitter>
     SG_ <SignalName> : <StartBit>|<Length>@<ByteOrder><ValueType>
         (<Factor>,<Offset>) [<Min>|<Max>] "<Unit>" <Receivers>

    ByteOrder: 1 = little-endian (Intel), 0 = big-endian (Motorola)
    ValueType: + = unsigned, - = signed

This module:
1. Parses DBC files into structured Message / Signal objects
2. Decodes raw CAN data bytes into physical values using factor+offset
3. Auto-selects the right DBC file set based on VIN / manufacturer
4. Integrates with SnifferCapture to add decoded broadcast data
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────
# DBC data structures
# ─────────────────────────────────────────────────────────────

# Support PyInstaller frozen bundles (uses sys._MEIPASS for data files)
import sys as _sys
if getattr(_sys, 'frozen', False) and hasattr(_sys, '_MEIPASS'):
    DBC_DIR = Path(_sys._MEIPASS) / "elm327_gateway" / "dbc"
else:
    DBC_DIR = Path(__file__).parent / "dbc"


@dataclass
class DBCSignal:
    """A single signal within a CAN message."""
    name: str
    start_bit: int           # DBC start bit position
    length: int              # signal length in bits
    byte_order: int          # 0 = big-endian (Motorola), 1 = little-endian (Intel)
    is_signed: bool          # True = signed value
    factor: float            # physical = raw * factor + offset
    offset: float
    minimum: float
    maximum: float
    unit: str
    receivers: List[str] = field(default_factory=list)
    comment: str = ""
    value_table: Optional[Dict[int, str]] = None  # enum-style named values

    def decode(self, data: bytes) -> Any:
        """Decode this signal's value from raw CAN data bytes.

        Args:
            data: Raw CAN frame data (up to 64 bytes for CAN-FD)

        Returns:
            Physical value (float or int), or named string if value_table exists
        """
        raw = self._extract_raw(data)
        physical = raw * self.factor + self.offset

        # Clamp to min/max if defined
        if self.maximum > self.minimum:
            physical = max(self.minimum, min(self.maximum, physical))

        # Return named value if value table exists
        if self.value_table:
            raw_int = int(raw)
            if raw_int in self.value_table:
                return self.value_table[raw_int]

        # Return int if factor is 1.0 and offset is 0 and no fractional part
        if self.factor == 1.0 and self.offset == 0.0 and physical == int(physical):
            return int(physical)

        return round(physical, 4)

    def _extract_raw(self, data: bytes) -> int:
        """Extract raw integer value from CAN data bytes."""
        if self.byte_order == 1:
            # Little-endian (Intel byte order)
            return self._extract_intel(data)
        else:
            # Big-endian (Motorola byte order)
            return self._extract_motorola(data)

    def _extract_intel(self, data: bytes) -> int:
        """Extract little-endian (Intel) signal."""
        # In Intel format, start_bit is the LSB position
        # Bits are numbered: byte0_bit0=0, byte0_bit7=7, byte1_bit0=8, etc.
        start = self.start_bit
        length = self.length

        # Convert data to a large integer (little-endian)
        value = int.from_bytes(data, byteorder='little')

        # Shift and mask
        raw = (value >> start) & ((1 << length) - 1)

        # Handle signed
        if self.is_signed and raw & (1 << (length - 1)):
            raw -= (1 << length)

        return raw

    def _extract_motorola(self, data: bytes) -> int:
        """Extract big-endian (Motorola) signal.

        In Motorola format, start_bit is the MSB position in DBC notation:
        bit numbering within each byte goes 7,6,5,4,3,2,1,0 (MSB first)
        and bytes go 0,1,2,3... So bit positions are:
        byte0: 7,6,5,4,3,2,1,0
        byte1: 15,14,13,12,11,10,9,8
        byte2: 23,22,21,20,19,18,17,16
        etc.
        """
        start = self.start_bit
        length = self.length

        # Build list of bit positions (MSB to LSB)
        bits = []
        pos = start
        for _ in range(length):
            bits.append(pos)
            # Next bit: move right within byte, or wrap to next byte
            byte_num = pos // 8
            bit_in_byte = pos % 8
            if bit_in_byte > 0:
                pos = byte_num * 8 + (bit_in_byte - 1)
            else:
                # Wrap to MSB of next byte
                pos = (byte_num + 1) * 8 + 7

        # Extract bits from data
        raw = 0
        for bit_pos in bits:
            byte_idx = bit_pos // 8
            bit_idx = bit_pos % 8
            if byte_idx < len(data):
                bit_val = (data[byte_idx] >> bit_idx) & 1
            else:
                bit_val = 0
            raw = (raw << 1) | bit_val

        # Handle signed
        if self.is_signed and raw & (1 << (length - 1)):
            raw -= (1 << length)

        return raw


@dataclass
class DBCMessage:
    """A CAN message definition from a DBC file."""
    can_id: int              # 11-bit or 29-bit CAN arbitration ID
    name: str                # Human-readable message name
    dlc: int                 # Data Length Code (bytes)
    transmitter: str         # Transmitting ECU node name
    signals: Dict[str, DBCSignal] = field(default_factory=dict)
    comment: str = ""
    is_extended: bool = False  # True for 29-bit CAN IDs

    def decode(self, data: bytes) -> Dict[str, Any]:
        """Decode all signals from raw CAN data.

        Args:
            data: Raw CAN frame data bytes

        Returns:
            Dict mapping signal names to decoded physical values
        """
        result = {}
        for sig_name, sig in self.signals.items():
            try:
                result[sig_name] = sig.decode(data)
            except Exception as e:
                logger.debug("Failed to decode signal %s in %s: %s",
                             sig_name, self.name, e)
        return result


@dataclass
class DBCDatabase:
    """Complete DBC database — all messages from one or more DBC files."""
    messages: Dict[int, DBCMessage] = field(default_factory=dict)
    # Map CAN ID -> message for fast lookup
    source_files: List[str] = field(default_factory=list)

    def decode_frame(self, can_id: int, data: bytes) -> Optional[Dict[str, Any]]:
        """Decode a CAN frame if its ID is known.

        Args:
            can_id: CAN arbitration ID
            data: Raw CAN data bytes

        Returns:
            Dict with 'message', 'signals' keys, or None if ID unknown
        """
        msg = self.messages.get(can_id)
        if msg is None:
            return None

        signals = msg.decode(data)
        return {
            "message": msg.name,
            "transmitter": msg.transmitter,
            "signals": signals,
        }

    def get_message(self, can_id: int) -> Optional[DBCMessage]:
        return self.messages.get(can_id)

    @property
    def total_messages(self) -> int:
        return len(self.messages)

    @property
    def total_signals(self) -> int:
        return sum(len(m.signals) for m in self.messages.values())

    def known_ids(self) -> Set[int]:
        return set(self.messages.keys())

    def summary(self) -> dict:
        """Return summary info about loaded DBC data."""
        return {
            "files": self.source_files,
            "messages": self.total_messages,
            "signals": self.total_signals,
        }


# ─────────────────────────────────────────────────────────────
# DBC file parser
# ─────────────────────────────────────────────────────────────

# Regex patterns for DBC parsing
_BO_RE = re.compile(
    r"^BO_\s+(\d+)\s+(\w+)\s*:\s*(\d+)\s+(\S+)"
)
_SG_RE = re.compile(
    r"^\s+SG_\s+(\w+)\s*:\s*(\d+)\|(\d+)@([01])([+-])"
    r"\s+\(([^,]+),([^)]+)\)\s+\[([^|]+)\|([^\]]+)\]\s+"
    r'"([^"]*)"\s+(.*)'
)
_CM_SG_RE = re.compile(
    r'^CM_\s+SG_\s+(\d+)\s+(\w+)\s+"((?:[^"\\]|\\.)*)"\s*;'
)
_CM_BO_RE = re.compile(
    r'^CM_\s+BO_\s+(\d+)\s+"((?:[^"\\]|\\.)*)"\s*;'
)
_VAL_RE = re.compile(
    r'^VAL_\s+(\d+)\s+(\w+)\s+(.*?)\s*;'
)
_VAL_TABLE_RE = re.compile(
    r'^VAL_TABLE_\s+(\w+)\s+(.*?)\s*;'
)


def parse_dbc_file(filepath: str) -> DBCDatabase:
    """Parse a single DBC file into a DBCDatabase.

    Args:
        filepath: Path to .dbc file

    Returns:
        DBCDatabase with all messages and signals
    """
    db = DBCDatabase(source_files=[os.path.basename(filepath)])
    current_msg: Optional[DBCMessage] = None
    value_tables: Dict[str, Dict[int, str]] = {}

    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    except FileNotFoundError:
        logger.error("DBC file not found: %s", filepath)
        return db

    # First pass: parse value tables
    for m in _VAL_TABLE_RE.finditer(content):
        table_name = m.group(1)
        vals_str = m.group(2)
        value_tables[table_name] = _parse_value_definitions(vals_str)

    # Main parse: line by line
    for line in content.split("\n"):
        line_stripped = line.strip()

        # Message definition
        m = _BO_RE.match(line_stripped)
        if m:
            raw_id = int(m.group(1))
            name = m.group(2)
            dlc = int(m.group(3))
            transmitter = m.group(4)

            # In DBC format, bit 31 flags extended CAN ID
            is_extended = bool(raw_id & 0x80000000)
            can_id = raw_id & 0x1FFFFFFF if is_extended else raw_id

            # Also treat any ID > 0x7FF as extended (29-bit)
            if can_id > 0x7FF:
                is_extended = True

            current_msg = DBCMessage(
                can_id=can_id,
                name=name,
                dlc=dlc,
                transmitter=transmitter,
                is_extended=is_extended,
            )
            db.messages[can_id] = current_msg
            continue

        # Signal definition (must follow a BO_ line)
        m = _SG_RE.match(line)
        if m and current_msg is not None:
            name = m.group(1)
            start_bit = int(m.group(2))
            length = int(m.group(3))
            byte_order = int(m.group(4))
            is_signed = m.group(5) == "-"
            factor = float(m.group(6))
            offset = float(m.group(7))
            minimum = float(m.group(8))
            maximum = float(m.group(9))
            unit = m.group(10)
            receivers = [r.strip() for r in m.group(11).split(",") if r.strip()]

            sig = DBCSignal(
                name=name,
                start_bit=start_bit,
                length=length,
                byte_order=byte_order,
                is_signed=is_signed,
                factor=factor,
                offset=offset,
                minimum=minimum,
                maximum=maximum,
                unit=unit,
                receivers=receivers,
            )
            current_msg.signals[name] = sig
            continue

        # If line doesn't start with whitespace/SG_, reset current msg context
        if line_stripped and not line_stripped.startswith("SG_") and current_msg is not None:
            if not line.startswith(" ") and not line.startswith("\t"):
                current_msg = None

    # Second pass: apply comments
    for m in _CM_SG_RE.finditer(content):
        msg_id = int(m.group(1))
        sig_name = m.group(2)
        comment = m.group(3).replace('\\"', '"')
        if msg_id in db.messages and sig_name in db.messages[msg_id].signals:
            db.messages[msg_id].signals[sig_name].comment = comment

    for m in _CM_BO_RE.finditer(content):
        msg_id = int(m.group(1))
        comment = m.group(2).replace('\\"', '"')
        if msg_id in db.messages:
            db.messages[msg_id].comment = comment

    # Third pass: apply value definitions (VAL_ per signal)
    for m in _VAL_RE.finditer(content):
        msg_id = int(m.group(1))
        sig_name = m.group(2)
        vals_str = m.group(3)
        if msg_id in db.messages and sig_name in db.messages[msg_id].signals:
            vals = _parse_value_definitions(vals_str)
            if vals:
                db.messages[msg_id].signals[sig_name].value_table = vals

    logger.info("Parsed DBC %s: %d messages, %d signals",
                os.path.basename(filepath), db.total_messages, db.total_signals)
    return db


def _parse_value_definitions(vals_str: str) -> Dict[int, str]:
    """Parse value definitions like: 3 "Third" 2 "Second" 1 "First" 0 "Park" """
    result = {}
    # Match pairs of: <integer> "<string>"
    for m in re.finditer(r'(\d+)\s+"([^"]*)"', vals_str):
        result[int(m.group(1))] = m.group(2)
    return result


def merge_databases(*dbs: DBCDatabase) -> DBCDatabase:
    """Merge multiple DBC databases into one. Later DBs override earlier on conflict."""
    merged = DBCDatabase()
    for db in dbs:
        merged.messages.update(db.messages)
        merged.source_files.extend(db.source_files)
    return merged


# ─────────────────────────────────────────────────────────────
# OEM DBC file sets — map manufacturer to relevant DBC files
# ─────────────────────────────────────────────────────────────

# Which DBC files to load for each manufacturer
_OEM_DBC_FILES: Dict[str, List[str]] = {
    "ford": [
        "ford_lincoln_base_pt.dbc",
        "ford_cgea1_2_ptcan_2011.dbc",
        "ford_cgea1_2_bodycan_2011.dbc",
        "ford_fusion_2018_pt.dbc",
        "ford_fusion_2018_adas.dbc",
        "FORD_CADS.dbc",
        "FORD_CADS_64.dbc",
    ],
    "lincoln": [
        "ford_lincoln_base_pt.dbc",
        "ford_cgea1_2_ptcan_2011.dbc",
        "ford_cgea1_2_bodycan_2011.dbc",
    ],
    "gm": [
        "gm_global_a_lowspeed.dbc",
        "gm_global_a_lowspeed_1818125.dbc",
        "gm_global_a_chassis.dbc",
        "gm_global_a_powertrain_expansion.dbc",
        "gm_global_a_object.dbc",
        "gm_global_a_high_voltage_management.dbc",
        "cadillac_ct6_powertrain.dbc",
        "cadillac_ct6_chassis.dbc",
        "cadillac_ct6_object.dbc",
    ],
    "chevrolet": [
        "gm_global_a_lowspeed.dbc",
        "gm_global_a_lowspeed_1818125.dbc",
        "gm_global_a_chassis.dbc",
        "gm_global_a_powertrain_expansion.dbc",
        "gm_global_a_object.dbc",
        "gm_global_a_high_voltage_management.dbc",
    ],
    "gmc": [
        "gm_global_a_lowspeed.dbc",
        "gm_global_a_lowspeed_1818125.dbc",
        "gm_global_a_chassis.dbc",
        "gm_global_a_powertrain_expansion.dbc",
        "gm_global_a_object.dbc",
    ],
    "buick": [
        "gm_global_a_lowspeed.dbc",
        "gm_global_a_lowspeed_1818125.dbc",
        "gm_global_a_chassis.dbc",
        "gm_global_a_powertrain_expansion.dbc",
    ],
    "cadillac": [
        "gm_global_a_lowspeed.dbc",
        "gm_global_a_lowspeed_1818125.dbc",
        "gm_global_a_chassis.dbc",
        "gm_global_a_powertrain_expansion.dbc",
        "gm_global_a_object.dbc",
        "gm_global_a_high_voltage_management.dbc",
        "cadillac_ct6_powertrain.dbc",
        "cadillac_ct6_chassis.dbc",
        "cadillac_ct6_object.dbc",
    ],
    "chrysler": [
        "chrysler_pacifica_2017_hybrid_private_fusion.dbc",
        "chrysler_cusw.dbc",
        "fca_giorgio.dbc",
    ],
    "dodge": [
        "chrysler_pacifica_2017_hybrid_private_fusion.dbc",
        "chrysler_cusw.dbc",
        "fca_giorgio.dbc",
    ],
    "jeep": [
        "chrysler_pacifica_2017_hybrid_private_fusion.dbc",
        "chrysler_cusw.dbc",
        "fca_giorgio.dbc",
    ],
    "ram": [
        "chrysler_pacifica_2017_hybrid_private_fusion.dbc",
        "chrysler_cusw.dbc",
        "fca_giorgio.dbc",
    ],
}

# WMI (first 3 chars of VIN) to manufacturer mapping for auto-detection
_WMI_TO_MAKE: Dict[str, str] = {
    # Ford
    "1FA": "ford", "1FB": "ford", "1FC": "ford", "1FD": "ford",
    "1FM": "ford", "1FT": "ford", "3FA": "ford", "3FE": "ford",
    "MAJ": "ford",
    # Lincoln
    "1LN": "lincoln", "2LM": "lincoln", "5LM": "lincoln",
    # GM / Chevrolet
    "1G1": "chevrolet", "1GC": "chevrolet", "1GN": "chevrolet",
    "2G1": "chevrolet", "3G1": "chevrolet",
    # GMC
    "1GT": "gmc", "2GT": "gmc", "3GT": "gmc",
    # Buick
    "1G4": "buick", "2G4": "buick",
    # Cadillac
    "1G6": "cadillac", "1GY": "cadillac",
    # Chrysler
    "1C3": "chrysler", "2C3": "chrysler", "1C4": "chrysler",
    "2C4": "chrysler",
    # Dodge
    "1B3": "dodge", "2B3": "dodge", "1C6": "dodge", "2C7": "dodge",
    "3C6": "dodge", "3D7": "dodge",
    # Jeep
    "1C4": "jeep", "1J4": "jeep", "1J8": "jeep",
    # Ram
    "1C6": "ram", "3C6": "ram", "3C7": "ram", "3D7": "ram",
}


# Cache loaded databases to avoid re-parsing
_dbc_cache: Dict[str, DBCDatabase] = {}


def load_dbc_for_oem(make: str, dbc_dir: Optional[str] = None) -> DBCDatabase:
    """Load and merge all DBC files for a given OEM/make.

    Args:
        make: Manufacturer name (e.g. "ford", "lincoln", "gm", "chevrolet")
        dbc_dir: Override path to DBC file directory

    Returns:
        Merged DBCDatabase with all relevant messages
    """
    make_lower = make.lower().strip()

    # Check cache
    if make_lower in _dbc_cache:
        return _dbc_cache[make_lower]

    dbc_path = Path(dbc_dir) if dbc_dir else DBC_DIR
    files = _OEM_DBC_FILES.get(make_lower, [])

    if not files:
        logger.warning("No DBC files configured for make: %s", make)
        return DBCDatabase()

    databases = []
    for fname in files:
        fpath = dbc_path / fname
        if fpath.exists():
            db = parse_dbc_file(str(fpath))
            databases.append(db)
        else:
            logger.warning("DBC file not found: %s", fpath)

    if not databases:
        return DBCDatabase()

    merged = merge_databases(*databases)
    _dbc_cache[make_lower] = merged
    logger.info("Loaded DBC for %s: %d messages, %d signals from %d files",
                make_lower, merged.total_messages, merged.total_signals,
                len(databases))
    return merged


def load_dbc_for_vin(vin: str, dbc_dir: Optional[str] = None) -> DBCDatabase:
    """Auto-detect manufacturer from VIN and load appropriate DBC files.

    Args:
        vin: 17-character Vehicle Identification Number
        dbc_dir: Override path to DBC file directory

    Returns:
        DBCDatabase for the detected manufacturer
    """
    if not vin or len(vin) < 3:
        logger.warning("VIN too short for DBC auto-detect: %s", vin)
        return DBCDatabase()

    wmi = vin[:3].upper()
    make = _WMI_TO_MAKE.get(wmi)

    if not make:
        # Try first 2 chars
        wmi2 = vin[:2].upper()
        for k, v in _WMI_TO_MAKE.items():
            if k[:2] == wmi2:
                make = v
                break

    if not make:
        logger.warning("Cannot detect make from VIN %s (WMI=%s)", vin, wmi)
        return DBCDatabase()

    logger.info("VIN %s -> make=%s (WMI=%s)", vin, make, wmi)
    return load_dbc_for_oem(make, dbc_dir)


def clear_dbc_cache():
    """Clear the DBC cache (useful for testing or reload)."""
    _dbc_cache.clear()


# ─────────────────────────────────────────────────────────────
# Broadcast frame decoder — integrates with SnifferCapture
# ─────────────────────────────────────────────────────────────

@dataclass
class DecodedBroadcast:
    """A decoded broadcast CAN message with all signal values."""
    timestamp: float
    can_id: int
    message_name: str
    transmitter: str
    signals: Dict[str, Any]     # signal_name -> decoded value
    raw_data: bytes

    @property
    def can_id_hex(self) -> str:
        return f"0x{self.can_id:03X}"

    def to_dict(self) -> dict:
        return {
            "can_id": self.can_id_hex,
            "message": self.message_name,
            "transmitter": self.transmitter,
            "signals": self.signals,
            "timestamp": self.timestamp,
        }


class LiveBroadcastDecoder:
    """Decodes broadcast CAN frames in real-time using loaded DBC database.

    Tracks the latest value of every decoded signal and provides
    a snapshot of the current vehicle state.
    """

    def __init__(self, dbc: DBCDatabase):
        self.dbc = dbc
        # Latest decoded value for each signal: (msg_name, sig_name) -> value
        self._latest: Dict[Tuple[str, str], Any] = {}
        # Latest units: (msg_name, sig_name) -> unit
        self._units: Dict[Tuple[str, str], str] = {}
        # Timestamps per message
        self._timestamps: Dict[int, float] = {}
        # Message names by CAN ID
        self._msg_names: Dict[int, str] = {}
        # Stats
        self.total_decoded: int = 0
        self.total_unknown: int = 0
        self._unknown_ids: Set[int] = set()

    def decode_frame(self, can_id: int, data: bytes,
                     timestamp: float = 0.0) -> Optional[DecodedBroadcast]:
        """Decode a single CAN frame and update internal state.

        Args:
            can_id: CAN arbitration ID
            data: Raw CAN data bytes
            timestamp: Monotonic timestamp

        Returns:
            DecodedBroadcast if the frame was decoded, else None
        """
        msg = self.dbc.get_message(can_id)
        if msg is None:
            self.total_unknown += 1
            self._unknown_ids.add(can_id)
            return None

        signals = msg.decode(data)
        self.total_decoded += 1
        self._timestamps[can_id] = timestamp
        self._msg_names[can_id] = msg.name

        # Update latest values
        for sig_name, value in signals.items():
            key = (msg.name, sig_name)
            self._latest[key] = value
            if sig_name in msg.signals:
                self._units[key] = msg.signals[sig_name].unit

        return DecodedBroadcast(
            timestamp=timestamp,
            can_id=can_id,
            message_name=msg.name,
            transmitter=msg.transmitter,
            signals=signals,
            raw_data=data,
        )

    def get_snapshot(self) -> Dict[str, Dict[str, Any]]:
        """Get current snapshot of all decoded signal values.

        Returns:
            Dict grouped by message name:
            {
                "WheelSpeed": {
                    "WhlFl_W_Meas": {"value": 32.5, "unit": "rad/s"},
                    "WhlFr_W_Meas": {"value": 32.6, "unit": "rad/s"},
                },
                ...
            }
        """
        snapshot: Dict[str, Dict[str, Any]] = {}
        for (msg_name, sig_name), value in self._latest.items():
            unit = self._units.get((msg_name, sig_name), "")
            msg_signals = snapshot.setdefault(msg_name, {})
            msg_signals[sig_name] = {"value": value, "unit": unit}
        return snapshot

    def get_key_signals(self) -> Dict[str, Any]:
        """Get commonly-requested diagnostic signals as flat dict.

        Returns human-friendly values for the most important signals:
        RPM, vehicle speed, coolant temp, throttle, steering angle, etc.
        """
        result: Dict[str, Any] = {}

        # Define lookups: (friendly_name, [(msg_name_contains, sig_name_contains), ...])
        searches = [
            ("rpm", [("Engine", "EngAout_N_Dsply"), ("Engine", "EngAout_N_Actl"),
                     ("EngVehicleSpThrottle", "EngAout3_N_Actl"),
                     ("PowertrainData", "EngSpd")]),
            ("vehicle_speed_kph", [("BrakeSysFeatures", "Veh_V_ActlBrk"),
                                   ("VehicleSpeed", "VehicleSpeed"),
                                   ("EngVehicleSpThrottle", "Veh_V_ActlEng")]),
            ("throttle_pct", [("EngVehicleSpThrottle", "ApedPos_Pc_ActlArb"),
                              ("GasPedalRegenCruise", "GasPedal")]),
            ("steering_angle_deg", [("SteeringPinion", "StePinComp_An_Est"),
                                    ("SteeringWheelAngle", "SteeringWheelAngle"),
                                    ("BrakeSnData", "SteWhlComp_An_Est")]),
            ("wheel_speed_fl", [("WheelSpeed", "WhlFl_W_Meas"),
                                ("WheelSpeed", "WheelSpeedFL")]),
            ("wheel_speed_fr", [("WheelSpeed", "WhlFr_W_Meas"),
                                ("WheelSpeed", "WheelSpeedFR")]),
            ("wheel_speed_rl", [("WheelSpeed", "WhlRl_W_Meas"),
                                ("WheelSpeed", "WheelSpeedRL")]),
            ("wheel_speed_rr", [("WheelSpeed", "WhlRr_W_Meas"),
                                ("WheelSpeed", "WheelSpeedRR")]),
            ("brake_pressed", [("BrakePedal", "BrakeSensor"),
                               ("EngBrakeData", "BpedDrvAppl_D_Actl")]),
            ("gear", [("PowertrainData", "TrnRng_D_Rq"),
                      ("GearShifter", "GearShifter"),
                      ("Gear", "GearPos_D_Actl")]),
            ("fuel_level_pct", [("Engine", "FuelLvl_Pc_DsplyEng"),
                                ("Fuel", "FuelLvl_Pc_Dsply")]),
            ("cruise_active", [("EngBrakeData", "CcStat_D_Actl"),
                               ("CruiseButtons", "CruiseControlActive")]),
        ]

        for friendly_name, candidates in searches:
            for msg_prefix, sig_name in candidates:
                for (mn, sn), val in self._latest.items():
                    if msg_prefix in mn and sn == sig_name:
                        unit = self._units.get((mn, sn), "")
                        result[friendly_name] = {
                            "value": val,
                            "unit": unit,
                            "source": f"{mn}.{sn}",
                        }
                        break
                if friendly_name in result:
                    break

        return result

    def get_stats(self) -> dict:
        """Get decoder statistics."""
        return {
            "dbc_messages_loaded": self.dbc.total_messages,
            "dbc_signals_loaded": self.dbc.total_signals,
            "frames_decoded": self.total_decoded,
            "frames_unknown": self.total_unknown,
            "unique_decoded_signals": len(self._latest),
            "unique_unknown_ids": len(self._unknown_ids),
            "unknown_ids_sample": sorted(
                [f"0x{x:03X}" for x in list(self._unknown_ids)[:20]]
            ),
        }
