"""
OBD-II PID Definitions and Decoders

Standard PIDs from Mode 01 (current data) with formulas for decoding.

Reference: SAE J1979 / ISO 15031-5
"""

from dataclasses import dataclass
from enum import Enum
from typing import Callable, Dict, List, Optional, Union


class PIDCategory(Enum):
    """PID categories for organization."""
    ENGINE = "engine"
    FUEL = "fuel"
    AIR = "air"
    TEMPERATURE = "temperature"
    SPEED = "speed"
    OXYGEN = "oxygen"
    EMISSIONS = "emissions"
    CATALYST = "catalyst"
    EVAP = "evap"
    FREEZE_FRAME = "freeze_frame"
    VEHICLE_INFO = "vehicle_info"


@dataclass
class PIDDefinition:
    """Definition for an OBD-II PID."""
    pid: int
    name: str
    description: str
    bytes: int
    unit: str
    min_value: float
    max_value: float
    formula: Callable[[bytes], float]
    category: PIDCategory
    
    # Optional: alternate names for this PID
    aliases: List[str] = None
    
    def decode(self, data: bytes) -> float:
        """Decode raw bytes to value using formula."""
        if len(data) < self.bytes:
            raise ValueError(f"Expected {self.bytes} bytes, got {len(data)}")
        return self.formula(data[:self.bytes])


# Standard OBD-II PIDs (Mode 01)
# Format: PID -> PIDDefinition

PID_DEFINITIONS: Dict[int, PIDDefinition] = {}


def register_pid(
    pid: int,
    name: str,
    description: str,
    num_bytes: int,
    unit: str,
    min_val: float,
    max_val: float,
    formula: Callable[[bytes], float],
    category: PIDCategory,
    aliases: List[str] = None
) -> PIDDefinition:
    """Register a PID definition."""
    defn = PIDDefinition(
        pid=pid,
        name=name,
        description=description,
        bytes=num_bytes,
        unit=unit,
        min_value=min_val,
        max_value=max_val,
        formula=formula,
        category=category,
        aliases=aliases or []
    )
    PID_DEFINITIONS[pid] = defn
    return defn


# -----------------------------------------------------------------------------
# Engine PIDs
# -----------------------------------------------------------------------------

register_pid(
    pid=0x04,
    name="LOAD",
    description="Calculated Engine Load",
    num_bytes=1,
    unit="%",
    min_val=0,
    max_val=100,
    formula=lambda d: d[0] * 100 / 255,
    category=PIDCategory.ENGINE,
    aliases=["ENGINE_LOAD", "CALC_LOAD"]
)

register_pid(
    pid=0x0C,
    name="RPM",
    description="Engine RPM",
    num_bytes=2,
    unit="rpm",
    min_val=0,
    max_val=16383.75,
    formula=lambda d: ((d[0] * 256) + d[1]) / 4,
    category=PIDCategory.ENGINE,
    aliases=["ENGINE_RPM"]
)

register_pid(
    pid=0x0E,
    name="TIMING_ADV",
    description="Timing Advance",
    num_bytes=1,
    unit="degrees BTDC",
    min_val=-64,
    max_val=63.5,
    formula=lambda d: (d[0] / 2) - 64,
    category=PIDCategory.ENGINE,
    aliases=["TIMING_ADVANCE", "SPARK_ADV"]
)

register_pid(
    pid=0x11,
    name="THROTTLE_POS",
    description="Throttle Position",
    num_bytes=1,
    unit="%",
    min_val=0,
    max_val=100,
    formula=lambda d: d[0] * 100 / 255,
    category=PIDCategory.ENGINE,
    aliases=["TPS", "THROTTLE"]
)

register_pid(
    pid=0x1F,
    name="RUN_TIME",
    description="Run Time Since Engine Start",
    num_bytes=2,
    unit="seconds",
    min_val=0,
    max_val=65535,
    formula=lambda d: (d[0] * 256) + d[1],
    category=PIDCategory.ENGINE,
    aliases=["ENGINE_RUN_TIME"]
)

register_pid(
    pid=0x21,
    name="DIST_MIL_ON",
    description="Distance Traveled With MIL On",
    num_bytes=2,
    unit="km",
    min_val=0,
    max_val=65535,
    formula=lambda d: (d[0] * 256) + d[1],
    category=PIDCategory.ENGINE
)

register_pid(
    pid=0x31,
    name="DIST_CLR",
    description="Distance Since DTCs Cleared",
    num_bytes=2,
    unit="km",
    min_val=0,
    max_val=65535,
    formula=lambda d: (d[0] * 256) + d[1],
    category=PIDCategory.ENGINE
)

# -----------------------------------------------------------------------------
# Temperature PIDs
# -----------------------------------------------------------------------------

register_pid(
    pid=0x05,
    name="COOLANT_TEMP",
    description="Engine Coolant Temperature",
    num_bytes=1,
    unit="°C",
    min_val=-40,
    max_val=215,
    formula=lambda d: d[0] - 40,
    category=PIDCategory.TEMPERATURE,
    aliases=["ECT", "COOLANT"]
)

register_pid(
    pid=0x0F,
    name="IAT",
    description="Intake Air Temperature",
    num_bytes=1,
    unit="°C",
    min_val=-40,
    max_val=215,
    formula=lambda d: d[0] - 40,
    category=PIDCategory.TEMPERATURE,
    aliases=["INTAKE_TEMP", "INTAKE_AIR_TEMP"]
)

register_pid(
    pid=0x46,
    name="AMBIENT_TEMP",
    description="Ambient Air Temperature",
    num_bytes=1,
    unit="°C",
    min_val=-40,
    max_val=215,
    formula=lambda d: d[0] - 40,
    category=PIDCategory.TEMPERATURE,
    aliases=["AAT", "OUTSIDE_TEMP"]
)

register_pid(
    pid=0x5C,
    name="OIL_TEMP",
    description="Engine Oil Temperature",
    num_bytes=1,
    unit="°C",
    min_val=-40,
    max_val=210,
    formula=lambda d: d[0] - 40,
    category=PIDCategory.TEMPERATURE,
    aliases=["EOT"]
)

# -----------------------------------------------------------------------------
# Fuel System PIDs
# -----------------------------------------------------------------------------

register_pid(
    pid=0x03,
    name="FUEL_STATUS",
    description="Fuel System Status",
    num_bytes=2,
    unit="",
    min_val=0,
    max_val=255,
    formula=lambda d: d[0],  # Returns status code
    category=PIDCategory.FUEL
)

register_pid(
    pid=0x06,
    name="STFT_B1",
    description="Short Term Fuel Trim - Bank 1",
    num_bytes=1,
    unit="%",
    min_val=-100,
    max_val=99.2,
    formula=lambda d: (d[0] - 128) * 100 / 128,
    category=PIDCategory.FUEL,
    aliases=["STFT1", "SHORT_FUEL_TRIM_1"]
)

register_pid(
    pid=0x07,
    name="LTFT_B1",
    description="Long Term Fuel Trim - Bank 1",
    num_bytes=1,
    unit="%",
    min_val=-100,
    max_val=99.2,
    formula=lambda d: (d[0] - 128) * 100 / 128,
    category=PIDCategory.FUEL,
    aliases=["LTFT1", "LONG_FUEL_TRIM_1"]
)

register_pid(
    pid=0x08,
    name="STFT_B2",
    description="Short Term Fuel Trim - Bank 2",
    num_bytes=1,
    unit="%",
    min_val=-100,
    max_val=99.2,
    formula=lambda d: (d[0] - 128) * 100 / 128,
    category=PIDCategory.FUEL,
    aliases=["STFT2", "SHORT_FUEL_TRIM_2"]
)

register_pid(
    pid=0x09,
    name="LTFT_B2",
    description="Long Term Fuel Trim - Bank 2",
    num_bytes=1,
    unit="%",
    min_val=-100,
    max_val=99.2,
    formula=lambda d: (d[0] - 128) * 100 / 128,
    category=PIDCategory.FUEL,
    aliases=["LTFT2", "LONG_FUEL_TRIM_2"]
)

register_pid(
    pid=0x0A,
    name="FUEL_PRESSURE",
    description="Fuel Pressure (gauge)",
    num_bytes=1,
    unit="kPa",
    min_val=0,
    max_val=765,
    formula=lambda d: d[0] * 3,
    category=PIDCategory.FUEL,
    aliases=["FP"]
)

register_pid(
    pid=0x2F,
    name="FUEL_LEVEL",
    description="Fuel Tank Level Input",
    num_bytes=1,
    unit="%",
    min_val=0,
    max_val=100,
    formula=lambda d: d[0] * 100 / 255,
    category=PIDCategory.FUEL
)

register_pid(
    pid=0x23,
    name="FUEL_RAIL_PRESSURE",
    description="Fuel Rail Gauge Pressure",
    num_bytes=2,
    unit="kPa",
    min_val=0,
    max_val=655350,
    formula=lambda d: ((d[0] * 256) + d[1]) * 10,
    category=PIDCategory.FUEL,
    aliases=["FRP"]
)

register_pid(
    pid=0x59,
    name="FUEL_RAIL_ABS",
    description="Fuel Rail Absolute Pressure",
    num_bytes=2,
    unit="kPa",
    min_val=0,
    max_val=655350,
    formula=lambda d: ((d[0] * 256) + d[1]) * 10,
    category=PIDCategory.FUEL
)

# -----------------------------------------------------------------------------
# Air Flow PIDs
# -----------------------------------------------------------------------------

register_pid(
    pid=0x0B,
    name="MAP",
    description="Intake Manifold Absolute Pressure",
    num_bytes=1,
    unit="kPa",
    min_val=0,
    max_val=255,
    formula=lambda d: d[0],
    category=PIDCategory.AIR,
    aliases=["INTAKE_PRESSURE", "MANIFOLD_PRESSURE"]
)

register_pid(
    pid=0x10,
    name="MAF",
    description="Mass Air Flow Rate",
    num_bytes=2,
    unit="g/s",
    min_val=0,
    max_val=655.35,
    formula=lambda d: ((d[0] * 256) + d[1]) / 100,
    category=PIDCategory.AIR,
    aliases=["MAF_RATE", "AIR_FLOW"]
)

register_pid(
    pid=0x33,
    name="BARO",
    description="Barometric Pressure",
    num_bytes=1,
    unit="kPa",
    min_val=0,
    max_val=255,
    formula=lambda d: d[0],
    category=PIDCategory.AIR,
    aliases=["BAROMETRIC_PRESSURE"]
)

# -----------------------------------------------------------------------------
# Speed PIDs
# -----------------------------------------------------------------------------

register_pid(
    pid=0x0D,
    name="SPEED",
    description="Vehicle Speed",
    num_bytes=1,
    unit="km/h",
    min_val=0,
    max_val=255,
    formula=lambda d: d[0],
    category=PIDCategory.SPEED,
    aliases=["VSS", "VEHICLE_SPEED"]
)

# -----------------------------------------------------------------------------
# Oxygen Sensor PIDs
# -----------------------------------------------------------------------------

register_pid(
    pid=0x14,
    name="O2_B1S1",
    description="O2 Sensor Voltage - Bank 1, Sensor 1",
    num_bytes=2,
    unit="V",
    min_val=0,
    max_val=1.275,
    formula=lambda d: d[0] / 200,  # First byte is voltage
    category=PIDCategory.OXYGEN,
    aliases=["O2_11"]
)

register_pid(
    pid=0x15,
    name="O2_B1S2",
    description="O2 Sensor Voltage - Bank 1, Sensor 2",
    num_bytes=2,
    unit="V",
    min_val=0,
    max_val=1.275,
    formula=lambda d: d[0] / 200,
    category=PIDCategory.OXYGEN,
    aliases=["O2_12"]
)

register_pid(
    pid=0x16,
    name="O2_B1S3",
    description="O2 Sensor Voltage - Bank 1, Sensor 3",
    num_bytes=2,
    unit="V",
    min_val=0,
    max_val=1.275,
    formula=lambda d: d[0] / 200,
    category=PIDCategory.OXYGEN
)

register_pid(
    pid=0x17,
    name="O2_B1S4",
    description="O2 Sensor Voltage - Bank 1, Sensor 4",
    num_bytes=2,
    unit="V",
    min_val=0,
    max_val=1.275,
    formula=lambda d: d[0] / 200,
    category=PIDCategory.OXYGEN
)

register_pid(
    pid=0x18,
    name="O2_B2S1",
    description="O2 Sensor Voltage - Bank 2, Sensor 1",
    num_bytes=2,
    unit="V",
    min_val=0,
    max_val=1.275,
    formula=lambda d: d[0] / 200,
    category=PIDCategory.OXYGEN,
    aliases=["O2_21"]
)

register_pid(
    pid=0x19,
    name="O2_B2S2",
    description="O2 Sensor Voltage - Bank 2, Sensor 2",
    num_bytes=2,
    unit="V",
    min_val=0,
    max_val=1.275,
    formula=lambda d: d[0] / 200,
    category=PIDCategory.OXYGEN,
    aliases=["O2_22"]
)

# Wide-band O2 sensors (air-fuel ratio)
register_pid(
    pid=0x24,
    name="AFR_B1S1",
    description="Air-Fuel Ratio - Bank 1, Sensor 1",
    num_bytes=4,
    unit="lambda",
    min_val=0,
    max_val=2,
    formula=lambda d: (((d[0] * 256) + d[1]) * 2 / 65536),
    category=PIDCategory.OXYGEN,
    aliases=["LAMBDA_B1S1", "WIDEBAND_B1S1"]
)

register_pid(
    pid=0x25,
    name="AFR_B1S2",
    description="Air-Fuel Ratio - Bank 1, Sensor 2",
    num_bytes=4,
    unit="lambda",
    min_val=0,
    max_val=2,
    formula=lambda d: (((d[0] * 256) + d[1]) * 2 / 65536),
    category=PIDCategory.OXYGEN
)

# -----------------------------------------------------------------------------
# Catalyst PIDs
# -----------------------------------------------------------------------------

register_pid(
    pid=0x3C,
    name="CAT_TEMP_B1S1",
    description="Catalyst Temperature - Bank 1, Sensor 1",
    num_bytes=2,
    unit="°C",
    min_val=-40,
    max_val=6513.5,
    formula=lambda d: (((d[0] * 256) + d[1]) / 10) - 40,
    category=PIDCategory.CATALYST
)

register_pid(
    pid=0x3D,
    name="CAT_TEMP_B2S1",
    description="Catalyst Temperature - Bank 2, Sensor 1",
    num_bytes=2,
    unit="°C",
    min_val=-40,
    max_val=6513.5,
    formula=lambda d: (((d[0] * 256) + d[1]) / 10) - 40,
    category=PIDCategory.CATALYST
)

register_pid(
    pid=0x3E,
    name="CAT_TEMP_B1S2",
    description="Catalyst Temperature - Bank 1, Sensor 2",
    num_bytes=2,
    unit="°C",
    min_val=-40,
    max_val=6513.5,
    formula=lambda d: (((d[0] * 256) + d[1]) / 10) - 40,
    category=PIDCategory.CATALYST
)

register_pid(
    pid=0x3F,
    name="CAT_TEMP_B2S2",
    description="Catalyst Temperature - Bank 2, Sensor 2",
    num_bytes=2,
    unit="°C",
    min_val=-40,
    max_val=6513.5,
    formula=lambda d: (((d[0] * 256) + d[1]) / 10) - 40,
    category=PIDCategory.CATALYST
)

# -----------------------------------------------------------------------------
# EVAP System PIDs
# -----------------------------------------------------------------------------

register_pid(
    pid=0x32,
    name="EVAP_PURGE",
    description="Commanded Evaporative Purge",
    num_bytes=1,
    unit="%",
    min_val=0,
    max_val=100,
    formula=lambda d: d[0] * 100 / 255,
    category=PIDCategory.EVAP,
    aliases=["EVAP_PCT"]
)

register_pid(
    pid=0x2E,
    name="EVAP_VP",
    description="Commanded Evaporative Vent",
    num_bytes=1,
    unit="%",
    min_val=0,
    max_val=100,
    formula=lambda d: d[0] * 100 / 255,
    category=PIDCategory.EVAP
)

# -----------------------------------------------------------------------------
# Battery / Charging PIDs  
# -----------------------------------------------------------------------------

register_pid(
    pid=0x42,
    name="VOLTAGE",
    description="Control Module Voltage",
    num_bytes=2,
    unit="V",
    min_val=0,
    max_val=65.535,
    formula=lambda d: ((d[0] * 256) + d[1]) / 1000,
    category=PIDCategory.ENGINE,
    aliases=["BATTERY_VOLTAGE", "CTRL_MOD_VOLTAGE"]
)

register_pid(
    pid=0x43,
    name="ABS_LOAD",
    description="Absolute Load Value",
    num_bytes=2,
    unit="%",
    min_val=0,
    max_val=25700,
    formula=lambda d: ((d[0] * 256) + d[1]) * 100 / 255,
    category=PIDCategory.ENGINE
)

# -----------------------------------------------------------------------------
# Status / Metadata PIDs
# -----------------------------------------------------------------------------

register_pid(
    pid=0x01,
    name="MONITOR_STATUS",
    description="Monitor Status Since DTCs Cleared (MIL, DTC count, readiness)",
    num_bytes=4,
    unit="",
    min_val=0,
    max_val=0,
    formula=lambda d: (d[0] * 16777216) + (d[1] * 65536) + (d[2] * 256) + d[3],
    category=PIDCategory.ENGINE,
    aliases=["MIL_STATUS", "DTC_STATUS"]
)

register_pid(
    pid=0x13,
    name="O2_SENSORS_PRESENT",
    description="Oxygen Sensors Present (2 banks)",
    num_bytes=1,
    unit="",
    min_val=0,
    max_val=255,
    formula=lambda d: d[0],
    category=PIDCategory.OXYGEN
)

register_pid(
    pid=0x1C,
    name="OBD_STANDARD",
    description="OBD Standards This Vehicle Conforms To",
    num_bytes=1,
    unit="",
    min_val=0,
    max_val=255,
    formula=lambda d: d[0],
    category=PIDCategory.VEHICLE_INFO,
    aliases=["OBD_COMPLIANCE"]
)

register_pid(
    pid=0x41,
    name="MONITOR_STATUS_DRIVE",
    description="Monitor Status This Drive Cycle",
    num_bytes=4,
    unit="",
    min_val=0,
    max_val=0,
    formula=lambda d: (d[0] * 16777216) + (d[1] * 65536) + (d[2] * 256) + d[3],
    category=PIDCategory.ENGINE,
    aliases=["DRIVE_MONITOR"]
)

register_pid(
    pid=0x51,
    name="FUEL_TYPE",
    description="Fuel Type (gasoline, diesel, hybrid, etc.)",
    num_bytes=1,
    unit="",
    min_val=0,
    max_val=255,
    formula=lambda d: d[0],
    category=PIDCategory.FUEL
)

# -----------------------------------------------------------------------------
# Throttle / Pedal PIDs
# -----------------------------------------------------------------------------

register_pid(
    pid=0x45,
    name="REL_THROTTLE_POS",
    description="Relative Throttle Position",
    num_bytes=1,
    unit="%",
    min_val=0,
    max_val=100,
    formula=lambda d: d[0] * 100 / 255,
    category=PIDCategory.ENGINE,
    aliases=["RELATIVE_THROTTLE"]
)

register_pid(
    pid=0x47,
    name="ABS_THROTTLE_B",
    description="Absolute Throttle Position B",
    num_bytes=1,
    unit="%",
    min_val=0,
    max_val=100,
    formula=lambda d: d[0] * 100 / 255,
    category=PIDCategory.ENGINE,
    aliases=["THROTTLE_POS_B"]
)

register_pid(
    pid=0x49,
    name="ACCEL_POS_D",
    description="Accelerator Pedal Position D",
    num_bytes=1,
    unit="%",
    min_val=0,
    max_val=100,
    formula=lambda d: d[0] * 100 / 255,
    category=PIDCategory.ENGINE,
    aliases=["PEDAL_D", "APP_D"]
)

register_pid(
    pid=0x4A,
    name="ACCEL_POS_E",
    description="Accelerator Pedal Position E",
    num_bytes=1,
    unit="%",
    min_val=0,
    max_val=100,
    formula=lambda d: d[0] * 100 / 255,
    category=PIDCategory.ENGINE,
    aliases=["PEDAL_E", "APP_E"]
)

register_pid(
    pid=0x4C,
    name="CMD_THROTTLE",
    description="Commanded Throttle Actuator",
    num_bytes=1,
    unit="%",
    min_val=0,
    max_val=100,
    formula=lambda d: d[0] * 100 / 255,
    category=PIDCategory.ENGINE,
    aliases=["COMMANDED_THROTTLE"]
)

# -----------------------------------------------------------------------------
# EGR / Emissions PIDs
# -----------------------------------------------------------------------------

register_pid(
    pid=0x2C,
    name="CMD_EGR",
    description="Commanded EGR",
    num_bytes=1,
    unit="%",
    min_val=0,
    max_val=100,
    formula=lambda d: d[0] * 100 / 255,
    category=PIDCategory.EMISSIONS,
    aliases=["EGR", "COMMANDED_EGR"]
)

register_pid(
    pid=0x30,
    name="WARMUPS_CLR",
    description="Warm-ups Since Codes Cleared",
    num_bytes=1,
    unit="count",
    min_val=0,
    max_val=255,
    formula=lambda d: d[0],
    category=PIDCategory.EMISSIONS,
    aliases=["WARMUPS_SINCE_CLEAR"]
)

register_pid(
    pid=0x44,
    name="CMD_EQUIV_RATIO",
    description="Fuel-Air Commanded Equivalence Ratio",
    num_bytes=2,
    unit="lambda",
    min_val=0,
    max_val=2,
    formula=lambda d: ((d[0] * 256) + d[1]) * 2 / 65536,
    category=PIDCategory.FUEL,
    aliases=["LAMBDA", "EQUIV_RATIO"]
)

# Wide-band O2 with current (Mode $06 style)
register_pid(
    pid=0x34,
    name="O2_B1S1_WR",
    description="O2 Sensor 1 - Fuel-Air Equiv. Ratio & Current",
    num_bytes=4,
    unit="lambda",
    min_val=0,
    max_val=2,
    formula=lambda d: ((d[0] * 256) + d[1]) * 2 / 65536,
    category=PIDCategory.OXYGEN,
    aliases=["WIDEBAND_O2_B1S1"]
)

# Supported PIDs bitmaps (0x00, 0x20, 0x40 — metadata, not real data)
# We register them so they get names but they're system PIDs
register_pid(
    pid=0x20,
    name="PIDS_SUPPORTED_21_40",
    description="PIDs Supported [21-40] (bitmap)",
    num_bytes=4,
    unit="",
    min_val=0,
    max_val=0,
    formula=lambda d: (d[0] * 16777216) + (d[1] * 65536) + (d[2] * 256) + d[3],
    category=PIDCategory.VEHICLE_INFO
)

register_pid(
    pid=0x40,
    name="PIDS_SUPPORTED_41_60",
    description="PIDs Supported [41-60] (bitmap)",
    num_bytes=4,
    unit="",
    min_val=0,
    max_val=0,
    formula=lambda d: (d[0] * 16777216) + (d[1] * 65536) + (d[2] * 256) + d[3],
    category=PIDCategory.VEHICLE_INFO
)

# -----------------------------------------------------------------------------
# Helper Functions
# -----------------------------------------------------------------------------

# Name/alias to PID mapping for easy lookup
_NAME_TO_PID: Dict[str, int] = {}

def _build_name_map():
    """Build name to PID lookup map."""
    global _NAME_TO_PID
    for pid, defn in PID_DEFINITIONS.items():
        _NAME_TO_PID[defn.name.upper()] = pid
        if defn.aliases:
            for alias in defn.aliases:
                _NAME_TO_PID[alias.upper()] = pid

_build_name_map()


def get_pid_by_name(name: str) -> Optional[int]:
    """
    Get PID number by name or alias.
    
    Args:
        name: PID name or alias (case-insensitive)
        
    Returns:
        PID number or None if not found
    """
    return _NAME_TO_PID.get(name.upper())


def decode_pid(pid: int, data: bytes) -> Optional[float]:
    """
    Decode raw PID data to value.
    
    Args:
        pid: PID number
        data: Raw response bytes
        
    Returns:
        Decoded value or None if PID unknown
    """
    defn = PID_DEFINITIONS.get(pid)
    if defn:
        return defn.decode(data)
    return None


def get_pid_info(pid: int) -> Optional[PIDDefinition]:
    """Get PID definition by number."""
    return PID_DEFINITIONS.get(pid)


def get_pid_unit(pid: int) -> str:
    """Get unit string for a PID."""
    defn = PID_DEFINITIONS.get(pid)
    return defn.unit if defn else ""


def list_pids_by_category(category: PIDCategory) -> List[PIDDefinition]:
    """Get all PIDs in a category."""
    return [d for d in PID_DEFINITIONS.values() if d.category == category]


class PIDRegistry:
    """Registry for accessing PID definitions."""
    
    @staticmethod
    def get(pid: Union[int, str]) -> Optional[PIDDefinition]:
        """
        Get PID definition by number or name.
        
        Args:
            pid: PID number (int) or name/alias (str)
            
        Returns:
            PIDDefinition or None
        """
        if isinstance(pid, str):
            pid_num = get_pid_by_name(pid)
            if pid_num is None:
                return None
            return PID_DEFINITIONS.get(pid_num)
        return PID_DEFINITIONS.get(pid)
    
    @staticmethod
    def decode(pid: Union[int, str], data: bytes) -> Optional[float]:
        """
        Decode raw data using PID definition.
        
        Args:
            pid: PID number or name
            data: Raw response bytes
            
        Returns:
            Decoded value
        """
        defn = PIDRegistry.get(pid)
        if defn:
            return defn.decode(data)
        return None
    
    @staticmethod
    def list_all() -> List[PIDDefinition]:
        """List all registered PIDs."""
        return list(PID_DEFINITIONS.values())
    
    @staticmethod
    def list_names() -> List[str]:
        """List all PID names."""
        return [d.name for d in PID_DEFINITIONS.values()]


# Common PID groups for diagnostic scenarios
FUEL_TRIM_PIDS = [0x06, 0x07, 0x08, 0x09]  # STFT/LTFT Bank 1 & 2
OXYGEN_PIDS = [0x14, 0x15, 0x18, 0x19, 0x24, 0x25]  # O2 sensors
TEMPERATURE_PIDS = [0x05, 0x0F, 0x46, 0x5C]  # Coolant, IAT, Ambient, Oil
ENGINE_PIDS = [0x04, 0x0C, 0x0E, 0x11]  # Load, RPM, Timing, Throttle
AIR_PIDS = [0x0B, 0x10, 0x33]  # MAP, MAF, Baro

# Diagnostic snapshot - comprehensive PID list
DIAGNOSTIC_SNAPSHOT_PIDS = [
    0x04,  # Load
    0x05,  # Coolant temp
    0x06,  # STFT B1
    0x07,  # LTFT B1
    0x08,  # STFT B2
    0x09,  # LTFT B2
    0x0B,  # MAP
    0x0C,  # RPM
    0x0D,  # Speed
    0x0E,  # Timing advance
    0x0F,  # IAT
    0x10,  # MAF
    0x11,  # Throttle
    0x14,  # O2 B1S1
    0x15,  # O2 B1S2
    0x42,  # Voltage
]
