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
    MILEAGE = "mileage"
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
    category=PIDCategory.MILEAGE,
    aliases=["DISTANCE_MIL", "MIL_DISTANCE"]
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
    category=PIDCategory.MILEAGE,
    aliases=["DISTANCE_CLR", "MILEAGE_SINCE_CLEAR"]
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
    description="Evaporative System Vapor Pressure",
    num_bytes=2,
    unit="Pa",
    min_val=-8192,
    max_val=8191.75,
    formula=lambda d: int.from_bytes(d[:2], 'big', signed=True) / 4,
    category=PIDCategory.EVAP,
    aliases=["EVAP_VAPOR_PRESSURE"]
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

# -----------------------------------------------------------------------------
# Throttle / Pedal PIDs (extended)
# -----------------------------------------------------------------------------

register_pid(
    pid=0x48,
    name="ABS_THROTTLE_C",
    description="Absolute Throttle Position C",
    num_bytes=1,
    unit="%",
    min_val=0,
    max_val=100,
    formula=lambda d: d[0] * 100 / 255,
    category=PIDCategory.ENGINE,
    aliases=["THROTTLE_POS_C"]
)

register_pid(
    pid=0x5A,
    name="REL_ACCEL_POS",
    description="Relative Accelerator Pedal Position",
    num_bytes=1,
    unit="%",
    min_val=0,
    max_val=100,
    formula=lambda d: d[0] * 100 / 255,
    category=PIDCategory.ENGINE,
    aliases=["RELATIVE_ACCEL", "REL_PEDAL_POS"]
)

# -----------------------------------------------------------------------------
# Time / Distance PIDs
# -----------------------------------------------------------------------------

register_pid(
    pid=0x4D,
    name="TIME_MIL_ON",
    description="Time Run With MIL On",
    num_bytes=2,
    unit="minutes",
    min_val=0,
    max_val=65535,
    formula=lambda d: (d[0] * 256) + d[1],
    category=PIDCategory.MILEAGE,
    aliases=["MIL_TIME", "TIME_WITH_MIL"]
)

register_pid(
    pid=0x4E,
    name="TIME_SINCE_CLR",
    description="Time Since Trouble Codes Cleared",
    num_bytes=2,
    unit="minutes",
    min_val=0,
    max_val=65535,
    formula=lambda d: (d[0] * 256) + d[1],
    category=PIDCategory.MILEAGE,
    aliases=["TIME_SINCE_CLEAR", "CLR_TIME"]
)

register_pid(
    pid=0xA6,
    name="ODOMETER",
    description="Odometer (Total Vehicle Distance)",
    num_bytes=4,
    unit="km",
    min_val=0,
    max_val=429496729.5,
    formula=lambda d: ((d[0] * 16777216) + (d[1] * 65536) + (d[2] * 256) + d[3]) / 10,
    category=PIDCategory.MILEAGE,
    aliases=["TOTAL_DISTANCE", "VEHICLE_DISTANCE", "MILEAGE"]
)

# -----------------------------------------------------------------------------
# Engine Torque PIDs
# -----------------------------------------------------------------------------

register_pid(
    pid=0x61,
    name="DRIVER_TORQUE_DEMAND",
    description="Driver's Demand Engine - Percent Torque",
    num_bytes=1,
    unit="%",
    min_val=-125,
    max_val=130,
    formula=lambda d: d[0] - 125,
    category=PIDCategory.ENGINE,
    aliases=["DEMAND_TORQUE", "DRIVER_TORQUE"]
)

register_pid(
    pid=0x62,
    name="ACTUAL_TORQUE",
    description="Actual Engine - Percent Torque",
    num_bytes=1,
    unit="%",
    min_val=-125,
    max_val=130,
    formula=lambda d: d[0] - 125,
    category=PIDCategory.ENGINE,
    aliases=["ENGINE_TORQUE", "TORQUE_PCT"]
)

register_pid(
    pid=0x63,
    name="REF_TORQUE",
    description="Engine Reference Torque",
    num_bytes=2,
    unit="Nm",
    min_val=0,
    max_val=65535,
    formula=lambda d: (d[0] * 256) + d[1],
    category=PIDCategory.ENGINE,
    aliases=["REFERENCE_TORQUE", "MAX_TORQUE"]
)

# -----------------------------------------------------------------------------
# Fuel Rate PIDs
# -----------------------------------------------------------------------------

register_pid(
    pid=0x5E,
    name="FUEL_RATE",
    description="Engine Fuel Rate",
    num_bytes=2,
    unit="L/h",
    min_val=0,
    max_val=3276.75,
    formula=lambda d: ((d[0] * 256) + d[1]) / 20,
    category=PIDCategory.FUEL,
    aliases=["ENGINE_FUEL_RATE", "FUEL_CONSUMPTION"]
)

# -----------------------------------------------------------------------------
# Extended EVAP PIDs
# -----------------------------------------------------------------------------

register_pid(
    pid=0x53,
    name="EVAP_ABS_VP",
    description="Absolute Evap System Vapor Pressure",
    num_bytes=2,
    unit="kPa",
    min_val=0,
    max_val=327.675,
    formula=lambda d: ((d[0] * 256) + d[1]) / 200,
    category=PIDCategory.EVAP,
    aliases=["ABS_EVAP_PRESSURE"]
)

register_pid(
    pid=0x54,
    name="EVAP_VP_ALT",
    description="Evap System Vapor Pressure (wide range)",
    num_bytes=2,
    unit="Pa",
    min_val=-32767,
    max_val=32768,
    formula=lambda d: int.from_bytes(d[:2], 'big', signed=True),
    category=PIDCategory.EVAP,
    aliases=["EVAP_PRESSURE_WIDE"]
)

# -----------------------------------------------------------------------------
# Hybrid / EV PIDs (for future use)
# -----------------------------------------------------------------------------

register_pid(
    pid=0x5B,
    name="HYBRID_BATTERY_LIFE",
    description="Hybrid Battery Pack Remaining Life",
    num_bytes=1,
    unit="%",
    min_val=0,
    max_val=100,
    formula=lambda d: d[0] * 100 / 255,
    category=PIDCategory.ENGINE,
    aliases=["HV_BATTERY_LIFE", "BATTERY_SOH"]
)

# -----------------------------------------------------------------------------
# Additional Missing Standard PIDs (0x00 - 0x5F)
# Reference: SAE J1979 / ISO 15031-5
# -----------------------------------------------------------------------------

register_pid(
    pid=0x02,
    name="FREEZE_DTC",
    description="Freeze DTC",
    num_bytes=2,
    unit="",
    min_val=0,
    max_val=65535,
    formula=lambda d: (d[0] * 256) + d[1],
    category=PIDCategory.FREEZE_FRAME,
    aliases=["DTC_FREEZE_FRAME"],
)

register_pid(
    pid=0x12,
    name="AIR_STATUS",
    description="Commanded Secondary Air Status",
    num_bytes=1,
    unit="encoded",
    min_val=0,
    max_val=255,
    formula=lambda d: d[0],
    category=PIDCategory.AIR,
    aliases=["SEC_AIR_STATUS", "SECONDARY_AIR"],
)

register_pid(
    pid=0x1A,
    name="O2_B2S3",
    description="O2 Bank 2 Sensor 3 Voltage",
    num_bytes=2,
    unit="V",
    min_val=0,
    max_val=1.275,
    formula=lambda d: d[0] / 200.0,
    category=PIDCategory.OXYGEN,
    aliases=["O2_BANK2_SENSOR3"],
)

register_pid(
    pid=0x1B,
    name="O2_B2S4",
    description="O2 Bank 2 Sensor 4 Voltage",
    num_bytes=2,
    unit="V",
    min_val=0,
    max_val=1.275,
    formula=lambda d: d[0] / 200.0,
    category=PIDCategory.OXYGEN,
    aliases=["O2_BANK2_SENSOR4"],
)

register_pid(
    pid=0x1D,
    name="O2_SENSORS_ALT",
    description="O2 Sensors Present (alternate)",
    num_bytes=1,
    unit="encoded",
    min_val=0,
    max_val=255,
    formula=lambda d: d[0],
    category=PIDCategory.OXYGEN,
    aliases=["O2_SENSORS_PRESENT_ALT"],
)

register_pid(
    pid=0x1E,
    name="AUX_INPUT",
    description="Auxiliary Input Status",
    num_bytes=1,
    unit="",
    min_val=0,
    max_val=1,
    formula=lambda d: d[0] & 0x01,
    category=PIDCategory.ENGINE,
    aliases=["AUX_INPUT_STATUS", "PTO_STATUS"],
)

register_pid(
    pid=0x22,
    name="FUEL_RAIL_PRESSURE_VAC",
    description="Fuel Rail Pressure (relative to vacuum)",
    num_bytes=2,
    unit="kPa",
    min_val=0,
    max_val=5177.265,
    formula=lambda d: ((d[0] * 256) + d[1]) * 0.079,
    category=PIDCategory.FUEL,
    aliases=["FRP_VAC", "FUEL_RAIL_PRESS_VAC"],
)

register_pid(
    pid=0x26,
    name="O2_S3_WR_VOLTAGE",
    description="O2 Sensor 3 WR Lambda Voltage",
    num_bytes=4,
    unit="V",
    min_val=0,
    max_val=7.999,
    formula=lambda d: ((d[2] * 256) + d[3]) * 8.0 / 65535,
    category=PIDCategory.OXYGEN,
    aliases=["O2_S3_WR_V"],
)

register_pid(
    pid=0x27,
    name="O2_S4_WR_VOLTAGE",
    description="O2 Sensor 4 WR Lambda Voltage",
    num_bytes=4,
    unit="V",
    min_val=0,
    max_val=7.999,
    formula=lambda d: ((d[2] * 256) + d[3]) * 8.0 / 65535,
    category=PIDCategory.OXYGEN,
)

register_pid(
    pid=0x28,
    name="O2_S5_WR_VOLTAGE",
    description="O2 Sensor 5 WR Lambda Voltage",
    num_bytes=4,
    unit="V",
    min_val=0,
    max_val=7.999,
    formula=lambda d: ((d[2] * 256) + d[3]) * 8.0 / 65535,
    category=PIDCategory.OXYGEN,
)

register_pid(
    pid=0x29,
    name="O2_S6_WR_VOLTAGE",
    description="O2 Sensor 6 WR Lambda Voltage",
    num_bytes=4,
    unit="V",
    min_val=0,
    max_val=7.999,
    formula=lambda d: ((d[2] * 256) + d[3]) * 8.0 / 65535,
    category=PIDCategory.OXYGEN,
)

register_pid(
    pid=0x2A,
    name="O2_S7_WR_VOLTAGE",
    description="O2 Sensor 7 WR Lambda Voltage",
    num_bytes=4,
    unit="V",
    min_val=0,
    max_val=7.999,
    formula=lambda d: ((d[2] * 256) + d[3]) * 8.0 / 65535,
    category=PIDCategory.OXYGEN,
)

register_pid(
    pid=0x2B,
    name="O2_S8_WR_VOLTAGE",
    description="O2 Sensor 8 WR Lambda Voltage",
    num_bytes=4,
    unit="V",
    min_val=0,
    max_val=7.999,
    formula=lambda d: ((d[2] * 256) + d[3]) * 8.0 / 65535,
    category=PIDCategory.OXYGEN,
)

register_pid(
    pid=0x2D,
    name="EGR_ERROR",
    description="EGR Error",
    num_bytes=1,
    unit="%",
    min_val=-100,
    max_val=99.2,
    formula=lambda d: (d[0] * 100.0 / 128) - 100,
    category=PIDCategory.EMISSIONS,
    aliases=["EGR_ERR"],
)

register_pid(
    pid=0x35,
    name="O2_S2_WR_CURRENT",
    description="O2 Sensor 2 WR Lambda Current",
    num_bytes=4,
    unit="mA",
    min_val=-128,
    max_val=127.996,
    formula=lambda d: ((d[2] * 256) + d[3]) / 256.0 - 128,
    category=PIDCategory.OXYGEN,
)

register_pid(
    pid=0x36,
    name="O2_S3_WR_CURRENT",
    description="O2 Sensor 3 WR Lambda Current",
    num_bytes=4,
    unit="mA",
    min_val=-128,
    max_val=127.996,
    formula=lambda d: ((d[2] * 256) + d[3]) / 256.0 - 128,
    category=PIDCategory.OXYGEN,
)

register_pid(
    pid=0x37,
    name="O2_S4_WR_CURRENT",
    description="O2 Sensor 4 WR Lambda Current",
    num_bytes=4,
    unit="mA",
    min_val=-128,
    max_val=127.996,
    formula=lambda d: ((d[2] * 256) + d[3]) / 256.0 - 128,
    category=PIDCategory.OXYGEN,
)

register_pid(
    pid=0x38,
    name="O2_S5_WR_CURRENT",
    description="O2 Sensor 5 WR Lambda Current",
    num_bytes=4,
    unit="mA",
    min_val=-128,
    max_val=127.996,
    formula=lambda d: ((d[2] * 256) + d[3]) / 256.0 - 128,
    category=PIDCategory.OXYGEN,
)

register_pid(
    pid=0x39,
    name="O2_S6_WR_CURRENT",
    description="O2 Sensor 6 WR Lambda Current",
    num_bytes=4,
    unit="mA",
    min_val=-128,
    max_val=127.996,
    formula=lambda d: ((d[2] * 256) + d[3]) / 256.0 - 128,
    category=PIDCategory.OXYGEN,
)

register_pid(
    pid=0x3A,
    name="O2_S7_WR_CURRENT",
    description="O2 Sensor 7 WR Lambda Current",
    num_bytes=4,
    unit="mA",
    min_val=-128,
    max_val=127.996,
    formula=lambda d: ((d[2] * 256) + d[3]) / 256.0 - 128,
    category=PIDCategory.OXYGEN,
)

register_pid(
    pid=0x3B,
    name="O2_S8_WR_CURRENT",
    description="O2 Sensor 8 WR Lambda Current",
    num_bytes=4,
    unit="mA",
    min_val=-128,
    max_val=127.996,
    formula=lambda d: ((d[2] * 256) + d[3]) / 256.0 - 128,
    category=PIDCategory.OXYGEN,
)

register_pid(
    pid=0x4B,
    name="ACCEL_POS_F",
    description="Accelerator Pedal Position F",
    num_bytes=1,
    unit="%",
    min_val=0,
    max_val=100,
    formula=lambda d: d[0] * 100.0 / 255,
    category=PIDCategory.ENGINE,
    aliases=["ACCELERATOR_POS_F"],
)

register_pid(
    pid=0x4F,
    name="MAX_VALUES",
    description="Max Equiv Ratio / O2 Voltage / O2 Current / Intake Pressure",
    num_bytes=4,
    unit="",
    min_val=0,
    max_val=255,
    formula=lambda d: d[0],
    category=PIDCategory.ENGINE,
    aliases=["MAX_RATIO_V_I_PRESSURE"],
)

register_pid(
    pid=0x50,
    name="MAX_MAF",
    description="Maximum MAF Rate",
    num_bytes=1,
    unit="g/s",
    min_val=0,
    max_val=2550,
    formula=lambda d: d[0] * 10,
    category=PIDCategory.AIR,
    aliases=["MAX_AIR_FLOW_RATE"],
)

register_pid(
    pid=0x52,
    name="ETHANOL_PCT",
    description="Ethanol Fuel Percentage",
    num_bytes=1,
    unit="%",
    min_val=0,
    max_val=100,
    formula=lambda d: d[0] * 100.0 / 255,
    category=PIDCategory.FUEL,
    aliases=["ETHANOL_PERCENT", "FLEX_FUEL"],
)

register_pid(
    pid=0x55,
    name="SHORT_O2_TRIM_B1",
    description="Short Term Secondary O2 Trim Bank 1",
    num_bytes=1,
    unit="%",
    min_val=-100,
    max_val=99.2,
    formula=lambda d: (d[0] * 100.0 / 128) - 100,
    category=PIDCategory.OXYGEN,
    aliases=["STO2_TRIM_B1"],
)

register_pid(
    pid=0x56,
    name="LONG_O2_TRIM_B1",
    description="Long Term Secondary O2 Trim Bank 1",
    num_bytes=1,
    unit="%",
    min_val=-100,
    max_val=99.2,
    formula=lambda d: (d[0] * 100.0 / 128) - 100,
    category=PIDCategory.OXYGEN,
    aliases=["LTO2_TRIM_B1"],
)

register_pid(
    pid=0x57,
    name="SHORT_O2_TRIM_B2",
    description="Short Term Secondary O2 Trim Bank 2",
    num_bytes=1,
    unit="%",
    min_val=-100,
    max_val=99.2,
    formula=lambda d: (d[0] * 100.0 / 128) - 100,
    category=PIDCategory.OXYGEN,
    aliases=["STO2_TRIM_B2"],
)

register_pid(
    pid=0x58,
    name="LONG_O2_TRIM_B2",
    description="Long Term Secondary O2 Trim Bank 2",
    num_bytes=1,
    unit="%",
    min_val=-100,
    max_val=99.2,
    formula=lambda d: (d[0] * 100.0 / 128) - 100,
    category=PIDCategory.OXYGEN,
    aliases=["LTO2_TRIM_B2"],
)

register_pid(
    pid=0x5D,
    name="FUEL_INJECT_TIMING",
    description="Fuel Injection Timing",
    num_bytes=2,
    unit="degrees",
    min_val=-210,
    max_val=301.992,
    formula=lambda d: ((d[0] * 256) + d[1]) / 128.0 - 210,
    category=PIDCategory.FUEL,
    aliases=["INJECTION_TIMING"],
)

register_pid(
    pid=0x5F,
    name="EMISSION_REQ",
    description="Emission Requirements",
    num_bytes=1,
    unit="encoded",
    min_val=0,
    max_val=255,
    formula=lambda d: d[0],
    category=PIDCategory.EMISSIONS,
    aliases=["EMISSION_STANDARD"],
)

# -----------------------------------------------------------------------------
# Extended PID Support Bitmaps
# -----------------------------------------------------------------------------

register_pid(
    pid=0x60,
    name="PIDS_SUPPORTED_61_80",
    description="PIDs Supported [61-80] (bitmap)",
    num_bytes=4,
    unit="",
    min_val=0,
    max_val=0,
    formula=lambda d: (d[0] * 16777216) + (d[1] * 65536) + (d[2] * 256) + d[3],
    category=PIDCategory.VEHICLE_INFO
)

register_pid(
    pid=0x80,
    name="PIDS_SUPPORTED_81_A0",
    description="PIDs Supported [81-A0] (bitmap)",
    num_bytes=4,
    unit="",
    min_val=0,
    max_val=0,
    formula=lambda d: (d[0] * 16777216) + (d[1] * 65536) + (d[2] * 256) + d[3],
    category=PIDCategory.VEHICLE_INFO
)

register_pid(
    pid=0xA0,
    name="PIDS_SUPPORTED_A1_C0",
    description="PIDs Supported [A1-C0] (bitmap)",
    num_bytes=4,
    unit="",
    min_val=0,
    max_val=0,
    formula=lambda d: (d[0] * 16777216) + (d[1] * 65536) + (d[2] * 256) + d[3],
    category=PIDCategory.VEHICLE_INFO
)

# -----------------------------------------------------------------------------
# Extended PIDs (0x64 - 0xAF)
# Reference: SAE J1979-2 / ISO 15031-5, telemetry-obd
# Simplified decoders extracting primary value from multi-value responses
# -----------------------------------------------------------------------------

register_pid(
    pid=0x64,
    name="PERCENT_TORQUE_IDLE",
    description="Engine Percent Torque at Idle",
    num_bytes=1,
    unit="%",
    min_val=-125,
    max_val=130,
    formula=lambda d: d[0] - 125,
    category=PIDCategory.ENGINE,
    aliases=["IDLE_TORQUE_PCT"],
)

register_pid(
    pid=0x65,
    name="AUX_IO_STATUS",
    description="Auxiliary Input/Output Supported",
    num_bytes=2,
    unit="encoded",
    min_val=0,
    max_val=65535,
    formula=lambda d: (d[0] * 256) + d[1],
    category=PIDCategory.ENGINE,
    aliases=["AUXILIARY_IO"],
)

register_pid(
    pid=0x66,
    name="MAF_SENSOR",
    description="Mass Air Flow Sensor A",
    num_bytes=3,
    unit="g/s",
    min_val=0,
    max_val=2047.96875,
    formula=lambda d: ((d[1] * 256) + d[2]) / 32.0,
    category=PIDCategory.AIR,
    aliases=["MAF_A", "MASS_AIR_FLOW_A"],
)

register_pid(
    pid=0x67,
    name="ENGINE_COOLANT_TEMP_2",
    description="Engine Coolant Temperature Sensor A",
    num_bytes=2,
    unit="°C",
    min_val=-40,
    max_val=215,
    formula=lambda d: d[1] - 40,
    category=PIDCategory.TEMPERATURE,
    aliases=["COOLANT_TEMP_2"],
)

register_pid(
    pid=0x68,
    name="INTAKE_AIR_TEMP_2",
    description="Intake Air Temperature Sensor A",
    num_bytes=2,
    unit="°C",
    min_val=-40,
    max_val=215,
    formula=lambda d: d[1] - 40,
    category=PIDCategory.TEMPERATURE,
    aliases=["IAT_2"],
)

register_pid(
    pid=0x69,
    name="EGR_COMMANDED_2",
    description="Commanded EGR A Duty Cycle",
    num_bytes=2,
    unit="%",
    min_val=0,
    max_val=100,
    formula=lambda d: d[1] * 100.0 / 255,
    category=PIDCategory.EMISSIONS,
    aliases=["EGR_2"],
)

register_pid(
    pid=0x6A,
    name="DIESEL_AIR_INTAKE",
    description="Commanded Diesel Intake Air Flow",
    num_bytes=2,
    unit="%",
    min_val=0,
    max_val=100,
    formula=lambda d: d[1] * 100.0 / 255,
    category=PIDCategory.AIR,
    aliases=["DIESEL_AIR_CMD"],
)

register_pid(
    pid=0x6B,
    name="EGR_TEMP",
    description="Exhaust Gas Recirculation Temperature A",
    num_bytes=2,
    unit="°C",
    min_val=-40,
    max_val=215,
    formula=lambda d: d[1] - 40,
    category=PIDCategory.TEMPERATURE,
    aliases=["EGR_TEMPERATURE"],
)

register_pid(
    pid=0x6C,
    name="THROTTLE_CMD_2",
    description="Commanded Throttle Actuator A",
    num_bytes=2,
    unit="%",
    min_val=0,
    max_val=100,
    formula=lambda d: d[1] * 100.0 / 255,
    category=PIDCategory.ENGINE,
    aliases=["THROTTLE_ACTUATOR_2"],
)

register_pid(
    pid=0x6D,
    name="FUEL_PRESS_CTRL",
    description="Fuel Pressure Control System Pressure",
    num_bytes=3,
    unit="kPa",
    min_val=0,
    max_val=655350,
    formula=lambda d: ((d[1] * 256) + d[2]) * 10,
    category=PIDCategory.FUEL,
    aliases=["FUEL_PRESSURE_CTRL"],
)

register_pid(
    pid=0x6E,
    name="INJ_PRESS_CTRL",
    description="Injection Pressure Control System Pressure",
    num_bytes=3,
    unit="kPa",
    min_val=0,
    max_val=655350,
    formula=lambda d: ((d[1] * 256) + d[2]) * 10,
    category=PIDCategory.FUEL,
    aliases=["INJECTION_PRESSURE_CTRL"],
)

register_pid(
    pid=0x6F,
    name="TURBO_INLET_PRESS",
    description="Turbocharger A Compressor Inlet Pressure",
    num_bytes=3,
    unit="kPa",
    min_val=0,
    max_val=2047.96875,
    formula=lambda d: ((d[1] * 256) + d[2]) / 32.0,
    category=PIDCategory.AIR,
    aliases=["TURBO_INLET_PRESSURE"],
)

register_pid(
    pid=0x70,
    name="BOOST_PRESS_A",
    description="Boost Pressure A",
    num_bytes=3,
    unit="kPa",
    min_val=0,
    max_val=2047.96875,
    formula=lambda d: ((d[1] * 256) + d[2]) / 32.0,
    category=PIDCategory.AIR,
    aliases=["BOOST_PRESSURE"],
)

register_pid(
    pid=0x71,
    name="VGT_CONTROL_A",
    description="Variable Geometry Turbo Control A Position",
    num_bytes=2,
    unit="%",
    min_val=0,
    max_val=100,
    formula=lambda d: d[1] * 100.0 / 255,
    category=PIDCategory.ENGINE,
    aliases=["VGT_A"],
)

register_pid(
    pid=0x72,
    name="WASTEGATE_A",
    description="Wastegate A Position",
    num_bytes=2,
    unit="%",
    min_val=0,
    max_val=100,
    formula=lambda d: d[1] * 100.0 / 255,
    category=PIDCategory.ENGINE,
    aliases=["WASTEGATE"],
)

register_pid(
    pid=0x73,
    name="EXHAUST_PRESS",
    description="Exhaust Pressure Bank 1 Sensor 1",
    num_bytes=3,
    unit="kPa",
    min_val=0,
    max_val=2047.96875,
    formula=lambda d: ((d[1] * 256) + d[2]) / 32.0,
    category=PIDCategory.EMISSIONS,
    aliases=["EXHAUST_PRESSURE"],
)

register_pid(
    pid=0x74,
    name="TURBO_RPM_A",
    description="Turbocharger A RPM",
    num_bytes=3,
    unit="rpm",
    min_val=0,
    max_val=6553500,
    formula=lambda d: ((d[1] * 256) + d[2]) * 10,
    category=PIDCategory.ENGINE,
    aliases=["TURBO_RPM"],
)

register_pid(
    pid=0x75,
    name="TURBO_A_TEMP1",
    description="Turbocharger A Inlet Temperature",
    num_bytes=2,
    unit="°C",
    min_val=-40,
    max_val=6513.5,
    formula=lambda d: ((d[0] * 256) + d[1]) / 10.0 - 40,
    category=PIDCategory.TEMPERATURE,
    aliases=["TURBO_A_TEMP"],
)

register_pid(
    pid=0x76,
    name="TURBO_B_TEMP1",
    description="Turbocharger B Inlet Temperature",
    num_bytes=2,
    unit="°C",
    min_val=-40,
    max_val=6513.5,
    formula=lambda d: ((d[0] * 256) + d[1]) / 10.0 - 40,
    category=PIDCategory.TEMPERATURE,
    aliases=["TURBO_B_TEMP"],
)

register_pid(
    pid=0x77,
    name="CACT_TEMP",
    description="Charge Air Cooler Temperature A",
    num_bytes=2,
    unit="°C",
    min_val=-40,
    max_val=6513.5,
    formula=lambda d: ((d[0] * 256) + d[1]) / 10.0 - 40,
    category=PIDCategory.TEMPERATURE,
    aliases=["CACT", "INTERCOOLER_TEMP"],
)

register_pid(
    pid=0x78,
    name="EGT_B1",
    description="Exhaust Gas Temperature Bank 1 Sensor 1",
    num_bytes=3,
    unit="°C",
    min_val=-40,
    max_val=6513.5,
    formula=lambda d: ((d[1] * 256) + d[2]) / 10.0 - 40,
    category=PIDCategory.TEMPERATURE,
    aliases=["EGT_BANK1", "EGT1"],
)

register_pid(
    pid=0x79,
    name="EGT_B2",
    description="Exhaust Gas Temperature Bank 2 Sensor 1",
    num_bytes=3,
    unit="°C",
    min_val=-40,
    max_val=6513.5,
    formula=lambda d: ((d[1] * 256) + d[2]) / 10.0 - 40,
    category=PIDCategory.TEMPERATURE,
    aliases=["EGT_BANK2", "EGT2"],
)

register_pid(
    pid=0x7A,
    name="DPF_DIFF_PRESS_B1",
    description="Diesel Particulate Filter Differential Pressure Bank 1",
    num_bytes=3,
    unit="kPa",
    min_val=0,
    max_val=2047.96875,
    formula=lambda d: ((d[1] * 256) + d[2]) / 32.0,
    category=PIDCategory.EMISSIONS,
    aliases=["DPF_PRESS_B1"],
)

register_pid(
    pid=0x7B,
    name="DPF_DIFF_PRESS_B2",
    description="Diesel Particulate Filter Differential Pressure Bank 2",
    num_bytes=3,
    unit="kPa",
    min_val=0,
    max_val=2047.96875,
    formula=lambda d: ((d[1] * 256) + d[2]) / 32.0,
    category=PIDCategory.EMISSIONS,
    aliases=["DPF_PRESS_B2"],
)

register_pid(
    pid=0x7C,
    name="DPF_TEMP_B1",
    description="Diesel Particulate Filter Temperature Bank 1 Inlet",
    num_bytes=3,
    unit="°C",
    min_val=-40,
    max_val=6513.5,
    formula=lambda d: ((d[1] * 256) + d[2]) / 10.0 - 40,
    category=PIDCategory.TEMPERATURE,
    aliases=["DPF_TEMP"],
)

register_pid(
    pid=0x7D,
    name="NOX_NTE",
    description="NOx NTE Control Area Status",
    num_bytes=1,
    unit="encoded",
    min_val=0,
    max_val=255,
    formula=lambda d: d[0],
    category=PIDCategory.EMISSIONS,
    aliases=["NOX_NTE_STATUS"],
)

register_pid(
    pid=0x7E,
    name="PM_NTE",
    description="PM NTE Control Area Status",
    num_bytes=1,
    unit="encoded",
    min_val=0,
    max_val=255,
    formula=lambda d: d[0],
    category=PIDCategory.EMISSIONS,
    aliases=["PM_NTE_STATUS"],
)

register_pid(
    pid=0x7F,
    name="ENGINE_RUN_TIME_TOTAL",
    description="Total Engine Run Time",
    num_bytes=5,
    unit="seconds",
    min_val=0,
    max_val=4294967295,
    formula=lambda d: (d[1] * 16777216) + (d[2] * 65536) + (d[3] * 256) + d[4],
    category=PIDCategory.ENGINE,
    aliases=["TOTAL_RUN_TIME"],
)

register_pid(
    pid=0x83,
    name="NOX_SENSOR_PPM",
    description="NOx Sensor Concentration Sensor A",
    num_bytes=3,
    unit="ppm",
    min_val=0,
    max_val=65535,
    formula=lambda d: (d[1] * 256) + d[2],
    category=PIDCategory.EMISSIONS,
    aliases=["NOX_PPM", "NOX_SENSOR"],
)

register_pid(
    pid=0x84,
    name="MANIFOLD_SURFACE_TEMP",
    description="Manifold Surface Temperature",
    num_bytes=1,
    unit="°C",
    min_val=-40,
    max_val=215,
    formula=lambda d: d[0] - 40,
    category=PIDCategory.TEMPERATURE,
    aliases=["MANIFOLD_TEMP"],
)

register_pid(
    pid=0x8D,
    name="THROTTLE_POS_G",
    description="Throttle Position G",
    num_bytes=1,
    unit="%",
    min_val=0,
    max_val=100,
    formula=lambda d: d[0] * 100.0 / 255,
    category=PIDCategory.ENGINE,
    aliases=["THROTTLE_G"],
)

register_pid(
    pid=0x8E,
    name="ENGINE_FRICTION",
    description="Engine Friction Percent Torque",
    num_bytes=1,
    unit="%",
    min_val=-125,
    max_val=130,
    formula=lambda d: d[0] - 125,
    category=PIDCategory.ENGINE,
    aliases=["FRICTION_TORQUE"],
)

register_pid(
    pid=0x9A,
    name="HYBRID_BATT_PCT",
    description="Hybrid/EV Battery Pack State of Charge",
    num_bytes=2,
    unit="%",
    min_val=0,
    max_val=100,
    formula=lambda d: d[1] * 100.0 / 255,
    category=PIDCategory.ENGINE,
    aliases=["HV_BATTERY_SOC", "EV_BATTERY"],
)

register_pid(
    pid=0x9D,
    name="FUEL_RATE_2",
    description="Engine Fuel Rate (grams/sec)",
    num_bytes=2,
    unit="g/s",
    min_val=0,
    max_val=1310.7,
    formula=lambda d: ((d[0] * 256) + d[1]) / 50.0,
    category=PIDCategory.FUEL,
    aliases=["FUEL_RATE_GS"],
)

register_pid(
    pid=0x9E,
    name="EXHAUST_FLOW",
    description="Engine Exhaust Flow Rate",
    num_bytes=2,
    unit="kg/hr",
    min_val=0,
    max_val=3276.75,
    formula=lambda d: ((d[0] * 256) + d[1]) / 5.0,
    category=PIDCategory.EMISSIONS,
    aliases=["EXHAUST_FLOW_RATE"],
)

register_pid(
    pid=0xA2,
    name="CYL_FUEL_RATE",
    description="Cylinder Fuel Rate",
    num_bytes=2,
    unit="mg/stroke",
    min_val=0,
    max_val=2047.96875,
    formula=lambda d: ((d[0] * 256) + d[1]) / 32.0,
    category=PIDCategory.FUEL,
    aliases=["CYLINDER_FUEL_RATE"],
)

register_pid(
    pid=0xA3,
    name="EVAP_PRESS_2",
    description="Evaporative System Vapor Pressure (wide range)",
    num_bytes=3,
    unit="Pa",
    min_val=0,
    max_val=65535,
    formula=lambda d: (d[1] * 256) + d[2],
    category=PIDCategory.EVAP,
    aliases=["EVAP_VAPOR_PRESS_2"],
)

register_pid(
    pid=0xA4,
    name="TRANS_GEAR",
    description="Transmission Actual Gear",
    num_bytes=2,
    unit="gear",
    min_val=0,
    max_val=15,
    formula=lambda d: d[1] >> 4,
    category=PIDCategory.SPEED,
    aliases=["TRANSMISSION_GEAR", "GEAR"],
)

register_pid(
    pid=0xA5,
    name="DEF_DOSING_PCT",
    description="Diesel Exhaust Fluid Dosing",
    num_bytes=2,
    unit="%",
    min_val=0,
    max_val=127.5,
    formula=lambda d: d[1] / 2.0,
    category=PIDCategory.EMISSIONS,
    aliases=["DEF_DOSING"],
)

register_pid(
    pid=0xA7,
    name="NOX_SENSOR_2",
    description="NOx Sensor 2 Concentration",
    num_bytes=3,
    unit="ppm",
    min_val=0,
    max_val=65535,
    formula=lambda d: (d[1] * 256) + d[2],
    category=PIDCategory.EMISSIONS,
    aliases=["NOX_PPM_2"],
)

register_pid(
    pid=0xA8,
    name="NOX_CORRECTED_2",
    description="NOx Sensor 2 Corrected",
    num_bytes=3,
    unit="ppm",
    min_val=0,
    max_val=65535,
    formula=lambda d: (d[1] * 256) + d[2],
    category=PIDCategory.EMISSIONS,
    aliases=["NOX_CORRECTED"],
)

register_pid(
    pid=0xAA,
    name="SPEED_LIMITER",
    description="Vehicle Speed Limiter Set Speed",
    num_bytes=1,
    unit="km/h",
    min_val=0,
    max_val=255,
    formula=lambda d: d[0],
    category=PIDCategory.SPEED,
    aliases=["VEH_SPEED_LIMIT"],
)

register_pid(
    pid=0xAD,
    name="CRANKCASE_VENT",
    description="Crankcase Ventilation Pressure",
    num_bytes=3,
    unit="kPa",
    min_val=0,
    max_val=2047.96875,
    formula=lambda d: ((d[1] * 256) + d[2]) / 32.0,
    category=PIDCategory.ENGINE,
    aliases=["CRANKCASE_VENTILATION"],
)

register_pid(
    pid=0xAE,
    name="EVAP_PURGE_PRESS",
    description="Evaporative Purge Pressure Sensor",
    num_bytes=3,
    unit="kPa",
    min_val=0,
    max_val=2047.96875,
    formula=lambda d: ((d[1] * 256) + d[2]) / 32.0,
    category=PIDCategory.EVAP,
    aliases=["PURGE_PRESSURE"],
)

register_pid(
    pid=0xAF,
    name="EGR_AIR_FLOW_CMD",
    description="EGR Commanded Fresh Air Flow",
    num_bytes=3,
    unit="%",
    min_val=0,
    max_val=100,
    formula=lambda d: d[1] * 100.0 / 255,
    category=PIDCategory.EMISSIONS,
    aliases=["EGR_AIR_FLOW"],
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


# ──────────────────────────────────────────────────────
# OBD Standard Type Decoder (PID 0x1C)
# Maps raw byte → compliance standard name
# Reference: SAE J1979 Table A9, ISO 15031-5
# ──────────────────────────────────────────────────────
OBD_STANDARD_TYPES: Dict[int, str] = {
    0x01: "OBD-II (CARB)",
    0x02: "OBD (EPA)",
    0x03: "OBD + OBD-II",
    0x04: "OBD-I",
    0x05: "Not OBD Compliant",
    0x06: "EOBD (Europe)",
    0x07: "EOBD + OBD-II",
    0x08: "EOBD + OBD",
    0x09: "EOBD + OBD + OBD-II",
    0x0A: "JOBD (Japan)",
    0x0B: "JOBD + OBD-II",
    0x0C: "JOBD + EOBD",
    0x0D: "JOBD + EOBD + OBD-II",
    0x0E: "Reserved",
    0x0F: "Reserved",
    0x10: "Reserved",
    0x11: "EMD (Engine Manufacturer Diagnostics)",
    0x12: "EMD+",
    0x13: "HD OBD-C (Heavy Duty)",
    0x14: "HD OBD (Heavy Duty)",
    0x15: "WWH OBD (World Wide Harmonized)",
    0x16: "Reserved",
    0x17: "HD EOBD Stage I (no NOx)",
    0x18: "HD EOBD Stage I (with NOx)",
    0x19: "HD EOBD Stage II (no NOx)",
    0x1A: "HD EOBD Stage II (with NOx)",
    0x1B: "Reserved",
    0x1C: "OBD-II + EOBD + HD OBD (Brazil)",
    0x1D: "KOBD (Korea)",
    0x1E: "IOBD I (India BS-IV)",
    0x1F: "IOBD II (India BS-VI)",
    0x20: "HD EOBD Stage VI",
}


def decode_obd_standard(raw_value: int) -> str:
    """
    Decode PID 0x1C raw byte to OBD compliance standard name.
    
    Args:
        raw_value: The raw byte from PID 0x1C response
        
    Returns:
        Human-readable OBD standard name
    """
    return OBD_STANDARD_TYPES.get(raw_value, f"Unknown OBD Standard (0x{raw_value:02X})")


# Common PID groups for diagnostic scenarios
FUEL_TRIM_PIDS = [0x06, 0x07, 0x08, 0x09]  # STFT/LTFT Bank 1 & 2
OXYGEN_PIDS = [0x14, 0x15, 0x18, 0x19, 0x1A, 0x1B, 0x24, 0x25, 0x26, 0x27]  # O2 sensors
TEMPERATURE_PIDS = [0x05, 0x0F, 0x46, 0x5C, 0x67, 0x68, 0x6B, 0x78, 0x79]  # Coolant, IAT, Ambient, Oil, ECT2, IAT2, EGR, EGT
ENGINE_PIDS = [0x04, 0x0C, 0x0E, 0x11]  # Load, RPM, Timing, Throttle
AIR_PIDS = [0x0B, 0x10, 0x33, 0x66, 0x6F, 0x70]  # MAP, MAF, Baro, MAF2, Turbo inlet, Boost
TORQUE_PIDS = [0x61, 0x62, 0x63, 0x64, 0x8E]  # Driver demand, actual, reference, idle, friction
DISTANCE_TIME_PIDS = [0x1F, 0x21, 0x31, 0x4D, 0x4E, 0x7F, 0xA6]  # Run time, dist MIL, dist CLR, time MIL, time CLR, total runtime, odometer
TURBO_PIDS = [0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77]  # Turbo inlet, boost, VGT, wastegate, exhaust, RPM, temps, CACT
DIESEL_PIDS = [0x6A, 0x6D, 0x6E, 0x7A, 0x7B, 0x7C, 0x83, 0xA5, 0xA7]  # Diesel air, fuel pressure, injection, DPF, NOx, DEF
EMISSIONS_PIDS = [0x2C, 0x2D, 0x69, 0x7D, 0x7E, 0x83, 0x9E, 0xAF]  # EGR, EGR err, EGR2, NOx NTE, PM NTE, NOx, exhaust flow, EGR air

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
    0x5E,  # Fuel rate
    0x61,  # Driver torque demand
    0x62,  # Actual torque
    0xA6,  # Odometer
]
