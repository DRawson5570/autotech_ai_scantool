"""
OBD-II Mode 06 — On-Board Monitoring Test Results

Implements the SAE J1979 Mode 06 system:
- Units and Scaling (UAS) table — 80+ standardized scaling definitions
- Monitor commands (MID-based) — O2 sensors, catalyst, EGR, VVT, EVAP, misfire, etc.
- Standard Test IDs (TID) — RTL/LTR threshold, switch time, voltage, period, misfire
- MonitorTest / Monitor response types — structured test results with pass/fail
- Response parser — decodes 9-byte test result blocks from Mode 06 responses

Mode 06 is CAN-only (ISO 15765-4). Pre-CAN vehicles used Mode 05 for similar data.

Usage:
    from addons.scan_tool.mode06 import (
        Monitor, MonitorTest, parse_monitor_response,
        get_monitor_command, list_monitors, UAS, UAS_IDS,
    )

    # Parse a raw Mode 06 response
    data = bytes.fromhex("460001010105DC006003E8")
    monitors = parse_monitor_response(data)
    for test in monitors:
        print(f"{test.name}: {test.value} ({test.unit}) - {'PASS' if test.passed else 'FAIL'}")
"""

import logging
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Dict, List, Optional, Tuple, Union

logger = logging.getLogger(__name__)


# =============================================================================
# UNITS AND SCALING (UAS) — SAE J1979 Appendix
# =============================================================================
# Each UAS entry: (signed, scale, unit_string, offset)
# value = (raw_value * scale) + offset  (raw_value is signed if signed=True)

@dataclass(frozen=True)
class UAS:
    """Units and Scaling entry — converts raw Mode 06 values to engineering units."""
    signed: bool
    scale: float
    unit: str
    offset: float = 0.0

    def decode(self, raw: int) -> float:
        """Decode a raw 16-bit value to engineering units."""
        if self.signed and raw > 0x7FFF:
            raw -= 0x10000
        return (raw * self.scale) + self.offset

    def __call__(self, raw: int) -> float:
        return self.decode(raw)

    def format(self, raw: int) -> str:
        """Decode and format with unit string."""
        val = self.decode(raw)
        if val == int(val):
            return f"{int(val)} {self.unit}"
        return f"{val:.4g} {self.unit}"


# UAS ID table — SAE J1979 Appendix
# IDs 0x01-0x41 = unsigned, IDs 0x81-0xFE = signed counterparts
UAS_IDS: Dict[int, UAS] = {
    # === Unsigned (0x01-0x41) ===
    0x01: UAS(False, 1.0, "count"),
    0x02: UAS(False, 0.1, "count"),
    0x03: UAS(False, 0.01, "count"),
    0x04: UAS(False, 0.001, "count"),
    0x05: UAS(False, 0.0000305, "count"),
    0x06: UAS(False, 0.000305, "count"),
    0x07: UAS(False, 0.25, "rpm"),
    0x08: UAS(False, 0.01, "kph"),
    0x09: UAS(False, 1.0, "kph"),
    0x0A: UAS(False, 0.122, "mV"),
    0x0B: UAS(False, 0.001, "V"),
    0x0C: UAS(False, 0.01, "V"),
    0x0D: UAS(False, 0.00390625, "mA"),     # 1/256
    0x0E: UAS(False, 0.001, "A"),
    0x0F: UAS(False, 0.01, "A"),
    0x10: UAS(False, 1.0, "ms"),
    0x11: UAS(False, 100.0, "ms"),
    0x12: UAS(False, 1.0, "s"),
    0x13: UAS(False, 1.0, "g/s"),            # milligrams per stroke → grams/sec
    0x14: UAS(False, 1.0, "count"),          # number of passes
    0x15: UAS(False, 0.01, "kPa"),
    0x16: UAS(False, 0.001, "kPa"),
    0x17: UAS(False, 0.0001, "kPa"),         # for high precision vacuum
    0x18: UAS(False, 0.001, "kPa"),          # gauge pressure
    0x19: UAS(False, 0.01, "kPa"),           # gauge pressure
    0x1A: UAS(False, 0.1, "kPa"),
    0x1B: UAS(False, 1.0, "kPa"),
    0x1C: UAS(False, 10.0, "kPa"),
    0x1D: UAS(False, 0.01, "°C"),
    0x1E: UAS(False, 0.1, "°C"),
    0x1F: UAS(False, 1.0, "°C"),
    0x20: UAS(False, 10.0, "°C"),
    0x21: UAS(False, 0.01, "%"),
    0x22: UAS(False, 0.001526, "%"),         # 100/65535
    0x23: UAS(False, 0.01, "ratio"),
    0x24: UAS(False, 0.001, "ratio"),
    0x25: UAS(False, 1.0, "min"),
    0x26: UAS(False, 10.0, "ms"),
    0x27: UAS(False, 0.01, "g"),
    0x28: UAS(False, 0.1, "g"),
    0x29: UAS(False, 1.0, "g"),
    0x2A: UAS(False, 0.01, "°"),             # degrees
    0x2B: UAS(False, 0.5, "°"),
    0x2C: UAS(False, 0.0002778, "°/s"),      # 1/3600
    0x2D: UAS(False, 0.01, "°/s"),
    0x2E: UAS(False, 0.1, "°/s²"),
    0x2F: UAS(False, 0.25, "kph/h"),         # acceleration
    0x30: UAS(False, 0.001, "kph/s"),
    0x31: UAS(False, 1.0, "μA"),
    0x32: UAS(False, 0.01, "Ω"),
    0x33: UAS(False, 1.0, "Ω"),
    0x34: UAS(False, 1.0, "mΩ"),
    0x35: UAS(False, 0.001, "Hz"),
    0x36: UAS(False, 1.0, "Hz"),
    0x37: UAS(False, 1.0, "kHz"),
    0x38: UAS(False, 1.0, "count"),          # generic unsigned
    0x39: UAS(False, 1.0, "km"),
    0x3A: UAS(False, 0.1, "mV/ms"),
    0x3B: UAS(False, 0.01, "g/cyl"),
    0x3C: UAS(False, 0.01, "mg/stroke"),
    0x3D: UAS(False, 1.0, ""),               # boolean (0 or 1)
    0x3E: UAS(False, 0.01, "%"),             # percent boost
    0x3F: UAS(False, 0.001, "ratio"),        # lambda
    0x40: UAS(False, 0.1, "ppm"),
    0x41: UAS(False, 1.0, "ppm"),

    # === Signed (0x81-0xFE) — mirror unsigned with signed=True ===
    0x81: UAS(True, 1.0, "count"),
    0x82: UAS(True, 0.1, "count"),
    0x83: UAS(True, 0.01, "count"),
    0x84: UAS(True, 0.001, "count"),
    0x85: UAS(True, 0.0000305, "count"),
    0x86: UAS(True, 0.000305, "count"),
    0x87: UAS(True, 0.25, "rpm"),
    0x88: UAS(True, 0.01, "kph"),
    0x89: UAS(True, 1.0, "kph"),
    0x8A: UAS(True, 0.122, "mV"),
    0x8B: UAS(True, 0.001, "V"),
    0x8C: UAS(True, 0.01, "V"),
    0x8D: UAS(True, 0.00390625, "mA"),
    0x8E: UAS(True, 0.001, "A"),
    0x8F: UAS(True, 0.01, "A"),
    0x90: UAS(True, 1.0, "ms"),
    0x91: UAS(True, 100.0, "ms"),
    0x92: UAS(True, 1.0, "s"),
    0x93: UAS(True, 1.0, "g/s"),
    0x94: UAS(True, 1.0, "count"),
    0x95: UAS(True, 0.01, "kPa"),
    0x96: UAS(True, 0.001, "kPa"),
    0x97: UAS(True, 0.0001, "kPa"),
    0x98: UAS(True, 0.001, "kPa"),
    0x99: UAS(True, 0.01, "kPa"),
    0x9A: UAS(True, 0.1, "kPa"),
    0x9B: UAS(True, 1.0, "kPa"),
    0x9C: UAS(True, 10.0, "kPa"),
    0x9D: UAS(True, 0.01, "°C"),
    0x9E: UAS(True, 0.1, "°C"),
    0x9F: UAS(True, 1.0, "°C"),
    0xA0: UAS(True, 10.0, "°C"),
    0xA1: UAS(True, 0.01, "%"),
    0xA2: UAS(True, 0.001526, "%"),
    0xA3: UAS(True, 0.01, "ratio"),
    0xA4: UAS(True, 0.001, "ratio"),
    0xA5: UAS(True, 1.0, "min"),
    0xA6: UAS(True, 10.0, "ms"),
    0xA7: UAS(True, 0.01, "g"),
    0xA8: UAS(True, 0.1, "g"),
    0xA9: UAS(True, 1.0, "g"),
    0xAA: UAS(True, 0.01, "°"),
    0xAB: UAS(True, 0.5, "°"),
    0xAC: UAS(True, 0.0002778, "°/s"),
    0xAD: UAS(True, 0.01, "°/s"),
    0xAE: UAS(True, 0.1, "°/s²"),
    0xAF: UAS(True, 0.25, "kph/h"),
    0xB0: UAS(True, 0.001, "kph/s"),
    0xB1: UAS(True, 1.0, "μA"),
    0xB2: UAS(True, 0.01, "Ω"),
    0xB3: UAS(True, 1.0, "Ω"),
    0xB4: UAS(True, 1.0, "mΩ"),
    0xB5: UAS(True, 0.001, "Hz"),
    0xB6: UAS(True, 1.0, "Hz"),
    0xB7: UAS(True, 1.0, "kHz"),

    # === Manufacturer-specific UAS IDs ===
    # GM uses 0xFD-0xFE for signed manufacturer-specific tests
    # (EGR flow deviation, purge flow rate, etc.)
    0xFD: UAS(True, 1.0, "count"),
    0xFE: UAS(True, 1.0, "count"),
}


# =============================================================================
# STANDARD TEST IDs (TID) — SAE J1979
# =============================================================================

@dataclass(frozen=True)
class TestId:
    """Standard Monitor Test identifier."""
    tid: int
    name: str
    desc: str


# Standard test IDs defined by SAE J1979 + common manufacturer extensions
TEST_IDS: Dict[int, TestId] = {
    # === SAE Standard TIDs (0x01-0x0C) ===
    0x01: TestId(0x01, "Rich→Lean Threshold", "Rich to lean sensor threshold voltage"),
    0x02: TestId(0x02, "Lean→Rich Threshold", "Lean to rich sensor threshold voltage"),
    0x03: TestId(0x03, "Low Voltage for Switch", "Low sensor voltage for switch time calculation"),
    0x04: TestId(0x04, "High Voltage for Switch", "High sensor voltage for switch time calculation"),
    0x05: TestId(0x05, "Rich→Lean Switch Time", "Rich to lean sensor switch time"),
    0x06: TestId(0x06, "Lean→Rich Switch Time", "Lean to rich sensor switch time"),
    0x07: TestId(0x07, "Min Sensor Voltage", "Minimum sensor voltage for test cycle"),
    0x08: TestId(0x08, "Max Sensor Voltage", "Maximum sensor voltage for test cycle"),
    0x09: TestId(0x09, "Transition Time", "Time between sensor transitions"),
    0x0A: TestId(0x0A, "Sensor Period", "Sensor period"),
    0x0B: TestId(0x0B, "Avg Misfire Count", "Average misfire counts for last ten driving cycles"),
    0x0C: TestId(0x0C, "Current Misfire Count", "Misfire counts for last/current driving cycle"),

    # === Manufacturer-extended TIDs (0x80+) ===
    # O2 sensor extended tests
    0x80: TestId(0x80, "O2 Sensor Amplitude", "O2 sensor signal amplitude"),
    0x81: TestId(0x81, "O2 Sensor Phase Shift", "O2 sensor signal phase shift"),
    0x82: TestId(0x82, "O2 Heater Resistance", "O2 sensor heater circuit resistance"),
    0x83: TestId(0x83, "O2 Response Time", "O2 sensor response time"),
    0x84: TestId(0x84, "O2 Sensor Gain", "O2 sensor loop gain"),
    0x85: TestId(0x85, "O2 Lean→Rich Response", "O2 sensor lean to rich response time"),
    0x86: TestId(0x86, "O2 Rich→Lean Response", "O2 sensor rich to lean response time"),
    0x87: TestId(0x87, "O2 Heater Power", "O2 sensor heater circuit power"),
    0x88: TestId(0x88, "O2 Switch Delay", "O2 sensor switching delay time"),
    0x89: TestId(0x89, "O2 Voltage Range", "O2 sensor voltage range"),
    0x8A: TestId(0x8A, "O2 Sensor Ratio", "O2 sensor signal ratio"),
    0x8B: TestId(0x8B, "O2 Peak Voltage", "O2 sensor peak voltage"),
    0x8C: TestId(0x8C, "O2 Trough Voltage", "O2 sensor minimum voltage"),

    # Catalyst tests
    0xA0: TestId(0xA0, "Catalyst Efficiency", "Catalyst conversion efficiency index"),
    0xA1: TestId(0xA1, "Catalyst O2 Storage", "Catalyst oxygen storage capacity"),
    0xA2: TestId(0xA2, "Catalyst Light-Off", "Catalyst light-off time"),

    # EGR tests
    0xA9: TestId(0xA9, "EGR Flow Test", "EGR flow deviation from expected"),
    0xAA: TestId(0xAA, "EGR Slow Response", "EGR slow response test"),
    0xAB: TestId(0xAB, "EGR Flow Excess", "EGR excessive flow detected"),

    # EVAP tests
    0xC0: TestId(0xC0, "EVAP Gross Leak", "EVAP system gross leak detection (0.090\")"),
    0xC1: TestId(0xC1, "EVAP Conditions Met", "EVAP gross leak test completion time"),
    0xC4: TestId(0xC4, "Purge Flow Test", "Purge flow volume test"),
    0xC5: TestId(0xC5, "Purge Flow Rate", "Purge flow rate measurement"),
    0xC6: TestId(0xC6, "Purge Valve Delay", "Purge valve response delay time"),
    0xC7: TestId(0xC7, "Purge Vacuum", "Purge system vacuum level"),
    0xC8: TestId(0xC8, "EVAP Fine Leak", "EVAP system fine leak detection (0.020\")"),
    0xC9: TestId(0xC9, "EVAP Conditions", "EVAP fine leak test ambient conditions"),
    0xCA: TestId(0xCA, "EVAP Leak Ratio A", "EVAP system leak detection ratio A"),
    0xCB: TestId(0xCB, "EVAP Leak Ratio B", "EVAP system leak detection ratio B"),

    # O2 Sensor Heater tests
    0xD2: TestId(0xD2, "Heater Current Drift", "O2 heater current drift from target"),
    0xD3: TestId(0xD3, "Heater Response", "O2 heater warm-up response characteristic"),
}


# =============================================================================
# MONITOR TEST RESULT
# =============================================================================

@dataclass
class MonitorTest:
    """A single Mode 06 on-board monitoring test result.

    Attributes:
        tid: Test ID number (0x01-0xFF)
        name: Human-readable test name (from TEST_IDS or MID name)
        desc: Description of what the test measures
        value: Current measured value (decoded via UAS)
        min: Minimum threshold (if applicable; None means no lower limit)
        max: Maximum threshold (if applicable; None means no upper limit)
        unit: Engineering unit string
    """
    tid: int
    name: str
    desc: str
    value: float
    min: Optional[float]
    max: Optional[float]
    unit: str

    @property
    def passed(self) -> Optional[bool]:
        """Check if the test result is within limits.

        Returns True if within limits, False if out of limits,
        None if no limits are defined.
        """
        if self.min is None and self.max is None:
            return None
        if self.min is not None and self.value < self.min:
            return False
        if self.max is not None and self.value > self.max:
            return False
        return True

    @property
    def status(self) -> str:
        """Human-readable pass/fail status."""
        p = self.passed
        if p is None:
            return "N/A"
        return "PASS" if p else "FAIL"

    def __repr__(self) -> str:
        return (
            f"MonitorTest({self.name}: {self.value:.4g} {self.unit} "
            f"[{self.min}..{self.max}] {self.status})"
        )


# =============================================================================
# MONITOR — Collection of Tests for a MID
# =============================================================================

@dataclass
class Monitor:
    """Collection of test results for a single Monitor ID (MID).

    Attributes:
        mid: Monitor ID (0x01-0xFF)
        name: Monitor name (e.g. "O2 Sensor B1S1")
        tests: List of MonitorTest results
    """
    mid: int
    name: str
    tests: List[MonitorTest] = field(default_factory=list)

    @property
    def passed(self) -> Optional[bool]:
        """True if all tests pass, False if any fail, None if no tests."""
        if not self.tests:
            return None
        results = [t.passed for t in self.tests if t.passed is not None]
        if not results:
            return None
        return all(results)

    @property
    def status(self) -> str:
        p = self.passed
        if p is None:
            return "N/A"
        return "PASS" if p else "FAIL"

    def get_test(self, tid_or_name: Union[int, str]) -> Optional[MonitorTest]:
        """Look up a test by TID number or name."""
        for t in self.tests:
            if isinstance(tid_or_name, int) and t.tid == tid_or_name:
                return t
            if isinstance(tid_or_name, str) and t.name == tid_or_name:
                return t
        return None

    def __repr__(self) -> str:
        return f"Monitor(0x{self.mid:02X} {self.name}: {len(self.tests)} tests, {self.status})"


# =============================================================================
# MONITOR COMMANDS — MID → Name Mapping
# =============================================================================
# Mode 06 uses Monitor IDs (MIDs). Each MID tests a specific subsystem.
# MID 0x00, 0x20, 0x40, 0x60, 0x80, 0xA0 are support bitmasks (like PIDs).

class MID(IntEnum):
    """Well-known Monitor IDs (MIDs) for Mode 06."""
    # Support MIDs — return bitmask of supported MIDs
    MIDS_A = 0x00   # MIDs 0x01-0x20 supported
    MIDS_B = 0x20   # MIDs 0x21-0x40 supported
    MIDS_C = 0x40   # MIDs 0x41-0x60 supported
    MIDS_D = 0x60   # MIDs 0x61-0x80 supported
    MIDS_E = 0x80   # MIDs 0x81-0xA0 supported
    MIDS_F = 0xA0   # MIDs 0xA1-0xC0 supported


# Human-readable names for all standard MIDs
MONITOR_NAMES: Dict[int, str] = {
    # Support MIDs
    0x00: "MIDs Supported [01-20]",
    0x20: "MIDs Supported [21-40]",
    0x40: "MIDs Supported [41-60]",
    0x60: "MIDs Supported [61-80]",
    0x80: "MIDs Supported [81-A0]",
    0xA0: "MIDs Supported [A1-C0]",

    # O2 Sensor Monitors
    0x01: "O2 Sensor Monitor Bank 1 Sensor 1",
    0x02: "O2 Sensor Monitor Bank 1 Sensor 2",
    0x03: "O2 Sensor Monitor Bank 1 Sensor 3",
    0x04: "O2 Sensor Monitor Bank 1 Sensor 4",
    0x05: "O2 Sensor Monitor Bank 2 Sensor 1",
    0x06: "O2 Sensor Monitor Bank 2 Sensor 2",
    0x07: "O2 Sensor Monitor Bank 2 Sensor 3",
    0x08: "O2 Sensor Monitor Bank 2 Sensor 4",
    0x09: "O2 Sensor Monitor Bank 3 Sensor 1",
    0x0A: "O2 Sensor Monitor Bank 3 Sensor 2",
    0x0B: "O2 Sensor Monitor Bank 3 Sensor 3",
    0x0C: "O2 Sensor Monitor Bank 3 Sensor 4",
    0x0D: "O2 Sensor Monitor Bank 4 Sensor 1",
    0x0E: "O2 Sensor Monitor Bank 4 Sensor 2",
    0x0F: "O2 Sensor Monitor Bank 4 Sensor 3",
    0x10: "O2 Sensor Monitor Bank 4 Sensor 4",

    # Catalyst Monitors
    0x21: "Catalyst Monitor Bank 1",
    0x22: "Catalyst Monitor Bank 2",
    0x23: "Catalyst Monitor Bank 3",
    0x24: "Catalyst Monitor Bank 4",

    # EGR / VVT Monitors
    0x31: "EGR Monitor Bank 1",
    0x32: "EGR Monitor Bank 2",
    0x33: "EGR Monitor Bank 3",
    0x34: "EGR Monitor Bank 4",
    0x35: "VVT Monitor Bank 1",
    0x36: "VVT Monitor Bank 2",
    0x37: "VVT Monitor Bank 3",
    0x38: "VVT Monitor Bank 4",

    # EVAP Monitors
    0x39: "EVAP Monitor (Cap Off / 0.150\")",
    0x3A: "EVAP Monitor (0.090\")",
    0x3B: "EVAP Monitor (0.040\")",
    0x3C: "EVAP Monitor (0.020\")",
    0x3D: "Purge Flow Monitor",

    # Oxygen Sensor Heater
    0x41: "O2 Sensor Heater Monitor Bank 1 Sensor 1",
    0x42: "O2 Sensor Heater Monitor Bank 1 Sensor 2",
    0x43: "O2 Sensor Heater Monitor Bank 1 Sensor 3",
    0x44: "O2 Sensor Heater Monitor Bank 1 Sensor 4",
    0x45: "O2 Sensor Heater Monitor Bank 2 Sensor 1",
    0x46: "O2 Sensor Heater Monitor Bank 2 Sensor 2",
    0x47: "O2 Sensor Heater Monitor Bank 2 Sensor 3",
    0x48: "O2 Sensor Heater Monitor Bank 2 Sensor 4",

    # Heated Catalyst
    0x49: "Heated Catalyst Monitor Bank 1",
    0x4A: "Heated Catalyst Monitor Bank 2",

    # Secondary Air
    0x4B: "Secondary Air Monitor System 1 (upstream)",
    0x4C: "Secondary Air Monitor System 2 (downstream)",

    # Fuel System
    0x51: "Fuel System Monitor Bank 1",
    0x52: "Fuel System Monitor Bank 2",

    # Boost Pressure
    0x53: "Boost Pressure Control Monitor Bank 1",
    0x54: "Boost Pressure Control Monitor Bank 2",

    # NOx / PM / SCR
    0x55: "NOx Adsorber Monitor",
    0x56: "NOx/SCR Catalyst Monitor",
    0x57: "PM Filter Monitor Bank 1",
    0x58: "PM Filter Monitor Bank 2",
    0x59: "Exhaust Gas Sensor Monitor Bank 1 Sensor 1",
    0x5A: "Exhaust Gas Sensor Monitor Bank 1 Sensor 2",
    0x5B: "Exhaust Gas Sensor Monitor Bank 2 Sensor 1",
    0x5C: "Exhaust Gas Sensor Monitor Bank 2 Sensor 2",

    # Misfire Monitors
    0x61: "Misfire Monitor General Data",
    0x62: "Misfire Monitor Cylinder 1",
    0x63: "Misfire Monitor Cylinder 2",
    0x64: "Misfire Monitor Cylinder 3",
    0x65: "Misfire Monitor Cylinder 4",
    0x66: "Misfire Monitor Cylinder 5",
    0x67: "Misfire Monitor Cylinder 6",
    0x68: "Misfire Monitor Cylinder 7",
    0x69: "Misfire Monitor Cylinder 8",
    0x6A: "Misfire Monitor Cylinder 9",
    0x6B: "Misfire Monitor Cylinder 10",
    0x6C: "Misfire Monitor Cylinder 11",
    0x6D: "Misfire Monitor Cylinder 12",

    # Other — SAE standard names (0xA1-0xA4)
    # NOTE: These SAE names apply to diesel/GDI vehicles. On conventional
    # gasoline engines (spark ignition without GDI), these MID ranges are
    # REUSED for manufacturer-specific misfire monitors.
    # Use get_monitor_name_for_vehicle() for vehicle-aware naming.
    0xA1: "NMHC Catalyst Monitor",
    0xA2: "NOx Catalyst/Adsorber Monitor",
    0xA3: "NOx Sensor Data",
    0xA4: "PM Sensor Data",
    0xA5: "Exhaust Gas Sensor Monitor",
    0xA6: "Boost Pressure Monitor",
    0xA7: "EGR/VVT Monitor (Extended)",
}


# =============================================================================
# GM / MANUFACTURER-SPECIFIC MID OVERRIDES
# =============================================================================
# On GM spark-ignition vehicles (conventional port injection, no GDI),
# MIDs 0xA0+ are used for misfire data — NOT NOx/PM/SCR. The vehicle's
# ignition type and supported PIDs determine which mapping applies.

_GM_SPARK_MID_NAMES: Dict[int, str] = {
    # GM repurposes the 0xA0+ range for misfire on conventional engines
    0xA1: "Misfire Monitor General",
    0xA2: "Misfire Monitor Cylinder 1",
    0xA3: "Misfire Monitor Cylinder 2",
    0xA4: "Misfire Monitor Cylinder 3",
    0xA5: "Misfire Monitor Cylinder 4",
    0xA6: "Misfire Monitor Cylinder 5",
    0xA7: "Misfire Monitor Cylinder 6",
    0xA8: "Misfire Monitor Cylinder 7",
    0xA9: "Misfire Monitor Cylinder 8",
    0xAA: "Misfire Monitor Cylinder 9",
    0xAB: "Misfire Monitor Cylinder 10",
    0xAC: "Misfire Monitor Cylinder 11",
    0xAD: "Misfire Monitor Cylinder 12",
}


def get_monitor_name_for_vehicle(
    mid: int,
    *,
    is_spark: bool = True,
    is_gm: bool = False,
    cylinder_count: int = 0,
) -> str:
    """Get the correct monitor name considering vehicle type.

    Standard SAE MID names assume diesel/GDI for 0xA0+ range, but
    conventional spark-ignition engines (especially GM) use those
    MIDs for misfire cylinder data.

    Args:
        mid: Monitor ID
        is_spark: True for spark ignition (gasoline), False for diesel
        is_gm: True if vehicle is GM/Chevrolet/Buick/etc.
        cylinder_count: Number of cylinders (for misfire mapping)

    Returns:
        Human-readable monitor name
    """
    # GM spark vehicles use 0xA0+ for misfire
    if is_gm and is_spark and mid in _GM_SPARK_MID_NAMES:
        name = _GM_SPARK_MID_NAMES[mid]
        # Validate cylinder number if we know the count
        if cylinder_count > 0 and "Cylinder" in name:
            try:
                cyl_num = int(name.split("Cylinder ")[1])
                if cyl_num > cylinder_count:
                    return f"Monitor 0x{mid:02X}"  # Beyond cylinder count
            except (IndexError, ValueError):
                pass
        return name

    return MONITOR_NAMES.get(mid, f"Monitor 0x{mid:02X}")


# =============================================================================
# MID SUPPORT BITMASK PARSING
# =============================================================================

SUPPORT_MIDS = {0x00, 0x20, 0x40, 0x60, 0x80, 0xA0}


def parse_supported_mids(mid_base: int, data: bytes) -> List[int]:
    """Parse a 4-byte bitmask response for supported MIDs.

    Args:
        mid_base: The support MID that was queried (0x00, 0x20, ...)
        data: 4 bytes of bitmask data

    Returns:
        List of supported MID numbers
    """
    supported = []
    if len(data) < 4:
        return supported

    bits = int.from_bytes(data[:4], "big")
    for i in range(32):
        if bits & (1 << (31 - i)):
            supported.append(mid_base + i + 1)
    return supported


# =============================================================================
# MODE 06 RESPONSE PARSER
# =============================================================================

def _parse_test_result(mid: int, data: bytes, offset: int) -> Optional[MonitorTest]:
    """Parse a single 9-byte test result block.

    Format (CAN / ISO 15765-4):
        Byte 0: MID
        Byte 1: TID (test ID)
        Byte 2: UAS ID (unit/scaling identifier)
        Bytes 3-4: Test value (16-bit)
        Bytes 5-6: Min limit (16-bit, 0x0000 = no limit)
        Bytes 7-8: Max limit (16-bit, 0x0000 = no limit)

    Note: The first byte (MID) may already be consumed by the caller,
    so we start from TID.
    """
    if offset + 8 > len(data):
        return None

    tid = data[offset]
    uas_id = data[offset + 1]
    raw_value = (data[offset + 2] << 8) | data[offset + 3]
    raw_min = (data[offset + 4] << 8) | data[offset + 5]
    raw_max = (data[offset + 6] << 8) | data[offset + 7]

    # Look up UAS scaling
    uas = UAS_IDS.get(uas_id)
    if uas is None:
        # Unknown UAS — use raw values with count unit
        uas = UAS(False, 1.0, "raw")
        logger.warning(f"Unknown UAS ID 0x{uas_id:02X} for MID 0x{mid:02X} TID 0x{tid:02X}")

    value = uas.decode(raw_value)
    # For limits, 0x0000 typically means "no limit" but for signed UAS
    # 0x0000 is a valid value (0). Use 0x0000→None only for unsigned.
    # For max, 0xFFFF often means "no upper limit" on misfire counters.
    if raw_min == 0x0000:
        min_val = None
    else:
        min_val = uas.decode(raw_min)

    if raw_max == 0x0000:
        max_val = None
    elif raw_max == 0xFFFF and not uas.signed:
        # 0xFFFF unsigned = max possible value = effectively no limit
        max_val = None
    else:
        max_val = uas.decode(raw_max)

    # Fix inverted limits: if min > max after decoding (common with signed
    # UAS where the ECU stores limits in a way our scaling inverts),
    # swap them so pass/fail logic works correctly.
    if min_val is not None and max_val is not None and min_val > max_val:
        min_val, max_val = max_val, min_val

    # Look up test name
    test_def = TEST_IDS.get(tid)
    if test_def:
        name = test_def.name
        desc = test_def.desc
    else:
        # Use MID name + TID as fallback
        mid_name = MONITOR_NAMES.get(mid, f"MID_0x{mid:02X}")
        name = f"Test 0x{tid:02X}"
        desc = f"{mid_name} test 0x{tid:02X}"

    return MonitorTest(
        tid=tid,
        name=name,
        desc=desc,
        value=value,
        min=min_val,
        max=max_val,
        unit=uas.unit,
    )


def parse_monitor_response(data: bytes) -> List[Monitor]:
    """Parse a complete Mode 06 response into Monitor objects.

    The response format for Mode 06 (CAN) is:
        Byte 0: 0x46 (Mode 06 response identifier)
        Then for each test result:
            Byte 0: MID
            Byte 1: TID
            Byte 2: UAS ID
            Bytes 3-4: Value
            Bytes 5-6: Min limit
            Bytes 7-8: Max limit

    Args:
        data: Raw response bytes (may include 0x46 prefix)

    Returns:
        List of Monitor objects, each containing their test results
    """
    if not data:
        return []

    # Skip the Mode 06 response prefix (0x46)
    offset = 0
    if data[0] == 0x46:
        offset = 1

    monitors: Dict[int, Monitor] = {}

    while offset + 9 <= len(data):
        mid = data[offset]
        offset += 1

        # Support MIDs are bitmasks, not test results
        if mid in SUPPORT_MIDS:
            # Skip the 4 bitmask bytes + remaining alignment
            offset += 8  # TID(1) + UAS(1) + value(2) + min(2) + max(2)
            continue

        test = _parse_test_result(mid, data, offset)
        if test is None:
            break
        offset += 8

        if mid not in monitors:
            name = MONITOR_NAMES.get(mid, f"Monitor 0x{mid:02X}")
            monitors[mid] = Monitor(mid=mid, name=name)
        monitors[mid].tests.append(test)

    return list(monitors.values())


def parse_single_monitor(mid: int, data: bytes) -> Monitor:
    """Parse test results for a single MID.

    This handles the case where we query a specific MID and get back
    only the test results for that monitor.

    Args:
        mid: The Monitor ID that was queried
        data: Raw response bytes (test result blocks only, no 0x46 header)

    Returns:
        Monitor object with test results
    """
    name = MONITOR_NAMES.get(mid, f"Monitor 0x{mid:02X}")
    monitor = Monitor(mid=mid, name=name)

    offset = 0
    while offset + 8 <= len(data):
        test = _parse_test_result(mid, data, offset)
        if test is None:
            break
        monitor.tests.append(test)
        offset += 8

    return monitor


# =============================================================================
# HIGH-LEVEL API
# =============================================================================

def get_monitor_name(mid: int) -> str:
    """Get the human-readable name for a MID."""
    return MONITOR_NAMES.get(mid, f"Monitor 0x{mid:02X}")


def get_monitor_command(name_or_mid: Union[str, int]) -> Optional[int]:
    """Look up a MID by name or number.

    Args:
        name_or_mid: Either a MID number (int) or a search string

    Returns:
        MID number, or None if not found
    """
    if isinstance(name_or_mid, int):
        if name_or_mid in MONITOR_NAMES:
            return name_or_mid
        return None

    # Search by name (case-insensitive partial match)
    query = name_or_mid.lower()
    for mid_num, name in MONITOR_NAMES.items():
        if query in name.lower():
            return mid_num
    return None


def list_monitors() -> List[Tuple[int, str]]:
    """List all known monitor MIDs and their names.

    Returns:
        List of (mid, name) tuples, excluding support MIDs
    """
    return [
        (mid, name) for mid, name in sorted(MONITOR_NAMES.items())
        if mid not in SUPPORT_MIDS
    ]


def build_mode06_command(mid: int) -> str:
    """Build the OBD command string for a Mode 06 query.

    Args:
        mid: Monitor ID to query (0x00-0xFF)

    Returns:
        AT command string like "06 01"
    """
    return f"06 {mid:02X}"


# =============================================================================
# PID 0x01 STATUS DECODER — Readiness Monitors
# =============================================================================
# While not strictly Mode 06, the PID 01 status byte-field is closely related
# to the monitor system. This decodes the 4-byte PID 01 response into
# structured readiness monitor data.

@dataclass
class ReadinessMonitor:
    """Status of a single readiness monitor."""
    name: str
    available: bool
    complete: bool

    @property
    def status(self) -> str:
        if not self.available:
            return "N/A"
        return "Complete" if self.complete else "Incomplete"


@dataclass
class StatusResult:
    """Decoded PID 0x01 status response.

    Attributes:
        mil: Malfunction Indicator Lamp (Check Engine Light) on/off
        dtc_count: Number of confirmed DTCs
        ignition_type: "spark" or "compression" (gas vs diesel)
        monitors: List of ReadinessMonitor objects
    """
    mil: bool
    dtc_count: int
    ignition_type: str  # "spark" or "compression"
    monitors: List[ReadinessMonitor] = field(default_factory=list)

    @property
    def all_ready(self) -> bool:
        """True if all available monitors are complete."""
        return all(
            m.complete for m in self.monitors if m.available
        )

    def incomplete_monitors(self) -> List[str]:
        """List names of monitors that are available but not complete."""
        return [m.name for m in self.monitors if m.available and not m.complete]


# Base tests (Byte B, common to all vehicles)
_BASE_TESTS = [
    (0, "Misfire"),
    (1, "Fuel System"),
    (2, "Components"),
]

# Spark ignition tests (Byte C bits 0-3 available, Byte D bits 0-3 complete)
_SPARK_TESTS = [
    (0, "Catalyst"),
    (1, "Heated Catalyst"),
    (2, "Evaporative System"),
    (3, "Secondary Air System"),
    (4, "A/C Refrigerant"),
    (5, "Oxygen Sensor"),
    (6, "Oxygen Sensor Heater"),
    (7, "EGR System"),
]

# Compression ignition tests (diesel, Byte C bits 0-3 available, Byte D bits 0-3 complete)
_COMPRESSION_TESTS = [
    (0, "NMHC Catalyst"),
    (1, "NOx/SCR Monitor"),
    (2, "Boost Pressure"),
    (3, "Exhaust Gas Sensor"),
    (4, "PM Filter Monitoring"),
    (5, "EGR and/or VVT System"),
    (6, "Reserved (Diesel)"),
    (7, "Reserved (Diesel)"),
]


def decode_status(data: bytes) -> StatusResult:
    """Decode PID 0x01 Monitor Status response (4 bytes: A B C D).

    Byte A: bit 7 = MIL on/off, bits 0-6 = DTC count
    Byte B: bit 3 = ignition type (0=spark, 1=compression),
            bits 0-2 = base test availability, bit 4-6 not used here
            (availability for base tests is in upper nibble)
    Byte C: Readiness support bits (availability)
    Byte D: Readiness status bits (completeness, inverted: 0=complete, 1=incomplete)

    More precisely for Byte B:
    - Bits 0-2: Base test available (misfire/fuel/components)
    - Bit 3: Ignition type (0=spark, 1=compression)
    - Bits 4-6: Base test incomplete (misfire/fuel/components) — 0=complete, 1=incomplete

    Args:
        data: 4 bytes of PID 0x01 response

    Returns:
        StatusResult with all decoded information
    """
    if len(data) < 4:
        raise ValueError(f"PID 01 status requires 4 bytes, got {len(data)}")

    a, b, c, d = data[0], data[1], data[2], data[3]

    # Byte A
    mil = bool(a & 0x80)
    dtc_count = a & 0x7F

    # Byte B — ignition type
    is_compression = bool(b & 0x08)
    ignition_type = "compression" if is_compression else "spark"

    monitors: List[ReadinessMonitor] = []

    # Base tests from Byte B
    for bit, name in _BASE_TESTS:
        available = bool(b & (1 << bit))
        complete = not bool(b & (1 << (bit + 4)))  # Upper nibble, inverted
        monitors.append(ReadinessMonitor(name=name, available=available, complete=complete))

    # Vehicle-type-specific tests from Bytes C and D
    specific_tests = _COMPRESSION_TESTS if is_compression else _SPARK_TESTS
    for bit, name in specific_tests:
        available = bool(c & (1 << bit))
        complete = not bool(d & (1 << bit))  # Inverted: 0 means complete
        monitors.append(ReadinessMonitor(name=name, available=available, complete=complete))

    return StatusResult(
        mil=mil,
        dtc_count=dtc_count,
        ignition_type=ignition_type,
        monitors=monitors,
    )


def format_status(status: StatusResult) -> str:
    """Format a StatusResult as a human-readable string."""
    lines = []
    lines.append(f"MIL: {'ON ⚠️' if status.mil else 'OFF'}")
    lines.append(f"DTCs: {status.dtc_count}")
    lines.append(f"Ignition: {status.ignition_type}")
    lines.append(f"All Monitors Ready: {'Yes' if status.all_ready else 'No'}")
    lines.append("")
    lines.append("Monitor Status:")
    for m in status.monitors:
        if m.available:
            icon = "✓" if m.complete else "✗"
            lines.append(f"  {icon} {m.name}: {m.status}")
    incomplete = status.incomplete_monitors()
    if incomplete:
        lines.append(f"\nIncomplete: {', '.join(incomplete)}")
    return "\n".join(lines)


# =============================================================================
# FREEZE FRAME (MODE 02) — PID 01 Clone
# =============================================================================
# Mode 02 returns the same PIDs as Mode 01, but from the freeze frame
# snapshot stored when a DTC was set. The only difference is:
#   Request:  02 <PID> <frame_number>  (usually frame 0)
#   Response: 42 <PID> <data>

def build_freeze_frame_command(pid: int, frame: int = 0) -> str:
    """Build a Mode 02 (freeze frame) command string.

    Args:
        pid: PID number to read from freeze frame (same as Mode 01 PIDs)
        frame: Frame number (usually 0, max 255)

    Returns:
        Command string like "02 0C 00" (for RPM in frame 0)
    """
    return f"02 {pid:02X} {frame:02X}"


# Common PIDs to read from freeze frame (tells the tech what was happening
# when the DTC was set)
FREEZE_FRAME_PIDS = [
    (0x02, "Freeze Frame DTC That Triggered Snapshot"),
    (0x04, "Calculated Engine Load"),
    (0x05, "Engine Coolant Temperature"),
    (0x06, "Short Term Fuel Trim — Bank 1"),
    (0x07, "Long Term Fuel Trim — Bank 1"),
    (0x0B, "Intake Manifold Absolute Pressure"),
    (0x0C, "Engine RPM"),
    (0x0D, "Vehicle Speed"),
    (0x0E, "Timing Advance"),
    (0x0F, "Intake Air Temperature"),
    (0x10, "MAF Air Flow Rate"),
    (0x11, "Throttle Position"),
]


def format_freeze_frame_report(
    data: Dict[int, float],
    units: Optional[Dict[int, str]] = None,
) -> str:
    """Format freeze frame data as a readable report.

    Args:
        data: Dict of PID → decoded value
        units: Optional dict of PID → unit string

    Returns:
        Multi-line formatted report
    """
    units = units or {}
    lines = ["=== Freeze Frame Snapshot ===", ""]

    for pid, name in FREEZE_FRAME_PIDS:
        if pid in data:
            val = data[pid]
            unit = units.get(pid, "")
            lines.append(f"  {name}: {val} {unit}".rstrip())

    return "\n".join(lines)


# Module stats
logger.debug(
    f"Mode 06 module loaded: {len(UAS_IDS)} UAS entries, "
    f"{len(TEST_IDS)} standard TIDs, "
    f"{len(MONITOR_NAMES)} monitor names"
)
