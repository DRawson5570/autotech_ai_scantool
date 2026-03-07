"""
Calibration & Service Routines

Standard maintenance and calibration procedures that can be performed
over UDS (ISO 14229) via an ELM327/STN adapter. These are common
"reset" and "relearn" operations that shops perform regularly.

Supported routines:
 - Oil life reset
 - Throttle body relearn (idle adaptation)
 - TPMS sensor relearn / reset
 - Battery registration / BMS reset
 - Steering angle sensor calibration
 - DPF regeneration (diesel)
 - Injector coding
 - Transmission adaptation reset
 - ABS bleeding assist
 - Brake pad reset (EPB service mode)

Note: Many of these use UDS RoutineControl (0x31), WriteDataByIdentifier (0x2E),
or IOControlByIdentifier (0x2F). Support varies significantly by manufacturer
and model year.
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# UDS Service IDs used by calibrations
SID_DIAGNOSTIC_SESSION   = 0x10
SID_SECURITY_ACCESS      = 0x27
SID_WRITE_DATA           = 0x2E
SID_IO_CONTROL           = 0x2F
SID_ROUTINE_CONTROL      = 0x31

# Routine Control sub-functions
RC_START_ROUTINE     = 0x01
RC_STOP_ROUTINE      = 0x02
RC_REQUEST_RESULTS   = 0x03

# Session types
SESSION_DEFAULT   = 0x01
SESSION_EXTENDED  = 0x03


class CalibrationCategory(str, Enum):
    """Category of calibration/service routine."""
    OIL_RESET = "oil_reset"
    THROTTLE_RELEARN = "throttle_relearn"
    TPMS = "tpms"
    BATTERY = "battery_registration"
    STEERING_ANGLE = "steering_angle"
    BRAKE_SERVICE = "brake_service"
    TRANSMISSION = "transmission_reset"
    DPF_REGEN = "dpf_regen"
    INJECTOR = "injector_coding"
    ABS_BLEED = "abs_bleed"
    SAS_CAL = "sas_calibration"
    GENERAL = "general"


class DifficultyLevel(str, Enum):
    """How complex the routine is."""
    EASY = "easy"        # Single command, no prerequisites
    MODERATE = "moderate" # Requires extended session, maybe specific conditions
    ADVANCED = "advanced" # Requires security access or multi-step sequence


class RiskLevel(str, Enum):
    """Risk assessment for the routine."""
    SAFE = "safe"           # Read-only or purely informational reset
    LOW = "low"             # Oil reset, TPMS — no safety impact
    MEDIUM = "medium"       # Throttle relearn — may affect idle briefly
    HIGH = "high"           # Battery registration, brake service — safety-relevant


@dataclass
class CalibrationRoutine:
    """Definition of a calibration/service routine."""
    id: str
    name: str
    category: CalibrationCategory
    difficulty: DifficultyLevel
    risk: RiskLevel
    description: str
    manufacturer: str            # "ford", "gm", "toyota", etc. or "universal"
    applicable_models: List[str] # Vehicle models / years this applies to
    prerequisites: List[str]     # What must be true before running
    steps_description: List[str] # Human-readable step descriptions
    
    # UDS parameters for automatic execution
    module_addr: str = "0x7E0"    # Target ECU address
    bus: str = "HS-CAN"
    session_type: int = SESSION_EXTENDED
    security_level: int = 0       # 0 = none, 1 = level 1, 3 = level 3, etc.
    
    # The actual UDS commands to execute (in order)
    # Each is a dict with: command (hex string), description, expected_response
    uds_sequence: List[Dict[str, Any]] = field(default_factory=list)
    
    # Post-operation requirements
    requires_ignition_cycle: bool = False  # Need to cycle key on/off after
    requires_engine_running: bool = False
    estimated_time_seconds: int = 30
    
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "category": self.category.value,
            "difficulty": self.difficulty.value,
            "risk": self.risk.value,
            "description": self.description,
            "manufacturer": self.manufacturer,
            "applicable_models": self.applicable_models,
            "prerequisites": self.prerequisites,
            "steps": self.steps_description,
            "module_addr": self.module_addr,
            "bus": self.bus,
            "requires_ignition_cycle": self.requires_ignition_cycle,
            "requires_engine_running": self.requires_engine_running,
            "estimated_time_seconds": self.estimated_time_seconds,
            "notes": self.notes,
        }


@dataclass
class CalibrationResult:
    """Result of executing a calibration routine."""
    routine_id: str
    routine_name: str
    success: bool
    steps_completed: int
    total_steps: int
    messages: List[str] = field(default_factory=list)
    raw_responses: List[str] = field(default_factory=list)
    error: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        d = {
            "routine_id": self.routine_id,
            "routine_name": self.routine_name,
            "success": self.success,
            "steps_completed": self.steps_completed,
            "total_steps": self.total_steps,
            "messages": self.messages,
        }
        if self.error:
            d["error"] = self.error
        return d


# ===========================================================================
# Calibration Routine Library
# ===========================================================================

CALIBRATION_LIBRARY: Dict[str, CalibrationRoutine] = {}


def _register(routine: CalibrationRoutine) -> None:
    """Register a calibration routine."""
    CALIBRATION_LIBRARY[routine.id] = routine


# ---------------------------------------------------------------------------
# Oil Life Reset Routines
# ---------------------------------------------------------------------------

_register(CalibrationRoutine(
    id="ford_oil_life_reset",
    name="Ford Oil Life Reset",
    category=CalibrationCategory.OIL_RESET,
    difficulty=DifficultyLevel.EASY,
    risk=RiskLevel.SAFE,
    description="Reset the oil life monitor to 100% after an oil change. Works on most 2011+ Ford/Lincoln/Mercury vehicles.",
    manufacturer="ford",
    applicable_models=["F-150", "Explorer", "Edge", "Fusion", "Escape", "Mustang", "Transit", "MKZ", "MKX", "MKS", "Navigator", "Expedition"],
    prerequisites=["Key ON, engine OFF", "Oil change completed"],
    steps_description=[
        "Switch to extended diagnostic session",
        "Write oil life reset DID (0x0408 = 100%)",
        "Verify oil life reads 100%",
    ],
    module_addr="0x7E0",
    bus="HS-CAN",
    session_type=SESSION_EXTENDED,
    security_level=0,
    uds_sequence=[
        {"command": "1003", "description": "Extended session", "expected_positive": "50"},
        {"command": "2E040800", "description": "Reset oil life to 100%", "expected_positive": "6E"},
    ],
    requires_ignition_cycle=False,
    estimated_time_seconds=5,
    notes="DID 0x0408 is the oil life percentage on Ford PCMs. Writing 0x00 = 100%.",
))

_register(CalibrationRoutine(
    id="gm_oil_life_reset",
    name="GM Oil Life Reset",
    category=CalibrationCategory.OIL_RESET,
    difficulty=DifficultyLevel.EASY,
    risk=RiskLevel.SAFE,
    description="Reset GM Oil Life Monitor system after an oil change.",
    manufacturer="gm",
    applicable_models=["Silverado", "Sierra", "Tahoe", "Yukon", "Suburban", "Equinox", "Traverse", "Malibu", "Camaro", "Corvette"],
    prerequisites=["Key ON, engine OFF", "Oil change completed"],
    steps_description=[
        "Switch to extended diagnostic session",
        "Write engine oil life reset routine",
        "Verify oil life monitor reset",
    ],
    module_addr="0x7E0",
    bus="HS-CAN",
    session_type=SESSION_EXTENDED,
    uds_sequence=[
        {"command": "1003", "description": "Extended session", "expected_positive": "50"},
        {"command": "2E041E64", "description": "Reset oil life to 100%", "expected_positive": "6E"},
    ],
    estimated_time_seconds=5,
    notes="GM uses DID 0x041E. Writing 0x64 (100 decimal) = 100%.",
))

_register(CalibrationRoutine(
    id="stellantis_oil_life_reset",
    name="Stellantis/FCA Oil Life Reset",
    category=CalibrationCategory.OIL_RESET,
    difficulty=DifficultyLevel.EASY,
    risk=RiskLevel.SAFE,
    description="Reset oil change indicator on Chrysler/Dodge/Jeep/Ram vehicles.",
    manufacturer="stellantis",
    applicable_models=["Ram 1500", "Wrangler", "Grand Cherokee", "Cherokee", "Durango", "Charger", "Challenger"],
    prerequisites=["Key ON, engine OFF", "Oil change completed"],
    steps_description=[
        "Switch to extended diagnostic session",
        "Start oil reset routine via RoutineControl (0x31)",
    ],
    module_addr="0x7E0",
    bus="HS-CAN",
    session_type=SESSION_EXTENDED,
    uds_sequence=[
        {"command": "1003", "description": "Extended session", "expected_positive": "50"},
        {"command": "3101FF00", "description": "Start oil life reset routine", "expected_positive": "71"},
    ],
    estimated_time_seconds=5,
    notes="Many Stellantis vehicles use RoutineControl 0xFF00 for oil reset.",
))

_register(CalibrationRoutine(
    id="toyota_oil_reset",
    name="Toyota Oil Maintenance Reset",
    category=CalibrationCategory.OIL_RESET,
    difficulty=DifficultyLevel.EASY,
    risk=RiskLevel.SAFE,
    description="Reset oil maintenance reminder on Toyota/Lexus vehicles.",
    manufacturer="toyota",
    applicable_models=["Camry", "Corolla", "RAV4", "Highlander", "Tacoma", "Tundra", "4Runner", "Sienna"],
    prerequisites=["Key ON, engine OFF", "Oil change completed"],
    steps_description=[
        "Switch to extended diagnostic session",
        "Write maintenance reset DID",
    ],
    module_addr="0x7E0",
    bus="HS-CAN",
    session_type=SESSION_EXTENDED,
    uds_sequence=[
        {"command": "1003", "description": "Extended session", "expected_positive": "50"},
        {"command": "2ED00100", "description": "Reset maintenance counter", "expected_positive": "6E"},
    ],
    estimated_time_seconds=5,
))

_register(CalibrationRoutine(
    id="honda_oil_reset",
    name="Honda/Acura Oil Life Reset",
    category=CalibrationCategory.OIL_RESET,
    difficulty=DifficultyLevel.EASY,
    risk=RiskLevel.SAFE,
    description="Reset the Maintenance Minder oil life percentage on Honda/Acura vehicles.",
    manufacturer="honda",
    applicable_models=["Civic", "Accord", "CR-V", "Pilot", "Odyssey", "HR-V", "Ridgeline", "MDX", "RDX"],
    prerequisites=["Key ON, engine OFF", "Oil change completed"],
    steps_description=[
        "Enter extended diagnostic session",
        "Write oil life counter reset",
    ],
    module_addr="0x7E0",
    bus="HS-CAN",
    session_type=SESSION_EXTENDED,
    uds_sequence=[
        {"command": "1003", "description": "Extended session", "expected_positive": "50"},
        {"command": "2E012164", "description": "Reset oil life to 100%", "expected_positive": "6E"},
    ],
    estimated_time_seconds=5,
))

_register(CalibrationRoutine(
    id="hyundai_oil_reset",
    name="Hyundai/Kia Oil Maintenance Reset",
    category=CalibrationCategory.OIL_RESET,
    difficulty=DifficultyLevel.EASY,
    risk=RiskLevel.SAFE,
    description="Reset oil service interval reminder on Hyundai/Kia vehicles.",
    manufacturer="hyundai",
    applicable_models=["Sonata", "Elantra", "Tucson", "Santa Fe", "K5", "Sportage", "Sorento", "Telluride"],
    prerequisites=["Key ON, engine OFF", "Oil change completed"],
    steps_description=[
        "Enter extended session",
        "Write service interval reset to cluster",
    ],
    module_addr="0x7C0",
    bus="HS-CAN",
    session_type=SESSION_EXTENDED,
    uds_sequence=[
        {"command": "1003", "description": "Extended session", "expected_positive": "50"},
        {"command": "2EF20000", "description": "Reset service interval", "expected_positive": "6E"},
    ],
    estimated_time_seconds=5,
))

_register(CalibrationRoutine(
    id="bmw_oil_reset",
    name="BMW Oil Service Reset",
    category=CalibrationCategory.OIL_RESET,
    difficulty=DifficultyLevel.MODERATE,
    risk=RiskLevel.SAFE,
    description="Reset CBS (Condition Based Service) oil counter on BMW vehicles.",
    manufacturer="bmw",
    applicable_models=["3 Series", "5 Series", "X3", "X5", "1 Series", "X1"],
    prerequisites=["Key ON, engine OFF", "Oil change completed"],
    steps_description=[
        "Enter extended session on instrument cluster",
        "Reset CBS oil service counter via RoutineControl",
    ],
    module_addr="0x720",
    bus="HS-CAN",
    session_type=SESSION_EXTENDED,
    uds_sequence=[
        {"command": "1003", "description": "Extended session on KOMBI", "expected_positive": "50"},
        {"command": "3101FF01", "description": "Reset CBS oil counter", "expected_positive": "71"},
    ],
    estimated_time_seconds=10,
    notes="BMW uses CBS (Condition Based Service) system. Some models require ISTA for full reset.",
))

_register(CalibrationRoutine(
    id="vw_oil_reset",
    name="VW/Audi Oil Service Reset",
    category=CalibrationCategory.OIL_RESET,
    difficulty=DifficultyLevel.EASY,
    risk=RiskLevel.SAFE,
    description="Reset oil service interval indicator on VW/Audi vehicles.",
    manufacturer="vw",
    applicable_models=["Golf", "Jetta", "Tiguan", "Atlas", "A3", "A4", "A5", "Q5"],
    prerequisites=["Key ON, engine OFF", "Oil change completed"],
    steps_description=[
        "Enter extended session on instrument cluster",
        "Write service reset to cluster",
    ],
    module_addr="0x714",
    bus="HS-CAN",
    session_type=SESSION_EXTENDED,
    uds_sequence=[
        {"command": "1003", "description": "Extended session", "expected_positive": "50"},
        {"command": "2E04A200", "description": "Reset oil service indicator", "expected_positive": "6E"},
    ],
    estimated_time_seconds=5,
))


# ---------------------------------------------------------------------------
# Throttle Body / Idle Relearn
# ---------------------------------------------------------------------------

_register(CalibrationRoutine(
    id="ford_throttle_relearn",
    name="Ford Throttle Body Relearn",
    category=CalibrationCategory.THROTTLE_RELEARN,
    difficulty=DifficultyLevel.MODERATE,
    risk=RiskLevel.MEDIUM,
    description="Reset throttle body adaptation values after cleaning or replacing the electronic throttle body. Engine may idle rough temporarily.",
    manufacturer="ford",
    applicable_models=["F-150", "Explorer", "Edge", "Fusion", "Escape", "Mustang", "MKZ", "MKS"],
    prerequisites=[
        "Key ON, engine OFF",
        "Throttle body installed and connector plugged in",
        "No throttle-related DTCs (clear first)",
    ],
    steps_description=[
        "Enter extended diagnostic session on PCM",
        "Execute throttle adaptation reset routine",
        "Start engine and let idle for 3 minutes",
        "Drive vehicle for 10 minutes for full adaptation",
    ],
    module_addr="0x7E0",
    bus="HS-CAN",
    session_type=SESSION_EXTENDED,
    uds_sequence=[
        {"command": "1003", "description": "Extended session", "expected_positive": "50"},
        {"command": "3101F001", "description": "Start throttle adaptation reset", "expected_positive": "71"},
        {"command": "310301", "description": "Request routine result", "expected_positive": "71"},
    ],
    requires_ignition_cycle=True,
    estimated_time_seconds=15,
    notes="After relearn, engine may idle rough for 3-5 minutes while PCM re-adapts. "
          "Normal — do NOT clear DTCs during adaptation. Drive cycle completes it.",
))

_register(CalibrationRoutine(
    id="gm_throttle_relearn",
    name="GM Throttle Position Relearn",
    category=CalibrationCategory.THROTTLE_RELEARN,
    difficulty=DifficultyLevel.MODERATE,
    risk=RiskLevel.MEDIUM,
    description="Reset GM TAC (Throttle Actuator Control) module adaptation values.",
    manufacturer="gm",
    applicable_models=["Silverado", "Sierra", "Tahoe", "Suburban", "Equinox", "Malibu", "Camaro"],
    prerequisites=[
        "Key ON, engine OFF",
        "No TAC DTCs present",
        "Throttle body clean/installed correctly",
    ],
    steps_description=[
        "Enter extended session",
        "Clear TAC adaptation values",
        "Cycle ignition OFF for 30 seconds, then ON",
        "Start engine and idle for 5 minutes",
    ],
    module_addr="0x7E0",
    bus="HS-CAN",
    session_type=SESSION_EXTENDED,
    uds_sequence=[
        {"command": "1003", "description": "Extended session", "expected_positive": "50"},
        {"command": "3101F001", "description": "Reset TAC adaptation", "expected_positive": "71"},
    ],
    requires_ignition_cycle=True,
    estimated_time_seconds=10,
))

_register(CalibrationRoutine(
    id="toyota_throttle_relearn",
    name="Toyota Throttle Body Relearn",
    category=CalibrationCategory.THROTTLE_RELEARN,
    difficulty=DifficultyLevel.MODERATE,
    risk=RiskLevel.MEDIUM,
    description="Reset ETCS (Electronic Throttle Control System) idle learned values on Toyota vehicles.",
    manufacturer="toyota",
    applicable_models=["Camry", "Corolla", "RAV4", "Highlander", "Tacoma", "Tundra"],
    prerequisites=[
        "Key ON, engine OFF",
        "Coolant temp between 75-100°C (167-212°F)",
        "No ETCS DTCs active",
    ],
    steps_description=[
        "Verify coolant temp is at operating temp",
        "Enter extended session on ECM",
        "Execute idle speed learning routine",
        "Let engine idle for 5 minutes undisturbed",
    ],
    module_addr="0x7E0",
    bus="HS-CAN",
    session_type=SESSION_EXTENDED,
    uds_sequence=[
        {"command": "1003", "description": "Extended session", "expected_positive": "50"},
        {"command": "3101F001", "description": "Start idle learning", "expected_positive": "71"},
    ],
    requires_engine_running=True,
    estimated_time_seconds=10,
))

_register(CalibrationRoutine(
    id="honda_idle_relearn",
    name="Honda Idle Learn Procedure",
    category=CalibrationCategory.THROTTLE_RELEARN,
    difficulty=DifficultyLevel.MODERATE,
    risk=RiskLevel.MEDIUM,
    description="Reset idle air volume learning on Honda/Acura vehicles after throttle body cleaning or battery disconnect.",
    manufacturer="honda",
    applicable_models=["Civic", "Accord", "CR-V", "Pilot", "Odyssey", "MDX", "RDX"],
    prerequisites=[
        "Engine at operating temperature",
        "All accessories OFF",
        "Steering wheel centered",
    ],
    steps_description=[
        "Enter extended session on ECM/PCM",
        "Execute idle learn reset routine",
        "Let engine idle for 10 minutes with A/C off",
    ],
    module_addr="0x7E0",
    bus="HS-CAN",
    session_type=SESSION_EXTENDED,
    uds_sequence=[
        {"command": "1003", "description": "Extended session", "expected_positive": "50"},
        {"command": "3101F001", "description": "Reset idle air volume", "expected_positive": "71"},
    ],
    requires_engine_running=True,
    estimated_time_seconds=10,
))


# ---------------------------------------------------------------------------
# TPMS Relearn / Reset
# ---------------------------------------------------------------------------

_register(CalibrationRoutine(
    id="ford_tpms_reset",
    name="Ford TPMS Sensor Relearn",
    category=CalibrationCategory.TPMS,
    difficulty=DifficultyLevel.MODERATE,
    risk=RiskLevel.LOW,
    description="Put the BCM/GEM into TPMS learn mode so it can register new or rotated tire sensors.",
    manufacturer="ford",
    applicable_models=["F-150", "Explorer", "Edge", "Fusion", "Escape", "Mustang", "Transit"],
    prerequisites=[
        "Key ON, engine OFF",
        "All tires inflated to placard pressure",
        "TPMS trigger tool available (or 20+ PSI drop method)",
    ],
    steps_description=[
        "Enter TPMS learn mode on BCM",
        "Trigger each sensor in order: LF → RF → RR → LR",
        "BCM will honk horn once per learned sensor, twice when complete",
    ],
    module_addr="0x726",
    bus="MS-CAN",
    session_type=SESSION_EXTENDED,
    uds_sequence=[
        {"command": "1003", "description": "Extended session on GEM/BCM", "expected_positive": "50"},
        {"command": "3101FF10", "description": "Enter TPMS learn mode", "expected_positive": "71"},
    ],
    estimated_time_seconds=120,
    notes="Sensors must be triggered in LF→RF→RR→LR order. Use a TPMS activation tool "
          "or rapidly deflate/inflate each tire by 20+ PSI to wake the sensor.",
))

_register(CalibrationRoutine(
    id="gm_tpms_relearn",
    name="GM TPMS Sensor Relearn",
    category=CalibrationCategory.TPMS,
    difficulty=DifficultyLevel.MODERATE,
    risk=RiskLevel.LOW,
    description="Register TPMS sensors with the BCM after tire rotation or sensor replacement.",
    manufacturer="gm",
    applicable_models=["Silverado", "Sierra", "Tahoe", "Equinox", "Traverse", "Malibu", "Camaro"],
    prerequisites=[
        "Key ON, engine OFF",
        "All tires at placard pressure",
        "TPMS activation tool available",
    ],
    steps_description=[
        "Enter TPMS learn mode via BCM",
        "Trigger each sensor: LF → RF → RR → LR (→ spare if equipped)",
        "Horn chirps confirm each sensor learned",
    ],
    module_addr="0x741",
    bus="HS-CAN",
    session_type=SESSION_EXTENDED,
    uds_sequence=[
        {"command": "1003", "description": "Extended session", "expected_positive": "50"},
        {"command": "3101FF10", "description": "Enter TPMS learn mode", "expected_positive": "71"},
    ],
    estimated_time_seconds=120,
))

_register(CalibrationRoutine(
    id="universal_tpms_check",
    name="TPMS Sensor Status Check",
    category=CalibrationCategory.TPMS,
    difficulty=DifficultyLevel.EASY,
    risk=RiskLevel.SAFE,
    description="Read TPMS sensor data (pressure, temperature, battery status) from the TPMS module.",
    manufacturer="universal",
    applicable_models=["All 2008+ US vehicles"],
    prerequisites=["Key ON"],
    steps_description=[
        "Read TPMS DIDs from BCM/dedicated TPMS module",
        "Display tire pressures and sensor IDs",
    ],
    module_addr="0x724",
    bus="HS-CAN",
    session_type=SESSION_DEFAULT,
    uds_sequence=[
        {"command": "22DD01", "description": "Read TPMS sensor data", "expected_positive": "62"},
    ],
    estimated_time_seconds=5,
))


# ---------------------------------------------------------------------------
# Battery Registration / BMS Reset
# ---------------------------------------------------------------------------

_register(CalibrationRoutine(
    id="bmw_battery_registration",
    name="BMW Battery Registration",
    category=CalibrationCategory.BATTERY,
    difficulty=DifficultyLevel.ADVANCED,
    risk=RiskLevel.HIGH,
    description="Register a new battery with the BMW power management system (BMS/IBS). "
                "Required after battery replacement to prevent overcharging or undercharging.",
    manufacturer="bmw",
    applicable_models=["3 Series", "5 Series", "7 Series", "X1", "X3", "X5", "X6", "X7"],
    prerequisites=[
        "New battery installed",
        "Key ON, engine OFF",
        "Know battery Ah rating and type (AGM, EFB, etc.)",
    ],
    steps_description=[
        "Enter extended session on BDC/power management module",
        "Security access (may be required on some models)",
        "Write battery capacity (Ah) and type to BMS",
        "Reset charge cycle counter",
    ],
    module_addr="0x740",
    bus="HS-CAN",
    session_type=SESSION_EXTENDED,
    security_level=1,
    uds_sequence=[
        {"command": "1003", "description": "Extended session on BDC", "expected_positive": "50"},
        {"command": "2701", "description": "Request security seed (level 1)", "expected_positive": "67"},
        {"command": "2E1032XX", "description": "Write battery Ah rating (XX = Ah hex)", "expected_positive": "6E"},
        {"command": "3101F006", "description": "Reset battery charge counter", "expected_positive": "71"},
    ],
    requires_ignition_cycle=True,
    estimated_time_seconds=30,
    notes="CRITICAL: Incorrect battery registration can cause overcharging (fire risk) or "
          "premature battery death. Ensure correct Ah and type. AGM=0x01, Lead-acid=0x00.",
))

_register(CalibrationRoutine(
    id="ford_battery_monitor_reset",
    name="Ford Battery Monitor Reset",
    category=CalibrationCategory.BATTERY,
    difficulty=DifficultyLevel.MODERATE,
    risk=RiskLevel.LOW,
    description="Reset the Battery Monitoring System (BMS) after battery replacement on Ford vehicles with Intelligent Battery Sensor.",
    manufacturer="ford",
    applicable_models=["F-150 2015+", "Explorer 2016+", "Edge 2015+", "Expedition 2018+"],
    prerequisites=[
        "New battery installed",
        "Key ON, engine OFF",
    ],
    steps_description=[
        "Enter extended session on PCM",
        "Reset BMS learned values",
        "Cycle ignition",
    ],
    module_addr="0x7E0",
    bus="HS-CAN",
    session_type=SESSION_EXTENDED,
    uds_sequence=[
        {"command": "1003", "description": "Extended session", "expected_positive": "50"},
        {"command": "3101F007", "description": "Reset BMS learned values", "expected_positive": "71"},
    ],
    requires_ignition_cycle=True,
    estimated_time_seconds=10,
))

_register(CalibrationRoutine(
    id="vw_battery_adaptation",
    name="VW/Audi Battery Adaptation",
    category=CalibrationCategory.BATTERY,
    difficulty=DifficultyLevel.ADVANCED,
    risk=RiskLevel.HIGH,
    description="Adapt the power management module to a new battery on VW/Audi vehicles. "
                "Required to prevent overcharging AGM batteries.",
    manufacturer="vw",
    applicable_models=["Golf", "Jetta", "Tiguan", "A3", "A4", "Q5", "Passat"],
    prerequisites=[
        "New battery installed",
        "Battery part number known",
        "Key ON, engine OFF",
    ],
    steps_description=[
        "Enter extended session on power management module",
        "Write battery part number and capacity",
        "Reset charge counters",
    ],
    module_addr="0x740",
    bus="HS-CAN",
    session_type=SESSION_EXTENDED,
    security_level=1,
    uds_sequence=[
        {"command": "1003", "description": "Extended session", "expected_positive": "50"},
        {"command": "2701", "description": "Security seed request", "expected_positive": "67"},
        {"command": "2E0336XX", "description": "Write battery parameters", "expected_positive": "6E"},
    ],
    requires_ignition_cycle=True,
    estimated_time_seconds=30,
    notes="Battery coding via VCDS/OBD11 is the best-supported path for VW. "
          "UDS direct write may require manufacturer seed/key algorithm.",
))


# ---------------------------------------------------------------------------
# Steering Angle Sensor Calibration
# ---------------------------------------------------------------------------

_register(CalibrationRoutine(
    id="ford_sas_calibration",
    name="Ford Steering Angle Sensor Calibration",
    category=CalibrationCategory.SAS_CAL,
    difficulty=DifficultyLevel.MODERATE,
    risk=RiskLevel.MEDIUM,
    description="Calibrate the steering angle sensor after alignment, steering component replacement, ABS module replacement, or sensor replacement.",
    manufacturer="ford",
    applicable_models=["F-150", "Explorer", "Edge", "Fusion", "Escape", "MKZ", "MKS", "MKX"],
    prerequisites=[
        "Wheels straight ahead (centered)",
        "Key ON, engine running",
        "No ABS DTCs (clear first)",
    ],
    steps_description=[
        "Center steering wheel and hold straight",
        "Enter extended session on ABS module",
        "Start SAS calibration routine",
        "Slowly turn wheel lock-to-lock when prompted",
        "Return wheel to center",
    ],
    module_addr="0x760",
    bus="HS-CAN",
    session_type=SESSION_EXTENDED,
    uds_sequence=[
        {"command": "1003", "description": "Extended session on ABS", "expected_positive": "50"},
        {"command": "3101FF20", "description": "Start SAS calibration", "expected_positive": "71"},
    ],
    requires_engine_running=True,
    estimated_time_seconds=60,
    notes="Some Ford models auto-calibrate during a specific drive pattern (straight → full left → full right → straight).",
))

_register(CalibrationRoutine(
    id="gm_sas_calibration",
    name="GM Steering Position Sensor Learn",
    category=CalibrationCategory.SAS_CAL,
    difficulty=DifficultyLevel.MODERATE,
    risk=RiskLevel.MEDIUM,
    description="Reset the SPS (Steering Position Sensor) zero point after alignment or steering work.",
    manufacturer="gm",
    applicable_models=["Silverado", "Sierra", "Tahoe", "Equinox", "Malibu", "Camaro"],
    prerequisites=[
        "Wheels straight ahead",
        "Key ON, engine running",
        "Alignment completed",
    ],
    steps_description=[
        "Center steering wheel",
        "Enter extended session on EBCM",
        "Execute SPS calibration",
        "Drive in straight line for 100 ft to verify",
    ],
    module_addr="0x741",
    bus="HS-CAN",
    session_type=SESSION_EXTENDED,
    uds_sequence=[
        {"command": "1003", "description": "Extended session", "expected_positive": "50"},
        {"command": "3101FF20", "description": "Start steering angle learn", "expected_positive": "71"},
    ],
    requires_engine_running=True,
    estimated_time_seconds=30,
))

_register(CalibrationRoutine(
    id="universal_sas_reset",
    name="Universal Steering Angle Reset",
    category=CalibrationCategory.SAS_CAL,
    difficulty=DifficultyLevel.EASY,
    risk=RiskLevel.LOW,
    description="Attempt steering angle sensor reset on any vehicle via standard ABS module routine.",
    manufacturer="universal",
    applicable_models=["Most 2008+ vehicles with electronic stability control"],
    prerequisites=[
        "Wheels straight ahead",
        "Key ON",
    ],
    steps_description=[
        "Center steering wheel precisely",
        "Attempt SAS calibration routine on ABS module",
    ],
    module_addr="0x760",
    bus="HS-CAN",
    session_type=SESSION_EXTENDED,
    uds_sequence=[
        {"command": "1003", "description": "Extended session on ABS", "expected_positive": "50"},
        {"command": "3101FF20", "description": "SAS calibration routine", "expected_positive": "71"},
    ],
    estimated_time_seconds=30,
    notes="May not work on all vehicles. Some OEMs use different routine IDs.",
))


# ---------------------------------------------------------------------------
# Brake Service (EPB / Parking Brake)
# ---------------------------------------------------------------------------

_register(CalibrationRoutine(
    id="ford_epb_service_mode",
    name="Ford Electronic Parking Brake Service Mode",
    category=CalibrationCategory.BRAKE_SERVICE,
    difficulty=DifficultyLevel.MODERATE,
    risk=RiskLevel.HIGH,
    description="Put the EPB into service mode to retract caliper pistons for brake pad replacement.",
    manufacturer="ford",
    applicable_models=["Explorer 2016+", "Edge 2015+", "Fusion 2013+", "MKZ 2013+", "MKX 2016+", "Expedition 2018+"],
    prerequisites=[
        "Vehicle on level ground",
        "Key ON, engine OFF",
        "EPB switch released",
    ],
    steps_description=[
        "Enter extended session on EPB/parking brake module",
        "Command EPB into service/retract mode",
        "Replace brake pads while calipers are retracted",
        "Exit service mode to re-extend calipers",
    ],
    module_addr="0x760",
    bus="HS-CAN",
    session_type=SESSION_EXTENDED,
    uds_sequence=[
        {"command": "1003", "description": "Extended session", "expected_positive": "50"},
        {"command": "3101F003", "description": "Enter EPB service mode (retract)", "expected_positive": "71"},
    ],
    estimated_time_seconds=30,
    notes="IMPORTANT: Exit service mode with routine 0x3101F004 after pad installation. "
          "Failure to exit will leave brakes in retracted state!",
))

_register(CalibrationRoutine(
    id="ford_epb_exit_service",
    name="Ford EPB Exit Service Mode",
    category=CalibrationCategory.BRAKE_SERVICE,
    difficulty=DifficultyLevel.MODERATE,
    risk=RiskLevel.HIGH,
    description="Exit EPB service mode and re-apply the electronic parking brake after brake service.",
    manufacturer="ford",
    applicable_models=["Explorer 2016+", "Edge 2015+", "Fusion 2013+", "MKZ 2013+"],
    prerequisites=[
        "New brake pads installed",
        "Caliper bolts torqued to spec",
        "EPB currently in service mode",
    ],
    steps_description=[
        "Enter extended session on EPB module",
        "Exit service mode (re-extend calipers)",
        "Verify EPB applies normally",
    ],
    module_addr="0x760",
    bus="HS-CAN",
    session_type=SESSION_EXTENDED,
    uds_sequence=[
        {"command": "1003", "description": "Extended session", "expected_positive": "50"},
        {"command": "3101F004", "description": "Exit EPB service mode (re-apply)", "expected_positive": "71"},
    ],
    estimated_time_seconds=30,
))

_register(CalibrationRoutine(
    id="gm_epb_service",
    name="GM Electronic Parking Brake Service",
    category=CalibrationCategory.BRAKE_SERVICE,
    difficulty=DifficultyLevel.MODERATE,
    risk=RiskLevel.HIGH,
    description="Retract/extend GM EPB calipers for brake pad service.",
    manufacturer="gm",
    applicable_models=["Malibu 2016+", "Equinox 2018+", "Blazer", "CT4", "CT5", "XT4", "XT5"],
    prerequisites=[
        "Vehicle on level ground",
        "Key ON, engine OFF",
        "EPB released",
    ],
    steps_description=[
        "Enter extended session on EPB module",
        "Retract EPB calipers",
        "Replace pads",
        "Extend EPB calipers",
    ],
    module_addr="0x760",
    bus="HS-CAN",
    session_type=SESSION_EXTENDED,
    uds_sequence=[
        {"command": "1003", "description": "Extended session", "expected_positive": "50"},
        {"command": "3101F003", "description": "Retract EPB calipers", "expected_positive": "71"},
    ],
    estimated_time_seconds=30,
))

_register(CalibrationRoutine(
    id="vw_epb_service",
    name="VW/Audi EPB Service Mode",
    category=CalibrationCategory.BRAKE_SERVICE,
    difficulty=DifficultyLevel.MODERATE,
    risk=RiskLevel.HIGH,
    description="Enter EPB maintenance mode for brake pad replacement on VW/Audi vehicles.",
    manufacturer="vw",
    applicable_models=["Passat", "Tiguan", "Atlas", "A4", "A5", "Q5", "Q7"],
    prerequisites=[
        "Key ON, engine OFF",
        "EPB switch in released position",
    ],
    steps_description=[
        "Enter extended session on ABS module",
        "Enter EPB maintenance mode",
        "Perform brake service",
        "Exit maintenance mode",
    ],
    module_addr="0x713",
    bus="HS-CAN",
    session_type=SESSION_EXTENDED,
    uds_sequence=[
        {"command": "1003", "description": "Extended session", "expected_positive": "50"},
        {"command": "3101F003", "description": "Enter EPB service mode", "expected_positive": "71"},
    ],
    estimated_time_seconds=30,
))


# ---------------------------------------------------------------------------
# Transmission Adaptation Reset
# ---------------------------------------------------------------------------

_register(CalibrationRoutine(
    id="ford_transmission_reset",
    name="Ford Transmission Adaptive Learning Reset",
    category=CalibrationCategory.TRANSMISSION,
    difficulty=DifficultyLevel.MODERATE,
    risk=RiskLevel.MEDIUM,
    description="Reset transmission adaptive shift tables after TCM replacement or to address shift quality concerns.",
    manufacturer="ford",
    applicable_models=["F-150", "Explorer", "Edge", "Fusion", "Mustang", "Expedition"],
    prerequisites=[
        "Key ON, engine OFF",
        "No transmission DTCs",
        "Fluid level correct",
    ],
    steps_description=[
        "Enter extended session on TCM",
        "Reset adaptive shift parameters",
        "Cycle ignition",
        "Drive vehicle through all gears for 30 minutes to re-adapt",
    ],
    module_addr="0x7E1",
    bus="HS-CAN",
    session_type=SESSION_EXTENDED,
    uds_sequence=[
        {"command": "1003", "description": "Extended session on TCM", "expected_positive": "50"},
        {"command": "3101F001", "description": "Reset shift adaptation tables", "expected_positive": "71"},
    ],
    requires_ignition_cycle=True,
    estimated_time_seconds=10,
    notes="Shifts may be firm/harsh for 30+ miles while TCM re-learns driver habits. "
          "This is normal after a reset. Full adaptation takes 500-1000 miles.",
))

_register(CalibrationRoutine(
    id="gm_transmission_reset",
    name="GM Transmission Adaptation Reset",
    category=CalibrationCategory.TRANSMISSION,
    difficulty=DifficultyLevel.MODERATE,
    risk=RiskLevel.MEDIUM,
    description="Clear GM TCM adaptive values to address shift quality problems.",
    manufacturer="gm",
    applicable_models=["Silverado", "Sierra", "Tahoe", "Equinox", "Traverse", "Malibu"],
    prerequisites=[
        "Key ON, engine OFF",
        "No TCM DTCs",
    ],
    steps_description=[
        "Enter extended session on TCM",
        "Clear shift adaptation values",
        "Cycle ignition and drive for re-adaptation",
    ],
    module_addr="0x7E1",
    bus="HS-CAN",
    session_type=SESSION_EXTENDED,
    uds_sequence=[
        {"command": "1003", "description": "Extended session", "expected_positive": "50"},
        {"command": "3101F001", "description": "Reset TCM adaptation", "expected_positive": "71"},
    ],
    requires_ignition_cycle=True,
    estimated_time_seconds=10,
))


# ---------------------------------------------------------------------------
# DPF Regeneration (Diesel)
# ---------------------------------------------------------------------------

_register(CalibrationRoutine(
    id="ford_dpf_regen",
    name="Ford DPF Forced Regeneration",
    category=CalibrationCategory.DPF_REGEN,
    difficulty=DifficultyLevel.ADVANCED,
    risk=RiskLevel.HIGH,
    description="Force a DPF (Diesel Particulate Filter) regeneration cycle on Ford diesel vehicles. "
                "Exhaust temperatures will exceed 600°C (1100°F).",
    manufacturer="ford",
    applicable_models=["F-250 6.7L", "F-350 6.7L", "F-450 6.7L", "Transit 3.2L"],
    prerequisites=[
        "Engine at operating temperature",
        "Vehicle STATIONARY in Park",
        "Clear area — NO flammable materials near exhaust",
        "Fuel level above 1/4 tank",
        "No active DPF DTCs (address root cause first)",
    ],
    steps_description=[
        "Verify all prerequisites are met — fire hazard!",
        "Enter extended session on PCM",
        "Start forced DPF regeneration routine",
        "Monitor exhaust temps (will reach 600-700°C)",
        "Wait 20-40 minutes for completion",
        "Do NOT turn off engine during regen",
    ],
    module_addr="0x7E0",
    bus="HS-CAN",
    session_type=SESSION_EXTENDED,
    uds_sequence=[
        {"command": "1003", "description": "Extended session", "expected_positive": "50"},
        {"command": "3101F010", "description": "Start forced DPF regen", "expected_positive": "71"},
    ],
    requires_engine_running=True,
    estimated_time_seconds=2400,
    notes="⚠️ FIRE HAZARD: Exhaust gases exceed 1100°F during regen. Never perform near "
          "flammable materials, in enclosed spaces, or with people near the tailpipe. "
          "If the engine stalls during regen, wait for exhaust to cool before restarting.",
))

_register(CalibrationRoutine(
    id="gm_dpf_regen",
    name="GM DPF Forced Regeneration",
    category=CalibrationCategory.DPF_REGEN,
    difficulty=DifficultyLevel.ADVANCED,
    risk=RiskLevel.HIGH,
    description="Force DPF regeneration on GM Duramax diesel vehicles.",
    manufacturer="gm",
    applicable_models=["Silverado 2500/3500 Duramax", "Sierra 2500/3500 Duramax"],
    prerequisites=[
        "Engine at operating temp",
        "Vehicle in Park, stationary",
        "No flammable materials near exhaust",
        "Fuel above 1/4 tank",
    ],
    steps_description=[
        "Enter extended session on ECM",
        "Start forced DPF regeneration",
        "Monitor soot level and exhaust temp",
        "Wait 20-40 minutes for completion",
    ],
    module_addr="0x7E0",
    bus="HS-CAN",
    session_type=SESSION_EXTENDED,
    uds_sequence=[
        {"command": "1003", "description": "Extended session", "expected_positive": "50"},
        {"command": "3101F010", "description": "Start DPF regen", "expected_positive": "71"},
    ],
    requires_engine_running=True,
    estimated_time_seconds=2400,
    notes="⚠️ FIRE HAZARD: Same warnings as Ford DPF regen apply.",
))


# ---------------------------------------------------------------------------
# Miscellaneous / General
# ---------------------------------------------------------------------------

_register(CalibrationRoutine(
    id="ford_abs_bleed",
    name="Ford ABS Automated Bleed",
    category=CalibrationCategory.ABS_BLEED,
    difficulty=DifficultyLevel.ADVANCED,
    risk=RiskLevel.HIGH,
    description="Activate ABS pump and solenoids to bleed air from the ABS hydraulic unit. "
                "Required after ABS module replacement or when air enters the HCU.",
    manufacturer="ford",
    applicable_models=["F-150", "Explorer", "Edge", "Fusion", "Escape"],
    prerequisites=[
        "Conventional brake bleeding completed first",
        "Brake fluid reservoir full",
        "Bleeder person at each wheel with wrench",
    ],
    steps_description=[
        "Enter extended session on ABS module",
        "Start ABS bleed routine (activates pump and valves)",
        "Open/close bleeders in sequence as directed",
        "Repeat until pedal is firm",
    ],
    module_addr="0x760",
    bus="HS-CAN",
    session_type=SESSION_EXTENDED,
    uds_sequence=[
        {"command": "1003", "description": "Extended session on ABS", "expected_positive": "50"},
        {"command": "3101F008", "description": "Start ABS automated bleed", "expected_positive": "71"},
    ],
    estimated_time_seconds=300,
    notes="Requires a helper at each wheel. Keep reservoir topped off throughout. "
          "If pedal is still spongy, repeat the bleed cycle.",
))

_register(CalibrationRoutine(
    id="injector_coding_universal",
    name="Injector Code Programming (Info)",
    category=CalibrationCategory.INJECTOR,
    difficulty=DifficultyLevel.ADVANCED,
    risk=RiskLevel.HIGH,
    description="Write injector compensation codes to the ECM after injector replacement. "
                "Each injector has a unique correction code printed on it or etched into the body.",
    manufacturer="universal",
    applicable_models=["Diesel vehicles with piezo or solenoid injectors"],
    prerequisites=[
        "New injector installed",
        "Injector correction code from the injector body (e.g., 6-digit alphanumeric)",
        "Know which cylinder(s) were replaced",
    ],
    steps_description=[
        "Enter extended session on ECM",
        "Security access (usually required)",
        "Write injector trim code for the replaced cylinder(s)",
        "Clear DTCs and verify",
    ],
    module_addr="0x7E0",
    bus="HS-CAN",
    session_type=SESSION_EXTENDED,
    security_level=1,
    uds_sequence=[
        {"command": "1003", "description": "Extended session", "expected_positive": "50"},
        {"command": "2701", "description": "Request security seed", "expected_positive": "67"},
    ],
    estimated_time_seconds=60,
    notes="Injector codes are manufacturer and model specific. The DID for writing "
          "injector trim codes varies by OEM. This template provides the session setup — "
          "the actual code writing requires OEM-specific DIDs.",
))

_register(CalibrationRoutine(
    id="gm_crankshaft_relearn",
    name="GM Crankshaft Position Variation Relearn",
    category=CalibrationCategory.GENERAL,
    difficulty=DifficultyLevel.MODERATE,
    risk=RiskLevel.MEDIUM,
    description="Relearn crankshaft position sensor variation after ECM, crankshaft sensor, or engine replacement. "
                "Required for proper misfire detection.",
    manufacturer="gm",
    applicable_models=["Silverado", "Sierra", "Tahoe", "Camaro", "Corvette", "Malibu"],
    prerequisites=[
        "Engine at operating temperature (above 70°C/158°F)",
        "Vehicle in Park on level ground",
        "No DTCs related to crank/cam sensor",
    ],
    steps_description=[
        "Enter extended session on ECM",
        "Start crankshaft variation learn routine",
        "Rev engine to ~4000 RPM when prompted",
        "Quickly release throttle (fuel cut)",
        "ECM learns crank variation during deceleration",
        "Repeat 2-3 times until routine completes",
    ],
    module_addr="0x7E0",
    bus="HS-CAN",
    session_type=SESSION_EXTENDED,
    uds_sequence=[
        {"command": "1003", "description": "Extended session", "expected_positive": "50"},
        {"command": "3101F002", "description": "Start CKP variation learn", "expected_positive": "71"},
    ],
    requires_engine_running=True,
    estimated_time_seconds=120,
))


# ===========================================================================
# Calibration Executor
# ===========================================================================

class CalibrationExecutor:
    """
    Executes calibration routines against a live vehicle.
    
    Takes a protocol instance and runs the UDS command sequence,
    handling session changes and error checking.
    """

    def __init__(self, protocol):
        """
        Args:
            protocol: OBDProtocol instance (from protocol.py)
        """
        self.protocol = protocol

    async def execute(
        self,
        routine: CalibrationRoutine,
        on_step: Optional[callable] = None,
        **kwargs,
    ) -> CalibrationResult:
        """
        Execute a calibration routine.

        Args:
            routine: The CalibrationRoutine to execute
            on_step: Optional callback(step_num, total, description)
            **kwargs: Additional parameters (e.g., battery_ah for BMW registration)

        Returns:
            CalibrationResult with success/failure and messages
        """
        messages = []
        raw_responses = []
        steps_completed = 0
        total_steps = len(routine.uds_sequence)

        try:
            # Set headers for target module
            module_addr = routine.module_addr
            if module_addr.startswith("0x"):
                module_addr = module_addr[2:]
            
            await self.protocol.connection.send_command(f"ATSH{module_addr}", timeout=2.0)
            
            # Set bus if needed
            if routine.bus == "MS-CAN":
                await self.protocol.connection.send_command("STPBR 125000", timeout=2.0)
            
            for i, step in enumerate(routine.uds_sequence):
                if on_step:
                    try:
                        on_step(i + 1, total_steps, step["description"])
                    except Exception:
                        pass

                cmd = step["command"]
                
                # Substitute any kwargs into command (e.g., battery Ah)
                for k, v in kwargs.items():
                    placeholder = f"XX"
                    if placeholder in cmd:
                        if isinstance(v, int):
                            cmd = cmd.replace(placeholder, f"{v:02X}", 1)
                        else:
                            cmd = cmd.replace(placeholder, str(v), 1)

                response = await self.protocol.connection.send_command(cmd, timeout=10.0)
                raw_responses.append(response)

                # Check for positive response
                expected = step.get("expected_positive", "")
                if expected and expected.upper() in response.upper().replace(" ", ""):
                    messages.append(f"Step {i+1}: {step['description']} — OK")
                    steps_completed += 1
                elif "ERROR" in response.upper() or "NO DATA" in response.upper():
                    messages.append(f"Step {i+1}: {step['description']} — FAILED: {response}")
                    return CalibrationResult(
                        routine_id=routine.id,
                        routine_name=routine.name,
                        success=False,
                        steps_completed=steps_completed,
                        total_steps=total_steps,
                        messages=messages,
                        raw_responses=raw_responses,
                        error=f"Step {i+1} failed: {response}",
                    )
                elif "7F" in response.replace(" ", ""):
                    # Negative response
                    messages.append(f"Step {i+1}: {step['description']} — Rejected: {response}")
                    return CalibrationResult(
                        routine_id=routine.id,
                        routine_name=routine.name,
                        success=False,
                        steps_completed=steps_completed,
                        total_steps=total_steps,
                        messages=messages,
                        raw_responses=raw_responses,
                        error=f"ECU rejected command at step {i+1}",
                    )
                else:
                    # Unknown response — treat as success but note it
                    messages.append(f"Step {i+1}: {step['description']} — Response: {response}")
                    steps_completed += 1

            # Success
            if routine.requires_ignition_cycle:
                messages.append("⚠️ Cycle ignition OFF for 30 seconds, then back ON to complete.")
            
            return CalibrationResult(
                routine_id=routine.id,
                routine_name=routine.name,
                success=True,
                steps_completed=steps_completed,
                total_steps=total_steps,
                messages=messages,
                raw_responses=raw_responses,
            )

        except Exception as e:
            logger.error(f"Calibration {routine.id} failed: {e}")
            return CalibrationResult(
                routine_id=routine.id,
                routine_name=routine.name,
                success=False,
                steps_completed=steps_completed,
                total_steps=total_steps,
                messages=messages,
                raw_responses=raw_responses,
                error=str(e),
            )
        finally:
            # Restore defaults
            try:
                await self.protocol.connection.send_command("ATD", timeout=2.0)
                if routine.bus == "MS-CAN":
                    await self.protocol.connection.send_command("STPBR 500000", timeout=2.0)
            except Exception:
                pass


# ===========================================================================
# Public API
# ===========================================================================

def get_calibration(routine_id: str) -> Optional[CalibrationRoutine]:
    """Get a calibration routine by ID."""
    return CALIBRATION_LIBRARY.get(routine_id)


def list_calibrations(
    category: Optional[str] = None,
    manufacturer: Optional[str] = None,
    risk: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """List available calibration routines with optional filtering."""
    results = []
    for routine in CALIBRATION_LIBRARY.values():
        if category and routine.category.value != category:
            continue
        if manufacturer and routine.manufacturer != manufacturer.lower() and routine.manufacturer != "universal":
            continue
        if risk and routine.risk.value != risk:
            continue
        results.append(routine.to_dict())
    return results


def find_calibrations_for_operation(operation: str) -> List[Dict[str, Any]]:
    """Find calibrations matching an operation keyword (e.g., 'oil', 'brake', 'battery')."""
    results = []
    op_lower = operation.lower()
    for routine in CALIBRATION_LIBRARY.values():
        if (op_lower in routine.name.lower() or
            op_lower in routine.description.lower() or
            op_lower in routine.category.value.lower()):
            results.append(routine.to_dict())
    return results


def find_calibrations_for_vehicle(
    manufacturer: str,
    model: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Find calibrations applicable to a specific vehicle."""
    results = []
    mfr = manufacturer.lower()
    for routine in CALIBRATION_LIBRARY.values():
        if routine.manufacturer not in (mfr, "universal"):
            continue
        if model:
            # Check if any applicable model matches
            model_lower = model.lower()
            if not any(model_lower in m.lower() for m in routine.applicable_models):
                continue
        results.append(routine.to_dict())
    return results
