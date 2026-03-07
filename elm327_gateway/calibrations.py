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
# Database-backed Calibration Library
# ===========================================================================

CALIBRATION_LIBRARY: Dict[str, CalibrationRoutine] = {}


def _load_calibration_library() -> Dict[str, CalibrationRoutine]:
    """Load calibration routines from scan_tool_data.db."""
    import json
    import os
    import sqlite3

    db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "scan_tool_data.db")
    if not os.path.exists(db_path):
        logger.warning("scan_tool_data.db not found — calibrations empty")
        return {}

    result: Dict[str, CalibrationRoutine] = {}
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        for row in conn.execute("SELECT * FROM calibration_routines"):
            routine = CalibrationRoutine(
                id=row["id"],
                name=row["name"],
                category=CalibrationCategory(row["category"]),
                difficulty=DifficultyLevel(row["difficulty"]),
                risk=RiskLevel(row["risk"]),
                description=row["description"],
                manufacturer=row["manufacturer"],
                applicable_models=json.loads(row["applicable_models"]),
                prerequisites=json.loads(row["prerequisites"]),
                steps_description=json.loads(row["steps_description"]),
                module_addr=row["module_addr"],
                bus=row["bus"],
                session_type=row["session_type"],
                security_level=row["security_level"],
                uds_sequence=json.loads(row["uds_sequence"]),
                requires_ignition_cycle=bool(row["requires_ignition_cycle"]),
                requires_engine_running=bool(row["requires_engine_running"]),
                estimated_time_seconds=row["estimated_time_seconds"],
                notes=row["notes"],
            )
            result[routine.id] = routine
        conn.close()
        logger.info("Loaded %d calibration routines from database", len(result))
    except Exception as e:
        logger.error("Failed to load calibrations from DB: %s", e)
    return result


CALIBRATION_LIBRARY = _load_calibration_library()


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
