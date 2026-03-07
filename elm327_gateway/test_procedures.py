"""
Guided Test Procedures Engine

Provides structured, step-by-step diagnostic test procedures that the AI
can invoke during troubleshooting. Each procedure is a sequence of actions
(read PID, activate actuator, wait, compare) with pass/fail criteria.

Procedures are JSON-serializable so the AI can present each step to the
technician and explain what's happening and why.

Architecture:
    TestProcedure  → defines the procedure template (steps, criteria)
    TestStep       → one action within a procedure
    ProcedureRunner → executes a procedure against a live vehicle
    PROCEDURE_LIBRARY → built-in catalog of common test procedures
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class StepType(str, Enum):
    """Type of action performed in a test step."""
    INSTRUCTION = "instruction"        # Display instruction to technician
    READ_PID = "read_pid"              # Read an OBD-II PID
    READ_DID = "read_did"              # Read a UDS DID
    READ_DTCS = "read_dtcs"            # Read DTCs
    ACTUATOR_ON = "actuator_on"        # Activate an actuator via 0x2F
    ACTUATOR_OFF = "actuator_off"      # Deactivate an actuator
    UDS_COMMAND = "uds_command"        # Send raw UDS command
    WAIT = "wait"                      # Pause for specified duration
    MONITOR_PID = "monitor_pid"        # Monitor PID over time window
    COMPARE = "compare"               # Compare a captured value against criteria
    CONDITION_CHECK = "condition_check" # Branch based on a runtime value


class StepResult(str, Enum):
    """Result of executing a single step."""
    PASS = "pass"
    FAIL = "fail"
    WARN = "warn"
    SKIP = "skip"
    INFO = "info"
    ERROR = "error"


class ProcedureCategory(str, Enum):
    """Category of diagnostic procedure."""
    FUEL = "fuel"
    IGNITION = "ignition"
    COOLING = "cooling"
    EMISSIONS = "emissions"
    ELECTRICAL = "electrical"
    TRANSMISSION = "transmission"
    BRAKES = "brakes"
    HVAC = "hvac"
    BODY = "body"
    STARTING = "starting"
    CHARGING = "charging"
    EVAP = "evap"
    EXHAUST = "exhaust"
    SENSORS = "sensors"
    NETWORK = "network"
    STEERING = "steering"
    SAFETY = "safety"


class SafetyLevel(str, Enum):
    """Safety classification for procedures."""
    SAFE = "safe"           # Read-only, no risk
    CAUTION = "caution"     # Involves actuator control, minor risk
    WARNING = "warning"     # Involves critical systems (fuel, ignition)
    DANGER = "danger"       # Involves high-risk systems (ABS pump, airbag)


# ---------------------------------------------------------------------------
# Data Classes
# ---------------------------------------------------------------------------

@dataclass
class Criterion:
    """Pass/fail criterion for a measurement step."""
    field: str                    # Which value to check (e.g., "value", "voltage")
    operator: str                 # ">=", "<=", "==", "!=", "between", "contains"
    expected: Any                 # Expected value or [min, max] for "between"
    unit: str = ""               # Display unit
    description: str = ""        # Human-readable criterion description

    def evaluate(self, actual: Any) -> Tuple[bool, str]:
        """Evaluate criterion against actual value. Returns (passed, message)."""
        try:
            if self.operator == ">=":
                passed = float(actual) >= float(self.expected)
            elif self.operator == "<=":
                passed = float(actual) <= float(self.expected)
            elif self.operator == ">":
                passed = float(actual) > float(self.expected)
            elif self.operator == "<":
                passed = float(actual) < float(self.expected)
            elif self.operator == "==":
                passed = str(actual) == str(self.expected)
            elif self.operator == "!=":
                passed = str(actual) != str(self.expected)
            elif self.operator == "between":
                lo, hi = self.expected
                passed = float(lo) <= float(actual) <= float(hi)
            elif self.operator == "contains":
                passed = str(self.expected).lower() in str(actual).lower()
            elif self.operator == "not_contains":
                passed = str(self.expected).lower() not in str(actual).lower()
            else:
                return False, f"Unknown operator: {self.operator}"

            if passed:
                msg = f"PASS: {self.field} = {actual}{self.unit} ({self.description})"
            else:
                msg = f"FAIL: {self.field} = {actual}{self.unit}, expected {self.operator} {self.expected}{self.unit} ({self.description})"
            return passed, msg
        except (ValueError, TypeError) as e:
            return False, f"ERROR evaluating criterion: {e} (actual={actual})"


@dataclass
class TestStep:
    """A single step in a test procedure."""
    step_number: int
    step_type: StepType
    description: str              # Human-readable description of this step
    details: str = ""             # Detailed explanation for AI to relay

    # --- Parameters (depend on step_type) ---
    pid_name: str = ""            # For READ_PID / MONITOR_PID
    did: int = 0                  # For READ_DID
    module_addr: int = 0          # For READ_DID, ACTUATOR_ON/OFF, UDS_COMMAND
    bus: str = "HS-CAN"           # Bus for DID/UDS operations
    uds_command: str = ""         # For UDS_COMMAND
    duration: float = 0.0         # For WAIT, MONITOR_PID, ACTUATOR_ON
    actuator_name: str = ""       # For ACTUATOR_ON/OFF (from bidirectional catalog)
    store_as: str = ""            # Store result in named variable for later COMPARE

    # --- Pass/fail criteria ---
    criteria: List[Criterion] = field(default_factory=list)

    # --- Conditions ---
    skip_if: str = ""             # Skip this step if named variable matches
    required: bool = True         # If False, failure doesn't fail the procedure

    def to_dict(self) -> Dict[str, Any]:
        """Serialize for API/AI consumption."""
        d = {
            "step_number": self.step_number,
            "step_type": self.step_type.value,
            "description": self.description,
        }
        if self.details:
            d["details"] = self.details
        if self.pid_name:
            d["pid_name"] = self.pid_name
        if self.did:
            d["did"] = f"0x{self.did:04X}"
        if self.module_addr:
            d["module_addr"] = f"0x{self.module_addr:03X}"
        if self.bus != "HS-CAN":
            d["bus"] = self.bus
        if self.uds_command:
            d["uds_command"] = self.uds_command
        if self.duration:
            d["duration_seconds"] = self.duration
        if self.actuator_name:
            d["actuator_name"] = self.actuator_name
        if self.store_as:
            d["store_as"] = self.store_as
        if self.criteria:
            d["criteria"] = [
                {"field": c.field, "operator": c.operator,
                 "expected": c.expected, "unit": c.unit,
                 "description": c.description}
                for c in self.criteria
            ]
        if not self.required:
            d["required"] = False
        return d


@dataclass
class StepExecutionResult:
    """Result from executing a single step."""
    step_number: int
    step_type: str
    description: str
    result: StepResult
    message: str = ""
    value: Any = None             # Captured value (PID reading, DID value, etc.)
    criteria_results: List[Dict[str, Any]] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        d = {
            "step_number": self.step_number,
            "step_type": self.step_type,
            "description": self.description,
            "result": self.result.value,
        }
        if self.message:
            d["message"] = self.message
        if self.value is not None:
            d["value"] = self.value
        if self.criteria_results:
            d["criteria_results"] = self.criteria_results
        return d


@dataclass
class TestProcedure:
    """A complete diagnostic test procedure."""
    id: str                        # Unique ID (e.g., "fuel_pump_test")
    name: str                      # Human-readable name
    category: ProcedureCategory
    safety_level: SafetyLevel
    description: str               # What this test checks
    prerequisites: List[str]       # What must be true before running
    applicable_systems: List[str]  # DTC prefixes or systems (e.g., ["P0171", "P0174", "fuel"])
    steps: List[TestStep]
    estimated_time_minutes: int = 5
    requires_engine_running: bool = False
    requires_key_on: bool = True
    manufacturer: str = ""         # Empty = universal, or "ford", "gm", etc.

    def to_dict(self) -> Dict[str, Any]:
        d = {
            "id": self.id,
            "name": self.name,
            "category": self.category.value,
            "safety_level": self.safety_level.value,
            "description": self.description,
            "prerequisites": self.prerequisites,
            "applicable_systems": self.applicable_systems,
            "steps": [s.to_dict() for s in self.steps],
            "estimated_time_minutes": self.estimated_time_minutes,
            "requires_engine_running": self.requires_engine_running,
            "requires_key_on": self.requires_key_on,
        }
        if self.manufacturer:
            d["manufacturer"] = self.manufacturer
        return d


@dataclass
class ProcedureExecutionResult:
    """Complete result of running a test procedure."""
    procedure_id: str
    procedure_name: str
    overall_result: StepResult
    step_results: List[StepExecutionResult]
    variables: Dict[str, Any]      # All captured variables
    start_time: float = 0.0
    end_time: float = 0.0
    summary: str = ""

    @property
    def duration_seconds(self) -> float:
        return self.end_time - self.start_time

    def to_dict(self) -> Dict[str, Any]:
        return {
            "procedure_id": self.procedure_id,
            "procedure_name": self.procedure_name,
            "overall_result": self.overall_result.value,
            "duration_seconds": round(self.duration_seconds, 1),
            "summary": self.summary,
            "step_results": [s.to_dict() for s in self.step_results],
            "captured_values": {
                k: v for k, v in self.variables.items()
                if not k.startswith("_")
            },
        }


# ---------------------------------------------------------------------------
# Procedure Runner
# ---------------------------------------------------------------------------

class ProcedureRunner:
    """
    Executes a TestProcedure against a live vehicle connection.

    Takes an ELM327Service instance and runs each step sequentially,
    collecting results and evaluating pass/fail criteria.
    """

    def __init__(self, service):
        """
        Args:
            service: An ELM327Service instance (from service.py)
        """
        self.service = service
        self.variables: Dict[str, Any] = {}

    async def run(
        self,
        procedure: TestProcedure,
        on_step: Optional[Callable] = None,
    ) -> ProcedureExecutionResult:
        """
        Execute a complete test procedure.

        Args:
            procedure: The test procedure to run
            on_step: Optional callback(step_number, total_steps, description)
                     for progress reporting

        Returns:
            ProcedureExecutionResult with all step results
        """
        self.variables = {}
        step_results: List[StepExecutionResult] = []
        start_time = time.time()
        overall = StepResult.PASS

        total_steps = len(procedure.steps)
        for step in procedure.steps:
            # Progress callback
            if on_step:
                try:
                    on_step(step.step_number, total_steps, step.description)
                except Exception:
                    pass

            # Check skip condition
            if step.skip_if and step.skip_if in self.variables:
                step_results.append(StepExecutionResult(
                    step_number=step.step_number,
                    step_type=step.step_type.value,
                    description=step.description,
                    result=StepResult.SKIP,
                    message=f"Skipped: condition '{step.skip_if}' is set",
                ))
                continue

            # Execute the step
            try:
                result = await self._execute_step(step)
            except Exception as e:
                logger.error(f"Step {step.step_number} failed with exception: {e}")
                result = StepExecutionResult(
                    step_number=step.step_number,
                    step_type=step.step_type.value,
                    description=step.description,
                    result=StepResult.ERROR,
                    message=f"Exception: {e}",
                )

            step_results.append(result)

            # Update overall result
            if result.result == StepResult.FAIL and step.required:
                overall = StepResult.FAIL
            elif result.result == StepResult.ERROR and step.required:
                overall = StepResult.FAIL
            elif result.result == StepResult.WARN and overall == StepResult.PASS:
                overall = StepResult.WARN

        end_time = time.time()

        # Generate summary
        passed = sum(1 for r in step_results if r.result == StepResult.PASS)
        failed = sum(1 for r in step_results if r.result == StepResult.FAIL)
        errors = sum(1 for r in step_results if r.result == StepResult.ERROR)
        skipped = sum(1 for r in step_results if r.result == StepResult.SKIP)

        summary_parts = [f"{passed} passed"]
        if failed:
            summary_parts.append(f"{failed} failed")
        if errors:
            summary_parts.append(f"{errors} errors")
        if skipped:
            summary_parts.append(f"{skipped} skipped")
        summary = f"{procedure.name}: {overall.value.upper()} ({', '.join(summary_parts)})"

        return ProcedureExecutionResult(
            procedure_id=procedure.id,
            procedure_name=procedure.name,
            overall_result=overall,
            step_results=step_results,
            variables=self.variables,
            start_time=start_time,
            end_time=end_time,
            summary=summary,
        )

    async def _execute_step(self, step: TestStep) -> StepExecutionResult:
        """Execute a single test step."""
        handler = {
            StepType.INSTRUCTION: self._step_instruction,
            StepType.READ_PID: self._step_read_pid,
            StepType.READ_DID: self._step_read_did,
            StepType.READ_DTCS: self._step_read_dtcs,
            StepType.ACTUATOR_ON: self._step_actuator_on,
            StepType.ACTUATOR_OFF: self._step_actuator_off,
            StepType.UDS_COMMAND: self._step_uds_command,
            StepType.WAIT: self._step_wait,
            StepType.MONITOR_PID: self._step_monitor_pid,
            StepType.COMPARE: self._step_compare,
            StepType.CONDITION_CHECK: self._step_condition_check,
        }.get(step.step_type)

        if not handler:
            return StepExecutionResult(
                step_number=step.step_number,
                step_type=step.step_type.value,
                description=step.description,
                result=StepResult.ERROR,
                message=f"Unknown step type: {step.step_type}",
            )

        return await handler(step)

    # --- Step Handlers ---

    async def _step_instruction(self, step: TestStep) -> StepExecutionResult:
        """Display instruction — always passes (human reads it)."""
        return StepExecutionResult(
            step_number=step.step_number,
            step_type=step.step_type.value,
            description=step.description,
            result=StepResult.INFO,
            message=step.details or step.description,
        )

    async def _step_read_pid(self, step: TestStep) -> StepExecutionResult:
        """Read a PID and optionally evaluate criteria."""
        reading = await self.service.read_pid(step.pid_name)
        if reading is None:
            return StepExecutionResult(
                step_number=step.step_number,
                step_type=step.step_type.value,
                description=step.description,
                result=StepResult.ERROR,
                message=f"PID '{step.pid_name}' returned no data",
            )

        value = reading.value
        if step.store_as:
            self.variables[step.store_as] = value

        # Evaluate criteria
        result, criteria_results = self._evaluate_criteria(step.criteria, value)

        return StepExecutionResult(
            step_number=step.step_number,
            step_type=step.step_type.value,
            description=step.description,
            result=result,
            value=f"{value} {reading.unit}" if hasattr(reading, 'unit') else str(value),
            criteria_results=criteria_results,
            message=f"{step.pid_name} = {value}",
        )

    async def _step_read_did(self, step: TestStep) -> StepExecutionResult:
        """Read a UDS DID from a specific module."""
        value = await self.service.read_did(
            module_addr=step.module_addr,
            did=step.did,
            bus=step.bus,
        )
        if value is None:
            return StepExecutionResult(
                step_number=step.step_number,
                step_type=step.step_type.value,
                description=step.description,
                result=StepResult.FAIL if step.required else StepResult.WARN,
                message=f"DID 0x{step.did:04X} from 0x{step.module_addr:03X}: no response",
            )

        if step.store_as:
            self.variables[step.store_as] = value

        result, criteria_results = self._evaluate_criteria(step.criteria, value)

        return StepExecutionResult(
            step_number=step.step_number,
            step_type=step.step_type.value,
            description=step.description,
            result=result,
            value=value,
            criteria_results=criteria_results,
            message=f"DID 0x{step.did:04X} = {value}",
        )

    async def _step_read_dtcs(self, step: TestStep) -> StepExecutionResult:
        """Read DTCs and store count + codes."""
        dtcs = await self.service.read_all_dtcs()
        total_stored = len(dtcs.get("stored", []))
        total_pending = len(dtcs.get("pending", []))
        total_permanent = len(dtcs.get("permanent", []))
        total = total_stored + total_pending + total_permanent

        all_codes = []
        for category in dtcs.values():
            for dtc in category:
                code = dtc.code if hasattr(dtc, 'code') else str(dtc)
                all_codes.append(code)

        if step.store_as:
            self.variables[step.store_as] = total
            self.variables[f"{step.store_as}_codes"] = all_codes
            self.variables[f"{step.store_as}_stored"] = total_stored
            self.variables[f"{step.store_as}_pending"] = total_pending
            self.variables[f"{step.store_as}_permanent"] = total_permanent

        result, criteria_results = self._evaluate_criteria(step.criteria, total)

        code_str = ", ".join(all_codes[:10])
        if len(all_codes) > 10:
            code_str += f" ... (+{len(all_codes) - 10} more)"

        return StepExecutionResult(
            step_number=step.step_number,
            step_type=step.step_type.value,
            description=step.description,
            result=result,
            value={"total": total, "stored": total_stored,
                   "pending": total_pending, "permanent": total_permanent,
                   "codes": all_codes},
            criteria_results=criteria_results,
            message=f"DTCs found: {total} ({code_str})" if total > 0 else "No DTCs found",
        )

    async def _step_actuator_on(self, step: TestStep) -> StepExecutionResult:
        """Activate an actuator via UDS 0x2F or Mode $08."""
        try:
            # Use the bidirectional catalog via service layer
            result_data = await self.service.actuator_test(
                actuator_name=step.actuator_name,
                state="on",
                duration=step.duration if step.duration > 0 else None,
            )
            success = bool(result_data)

            return StepExecutionResult(
                step_number=step.step_number,
                step_type=step.step_type.value,
                description=step.description,
                result=StepResult.PASS if success else StepResult.FAIL,
                message=f"Activated: {step.actuator_name}" if success
                        else f"Failed to activate: {step.actuator_name}",
                value=result_data,
            )
        except Exception as e:
            return StepExecutionResult(
                step_number=step.step_number,
                step_type=step.step_type.value,
                description=step.description,
                result=StepResult.ERROR,
                message=f"Actuator error: {e}",
            )

    async def _step_actuator_off(self, step: TestStep) -> StepExecutionResult:
        """Deactivate / return control to ECU."""
        try:
            result_data = await self.service.actuator_test(
                actuator_name=step.actuator_name,
                state="off",
            )
            return StepExecutionResult(
                step_number=step.step_number,
                step_type=step.step_type.value,
                description=step.description,
                result=StepResult.PASS,
                message=f"Deactivated: {step.actuator_name}",
                value=result_data,
            )
        except Exception as e:
            return StepExecutionResult(
                step_number=step.step_number,
                step_type=step.step_type.value,
                description=step.description,
                result=StepResult.WARN,
                message=f"Deactivation warning: {e}",
            )

    async def _step_uds_command(self, step: TestStep) -> StepExecutionResult:
        """Send a raw UDS command and store response."""
        resp = await self.service.send_uds_raw(
            module_addr=step.module_addr,
            hex_cmd=step.uds_command,
            bus=step.bus,
        )

        if step.store_as:
            self.variables[step.store_as] = resp

        if not resp:
            return StepExecutionResult(
                step_number=step.step_number,
                step_type=step.step_type.value,
                description=step.description,
                result=StepResult.FAIL if step.required else StepResult.WARN,
                message=f"No response to UDS command: {step.uds_command}",
            )

        result, criteria_results = self._evaluate_criteria(step.criteria, resp)

        return StepExecutionResult(
            step_number=step.step_number,
            step_type=step.step_type.value,
            description=step.description,
            result=result,
            value=resp,
            criteria_results=criteria_results,
            message=f"UDS response: {resp}",
        )

    async def _step_wait(self, step: TestStep) -> StepExecutionResult:
        """Pause execution for a specified duration."""
        await asyncio.sleep(step.duration)
        return StepExecutionResult(
            step_number=step.step_number,
            step_type=step.step_type.value,
            description=step.description,
            result=StepResult.INFO,
            message=f"Waited {step.duration}s",
        )

    async def _step_monitor_pid(self, step: TestStep) -> StepExecutionResult:
        """Monitor a PID over a time window and collect min/max/avg."""
        samples = []
        end_time = time.time() + step.duration
        sample_interval = 0.5  # Read every 500ms

        while time.time() < end_time:
            try:
                reading = await self.service.read_pid(step.pid_name)
                if reading and reading.value is not None:
                    try:
                        samples.append(float(reading.value))
                    except (ValueError, TypeError):
                        samples.append(reading.value)
            except Exception:
                pass
            await asyncio.sleep(sample_interval)

        if not samples:
            return StepExecutionResult(
                step_number=step.step_number,
                step_type=step.step_type.value,
                description=step.description,
                result=StepResult.ERROR,
                message=f"No samples collected for {step.pid_name} over {step.duration}s",
            )

        # Calculate statistics for numeric samples
        numeric = [s for s in samples if isinstance(s, (int, float))]
        if numeric:
            stats = {
                "min": round(min(numeric), 2),
                "max": round(max(numeric), 2),
                "avg": round(sum(numeric) / len(numeric), 2),
                "samples": len(numeric),
                "duration": step.duration,
            }
            check_value = stats["avg"]  # Criteria evaluated against average
        else:
            stats = {"samples": len(samples), "values": samples[:20]}
            check_value = samples[-1]

        if step.store_as:
            self.variables[step.store_as] = stats
            self.variables[f"{step.store_as}_avg"] = stats.get("avg")
            self.variables[f"{step.store_as}_min"] = stats.get("min")
            self.variables[f"{step.store_as}_max"] = stats.get("max")

        result, criteria_results = self._evaluate_criteria(step.criteria, check_value)

        return StepExecutionResult(
            step_number=step.step_number,
            step_type=step.step_type.value,
            description=step.description,
            result=result,
            value=stats,
            criteria_results=criteria_results,
            message=f"{step.pid_name}: avg={stats.get('avg', '?')}, "
                    f"min={stats.get('min', '?')}, max={stats.get('max', '?')} "
                    f"({stats.get('samples', 0)} samples over {step.duration}s)",
        )

    async def _step_compare(self, step: TestStep) -> StepExecutionResult:
        """Compare a previously stored variable against criteria."""
        var_name = step.store_as or step.pid_name
        value = self.variables.get(var_name)

        if value is None:
            return StepExecutionResult(
                step_number=step.step_number,
                step_type=step.step_type.value,
                description=step.description,
                result=StepResult.ERROR,
                message=f"Variable '{var_name}' not found in captured data",
            )

        result, criteria_results = self._evaluate_criteria(step.criteria, value)

        return StepExecutionResult(
            step_number=step.step_number,
            step_type=step.step_type.value,
            description=step.description,
            result=result,
            value=value,
            criteria_results=criteria_results,
            message=f"{var_name} = {value}",
        )

    async def _step_condition_check(self, step: TestStep) -> StepExecutionResult:
        """Check a condition and set a variable for skip_if branching."""
        var_name = step.store_as or step.pid_name
        value = self.variables.get(var_name)

        if value is None:
            # Condition variable not set — that's a valid state
            return StepExecutionResult(
                step_number=step.step_number,
                step_type=step.step_type.value,
                description=step.description,
                result=StepResult.INFO,
                message=f"Condition '{var_name}': not set",
            )

        passed, criteria_results = self._evaluate_criteria(step.criteria, value)

        return StepExecutionResult(
            step_number=step.step_number,
            step_type=step.step_type.value,
            description=step.description,
            result=StepResult.PASS if passed == StepResult.PASS else StepResult.INFO,
            value=value,
            criteria_results=criteria_results,
            message=f"Condition '{var_name}' = {value}",
        )

    # --- Helpers ---

    def _evaluate_criteria(
        self, criteria: List[Criterion], value: Any
    ) -> Tuple[StepResult, List[Dict[str, Any]]]:
        """Evaluate all criteria against a value. Returns (result, details)."""
        if not criteria:
            return StepResult.PASS, []

        details = []
        all_pass = True
        for c in criteria:
            passed, msg = c.evaluate(value)
            details.append({"passed": passed, "message": msg})
            if not passed:
                all_pass = False

        return StepResult.PASS if all_pass else StepResult.FAIL, details


# ---------------------------------------------------------------------------
# Built-in Procedure Library

# ---------------------------------------------------------------------------
# Database-backed Procedure Library
# ---------------------------------------------------------------------------

PROCEDURE_LIBRARY: Dict[str, TestProcedure] = {}


def _load_procedure_library() -> Dict[str, TestProcedure]:
    """Load test procedures from scan_tool_data.db."""
    import json
    import os
    import sqlite3

    db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "scan_tool_data.db")
    if not os.path.exists(db_path):
        logger.warning("scan_tool_data.db not found — test procedures empty")
        return {}

    result: Dict[str, TestProcedure] = {}
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        for row in conn.execute("SELECT * FROM test_procedures"):
            steps_data = json.loads(row["steps"])
            steps = []
            for sd in steps_data:
                # Build criteria list
                criteria = []
                for cd in sd.get("criteria", []):
                    criteria.append(Criterion(
                        field=cd["field"],
                        operator=cd["operator"],
                        expected=cd["expected"],
                        unit=cd.get("unit", ""),
                        description=cd.get("description", ""),
                    ))

                steps.append(TestStep(
                    step_number=sd["step_number"],
                    step_type=StepType(sd["step_type"]),
                    description=sd["description"],
                    details=sd.get("details", ""),
                    pid_name=sd.get("pid_name", ""),
                    did=sd.get("did", 0),
                    module_addr=sd.get("module_addr", 0),
                    bus=sd.get("bus", "HS-CAN"),
                    uds_command=sd.get("uds_command", ""),
                    duration=sd.get("duration", 0.0),
                    actuator_name=sd.get("actuator_name", ""),
                    store_as=sd.get("store_as", ""),
                    criteria=criteria,
                    skip_if=sd.get("skip_if", ""),
                    required=sd.get("required", True),
                ))

            proc = TestProcedure(
                id=row["id"],
                name=row["name"],
                category=ProcedureCategory(row["category"]),
                safety_level=SafetyLevel(row["safety_level"]),
                description=row["description"],
                prerequisites=json.loads(row["prerequisites"]),
                applicable_systems=json.loads(row["applicable_systems"]),
                steps=steps,
                estimated_time_minutes=row["estimated_time_minutes"],
                requires_engine_running=bool(row["requires_engine_running"]),
                requires_key_on=bool(row["requires_key_on"]),
                manufacturer=row["manufacturer"],
            )
            result[proc.id] = proc
        conn.close()
        logger.info("Loaded %d test procedures from database", len(result))
    except Exception as e:
        logger.error("Failed to load test procedures from DB: %s", e)
    return result


PROCEDURE_LIBRARY = _load_procedure_library()

# Keep COMPACT_PROCEDURES as empty list for backward compatibility
COMPACT_PROCEDURES: List[dict] = []


def get_procedure(procedure_id: str) -> Optional[TestProcedure]:
    """Get a procedure by ID."""
    return PROCEDURE_LIBRARY.get(procedure_id)


def list_procedures(
    category: Optional[str] = None,
    manufacturer: Optional[str] = None,
    safety_level: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    List available procedures with optional filtering.

    Returns simplified dicts (not full procedure objects) for display.
    """
    results = []
    for proc in PROCEDURE_LIBRARY.values():
        if category and proc.category.value != category:
            continue
        if manufacturer and proc.manufacturer and proc.manufacturer != manufacturer:
            continue
        if safety_level and proc.safety_level.value != safety_level:
            continue

        results.append({
            "id": proc.id,
            "name": proc.name,
            "category": proc.category.value,
            "safety_level": proc.safety_level.value,
            "description": proc.description,
            "estimated_time_minutes": proc.estimated_time_minutes,
            "requires_engine_running": proc.requires_engine_running,
            "manufacturer": proc.manufacturer or "universal",
            "applicable_systems": proc.applicable_systems,
        })

    return results


def find_procedures_for_dtc(dtc_code: str) -> List[Dict[str, Any]]:
    """Find procedures applicable to a specific DTC code."""
    results = []
    dtc_upper = dtc_code.upper()
    for proc in PROCEDURE_LIBRARY.values():
        for system in proc.applicable_systems:
            if system.upper() == dtc_upper or dtc_upper.startswith(system.upper()):
                results.append({
                    "id": proc.id,
                    "name": proc.name,
                    "category": proc.category.value,
                    "description": proc.description,
                    "relevance": "direct_match" if system.upper() == dtc_upper else "category_match",
                })
                break
    return results


def find_procedures_for_symptom(symptom: str) -> List[Dict[str, Any]]:
    """Find procedures matching a symptom keyword."""
    results = []
    symptom_lower = symptom.lower()
    for proc in PROCEDURE_LIBRARY.values():
        # Check applicable_systems for keyword matches
        for system in proc.applicable_systems:
            if symptom_lower in system.lower():
                results.append({
                    "id": proc.id,
                    "name": proc.name,
                    "category": proc.category.value,
                    "description": proc.description,
                })
                break
        else:
            # Also check procedure name and description
            if symptom_lower in proc.name.lower() or symptom_lower in proc.description.lower():
                results.append({
                    "id": proc.id,
                    "name": proc.name,
                    "category": proc.category.value,
                    "description": proc.description,
                })
    return results
