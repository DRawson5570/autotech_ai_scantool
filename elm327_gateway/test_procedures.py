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

def _build_fuel_pump_test() -> TestProcedure:
    """Fuel pump prime/pressure test."""
    return TestProcedure(
        id="fuel_pump_test",
        name="Fuel Pump Test",
        category=ProcedureCategory.FUEL,
        safety_level=SafetyLevel.WARNING,
        description=(
            "Tests fuel pump operation by reading fuel pressure (if available), "
            "priming the pump with KOEO, and monitoring for pressure build-up. "
            "Useful for diagnosing no-start conditions and fuel delivery issues."
        ),
        prerequisites=[
            "Key ON, engine OFF (KOEO)",
            "Vehicle in Park/Neutral",
            "No fuel leaks visible",
        ],
        applicable_systems=["P0087", "P0088", "P0171", "P0174", "P0230", "P0231",
                           "P0232", "fuel", "no_start", "lean"],
        estimated_time_minutes=3,
        requires_engine_running=False,
        requires_key_on=True,
        steps=[
            TestStep(
                step_number=1,
                step_type=StepType.INSTRUCTION,
                description="Ensure key is ON, engine OFF. Verify no fuel leaks.",
                details="This test will activate the fuel pump relay for 5 seconds. "
                        "Listen for the pump running and check fuel pressure gauge if connected.",
            ),
            TestStep(
                step_number=2,
                step_type=StepType.READ_PID,
                description="Read initial fuel system status",
                pid_name="FUEL_STATUS",
                store_as="fuel_status_initial",
                required=False,
            ),
            TestStep(
                step_number=3,
                step_type=StepType.READ_PID,
                description="Read fuel rail pressure (if supported)",
                pid_name="FUEL_RAIL_PRESSURE_DIRECT",
                store_as="fuel_pressure_initial",
                required=False,
            ),
            TestStep(
                step_number=4,
                step_type=StepType.INSTRUCTION,
                description="Activating fuel pump for 5 seconds — LISTEN for pump hum",
                details="You should hear the fuel pump running from the rear of the vehicle. "
                        "If no sound is heard, check the fuel pump relay, fuse, and wiring.",
            ),
            TestStep(
                step_number=5,
                step_type=StepType.ACTUATOR_ON,
                description="Activate fuel pump relay",
                actuator_name="fuel_pump",
                duration=5.0,
            ),
            TestStep(
                step_number=6,
                step_type=StepType.WAIT,
                description="Allow pressure to stabilize",
                duration=2.0,
            ),
            TestStep(
                step_number=7,
                step_type=StepType.READ_PID,
                description="Read fuel rail pressure after pump activation",
                pid_name="FUEL_RAIL_PRESSURE_DIRECT",
                store_as="fuel_pressure_after",
                required=False,
                criteria=[
                    Criterion(
                        field="value",
                        operator=">=",
                        expected=250,
                        unit=" kPa",
                        description="Fuel pressure should be at least 250 kPa (~36 PSI) after priming",
                    ),
                ],
            ),
            TestStep(
                step_number=8,
                step_type=StepType.INSTRUCTION,
                description="Test complete. Report what you heard and observed.",
                details="Expected: Fuel pump hums for 5 seconds, pressure builds to spec. "
                        "If pump was silent: check relay, fuse F87 (Ford) or fuse 26 (GM), "
                        "inertia switch (Ford), or wiring to pump. "
                        "If pump runs but no pressure: possible failed pump, clogged filter, "
                        "or fuel pressure regulator fault.",
            ),
        ],
    )


def _build_cooling_fan_test() -> TestProcedure:
    """Engine cooling fan operation test."""
    return TestProcedure(
        id="cooling_fan_test",
        name="Cooling Fan Test",
        category=ProcedureCategory.COOLING,
        safety_level=SafetyLevel.CAUTION,
        description=(
            "Tests cooling fan operation by activating the fan relay and monitoring "
            "coolant temperature. Verifies the fan motor, relay, and wiring."
        ),
        prerequisites=[
            "Key ON, engine can be running or off",
            "Keep hands and loose clothing away from fan",
        ],
        applicable_systems=["P0480", "P0481", "P0482", "P0217", "cooling", "overheat"],
        estimated_time_minutes=3,
        requires_engine_running=False,
        requires_key_on=True,
        steps=[
            TestStep(
                step_number=1,
                step_type=StepType.INSTRUCTION,
                description="WARNING: Keep hands clear of the cooling fan area!",
                details="The cooling fan will be activated for 10 seconds. "
                        "Stand clear and observe the fan blade rotation.",
            ),
            TestStep(
                step_number=2,
                step_type=StepType.READ_PID,
                description="Read current coolant temperature",
                pid_name="COOLANT_TEMP",
                store_as="coolant_temp",
                criteria=[
                    Criterion(
                        field="value",
                        operator="<=",
                        expected=120,
                        unit=" °C",
                        description="Coolant temp should be below 120°C (overheat threshold)",
                    ),
                ],
            ),
            TestStep(
                step_number=3,
                step_type=StepType.INSTRUCTION,
                description="Activating cooling fan for 10 seconds — OBSERVE fan blade rotation",
            ),
            TestStep(
                step_number=4,
                step_type=StepType.ACTUATOR_ON,
                description="Activate cooling fan relay",
                actuator_name="cooling_fan",
                duration=10.0,
            ),
            TestStep(
                step_number=5,
                step_type=StepType.INSTRUCTION,
                description="Fan test complete. Did the fan spin?",
                details="If fan did NOT spin: Check fan relay, fuse, fan motor connector, "
                        "and fan motor ground. On Ford, check relay in underhood fuse box. "
                        "If fan spins slowly: check for seized bearings or corroded connector. "
                        "If fan works normally: fan circuit is OK, the PCM may not be commanding "
                        "it correctly — check coolant temp sensor and PCM fan control logic.",
            ),
        ],
    )


def _build_evap_system_test() -> TestProcedure:
    """EVAP system leak test (purge + vent solenoid test)."""
    return TestProcedure(
        id="evap_system_test",
        name="EVAP System Test",
        category=ProcedureCategory.EVAP,
        safety_level=SafetyLevel.CAUTION,
        description=(
            "Tests the EVAP purge and vent solenoids sequentially. "
            "Helps diagnose EVAP leak codes by verifying solenoid operation."
        ),
        prerequisites=[
            "Key ON, engine OFF (KOEO)",
            "Gas cap installed and tight",
        ],
        applicable_systems=["P0440", "P0441", "P0442", "P0443", "P0446", "P0449",
                           "P0455", "P0456", "P0457", "evap", "gas_cap"],
        estimated_time_minutes=3,
        requires_engine_running=False,
        requires_key_on=True,
        steps=[
            TestStep(
                step_number=1,
                step_type=StepType.INSTRUCTION,
                description="Ensure gas cap is installed and tight. Key ON, engine OFF.",
                details="This test activates the purge and vent solenoids. "
                        "Listen for clicking sounds from the EVAP canister area.",
            ),
            TestStep(
                step_number=2,
                step_type=StepType.READ_PID,
                description="Read EVAP system vapor pressure (if supported)",
                pid_name="EVAP_PRESSURE",
                store_as="evap_pressure_initial",
                required=False,
            ),
            TestStep(
                step_number=3,
                step_type=StepType.INSTRUCTION,
                description="Activating EVAP purge solenoid — listen for clicking near intake manifold",
            ),
            TestStep(
                step_number=4,
                step_type=StepType.ACTUATOR_ON,
                description="Activate EVAP purge solenoid",
                actuator_name="evap_purge",
                duration=5.0,
            ),
            TestStep(
                step_number=5,
                step_type=StepType.WAIT,
                description="Pause between solenoid tests",
                duration=2.0,
            ),
            TestStep(
                step_number=6,
                step_type=StepType.INSTRUCTION,
                description="Activating EVAP vent solenoid — listen for clicking near charcoal canister",
            ),
            TestStep(
                step_number=7,
                step_type=StepType.ACTUATOR_ON,
                description="Activate EVAP vent solenoid",
                actuator_name="evap_vent",
                duration=5.0,
            ),
            TestStep(
                step_number=8,
                step_type=StepType.READ_PID,
                description="Read EVAP pressure after test",
                pid_name="EVAP_PRESSURE",
                store_as="evap_pressure_after",
                required=False,
            ),
            TestStep(
                step_number=9,
                step_type=StepType.INSTRUCTION,
                description="EVAP test complete. Report what you heard.",
                details="Expected: Audible click from both purge and vent solenoids. "
                        "If purge solenoid is silent: Check connector at intake manifold, "
                        "check vacuum lines, verify 12V at connector with key on. "
                        "If vent solenoid is silent: Check connector at charcoal canister, "
                        "verify vent valve isn't stuck. "
                        "Common: P0442 (small leak) is often a bad gas cap O-ring. "
                        "P0455 (large leak) check purge/vent hoses for cracks.",
            ),
        ],
    )


def _build_o2_sensor_heater_test() -> TestProcedure:
    """O2 sensor heater circuit test."""
    return TestProcedure(
        id="o2_heater_test",
        name="O2 Sensor Heater Circuit Test",
        category=ProcedureCategory.EMISSIONS,
        safety_level=SafetyLevel.SAFE,
        description=(
            "Tests O2 sensor heater operation by reading heater current/voltage PIDs "
            "and monitoring O2 sensor response during warm-up. Read-only test."
        ),
        prerequisites=[
            "Key ON, engine running (warm engine preferred)",
        ],
        applicable_systems=["P0030", "P0031", "P0032", "P0036", "P0037", "P0038",
                           "P0135", "P0141", "P0155", "P0161", "o2_heater"],
        estimated_time_minutes=3,
        requires_engine_running=True,
        requires_key_on=True,
        steps=[
            TestStep(
                step_number=1,
                step_type=StepType.READ_PID,
                description="Read O2 sensor bank 1, sensor 1 voltage",
                pid_name="O2_B1S1",
                store_as="o2_b1s1",
                criteria=[
                    Criterion(
                        field="value",
                        operator="between",
                        expected=[0.0, 1.275],
                        unit=" V",
                        description="O2 voltage should be between 0.0-1.275V",
                    ),
                ],
            ),
            TestStep(
                step_number=2,
                step_type=StepType.READ_PID,
                description="Read O2 sensor bank 1, sensor 2 voltage",
                pid_name="O2_B1S2",
                store_as="o2_b1s2",
                required=False,
            ),
            TestStep(
                step_number=3,
                step_type=StepType.MONITOR_PID,
                description="Monitor O2 B1S1 for 10 seconds — check for switching activity",
                pid_name="O2_B1S1",
                duration=10.0,
                store_as="o2_b1s1_monitor",
                details="A healthy upstream O2 sensor should switch rapidly between "
                        "~0.1V (lean) and ~0.9V (rich) at least 5-8 times in 10 seconds. "
                        "A sensor that is stuck lean, stuck rich, or lazy (slow switching) "
                        "indicates a failing sensor or heater circuit issue.",
            ),
            TestStep(
                step_number=4,
                step_type=StepType.READ_PID,
                description="Read coolant temperature (heater should be unnecessary when warm)",
                pid_name="COOLANT_TEMP",
                store_as="coolant_temp_o2",
                criteria=[
                    Criterion(
                        field="value",
                        operator=">=",
                        expected=70,
                        unit=" °C",
                        description="Engine should be at operating temp for valid O2 readings",
                    ),
                ],
            ),
            TestStep(
                step_number=5,
                step_type=StepType.READ_PID,
                description="Read short-term fuel trim (should be near 0% if O2 is working)",
                pid_name="SHORT_FUEL_TRIM_1",
                store_as="stft",
                criteria=[
                    Criterion(
                        field="value",
                        operator="between",
                        expected=[-10, 10],
                        unit=" %",
                        description="STFT should be within ±10% at idle if O2 is responding",
                    ),
                ],
            ),
            TestStep(
                step_number=6,
                step_type=StepType.INSTRUCTION,
                description="O2 heater test complete. Review results above.",
                details="If O2 voltage is stuck at 0.45V: Sensor may not be heated — "
                        "check heater fuse, heater relay, and heater resistance (should be 6-13 ohms). "
                        "If O2 is switching but slowly: Sensor is aging, replace soon. "
                        "If STFT is >20% positive: Lean condition — not an O2 heater issue, "
                        "look for vacuum leaks, low fuel pressure, or MAF sensor issues.",
            ),
        ],
    )


def _build_misfire_diagnosis() -> TestProcedure:
    """Misfire diagnosis procedure."""
    return TestProcedure(
        id="misfire_diagnosis",
        name="Engine Misfire Diagnosis",
        category=ProcedureCategory.IGNITION,
        safety_level=SafetyLevel.SAFE,
        description=(
            "Systematic misfire diagnosis: reads DTCs, monitors misfire counters, "
            "checks fuel trims, and evaluates spark/fuel/compression indicators."
        ),
        prerequisites=[
            "Engine running at idle",
            "Check engine light may be on",
        ],
        applicable_systems=["P0300", "P0301", "P0302", "P0303", "P0304",
                           "P0305", "P0306", "P0307", "P0308",
                           "misfire", "rough_idle", "shaking"],
        estimated_time_minutes=5,
        requires_engine_running=True,
        requires_key_on=True,
        steps=[
            TestStep(
                step_number=1,
                step_type=StepType.READ_DTCS,
                description="Read all DTCs to identify misfiring cylinders",
                store_as="misfire_dtcs",
            ),
            TestStep(
                step_number=2,
                step_type=StepType.READ_PID,
                description="Read RPM to confirm engine is running",
                pid_name="RPM",
                store_as="rpm",
                criteria=[
                    Criterion(
                        field="value",
                        operator="between",
                        expected=[500, 1200],
                        unit=" RPM",
                        description="Idle RPM should be 500-1200 for most vehicles",
                    ),
                ],
            ),
            TestStep(
                step_number=3,
                step_type=StepType.MONITOR_PID,
                description="Monitor RPM stability for 15 seconds",
                pid_name="RPM",
                duration=15.0,
                store_as="rpm_stability",
                details="Large RPM fluctuations (>100 RPM variance) indicate active misfire.",
            ),
            TestStep(
                step_number=4,
                step_type=StepType.READ_PID,
                description="Read short-term fuel trim bank 1",
                pid_name="SHORT_FUEL_TRIM_1",
                store_as="stft_b1",
                criteria=[
                    Criterion(
                        field="value",
                        operator="between",
                        expected=[-25, 25],
                        unit=" %",
                        description="STFT beyond ±25% indicates significant air/fuel imbalance",
                    ),
                ],
            ),
            TestStep(
                step_number=5,
                step_type=StepType.READ_PID,
                description="Read long-term fuel trim bank 1",
                pid_name="LONG_FUEL_TRIM_1",
                store_as="ltft_b1",
                criteria=[
                    Criterion(
                        field="value",
                        operator="between",
                        expected=[-15, 15],
                        unit=" %",
                        description="LTFT beyond ±15% indicates chronic air/fuel issue",
                    ),
                ],
            ),
            TestStep(
                step_number=6,
                step_type=StepType.READ_PID,
                description="Read short-term fuel trim bank 2 (if V6/V8)",
                pid_name="SHORT_FUEL_TRIM_2",
                store_as="stft_b2",
                required=False,
            ),
            TestStep(
                step_number=7,
                step_type=StepType.READ_PID,
                description="Read long-term fuel trim bank 2 (if V6/V8)",
                pid_name="LONG_FUEL_TRIM_2",
                store_as="ltft_b2",
                required=False,
            ),
            TestStep(
                step_number=8,
                step_type=StepType.READ_PID,
                description="Read MAP sensor",
                pid_name="INTAKE_PRESSURE",
                store_as="map_pressure",
                required=False,
                criteria=[
                    Criterion(
                        field="value",
                        operator="between",
                        expected=[20, 80],
                        unit=" kPa",
                        description="MAP at idle should be 20-80 kPa (lower = normal vacuum)",
                    ),
                ],
            ),
            TestStep(
                step_number=9,
                step_type=StepType.READ_PID,
                description="Read coolant temperature (cold engine misfires more)",
                pid_name="COOLANT_TEMP",
                store_as="coolant_temp_misfire",
            ),
            TestStep(
                step_number=10,
                step_type=StepType.INSTRUCTION,
                description="Misfire diagnosis data collection complete. Analyze results.",
                details=(
                    "INTERPRETATION GUIDE:\n"
                    "• Single cylinder misfire (P030X): Check that cylinder's coil, plug, injector\n"
                    "• Random misfire (P0300): Usually vacuum leak, low fuel pressure, or "
                    "bad MAF sensor\n"
                    "• High positive fuel trims (>10%): Running lean — vacuum leak, "
                    "low fuel pressure, bad MAF, intake gasket leak\n"
                    "• High negative fuel trims (<-10%): Running rich — leaking injector, "
                    "bad MAP sensor, EVAP purge stuck open\n"
                    "• Bank-specific fuel trim skew: Leak is on that bank\n"
                    "• RPM variance >100: Active misfire present\n"
                    "• RPM stable but DTC set: Intermittent — check connectors, "
                    "heat-soak coil failures"
                ),
            ),
        ],
    )


def _build_catalytic_converter_test() -> TestProcedure:
    """Catalytic converter efficiency test."""
    return TestProcedure(
        id="catalyst_efficiency_test",
        name="Catalytic Converter Efficiency Test",
        category=ProcedureCategory.EMISSIONS,
        safety_level=SafetyLevel.SAFE,
        description=(
            "Monitors upstream and downstream O2 sensors to evaluate catalytic "
            "converter storage efficiency. Compares switching activity between "
            "sensors — a good cat shows flat downstream O2."
        ),
        prerequisites=[
            "Engine running, at normal operating temperature",
            "Drive at least 5 minutes before this test for accurate results",
        ],
        applicable_systems=["P0420", "P0421", "P0422", "P0430", "P0431",
                           "catalyst", "cat_efficiency"],
        estimated_time_minutes=3,
        requires_engine_running=True,
        requires_key_on=True,
        steps=[
            TestStep(
                step_number=1,
                step_type=StepType.READ_PID,
                description="Confirm engine is at operating temperature",
                pid_name="COOLANT_TEMP",
                store_as="cat_coolant",
                criteria=[
                    Criterion(
                        field="value",
                        operator=">=",
                        expected=80,
                        unit=" °C",
                        description="Engine must be fully warmed up for valid catalyst test",
                    ),
                ],
            ),
            TestStep(
                step_number=2,
                step_type=StepType.MONITOR_PID,
                description="Monitor UPSTREAM O2 (Bank 1 Sensor 1) for 20 seconds",
                pid_name="O2_B1S1",
                duration=20.0,
                store_as="upstream_o2",
                details="Upstream O2 should switch rapidly between lean (~0.1V) and "
                        "rich (~0.9V). This is normal closed-loop fuel control.",
            ),
            TestStep(
                step_number=3,
                step_type=StepType.MONITOR_PID,
                description="Monitor DOWNSTREAM O2 (Bank 1 Sensor 2) for 20 seconds",
                pid_name="O2_B1S2",
                duration=20.0,
                store_as="downstream_o2",
                details="Downstream O2 should be relatively FLAT around 0.5-0.7V "
                        "if the catalyst is working. If it mirrors the upstream "
                        "switching pattern, the catalyst has lost its oxygen storage "
                        "capacity and needs replacement.",
            ),
            TestStep(
                step_number=4,
                step_type=StepType.INSTRUCTION,
                description="Catalyst test complete. Compare upstream vs downstream O2.",
                details=(
                    "GOOD CATALYST: Upstream O2 switches rapidly (0.1V-0.9V), "
                    "downstream O2 stays flat around 0.5-0.7V.\n"
                    "BAD CATALYST: Downstream O2 mirrors upstream switching pattern.\n\n"
                    "Before replacing catalyst, rule out:\n"
                    "• Exhaust leaks upstream of cat (false P0420)\n"
                    "• Engine misfire (unburned fuel damages cat)\n"
                    "• Rich running condition (kills cat over time)\n"
                    "• Coolant leak into combustion (head gasket)\n"
                    "• Aftermarket O2 sensor (some don't match OE specs)"
                ),
            ),
        ],
    )


def _build_idle_air_control_test() -> TestProcedure:
    """Idle air control system test."""
    return TestProcedure(
        id="idle_control_test",
        name="Idle Air Control Test",
        category=ProcedureCategory.FUEL,
        safety_level=SafetyLevel.SAFE,
        description=(
            "Checks idle control by monitoring RPM, throttle position, and "
            "IAC valve position. Identifies stuck IAC, vacuum leaks, or "
            "throttle body issues causing high/low/surging idle."
        ),
        prerequisites=[
            "Engine running at idle, in Park/Neutral",
            "A/C OFF, headlights OFF (minimize electrical load)",
        ],
        applicable_systems=["P0505", "P0506", "P0507", "P0511",
                           "idle", "high_idle", "low_idle", "surge"],
        estimated_time_minutes=3,
        requires_engine_running=True,
        requires_key_on=True,
        steps=[
            TestStep(
                step_number=1,
                step_type=StepType.READ_PID,
                description="Read coolant temperature (cold engines idle higher)",
                pid_name="COOLANT_TEMP",
                store_as="idle_coolant",
            ),
            TestStep(
                step_number=2,
                step_type=StepType.MONITOR_PID,
                description="Monitor RPM for 15 seconds at idle",
                pid_name="RPM",
                duration=15.0,
                store_as="idle_rpm",
                criteria=[
                    Criterion(
                        field="value",
                        operator="between",
                        expected=[550, 900],
                        unit=" RPM",
                        description="Warm idle should be 550-900 RPM for most vehicles",
                    ),
                ],
            ),
            TestStep(
                step_number=3,
                step_type=StepType.READ_PID,
                description="Read throttle position (should be near 0% at idle)",
                pid_name="THROTTLE_POS",
                store_as="idle_throttle",
                criteria=[
                    Criterion(
                        field="value",
                        operator="<=",
                        expected=5.0,
                        unit=" %",
                        description="Throttle should be <5% at idle (0 = fully closed)",
                    ),
                ],
            ),
            TestStep(
                step_number=4,
                step_type=StepType.READ_PID,
                description="Read MAF sensor (idle airflow)",
                pid_name="MAF",
                store_as="idle_maf",
                required=False,
                criteria=[
                    Criterion(
                        field="value",
                        operator="between",
                        expected=[2.0, 8.0],
                        unit=" g/s",
                        description="MAF at idle typically 2-8 g/s (varies by engine size)",
                    ),
                ],
            ),
            TestStep(
                step_number=5,
                step_type=StepType.READ_PID,
                description="Read short-term fuel trim",
                pid_name="SHORT_FUEL_TRIM_1",
                store_as="idle_stft",
            ),
            TestStep(
                step_number=6,
                step_type=StepType.INSTRUCTION,
                description="Idle control test complete. Review results.",
                details=(
                    "HIGH IDLE (>1000 RPM when warm):\n"
                    "  • Vacuum leak (check hoses, intake gasket, PCV valve)\n"
                    "  • Stuck IAC valve (clean with throttle body cleaner)\n"
                    "  • Throttle plate stuck partially open (carbon buildup)\n"
                    "  • Coolant temp sensor reading cold (ECU idles high)\n\n"
                    "LOW IDLE (<500 RPM):\n"
                    "  • Dirty/stuck IAC valve\n"
                    "  • Carbon buildup on throttle body\n"
                    "  • Weak fuel pressure\n\n"
                    "SURGING IDLE (RPM oscillates):\n"
                    "  • Vacuum leak (especially from brake booster hose)\n"
                    "  • Dirty MAF sensor\n"
                    "  • Bad PCV valve\n"
                    "  • O2 sensor issue causing hunting"
                ),
            ),
        ],
    )


def _build_charging_system_test() -> TestProcedure:
    """Alternator / charging system test."""
    return TestProcedure(
        id="charging_system_test",
        name="Charging System Test",
        category=ProcedureCategory.CHARGING,
        safety_level=SafetyLevel.SAFE,
        description=(
            "Tests the alternator and charging system by monitoring battery voltage "
            "at idle and under electrical load. Identifies undercharging or "
            "overcharging conditions."
        ),
        prerequisites=[
            "Engine running at idle",
            "Battery should be in reasonable condition",
        ],
        applicable_systems=["P0562", "P0563", "P0620", "P0621", "P0622",
                           "charging", "battery", "alternator", "low_voltage"],
        estimated_time_minutes=3,
        requires_engine_running=True,
        requires_key_on=True,
        steps=[
            TestStep(
                step_number=1,
                step_type=StepType.READ_PID,
                description="Read battery/system voltage at idle",
                pid_name="CONTROL_MODULE_VOLTAGE",
                store_as="voltage_idle",
                criteria=[
                    Criterion(
                        field="value",
                        operator="between",
                        expected=[13.5, 14.8],
                        unit=" V",
                        description="Charging voltage at idle should be 13.5-14.8V",
                    ),
                ],
            ),
            TestStep(
                step_number=2,
                step_type=StepType.MONITOR_PID,
                description="Monitor voltage stability for 15 seconds",
                pid_name="CONTROL_MODULE_VOLTAGE",
                duration=15.0,
                store_as="voltage_monitor",
                details="Voltage should be stable. Fluctuations >0.5V may indicate "
                        "a failing alternator diode or loose belt.",
            ),
            TestStep(
                step_number=3,
                step_type=StepType.READ_PID,
                description="Read RPM at idle",
                pid_name="RPM",
                store_as="charge_rpm",
            ),
            TestStep(
                step_number=4,
                step_type=StepType.INSTRUCTION,
                description="Turn ON headlights, A/C, and rear defroster (add electrical load)",
                details="This loads the alternator to test its capacity. "
                        "Wait 10 seconds after turning on loads.",
            ),
            TestStep(
                step_number=5,
                step_type=StepType.WAIT,
                description="Wait for system to stabilize under load",
                duration=10.0,
            ),
            TestStep(
                step_number=6,
                step_type=StepType.READ_PID,
                description="Read voltage under electrical load",
                pid_name="CONTROL_MODULE_VOLTAGE",
                store_as="voltage_loaded",
                criteria=[
                    Criterion(
                        field="value",
                        operator=">=",
                        expected=13.2,
                        unit=" V",
                        description="Voltage under load should stay above 13.2V",
                    ),
                ],
            ),
            TestStep(
                step_number=7,
                step_type=StepType.INSTRUCTION,
                description="Turn OFF headlights, A/C, and defroster. Test complete.",
                details=(
                    "NORMAL: 13.5-14.8V at idle, drops no more than 0.5V under load.\n\n"
                    "UNDERCHARGING (<13.2V):\n"
                    "  • Worn/slipping drive belt\n"
                    "  • Bad alternator (diode failure, worn brushes)\n"
                    "  • Poor battery cable connections (corrosion)\n"
                    "  • Bad ground strap\n\n"
                    "OVERCHARGING (>15.0V):\n"
                    "  • Faulty voltage regulator (internal to alternator on most modern vehicles)\n"
                    "  • Bad PCM/BCM command signal to alternator\n"
                    "  • Can boil battery and damage electronics\n\n"
                    "FLUCTUATING (>0.5V swings):\n"
                    "  • Bad alternator diode (AC ripple)\n"
                    "  • Loose belt\n"
                    "  • Intermittent wiring connection"
                ),
            ),
        ],
    )


def _build_thermostat_test() -> TestProcedure:
    """Thermostat operation test via coolant warm-up rate."""
    return TestProcedure(
        id="thermostat_test",
        name="Thermostat Test",
        category=ProcedureCategory.COOLING,
        safety_level=SafetyLevel.SAFE,
        description=(
            "Tests thermostat operation by monitoring coolant temperature warm-up rate. "
            "A stuck-open thermostat causes slow warm-up; stuck-closed causes overheat."
        ),
        prerequisites=[
            "Cold engine preferred (at least partially cooled)",
            "Engine running",
        ],
        applicable_systems=["P0125", "P0126", "P0128",
                           "thermostat", "overheat", "slow_warmup", "no_heat"],
        estimated_time_minutes=10,
        requires_engine_running=True,
        requires_key_on=True,
        steps=[
            TestStep(
                step_number=1,
                step_type=StepType.READ_PID,
                description="Read initial coolant temperature",
                pid_name="COOLANT_TEMP",
                store_as="thermo_temp_start",
            ),
            TestStep(
                step_number=2,
                step_type=StepType.INSTRUCTION,
                description="Monitoring coolant warm-up for 3 minutes. Heater ON, no driving.",
                details="The coolant should rise steadily. Watch for: "
                        "stall at ~50°C (thermostat won't open), "
                        "no rise at all (stuck open), or rapid spike (stuck closed/low coolant).",
            ),
            TestStep(
                step_number=3,
                step_type=StepType.MONITOR_PID,
                description="Monitor coolant temperature for 180 seconds",
                pid_name="COOLANT_TEMP",
                duration=180.0,
                store_as="thermo_warmup",
            ),
            TestStep(
                step_number=4,
                step_type=StepType.READ_PID,
                description="Read coolant temperature after warm-up period",
                pid_name="COOLANT_TEMP",
                store_as="thermo_temp_end",
            ),
            TestStep(
                step_number=5,
                step_type=StepType.INSTRUCTION,
                description="Thermostat test complete. Review warm-up data.",
                details=(
                    "NORMAL: Temperature rises steadily from cold to ~85-95°C, "
                    "then stabilizes. Thermostat opens around 82-92°C (varies by vehicle).\n\n"
                    "STUCK OPEN: Temperature barely rises or takes >15 min to reach "
                    "operating temp. Heater blows lukewarm air. P0128 common.\n\n"
                    "STUCK CLOSED: Temperature climbs past 105°C and keeps rising. "
                    "Risk of overheating. Radiator hoses won't get hot (no flow).\n\n"
                    "INTERMITTENT: Temperature oscillates — rises, drops, rises again. "
                    "Thermostat opening and closing erratically."
                ),
            ),
        ],
    )


def _build_mass_airflow_test() -> TestProcedure:
    """MAF sensor performance test."""
    return TestProcedure(
        id="maf_sensor_test",
        name="MAF Sensor Test",
        category=ProcedureCategory.SENSORS,
        safety_level=SafetyLevel.SAFE,
        description=(
            "Tests the MAF (Mass Air Flow) sensor by reading airflow at idle and "
            "during snap throttle to verify range and response time."
        ),
        prerequisites=[
            "Engine running at idle, warmed up",
            "Air filter should be clean",
        ],
        applicable_systems=["P0100", "P0101", "P0102", "P0103", "P0104",
                           "maf", "air_flow", "hesitation", "stall"],
        estimated_time_minutes=3,
        requires_engine_running=True,
        requires_key_on=True,
        steps=[
            TestStep(
                step_number=1,
                step_type=StepType.MONITOR_PID,
                description="Monitor MAF at idle for 10 seconds",
                pid_name="MAF",
                duration=10.0,
                store_as="maf_idle",
                criteria=[
                    Criterion(
                        field="value",
                        operator="between",
                        expected=[2.0, 10.0],
                        unit=" g/s",
                        description="MAF at idle typically 2-10 g/s depending on engine size",
                    ),
                ],
            ),
            TestStep(
                step_number=2,
                step_type=StepType.READ_PID,
                description="Read intake air temperature",
                pid_name="INTAKE_TEMP",
                store_as="intake_temp",
                required=False,
            ),
            TestStep(
                step_number=3,
                step_type=StepType.READ_PID,
                description="Read MAP sensor for cross-reference",
                pid_name="INTAKE_PRESSURE",
                store_as="map_sensor",
                required=False,
            ),
            TestStep(
                step_number=4,
                step_type=StepType.READ_PID,
                description="Read fuel trims (high LTFT indicates dirty MAF)",
                pid_name="LONG_FUEL_TRIM_1",
                store_as="maf_ltft",
                criteria=[
                    Criterion(
                        field="value",
                        operator="between",
                        expected=[-10, 10],
                        unit=" %",
                        description="LTFT should be ±10%. High positive = MAF "
                                    "under-reading (dirty). High negative = MAF over-reading.",
                    ),
                ],
            ),
            TestStep(
                step_number=5,
                step_type=StepType.INSTRUCTION,
                description="SNAP THROTTLE TEST: Quickly blip the throttle to 3000 RPM",
                details="While monitoring, quickly press and release the gas pedal. "
                        "MAF should spike to 30-80+ g/s and return quickly. "
                        "Sluggish response indicates contaminated MAF element.",
            ),
            TestStep(
                step_number=6,
                step_type=StepType.MONITOR_PID,
                description="Monitor MAF during snap throttle (10 seconds — blip the throttle NOW)",
                pid_name="MAF",
                duration=10.0,
                store_as="maf_snap",
            ),
            TestStep(
                step_number=7,
                step_type=StepType.INSTRUCTION,
                description="MAF test complete. Review results.",
                details=(
                    "DIRTY MAF (most common):\n"
                    "  • LTFT >10% positive (MAF under-reads, ECU adds fuel to compensate)\n"
                    "  • Clean with MAF-specific cleaner only (CRC MAF cleaner)\n"
                    "  • NEVER touch the sensing element\n\n"
                    "FAILED MAF:\n"
                    "  • 0 g/s or stuck value at idle\n"
                    "  • No change during snap throttle\n"
                    "  • Replace sensor\n\n"
                    "RULE OF THUMB: Engine displacement (L) × ~1000 = expected MAF at WOT.\n"
                    "  e.g., 3.7L engine ≈ 37 g/s at idle RPM, ~100+ g/s at WOT."
                ),
            ),
        ],
    )


def _build_egr_test() -> TestProcedure:
    """EGR system test."""
    return TestProcedure(
        id="egr_system_test",
        name="EGR System Test",
        category=ProcedureCategory.EMISSIONS,
        safety_level=SafetyLevel.WARNING,
        description=(
            "Tests EGR system by commanding the EGR valve open at idle and monitoring "
            "RPM drop. A functional EGR causes rough idle when opened at idle."
        ),
        prerequisites=[
            "Engine running at idle, warmed up",
            "Vehicle in Park/Neutral",
        ],
        applicable_systems=["P0400", "P0401", "P0402", "P0403", "P0404", "P0405",
                           "egr", "nox"],
        estimated_time_minutes=3,
        requires_engine_running=True,
        requires_key_on=True,
        manufacturer="",
        steps=[
            TestStep(
                step_number=1,
                step_type=StepType.MONITOR_PID,
                description="Record baseline RPM at idle for 5 seconds",
                pid_name="RPM",
                duration=5.0,
                store_as="egr_baseline_rpm",
            ),
            TestStep(
                step_number=2,
                step_type=StepType.INSTRUCTION,
                description="Commanding EGR valve OPEN — expect RPM drop and rough idle",
                details="When the EGR valve opens at idle, exhaust gas displaces fresh air. "
                        "RPM should drop 200-400 RPM and the engine should stumble. "
                        "If nothing happens, the EGR valve or passage is stuck.",
            ),
            TestStep(
                step_number=3,
                step_type=StepType.ACTUATOR_ON,
                description="Command EGR valve open",
                actuator_name="egr_valve",
                duration=5.0,
            ),
            TestStep(
                step_number=4,
                step_type=StepType.MONITOR_PID,
                description="Monitor RPM with EGR open (should drop significantly)",
                pid_name="RPM",
                duration=5.0,
                store_as="egr_open_rpm",
            ),
            TestStep(
                step_number=5,
                step_type=StepType.ACTUATOR_OFF,
                description="Close EGR valve — return to idle",
                actuator_name="egr_valve",
            ),
            TestStep(
                step_number=6,
                step_type=StepType.WAIT,
                description="Wait for idle to recover",
                duration=3.0,
            ),
            TestStep(
                step_number=7,
                step_type=StepType.READ_PID,
                description="Confirm RPM recovered to normal idle",
                pid_name="RPM",
                store_as="egr_recovery_rpm",
            ),
            TestStep(
                step_number=8,
                step_type=StepType.INSTRUCTION,
                description="EGR test complete. Evaluate RPM drop.",
                details=(
                    "GOOD EGR: RPM dropped 200-400+ RPM and engine stumbled when EGR was "
                    "commanded open. EGR valve and passages are clear.\n\n"
                    "BAD EGR (no RPM change):\n"
                    "  • P0401 (insufficient flow): EGR passages clogged with carbon,\n"
                    "    or EGR valve diaphragm torn, or vacuum supply issue\n"
                    "  • P0402 (excessive flow): EGR stuck partially open,\n"
                    "    or DPFE sensor reading incorrectly (Ford)\n"
                    "  • Clean EGR valve and port with carbon cleaner\n"
                    "  • Check DPFE/EGR pressure feedback sensor hoses (Ford)"
                ),
            ),
        ],
    )


def _build_ford_gem_light_test() -> TestProcedure:
    """Ford GEM exterior light test."""
    return TestProcedure(
        id="ford_gem_light_test",
        name="Ford Exterior Light Test",
        category=ProcedureCategory.ELECTRICAL,
        safety_level=SafetyLevel.CAUTION,
        description=(
            "Tests all exterior lights controlled by the Ford GEM module by "
            "cycling through headlights, parking lights, turn signals, and brake lights. "
            "Useful for diagnosing B-codes and light outage complaints."
        ),
        prerequisites=[
            "Key ON, engine OFF",
            "Have an assistant observe lights outside the vehicle",
        ],
        applicable_systems=["B1342", "B1352", "B1595",
                           "lights", "headlight", "turn_signal", "brake_light"],
        estimated_time_minutes=5,
        requires_engine_running=False,
        requires_key_on=True,
        manufacturer="ford",
        steps=[
            TestStep(
                step_number=1,
                step_type=StepType.INSTRUCTION,
                description="Position someone outside to observe each light activation",
            ),
            TestStep(
                step_number=2,
                step_type=StepType.ACTUATOR_ON,
                description="Activate low beam headlights",
                actuator_name="low_beams",
                duration=3.0,
            ),
            TestStep(
                step_number=3,
                step_type=StepType.WAIT,
                description="Pause between light tests",
                duration=1.0,
            ),
            TestStep(
                step_number=4,
                step_type=StepType.ACTUATOR_ON,
                description="Activate high beam headlights",
                actuator_name="high_beams",
                duration=3.0,
            ),
            TestStep(
                step_number=5,
                step_type=StepType.WAIT,
                description="Pause",
                duration=1.0,
            ),
            TestStep(
                step_number=6,
                step_type=StepType.ACTUATOR_ON,
                description="Activate parking/marker lights",
                actuator_name="parking_lights",
                duration=3.0,
            ),
            TestStep(
                step_number=7,
                step_type=StepType.WAIT,
                description="Pause",
                duration=1.0,
            ),
            TestStep(
                step_number=8,
                step_type=StepType.ACTUATOR_ON,
                description="Flash left turn signal",
                actuator_name="left_turn_signal",
                duration=4.0,
            ),
            TestStep(
                step_number=9,
                step_type=StepType.WAIT,
                description="Pause",
                duration=1.0,
            ),
            TestStep(
                step_number=10,
                step_type=StepType.ACTUATOR_ON,
                description="Flash right turn signal",
                actuator_name="right_turn_signal",
                duration=4.0,
            ),
            TestStep(
                step_number=11,
                step_type=StepType.WAIT,
                description="Pause",
                duration=1.0,
            ),
            TestStep(
                step_number=12,
                step_type=StepType.ACTUATOR_ON,
                description="Activate fog lights (if equipped)",
                actuator_name="fog_lights",
                duration=3.0,
                required=False,
            ),
            TestStep(
                step_number=13,
                step_type=StepType.WAIT,
                description="Pause",
                duration=1.0,
            ),
            TestStep(
                step_number=14,
                step_type=StepType.ACTUATOR_ON,
                description="Activate reverse lights",
                actuator_name="reverse_lights",
                duration=3.0,
            ),
            TestStep(
                step_number=15,
                step_type=StepType.INSTRUCTION,
                description="Light test complete. Which lights did NOT illuminate?",
                details=(
                    "If a specific light didn't come on during the command:\n"
                    "  1. Check the bulb (remove and inspect filament)\n"
                    "  2. Check voltage at the socket with a test light\n"
                    "  3. Check the fuse for that circuit\n"
                    "  4. Check the ground connection at the light assembly\n\n"
                    "If the GEM command was sent but the light didn't activate:\n"
                    "  The issue is in the wiring between GEM and the light.\n"
                    "If the GEM command failed (no positive response):\n"
                    "  The GEM output driver may be damaged — check for B-codes."
                ),
            ),
        ],
    )


def _build_ford_door_lock_test() -> TestProcedure:
    """Ford door lock/unlock actuator test."""
    return TestProcedure(
        id="ford_door_lock_test",
        name="Ford Door Lock Actuator Test",
        category=ProcedureCategory.BODY,
        safety_level=SafetyLevel.CAUTION,
        description=(
            "Tests all door lock actuators by commanding lock and unlock cycles "
            "through the GEM module. Identifies failing door lock actuators."
        ),
        prerequisites=[
            "Key ON, engine OFF",
            "All doors closed",
        ],
        applicable_systems=["B1681", "B1682", "door_lock", "lock", "unlock"],
        estimated_time_minutes=2,
        requires_engine_running=False,
        requires_key_on=True,
        manufacturer="ford",
        steps=[
            TestStep(
                step_number=1,
                step_type=StepType.INSTRUCTION,
                description="Listen for each door lock actuator during the test",
            ),
            TestStep(
                step_number=2,
                step_type=StepType.ACTUATOR_ON,
                description="Command ALL doors LOCK",
                actuator_name="door_lock_all",
                duration=2.0,
            ),
            TestStep(
                step_number=3,
                step_type=StepType.WAIT,
                description="Pause",
                duration=2.0,
            ),
            TestStep(
                step_number=4,
                step_type=StepType.ACTUATOR_ON,
                description="Command ALL doors UNLOCK",
                actuator_name="door_unlock_all",
                duration=2.0,
            ),
            TestStep(
                step_number=5,
                step_type=StepType.WAIT,
                description="Pause",
                duration=2.0,
            ),
            TestStep(
                step_number=6,
                step_type=StepType.ACTUATOR_ON,
                description="Command driver door LOCK",
                actuator_name="driver_door_lock",
                duration=2.0,
                required=False,
            ),
            TestStep(
                step_number=7,
                step_type=StepType.WAIT,
                description="Pause",
                duration=1.0,
            ),
            TestStep(
                step_number=8,
                step_type=StepType.ACTUATOR_ON,
                description="Command driver door UNLOCK",
                actuator_name="driver_door_unlock",
                duration=2.0,
                required=False,
            ),
            TestStep(
                step_number=9,
                step_type=StepType.INSTRUCTION,
                description="Door lock test complete.",
                details=(
                    "If a specific door didn't lock/unlock:\n"
                    "  1. Check the door lock actuator motor (inside door panel)\n"
                    "  2. Check wiring between GEM and door harness (at door hinge boot)\n"
                    "  3. Check for broken linkage rod inside the door\n"
                    "  4. Hinge area harness flex-break is very common on older Fords\n\n"
                    "If ALL doors failed: Check GEM fuse, door lock relay, "
                    "or GEM output driver damage."
                ),
            ),
        ],
    )


def _build_abs_module_test() -> TestProcedure:
    """ABS module communication and DTC test."""
    return TestProcedure(
        id="abs_module_test",
        name="ABS Module Test",
        category=ProcedureCategory.BRAKES,
        safety_level=SafetyLevel.SAFE,
        description=(
            "Reads ABS module DTCs and wheel speed sensor data to diagnose "
            "ABS/traction control warning lights. Read-only, no actuator control."
        ),
        prerequisites=[
            "Key ON (engine can be off or running)",
            "ABS warning light may be on",
        ],
        applicable_systems=["C0035", "C0040", "C0045", "C0050",
                           "C1095", "C1145", "C1155", "C1165",
                           "abs", "traction_control", "stability"],
        estimated_time_minutes=3,
        requires_engine_running=False,
        requires_key_on=True,
        steps=[
            TestStep(
                step_number=1,
                step_type=StepType.READ_DTCS,
                description="Read all DTCs including ABS module",
                store_as="abs_dtcs",
            ),
            TestStep(
                step_number=2,
                step_type=StepType.READ_DID,
                description="Read ABS module software version",
                did=0xF195,
                module_addr=0x760,
                bus="MS-CAN",
                store_as="abs_sw_version",
                required=False,
            ),
            TestStep(
                step_number=3,
                step_type=StepType.INSTRUCTION,
                description="ABS data collection complete. Review DTCs.",
                details=(
                    "COMMON ABS ISSUES:\n"
                    "• C0035-C0050 (wheel speed sensors): Bad sensor, damaged tone ring, "
                    "corroded connector, or excessive wheel bearing play causing gap change.\n"
                    "• C0265/C0710 (pump motor): ABS pump circuit open/short.\n"
                    "• C1095-C1165 (Ford ABS sensors): Same as above, Ford-specific codes.\n"
                    "• U0121 (lost communication with ABS): Check CAN bus wiring to ABS module, "
                    "power/ground to ABS module, and ABS module connector.\n\n"
                    "WHEEL SPEED SENSOR DIAGNOSTICS:\n"
                    "  1. Compare all 4 wheel speed readings at 20 MPH — they should match within 2 MPH\n"
                    "  2. If one reads 0: bad sensor or cracked tone ring\n"
                    "  3. If one reads erratic: corroded connector or excessive bearing play\n"
                    "  4. Sensor resistance should be 800-2000 ohms (varies by vehicle)"
                ),
            ),
        ],
    )


def _build_tpms_test() -> TestProcedure:
    """TPMS sensor reading test."""
    return TestProcedure(
        id="tpms_test",
        name="TPMS Sensor Test",
        category=ProcedureCategory.BODY,
        safety_level=SafetyLevel.SAFE,
        description=(
            "Reads TPMS sensor data from the TPMS module to verify all sensors "
            "are communicating and reporting reasonable pressures."
        ),
        prerequisites=[
            "Key ON",
            "TPMS light may be on",
        ],
        applicable_systems=["C0750", "C0755", "C0760", "C0765",
                           "tpms", "tire_pressure", "low_tire"],
        estimated_time_minutes=2,
        requires_engine_running=False,
        requires_key_on=True,
        manufacturer="ford",
        steps=[
            TestStep(
                step_number=1,
                step_type=StepType.READ_DID,
                description="Read TPMS module part number",
                did=0xF111,
                module_addr=0x7A7,
                bus="MS-CAN",
                store_as="tpms_part",
                required=False,
            ),
            TestStep(
                step_number=2,
                step_type=StepType.READ_DID,
                description="Read TPMS tire pressure data DID DD01",
                did=0xDD01,
                module_addr=0x7A7,
                bus="MS-CAN",
                store_as="tpms_pressures",
                required=False,
            ),
            TestStep(
                step_number=3,
                step_type=StepType.READ_DID,
                description="Read TPMS temperature data DID DD02",
                did=0xDD02,
                module_addr=0x7A7,
                bus="MS-CAN",
                store_as="tpms_temps",
                required=False,
            ),
            TestStep(
                step_number=4,
                step_type=StepType.INSTRUCTION,
                description="TPMS test complete. Review sensor data.",
                details=(
                    "TPMS TROUBLESHOOTING:\n"
                    "• Flashing TPMS light (1 min then solid): Sensor communication lost — "
                    "check for dead battery in sensor (typical life 7-10 years), "
                    "or sensor damaged during tire change.\n"
                    "• Solid TPMS light: Low pressure detected — inflate to door placard spec.\n"
                    "• After tire rotation: Some vehicles need TPMS relearn procedure.\n"
                    "• After new sensors: Program sensor IDs to the TPMS module."
                ),
            ),
        ],
    )


# ---------------------------------------------------------------------------
# Procedure Library & Registry
# ---------------------------------------------------------------------------

# Build all procedures
PROCEDURE_LIBRARY: Dict[str, TestProcedure] = {}

def _register_procedure(proc: TestProcedure) -> None:
    """Register a procedure in the library."""
    PROCEDURE_LIBRARY[proc.id] = proc


def _build_from_compact(d: dict) -> TestProcedure:
    """Build a TestProcedure from a compact dict definition.
    
    Compact format:
        id, name, cat (category enum value), safe (safety enum value),
        desc, pre (prerequisites list), sys (applicable_systems list),
        time (est minutes), eng (requires engine running), mfr (manufacturer),
        steps: list of step dicts with keys:
            t (StepType value), d (description), dt (details),
            pid, did, mod (module_addr hex int), bus, uds, dur (duration),
            act (actuator_name), s (store_as), req (required, default True),
            c (criteria list of tuples: (field, op, expected, unit, desc))
    """
    steps = []
    for i, sd in enumerate(d["steps"], 1):
        criteria = []
        for ct in sd.get("c", []):
            criteria.append(Criterion(
                field=ct[0], operator=ct[1], expected=ct[2],
                unit=ct[3] if len(ct) > 3 else "",
                description=ct[4] if len(ct) > 4 else "",
            ))
        steps.append(TestStep(
            step_number=i,
            step_type=StepType(sd["t"]),
            description=sd["d"],
            details=sd.get("dt", ""),
            pid_name=sd.get("pid", ""),
            did=sd.get("did", 0),
            module_addr=sd.get("mod", 0),
            bus=sd.get("bus", "HS-CAN"),
            uds_command=sd.get("uds", ""),
            duration=sd.get("dur", 0.0),
            actuator_name=sd.get("act", ""),
            store_as=sd.get("s", ""),
            criteria=criteria,
            required=sd.get("req", True),
        ))
    return TestProcedure(
        id=d["id"],
        name=d["name"],
        category=ProcedureCategory(d["cat"]),
        safety_level=SafetyLevel(d["safe"]),
        description=d["desc"],
        prerequisites=d.get("pre", []),
        applicable_systems=d.get("sys", []),
        steps=steps,
        estimated_time_minutes=d.get("time", 5),
        requires_engine_running=d.get("eng", False),
        requires_key_on=d.get("key", True),
        manufacturer=d.get("mfr", ""),
    )


# ---------------------------------------------------------------------------
# Compact procedure definitions (data-driven, ~85 additional procedures)
# ---------------------------------------------------------------------------
COMPACT_PROCEDURES: List[dict] = [
    # ── TRANSMISSION (8) ─────────────────────────────────────────────────
    {
        "id": "trans_fluid_temp",
        "name": "Transmission Fluid Temperature Test",
        "cat": "transmission",
        "safe": "caution",
        "desc": "Monitor transmission fluid temperature during warmup to verify the temp sensor and thermostat are operating correctly. Fluid should reach 70-110°C during normal driving.",
        "pre": ["Engine running", "Transmission in Park", "Vehicle on level ground"],
        "sys": ["P0710", "P0711", "P0712", "P0713", "transmission", "trans fluid temp"],
        "time": 15,
        "eng": True,
        "mfr": "",
        "steps": [
            {"t": "read_pid", "d": "Read transmission oil temperature at cold start", "pid": "OIL_TEMP", "s": "cold_trans_temp",
             "c": [("value", "<", 50, "°C", "Fluid should be near ambient at cold start")]},
            {"t": "instruction", "d": "Drive the vehicle for 10-15 minutes under normal conditions to warm the transmission fluid"},
            {"t": "monitor_pid", "d": "Monitor transmission temperature during warmup", "pid": "OIL_TEMP", "dur": 60.0,
             "c": [("value", "between", [40, 130], "°C", "Temp should be rising steadily")]},
            {"t": "read_pid", "d": "Read stabilized transmission fluid temperature", "pid": "OIL_TEMP", "s": "warm_trans_temp",
             "c": [("value", "between", [70, 110], "°C", "Normal operating range is 70-110°C")]},
            {"t": "read_pid", "d": "Check for related DTCs", "pid": "OIL_TEMP", "req": False,
             "c": [("value", "<=", 120, "°C", "Temperature above 120°C indicates overheating")]},
        ],
    },
    {
        "id": "shift_solenoid_test",
        "name": "Shift Solenoid A/B Test",
        "cat": "transmission",
        "safe": "warning",
        "desc": "Test shift solenoids A and B via actuator control on the TCM. Verifies solenoid click and electrical operation. Vehicle must be stationary with wheels blocked.",
        "pre": ["Engine running", "Vehicle in Park", "Parking brake set", "Wheels chocked"],
        "sys": ["P0750", "P0755", "P0760", "P0765", "shift solenoid", "transmission"],
        "time": 10,
        "eng": True,
        "mfr": "",
        "steps": [
            {"t": "read_dtcs", "d": "Read existing transmission DTCs before testing", "s": "pre_dtcs"},
            {"t": "instruction", "d": "Ensure vehicle is securely in Park with parking brake set and wheels chocked. Listen near the transmission for solenoid clicks."},
            {"t": "actuator_on", "d": "Activate Shift Solenoid A", "act": "SHIFT_SOLENOID_A", "mod": 0x7E1, "dur": 3.0},
            {"t": "actuator_off", "d": "Deactivate Shift Solenoid A", "act": "SHIFT_SOLENOID_A", "mod": 0x7E1},
            {"t": "actuator_on", "d": "Activate Shift Solenoid B", "act": "SHIFT_SOLENOID_B", "mod": 0x7E1, "dur": 3.0},
            {"t": "actuator_off", "d": "Deactivate Shift Solenoid B", "act": "SHIFT_SOLENOID_B", "mod": 0x7E1},
            {"t": "read_dtcs", "d": "Read DTCs after solenoid test — new codes indicate a fault", "s": "post_dtcs"},
        ],
    },
    {
        "id": "torque_converter_clutch",
        "name": "Torque Converter Clutch Test",
        "cat": "transmission",
        "safe": "warning",
        "desc": "Test TCC engagement by monitoring the RPM vs vehicle speed ratio at highway speed. When the TCC locks, engine RPM should drop noticeably.",
        "pre": ["Engine at operating temp", "Vehicle on highway or dyno", "Transmission in Drive"],
        "sys": ["P0740", "P0741", "P0742", "P0743", "torque converter", "TCC"],
        "time": 15,
        "eng": True,
        "mfr": "",
        "steps": [
            {"t": "instruction", "d": "Drive the vehicle to 45-55 mph in top gear on a level road. Maintain steady speed."},
            {"t": "read_pid", "d": "Read RPM before TCC engagement", "pid": "RPM", "s": "rpm_unlocked",
             "c": [("value", "between", [1200, 2500], "RPM", "Normal cruising RPM range")]},
            {"t": "read_pid", "d": "Read vehicle speed", "pid": "SPEED", "s": "cruise_speed",
             "c": [("value", "between", [70, 100], "km/h", "Highway cruising speed")]},
            {"t": "instruction", "d": "TCC should engage at steady cruise. Watch for a 200-400 RPM drop indicating lockup."},
            {"t": "monitor_pid", "d": "Monitor RPM for TCC lockup event", "pid": "RPM", "dur": 15.0, "s": "rpm_locked",
             "c": [("value", "between", [1000, 2200], "RPM", "RPM should drop when TCC locks")]},
            {"t": "compare", "d": "Verify RPM dropped at least 150 RPM indicating TCC engagement",
             "c": [("value", ">=", 150, "RPM", "RPM drop should be ≥150 when TCC engages")]},
        ],
    },
    {
        "id": "trans_line_pressure",
        "name": "Transmission Line Pressure Test",
        "cat": "transmission",
        "safe": "caution",
        "desc": "Read transmission line pressure from the TCM via UDS DID. Compare against manufacturer specification for each gear range.",
        "pre": ["Engine running", "Transmission at operating temp", "Vehicle in Park"],
        "sys": ["P0868", "P0869", "P0962", "P0963", "line pressure", "transmission"],
        "time": 10,
        "eng": True,
        "mfr": "",
        "steps": [
            {"t": "instruction", "d": "Ensure transmission is at normal operating temperature (70-100°C)."},
            {"t": "read_did", "d": "Read transmission line pressure in Park", "did": 0xDD06, "mod": 0x7E1, "s": "line_press_park",
             "c": [("value", "between", [40, 80], "psi", "Park line pressure should be 40-80 psi")]},
            {"t": "instruction", "d": "With foot firmly on brake, shift to Drive."},
            {"t": "read_did", "d": "Read transmission line pressure in Drive", "did": 0xDD06, "mod": 0x7E1, "s": "line_press_drive",
             "c": [("value", "between", [55, 100], "psi", "Drive line pressure should be 55-100 psi")]},
            {"t": "instruction", "d": "With foot firmly on brake, shift to Reverse."},
            {"t": "read_did", "d": "Read transmission line pressure in Reverse", "did": 0xDD06, "mod": 0x7E1, "s": "line_press_rev",
             "c": [("value", "between", [70, 130], "psi", "Reverse line pressure is typically higher")]},
        ],
    },
    {
        "id": "gear_ratio_test",
        "name": "Gear Ratio Verification Test",
        "cat": "transmission",
        "safe": "warning",
        "desc": "Calculate actual gear ratios by comparing engine RPM to vehicle speed at each gear. Abnormal ratios indicate slipping or incorrect gear engagement.",
        "pre": ["Engine at operating temp", "Vehicle on road or dyno", "Transmission in Drive"],
        "sys": ["P0730", "P0731", "P0732", "P0733", "P0734", "gear ratio", "transmission"],
        "time": 20,
        "eng": True,
        "mfr": "",
        "steps": [
            {"t": "instruction", "d": "Drive the vehicle and manually hold each gear if possible. Start with 1st gear at 15-20 mph."},
            {"t": "read_pid", "d": "Read RPM in 1st gear", "pid": "RPM", "s": "rpm_gear1"},
            {"t": "read_pid", "d": "Read vehicle speed in 1st gear", "pid": "SPEED", "s": "speed_gear1"},
            {"t": "instruction", "d": "Accelerate smoothly and shift to 2nd gear. Hold at 25-35 mph."},
            {"t": "read_pid", "d": "Read RPM in 2nd gear", "pid": "RPM", "s": "rpm_gear2"},
            {"t": "read_pid", "d": "Read vehicle speed in 2nd gear", "pid": "SPEED", "s": "speed_gear2"},
            {"t": "read_pid", "d": "Read actual gear from transmission", "pid": "TRANS_ACTUAL_GEAR", "s": "actual_gear",
             "c": [("value", ">=", 1, "", "Gear number should be a valid gear")]},
        ],
    },
    {
        "id": "neutral_safety_switch",
        "name": "Neutral Safety Switch Test",
        "cat": "transmission",
        "safe": "warning",
        "desc": "Verify the neutral safety switch only allows starter engagement in Park and Neutral. Tests electrical continuity through the switch in all gear positions.",
        "pre": ["Key ON engine OFF", "Parking brake set", "Wheels chocked"],
        "sys": ["P0705", "P0706", "P0707", "P0708", "neutral safety", "range sensor"],
        "time": 10,
        "eng": False,
        "mfr": "",
        "steps": [
            {"t": "instruction", "d": "Set parking brake firmly and chock wheels. Have an assistant ready at the key."},
            {"t": "instruction", "d": "Place selector in PARK. Attempt to crank engine — it should crank normally."},
            {"t": "read_pid", "d": "Read RPM to verify engine cranking in Park", "pid": "RPM", "s": "rpm_park", "req": False},
            {"t": "instruction", "d": "Place selector in NEUTRAL. Attempt to crank — it should crank normally."},
            {"t": "instruction", "d": "Place selector in DRIVE (foot on brake). Attempt to crank — starter should NOT engage."},
            {"t": "instruction", "d": "Place selector in REVERSE (foot on brake). Attempt to crank — starter should NOT engage."},
            {"t": "instruction", "d": "If starter engages in Drive or Reverse, the neutral safety switch is faulty and must be replaced."},
        ],
    },
    {
        "id": "tcc_slip_test",
        "name": "TCC Slip RPM Test",
        "cat": "transmission",
        "safe": "warning",
        "desc": "Monitor TCC slip by comparing engine RPM to calculated converter output speed at steady cruise. Excessive slip indicates worn clutch or faulty TCC solenoid.",
        "pre": ["Engine at operating temp", "Vehicle at highway speed", "Transmission in top gear"],
        "sys": ["P0741", "P2769", "P2770", "TCC slip", "torque converter"],
        "time": 15,
        "eng": True,
        "mfr": "",
        "steps": [
            {"t": "instruction", "d": "Drive at a steady 55-65 mph on a level road in top gear. TCC should be locked."},
            {"t": "read_pid", "d": "Read engine RPM at cruise", "pid": "RPM", "s": "engine_rpm",
             "c": [("value", "between", [1200, 2200], "RPM", "Normal highway cruise RPM")]},
            {"t": "read_pid", "d": "Read vehicle speed", "pid": "SPEED", "s": "veh_speed"},
            {"t": "monitor_pid", "d": "Monitor RPM stability over 20 seconds — should be rock steady when TCC is locked", "pid": "RPM", "dur": 20.0,
             "c": [("value", "between", [1100, 2300], "RPM", "RPM fluctuation >50 RPM suggests TCC slip")]},
            {"t": "instruction", "d": "Lightly apply throttle and release. RPM should stay steady if TCC remains locked. A flare in RPM indicates TCC releasing under light load."},
            {"t": "read_dtcs", "d": "Check for TCC-related DTCs", "s": "tcc_dtcs"},
        ],
    },
    {
        "id": "reverse_light_test",
        "name": "Reverse Light Actuator Test",
        "cat": "transmission",
        "safe": "safe",
        "desc": "Verify reverse light operation by activating the reverse light output via the body control module actuator. Confirms wiring and bulb integrity.",
        "pre": ["Key ON engine OFF", "Vehicle in Park"],
        "sys": ["B1318", "B1342", "reverse light", "backup lamp"],
        "time": 5,
        "eng": False,
        "mfr": "",
        "steps": [
            {"t": "instruction", "d": "Have an assistant stand behind the vehicle to observe the reverse lights."},
            {"t": "actuator_on", "d": "Activate reverse light output via body module", "act": "REVERSE_LAMPS", "mod": 0x760, "bus": "MS-CAN", "dur": 5.0},
            {"t": "instruction", "d": "Verify both reverse lights illuminate. Note any that are dim or not working."},
            {"t": "actuator_off", "d": "Deactivate reverse light output", "act": "REVERSE_LAMPS", "mod": 0x760, "bus": "MS-CAN"},
            {"t": "instruction", "d": "If lights did not illuminate, check fuse, wiring, and bulbs. If actuator command was accepted but lights stayed off, suspect wiring or bulb failure."},
        ],
    },

    # ── IGNITION (6) ─────────────────────────────────────────────────────
    {
        "id": "ignition_coil_test",
        "name": "Ignition Coil Output Test",
        "cat": "ignition",
        "safe": "caution",
        "desc": "Test individual ignition coil outputs using UDS commands to disable cylinders one at a time and monitor misfire counters. Identifies weak or failed coils.",
        "pre": ["Engine running at idle", "Engine at operating temp"],
        "sys": ["P0351", "P0352", "P0353", "P0354", "P0300", "P0301", "P0302", "ignition coil", "misfire"],
        "time": 15,
        "eng": True,
        "mfr": "",
        "steps": [
            {"t": "read_pid", "d": "Read baseline RPM at idle", "pid": "RPM", "s": "baseline_rpm",
             "c": [("value", "between", [600, 900], "RPM", "Normal idle RPM range")]},
            {"t": "read_dtcs", "d": "Check for existing misfire DTCs", "s": "misfire_dtcs"},
            {"t": "read_did", "d": "Read misfire counters for all cylinders", "did": 0xDD01, "mod": 0x7E0, "s": "misfire_counts"},
            {"t": "instruction", "d": "Using scan tool cylinder balance test or UDS, disable cylinder 1 and note RPM drop. A healthy cylinder should cause a 50-100 RPM drop."},
            {"t": "instruction", "d": "Repeat for each cylinder. A cylinder showing little or no RPM drop when disabled is suspect for ignition coil or spark plug failure."},
            {"t": "read_did", "d": "Re-read misfire counters after testing", "did": 0xDD01, "mod": 0x7E0, "s": "misfire_counts_post"},
        ],
    },
    {
        "id": "crank_sensor_test",
        "name": "Crankshaft Position Sensor Test",
        "cat": "ignition",
        "safe": "caution",
        "desc": "Verify the crankshaft position sensor (CKP) signal by reading its DID during cranking and at idle. No signal during crank = bad sensor or wiring.",
        "pre": ["Key ON engine OFF"],
        "sys": ["P0335", "P0336", "P0337", "P0338", "crank sensor", "CKP", "no start"],
        "time": 10,
        "eng": False,
        "mfr": "",
        "steps": [
            {"t": "read_pid", "d": "Attempt to read RPM with key on engine off — should be 0", "pid": "RPM", "s": "rpm_koeo",
             "c": [("value", "==", 0, "RPM", "RPM should be 0 with engine off")]},
            {"t": "instruction", "d": "Crank the engine for 3-5 seconds while monitoring RPM. Do not start the engine."},
            {"t": "read_pid", "d": "Read RPM during cranking — should show 150-300 RPM", "pid": "RPM", "s": "rpm_crank",
             "c": [("value", "between", [100, 400], "RPM", "Cranking RPM should be 150-300 RPM")]},
            {"t": "read_dtcs", "d": "Check for CKP sensor DTCs", "s": "ckp_dtcs"},
            {"t": "instruction", "d": "If RPM reads 0 during cranking, the CKP sensor has no signal. Check connector, wiring, and sensor air gap. Measure resistance: typically 200-1000 ohms."},
        ],
    },
    {
        "id": "cam_sensor_test",
        "name": "Camshaft Position Sensor Test",
        "cat": "ignition",
        "safe": "caution",
        "desc": "Verify camshaft position sensor (CMP) operation by reading the CMP DID and comparing cam-to-crank synchronization. Ensures correct valve timing reference.",
        "pre": ["Engine running at idle"],
        "sys": ["P0340", "P0341", "P0342", "P0343", "cam sensor", "CMP", "synchronization"],
        "time": 10,
        "eng": True,
        "mfr": "",
        "steps": [
            {"t": "read_pid", "d": "Read engine RPM to confirm engine is running", "pid": "RPM", "s": "idle_rpm",
             "c": [("value", "between", [600, 900], "RPM", "Engine should be idling normally")]},
            {"t": "read_did", "d": "Read camshaft position sensor status DID from PCM", "did": 0xDD02, "mod": 0x7E0, "s": "cmp_status"},
            {"t": "read_did", "d": "Read cam-to-crank correlation DID", "did": 0xDD03, "mod": 0x7E0, "s": "cam_crank_corr"},
            {"t": "read_dtcs", "d": "Check for CMP-related DTCs", "s": "cmp_dtcs"},
            {"t": "instruction", "d": "If cam-to-crank correlation is out of spec, check timing chain stretch, cam sensor air gap, and sensor wiring. On VVT engines, also check oil control valve operation."},
        ],
    },
    {
        "id": "ignition_timing_test",
        "name": "Ignition Timing Advance Test",
        "cat": "ignition",
        "safe": "caution",
        "desc": "Read ignition timing advance at idle and during snap throttle to verify the PCM is correctly advancing timing under load. Confirms knock sensor and timing control loop.",
        "pre": ["Engine running at idle", "Engine at operating temp"],
        "sys": ["P0325", "P0326", "P0327", "ignition timing", "timing advance", "knock"],
        "time": 10,
        "eng": True,
        "mfr": "",
        "steps": [
            {"t": "read_pid", "d": "Read timing advance at idle", "pid": "TIMING_ADVANCE", "s": "timing_idle",
             "c": [("value", "between", [5, 20], "°BTDC", "Idle timing is typically 8-15° BTDC")]},
            {"t": "read_pid", "d": "Read engine RPM at idle", "pid": "RPM", "s": "rpm_idle"},
            {"t": "instruction", "d": "Quickly snap the throttle open to about 3000 RPM and hold for 2-3 seconds."},
            {"t": "read_pid", "d": "Read timing advance during snap throttle", "pid": "TIMING_ADVANCE", "s": "timing_snap",
             "c": [("value", "between", [15, 40], "°BTDC", "Timing should advance 15-40° under acceleration")]},
            {"t": "instruction", "d": "Release throttle. If timing doesn't advance, suspect knock sensor fault or PCM issue. If timing retards excessively, check for engine knock."},
            {"t": "read_pid", "d": "Verify timing returns to idle spec", "pid": "TIMING_ADVANCE", "s": "timing_return",
             "c": [("value", "between", [5, 20], "°BTDC", "Timing should return to idle range")]},
        ],
    },
    {
        "id": "knock_sensor_test",
        "name": "Knock Sensor Activity Test",
        "cat": "ignition",
        "safe": "caution",
        "desc": "Read knock sensor activity data from the PCM to verify the sensor detects vibration. Use a controlled tap on the engine block to trigger a response.",
        "pre": ["Engine running at idle", "Engine at operating temp"],
        "sys": ["P0325", "P0326", "P0327", "P0328", "P0330", "knock sensor", "detonation"],
        "time": 10,
        "eng": True,
        "mfr": "",
        "steps": [
            {"t": "read_pid", "d": "Read timing advance as baseline", "pid": "TIMING_ADVANCE", "s": "timing_baseline"},
            {"t": "read_did", "d": "Read knock sensor activity count from PCM", "did": 0xDD04, "mod": 0x7E0, "s": "knock_count_before"},
            {"t": "instruction", "d": "Using a small wrench, tap lightly on the engine block near the knock sensor. Do NOT strike hard enough to damage anything."},
            {"t": "read_pid", "d": "Read timing advance — should retard in response to knock detection", "pid": "TIMING_ADVANCE", "s": "timing_after_knock",
             "c": [("value", "<", 15, "°BTDC", "Timing should retard in response to knock event")]},
            {"t": "read_did", "d": "Read knock sensor activity count — should have increased", "did": 0xDD04, "mod": 0x7E0, "s": "knock_count_after"},
            {"t": "instruction", "d": "If knock count didn't increase and timing didn't retard, the knock sensor or wiring may be faulty. Check connector and sensor resistance (typically 4-6 MΩ for piezo type)."},
        ],
    },
    {
        "id": "spark_plug_test",
        "name": "Spark Plug / Cylinder Power Balance Test",
        "cat": "ignition",
        "safe": "caution",
        "desc": "Perform a cylinder power balance test by comparing RPM drop when each cylinder is disabled. A weak cylinder indicates spark plug, coil, or compression issues.",
        "pre": ["Engine running at idle", "Engine at operating temp"],
        "sys": ["P0300", "P0301", "P0302", "P0303", "P0304", "misfire", "spark plug", "power balance"],
        "time": 15,
        "eng": True,
        "mfr": "",
        "steps": [
            {"t": "read_pid", "d": "Read baseline idle RPM", "pid": "RPM", "s": "baseline_rpm",
             "c": [("value", "between", [600, 900], "RPM", "Normal idle RPM")]},
            {"t": "read_did", "d": "Read misfire counters from PCM", "did": 0xDD01, "mod": 0x7E0, "s": "misfire_initial"},
            {"t": "instruction", "d": "Disable cylinder 1 (via scan tool cylinder kill or by unplugging coil connector). Record RPM drop. Expected: 50-100 RPM drop per cylinder."},
            {"t": "instruction", "d": "Re-enable cylinder 1. Disable cylinder 2 and record RPM drop. Repeat for all cylinders."},
            {"t": "instruction", "d": "A cylinder showing less than 30 RPM drop is weak — suspect spark plug fouling, cracked insulator, or excessive gap. Remove and inspect plugs."},
            {"t": "read_did", "d": "Read final misfire counters", "did": 0xDD01, "mod": 0x7E0, "s": "misfire_final"},
        ],
    },

    # ── ELECTRICAL (6) ───────────────────────────────────────────────────
    {
        "id": "battery_load_test",
        "name": "Battery Load / Cranking Voltage Test",
        "cat": "electrical",
        "safe": "caution",
        "desc": "Read system voltage at rest and during cranking to evaluate battery condition. Voltage should remain above 9.6V during cranking. Below that indicates a weak battery.",
        "pre": ["Key ON engine OFF", "Headlights off", "All accessories off"],
        "sys": ["P0562", "P0563", "battery", "low voltage", "no crank", "slow crank"],
        "time": 10,
        "eng": False,
        "mfr": "",
        "steps": [
            {"t": "read_pid", "d": "Read resting battery voltage with key on", "pid": "CONTROL_MODULE_VOLTAGE", "s": "rest_voltage",
             "c": [("value", "between", [12.2, 13.0], "V", "Resting voltage should be 12.4-12.8V for a charged battery")]},
            {"t": "instruction", "d": "Turn on headlights for 30 seconds to apply a surface charge load, then turn them off."},
            {"t": "wait", "d": "Wait 10 seconds for voltage to stabilize", "dur": 10.0},
            {"t": "read_pid", "d": "Read voltage after surface charge removal", "pid": "CONTROL_MODULE_VOLTAGE", "s": "loaded_voltage",
             "c": [("value", ">=", 12.2, "V", "Voltage should stay above 12.2V after headlight load")]},
            {"t": "instruction", "d": "Crank the engine while monitoring voltage. Note minimum voltage during cranking."},
            {"t": "read_pid", "d": "Read voltage during/after cranking", "pid": "CONTROL_MODULE_VOLTAGE", "s": "crank_voltage",
             "c": [("value", ">=", 9.6, "V", "Cranking voltage must stay above 9.6V")]},
        ],
    },
    {
        "id": "alternator_output_test",
        "name": "Alternator Output Voltage Test",
        "cat": "electrical",
        "safe": "caution",
        "desc": "Monitor charging system voltage at idle and under electrical load. Proper alternator output should maintain 13.5-14.7V. Below 13.2V or above 15.0V indicates a problem.",
        "pre": ["Engine running at idle", "Engine at operating temp"],
        "sys": ["P0562", "P0563", "P0620", "P0621", "P0622", "alternator", "charging", "battery light"],
        "time": 10,
        "eng": True,
        "mfr": "",
        "steps": [
            {"t": "read_pid", "d": "Read charging voltage at idle with no loads", "pid": "CONTROL_MODULE_VOLTAGE", "s": "idle_voltage",
             "c": [("value", "between", [13.5, 14.7], "V", "Normal charging voltage range")]},
            {"t": "instruction", "d": "Turn on high beam headlights, rear defroster, blower on high, and heated seats if equipped."},
            {"t": "read_pid", "d": "Read voltage under electrical load", "pid": "CONTROL_MODULE_VOLTAGE", "s": "loaded_voltage",
             "c": [("value", ">=", 13.2, "V", "Voltage should stay above 13.2V under load")]},
            {"t": "read_pid", "d": "Read RPM to verify idle is compensating", "pid": "RPM", "s": "loaded_rpm"},
            {"t": "instruction", "d": "Rev engine to 2000 RPM briefly and read voltage."},
            {"t": "read_pid", "d": "Read voltage at 2000 RPM", "pid": "CONTROL_MODULE_VOLTAGE", "s": "rev_voltage",
             "c": [("value", "between", [13.8, 14.8], "V", "Voltage should be solid at higher RPM")]},
        ],
    },
    {
        "id": "starter_current_draw",
        "name": "Starter Motor Current Draw Test",
        "cat": "electrical",
        "safe": "caution",
        "desc": "Measure starter motor current draw during cranking using a clamp meter on the battery cable. Excessive draw indicates a failing starter or engine mechanical issue.",
        "pre": ["Key ON engine OFF", "Clamp meter available", "Battery fully charged"],
        "sys": ["starter", "no crank", "slow crank", "high current draw"],
        "time": 10,
        "eng": False,
        "mfr": "",
        "steps": [
            {"t": "read_pid", "d": "Read battery voltage before test", "pid": "CONTROL_MODULE_VOLTAGE", "s": "pre_voltage",
             "c": [("value", ">=", 12.4, "V", "Battery must be fully charged for valid results")]},
            {"t": "instruction", "d": "Place DC clamp meter around the battery positive cable. Set to 400A or higher range."},
            {"t": "instruction", "d": "Disable ignition (pull fuel pump fuse or ignition fuse) to prevent starting."},
            {"t": "instruction", "d": "Crank engine for 3-5 seconds. Record peak current draw. Normal: 4-cyl 100-150A, 6-cyl 150-200A, 8-cyl 200-250A."},
            {"t": "read_pid", "d": "Read RPM to verify cranking speed", "pid": "RPM", "s": "crank_rpm",
             "c": [("value", "between", [100, 350], "RPM", "Cranking speed should be 150-300 RPM")]},
            {"t": "instruction", "d": "If current draw exceeds spec by >50A, starter motor is likely failing. If cranking RPM is low with normal current, suspect engine mechanical drag."},
        ],
    },
    {
        "id": "parasitic_drain_test",
        "name": "Parasitic Battery Drain Test",
        "cat": "electrical",
        "safe": "safe",
        "desc": "Measure key-off current draw to identify parasitic drains killing the battery. Normal draw is under 50mA after all modules go to sleep (may take 20+ minutes).",
        "pre": ["Key OFF", "All doors closed", "DC clamp meter or milliamp meter available"],
        "sys": ["battery drain", "dead battery", "parasitic draw"],
        "time": 30,
        "eng": False,
        "mfr": "",
        "steps": [
            {"t": "instruction", "d": "Turn off all accessories. Remove key. Close all doors. Place DC clamp meter (milliamp capable) around battery negative cable."},
            {"t": "instruction", "d": "Lock the vehicle and wait 20-30 minutes for all modules to enter sleep mode. Some vehicles take up to 45 minutes."},
            {"t": "wait", "d": "Wait for modules to go to sleep", "dur": 60.0},
            {"t": "instruction", "d": "Read the current draw on the clamp meter. Normal: 20-50 mA. Over 50 mA indicates a parasitic drain."},
            {"t": "instruction", "d": "If drain exceeds 50mA: pull fuses one at a time from the interior fuse box. When the draw drops, that circuit contains the drain."},
            {"t": "instruction", "d": "Common culprits: aftermarket stereo, trunk light staying on, BCM not sleeping, faulty door latch switch, glove box light."},
        ],
    },
    {
        "id": "ground_circuit_test",
        "name": "Ground Circuit Voltage Drop Test",
        "cat": "electrical",
        "safe": "safe",
        "desc": "Measure voltage drop across key ground circuits to identify high-resistance connections. Ground voltage drop should be less than 0.1V under load.",
        "pre": ["Engine running", "Headlights on", "DVOM available"],
        "sys": ["ground", "voltage drop", "poor ground", "intermittent"],
        "time": 15,
        "eng": True,
        "mfr": "",
        "steps": [
            {"t": "instruction", "d": "Set DVOM to DC voltage, 2V or 200mV scale. Test is performed with engine running and loads on."},
            {"t": "instruction", "d": "Connect DVOM negative lead to battery negative post. Touch positive lead to engine block ground bolt. Read voltage drop. Should be <0.1V.",
             "dt": "This tests the battery-to-engine ground path. Over 0.1V indicates a corroded or loose ground connection."},
            {"t": "instruction", "d": "Move positive lead to body ground location (usually inner fender or firewall). Read voltage drop. Should be <0.1V."},
            {"t": "instruction", "d": "Test the PCM ground pin at the connector (back-probe). Should be <0.1V from battery negative."},
            {"t": "read_pid", "d": "Read system voltage — should be stable during testing", "pid": "CONTROL_MODULE_VOLTAGE", "s": "sys_voltage",
             "c": [("value", "between", [13.5, 14.7], "V", "System voltage should be normal with engine running")]},
            {"t": "instruction", "d": "Any ground showing >0.2V drop should be cleaned, tightened, or repaired. High ground resistance causes erratic sensor readings and DTCs."},
        ],
    },
    {
        "id": "voltage_drop_test",
        "name": "Charging Circuit Voltage Drop Test",
        "cat": "electrical",
        "safe": "caution",
        "desc": "Compare PCM-reported system voltage to actual battery post voltage to detect voltage drop in the charging circuit wiring between alternator, battery, and PCM.",
        "pre": ["Engine running", "DVOM available"],
        "sys": ["P0562", "P0563", "voltage drop", "charging", "wiring"],
        "time": 10,
        "eng": True,
        "mfr": "",
        "steps": [
            {"t": "read_pid", "d": "Read PCM-reported system voltage", "pid": "CONTROL_MODULE_VOLTAGE", "s": "pcm_voltage",
             "c": [("value", "between", [13.0, 15.0], "V", "PCM voltage reading")]},
            {"t": "instruction", "d": "Measure actual voltage at battery posts with DVOM. Record the reading."},
            {"t": "instruction", "d": "Measure voltage directly at alternator output terminal. Record the reading."},
            {"t": "instruction", "d": "Compare: Alternator terminal to battery positive should be <0.3V difference. Battery to PCM voltage should be <0.5V difference."},
            {"t": "instruction", "d": "If voltage drop exceeds 0.5V between any two points, inspect cables, fusible links, and connections in that segment for corrosion or damage."},
        ],
    },

    # ── HVAC (6) ─────────────────────────────────────────────────────────
    {
        "id": "ac_compressor_test",
        "name": "AC Compressor Clutch Test",
        "cat": "hvac",
        "safe": "caution",
        "desc": "Activate the AC compressor clutch via actuator command and verify engagement by monitoring RPM drop and intake air temperature decrease.",
        "pre": ["Engine running at idle", "Engine at operating temp", "AC system charged"],
        "sys": ["B1262", "P0530", "P0532", "P0533", "AC compressor", "AC clutch", "no cold air"],
        "time": 10,
        "eng": True,
        "mfr": "",
        "steps": [
            {"t": "read_pid", "d": "Read baseline RPM before AC activation", "pid": "RPM", "s": "rpm_no_ac",
             "c": [("value", "between", [600, 900], "RPM", "Normal idle")]},
            {"t": "read_pid", "d": "Read intake temp baseline", "pid": "INTAKE_TEMP", "s": "iat_baseline"},
            {"t": "actuator_on", "d": "Activate AC compressor clutch", "act": "AC_COMPRESSOR_CLUTCH", "mod": 0x7E0, "dur": 10.0},
            {"t": "read_pid", "d": "Read RPM with AC on — should increase slightly due to idle-up", "pid": "RPM", "s": "rpm_with_ac",
             "c": [("value", "between", [650, 1100], "RPM", "Idle should bump up 50-200 RPM with AC")]},
            {"t": "instruction", "d": "Verify AC clutch is physically engaged (hub spinning with pulley). Listen for compressor operation."},
            {"t": "actuator_off", "d": "Deactivate AC compressor clutch", "act": "AC_COMPRESSOR_CLUTCH", "mod": 0x7E0},
        ],
    },
    {
        "id": "blend_door_test",
        "name": "Blend Door Actuator Test",
        "cat": "hvac",
        "safe": "safe",
        "desc": "Activate the blend door actuator through its full range and verify temperature change at the vents. Tests the actuator motor and door linkage.",
        "pre": ["Engine running at operating temp", "Heater core warm"],
        "sys": ["B1260", "B1261", "blend door", "no heat", "stuck on hot", "stuck on cold"],
        "time": 10,
        "eng": True,
        "mfr": "",
        "steps": [
            {"t": "instruction", "d": "Set HVAC to maximum heat, face vents, blower on medium."},
            {"t": "instruction", "d": "Verify hot air comes from vents. Place thermometer in center vent."},
            {"t": "actuator_on", "d": "Command blend door to full cold position", "act": "BLEND_DOOR", "mod": 0x760, "bus": "MS-CAN", "dur": 10.0},
            {"t": "instruction", "d": "Verify vent temperature dropped significantly (should be near ambient or colder with AC)."},
            {"t": "actuator_on", "d": "Command blend door to full hot position", "act": "BLEND_DOOR", "mod": 0x760, "bus": "MS-CAN", "dur": 10.0},
            {"t": "instruction", "d": "Verify vent temperature returned to hot. If no temp change during the test, the blend door actuator or linkage is likely broken."},
        ],
    },
    {
        "id": "blower_motor_test",
        "name": "Blower Motor Speed Test",
        "cat": "hvac",
        "safe": "safe",
        "desc": "Activate the blower motor at multiple speed settings via actuator control. Verifies blower motor, resistor/module, and control circuit.",
        "pre": ["Key ON", "HVAC system accessible"],
        "sys": ["B1263", "blower motor", "no air flow", "blower resistor"],
        "time": 10,
        "eng": False,
        "mfr": "",
        "steps": [
            {"t": "instruction", "d": "Open a vent and place hand near it to feel airflow changes during the test."},
            {"t": "actuator_on", "d": "Command blower motor to low speed", "act": "BLOWER_MOTOR_LOW", "mod": 0x760, "bus": "MS-CAN", "dur": 5.0},
            {"t": "instruction", "d": "Verify low-speed airflow from vents."},
            {"t": "actuator_on", "d": "Command blower motor to high speed", "act": "BLOWER_MOTOR_HIGH", "mod": 0x760, "bus": "MS-CAN", "dur": 5.0},
            {"t": "instruction", "d": "Verify high-speed airflow from vents. Airflow should be noticeably stronger than low."},
            {"t": "actuator_off", "d": "Turn off blower motor", "act": "BLOWER_MOTOR_HIGH", "mod": 0x760, "bus": "MS-CAN"},
        ],
    },
    {
        "id": "cabin_temp_sensor",
        "name": "Cabin Temperature Sensor Test",
        "cat": "hvac",
        "safe": "safe",
        "desc": "Read the cabin temperature sensor value from the HVAC module and compare it to an actual thermometer reading. Verifies sensor accuracy for automatic climate control.",
        "pre": ["Key ON", "Thermometer available"],
        "sys": ["B1249", "B1250", "cabin temp sensor", "auto climate", "HVAC"],
        "time": 5,
        "eng": False,
        "mfr": "",
        "steps": [
            {"t": "instruction", "d": "Place a thermometer near the cabin temperature sensor aspirator (usually in the dash). Wait 2 minutes for it to stabilize."},
            {"t": "read_did", "d": "Read cabin temperature from HVAC module", "did": 0xDD10, "mod": 0x760, "bus": "MS-CAN", "s": "cabin_temp_did",
             "c": [("value", "between", [10, 45], "°C", "Reading should be in a reasonable cabin temperature range")]},
            {"t": "instruction", "d": "Compare the DID reading to the thermometer. They should match within ±3°C."},
            {"t": "instruction", "d": "If sensor reads significantly different from actual temp, check sensor aspirator tube for blockage and sensor connector for corrosion."},
        ],
    },
    {
        "id": "heater_core_flow",
        "name": "Heater Core Flow / Output Test",
        "cat": "hvac",
        "safe": "caution",
        "desc": "Monitor coolant temperature with heater on full blast to verify heater core flow. Insufficient heat output may indicate a clogged heater core or stuck blend door.",
        "pre": ["Engine running at operating temp", "Coolant level full"],
        "sys": ["no heat", "heater core", "low heat output", "coolant flow"],
        "time": 10,
        "eng": True,
        "mfr": "",
        "steps": [
            {"t": "read_pid", "d": "Read engine coolant temperature", "pid": "COOLANT_TEMP", "s": "ect_start",
             "c": [("value", "between", [80, 105], "°C", "Engine should be at operating temperature")]},
            {"t": "instruction", "d": "Set HVAC to maximum heat, blower on high, recirculation off. Place thermometer in center dash vent."},
            {"t": "wait", "d": "Wait 60 seconds for heater output to stabilize", "dur": 60.0},
            {"t": "instruction", "d": "Read vent temperature. Should be at least 50°C (122°F) with engine at operating temp. Below 40°C indicates restricted heater core."},
            {"t": "read_pid", "d": "Re-read coolant temp — should not have dropped significantly", "pid": "COOLANT_TEMP", "s": "ect_end",
             "c": [("value", "between", [78, 105], "°C", "Coolant temp should remain stable")]},
            {"t": "instruction", "d": "Feel both heater hoses at the firewall. Both should be hot. If inlet is hot and outlet is cool, the heater core is clogged."},
        ],
    },
    {
        "id": "ac_pressure_test",
        "name": "AC System Pressure Test",
        "cat": "hvac",
        "safe": "caution",
        "desc": "Read AC system high and low side pressures to evaluate refrigerant charge and compressor function. Can be read via DIDs on some vehicles or with manual gauge set.",
        "pre": ["Engine running at idle", "AC system accessible", "Ambient temp above 15°C"],
        "sys": ["P0530", "P0532", "P0533", "AC pressure", "low refrigerant", "AC not cold"],
        "time": 15,
        "eng": True,
        "mfr": "",
        "steps": [
            {"t": "read_pid", "d": "Read ambient/intake air temperature", "pid": "INTAKE_TEMP", "s": "ambient_temp",
             "c": [("value", ">=", 15, "°C", "AC testing requires ambient temp above 15°C")]},
            {"t": "instruction", "d": "Connect AC manifold gauge set to service ports if DIDs are not available. Turn AC on max cold, blower high, doors open."},
            {"t": "read_did", "d": "Read AC low-side pressure from AC module (if supported)", "did": 0xDD11, "mod": 0x760, "bus": "MS-CAN", "s": "ac_low_psi", "req": False,
             "c": [("value", "between", [25, 45], "psi", "Low side should be 25-45 psi at idle with AC on")]},
            {"t": "read_did", "d": "Read AC high-side pressure from AC module (if supported)", "did": 0xDD12, "mod": 0x760, "bus": "MS-CAN", "s": "ac_high_psi", "req": False,
             "c": [("value", "between", [150, 300], "psi", "High side should be 150-300 psi depending on ambient temp")]},
            {"t": "instruction", "d": "Compare pressures: Low side 25-45, high side 150-300 psi at 80°F ambient. Both sides equal = compressor not running. Low side high + high side low = bad compressor valve."},
            {"t": "instruction", "d": "If low side is very low (<15 psi) and high side is low, system is undercharged. Recover, vacuum, and recharge to spec."},
        ],
    },

    # ── SENSORS (8) ──────────────────────────────────────────────────────
    {
        "id": "map_sensor_test",
        "name": "MAP Sensor Test",
        "cat": "sensors",
        "safe": "safe",
        "desc": "Read manifold absolute pressure at key-on engine-off (should equal barometric) and at idle (should be 25-35 kPa). Verifies MAP sensor accuracy.",
        "pre": ["Key ON engine OFF for first reading, then start engine"],
        "sys": ["P0105", "P0106", "P0107", "P0108", "MAP sensor", "manifold pressure"],
        "time": 10,
        "eng": False,
        "mfr": "",
        "steps": [
            {"t": "read_pid", "d": "Read BAROMETRIC_PRESSURE at KOEO for reference", "pid": "BAROMETRIC_PRESSURE", "s": "baro_ref",
             "c": [("value", "between", [90, 105], "kPa", "Barometric pressure at sea level is ~101 kPa")]},
            {"t": "read_pid", "d": "Read intake manifold pressure at KOEO — should equal barometric", "pid": "INTAKE_PRESSURE", "s": "map_koeo", "req": False,
             "c": [("value", "between", [90, 105], "kPa", "MAP at KOEO should match barometric pressure")]},
            {"t": "instruction", "d": "Start the engine and let it idle."},
            {"t": "read_pid", "d": "Read MAP sensor at idle", "pid": "INTAKE_PRESSURE", "s": "map_idle",
             "c": [("value", "between", [25, 45], "kPa", "Idle manifold vacuum should produce 25-35 kPa")]},
            {"t": "instruction", "d": "Snap throttle open briefly and release."},
            {"t": "read_pid", "d": "Read MAP during snap throttle — should spike to near barometric then return", "pid": "INTAKE_PRESSURE", "s": "map_snap",
             "c": [("value", "between", [60, 105], "kPa", "MAP should spike during wide open throttle")]},
        ],
    },
    {
        "id": "throttle_position_test",
        "name": "Throttle Position Sensor Test",
        "cat": "sensors",
        "safe": "safe",
        "desc": "Read throttle position at closed throttle and wide open throttle to verify the TPS signal range and linearity. Ensures smooth throttle response.",
        "pre": ["Key ON engine OFF"],
        "sys": ["P0120", "P0121", "P0122", "P0123", "TPS", "throttle position"],
        "time": 5,
        "eng": False,
        "mfr": "",
        "steps": [
            {"t": "read_pid", "d": "Read throttle position at rest (foot off pedal)", "pid": "THROTTLE_POS", "s": "tp_closed",
             "c": [("value", "between", [10, 22], "%", "Closed throttle should read 14-20%")]},
            {"t": "instruction", "d": "Slowly press the accelerator pedal to wide open throttle (WOT) and hold."},
            {"t": "read_pid", "d": "Read throttle position at WOT", "pid": "THROTTLE_POS", "s": "tp_wot",
             "c": [("value", "between", [90, 100], "%", "WOT should read 95-100%")]},
            {"t": "instruction", "d": "Slowly release the pedal while watching the TPS reading. It should decrease smoothly without any jumps or dropouts."},
            {"t": "read_pid", "d": "Verify TPS returned to closed throttle value", "pid": "THROTTLE_POS", "s": "tp_return",
             "c": [("value", "between", [10, 22], "%", "Should return to closed position")]},
        ],
    },
    {
        "id": "iat_sensor_test",
        "name": "Intake Air Temperature Sensor Test",
        "cat": "sensors",
        "safe": "safe",
        "desc": "Read intake air temperature at cold start and compare to ambient temperature. The IAT should be within 5°C of ambient on a cold engine start.",
        "pre": ["Engine cold (sat for 2+ hours)", "Key ON engine OFF", "Thermometer available"],
        "sys": ["P0110", "P0111", "P0112", "P0113", "IAT sensor", "intake air temp"],
        "time": 5,
        "eng": False,
        "mfr": "",
        "steps": [
            {"t": "instruction", "d": "Verify engine has been sitting for at least 2 hours and is at ambient temperature. Note the ambient temperature from a thermometer."},
            {"t": "read_pid", "d": "Read intake air temperature sensor", "pid": "INTAKE_TEMP", "s": "iat_reading",
             "c": [("value", "between", [-10, 50], "°C", "IAT should read a reasonable ambient temperature")]},
            {"t": "read_pid", "d": "Read coolant temp for comparison (should also be near ambient on cold engine)", "pid": "COOLANT_TEMP", "s": "ect_cold",
             "c": [("value", "between", [-10, 50], "°C", "ECT should be near ambient on cold engine")]},
            {"t": "instruction", "d": "IAT and ECT should be within 5°C of each other and within 5°C of ambient temperature on a cold engine."},
            {"t": "instruction", "d": "If IAT is significantly different from ambient, check sensor connector, wiring, and sensor resistance. Typical: 2-3 kΩ at 20°C."},
        ],
    },
    {
        "id": "ect_sensor_test",
        "name": "Engine Coolant Temperature Sensor Test",
        "cat": "sensors",
        "safe": "safe",
        "desc": "Read coolant temperature at cold start (should be near ambient) and after warmup (80-105°C). Verifies the ECT sensor and thermostat operation.",
        "pre": ["Engine cold (sat for 2+ hours)", "Key ON engine OFF"],
        "sys": ["P0115", "P0116", "P0117", "P0118", "P0125", "ECT sensor", "coolant temp"],
        "time": 15,
        "eng": False,
        "mfr": "",
        "steps": [
            {"t": "read_pid", "d": "Read coolant temperature at cold start", "pid": "COOLANT_TEMP", "s": "ect_cold",
             "c": [("value", "between", [-10, 50], "°C", "Cold engine should be near ambient temperature")]},
            {"t": "instruction", "d": "Start the engine and let it idle. Monitor coolant temperature as it warms up."},
            {"t": "monitor_pid", "d": "Monitor coolant temp during warmup — should rise steadily", "pid": "COOLANT_TEMP", "dur": 120.0,
             "c": [("value", "between", [0, 110], "°C", "Temperature should be rising steadily")]},
            {"t": "instruction", "d": "Watch for thermostat opening around 82-95°C — temp may dip briefly then stabilize."},
            {"t": "read_pid", "d": "Read stabilized coolant temperature after warmup", "pid": "COOLANT_TEMP", "s": "ect_warm",
             "c": [("value", "between", [80, 105], "°C", "Normal operating temp is 82-100°C")]},
            {"t": "instruction", "d": "If temp never reaches 80°C, thermostat may be stuck open. If temp exceeds 110°C, check cooling fan, coolant level, and thermostat."},
        ],
    },
    {
        "id": "vehicle_speed_sensor",
        "name": "Vehicle Speed Sensor Test",
        "cat": "sensors",
        "safe": "warning",
        "desc": "Read the vehicle speed PID while driving and compare to GPS speed or speedometer. Verifies the VSS signal is accurate for speedometer, transmission, and ABS function.",
        "pre": ["Vehicle on road", "GPS or verified speedometer available"],
        "sys": ["P0500", "P0501", "P0502", "P0503", "vehicle speed sensor", "VSS", "speedometer"],
        "time": 10,
        "eng": True,
        "mfr": "",
        "steps": [
            {"t": "instruction", "d": "Drive the vehicle on a safe, straight road. Have a GPS device or phone GPS speedometer ready for comparison."},
            {"t": "read_pid", "d": "Read speed at approximately 30 mph / 50 km/h", "pid": "SPEED", "s": "speed_low",
             "c": [("value", "between", [40, 60], "km/h", "Should read approximately 50 km/h")]},
            {"t": "read_pid", "d": "Read speed at approximately 60 mph / 100 km/h", "pid": "SPEED", "s": "speed_high",
             "c": [("value", "between", [85, 115], "km/h", "Should read approximately 100 km/h")]},
            {"t": "instruction", "d": "Compare OBD speed reading to GPS speed. They should match within ±5 km/h. Speedometer typically reads 2-5% high by design."},
            {"t": "instruction", "d": "If speed reads 0 while driving, the VSS has no signal. Check sensor, tone ring, and wiring. If speed is erratic, check tone ring for damage."},
        ],
    },
    {
        "id": "app_sensor_test",
        "name": "Accelerator Pedal Position Sensor Test",
        "cat": "sensors",
        "safe": "safe",
        "desc": "Read throttle position and commanded throttle actuator while sweeping the accelerator pedal. Verifies APP sensor correlation and electronic throttle body response.",
        "pre": ["Key ON engine OFF"],
        "sys": ["P2122", "P2123", "P2127", "P2128", "P2138", "APP sensor", "accelerator pedal", "throttle body"],
        "time": 5,
        "eng": False,
        "mfr": "",
        "steps": [
            {"t": "read_pid", "d": "Read throttle position at rest", "pid": "THROTTLE_POS", "s": "tp_rest",
             "c": [("value", "between", [10, 22], "%", "Closed throttle should read 14-20%")]},
            {"t": "instruction", "d": "Slowly press the accelerator pedal from rest to 25%, 50%, 75%, and 100% (WOT), pausing briefly at each position."},
            {"t": "read_pid", "d": "Read throttle position at mid-pedal", "pid": "THROTTLE_POS", "s": "tp_mid",
             "c": [("value", "between", [40, 60], "%", "Mid-pedal should read approximately 50%")]},
            {"t": "read_pid", "d": "Read throttle position at WOT", "pid": "THROTTLE_POS", "s": "tp_wot",
             "c": [("value", "between", [90, 100], "%", "WOT should read 95-100%")]},
            {"t": "instruction", "d": "Release the pedal smoothly. Throttle position should decrease linearly without dead spots, jumps, or glitches."},
            {"t": "read_pid", "d": "Verify return to rest position", "pid": "THROTTLE_POS", "s": "tp_final",
             "c": [("value", "between", [10, 22], "%", "Should return cleanly to rest position")]},
        ],
    },
    {
        "id": "fuel_rail_pressure_test",
        "name": "Fuel Rail Pressure Test",
        "cat": "sensors",
        "safe": "caution",
        "desc": "Read fuel rail pressure at idle and during snap throttle to verify fuel pump output, pressure regulator, and injector balance. Applicable to GDI and port injection.",
        "pre": ["Engine running at idle", "Engine at operating temp"],
        "sys": ["P0190", "P0191", "P0192", "P0193", "P0087", "fuel rail pressure", "fuel pump", "low fuel pressure"],
        "time": 10,
        "eng": True,
        "mfr": "",
        "steps": [
            {"t": "read_pid", "d": "Read fuel rail pressure at idle", "pid": "FUEL_RAIL_PRESSURE_DIRECT", "s": "frp_idle",
             "c": [("value", "between", [30000, 60000], "kPa", "GDI idle pressure typically 3000-6000 kPa; port injection 250-400 kPa")]},
            {"t": "read_pid", "d": "Read engine RPM for reference", "pid": "RPM", "s": "rpm_idle"},
            {"t": "instruction", "d": "Snap throttle to 3000 RPM and hold briefly. Fuel pressure should rise to support increased demand."},
            {"t": "read_pid", "d": "Read fuel rail pressure during snap throttle", "pid": "FUEL_RAIL_PRESSURE_DIRECT", "s": "frp_snap",
             "c": [("value", ">=", 25000, "kPa", "Pressure should increase with demand")]},
            {"t": "instruction", "d": "Release throttle. Pressure should return to idle spec within 2-3 seconds."},
            {"t": "read_pid", "d": "Read fuel rail pressure after return to idle", "pid": "FUEL_RAIL_PRESSURE_DIRECT", "s": "frp_return",
             "c": [("value", "between", [30000, 60000], "kPa", "Pressure should stabilize at idle spec")]},
        ],
    },
    {
        "id": "baro_pressure_test",
        "name": "Barometric Pressure Sensor Test",
        "cat": "sensors",
        "safe": "safe",
        "desc": "Read the barometric pressure sensor and compare to known local altitude-adjusted pressure. Verifies BARO sensor accuracy for fuel trim calculations.",
        "pre": ["Key ON", "Know your local altitude/barometric pressure"],
        "sys": ["P0105", "P0106", "barometric", "BARO sensor", "altitude"],
        "time": 5,
        "eng": False,
        "mfr": "",
        "steps": [
            {"t": "read_pid", "d": "Read barometric pressure from PCM", "pid": "BAROMETRIC_PRESSURE", "s": "baro_reading",
             "c": [("value", "between", [85, 105], "kPa", "Sea level ~101 kPa, decreases with altitude")]},
            {"t": "instruction", "d": "Compare to known local barometric pressure (from weather station or phone app). Should match within ±3 kPa."},
            {"t": "instruction", "d": "At sea level: expect 99-103 kPa. At 1000m altitude: expect ~90 kPa. At 1500m: expect ~85 kPa."},
            {"t": "read_pid", "d": "Read intake manifold pressure for comparison — at KOEO, MAP should equal BARO", "pid": "INTAKE_PRESSURE", "s": "map_compare",
             "c": [("value", "between", [85, 105], "kPa", "MAP at KOEO should match barometric pressure")]},
        ],
    },

    # ── BRAKES (6) ───────────────────────────────────────────────────────
    {
        "id": "abs_wheel_speed_test",
        "name": "ABS Wheel Speed Sensor Consistency Test",
        "cat": "brakes",
        "safe": "warning",
        "desc": "Read all four ABS wheel speed sensors at a constant vehicle speed and compare for consistency. All four should be within 2 km/h of each other. Discrepancies indicate a faulty sensor or tone ring.",
        "pre": ["Vehicle driving at steady 40-60 km/h", "Flat level road", "Tires same size all around"],
        "sys": ["C0035", "C0040", "C0045", "C0050", "wheel speed", "ABS", "traction control"],
        "time": 10,
        "eng": True,
        "mfr": "",
        "steps": [
            {"t": "instruction", "d": "Drive vehicle at a steady 50 km/h on a flat, straight road. Maintain constant speed."},
            {"t": "read_did", "d": "Read left front wheel speed from ABS module", "did": 0xDD01, "mod": 0x760, "bus": "HS-CAN", "s": "ws_lf",
             "c": [("value", "between", [40, 60], "km/h", "Should match vehicle speed")]},
            {"t": "read_did", "d": "Read right front wheel speed from ABS module", "did": 0xDD02, "mod": 0x760, "bus": "HS-CAN", "s": "ws_rf",
             "c": [("value", "between", [40, 60], "km/h", "Should match vehicle speed")]},
            {"t": "read_did", "d": "Read left rear wheel speed from ABS module", "did": 0xDD03, "mod": 0x760, "bus": "HS-CAN", "s": "ws_lr",
             "c": [("value", "between", [40, 60], "km/h", "Should match vehicle speed")]},
            {"t": "read_did", "d": "Read right rear wheel speed from ABS module", "did": 0xDD04, "mod": 0x760, "bus": "HS-CAN", "s": "ws_rr",
             "c": [("value", "between", [40, 60], "km/h", "Should match vehicle speed")]},
            {"t": "instruction", "d": "Compare all four readings. Maximum deviation should be ≤2 km/h. If one sensor reads significantly different, inspect that wheel's tone ring, sensor gap, and wiring."},
        ],
    },
    {
        "id": "brake_switch_test",
        "name": "Brake Light Switch Test",
        "cat": "brakes",
        "safe": "safe",
        "desc": "Read the brake switch input state from the BCM via DID while pressing and releasing the brake pedal. Verifies the switch toggles correctly for brake lights and cruise cancel.",
        "pre": ["Key ON", "Engine off or running"],
        "sys": ["C0110", "P0504", "P0571", "brake switch", "brake light", "cruise cancel"],
        "time": 5,
        "eng": False,
        "mfr": "",
        "steps": [
            {"t": "instruction", "d": "Do NOT press the brake pedal yet."},
            {"t": "read_did", "d": "Read brake switch state from BCM — should show OFF/released", "did": 0xDD10, "mod": 0x726, "bus": "MS-CAN", "s": "brake_off",
             "c": [("value", "==", 0, "", "Brake switch should read 0/OFF when pedal is released")]},
            {"t": "instruction", "d": "Press and hold the brake pedal firmly."},
            {"t": "read_did", "d": "Read brake switch state from BCM — should show ON/pressed", "did": 0xDD10, "mod": 0x726, "bus": "MS-CAN", "s": "brake_on",
             "c": [("value", "==", 1, "", "Brake switch should read 1/ON when pedal is pressed")]},
            {"t": "instruction", "d": "Release the brake pedal. Have an assistant verify brake lights illuminate when pedal is pressed and turn off when released."},
        ],
    },
    {
        "id": "brake_pedal_position",
        "name": "Brake Pedal Position Sensor Test",
        "cat": "brakes",
        "safe": "safe",
        "desc": "Read brake pedal position sensor data from the ABS module via DID. Verify smooth linear output through full pedal travel from released to fully depressed.",
        "pre": ["Key ON", "Engine off"],
        "sys": ["C0186", "U0121", "brake pedal position", "BPP sensor"],
        "time": 5,
        "eng": False,
        "mfr": "",
        "steps": [
            {"t": "instruction", "d": "Ensure brake pedal is fully released."},
            {"t": "read_did", "d": "Read brake pedal position at rest", "did": 0xDD11, "mod": 0x760, "bus": "HS-CAN", "s": "bpp_rest",
             "c": [("value", "between", [0, 10], "%", "Should be near 0% when fully released")]},
            {"t": "instruction", "d": "Slowly depress brake pedal to approximately half travel."},
            {"t": "read_did", "d": "Read brake pedal position at mid-travel", "did": 0xDD11, "mod": 0x760, "bus": "HS-CAN", "s": "bpp_mid",
             "c": [("value", "between", [30, 70], "%", "Should be approximately 50% at mid-travel")]},
            {"t": "instruction", "d": "Depress brake pedal fully."},
            {"t": "read_did", "d": "Read brake pedal position at full travel", "did": 0xDD11, "mod": 0x760, "bus": "HS-CAN", "s": "bpp_full",
             "c": [("value", "between", [80, 100], "%", "Should be near 100% when fully depressed")]},
        ],
    },
    {
        "id": "brake_fluid_level",
        "name": "Brake Fluid Level Check",
        "cat": "brakes",
        "safe": "safe",
        "desc": "Read the brake fluid level sensor DID from the ABS module and visually inspect the reservoir level. Low fluid may indicate worn pads or a leak.",
        "pre": ["Key ON", "Vehicle on level ground"],
        "sys": ["C0050", "C0070", "brake fluid", "low brake fluid", "brake warning"],
        "time": 5,
        "eng": False,
        "mfr": "",
        "steps": [
            {"t": "read_did", "d": "Read brake fluid level sensor from ABS module", "did": 0xDD12, "mod": 0x760, "bus": "HS-CAN", "s": "fluid_level",
             "c": [("value", "==", 1, "", "1 = OK/Normal, 0 = Low")]},
            {"t": "instruction", "d": "Open the hood and locate the brake master cylinder reservoir. Check fluid level visually — it should be between MIN and MAX marks."},
            {"t": "instruction", "d": "If fluid is low, check brake pad thickness on all four wheels. Worn pads cause fluid level to drop as calipers extend."},
            {"t": "instruction", "d": "Inspect for leaks at brake lines, calipers, wheel cylinders, and master cylinder. Low fluid with good pads indicates a leak."},
        ],
    },
    {
        "id": "parking_brake_test",
        "name": "Electric Parking Brake Test",
        "cat": "brakes",
        "safe": "caution",
        "desc": "Activate and release the electric parking brake motor via actuator command. Verifies the EPB motor, cables, and module are functioning correctly.",
        "pre": ["Vehicle stationary", "Engine running", "Foot on brake pedal", "Vehicle on level ground"],
        "sys": ["C0062", "C0063", "parking brake", "EPB", "electric parking brake"],
        "time": 10,
        "eng": True,
        "mfr": "",
        "steps": [
            {"t": "instruction", "d": "Ensure vehicle is on level ground, foot firmly on the service brake. Vehicle must be stationary."},
            {"t": "read_did", "d": "Read EPB status — should show released/disengaged", "did": 0xDD15, "mod": 0x760, "bus": "HS-CAN", "s": "epb_status_pre"},
            {"t": "actuator_on", "d": "Command electric parking brake to ENGAGE (apply)", "act": "EPB_APPLY", "mod": 0x760, "dur": 5.0},
            {"t": "read_did", "d": "Read EPB status — should now show engaged/applied", "did": 0xDD15, "mod": 0x760, "bus": "HS-CAN", "s": "epb_status_on",
             "c": [("value", "==", 1, "", "EPB should report engaged status")]},
            {"t": "actuator_on", "d": "Command electric parking brake to RELEASE", "act": "EPB_RELEASE", "mod": 0x760, "dur": 5.0},
            {"t": "read_did", "d": "Read EPB status — should show released again", "did": 0xDD15, "mod": 0x760, "bus": "HS-CAN", "s": "epb_status_off",
             "c": [("value", "==", 0, "", "EPB should report released status")]},
        ],
    },
    {
        "id": "abs_pump_test",
        "name": "ABS Pump Motor Test",
        "cat": "brakes",
        "safe": "caution",
        "desc": "Briefly activate the ABS pump motor to verify it operates. The pump should produce an audible hum and the brake pedal may pulse slightly during the test.",
        "pre": ["Key ON", "Engine running", "Foot off brake pedal"],
        "sys": ["C0060", "C0065", "C0070", "ABS pump", "ABS motor", "brake modulator"],
        "time": 5,
        "eng": True,
        "mfr": "",
        "steps": [
            {"t": "instruction", "d": "Keep foot OFF the brake pedal. The ABS pump will be activated briefly. Listen for a humming/buzzing sound from the ABS modulator under the hood."},
            {"t": "read_dtcs", "d": "Read ABS DTCs before test", "s": "abs_dtcs_before"},
            {"t": "actuator_on", "d": "Activate ABS pump motor", "act": "ABS_PUMP_MOTOR", "mod": 0x760, "dur": 3.0},
            {"t": "instruction", "d": "Verify the ABS pump motor was audible. A clicking or humming near the ABS module is normal. No sound indicates a faulty pump motor or relay."},
            {"t": "actuator_off", "d": "Deactivate ABS pump motor", "act": "ABS_PUMP_MOTOR", "mod": 0x760},
            {"t": "read_dtcs", "d": "Read ABS DTCs after pump test — new codes indicate a fault", "s": "abs_dtcs_after"},
        ],
    },

    # ── BODY (8) ─────────────────────────────────────────────────────────
    {
        "id": "power_window_test",
        "name": "Power Window Actuator Test",
        "cat": "body",
        "safe": "caution",
        "desc": "Test power window up/down operation via BCM actuator control. Verifies the window motor, regulator, and BCM output circuits.",
        "pre": ["Key ON or engine running", "Door closed", "Window not obstructed"],
        "sys": ["B1342", "B1583", "B1584", "power window", "window motor", "window stuck"],
        "time": 10,
        "eng": False,
        "mfr": "",
        "steps": [
            {"t": "instruction", "d": "Clear the area around all windows. Ensure nothing is blocking window travel and fingers are clear."},
            {"t": "actuator_on", "d": "Command driver window DOWN through BCM", "act": "WINDOW_DR_DOWN", "mod": 0x726, "bus": "MS-CAN", "dur": 5.0},
            {"t": "instruction", "d": "Verify the driver window moved down smoothly without binding or unusual noise."},
            {"t": "actuator_on", "d": "Command driver window UP through BCM", "act": "WINDOW_DR_UP", "mod": 0x726, "bus": "MS-CAN", "dur": 5.0},
            {"t": "instruction", "d": "Verify the driver window moved up smoothly and sealed at the top. Repeat for passenger windows as needed."},
        ],
    },
    {
        "id": "door_ajar_test",
        "name": "Door Ajar Switch Test",
        "cat": "body",
        "safe": "safe",
        "desc": "Open and close each door while reading door ajar switch state from the BCM. Verifies the plunger switches, wiring, and BCM inputs for all doors.",
        "pre": ["Key ON", "All doors closed"],
        "sys": ["B1342", "B1540", "B1541", "door ajar", "dome light stays on", "door open warning"],
        "time": 10,
        "eng": False,
        "mfr": "",
        "steps": [
            {"t": "read_did", "d": "Read door ajar status with all doors closed — all should show CLOSED", "did": 0xDD20, "mod": 0x726, "bus": "MS-CAN", "s": "doors_closed",
             "c": [("value", "==", 0, "", "All door ajar switches should read 0/closed")]},
            {"t": "instruction", "d": "Open the driver door. Leave all other doors closed."},
            {"t": "read_did", "d": "Read door ajar status — driver door should show OPEN", "did": 0xDD20, "mod": 0x726, "bus": "MS-CAN", "s": "dr_door_open"},
            {"t": "instruction", "d": "Close driver door. Open the front passenger door."},
            {"t": "read_did", "d": "Read door ajar status — passenger door should show OPEN", "did": 0xDD20, "mod": 0x726, "bus": "MS-CAN", "s": "pass_door_open"},
            {"t": "instruction", "d": "Close passenger door. Repeat for each remaining door (rear left, rear right, liftgate/trunk). All switches should toggle cleanly."},
        ],
    },
    {
        "id": "trunk_release_test",
        "name": "Trunk/Liftgate Release Actuator Test",
        "cat": "body",
        "safe": "safe",
        "desc": "Activate the trunk or liftgate release solenoid via BCM actuator command. Verifies the release motor, latch, and BCM output circuit.",
        "pre": ["Key ON", "Vehicle in Park", "Trunk area clear"],
        "sys": ["B1342", "B1596", "trunk release", "liftgate", "trunk won't open"],
        "time": 5,
        "eng": False,
        "mfr": "",
        "steps": [
            {"t": "instruction", "d": "Ensure the trunk/liftgate area is clear and nothing is blocking it from opening."},
            {"t": "actuator_on", "d": "Activate trunk release solenoid via BCM", "act": "TRUNK_RELEASE", "mod": 0x726, "bus": "MS-CAN", "dur": 2.0},
            {"t": "instruction", "d": "Verify the trunk/liftgate unlatched and opened. Listen for the solenoid click."},
            {"t": "instruction", "d": "Close the trunk/liftgate manually and verify it latches securely. If the solenoid clicked but the latch didn't release, the cable or latch mechanism may be binding."},
        ],
    },
    {
        "id": "mirror_adjust_test",
        "name": "Power Mirror Actuator Test",
        "cat": "body",
        "safe": "safe",
        "desc": "Activate power mirror motors (left/right mirror, up/down/left/right adjust) via BCM actuator. Verifies mirror motor operation and BCM outputs.",
        "pre": ["Key ON", "Mirrors not obstructed"],
        "sys": ["B1498", "B1499", "mirror motor", "power mirror", "mirror adjust"],
        "time": 10,
        "eng": False,
        "mfr": "",
        "steps": [
            {"t": "instruction", "d": "Note the current position of both side mirrors for reference."},
            {"t": "actuator_on", "d": "Tilt left mirror DOWN via BCM", "act": "MIRROR_L_DOWN", "mod": 0x726, "bus": "MS-CAN", "dur": 2.0},
            {"t": "actuator_on", "d": "Tilt left mirror UP via BCM", "act": "MIRROR_L_UP", "mod": 0x726, "bus": "MS-CAN", "dur": 2.0},
            {"t": "actuator_on", "d": "Tilt right mirror DOWN via BCM", "act": "MIRROR_R_DOWN", "mod": 0x726, "bus": "MS-CAN", "dur": 2.0},
            {"t": "actuator_on", "d": "Tilt right mirror UP via BCM", "act": "MIRROR_R_UP", "mod": 0x726, "bus": "MS-CAN", "dur": 2.0},
            {"t": "instruction", "d": "Verify both mirrors moved in each direction. If a mirror didn't move, check the mirror motor connector and BCM output fuse."},
        ],
    },
    {
        "id": "horn_circuit_test",
        "name": "Horn Circuit Test",
        "cat": "body",
        "safe": "caution",
        "desc": "Activate the horn relay via BCM actuator command and verify the horn sounds. Tests the relay, horn, and wiring circuit.",
        "pre": ["Key ON", "Warn nearby people before testing"],
        "sys": ["B1342", "B1585", "horn", "horn inoperative", "horn relay"],
        "time": 5,
        "eng": False,
        "mfr": "",
        "steps": [
            {"t": "instruction", "d": "WARNING: The horn will sound loudly. Alert anyone nearby before proceeding."},
            {"t": "actuator_on", "d": "Activate horn relay via BCM", "act": "HORN_RELAY", "mod": 0x726, "bus": "MS-CAN", "dur": 1.0},
            {"t": "instruction", "d": "Verify the horn sounded. If no sound, check the horn fuse, relay, and horn ground connection."},
            {"t": "actuator_off", "d": "Deactivate horn relay", "act": "HORN_RELAY", "mod": 0x726, "bus": "MS-CAN"},
            {"t": "instruction", "d": "If the horn was weak, check for corrosion on the horn ground wire and horn mounting bracket."},
        ],
    },
    {
        "id": "wiper_system_test",
        "name": "Wiper System Actuator Test",
        "cat": "body",
        "safe": "caution",
        "desc": "Activate front and rear wipers at different speeds via BCM actuator commands. Verifies wiper motors, park switches, and BCM output circuits.",
        "pre": ["Key ON", "Windshield clear", "Wiper blades in good condition"],
        "sys": ["B1342", "B1450", "B1451", "wiper", "wipers inoperative", "wiper motor"],
        "time": 10,
        "eng": False,
        "mfr": "",
        "steps": [
            {"t": "instruction", "d": "Ensure windshield is wet or spray washer fluid first to avoid scratching dry glass."},
            {"t": "actuator_on", "d": "Activate front wipers at LOW speed", "act": "WIPER_FRONT_LOW", "mod": 0x726, "bus": "MS-CAN", "dur": 5.0},
            {"t": "instruction", "d": "Verify front wipers operate at low speed with smooth, full sweep and proper park position."},
            {"t": "actuator_on", "d": "Activate front wipers at HIGH speed", "act": "WIPER_FRONT_HIGH", "mod": 0x726, "bus": "MS-CAN", "dur": 5.0},
            {"t": "instruction", "d": "Verify wipers speed increased. Wipers should park correctly when deactivated."},
            {"t": "actuator_off", "d": "Deactivate front wipers", "act": "WIPER_FRONT_LOW", "mod": 0x726, "bus": "MS-CAN"},
        ],
    },
    {
        "id": "interior_light_test",
        "name": "Interior Light Test",
        "cat": "body",
        "safe": "safe",
        "desc": "Activate interior lights (dome, map, footwell) via BCM actuator commands. Verifies lighting circuits, bulbs/LEDs, and BCM outputs.",
        "pre": ["Key ON", "All doors closed"],
        "sys": ["B1342", "B1552", "dome light", "interior lights", "courtesy light"],
        "time": 5,
        "eng": False,
        "mfr": "",
        "steps": [
            {"t": "instruction", "d": "Set the interior light switch to DOOR or OFF position so BCM has control."},
            {"t": "actuator_on", "d": "Activate dome light via BCM", "act": "DOME_LIGHT", "mod": 0x726, "bus": "MS-CAN", "dur": 3.0},
            {"t": "instruction", "d": "Verify the dome light illuminated. Check for dim or flickering operation."},
            {"t": "actuator_off", "d": "Deactivate dome light", "act": "DOME_LIGHT", "mod": 0x726, "bus": "MS-CAN"},
            {"t": "instruction", "d": "If any lights did not illuminate, check the bulbs/LEDs, fuses, and BCM connector for the affected circuit."},
        ],
    },
    {
        "id": "rear_defrost_test",
        "name": "Rear Window Defroster Test",
        "cat": "body",
        "safe": "safe",
        "desc": "Activate the rear window defroster grid via BCM actuator command. Verify the grid heats by touching the glass after a few minutes or using an IR thermometer.",
        "pre": ["Engine running", "Rear window clean and dry"],
        "sys": ["B1342", "B1595", "rear defrost", "rear defroster", "heated rear window"],
        "time": 10,
        "eng": True,
        "mfr": "",
        "steps": [
            {"t": "actuator_on", "d": "Activate rear window defroster relay via BCM", "act": "REAR_DEFROST", "mod": 0x726, "bus": "MS-CAN", "dur": 30.0},
            {"t": "wait", "d": "Wait 30 seconds for grid to warm up", "dur": 30.0},
            {"t": "instruction", "d": "Touch the rear window glass near a grid line — it should feel warm. Or use an IR thermometer to verify the grid lines are hotter than surrounding glass."},
            {"t": "instruction", "d": "Check for cold spots (broken grid lines). Run a finger along each grid line to find breaks. Broken lines can be repaired with conductive paint."},
            {"t": "actuator_off", "d": "Deactivate rear window defroster", "act": "REAR_DEFROST", "mod": 0x726, "bus": "MS-CAN"},
        ],
    },

    # ── NETWORK (4) ──────────────────────────────────────────────────────
    {
        "id": "can_bus_integrity",
        "name": "CAN Bus Integrity Check",
        "cat": "network",
        "safe": "safe",
        "desc": "Read DTCs from multiple modules and check for U-codes indicating lost communication. U-codes point to wiring, connector, or module problems on the CAN bus network.",
        "pre": ["Key ON", "All modules powered"],
        "sys": ["U0100", "U0101", "U0121", "U0140", "U0155", "CAN bus", "lost communication", "network"],
        "time": 10,
        "eng": False,
        "mfr": "",
        "steps": [
            {"t": "read_dtcs", "d": "Read DTCs from PCM (0x7E0)", "s": "pcm_dtcs"},
            {"t": "read_dtcs", "d": "Read DTCs from TCM (0x7E1)", "s": "tcm_dtcs"},
            {"t": "read_dtcs", "d": "Read DTCs from ABS module (0x760)", "s": "abs_dtcs"},
            {"t": "read_dtcs", "d": "Read DTCs from BCM (0x726)", "s": "bcm_dtcs"},
            {"t": "instruction", "d": "Review all DTCs for U-codes (e.g., U0100 = lost comm with ECM, U0121 = lost comm with ABS). U-codes indicate the network path between modules is broken."},
            {"t": "instruction", "d": "If U-codes are present: inspect CAN bus wiring (CAN-H and CAN-L), check termination resistors (should measure 60Ω between CAN-H and CAN-L), and inspect connectors at the affected modules."},
        ],
    },
    {
        "id": "module_response_test",
        "name": "Module Communication Response Test",
        "cat": "network",
        "safe": "safe",
        "desc": "Send UDS Tester Present requests to key modules (PCM, TCM, BCM, ABS) and verify each responds. A non-responding module indicates a communication or power problem.",
        "pre": ["Key ON", "All modules powered"],
        "sys": ["U0100", "U0101", "U0121", "U0140", "no communication", "module offline"],
        "time": 10,
        "eng": False,
        "mfr": "",
        "steps": [
            {"t": "uds_command", "d": "Send Tester Present to PCM (0x7E0) on HS-CAN", "cmd": "3E00", "mod": 0x7E0, "bus": "HS-CAN", "s": "pcm_response"},
            {"t": "uds_command", "d": "Send Tester Present to TCM (0x7E1) on HS-CAN", "cmd": "3E00", "mod": 0x7E1, "bus": "HS-CAN", "s": "tcm_response"},
            {"t": "uds_command", "d": "Send Tester Present to BCM (0x726) on MS-CAN", "cmd": "3E00", "mod": 0x726, "bus": "MS-CAN", "s": "bcm_response"},
            {"t": "uds_command", "d": "Send Tester Present to ABS (0x760) on HS-CAN", "cmd": "3E00", "mod": 0x760, "bus": "HS-CAN", "s": "abs_response"},
            {"t": "instruction", "d": "All modules should respond with a positive response (7E xx). No response means the module is not communicating — check power, ground, and CAN bus connections at that module."},
        ],
    },
    {
        "id": "gateway_comms_test",
        "name": "Gateway Module Communication Test",
        "cat": "network",
        "safe": "safe",
        "desc": "Verify the gateway module correctly passes messages between the HS-CAN and MS-CAN buses. Tests cross-bus communication which is essential for modules on different networks.",
        "pre": ["Key ON", "All modules powered"],
        "sys": ["U0001", "U0002", "U0073", "gateway", "CAN bus", "network bridge"],
        "time": 10,
        "eng": False,
        "mfr": "",
        "steps": [
            {"t": "uds_command", "d": "Send Tester Present to PCM on HS-CAN (verify HS-CAN working)", "cmd": "3E00", "mod": 0x7E0, "bus": "HS-CAN", "s": "hs_can_ok"},
            {"t": "uds_command", "d": "Send Tester Present to BCM on MS-CAN (verify MS-CAN working)", "cmd": "3E00", "mod": 0x726, "bus": "MS-CAN", "s": "ms_can_ok"},
            {"t": "read_did", "d": "Read a DID from a module on the opposite bus to verify gateway routing", "did": 0xF190, "mod": 0x726, "bus": "MS-CAN", "s": "cross_bus_vin"},
            {"t": "instruction", "d": "If HS-CAN modules respond but MS-CAN modules do not (or vice versa), the gateway module may be faulty. Check gateway power, ground, and both CAN bus connections."},
            {"t": "instruction", "d": "Measure CAN bus resistance: 60Ω between CAN-H and CAN-L on each bus. 120Ω indicates a missing termination resistor. Open/short readings indicate wiring damage."},
        ],
    },
    {
        "id": "lost_comms_diagnosis",
        "name": "Lost Communications Diagnosis",
        "cat": "network",
        "safe": "safe",
        "desc": "Systematically identify which modules have lost communication by reading U-codes from all responding modules. Creates a map of what's online vs offline for targeted wiring diagnosis.",
        "pre": ["Key ON", "Communication warning light on or intermittent"],
        "sys": ["U0100", "U0101", "U0121", "U0140", "U0155", "U0164", "lost communication", "no crank"],
        "time": 15,
        "eng": False,
        "mfr": "",
        "steps": [
            {"t": "read_dtcs", "d": "Read all DTCs from a global OBD-II request to capture U-codes from all modules", "s": "all_dtcs"},
            {"t": "instruction", "d": "Filter the DTC list for U-codes only. Each U-code identifies a specific module that has lost communication (e.g., U0100=ECM, U0101=TCM, U0121=ABS, U0140=BCM)."},
            {"t": "instruction", "d": "For each offline module: (1) Check fuse, (2) Check module power and ground with DVOM, (3) Check CAN-H and CAN-L at the module connector, (4) Check for water damage or corrosion."},
            {"t": "uds_command", "d": "Attempt to reach the first suspect module with Tester Present", "cmd": "3E00", "mod": 0x7E0, "bus": "HS-CAN", "s": "module_check"},
            {"t": "instruction", "d": "If a module responds to Tester Present but sets U-codes in other modules, the problem is intermittent — check connector pins and wiring harness for chafing or loose connections."},
        ],
    },

    # ── EXHAUST (4) ──────────────────────────────────────────────────────
    {
        "id": "exhaust_backpressure",
        "name": "Exhaust Backpressure Test",
        "cat": "exhaust",
        "safe": "caution",
        "desc": "Monitor catalyst temperature and RPM under load to detect excessive exhaust backpressure from a plugged catalytic converter or crushed exhaust pipe.",
        "pre": ["Engine at operating temp", "Vehicle on road or dyno"],
        "sys": ["P0420", "P0421", "P0430", "exhaust backpressure", "catalytic converter", "restricted exhaust"],
        "time": 15,
        "eng": True,
        "mfr": "",
        "steps": [
            {"t": "read_pid", "d": "Read baseline catalyst temperature at idle", "pid": "CATALYST_TEMP_B1S1", "s": "cat_temp_idle",
             "c": [("value", "between", [300, 600], "°C", "Normal idle catalyst temp range")]},
            {"t": "read_pid", "d": "Read baseline RPM at idle", "pid": "RPM", "s": "rpm_idle",
             "c": [("value", "between", [600, 900], "RPM", "Normal idle")]},
            {"t": "instruction", "d": "Accelerate to 3000 RPM under load (driving uphill or on dyno) and hold for 30 seconds."},
            {"t": "read_pid", "d": "Read catalyst temperature under load — excessive temp indicates backpressure", "pid": "CATALYST_TEMP_B1S1", "s": "cat_temp_load",
             "c": [("value", "<=", 900, "°C", "Catalyst temp above 900°C under normal load is excessive")]},
            {"t": "read_pid", "d": "Read engine load percentage", "pid": "ENGINE_LOAD", "s": "eng_load",
             "c": [("value", "between", [40, 90], "%", "Moderate to high engine load")]},
            {"t": "instruction", "d": "If catalyst temp is excessively high or the engine feels power-limited, suspect a plugged catalytic converter or restricted exhaust pipe. Perform a vacuum test at the manifold."},
        ],
    },
    {
        "id": "o2_response_test",
        "name": "O2 Sensor Response Rate Test",
        "cat": "exhaust",
        "safe": "caution",
        "desc": "Monitor the upstream O2 sensor switching rate at elevated RPM. A healthy sensor should cycle between rich and lean 6-10 times in 10 seconds. Slow response indicates a lazy sensor.",
        "pre": ["Engine at operating temp", "No DTCs affecting fuel control", "Vehicle at steady RPM"],
        "sys": ["P0133", "P0153", "P0171", "P0172", "O2 sensor", "oxygen sensor", "lazy O2"],
        "time": 10,
        "eng": True,
        "mfr": "",
        "steps": [
            {"t": "instruction", "d": "Bring engine to 2500 RPM and hold steady. Closed-loop fuel control must be active."},
            {"t": "read_pid", "d": "Verify engine is in closed-loop fuel control", "pid": "FUEL_STATUS", "s": "fuel_status"},
            {"t": "monitor_pid", "d": "Monitor upstream O2 sensor voltage for 10 seconds — count the rich/lean cycles", "pid": "O2_B1S1", "dur": 10.0, "s": "o2_cycles",
             "c": [("value", "between", [0.0, 1.0], "V", "O2 voltage should swing between 0.1V (lean) and 0.9V (rich)")]},
            {"t": "read_pid", "d": "Read short-term fuel trim for reference", "pid": "SHORT_FUEL_TRIM_1", "s": "stft",
             "c": [("value", "between", [-10, 10], "%", "STFT should be actively hunting around 0%")]},
            {"t": "instruction", "d": "Count the number of full rich-lean-rich cycles in the 10-second capture. 6-10 cycles is normal. Fewer than 4 cycles indicates a lazy/slow-response O2 sensor that should be replaced."},
        ],
    },
    {
        "id": "lambda_sensor_test",
        "name": "Wideband Lambda Sensor Test",
        "cat": "exhaust",
        "safe": "caution",
        "desc": "Read the wideband lambda value from the PCM DID. At steady cruise, lambda should be very close to 1.0 (stoichiometric). Values outside 0.97-1.03 indicate a fueling problem.",
        "pre": ["Engine at operating temp", "Vehicle at steady cruise", "Closed-loop fuel control active"],
        "sys": ["P0130", "P2270", "P2271", "lambda", "wideband O2", "air-fuel ratio"],
        "time": 10,
        "eng": True,
        "mfr": "",
        "steps": [
            {"t": "instruction", "d": "Drive at a steady 50-70 km/h in top gear. Ensure closed-loop fuel control is active."},
            {"t": "read_did", "d": "Read wideband lambda value from PCM", "did": 0xDD40, "mod": 0x7E0, "bus": "HS-CAN", "s": "lambda_val",
             "c": [("value", "between", [0.97, 1.03], "λ", "Lambda should be 0.97-1.03 at steady cruise (stoichiometric)")]},
            {"t": "read_pid", "d": "Read long-term fuel trim for comparison", "pid": "LONG_FUEL_TRIM_1", "s": "ltft",
             "c": [("value", "between", [-10, 10], "%", "LTFT should confirm fueling is within tolerance")]},
            {"t": "read_pid", "d": "Read short-term fuel trim", "pid": "SHORT_FUEL_TRIM_1", "s": "stft",
             "c": [("value", "between", [-5, 5], "%", "STFT should be close to 0% at steady state")]},
            {"t": "instruction", "d": "Lambda >1.03 indicates lean condition (vacuum leak, low fuel pressure). Lambda <0.97 indicates rich condition (leaking injector, high fuel pressure, faulty sensor)."},
        ],
    },
    {
        "id": "dpf_pressure_test",
        "name": "DPF Differential Pressure Test",
        "cat": "exhaust",
        "safe": "caution",
        "desc": "Read the Diesel Particulate Filter (DPF) differential pressure DID from the diesel PCM. High pressure indicates a plugged filter requiring regeneration or replacement.",
        "pre": ["Diesel engine at operating temp", "Engine running"],
        "sys": ["P2002", "P2003", "P244A", "P2463", "DPF", "diesel particulate filter", "regen"],
        "time": 10,
        "eng": True,
        "mfr": "",
        "steps": [
            {"t": "read_did", "d": "Read DPF differential pressure from diesel PCM", "did": 0xDD41, "mod": 0x7E0, "bus": "HS-CAN", "s": "dpf_press",
             "c": [("value", "<=", 15, "kPa", "DPF differential pressure should be <10 kPa at idle; above 15 kPa indicates plugging")]},
            {"t": "read_pid", "d": "Read RPM to confirm idle condition", "pid": "RPM", "s": "rpm_idle",
             "c": [("value", "between", [600, 900], "RPM", "Engine should be at idle")]},
            {"t": "read_did", "d": "Read DPF soot load percentage if available", "did": 0xDD42, "mod": 0x7E0, "bus": "HS-CAN", "s": "soot_load"},
            {"t": "instruction", "d": "If DPF pressure is high (>15 kPa at idle): attempt a forced regeneration if soot load is below 90%. If above 90% or regen fails, the DPF may need cleaning or replacement."},
            {"t": "instruction", "d": "Check exhaust backpressure sensor wiring and DPF pressure sensor tubes for blockage by soot. A blocked sensor tube will give false high readings."},
        ],
    },

    # ── COOLING (4) ──────────────────────────────────────────────────────
    {
        "id": "water_pump_test",
        "name": "Water Pump Flow Test",
        "cat": "cooling",
        "safe": "caution",
        "desc": "Monitor coolant temperature during engine warmup to verify the water pump is circulating coolant properly. Erratic temp changes or unusually slow warmup indicate pump issues.",
        "pre": ["Engine cold start", "Radiator cap secure", "Coolant level OK"],
        "sys": ["P0117", "P0118", "P0125", "water pump", "coolant", "overheating", "slow warmup"],
        "time": 20,
        "eng": True,
        "mfr": "",
        "steps": [
            {"t": "read_pid", "d": "Read coolant temperature at cold start", "pid": "COOLANT_TEMP", "s": "ect_cold",
             "c": [("value", "<", 50, "°C", "Engine should be cold — near ambient temperature")]},
            {"t": "instruction", "d": "Start the engine and let it idle. Do not drive. Monitor coolant temperature for steady rise."},
            {"t": "monitor_pid", "d": "Monitor coolant temperature during warmup — should rise steadily without sudden jumps", "pid": "COOLANT_TEMP", "dur": 120.0, "s": "warmup_curve",
             "c": [("value", "between", [20, 110], "°C", "Temperature should rise smoothly during warmup")]},
            {"t": "read_pid", "d": "Read coolant temp after warmup period", "pid": "COOLANT_TEMP", "s": "ect_warm",
             "c": [("value", "between", [75, 105], "°C", "Should reach operating temp within 5-10 minutes at idle")]},
            {"t": "instruction", "d": "If temp rises unevenly or spikes before thermostat opens (~90°C), suspect poor water pump circulation. With engine at operating temp, feel upper radiator hose — it should be hot and firm with pressure once thermostat opens."},
        ],
    },
    {
        "id": "radiator_fan_relay",
        "name": "Radiator Fan Relay Test",
        "cat": "cooling",
        "safe": "caution",
        "desc": "Activate the radiator cooling fan relay via PCM actuator and verify the fan runs. Tests the relay, fan motor, and PCM output circuit.",
        "pre": ["Engine running", "Key ON", "Fan area clear of debris and fingers"],
        "sys": ["P0480", "P0481", "P0691", "P0692", "cooling fan", "fan relay", "overheating"],
        "time": 10,
        "eng": True,
        "mfr": "",
        "steps": [
            {"t": "instruction", "d": "WARNING: Keep hands, clothing, and tools clear of the cooling fan area. The fan will start suddenly."},
            {"t": "read_pid", "d": "Read coolant temperature for reference", "pid": "COOLANT_TEMP", "s": "ect_before_fan",
             "c": [("value", "between", [60, 110], "°C", "Engine should be at or near operating temp")]},
            {"t": "actuator_on", "d": "Activate radiator fan relay via PCM", "act": "COOLING_FAN_RELAY", "mod": 0x7E0, "dur": 10.0},
            {"t": "instruction", "d": "Verify the radiator fan is spinning. Listen for motor operation. Check for proper speed — a sluggish fan may indicate a failing motor."},
            {"t": "actuator_off", "d": "Deactivate radiator fan relay", "act": "COOLING_FAN_RELAY", "mod": 0x7E0},
            {"t": "instruction", "d": "If fan did not run: check the fan relay, fan motor connector, fan motor ground, and the fuse. A relay that clicks but the fan doesn't spin indicates a motor or wiring fault."},
        ],
    },
    {
        "id": "coolant_level_sensor",
        "name": "Coolant Level Sensor Test",
        "cat": "cooling",
        "safe": "safe",
        "desc": "Read the coolant level sensor DID from the PCM or BCM. Verify the sensor reads normal with proper coolant level. A faulty sensor can mask low coolant conditions.",
        "pre": ["Key ON", "Engine cold preferred", "Vehicle on level ground"],
        "sys": ["P2560", "P2561", "coolant level", "low coolant", "coolant warning"],
        "time": 5,
        "eng": False,
        "mfr": "",
        "steps": [
            {"t": "read_did", "d": "Read coolant level sensor from PCM", "did": 0xDD30, "mod": 0x7E0, "bus": "HS-CAN", "s": "coolant_level",
             "c": [("value", "==", 1, "", "1 = Normal/OK, 0 = Low")]},
            {"t": "instruction", "d": "Visually check the coolant overflow reservoir — level should be between MIN and MAX marks."},
            {"t": "instruction", "d": "If sensor reads LOW but reservoir is full, the sensor or its wiring is faulty. If sensor reads OK but reservoir is empty, the sensor may be stuck."},
            {"t": "instruction", "d": "Check for coolant leaks if the level is low: inspect radiator, hoses, water pump weep hole, heater core, and head gasket (look for milky oil or white exhaust smoke)."},
        ],
    },
    {
        "id": "head_gasket_test",
        "name": "Head Gasket Integrity Test",
        "cat": "cooling",
        "safe": "caution",
        "desc": "Monitor coolant temperature after full warmup and check for unusual temperature spikes. Also monitor fuel trims for signs of coolant being burned in the combustion chambers.",
        "pre": ["Engine at full operating temp", "Coolant level topped off", "No external leaks visible"],
        "sys": ["P0117", "P0118", "P0300", "head gasket", "overheating", "coolant loss", "white smoke"],
        "time": 20,
        "eng": True,
        "mfr": "",
        "steps": [
            {"t": "read_pid", "d": "Read coolant temperature — should be at stable operating temp", "pid": "COOLANT_TEMP", "s": "ect_stable",
             "c": [("value", "between", [85, 105], "°C", "Should be at normal operating temperature")]},
            {"t": "monitor_pid", "d": "Monitor coolant temp for 60 seconds — look for unexplained temperature spikes", "pid": "COOLANT_TEMP", "dur": 60.0, "s": "ect_monitor",
             "c": [("value", "<=", 110, "°C", "Temperature should remain stable; spikes suggest combustion gas entering coolant")]},
            {"t": "read_pid", "d": "Read long-term fuel trim — positive shift indicates lean from coolant burning", "pid": "LONG_FUEL_TRIM_1", "s": "ltft_check",
             "c": [("value", "between", [-15, 15], "%", "Large positive LTFT may indicate coolant entering combustion chamber")]},
            {"t": "instruction", "d": "Check for white sweet-smelling exhaust smoke (coolant burning). Check oil cap for milky residue (coolant in oil). Check coolant reservoir for bubbles with engine running (combustion gas in coolant)."},
            {"t": "instruction", "d": "For definitive diagnosis, perform a cooling system pressure test and a combustion leak test (block test) using chemical test fluid that changes color in the presence of exhaust gases."},
        ],
    },

    # ── STEERING (4) ─────────────────────────────────────────────────────
    {
        "id": "eps_torque_test",
        "name": "Electric Power Steering Torque Test",
        "cat": "steering",
        "safe": "caution",
        "desc": "Read EPS motor torque output DID while turning the steering wheel lock to lock. Verify the assist level varies with input torque and speed.",
        "pre": ["Engine running", "Vehicle stationary or at low speed", "Tires on ground"],
        "sys": ["C0545", "C0550", "C0460", "EPS", "electric power steering", "heavy steering"],
        "time": 10,
        "eng": True,
        "mfr": "",
        "steps": [
            {"t": "read_did", "d": "Read EPS motor torque at rest (wheels straight)", "did": 0xDD50, "mod": 0x730, "bus": "HS-CAN", "s": "eps_torque_rest",
             "c": [("value", "between", [-5, 5], "Nm", "EPS torque should be near zero with wheel centered")]},
            {"t": "instruction", "d": "Slowly turn the steering wheel to full left lock. The EPS motor should assist — the wheel should turn easily."},
            {"t": "read_did", "d": "Read EPS motor torque at full left lock", "did": 0xDD50, "mod": 0x730, "bus": "HS-CAN", "s": "eps_torque_left"},
            {"t": "instruction", "d": "Turn the steering wheel to full right lock. Verify equal assist in both directions."},
            {"t": "read_did", "d": "Read EPS motor torque at full right lock", "did": 0xDD50, "mod": 0x730, "bus": "HS-CAN", "s": "eps_torque_right"},
            {"t": "instruction", "d": "Compare left and right torque readings — they should be similar in magnitude. A large difference indicates an EPS motor or sensor problem on one side."},
        ],
    },
    {
        "id": "steering_angle_sensor",
        "name": "Steering Angle Sensor Calibration Check",
        "cat": "steering",
        "safe": "safe",
        "desc": "Read the steering angle sensor (SAS) DID from the SAS module. Turn the wheel from center to lock and verify a range of approximately 0° to 540° (1.5 turns lock to lock).",
        "pre": ["Key ON", "Wheels straight ahead", "Vehicle stationary"],
        "sys": ["C0455", "C0460", "U0126", "steering angle", "SAS", "stability control"],
        "time": 10,
        "eng": False,
        "mfr": "",
        "steps": [
            {"t": "instruction", "d": "Center the steering wheel with wheels pointing straight ahead. The SAS should read near 0°."},
            {"t": "read_did", "d": "Read steering angle sensor at center position", "did": 0xDD51, "mod": 0x730, "bus": "HS-CAN", "s": "sas_center",
             "c": [("value", "between", [-10, 10], "°", "Steering angle should be near 0° with wheel centered")]},
            {"t": "instruction", "d": "Turn the steering wheel slowly to full left lock. The angle should increase smoothly."},
            {"t": "read_did", "d": "Read steering angle sensor at full left lock", "did": 0xDD51, "mod": 0x730, "bus": "HS-CAN", "s": "sas_left",
             "c": [("value", "between", [400, 600], "°", "Full lock is typically 450-540° depending on vehicle")]},
            {"t": "instruction", "d": "Turn the steering wheel to full right lock. Angle should be negative of left."},
            {"t": "read_did", "d": "Read steering angle sensor at full right lock", "did": 0xDD51, "mod": 0x730, "bus": "HS-CAN", "s": "sas_right",
             "c": [("value", "between", [-600, -400], "°", "Should be approximately negative of left lock reading")]},
        ],
    },
    {
        "id": "power_steering_pressure",
        "name": "Power Steering Pressure Test",
        "cat": "steering",
        "safe": "caution",
        "desc": "Read power steering pressure DID on vehicles with hydraulic power steering. Turning the wheel at idle should produce a significant pressure rise. Low pressure indicates a pump or valve issue.",
        "pre": ["Engine running at idle", "Power steering fluid level OK", "Vehicle stationary"],
        "sys": ["C0460", "P0551", "power steering", "PS pressure", "hard steering", "hydraulic"],
        "time": 10,
        "eng": True,
        "mfr": "",
        "steps": [
            {"t": "read_did", "d": "Read PS pressure with wheel centered (no load)", "did": 0xDD52, "mod": 0x7E0, "bus": "HS-CAN", "s": "ps_press_center",
             "c": [("value", "between", [100, 500], "kPa", "Unloaded PS pressure at idle")]},
            {"t": "instruction", "d": "Turn the steering wheel slowly to full left lock and hold."},
            {"t": "read_did", "d": "Read PS pressure at full lock — should be significantly higher", "did": 0xDD52, "mod": 0x7E0, "bus": "HS-CAN", "s": "ps_press_lock",
             "c": [("value", ">=", 3000, "kPa", "PS pressure at full lock should be high — relief valve operates around 8000-12000 kPa")]},
            {"t": "instruction", "d": "Do NOT hold at full lock for more than 5 seconds — this can damage the PS pump."},
            {"t": "read_pid", "d": "Read RPM — engine should maintain idle with steering loaded", "pid": "RPM", "s": "rpm_at_lock",
             "c": [("value", ">=", 500, "RPM", "Engine should not stall under PS load")]},
            {"t": "instruction", "d": "If pressure does not rise at full lock, suspect a weak PS pump or internal leak in the steering gear/rack. Check PS fluid for contamination (burnt smell, dark color)."},
        ],
    },
    {
        "id": "steering_wheel_position",
        "name": "Steering Wheel Position Zero Check",
        "cat": "steering",
        "safe": "safe",
        "desc": "Read the steering angle sensor at rest with wheels pointed straight ahead. Verify the sensor reads within ±5° of center. An off-center reading affects stability control.",
        "pre": ["Key ON", "Wheels pointed straight ahead", "Vehicle on level ground"],
        "sys": ["C0455", "C0460", "U0126", "steering angle", "SAS calibration", "ESC"],
        "time": 5,
        "eng": False,
        "mfr": "",
        "steps": [
            {"t": "instruction", "d": "Ensure wheels are pointed straight ahead. The steering wheel spoke should be centered and level."},
            {"t": "read_did", "d": "Read steering angle sensor position", "did": 0xDD51, "mod": 0x730, "bus": "HS-CAN", "s": "sas_zero",
             "c": [("value", "between", [-5, 5], "°", "Should be within ±5° of center (0°)")]},
            {"t": "instruction", "d": "If the reading is more than ±5° off center with wheels straight, the SAS needs calibration. This is typically done after alignment, tie rod replacement, or steering column work."},
            {"t": "instruction", "d": "Most vehicles require a SAS calibration/zero-point reset via scan tool after alignment. An uncalibrated SAS will affect stability control, lane-keep assist, and other ADAS features."},
        ],
    },

    # ── SAFETY (4) ───────────────────────────────────────────────────────
    {
        "id": "airbag_circuit_test",
        "name": "Airbag/SRS Circuit Test",
        "cat": "safety",
        "safe": "warning",
        "desc": "Read DTCs from the airbag/SRS module to check for open or short circuit codes in the airbag deployment loops. WARNING: Never probe airbag connectors with test equipment.",
        "pre": ["Key ON", "SRS warning light on or DTCs present", "DO NOT unplug any SRS connectors"],
        "sys": ["B0100", "B0101", "B0102", "B0103", "airbag", "SRS", "airbag light"],
        "time": 10,
        "eng": False,
        "mfr": "",
        "steps": [
            {"t": "instruction", "d": "WARNING: NEVER probe, disconnect, or test airbag connectors with a DVOM or test light. Accidental deployment can cause serious injury. Diagnosis is DTC-based only."},
            {"t": "read_dtcs", "d": "Read DTCs from SRS/airbag module", "s": "srs_dtcs"},
            {"t": "instruction", "d": "Review DTCs: B01xx = driver front airbag circuit, B02xx = passenger front, B03xx = side airbag, B04xx = curtain airbag. Each DTC identifies the circuit and fault type (open, short to ground, short to B+, resistance out of range)."},
            {"t": "read_did", "d": "Read SRS system readiness status", "did": 0xDD60, "mod": 0x760, "bus": "HS-CAN", "s": "srs_status"},
            {"t": "instruction", "d": "If DTCs indicate open circuits: check the clock spring (steering wheel airbag), seat connectors (side airbags), and wiring harness under seats (often damaged by seat track movement). Clear DTCs after repair and verify SRS light turns off."},
        ],
    },
    {
        "id": "seatbelt_pretensioner",
        "name": "Seatbelt Buckle Detection Test",
        "cat": "safety",
        "safe": "safe",
        "desc": "Read the seatbelt buckle switch DID from the SRS module. Verify the switch correctly detects buckle and unbuckle events for the seatbelt warning chime and pretensioner arming.",
        "pre": ["Key ON", "Driver seated"],
        "sys": ["B0093", "B0095", "seatbelt", "buckle switch", "seatbelt warning"],
        "time": 5,
        "eng": False,
        "mfr": "",
        "steps": [
            {"t": "instruction", "d": "Ensure the driver seatbelt is unbuckled."},
            {"t": "read_did", "d": "Read seatbelt buckle status — should show UNBUCKLED", "did": 0xDD61, "mod": 0x760, "bus": "HS-CAN", "s": "belt_unbuckled",
             "c": [("value", "==", 0, "", "0 = Unbuckled")]},
            {"t": "instruction", "d": "Buckle the driver seatbelt."},
            {"t": "read_did", "d": "Read seatbelt buckle status — should show BUCKLED", "did": 0xDD61, "mod": 0x760, "bus": "HS-CAN", "s": "belt_buckled",
             "c": [("value", "==", 1, "", "1 = Buckled")]},
            {"t": "instruction", "d": "If the switch does not toggle, the buckle switch is faulty. Replace the buckle assembly — do NOT splice wiring on SRS circuits."},
        ],
    },
    {
        "id": "occupant_sensor_test",
        "name": "Occupant Detection Sensor Test",
        "cat": "safety",
        "safe": "safe",
        "desc": "Read the passenger occupant detection DID from the SRS module. Place appropriate weight on the seat and verify the sensor detects an occupant for proper airbag deployment decisions.",
        "pre": ["Key ON", "Passenger seat empty to start"],
        "sys": ["B0081", "B0082", "B0083", "occupant sensor", "OCS", "passenger airbag off"],
        "time": 10,
        "eng": False,
        "mfr": "",
        "steps": [
            {"t": "instruction", "d": "Ensure the passenger seat is completely empty."},
            {"t": "read_did", "d": "Read occupant detection sensor — should show EMPTY", "did": 0xDD62, "mod": 0x760, "bus": "HS-CAN", "s": "seat_empty",
             "c": [("value", "==", 0, "", "0 = Empty/child, passenger airbag should be OFF")]},
            {"t": "instruction", "d": "Place a weight of at least 30 kg (65 lbs) on the passenger seat to simulate an adult occupant. Sit a person in the seat or use a weighted box."},
            {"t": "read_did", "d": "Read occupant detection sensor — should show OCCUPIED", "did": 0xDD62, "mod": 0x760, "bus": "HS-CAN", "s": "seat_occupied",
             "c": [("value", "==", 1, "", "1 = Adult occupant detected, passenger airbag should be ON")]},
            {"t": "instruction", "d": "Check the PASSENGER AIRBAG OFF indicator on the dash. It should illuminate when the seat is empty and turn off when an adult is detected. If not, the OCS sensor mat under the seat cushion may be faulty."},
        ],
    },
    {
        "id": "crash_sensor_test",
        "name": "Crash Sensor Status Test",
        "cat": "safety",
        "safe": "safe",
        "desc": "Read crash sensor status DIDs from the SRS module. All sensors should report a ready/normal status. Faulted sensors will prevent airbag deployment in a crash.",
        "pre": ["Key ON", "SRS system armed"],
        "sys": ["B0100", "B0110", "B0115", "crash sensor", "SRS", "impact sensor"],
        "time": 5,
        "eng": False,
        "mfr": "",
        "steps": [
            {"t": "read_did", "d": "Read front crash sensor status from SRS module", "did": 0xDD63, "mod": 0x760, "bus": "HS-CAN", "s": "front_sensor",
             "c": [("value", "==", 1, "", "1 = Normal/Ready")]},
            {"t": "read_did", "d": "Read side crash sensor status from SRS module", "did": 0xDD64, "mod": 0x760, "bus": "HS-CAN", "s": "side_sensor",
             "c": [("value", "==", 1, "", "1 = Normal/Ready")]},
            {"t": "read_dtcs", "d": "Read SRS DTCs to check for sensor faults", "s": "srs_sensor_dtcs"},
            {"t": "instruction", "d": "All crash sensors should report 'Normal/Ready'. If any sensor reports faulted, check the sensor connector, mounting, and wiring. Crash sensors that have been impacted in a prior collision may need replacement."},
        ],
    },

    # ── FORD-SPECIFIC (8) ────────────────────────────────────────────────
    {
        "id": "ford_pats_test",
        "name": "Ford PATS Key Authentication Test",
        "cat": "safety",
        "safe": "safe",
        "desc": "Read Ford Passive Anti-Theft System (PATS) status and key count from the PCM. Verify the current key is recognized and check how many keys are programmed.",
        "pre": ["Key in ignition", "Key ON"],
        "sys": ["B1213", "B1232", "B1600", "B1601", "PATS", "anti-theft", "no start", "theft light"],
        "time": 5,
        "eng": False,
        "mfr": "ford",
        "steps": [
            {"t": "instruction", "d": "Insert the key and turn to ON (do not crank). Wait for the PATS/theft light on the dash to go out (should extinguish within 3 seconds if the key is valid)."},
            {"t": "read_did", "d": "Read PATS key authentication status from PCM", "did": 0xDD70, "mod": 0x7E0, "bus": "HS-CAN", "s": "pats_status",
             "c": [("value", "==", 1, "", "1 = Key authenticated successfully")]},
            {"t": "read_did", "d": "Read number of PATS keys programmed in PCM", "did": 0xDD71, "mod": 0x7E0, "bus": "HS-CAN", "s": "key_count",
             "c": [("value", ">=", 2, "keys", "At least 2 keys should be programmed for self-programming capability")]},
            {"t": "instruction", "d": "If PATS status shows NOT authenticated: the key's transponder may be faulty, wrong frequency, or not programmed to this vehicle. Ford requires 2 valid keys to program additional keys without a scan tool; with only 1 key, dealer-level tool is required."},
        ],
    },
    {
        "id": "ford_throttle_relearn",
        "name": "Ford Electronic Throttle Body Idle Relearn",
        "cat": "fuel",
        "safe": "safe",
        "desc": "Perform a Ford electronic throttle body idle relearn procedure. Required after battery disconnect, throttle body cleaning, or throttle body replacement. Read RPM and throttle position to verify.",
        "pre": ["Engine off", "Key available", "No DTCs present", "Battery fully charged"],
        "sys": ["P0506", "P0507", "P2110", "P2112", "throttle body", "idle relearn", "high idle", "surging"],
        "time": 10,
        "eng": False,
        "mfr": "ford",
        "steps": [
            {"t": "instruction", "d": "Turn ignition to OFF. Wait 10 seconds."},
            {"t": "instruction", "d": "Turn ignition to ON (do NOT start engine). Wait 3-5 seconds for throttle body to cycle."},
            {"t": "instruction", "d": "Turn ignition to OFF. Wait 10 seconds. Turn ignition to ON again. Wait 3-5 seconds."},
            {"t": "instruction", "d": "Start the engine. Do NOT touch the gas pedal. Let it idle for at least 1 minute."},
            {"t": "read_pid", "d": "Read RPM — should settle to normal idle after relearn", "pid": "RPM", "s": "rpm_relearn",
             "c": [("value", "between", [600, 850], "RPM", "Normal Ford idle is typically 650-750 RPM")]},
            {"t": "read_pid", "d": "Read throttle position — should be at closed throttle", "pid": "THROTTLE_POS", "s": "tp_relearn",
             "c": [("value", "between", [10, 22], "%", "Closed throttle should read 15-20%")]},
            {"t": "instruction", "d": "Turn on AC and headlights to verify idle compensation. RPM should bump up 50-100 RPM to compensate for electrical load."},
        ],
    },
    {
        "id": "ford_ac_clutch_test",
        "name": "Ford AC Compressor Clutch Test",
        "cat": "hvac",
        "safe": "caution",
        "desc": "Ford-specific AC clutch activation via PCM actuator. Monitor RPM drop and AC pressure DID to verify compressor engagement and refrigerant charge.",
        "pre": ["Engine running at idle", "Engine at operating temp", "AC system charged"],
        "sys": ["B1262", "P0530", "P0532", "P0533", "B1261", "AC clutch", "no cold air"],
        "time": 10,
        "eng": True,
        "mfr": "ford",
        "steps": [
            {"t": "read_pid", "d": "Read RPM baseline before AC activation", "pid": "RPM", "s": "rpm_pre_ac",
             "c": [("value", "between", [600, 900], "RPM", "Normal idle")]},
            {"t": "actuator_on", "d": "Activate AC compressor clutch via Ford PCM", "act": "AC_COMPRESSOR_CLUTCH", "mod": 0x7E0, "dur": 10.0},
            {"t": "read_pid", "d": "Read RPM with AC engaged — Ford idle-up should compensate", "pid": "RPM", "s": "rpm_with_ac",
             "c": [("value", "between", [650, 1100], "RPM", "Idle should increase with AC load")]},
            {"t": "read_did", "d": "Read AC high-side pressure DID from Ford PCM", "did": 0xDD72, "mod": 0x7E0, "bus": "HS-CAN", "s": "ac_high_press",
             "c": [("value", "between", [800, 2200], "kPa", "AC high-side pressure should be 800-2200 kPa depending on ambient temp")]},
            {"t": "instruction", "d": "Verify the AC clutch hub is spinning with the pulley (visual check at the compressor). Air gap should be 0.4-0.8mm."},
            {"t": "actuator_off", "d": "Deactivate AC compressor clutch", "act": "AC_COMPRESSOR_CLUTCH", "mod": 0x7E0},
        ],
    },
    {
        "id": "ford_wiper_test",
        "name": "Ford GEM Wiper Control Test",
        "cat": "body",
        "safe": "caution",
        "desc": "Activate front wipers at all speeds via the Ford GEM module (0x726, MS-CAN). Verifies GEM output, wiper motor, and park switch operation.",
        "pre": ["Key ON", "Windshield wet or use washer fluid"],
        "sys": ["B1450", "B1451", "B1461", "wiper", "wipers inoperative"],
        "time": 10,
        "eng": False,
        "mfr": "ford",
        "steps": [
            {"t": "instruction", "d": "Spray windshield with washer fluid or wet the glass to prevent scratching."},
            {"t": "actuator_on", "d": "Activate front wipers LOW speed via Ford GEM", "act": "WIPER_FRONT_LOW", "mod": 0x726, "bus": "MS-CAN", "dur": 5.0},
            {"t": "instruction", "d": "Verify wipers operate at low speed with consistent sweep."},
            {"t": "actuator_on", "d": "Activate front wipers HIGH speed via Ford GEM", "act": "WIPER_FRONT_HIGH", "mod": 0x726, "bus": "MS-CAN", "dur": 5.0},
            {"t": "instruction", "d": "Verify wipers increased to high speed. Wipers should park at bottom of windshield when deactivated."},
            {"t": "actuator_off", "d": "Deactivate front wipers", "act": "WIPER_FRONT_LOW", "mod": 0x726, "bus": "MS-CAN"},
        ],
    },
    {
        "id": "ford_pcm_mil_test",
        "name": "Ford MIL Lamp Test",
        "cat": "electrical",
        "safe": "safe",
        "desc": "Activate the Malfunction Indicator Lamp (Check Engine Light) via Ford PCM actuator to verify the bulb and circuit. The MIL should illuminate on command.",
        "pre": ["Key ON", "Engine off"],
        "sys": ["P0650", "MIL", "check engine", "MIL lamp test"],
        "time": 5,
        "eng": False,
        "mfr": "ford",
        "steps": [
            {"t": "instruction", "d": "Look at the instrument cluster. The MIL (Check Engine) light should be off with key ON engine off (after initial bulb check)."},
            {"t": "actuator_on", "d": "Activate MIL lamp via Ford PCM", "act": "MIL_LAMP", "mod": 0x7E0, "dur": 5.0},
            {"t": "instruction", "d": "Verify the MIL (Check Engine) light illuminated on the instrument cluster dashboard."},
            {"t": "actuator_off", "d": "Deactivate MIL lamp", "act": "MIL_LAMP", "mod": 0x7E0},
            {"t": "instruction", "d": "Verify the MIL turned off. If it did not illuminate during the test, check the bulb and the circuit from PCM to instrument cluster."},
        ],
    },
    {
        "id": "ford_ipc_gauge_sweep",
        "name": "Ford IPC Gauge Sweep Test",
        "cat": "body",
        "safe": "safe",
        "desc": "Perform a Ford Instrument Panel Cluster gauge sweep test. Commands the IPC to sweep all gauges (speedometer, tachometer, fuel, temperature) through their full range to verify gauge operation.",
        "pre": ["Key ON", "Engine off"],
        "sys": ["B1200", "B1201", "gauge", "instrument cluster", "IPC", "gauges not working"],
        "time": 10,
        "eng": False,
        "mfr": "ford",
        "steps": [
            {"t": "instruction", "d": "Watch the instrument cluster gauges during the test. All gauges should sweep from minimum to maximum and back."},
            {"t": "uds_command", "d": "Send gauge sweep test command to Ford IPC module on MS-CAN", "cmd": "3101FF00", "mod": 0x720, "bus": "MS-CAN", "s": "gauge_sweep"},
            {"t": "wait", "d": "Wait for gauge sweep to complete", "dur": 10.0},
            {"t": "instruction", "d": "Verify all gauges swept through full range: speedometer (0-max), tachometer (0-max), fuel gauge (E-F), temperature gauge (C-H). All warning lights should also flash briefly."},
            {"t": "instruction", "d": "If any gauge did not sweep, that gauge stepper motor may be faulty. IPC stepper motor replacement is a common repair on Ford vehicles."},
        ],
    },
    {
        "id": "ford_gem_horn_test",
        "name": "Ford GEM Horn Test",
        "cat": "body",
        "safe": "caution",
        "desc": "Activate the horn via the Ford GEM module (0x726, MS-CAN). Tests the GEM output, horn relay, and horn assembly.",
        "pre": ["Key ON", "Warn nearby people"],
        "sys": ["B1585", "horn", "horn inoperative", "horn relay"],
        "time": 5,
        "eng": False,
        "mfr": "ford",
        "steps": [
            {"t": "instruction", "d": "WARNING: The horn will sound. Alert anyone in the area."},
            {"t": "actuator_on", "d": "Activate horn via Ford GEM module on MS-CAN", "act": "HORN_RELAY", "mod": 0x726, "bus": "MS-CAN", "dur": 1.0},
            {"t": "instruction", "d": "Verify the horn sounded. If not, check horn fuse in the battery junction box (BJB), horn relay, and horn ground."},
            {"t": "actuator_off", "d": "Deactivate horn", "act": "HORN_RELAY", "mod": 0x726, "bus": "MS-CAN"},
        ],
    },
    {
        "id": "ford_fuel_pump_relay",
        "name": "Ford Fuel Pump Relay Test",
        "cat": "fuel",
        "safe": "caution",
        "desc": "Activate the fuel pump relay via Ford PCM actuator and monitor fuel rail pressure. Verifies the PCM output, fuel pump relay, fuel pump motor, and fuel system pressure.",
        "pre": ["Key ON", "Engine off", "Fuel tank not empty"],
        "sys": ["P0230", "P0231", "P0232", "fuel pump", "fuel pump relay", "no fuel pressure"],
        "time": 10,
        "eng": False,
        "mfr": "ford",
        "steps": [
            {"t": "instruction", "d": "Listen near the fuel tank for the fuel pump to prime (2-second run) when key is turned ON."},
            {"t": "actuator_on", "d": "Activate fuel pump relay via Ford PCM", "act": "FUEL_PUMP_RELAY", "mod": 0x7E0, "dur": 10.0},
            {"t": "instruction", "d": "Listen for the fuel pump running continuously. You should hear a humming from the fuel tank area."},
            {"t": "read_pid", "d": "Read fuel rail pressure — should build to specification", "pid": "FUEL_RAIL_PRESSURE_GAUGE", "s": "frp_pump_test",
             "c": [("value", "between", [250, 450], "kPa", "Port injection fuel pressure should be 250-400 kPa with pump running")]},
            {"t": "actuator_off", "d": "Deactivate fuel pump relay", "act": "FUEL_PUMP_RELAY", "mod": 0x7E0},
            {"t": "instruction", "d": "After deactivation, fuel pressure should hold for at least 5 minutes. A rapid drop indicates a leaking injector, check valve, or fuel pressure regulator."},
        ],
    },

    # ── GM-SPECIFIC (4) ──────────────────────────────────────────────────
    {
        "id": "gm_tpms_relearn",
        "name": "GM TPMS Sensor Relearn Procedure",
        "cat": "safety",
        "safe": "safe",
        "desc": "GM TPMS sensor relearn procedure using the deflation method. Required after tire rotation, sensor replacement, or if TPMS light is on. Programs sensor IDs to correct wheel positions.",
        "pre": ["All tires at correct pressure", "Vehicle stationary", "Key ON"],
        "sys": ["C0750", "C0755", "C0760", "TPMS", "tire pressure", "TPMS sensor"],
        "time": 20,
        "eng": False,
        "mfr": "gm",
        "steps": [
            {"t": "instruction", "d": "Set all four tires to the placard pressure. GM TPMS relearn requires the system to recognize each sensor in a specific order: LF, RF, RR, LR."},
            {"t": "instruction", "d": "Turn ignition to ON. Press and hold the TPMS reset button (or use the DIC menu) until the horn honks twice. The system is now in learn mode."},
            {"t": "instruction", "d": "Starting with the LEFT FRONT tire: deflate the tire by 8+ psi, then reinflate. The horn will honk once when the sensor is learned. Move to the RIGHT FRONT tire and repeat."},
            {"t": "instruction", "d": "Continue with the RIGHT REAR tire, then LEFT REAR tire. After all four sensors are learned, the horn will honk twice to confirm completion."},
            {"t": "read_did", "d": "Read TPMS sensor status from BCM to verify all four sensors learned", "did": 0xDD80, "mod": 0x741, "bus": "HS-CAN", "s": "tpms_status"},
            {"t": "instruction", "d": "Reinflate all tires to the correct placard pressure. Drive the vehicle for 2-3 minutes to verify the TPMS light turns off."},
        ],
    },
    {
        "id": "gm_stabilitrak_test",
        "name": "GM StabiliTrak System Test",
        "cat": "brakes",
        "safe": "safe",
        "desc": "Read GM StabiliTrak/ESC system status including yaw rate sensor and steering angle sensor calibration. Verify the stability control system is fully operational.",
        "pre": ["Key ON", "Engine running", "Vehicle stationary"],
        "sys": ["C0131", "C0136", "C0196", "C0710", "StabiliTrak", "ESC", "stability control", "traction control"],
        "time": 10,
        "eng": True,
        "mfr": "gm",
        "steps": [
            {"t": "read_did", "d": "Read yaw rate sensor status from EBCM", "did": 0xDD81, "mod": 0x760, "bus": "HS-CAN", "s": "yaw_rate",
             "c": [("value", "between", [-3, 3], "°/s", "Yaw rate should be near zero with vehicle stationary")]},
            {"t": "read_did", "d": "Read lateral acceleration sensor from EBCM", "did": 0xDD82, "mod": 0x760, "bus": "HS-CAN", "s": "lat_accel",
             "c": [("value", "between", [-1, 1], "g", "Lateral acceleration should be near zero when stationary on level ground")]},
            {"t": "read_did", "d": "Read steering angle sensor from EBCM", "did": 0xDD83, "mod": 0x760, "bus": "HS-CAN", "s": "steer_angle",
             "c": [("value", "between", [-10, 10], "°", "Steering angle should be near center")]},
            {"t": "read_dtcs", "d": "Read DTCs from EBCM for StabiliTrak-related codes", "s": "stabilitrak_dtcs"},
            {"t": "instruction", "d": "If the StabiliTrak or Traction Control lights are on, check for C-codes. Common causes: faulty wheel speed sensor (C0035-C0050), yaw rate sensor (C0131), or steering angle sensor (C0455). Sensor calibration may be needed after alignment."},
        ],
    },
    {
        "id": "gm_afm_test",
        "name": "GM Active Fuel Management (AFM/DOD) Test",
        "cat": "fuel",
        "safe": "caution",
        "desc": "Monitor GM Active Fuel Management cylinder deactivation. At light load cruise, AFM should engage (V8→V4 or V6→V3). Verify smooth transition by monitoring RPM stability and AFM status.",
        "pre": ["Engine at operating temp", "Vehicle at steady cruise", "V8 or V6 engine with AFM"],
        "sys": ["P0300", "P06DD", "P06DE", "AFM", "DOD", "cylinder deactivation", "lifter tick"],
        "time": 15,
        "eng": True,
        "mfr": "gm",
        "steps": [
            {"t": "instruction", "d": "Drive at a steady 50-70 km/h on a flat road in top gear with light throttle. AFM should engage under light load conditions."},
            {"t": "read_did", "d": "Read AFM cylinder deactivation status from PCM", "did": 0xDD84, "mod": 0x7E0, "bus": "HS-CAN", "s": "afm_status"},
            {"t": "read_pid", "d": "Read engine RPM — should be stable during AFM operation", "pid": "RPM", "s": "rpm_afm",
             "c": [("value", "between", [1000, 2200], "RPM", "RPM should remain stable during AFM, no hunting or surging")]},
            {"t": "read_pid", "d": "Read engine load — AFM engages at light to moderate load", "pid": "ENGINE_LOAD", "s": "load_afm",
             "c": [("value", "between", [15, 50], "%", "AFM typically engages at 15-50% load")]},
            {"t": "monitor_pid", "d": "Monitor RPM for 10 seconds to verify stability in AFM mode", "pid": "RPM", "dur": 10.0, "s": "rpm_stability"},
            {"t": "instruction", "d": "If AFM does not engage or causes roughness, check for AFM lifter failures (common on 5.3L and 6.2L). A persistent P06DD/P06DE indicates a stuck deactivation solenoid or collapsed lifter."},
        ],
    },
    {
        "id": "gm_onstar_comms",
        "name": "GM OnStar Communication Test",
        "cat": "network",
        "safe": "safe",
        "desc": "Read the OnStar module communication status DID to verify the cellular connection and module connectivity. Tests whether the OnStar module is communicating on the vehicle network.",
        "pre": ["Key ON", "OnStar subscription active or inactive"],
        "sys": ["U0184", "B3055", "OnStar", "telematics", "cellular", "no OnStar"],
        "time": 5,
        "eng": False,
        "mfr": "gm",
        "steps": [
            {"t": "uds_command", "d": "Send Tester Present to OnStar/telematics module", "cmd": "3E00", "mod": 0x7C4, "bus": "HS-CAN", "s": "onstar_alive"},
            {"t": "read_did", "d": "Read OnStar module status DID", "did": 0xDD85, "mod": 0x7C4, "bus": "HS-CAN", "s": "onstar_status"},
            {"t": "read_dtcs", "d": "Read DTCs from OnStar module", "s": "onstar_dtcs"},
            {"t": "instruction", "d": "If the OnStar module does not respond, check the module's power and ground connections (typically located behind the rearview mirror or in the trunk). Check the cellular antenna connection. U0184 = lost communication with telematics module."},
        ],
    },

    # ── TOYOTA-SPECIFIC (4) ──────────────────────────────────────────────
    {
        "id": "toyota_hybrid_battery",
        "name": "Toyota Hybrid Battery Health Check",
        "cat": "electrical",
        "safe": "warning",
        "desc": "Read the hybrid battery state of charge and cell balance from the hybrid ECU. Verifies overall battery health and identifies weak cells that may cause reduced power or failure.",
        "pre": ["Key ON (READY mode)", "Hybrid system active", "Vehicle stationary"],
        "sys": ["P0A80", "P0A7F", "P3000", "hybrid battery", "HV battery", "reduced power"],
        "time": 15,
        "eng": True,
        "mfr": "toyota",
        "steps": [
            {"t": "read_pid", "d": "Read hybrid battery state of charge", "pid": "HYBRID_BATTERY_REMAINING", "s": "hv_soc",
             "c": [("value", "between", [40, 80], "%", "Normal SOC range is 40-80%. Below 30% or above 85% indicates a control problem")]},
            {"t": "read_did", "d": "Read HV battery pack voltage from hybrid ECU", "did": 0xDD90, "mod": 0x7E2, "bus": "HS-CAN", "s": "hv_voltage",
             "c": [("value", "between", [200, 280], "V", "Toyota NiMH pack voltage is typically 200-273V. Low voltage indicates weak cells")]},
            {"t": "read_did", "d": "Read HV battery cell voltage deviation (max-min difference)", "did": 0xDD91, "mod": 0x7E2, "bus": "HS-CAN", "s": "cell_deviation",
             "c": [("value", "<=", 1.0, "V", "Cell deviation should be <0.5V. Over 1.0V indicates failing cell modules")]},
            {"t": "read_did", "d": "Read HV battery temperature from hybrid ECU", "did": 0xDD92, "mod": 0x7E2, "bus": "HS-CAN", "s": "hv_temp",
             "c": [("value", "between", [15, 50], "°C", "Battery temp should be 15-45°C. Overheating indicates fan failure or cell degradation")]},
            {"t": "read_dtcs", "d": "Read DTCs from hybrid ECU", "s": "hybrid_dtcs"},
            {"t": "instruction", "d": "If cell deviation exceeds 1.0V, individual cell modules are failing. On Gen 2/3 Prius, modules can be individually replaced. Check HV battery cooling fan for blockage (under rear seat)."},
        ],
    },
    {
        "id": "toyota_vvti_test",
        "name": "Toyota VVT-i System Test",
        "cat": "fuel",
        "safe": "caution",
        "desc": "Read cam advance DID from the Toyota ECM and verify the VVT-i (Variable Valve Timing with intelligence) system adjusts cam timing as RPM changes. Stuck timing indicates a solenoid or oil control problem.",
        "pre": ["Engine at operating temp", "Oil level and condition OK", "Engine running"],
        "sys": ["P0010", "P0011", "P0012", "P0014", "VVT-i", "cam timing", "variable valve timing"],
        "time": 10,
        "eng": True,
        "mfr": "toyota",
        "steps": [
            {"t": "read_pid", "d": "Read engine RPM at idle", "pid": "RPM", "s": "rpm_idle",
             "c": [("value", "between", [600, 900], "RPM", "Normal idle")]},
            {"t": "read_did", "d": "Read VVT-i cam advance angle at idle from ECM", "did": 0xDD93, "mod": 0x7E0, "bus": "HS-CAN", "s": "cam_advance_idle",
             "c": [("value", "between", [0, 15], "°", "Cam advance at idle should be near baseline (0-15°)")]},
            {"t": "instruction", "d": "Smoothly increase RPM to 3000 and hold steady. The VVT-i system should advance the cam timing."},
            {"t": "read_did", "d": "Read VVT-i cam advance angle at 3000 RPM", "did": 0xDD93, "mod": 0x7E0, "bus": "HS-CAN", "s": "cam_advance_3k",
             "c": [("value", "between", [15, 50], "°", "Cam advance should increase noticeably at higher RPM")]},
            {"t": "instruction", "d": "If cam advance does not change with RPM: check VVT-i oil control valve (solenoid) for sludge, verify oil pressure, and inspect the valve filter screen. Common fix is cleaning or replacing the OCV."},
        ],
    },
    {
        "id": "toyota_eps_test",
        "name": "Toyota Electric Power Steering Test",
        "cat": "steering",
        "safe": "caution",
        "desc": "Read Toyota EPS assist level DID from the EPS ECU. Turn the wheel at idle and verify the torque assist responds to driver input. Verifies EPS motor, torque sensor, and ECU.",
        "pre": ["Engine running at idle", "Vehicle stationary", "Tires on ground"],
        "sys": ["C1511", "C1512", "C1513", "EPS", "power steering", "heavy steering"],
        "time": 10,
        "eng": True,
        "mfr": "toyota",
        "steps": [
            {"t": "read_did", "d": "Read EPS assist torque with wheel centered (no input)", "did": 0xDD94, "mod": 0x730, "bus": "HS-CAN", "s": "eps_rest",
             "c": [("value", "between", [-3, 3], "Nm", "EPS assist should be near zero with no steering input")]},
            {"t": "instruction", "d": "Slowly turn the steering wheel to the left. The EPS should provide assist — the wheel should turn easily."},
            {"t": "read_did", "d": "Read EPS assist torque while turning left", "did": 0xDD94, "mod": 0x730, "bus": "HS-CAN", "s": "eps_left"},
            {"t": "instruction", "d": "Turn the steering wheel to the right. Verify equal assist in both directions."},
            {"t": "read_did", "d": "Read EPS assist torque while turning right", "did": 0xDD94, "mod": 0x730, "bus": "HS-CAN", "s": "eps_right"},
            {"t": "instruction", "d": "Assist torque should be similar in both directions. If one direction has noticeably less assist, suspect the EPS torque sensor or motor. Check for DTCs and verify the EPS ECU power supply."},
        ],
    },
    {
        "id": "toyota_tpws_test",
        "name": "Toyota Tire Pressure Warning System Test",
        "cat": "safety",
        "safe": "safe",
        "desc": "Read tire pressure values from all four Toyota TPMS sensors via the TPMS ECU. Compare all four readings for consistency and verify they are within the recommended range.",
        "pre": ["Key ON", "All tires cold (not driven in last 30 min)"],
        "sys": ["C2141", "C2142", "C2143", "C2176", "TPMS", "tire pressure", "TPWS"],
        "time": 10,
        "eng": False,
        "mfr": "toyota",
        "steps": [
            {"t": "read_did", "d": "Read left front tire pressure from TPMS ECU", "did": 0xDD95, "mod": 0x750, "bus": "HS-CAN", "s": "tp_lf",
             "c": [("value", "between", [200, 280], "kPa", "Normal tire pressure typically 220-250 kPa (32-36 psi)")]},
            {"t": "read_did", "d": "Read right front tire pressure from TPMS ECU", "did": 0xDD96, "mod": 0x750, "bus": "HS-CAN", "s": "tp_rf",
             "c": [("value", "between", [200, 280], "kPa", "Should match L/F within ±15 kPa")]},
            {"t": "read_did", "d": "Read left rear tire pressure from TPMS ECU", "did": 0xDD97, "mod": 0x750, "bus": "HS-CAN", "s": "tp_lr",
             "c": [("value", "between", [200, 280], "kPa", "Rear pressures may differ from front per placard")]},
            {"t": "read_did", "d": "Read right rear tire pressure from TPMS ECU", "did": 0xDD98, "mod": 0x750, "bus": "HS-CAN", "s": "tp_rr",
             "c": [("value", "between", [200, 280], "kPa", "Should match L/R within ±15 kPa")]},
            {"t": "instruction", "d": "Compare all four readings: all should be within ±15 kPa of each other (unless front/rear have different placard pressures). If one sensor gives no reading, the sensor battery may be dead (typical lifespan is 5-10 years)."},
        ],
    },

    # ── HONDA-SPECIFIC (1) ───────────────────────────────────────────────
    {
        "id": "honda_vtec_test",
        "name": "Honda VTEC Engagement Test",
        "cat": "fuel",
        "safe": "caution",
        "desc": "Read the Honda VTEC solenoid status DID from the PCM and rev the engine past the VTEC crossover point (~5500 RPM). Verify the solenoid engages and cam profile switches.",
        "pre": ["Engine at operating temp", "Oil level full", "Oil pressure normal", "Safe area for high RPM test"],
        "sys": ["P1259", "P2646", "P2647", "VTEC", "VTEC solenoid", "no VTEC engagement"],
        "time": 10,
        "eng": True,
        "mfr": "honda",
        "steps": [
            {"t": "read_pid", "d": "Read RPM at idle baseline", "pid": "RPM", "s": "rpm_idle",
             "c": [("value", "between", [600, 900], "RPM", "Normal idle")]},
            {"t": "read_did", "d": "Read VTEC solenoid status from PCM — should be OFF at idle", "did": 0xDDA0, "mod": 0x7E0, "bus": "HS-CAN", "s": "vtec_off",
             "c": [("value", "==", 0, "", "VTEC should be disengaged at idle")]},
            {"t": "instruction", "d": "In Park or Neutral, smoothly rev the engine past 5500 RPM. You should feel/hear a distinct change in engine note when VTEC engages. Hold above 5500 RPM briefly."},
            {"t": "read_did", "d": "Read VTEC solenoid status above crossover RPM — should be ON", "did": 0xDDA0, "mod": 0x7E0, "bus": "HS-CAN", "s": "vtec_on",
             "c": [("value", "==", 1, "", "VTEC should be engaged above crossover RPM")]},
            {"t": "read_pid", "d": "Verify RPM is above VTEC crossover point", "pid": "RPM", "s": "rpm_vtec",
             "c": [("value", ">=", 5400, "RPM", "Must be above ~5500 RPM for VTEC engagement")]},
            {"t": "instruction", "d": "If VTEC does not engage: check VTEC solenoid connector, oil pressure (VTEC requires adequate oil pressure), VTEC solenoid screen filter (often clogged with sludge), and verify oil level is at the full mark."},
        ],
    },
]
# COMPACT_PROCEDURES_PLACEHOLDER


def _build_library() -> None:
    """Build the complete procedure library."""
    # Original 15 hand-crafted procedures
    procedures = [
        _build_fuel_pump_test(),
        _build_cooling_fan_test(),
        _build_evap_system_test(),
        _build_o2_sensor_heater_test(),
        _build_misfire_diagnosis(),
        _build_catalytic_converter_test(),
        _build_idle_air_control_test(),
        _build_charging_system_test(),
        _build_thermostat_test(),
        _build_mass_airflow_test(),
        _build_egr_test(),
        _build_ford_gem_light_test(),
        _build_ford_door_lock_test(),
        _build_abs_module_test(),
        _build_tpms_test(),
    ]
    for proc in procedures:
        _register_procedure(proc)

    # Data-driven compact procedures
    for d in COMPACT_PROCEDURES:
        try:
            proc = _build_from_compact(d)
            _register_procedure(proc)
        except Exception as e:
            logger.warning("Failed to build procedure %s: %s", d.get("id", "?"), e)


# Initialize library at import time
_build_library()


# ---------------------------------------------------------------------------
# Lookup Functions (for AI/tool integration)
# ---------------------------------------------------------------------------

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
