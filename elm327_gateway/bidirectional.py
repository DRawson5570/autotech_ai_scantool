"""
Bidirectional Control for OBD-II

Handles Mode $08 actuator tests and manufacturer-specific UDS commands.

Capabilities vary by vehicle:
- Tier 2: Mode $08 standard actuator tests (EVAP, fan, etc.)
- Tier 3: UDS 0x2F InputOutputControlByIdentifier (full bidirectional)

Note: Many vehicles don't support bidirectional control via OBD-II.
Full bidirectional typically requires manufacturer tools/protocols.
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# ISO 14229-1 DID Range Constants
# ---------------------------------------------------------------------------
# From python-udsoncan dids.py + ISO 14229-1:2020 Annex C

DID_RANGE_SERVER_BOOT_SOFTWARE     = (0x0001, 0x000A)  # bootSoftwareIdentification
DID_RANGE_SERVER_APP_SOFTWARE      = (0x000B, 0x000F)  # applicationSoftwareIdentification
DID_RANGE_SERVER_APP_DATA          = (0x0010, 0x0017)  # applicationDataIdentification
DID_RANGE_VEHICLE_MFR_SPECIFIC     = (0x0100, 0xA5FF)  # vehicleManufacturerSpecific (main DID scan range)
DID_RANGE_SYSTEM_SUPPLIER_SPECIFIC = (0xA600, 0xA7FF)  # systemSupplierSpecific
DID_RANGE_TESTER_SPECIFIC          = (0xF000, 0xF00F)  # Reserved for tester use
DID_RANGE_IDENTIFICATION_OPTION    = (0xF100, 0xF17F)  # identificationOptionVehicleManufacturerSpecific
DID_VIN                            = 0xF190             # VIN (standard)
DID_RANGE_PERIODIC_DATA            = (0xF200, 0xF2FF)  # periodicDataIdentifier
DID_RANGE_DYNAMICALLY_DEFINED      = (0xF300, 0xF3FF)  # dynamicallyDefinedDataIdentifier
DID_RANGE_OBD_DATA                 = (0xF400, 0xF5FF)  # obdDataIdentifier
DID_RANGE_OBD_DTC_INFO             = (0xF600, 0xF6FF)  # obdMonitorDataIdentifier
DID_RANGE_OBD_INFO_TYPE            = (0xF800, 0xF8FF)  # obdInfoTypeDataIdentifier

# UDS 0x2F InputOutputControlByIdentifier control parameters
# (mirrors python-udsoncan ControlParam enum)
IOCP_RETURN_CONTROL  = 0x00  # returnControlToECU
IOCP_RESET_DEFAULT   = 0x01  # resetToDefault
IOCP_FREEZE_STATE    = 0x02  # freezeCurrentState
IOCP_SHORT_TERM_ADJ  = 0x03  # shortTermAdjustment

# UDS NRC codes relevant to actuation
NRC_SERVICE_NOT_SUPPORTED            = 0x11
NRC_SUBFUNCTION_NOT_SUPPORTED        = 0x12
NRC_INCORRECT_LENGTH                 = 0x13
NRC_CONDITIONS_NOT_CORRECT           = 0x22
NRC_REQUEST_SEQUENCE_ERROR           = 0x24
NRC_REQUEST_OUT_OF_RANGE             = 0x31
NRC_SECURITY_ACCESS_DENIED           = 0x33
NRC_INVALID_KEY                      = 0x35
NRC_EXCEEDED_NUMBER_OF_ATTEMPTS      = 0x36
NRC_GENERAL_REJECT                   = 0x10


class ActuatorType(Enum):
    """Standard actuator types for Mode $08."""
    EVAP_PURGE = "evap_purge"
    EVAP_VENT = "evap_vent"
    COOLING_FAN = "cooling_fan"
    AC_CLUTCH = "ac_clutch"
    FUEL_PUMP = "fuel_pump"
    EGR_VALVE = "egr_valve"
    AIR_PUMP = "air_pump"
    CANISTER_PURGE = "canister_purge"


class ActuatorState(Enum):
    """Actuator control states."""
    OFF = "off"
    ON = "on"
    CYCLE = "cycle"  # Cycle on/off
    DEFAULT = "default"  # Return to ECU control


class CautionLevel(Enum):
    """Risk level for actuator control — inspired by OpenVehicleDiag.
    
    NONE:  Purely observational or very low risk (EVAP purge, A/C clutch).
    WARN:  Moderate risk — could affect drivability or comfort if left on.
           User should confirm vehicle is stationary. (Cooling fan, air pump)
    ALERT: High risk — could stall engine or affect safety systems.
           Requires explicit acknowledgement. (Fuel pump, EGR valve)
    """
    NONE = "none"
    WARN = "warn"
    ALERT = "alert"


@dataclass
class ActuatorDefinition:
    """Definition for a controllable actuator."""
    actuator_type: ActuatorType
    name: str
    description: str
    tid: int  # Mode $08 Test ID
    supported_states: List[ActuatorState]
    caution_level: CautionLevel = CautionLevel.NONE
    caution_message: str = ""  # Shown to user before WARN/ALERT controls
    
    # Optional: UDS identifier for Tier 3 control
    uds_did: Optional[int] = None


# Mode $08 Test IDs (vehicle-dependent)
# These are common TIDs but actual support varies by manufacturer
STANDARD_ACTUATORS: Dict[ActuatorType, ActuatorDefinition] = {
    ActuatorType.EVAP_PURGE: ActuatorDefinition(
        actuator_type=ActuatorType.EVAP_PURGE,
        name="EVAP Purge Solenoid",
        description="Controls evaporative emission purge valve",
        tid=0x01,
        supported_states=[ActuatorState.OFF, ActuatorState.ON, ActuatorState.DEFAULT],
        caution_level=CautionLevel.NONE,
    ),
    ActuatorType.EVAP_VENT: ActuatorDefinition(
        actuator_type=ActuatorType.EVAP_VENT,
        name="EVAP Vent Solenoid",
        description="Controls evaporative emission vent valve",
        tid=0x02,
        supported_states=[ActuatorState.OFF, ActuatorState.ON, ActuatorState.DEFAULT],
        caution_level=CautionLevel.NONE,
    ),
    ActuatorType.COOLING_FAN: ActuatorDefinition(
        actuator_type=ActuatorType.COOLING_FAN,
        name="Cooling Fan",
        description="Engine cooling fan relay",
        tid=0x03,
        supported_states=[ActuatorState.OFF, ActuatorState.ON, ActuatorState.DEFAULT],
        caution_level=CautionLevel.WARN,
        caution_message="Cooling fan may spin at high speed. Keep clear of fan blades.",
    ),
    ActuatorType.AC_CLUTCH: ActuatorDefinition(
        actuator_type=ActuatorType.AC_CLUTCH,
        name="A/C Compressor Clutch",
        description="Air conditioning compressor clutch",
        tid=0x04,
        supported_states=[ActuatorState.OFF, ActuatorState.ON, ActuatorState.DEFAULT],
        caution_level=CautionLevel.NONE,
    ),
    ActuatorType.FUEL_PUMP: ActuatorDefinition(
        actuator_type=ActuatorType.FUEL_PUMP,
        name="Fuel Pump",
        description="Fuel pump relay",
        tid=0x05,
        supported_states=[ActuatorState.OFF, ActuatorState.ON, ActuatorState.CYCLE],
        caution_level=CautionLevel.ALERT,
        caution_message="Disabling fuel pump will stall a running engine. Ensure vehicle is stationary and in PARK.",
    ),
    ActuatorType.EGR_VALVE: ActuatorDefinition(
        actuator_type=ActuatorType.EGR_VALVE,
        name="EGR Valve",
        description="Exhaust gas recirculation valve",
        tid=0x06,
        supported_states=[ActuatorState.OFF, ActuatorState.ON, ActuatorState.DEFAULT],
        caution_level=CautionLevel.ALERT,
        caution_message="EGR control affects combustion and emissions. Engine must be idling in PARK.",
    ),
    ActuatorType.AIR_PUMP: ActuatorDefinition(
        actuator_type=ActuatorType.AIR_PUMP,
        name="Secondary Air Pump",
        description="Secondary air injection pump relay",
        tid=0x07,
        supported_states=[ActuatorState.OFF, ActuatorState.ON, ActuatorState.DEFAULT],
        caution_level=CautionLevel.WARN,
        caution_message="Secondary air pump adds load. Engine should be warm and idling.",
    ),
    ActuatorType.CANISTER_PURGE: ActuatorDefinition(
        actuator_type=ActuatorType.CANISTER_PURGE,
        name="Canister Purge Valve",
        description="Carbon canister purge control valve",
        tid=0x08,
        supported_states=[ActuatorState.OFF, ActuatorState.ON, ActuatorState.DEFAULT],
        caution_level=CautionLevel.NONE,
    ),
}


class ActuatorControl:
    """
    Bidirectional actuator control interface.
    
    Provides safe abstraction for controlling vehicle actuators via:
    - Mode $08 standard OBD-II actuator tests
    - UDS 0x2F InputOutputControlByIdentifier (when available)
    """
    
    def __init__(self, protocol):
        """
        Initialize actuator controller.
        
        Args:
            protocol: OBDProtocol instance
        """
        self.protocol = protocol
        self._active_controls: Dict[ActuatorType, ActuatorState] = {}
        self._supported_actuators: Optional[List[ActuatorType]] = None
    
    async def get_supported_actuators(self) -> List[ActuatorType]:
        """
        Probe for supported actuators.
        
        Returns:
            List of supported ActuatorType
            
        Note:
            This attempts to query each actuator. Many vehicles
            won't support any Mode $08 operations.
        """
        if self._supported_actuators is not None:
            return self._supported_actuators
        
        supported = []
        
        for actuator_type, defn in STANDARD_ACTUATORS.items():
            try:
                # Try to read current state (some vehicles support this)
                response = await self.protocol.connection.send_command(
                    f"08{defn.tid:02X}00",  # TID with read request
                    timeout=2.0
                )
                
                if "NO DATA" not in response and "ERROR" not in response:
                    supported.append(actuator_type)
                    logger.debug(f"Actuator {actuator_type.value} supported")
                    
            except Exception as e:
                logger.debug(f"Actuator {actuator_type.value} not supported: {e}")
        
        self._supported_actuators = supported
        return supported
    
    async def control(
        self,
        actuator: ActuatorType,
        state: ActuatorState,
        duration: Optional[float] = None
    ) -> bool:
        """
        Control an actuator.
        
        Args:
            actuator: Type of actuator to control
            state: Desired state
            duration: Optional duration in seconds (returns to default after)
            
        Returns:
            True if command was accepted
            
        Raises:
            ValueError: If actuator not supported or invalid state
        """
        defn = STANDARD_ACTUATORS.get(actuator)
        if not defn:
            raise ValueError(f"Unknown actuator: {actuator}")
        
        if state not in defn.supported_states:
            raise ValueError(f"State {state} not supported for {actuator}")
        
        # Build Mode $08 command
        # Format: 08 TID CTRL
        # CTRL: 00=off, FF=on, others vary
        ctrl_byte = self._state_to_byte(state)
        cmd = f"08{defn.tid:02X}{ctrl_byte:02X}"
        
        logger.info(f"Actuator control: {actuator.value} -> {state.value}")
        
        try:
            response = await self.protocol.connection.send_command(cmd)
            
            if "48" in response:  # Positive response for Mode $08
                self._active_controls[actuator] = state
                
                # If duration specified, schedule return to default
                if duration and state != ActuatorState.DEFAULT:
                    asyncio.create_task(self._timed_release(actuator, duration))
                
                return True
            else:
                logger.warning(f"Actuator control failed: {response}")
                return False
                
        except Exception as e:
            logger.error(f"Actuator control error: {e}")
            return False
    
    async def release(self, actuator: ActuatorType) -> bool:
        """
        Release actuator back to ECU control.
        
        Args:
            actuator: Actuator to release
            
        Returns:
            True if successful
        """
        return await self.control(actuator, ActuatorState.DEFAULT)
    
    async def release_all(self) -> None:
        """Release all active actuator controls."""
        for actuator in list(self._active_controls.keys()):
            await self.release(actuator)
        self._active_controls.clear()
    
    async def _timed_release(self, actuator: ActuatorType, duration: float) -> None:
        """Release actuator after specified duration."""
        await asyncio.sleep(duration)
        if self._active_controls.get(actuator) != ActuatorState.DEFAULT:
            await self.release(actuator)
    
    def _state_to_byte(self, state: ActuatorState) -> int:
        """Convert state enum to control byte."""
        if state == ActuatorState.OFF:
            return 0x00
        elif state == ActuatorState.ON:
            return 0xFF
        elif state == ActuatorState.CYCLE:
            return 0x01  # Cycle command (vehicle-specific)
        else:  # DEFAULT
            return 0x00  # Most vehicles treat 0x00 as return to ECU control
    
    # -------------------------------------------------------------------------
    # High-Level Diagnostic Tests
    # -------------------------------------------------------------------------
    
    async def test_cooling_fan(self, duration: float = 10.0) -> bool:
        """
        Test cooling fan operation.
        
        Args:
            duration: How long to run fan (seconds)
            
        Returns:
            True if fan was successfully commanded
        """
        logger.info(f"Testing cooling fan for {duration}s")
        success = await self.control(
            ActuatorType.COOLING_FAN,
            ActuatorState.ON,
            duration=duration
        )
        
        if success:
            logger.info("Cooling fan commanded ON - verify fan is running")
        else:
            logger.warning("Cooling fan test not supported or failed")
        
        return success
    
    async def test_evap_system(self, duration: float = 5.0) -> Dict[str, bool]:
        """
        Test EVAP system components.
        
        Args:
            duration: Test duration per component
            
        Returns:
            Dict of component -> success
        """
        results = {}
        
        # Test purge solenoid
        logger.info("Testing EVAP purge solenoid...")
        results['purge'] = await self.control(
            ActuatorType.EVAP_PURGE,
            ActuatorState.ON,
            duration=duration
        )
        await asyncio.sleep(duration + 0.5)
        
        # Test vent solenoid
        logger.info("Testing EVAP vent solenoid...")
        results['vent'] = await self.control(
            ActuatorType.EVAP_VENT,
            ActuatorState.ON,
            duration=duration
        )
        await asyncio.sleep(duration + 0.5)
        
        return results
    
    async def prime_fuel_pump(self, duration: float = 3.0) -> bool:
        """
        Prime fuel pump (key-on engine-off).
        
        Args:
            duration: Pump run time in seconds
            
        Returns:
            True if pump was commanded
        """
        logger.info(f"Priming fuel pump for {duration}s")
        return await self.control(
            ActuatorType.FUEL_PUMP,
            ActuatorState.ON,
            duration=duration
        )


# ---------------------------------------------------------------------------
# Security Algorithm Registry
# ---------------------------------------------------------------------------
# Follows the exact same callback signature as python-udsoncan's
# config['security_algo']:  f(level: int, seed: bytes, params: dict) -> bytes
#
# Usage:
#   def my_xor_algo(level: int, seed: bytes, params: dict) -> bytes:
#       """Simple XOR key derivation (example — NOT real)."""
#       xor_key = params.get("xor_key", 0xA5)
#       return bytes(b ^ xor_key for b in seed)
#
#   SecurityAlgorithmRegistry.register("my_manufacturer", my_xor_algo)
#
# Algorithms can also be registered per-module:
#   SecurityAlgorithmRegistry.register("ford_bcm", ford_bcm_algo)
#   SecurityAlgorithmRegistry.register("ford_pcm", ford_pcm_algo)

SecurityAlgo = Callable[[int, bytes, dict], bytes]


class SecurityAlgorithmRegistry:
    """Registry of manufacturer-specific seed→key algorithms.

    Each algorithm is a callable with signature:
        (level: int, seed: bytes, params: dict) -> bytes

    where:
        level  — UDS security level (odd = seed request, even = key send)
        seed   — raw seed bytes returned by the ECU (0x67 XX payload)
        params — arbitrary dict (can carry vehicle info, counters, etc.)

    Returns the computed key bytes to send with 0x27 (level+1).
    """

    _algorithms: Dict[str, SecurityAlgo] = {}

    @classmethod
    def register(cls, name: str, algorithm: SecurityAlgo) -> None:
        """Register a seed→key algorithm by name."""
        cls._algorithms[name.lower()] = algorithm
        logger.info("Registered security algorithm: %s", name)

    @classmethod
    def get(cls, name: str) -> Optional[SecurityAlgo]:
        """Look up an algorithm by name. Returns None if not registered."""
        return cls._algorithms.get(name.lower())

    @classmethod
    def list_algorithms(cls) -> List[str]:
        """List all registered algorithm names."""
        return sorted(cls._algorithms.keys())

    @classmethod
    def has(cls, name: str) -> bool:
        return name.lower() in cls._algorithms


# ---------------------------------------------------------------------------
# UDS Session Manager
# ---------------------------------------------------------------------------

class UDSSessionManager:
    """Manages UDS diagnostic session lifecycle on a single ECU module.

    Handles:
    1. DiagnosticSessionControl (0x10) — enter extended session
    2. SecurityAccess (0x27)          — seed/key unlock via pluggable algorithm
    3. TesterPresent (0x3E 0x80)      — keep session alive while active
    4. Clean teardown                 — return to default session on close

    This is the *protocol plumbing* layer. Actual IO control commands (0x2F)
    should go through io_control.IOControlEngine for safety gating.
    """

    def __init__(self, protocol):
        self.protocol = protocol
        self._session_active: Dict[str, bool] = {}      # module_addr -> True
        self._security_unlocked: Dict[str, bool] = {}   # module_addr -> True
        self._tester_present_tasks: Dict[str, asyncio.Task] = {}
        self._original_header: Optional[str] = None

    # --- Header management ---

    async def _set_header(self, module_addr: str) -> None:
        """Set AT SH to the target module address."""
        self._original_header = module_addr
        await self.protocol.connection.send_command(
            f"AT SH {module_addr}", timeout=1.0
        )

    # --- Session Control ---

    async def enter_extended_session(self, module_addr: str) -> bool:
        """Send DiagnosticSessionControl (0x10 0x03) to enter extended session.

        Returns True if ECU responded positively (0x50 0x03).
        """
        await self._set_header(module_addr)
        response = await self.protocol.connection.send_command(
            "10 03", timeout=3.0
        )
        if not response:
            logger.warning("No response to DiagnosticSessionControl on %s", module_addr)
            return False

        success = "50" in response and "03" in response
        if success:
            self._session_active[module_addr] = True
            self._start_tester_present(module_addr)
            logger.info("Extended diagnostic session active on %s", module_addr)
        else:
            logger.warning(
                "Extended session rejected on %s: %s", module_addr, response
            )
        return success

    async def return_to_default_session(self, module_addr: str) -> bool:
        """Return to default session (0x10 0x01) and stop TesterPresent."""
        self._stop_tester_present(module_addr)
        await self._set_header(module_addr)
        response = await self.protocol.connection.send_command(
            "10 01", timeout=3.0
        )
        self._session_active.pop(module_addr, None)
        self._security_unlocked.pop(module_addr, None)
        return bool(response and "50" in response)

    # --- Security Access ---

    async def unlock_security(
        self,
        module_addr: str,
        algorithm: str,
        level: int = 1,
        params: Optional[dict] = None,
    ) -> bool:
        """Perform UDS 0x27 SecurityAccess using a registered algorithm.

        Args:
            module_addr: Target ECU header (e.g. "7C0")
            algorithm: Name registered in SecurityAlgorithmRegistry
            level: Odd security level for seed request (even = key send)
            params: Extra params forwarded to the algorithm callback

        Returns:
            True if ECU accepted the computed key.
        """
        algo_fn = SecurityAlgorithmRegistry.get(algorithm)
        if algo_fn is None:
            logger.error(
                "No security algorithm registered for '%s'. "
                "Available: %s",
                algorithm,
                SecurityAlgorithmRegistry.list_algorithms(),
            )
            return False

        if not self._session_active.get(module_addr):
            logger.warning(
                "Extended session not active on %s — call enter_extended_session first",
                module_addr,
            )
            return False

        await self._set_header(module_addr)

        # Step 1: Request seed (0x27 with odd level)
        seed_cmd = f"27 {level:02X}"
        response = await self.protocol.connection.send_command(seed_cmd, timeout=3.0)
        if not response or "67" not in response:
            nrc = response[-2:] if response and len(response) >= 2 else "??"
            logger.warning(
                "Security seed request rejected on %s (NRC 0x%s): %s",
                module_addr, nrc, response,
            )
            return False

        # Parse seed from response: "67 01 AA BB CC DD ..."
        # Strip the "67 XX" prefix to get raw seed bytes
        try:
            resp_clean = response.replace(" ", "").replace("\r", "").replace("\n", "")
            # Find the positive response marker
            idx = resp_clean.find("67")
            if idx < 0:
                raise ValueError("No 0x67 in response")
            # Skip 67 + level byte (2 hex chars each = 4 total)
            seed_hex = resp_clean[idx + 4:]
            if not seed_hex:
                raise ValueError("Empty seed")
            seed_bytes = bytes.fromhex(seed_hex)
        except Exception as e:
            logger.error("Failed to parse seed from %s: %s", response, e)
            return False

        logger.info(
            "Got seed from %s (level %d): %s (%d bytes)",
            module_addr, level, seed_bytes.hex(), len(seed_bytes),
        )

        # Step 2: Compute key
        try:
            key_bytes = algo_fn(level, seed_bytes, params or {})
        except Exception as e:
            logger.error("Security algorithm '%s' raised: %s", algorithm, e)
            return False

        # Step 3: Send key (0x27 with level+1)
        key_cmd = f"27 {level + 1:02X} {key_bytes.hex().upper()}"
        response = await self.protocol.connection.send_command(key_cmd, timeout=3.0)

        if response and "67" in response:
            self._security_unlocked[module_addr] = True
            logger.info("Security unlocked on %s (level %d)", module_addr, level)
            return True
        else:
            nrc = response[-2:] if response and len(response) >= 2 else "??"
            logger.warning(
                "Security key rejected on %s (NRC 0x%s): %s",
                module_addr, nrc, response,
            )
            return False

    def is_session_active(self, module_addr: str) -> bool:
        return self._session_active.get(module_addr, False)

    def is_security_unlocked(self, module_addr: str) -> bool:
        return self._security_unlocked.get(module_addr, False)

    # --- TesterPresent keepalive ---

    def _start_tester_present(self, module_addr: str) -> None:
        """Start periodic 0x3E 0x80 (TesterPresent, suppressPositiveResponse)."""
        old_task = self._tester_present_tasks.get(module_addr)
        if old_task and not old_task.done():
            return  # already running
        task = asyncio.create_task(self._tester_present_loop(module_addr))
        self._tester_present_tasks[module_addr] = task

    def _stop_tester_present(self, module_addr: str) -> None:
        task = self._tester_present_tasks.pop(module_addr, None)
        if task and not task.done():
            task.cancel()

    async def _tester_present_loop(self, module_addr: str) -> None:
        """Send 0x3E 0x80 every 2 seconds to keep the session alive."""
        try:
            while self._session_active.get(module_addr):
                await asyncio.sleep(2.0)
                try:
                    await self.protocol.connection.send_command(
                        "3E 80", timeout=1.0
                    )
                except Exception:
                    logger.debug("TesterPresent failed on %s", module_addr)
        except asyncio.CancelledError:
            pass

    # --- Cleanup ---

    async def close_all(self) -> None:
        """Return all modules to default session and stop keepalives."""
        for module_addr in list(self._session_active.keys()):
            try:
                await self.return_to_default_session(module_addr)
            except Exception:
                logger.warning("Failed to close session on %s", module_addr, exc_info=True)


# ---------------------------------------------------------------------------
# UDS Bidirectional Control
# ---------------------------------------------------------------------------

class UDSBidirectional:
    """UDS (ISO 14229) bidirectional control via 0x2F.

    This class handles the **transport** side of IO control:
    - Entering extended diagnostic sessions
    - Security access with pluggable algorithms
    - Sending 0x2F commands and parsing responses

    **Safety gating is handled by io_control.IOControlEngine** — callers
    should use IOControlEngine.execute_control() for production actuation,
    which enforces trust checks, control path validation, and watchdog
    timeouts. This class provides the low-level building blocks that
    IOControlEngine's send_fn delegates to.

    Typical flow:
        1. UDSBidirectional.enter_extended_session()
        2. UDSBidirectional.unlock_security()  (if ECU requires it)
        3. io_control.IOControlEngine.execute_control(entry, action,
               send_fn=uds.raw_io_control)  # routes through safety gates
    """

    def __init__(self, protocol):
        """Initialize UDS controller."""
        self.protocol = protocol
        self._session_mgr = UDSSessionManager(protocol)

    @property
    def session_manager(self) -> UDSSessionManager:
        """Access the underlying session manager."""
        return self._session_mgr

    async def enter_extended_session(self, module_addr: str) -> bool:
        """Enter extended diagnostic session on a module."""
        return await self._session_mgr.enter_extended_session(module_addr)

    async def unlock_security(
        self,
        module_addr: str,
        algorithm: str,
        level: int = 1,
        params: Optional[dict] = None,
    ) -> bool:
        """Unlock security access using a registered algorithm.

        See SecurityAlgorithmRegistry for how to register algorithms.
        """
        return await self._session_mgr.unlock_security(
            module_addr, algorithm, level, params
        )

    async def raw_io_control(
        self,
        module_addr: str,
        raw_hex_cmd: str,
    ) -> str:
        """Send a raw hex command to a module and return the response.

        This is designed to be passed as the `send_fn` parameter to
        io_control.IOControlEngine.execute_control().

        Args:
            module_addr: ECU header (e.g. "7C0")
            raw_hex_cmd: Full UDS command in hex (e.g. "2FF02003FF")

        Returns:
            Raw hex response string from the ECU.
        """
        await self._session_mgr._set_header(module_addr)
        response = await self.protocol.connection.send_command(
            raw_hex_cmd, timeout=3.0
        )
        return response or ""

    async def control_by_identifier(
        self,
        module_addr: str,
        did: int,
        control_param: int,
        data: bytes = b"",
    ) -> Tuple[bool, str]:
        """UDS 0x2F InputOutputControlByIdentifier (low-level).

        For production use, prefer io_control.IOControlEngine.execute_control()
        which wraps this with safety gates.

        Args:
            module_addr: ECU header (e.g. "726")
            did: Data Identifier (2 bytes)
            control_param: IOCP value (0x00-0x03)
            data: Optional control state record bytes

        Returns:
            (success: bool, response_hex: str)
        """
        cmd = f"2F{did:04X}{control_param:02X}"
        if data:
            cmd += data.hex().upper()

        response = await self.raw_io_control(module_addr, cmd)
        success = "6F" in response
        return success, response

    async def return_control_to_ecu(
        self, module_addr: str, did: int
    ) -> Tuple[bool, str]:
        """Return control of a DID to the ECU (IOCP 0x00)."""
        return await self.control_by_identifier(
            module_addr, did, IOCP_RETURN_CONTROL
        )

    async def probe_session_support(self, module_addr: str) -> bool:
        """Check if a module accepts extended diagnostic session.

        Useful for surveying which ECUs are candidates for IO control
        without committing to a full session.
        """
        result = await self._session_mgr.enter_extended_session(module_addr)
        if result:
            # Return to default so we don't leave a session open
            await self._session_mgr.return_to_default_session(module_addr)
        return result

    async def probe_security_required(self, module_addr: str) -> Optional[bytes]:
        """Check if a module requires security access and capture the seed.

        Returns the seed bytes if the ECU provides one, or None if security
        access is not supported. Does NOT attempt to compute or send a key.

        Requires extended session to be active.
        """
        await self._session_mgr._set_header(module_addr)
        response = await self.protocol.connection.send_command(
            "27 01", timeout=3.0
        )
        if not response or "67" not in response:
            return None

        try:
            resp_clean = response.replace(" ", "").replace("\r", "").replace("\n", "")
            idx = resp_clean.find("67")
            seed_hex = resp_clean[idx + 4:]  # skip 67 + level byte
            if seed_hex:
                return bytes.fromhex(seed_hex)
        except Exception:
            pass
        return None

    async def close(self) -> None:
        """Close all active sessions."""
        await self._session_mgr.close_all()


# ---------------------------------------------------------------------------
# Verified Manufacturer DID Mappings for IO Control (0x2F)
# ---------------------------------------------------------------------------
# ONLY include DIDs that have been verified from real documentation or
# confirmed by live vehicle testing. Do NOT add guessed values.
#
# Structure: list of dicts, each describing one actuator DID.
# These can be loaded into io_control's registry when a matching vehicle
# is connected.

VERIFIED_ACTUATOR_DIDS: List[Dict[str, Any]] = [
    # -----------------------------------------------------------------------
    # Stellantis / Fiat — BCM (0x18DA40F1 = physical addr 0x40)
    # Source: odb_resources/OBD2_CAN_Bus_Library/examples/TestAll/TestAll.ino
    # Confirmed: Extended session (0x10 0x03) required, NO security access.
    # All use IOCP 0x03 (ShortTermAdjustment), data 0xFF to activate.
    # -----------------------------------------------------------------------
    {
        "manufacturer": "stellantis",
        "module": "BCM",
        "module_addr": "18DA40F1",  # 29-bit extended CAN ID
        "bus": "HS-CAN",
        "security_required": False,
        "signal_name": "door_lock",
        "did_hex": "5021",
        "control_param": IOCP_SHORT_TERM_ADJ,
        "on_data": b"\xFF",
        "off_data": b"\x00",
        "caution_level": "warn",
        "description": "Central door lock",
    },
    {
        "manufacturer": "stellantis",
        "module": "BCM",
        "module_addr": "18DA40F1",
        "bus": "HS-CAN",
        "security_required": False,
        "signal_name": "door_unlock",
        "did_hex": "5020",
        "control_param": IOCP_SHORT_TERM_ADJ,
        "on_data": b"\xFF",
        "off_data": b"\x00",
        "caution_level": "warn",
        "description": "Central door unlock",
    },
    {
        "manufacturer": "stellantis",
        "module": "BCM",
        "module_addr": "18DA40F1",
        "bus": "HS-CAN",
        "security_required": False,
        "signal_name": "left_turn_signal",
        "did_hex": "5009",
        "control_param": IOCP_SHORT_TERM_ADJ,
        "on_data": b"\xFF",
        "off_data": b"\x00",
        "caution_level": "none",
        "description": "Left turn signal / blinker",
    },
    {
        "manufacturer": "stellantis",
        "module": "BCM",
        "module_addr": "18DA40F1",
        "bus": "HS-CAN",
        "security_required": False,
        "signal_name": "right_turn_signal",
        "did_hex": "500A",
        "control_param": IOCP_SHORT_TERM_ADJ,
        "on_data": b"\xFF",
        "off_data": b"\x00",
        "caution_level": "none",
        "description": "Right turn signal / blinker",
    },
    {
        "manufacturer": "stellantis",
        "module": "BCM",
        "module_addr": "18DA40F1",
        "bus": "HS-CAN",
        "security_required": False,
        "signal_name": "low_beams",
        "did_hex": "5010",
        "control_param": IOCP_SHORT_TERM_ADJ,
        "on_data": b"\xFF",
        "off_data": b"\x00",
        "caution_level": "none",
        "description": "Low beam headlights",
    },
    {
        "manufacturer": "stellantis",
        "module": "BCM",
        "module_addr": "18DA40F1",
        "bus": "HS-CAN",
        "security_required": False,
        "signal_name": "high_beams",
        "did_hex": "5011",
        "control_param": IOCP_SHORT_TERM_ADJ,
        "on_data": b"\xFF",
        "off_data": b"\x00",
        "caution_level": "none",
        "description": "High beam headlights",
    },
    {
        "manufacturer": "stellantis",
        "module": "BCM",
        "module_addr": "18DA40F1",
        "bus": "HS-CAN",
        "security_required": False,
        "signal_name": "fog_lights",
        "did_hex": "5012",
        "control_param": IOCP_SHORT_TERM_ADJ,
        "on_data": b"\xFF",
        "off_data": b"\x00",
        "caution_level": "none",
        "description": "Fog lights",
    },
    {
        "manufacturer": "stellantis",
        "module": "BCM",
        "module_addr": "18DA40F1",
        "bus": "HS-CAN",
        "security_required": False,
        "signal_name": "wipers",
        "did_hex": "5030",
        "control_param": IOCP_SHORT_TERM_ADJ,
        "on_data": b"\x01",   # 0x01 = wipers ON
        "off_data": b"\xFF",  # 0xFF = wipers OFF (per TestAll.ino)
        "caution_level": "none",
        "description": "Windshield wipers",
    },
    {
        "manufacturer": "stellantis",
        "module": "BCM",
        "module_addr": "18DA40F1",
        "bus": "HS-CAN",
        "security_required": False,
        "signal_name": "left_window_down",
        "did_hex": "5057",
        "control_param": IOCP_SHORT_TERM_ADJ,
        "on_data": b"\xFF",
        "off_data": b"\x00",
        "caution_level": "warn",
        "description": "Left front window down",
    },
]


def get_verified_dids_for_manufacturer(manufacturer: str) -> List[Dict[str, Any]]:
    """Return verified actuator DIDs for a manufacturer.

    Args:
        manufacturer: e.g. "stellantis", "ford", "gm"

    Returns:
        List of actuator DID dicts matching the manufacturer.
    """
    mfr = manufacturer.lower()
    return [d for d in VERIFIED_ACTUATOR_DIDS if d["manufacturer"] == mfr]
