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
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


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


class UDSBidirectional:
    """
    UDS (ISO 14229) bidirectional control.
    
    This provides Tier 3 control using service 0x2F (InputOutputControlByIdentifier).
    Requires manufacturer-specific DIDs and often security access.
    
    Note: This is a placeholder for advanced functionality.
    Most vehicles require proprietary protocols for full bidirectional control.
    """
    
    def __init__(self, protocol):
        """Initialize UDS controller."""
        self.protocol = protocol
        self._security_unlocked = False
    
    async def unlock_security(self, level: int = 0x01) -> bool:
        """
        Attempt UDS security access.
        
        This is highly vehicle-specific and usually requires
        manufacturer seed/key algorithms.
        
        Args:
            level: Security level (odd number for seed request)
            
        Returns:
            True if unlocked
        """
        # Request seed
        cmd = f"27{level:02X}"
        response = await self.protocol.connection.send_command(cmd)
        
        if "67" not in response:
            logger.warning("Security access not supported")
            return False
        
        # Would need manufacturer-specific key calculation here
        logger.warning("UDS security requires manufacturer key algorithm")
        return False
    
    async def control_by_identifier(
        self,
        did: int,
        control_param: int,
        data: bytes = b''
    ) -> bool:
        """
        UDS 0x2F InputOutputControlByIdentifier.
        
        Args:
            did: Data Identifier (2 bytes)
            control_param: Control option
                0x00 = Return Control To ECU
                0x01 = Reset To Default
                0x02 = Freeze Current State
                0x03 = Short Term Adjustment
            data: Optional control data
            
        Returns:
            True if command accepted
        """
        if not self._security_unlocked:
            logger.warning("UDS control requires security access")
            return False
        
        cmd = f"2F{did:04X}{control_param:02X}"
        if data:
            cmd += data.hex().upper()
        
        response = await self.protocol.connection.send_command(cmd)
        return "6F" in response  # Positive response
    
    async def return_control_to_ecu(self, did: int) -> bool:
        """Return control of a DID to the ECU."""
        return await self.control_by_identifier(did, 0x00)


# Common manufacturer-specific DIDs for IO control (UDS service 0x2F)
# ISO 14229-1:2020 ranges:
#   0x0100-0xA5FF = Vehicle manufacturer specific (GM uses low range)
#   0xF010-0xF0FF = Vehicle manufacturer specific (Ford uses F0xx)
# These require proper security access and vary by model year and module
COMMON_UDS_DIDS = {
    # GM (0x01xx range — vehicle manufacturer specific)
    'gm_fuel_pump': 0x0100,
    'gm_cooling_fan_1': 0x0101,
    'gm_cooling_fan_2': 0x0102,
    'gm_ac_clutch': 0x0103,

    # Ford (0xF0xx range — vehicle manufacturer specific)
    'ford_fuel_pump': 0xF010,
    'ford_cooling_fan': 0xF011,

    # Note: These are examples — actual DIDs vary by model year and module
}
