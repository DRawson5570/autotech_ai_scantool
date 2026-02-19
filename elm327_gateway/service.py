"""
ELM327 Service - Main API

High-level interface for OBD-II diagnostics via ELM327 adapters.

Usage:
    async with ELM327Service() as elm:
        await elm.connect('wifi', '192.168.0.10:35000')
        
        # Read vehicle info
        vin = await elm.read_vin()
        dtcs = await elm.read_dtcs()
        
        # Monitor live data
        data = await elm.read_pids(['RPM', 'COOLANT_TEMP', 'STFT_B1', 'STFT_B2'])
        
        # Diagnostic snapshot
        snapshot = await elm.capture_diagnostic_snapshot()
"""

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Union

from .connection import (
    ConnectionType,
    ELM327Connection,
    create_connection,
    DEFAULT_ADDRESSES,
)
from .protocol import OBDProtocol, DTC, get_dtc_description
from .pids import (
    PIDRegistry,
    PIDDefinition,
    get_pid_by_name,
    DIAGNOSTIC_SNAPSHOT_PIDS,
    FUEL_TRIM_PIDS,
    OXYGEN_PIDS,
    TEMPERATURE_PIDS,
)
from .bidirectional import ActuatorControl, ActuatorType, ActuatorState

logger = logging.getLogger(__name__)


@dataclass
class PIDReading:
    """A single PID reading with metadata."""
    pid: int
    name: str
    value: float
    unit: str
    timestamp: datetime = field(default_factory=datetime.now)
    
    def __str__(self) -> str:
        return f"{self.name}: {self.value:.2f} {self.unit}"


@dataclass
class DiagnosticSnapshot:
    """Complete diagnostic snapshot."""
    timestamp: datetime
    vin: Optional[str]
    dtcs: List[DTC]
    pending_dtcs: List[DTC]
    pids: Dict[str, PIDReading]
    supported_pids: List[int]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            'timestamp': self.timestamp.isoformat(),
            'vin': self.vin,
            'dtcs': [{'code': d.code, 'status': d.status, 
                     'description': get_dtc_description(d.code)} for d in self.dtcs],
            'pending_dtcs': [{'code': d.code, 'status': d.status,
                            'description': get_dtc_description(d.code)} for d in self.pending_dtcs],
            'pids': {name: {'value': r.value, 'unit': r.unit} 
                    for name, r in self.pids.items()},
            'supported_pids': self.supported_pids,
        }


class ELM327Service:
    """
    High-level ELM327 service for OBD-II diagnostics.
    
    Provides:
    - Connection management (Bluetooth, WiFi, USB)
    - DTC reading and clearing
    - Live PID monitoring
    - Diagnostic snapshots
    - Actuator control (where supported)
    """
    
    def __init__(self):
        """Initialize ELM327 service."""
        self._connection: Optional[ELM327Connection] = None
        self._protocol: Optional[OBDProtocol] = None
        self._actuator_control: Optional[ActuatorControl] = None
        self._supported_pids: List[int] = []
        self._vin: Optional[str] = None
    
    @property
    def connected(self) -> bool:
        """Check if connected to adapter."""
        return self._connection is not None and self._connection.connected
    
    @property
    def vin(self) -> Optional[str]:
        """Get cached VIN."""
        return self._vin
    
    # -------------------------------------------------------------------------
    # Context Manager Support
    # -------------------------------------------------------------------------
    
    async def __aenter__(self) -> 'ELM327Service':
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.disconnect()
    
    # -------------------------------------------------------------------------
    # Connection Management
    # -------------------------------------------------------------------------
    
    async def connect(
        self,
        connection_type: Union[str, ConnectionType],
        address: Optional[str] = None,
        **kwargs
    ) -> bool:
        """
        Connect to ELM327 adapter.
        
        Args:
            connection_type: 'bluetooth', 'wifi', 'usb', or 'serial'
            address: Device address or path (uses default if not provided)
            **kwargs: Additional connection parameters
            
        Returns:
            True if connected successfully
        """
        # Convert string to enum
        if isinstance(connection_type, str):
            connection_type = ConnectionType(connection_type.lower())
        
        # Use default address if not provided
        if address is None:
            address = DEFAULT_ADDRESSES.get(connection_type)
            if address is None:
                raise ValueError(f"No default address for {connection_type}")
        
        logger.info(f"Connecting to ELM327 via {connection_type.value}: {address}")
        
        # Create connection
        self._connection = create_connection(connection_type, address, **kwargs)
        
        # Attempt connection
        if not await self._connection.connect():
            logger.error("Failed to connect to ELM327")
            self._connection = None
            return False
        
        # Initialize protocol handler
        self._protocol = OBDProtocol(self._connection)
        self._actuator_control = ActuatorControl(self._protocol)
        
        # Get supported PIDs
        try:
            self._supported_pids = await self._protocol.get_supported_pids()
            logger.info(f"Vehicle supports {len(self._supported_pids)} PIDs")
        except Exception as e:
            logger.warning(f"Could not query supported PIDs: {e}")
        
        # Try to read VIN
        try:
            self._vin = await self._protocol.read_vin()
            if self._vin:
                logger.info(f"Vehicle VIN: {self._vin}")
        except Exception as e:
            logger.debug(f"Could not read VIN: {e}")
        
        return True
    
    async def disconnect(self) -> None:
        """Disconnect from ELM327 adapter."""
        if self._actuator_control:
            await self._actuator_control.release_all()
            self._actuator_control = None
        
        if self._connection:
            await self._connection.disconnect()
            self._connection = None
        
        self._protocol = None
        logger.info("Disconnected from ELM327")
    
    # -------------------------------------------------------------------------
    # Vehicle Information
    # -------------------------------------------------------------------------
    
    async def read_vin(self) -> Optional[str]:
        """
        Read Vehicle Identification Number.
        
        Returns:
            17-character VIN or None
        """
        self._ensure_connected()
        self._vin = await self._protocol.read_vin()
        return self._vin
    
    async def get_supported_pids(self) -> List[int]:
        """
        Get list of supported PIDs.
        
        Returns:
            List of PID numbers supported by vehicle
        """
        self._ensure_connected()
        if not self._supported_pids:
            self._supported_pids = await self._protocol.get_supported_pids()
        return self._supported_pids
    
    async def scan_modules(self) -> list:
        """
        Discover all ECU modules on the CAN bus and enumerate
        each module's supported PIDs.
        
        Uses cached VIN (if available) to determine which secondary
        buses to probe — e.g., Ford gets MS-CAN, others skip it.
        
        Returns:
            List of ECUModule objects with supported_pids populated
        """
        self._ensure_connected()
        return await self._protocol.scan_all_modules(vin=self._vin)
    
    async def read_did(self, module_addr: int, did: int, bus: str = "HS-CAN") -> Optional[str]:
        """
        Read a single UDS DID from a specific module.
        
        Args:
            module_addr: CAN request address (e.g. 0x760 for GEM)
            did: DID number (e.g. 0xF190 for VIN)
            bus: "HS-CAN" or "MS-CAN"
            
        Returns:
            DID value as string, or None
        """
        self._ensure_connected()
        return await self._protocol.read_did(module_addr, did, bus=bus)
    
    async def read_dids(self, module_addr: int, dids: list, bus: str = "HS-CAN") -> dict:
        """
        Read multiple UDS DIDs from a specific module.
        
        Args:
            module_addr: CAN request address
            dids: List of DID numbers
            bus: "HS-CAN" or "MS-CAN"
            
        Returns:
            Dict mapping DID label to value string
        """
        self._ensure_connected()
        return await self._protocol.read_dids(module_addr, dids, bus=bus)
    
    # -------------------------------------------------------------------------
    # DTC Operations
    # -------------------------------------------------------------------------
    
    async def read_dtcs(self) -> List[DTC]:
        """
        Read stored Diagnostic Trouble Codes.
        
        Returns:
            List of DTC objects with codes and descriptions
        """
        self._ensure_connected()
        dtcs = await self._protocol.read_dtcs()
        
        # Add descriptions, preserving ECU source tag from parser
        for dtc in dtcs:
            ecu_tag = dtc.description if dtc.description.startswith('[') else ''
            desc = get_dtc_description(dtc.code)
            dtc.description = f"{desc} {ecu_tag}".strip()
        
        logger.info(f"Read {len(dtcs)} stored DTCs")
        return dtcs
    
    async def read_pending_dtcs(self) -> List[DTC]:
        """
        Read pending DTCs (current drive cycle).
        
        Returns:
            List of pending DTC objects
        """
        self._ensure_connected()
        dtcs = await self._protocol.read_pending_dtcs()
        
        for dtc in dtcs:
            ecu_tag = dtc.description if dtc.description.startswith('[') else ''
            desc = get_dtc_description(dtc.code)
            dtc.description = f"{desc} {ecu_tag}".strip()
        
        logger.info(f"Read {len(dtcs)} pending DTCs")
        return dtcs
    
    async def read_permanent_dtcs(self) -> List[DTC]:
        """
        Read permanent DTCs (survive clear).
        
        Returns:
            List of permanent DTC objects
        """
        self._ensure_connected()
        dtcs = await self._protocol.read_permanent_dtcs()
        
        for dtc in dtcs:
            ecu_tag = dtc.description if dtc.description.startswith('[') else ''
            desc = get_dtc_description(dtc.code)
            dtc.description = f"{desc} {ecu_tag}".strip()
        
        logger.info(f"Read {len(dtcs)} permanent DTCs")
        return dtcs
    
    async def read_all_dtcs(self) -> Dict[str, List[DTC]]:
        """
        Read all DTCs (stored, pending, permanent).
        
        Returns:
            Dict with 'stored', 'pending', 'permanent' lists
        """
        stored = await self.read_dtcs()
        pending = await self.read_pending_dtcs()
        permanent = await self.read_permanent_dtcs()
        
        return {
            'stored': stored,
            'pending': pending,
            'permanent': permanent,
        }
    
    async def clear_dtcs(self) -> bool:
        """
        Clear stored DTCs and freeze frame.
        
        WARNING: This clears the check engine light. Only do this
        after repairs have been made.
        
        Returns:
            True if successful
        """
        self._ensure_connected()
        logger.warning("Clearing DTCs and freeze frame data")
        return await self._protocol.clear_dtcs()
    
    # -------------------------------------------------------------------------
    # PID Reading
    # -------------------------------------------------------------------------
    
    async def read_pid(self, pid: Union[int, str]) -> Optional[PIDReading]:
        """
        Read a single PID value.
        
        Args:
            pid: PID number or name (e.g., 0x0C or 'RPM')
            
        Returns:
            PIDReading with decoded value, or None if not supported
        """
        self._ensure_connected()
        
        # Resolve PID name to number
        if isinstance(pid, str):
            pid_num = get_pid_by_name(pid)
            if pid_num is None:
                logger.warning(f"Unknown PID name: {pid}")
                return None
        else:
            pid_num = pid
        
        # Get PID definition
        defn = PIDRegistry.get(pid_num)
        if not defn:
            logger.warning(f"No definition for PID 0x{pid_num:02X}")
            return None
        
        # Read raw data
        data = await self._protocol.read_pid(pid_num)
        if data is None:
            return None
        
        # Decode value
        value = defn.decode(data)
        
        return PIDReading(
            pid=pid_num,
            name=defn.name,
            value=value,
            unit=defn.unit,
        )
    
    async def read_pids(
        self,
        pids: List[Union[int, str]]
    ) -> Dict[str, PIDReading]:
        """
        Read multiple PIDs.
        
        Args:
            pids: List of PID numbers or names
            
        Returns:
            Dict mapping PID name to PIDReading
        """
        self._ensure_connected()
        results = {}
        
        for pid in pids:
            reading = await self.read_pid(pid)
            if reading:
                results[reading.name] = reading
        
        return results
    
    async def read_fuel_trims(self) -> Dict[str, PIDReading]:
        """
        Read all fuel trim PIDs.
        
        Returns:
            Dict with STFT_B1, LTFT_B1, STFT_B2, LTFT_B2
        """
        return await self.read_pids(['STFT_B1', 'LTFT_B1', 'STFT_B2', 'LTFT_B2'])
    
    async def read_temperatures(self) -> Dict[str, PIDReading]:
        """
        Read all temperature PIDs.
        
        Returns:
            Dict with COOLANT_TEMP, IAT, OIL_TEMP, etc.
        """
        return await self.read_pids(['COOLANT_TEMP', 'IAT', 'OIL_TEMP', 'AMBIENT_TEMP'])
    
    # -------------------------------------------------------------------------
    # Monitoring
    # -------------------------------------------------------------------------
    
    async def monitor_pids(
        self,
        pids: List[Union[int, str]],
        duration: float,
        interval: float = 0.5,
        callback: Optional[callable] = None
    ) -> List[Dict[str, PIDReading]]:
        """
        Monitor PIDs over time.
        
        Args:
            pids: PIDs to monitor
            duration: Total monitoring time in seconds
            interval: Sample interval in seconds
            callback: Optional callback(readings) for each sample
            
        Returns:
            List of reading dictionaries over time
        """
        self._ensure_connected()
        
        samples = []
        start_time = asyncio.get_event_loop().time()
        
        while (asyncio.get_event_loop().time() - start_time) < duration:
            readings = await self.read_pids(pids)
            samples.append(readings)
            
            if callback:
                callback(readings)
            
            await asyncio.sleep(interval)
        
        logger.info(f"Collected {len(samples)} samples over {duration}s")
        return samples
    
    async def wait_for_condition(
        self,
        pid: Union[int, str],
        condition: callable,
        timeout: float = 30.0,
        interval: float = 0.2
    ) -> Optional[PIDReading]:
        """
        Wait for a PID to meet a condition.
        
        Args:
            pid: PID to monitor
            condition: Function(value) -> bool
            timeout: Max wait time in seconds
            interval: Check interval in seconds
            
        Returns:
            PIDReading when condition met, or None if timeout
            
        Example:
            # Wait for RPM to exceed 2500
            await elm.wait_for_condition('RPM', lambda v: v > 2500)
        """
        self._ensure_connected()
        
        start_time = asyncio.get_event_loop().time()
        
        while (asyncio.get_event_loop().time() - start_time) < timeout:
            reading = await self.read_pid(pid)
            if reading and condition(reading.value):
                return reading
            await asyncio.sleep(interval)
        
        logger.warning(f"Timeout waiting for condition on {pid}")
        return None
    
    # -------------------------------------------------------------------------
    # Diagnostic Snapshots
    # -------------------------------------------------------------------------
    
    async def capture_diagnostic_snapshot(self) -> DiagnosticSnapshot:
        """
        Capture comprehensive diagnostic snapshot.
        
        Includes:
        - VIN
        - All DTCs (stored, pending)
        - Common diagnostic PIDs
        - Supported PID list
        
        Returns:
            DiagnosticSnapshot object
        """
        self._ensure_connected()
        
        logger.info("Capturing diagnostic snapshot...")
        
        # Read VIN
        vin = await self.read_vin()
        
        # Read DTCs
        dtcs = await self.read_dtcs()
        pending = await self.read_pending_dtcs()
        
        # Read standard diagnostic PIDs
        pids = {}
        for pid_num in DIAGNOSTIC_SNAPSHOT_PIDS:
            if pid_num in self._supported_pids:
                reading = await self.read_pid(pid_num)
                if reading:
                    pids[reading.name] = reading
        
        snapshot = DiagnosticSnapshot(
            timestamp=datetime.now(),
            vin=vin,
            dtcs=dtcs,
            pending_dtcs=pending,
            pids=pids,
            supported_pids=self._supported_pids.copy(),
        )
        
        logger.info(f"Snapshot: {len(dtcs)} DTCs, {len(pids)} PIDs")
        return snapshot
    
    # -------------------------------------------------------------------------
    # Actuator Control
    # -------------------------------------------------------------------------
    
    async def actuator_test(
        self,
        actuator: Union[str, ActuatorType],
        state: Union[str, ActuatorState],
        duration: Optional[float] = None
    ) -> bool:
        """
        Control an actuator (where supported).
        
        Args:
            actuator: Actuator name or ActuatorType
            state: 'on', 'off', or ActuatorState
            duration: Auto-release after seconds
            
        Returns:
            True if command accepted
        """
        self._ensure_connected()
        
        if not self._actuator_control:
            logger.warning("Actuator control not available")
            return False
        
        # Convert strings to enums
        if isinstance(actuator, str):
            actuator = ActuatorType(actuator.lower())
        if isinstance(state, str):
            state = ActuatorState(state.lower())
        
        return await self._actuator_control.control(actuator, state, duration)
    
    async def test_cooling_fan(self, duration: float = 10.0) -> bool:
        """Test cooling fan operation."""
        self._ensure_connected()
        if self._actuator_control:
            return await self._actuator_control.test_cooling_fan(duration)
        return False
    
    # -------------------------------------------------------------------------
    # Helper Methods
    # -------------------------------------------------------------------------
    
    def _ensure_connected(self) -> None:
        """Raise error if not connected."""
        if not self.connected:
            raise ConnectionError("Not connected to ELM327 adapter")
    
    async def send_raw_command(self, command: str) -> str:
        """
        Send raw AT or OBD command.
        
        For advanced users only.
        
        Args:
            command: Raw command string
            
        Returns:
            Raw response string
        """
        self._ensure_connected()
        return await self._connection.send_command(command)


# Convenience function for simple scripts
async def quick_scan(
    connection_type: str = 'wifi',
    address: Optional[str] = None
) -> DiagnosticSnapshot:
    """
    Quick diagnostic scan.
    
    Args:
        connection_type: 'wifi', 'bluetooth', or 'usb'
        address: Device address (uses default if not provided)
        
    Returns:
        DiagnosticSnapshot
        
    Example:
        snapshot = await quick_scan('wifi', '192.168.0.10:35000')
        print(f"VIN: {snapshot.vin}")
        for dtc in snapshot.dtcs:
            print(f"  {dtc.code}: {dtc.description}")
    """
    async with ELM327Service() as elm:
        await elm.connect(connection_type, address)
        return await elm.capture_diagnostic_snapshot()
