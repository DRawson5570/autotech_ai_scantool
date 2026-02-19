"""
ELM327 Connection Management

Handles Bluetooth, WiFi, and USB connections to ELM327 adapters.

Connection Types:
    - Bluetooth: /dev/rfcomm0 (Linux) or COM port (Windows)
    - WiFi: TCP to 192.168.0.10:35000 (typical ELM327 WiFi)
    - USB: /dev/ttyUSB0 (Linux) or COM port (Windows)
"""

import asyncio
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Optional

logger = logging.getLogger(__name__)


class ConnectionType(Enum):
    """ELM327 connection types."""
    BLUETOOTH = "bluetooth"
    WIFI = "wifi"
    USB = "usb"
    SERIAL = "serial"  # Generic serial (could be BT or USB)


@dataclass
class ConnectionConfig:
    """Connection configuration."""
    connection_type: ConnectionType
    address: str  # Device path or IP:port
    baudrate: int = 38400  # For serial connections
    timeout: float = 5.0
    
    # WiFi-specific
    wifi_port: int = 35000
    
    # Bluetooth-specific
    bt_channel: int = 1


class ELM327Connection(ABC):
    """Abstract base class for ELM327 connections."""
    
    def __init__(self, config: ConnectionConfig):
        self.config = config
        self._connected = False
        self._reader: Optional[asyncio.StreamReader] = None
        self._writer: Optional[asyncio.StreamWriter] = None
    
    @property
    def connected(self) -> bool:
        return self._connected
    
    @abstractmethod
    async def connect(self) -> bool:
        """Establish connection to ELM327 adapter."""
        pass
    
    @abstractmethod
    async def disconnect(self) -> None:
        """Close connection."""
        pass
    
    async def send_command(self, command: str, timeout: Optional[float] = None) -> str:
        """
        Send AT or OBD command and return response.
        
        Args:
            command: Command string (e.g., "ATZ", "0100")
            timeout: Response timeout in seconds
            
        Returns:
            Response string with prompt removed
        """
        if not self._connected or not self._writer:
            raise ConnectionError("Not connected to ELM327")
        
        timeout = timeout or self.config.timeout
        
        # Send command with carriage return
        cmd_bytes = f"{command}\r".encode('ascii')
        self._writer.write(cmd_bytes)
        await self._writer.drain()
        
        logger.debug(f"Sent: {command}")
        
        # Read response until prompt (>)
        response = await self._read_until_prompt(timeout)
        logger.debug(f"Received: {response}")
        
        return response
    
    async def _read_until_prompt(self, timeout: float) -> str:
        """Read response until ELM327 prompt (>)."""
        if not self._reader:
            raise ConnectionError("Reader not initialized")
        
        buffer = b""
        try:
            while True:
                chunk = await asyncio.wait_for(
                    self._reader.read(1024),
                    timeout=timeout
                )
                if not chunk:
                    break
                buffer += chunk
                if b">" in buffer:
                    break
        except asyncio.TimeoutError:
            logger.warning(f"Timeout reading response, got: {buffer}")
        
        # Decode and clean response
        response = buffer.decode('ascii', errors='ignore')
        response = response.replace('\r', '\n').strip()
        response = response.rstrip('>')
        
        # Remove echo if present (command echoed back)
        lines = [l.strip() for l in response.split('\n') if l.strip()]
        if lines and not lines[0].startswith('4') and not lines[0].startswith('7E'):
            # OBD responses start with 4x (no headers) or 7Ex (with CAN headers)
            lines = lines[1:]  # Remove echo
        
        return '\n'.join(lines)


class SerialConnection(ELM327Connection):
    """Serial port connection (USB or Bluetooth serial)."""
    
    def __init__(self, config: ConnectionConfig):
        super().__init__(config)
        self._serial = None
    
    # Common baud rates for ELM327 adapters (ordered by likelihood)
    BAUD_RATES = [38400, 9600, 115200, 57600, 19200]
    
    async def connect(self) -> bool:
        """Connect via serial port with baud rate auto-detection."""
        try:
            import serial_asyncio
            
            # Try the configured baud rate first, then others
            rates_to_try = [self.config.baudrate] + [
                r for r in self.BAUD_RATES if r != self.config.baudrate
            ]
            
            for baudrate in rates_to_try:
                logger.info(f"Trying baud rate {baudrate} on {self.config.address}...")
                try:
                    # Close previous attempt if any
                    if self._writer:
                        try:
                            self._writer.close()
                            await self._writer.wait_closed()
                        except Exception:
                            pass
                        self._writer = None
                        self._reader = None
                    
                    self._reader, self._writer = await serial_asyncio.open_serial_connection(
                        url=self.config.address,
                        baudrate=baudrate,
                    )
                    self._connected = True
                    
                    # Quick poke: send CR and wait briefly for any response
                    self._writer.write(b"\r\n")
                    await self._writer.drain()
                    try:
                        await asyncio.wait_for(self._reader.read(1024), timeout=1.5)
                    except asyncio.TimeoutError:
                        pass
                    
                    # Quick test: send ATI and see if we get a real response
                    response = await self.send_command("ATI", timeout=2.0)
                    if response and "ELM" in response.upper():
                        logger.info(f"ELM327 detected at {baudrate} baud: {response}")
                        self.config.baudrate = baudrate
                        await self._initialize()
                        logger.info(f"Connected to ELM327 via serial: {self.config.address} @ {baudrate}")
                        return True
                    elif response:
                        logger.info(f"Got response at {baudrate} but not ELM327: {response[:50]}")
                        self.config.baudrate = baudrate
                        await self._initialize()
                        logger.info(f"Connected to ELM327 via serial: {self.config.address} @ {baudrate}")
                        return True
                    else:
                        logger.info(f"No response at {baudrate} baud")
                        
                except Exception as e:
                    logger.warning(f"Baud {baudrate} failed: {e}")
            
            logger.error(f"ELM327 not responding at any baud rate on {self.config.address}")
            self._connected = False
            return False
            
        except ImportError:
            logger.error("pyserial-asyncio not installed. Run: pip install pyserial-asyncio")
            return False
        except Exception as e:
            logger.error(f"Serial connection failed: {e}")
            return False
    
    async def disconnect(self) -> None:
        """Close serial connection."""
        if self._writer:
            self._writer.close()
            await self._writer.wait_closed()
        self._connected = False
        logger.info("Serial connection closed")
    
    async def _wake_up(self) -> None:
        """
        Wake up Bluetooth ELM327 adapters.
        
        Cheap BT clones drop into sleep after pairing. Windows scan tools
        keep them awake by sending CR bytes. We do the same: send CRs
        and wait for the '>' prompt, retrying several times.
        """
        logger.info("Waking up ELM327 (Bluetooth wake sequence)...")
        
        for attempt in range(5):
            try:
                # Send bare carriage return to poke the adapter
                self._writer.write(b"\r\n")
                await self._writer.drain()
                
                # Wait for any response (even partial)
                buffer = b""
                try:
                    chunk = await asyncio.wait_for(
                        self._reader.read(1024),
                        timeout=2.0
                    )
                    buffer = chunk or b""
                except asyncio.TimeoutError:
                    pass
                
                if buffer:
                    decoded = buffer.decode('ascii', errors='ignore').strip()
                    logger.info(f"Wake attempt {attempt + 1}: got response ({len(buffer)} bytes): {decoded[:50]}")
                    return  # Adapter is awake
                else:
                    logger.info(f"Wake attempt {attempt + 1}: no response, retrying...")
                    await asyncio.sleep(1.0)
                    
            except Exception as e:
                logger.warning(f"Wake attempt {attempt + 1} error: {e}")
                await asyncio.sleep(1.0)
        
        logger.warning("ELM327 did not respond to wake sequence, proceeding anyway...")
    
    async def _initialize(self) -> None:
        """Initialize ELM327 adapter."""
        # Reset - use longer timeout for Bluetooth adapters
        await self.send_command("ATZ", timeout=10.0)
        await asyncio.sleep(2.0)  # Give it time to reset (BT clones are slow)
        
        # Disable echo
        await self.send_command("ATE0")
        
        # Disable linefeeds
        await self.send_command("ATL0")
        
        # Disable spaces in responses
        await self.send_command("ATS0")
        
        # Auto-detect protocol
        await self.send_command("ATSP0")
        
        logger.debug("ELM327 initialized")


class WiFiConnection(ELM327Connection):
    """WiFi connection to ELM327 adapter."""
    
    async def connect(self) -> bool:
        """Connect via WiFi (TCP)."""
        try:
            # Parse address
            if ':' in self.config.address:
                host, port_str = self.config.address.split(':')
                port = int(port_str)
            else:
                host = self.config.address
                port = self.config.wifi_port
            
            self._reader, self._writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.config.timeout
            )
            self._connected = True
            
            # Initialize ELM327
            await self._initialize()
            
            logger.info(f"Connected to ELM327 via WiFi: {host}:{port}")
            return True
            
        except Exception as e:
            logger.error(f"WiFi connection failed: {e}")
            return False
    
    async def disconnect(self) -> None:
        """Close WiFi connection."""
        if self._writer:
            self._writer.close()
            await self._writer.wait_closed()
        self._connected = False
        logger.info("WiFi connection closed")
    
    async def _initialize(self) -> None:
        """Initialize ELM327 adapter."""
        # Reset
        await self.send_command("ATZ", timeout=3.0)
        await asyncio.sleep(1.0)
        
        # Disable echo
        await self.send_command("ATE0")
        
        # Disable linefeeds  
        await self.send_command("ATL0")
        
        # Disable spaces
        await self.send_command("ATS0")
        
        # Auto-detect protocol
        await self.send_command("ATSP0")
        
        logger.debug("ELM327 initialized")


def create_connection(
    connection_type: ConnectionType,
    address: str,
    **kwargs
) -> ELM327Connection:
    """
    Factory function to create appropriate connection.
    
    Args:
        connection_type: Type of connection (bluetooth, wifi, usb, serial)
        address: Device path or IP address
        **kwargs: Additional connection config
        
    Returns:
        Configured ELM327Connection instance
    """
    config = ConnectionConfig(
        connection_type=connection_type,
        address=address,
        **kwargs
    )
    
    if connection_type in (ConnectionType.BLUETOOTH, ConnectionType.USB, ConnectionType.SERIAL):
        return SerialConnection(config)
    elif connection_type == ConnectionType.WIFI:
        return WiFiConnection(config)
    else:
        raise ValueError(f"Unknown connection type: {connection_type}")


# Default addresses for common configurations
DEFAULT_ADDRESSES = {
    ConnectionType.BLUETOOTH: "/dev/rfcomm0",  # Linux Bluetooth serial
    ConnectionType.WIFI: "192.168.0.10:35000",  # Common WiFi ELM327
    ConnectionType.USB: "/dev/ttyUSB0",  # Linux USB serial
}
