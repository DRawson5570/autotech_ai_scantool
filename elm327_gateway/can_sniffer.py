"""
CAN Bus Sniffer — Passive traffic capture and UDS exchange parser.

Parses raw CAN frames from STN2120 STMA (Monitor All) mode into
structured UDS request/response exchanges. Used for reverse-engineering
professional scan tool DID reads.

Typical STMA output lines:
    7E0 03 22 D0 02          ← UDS request (ReadDataByIdentifier)
    7E8 06 62 D0 02 1F FE    ← UDS positive response

This module:
1. Parses raw lines into CANFrame objects
2. Matches request→response by arb ID (7E0→7E8, 760→768, etc.)
3. Extracts UDS Service 0x22 ReadDataByIdentifier exchanges
4. Handles ISO-TP multi-frame reassembly for long responses
5. Groups captured DIDs by module for organized output
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────
# CAN frame data structures
# ─────────────────────────────────────────────────────────────

@dataclass
class CANFrame:
    """A single CAN bus frame."""
    timestamp: float          # monotonic timestamp
    arb_id: int               # arbitration ID (e.g. 0x7E0)
    data: bytes               # raw data bytes
    raw_line: str = ""        # original text from adapter

    @property
    def arb_id_hex(self) -> str:
        return f"{self.arb_id:03X}"

    @property
    def data_hex(self) -> str:
        return " ".join(f"{b:02X}" for b in self.data)

    @property
    def is_request(self) -> bool:
        """True if this frame is a tester request (even arb ID in UDS range)."""
        return 0x700 <= self.arb_id <= 0x7FF and (self.arb_id & 0x08) == 0

    @property
    def is_response(self) -> bool:
        """True if this frame is an ECU response (request + 0x08)."""
        return 0x700 <= self.arb_id <= 0x7FF and (self.arb_id & 0x08) != 0

    @property
    def response_id(self) -> int:
        """Expected response arb ID for this request."""
        return self.arb_id + 0x08

    @property
    def request_id(self) -> int:
        """Expected request arb ID for this response."""
        return self.arb_id - 0x08


@dataclass
class UDSExchange:
    """A matched UDS request/response pair."""
    timestamp: float
    module_addr: int          # request address (e.g. 0x7E0)
    service: int              # UDS service ID (e.g. 0x22)
    did: Optional[int] = None # DID if service 0x22
    request_data: bytes = b""
    response_data: bytes = b""
    positive: bool = False    # True if positive response
    nrc: Optional[int] = None # Negative Response Code if negative

    @property
    def module_hex(self) -> str:
        return f"0x{self.module_addr:03X}"

    @property
    def did_hex(self) -> str:
        if self.did is not None:
            return f"{self.did:04X}"
        return ""

    @property
    def response_hex(self) -> str:
        return self.response_data.hex().upper()

    def to_dict(self) -> dict:
        return {
            "module": self.module_hex,
            "service": f"0x{self.service:02X}",
            "did": self.did_hex,
            "positive": self.positive,
            "nrc": f"0x{self.nrc:02X}" if self.nrc else None,
            "request": self.request_data.hex().upper(),
            "response": self.response_hex,
            "timestamp": self.timestamp,
        }


@dataclass
class SnifferCapture:
    """Accumulated capture session."""
    started_at: float = 0.0
    bus: str = "HS-CAN"
    frames: List[CANFrame] = field(default_factory=list)
    exchanges: List[UDSExchange] = field(default_factory=list)
    # Labels applied by user: (module_hex, did_hex) -> label
    labels: Dict[Tuple[str, str], str] = field(default_factory=dict)

    @property
    def duration_seconds(self) -> float:
        if not self.frames:
            return 0.0
        return self.frames[-1].timestamp - self.started_at

    def get_unique_dids(self) -> Dict[str, Set[str]]:
        """Group unique DIDs by module address. Returns {module_hex: {did_hex, ...}}."""
        result: Dict[str, Set[str]] = {}
        for ex in self.exchanges:
            if ex.did is not None and ex.positive:
                module = ex.module_hex
                result.setdefault(module, set()).add(ex.did_hex)
        return result

    def get_did_data(self) -> Dict[str, Dict[str, dict]]:
        """Get latest data for each module/DID. Returns {module_hex: {did_hex: {data, label}}}."""
        result: Dict[str, Dict[str, dict]] = {}
        for ex in self.exchanges:
            if ex.did is not None and ex.positive:
                module = ex.module_hex
                did = ex.did_hex
                label = self.labels.get((module, did), "")
                mod_dids = result.setdefault(module, {})
                mod_dids[did] = {
                    "data": ex.response_hex,
                    "label": label,
                    "timestamp": ex.timestamp,
                }
        return result

    def to_summary(self) -> dict:
        """Summary for API response."""
        unique = self.get_unique_dids()
        total_unique = sum(len(dids) for dids in unique.values())
        labeled = sum(1 for v in self.labels.values() if v)

        modules_summary = {}
        for module, dids in unique.items():
            modules_summary[module] = {
                "did_count": len(dids),
                "dids": sorted(dids),
            }

        return {
            "bus": self.bus,
            "duration_seconds": round(self.duration_seconds, 1),
            "total_frames": len(self.frames),
            "total_exchanges": len(self.exchanges),
            "unique_dids": total_unique,
            "labeled": labeled,
            "modules": modules_summary,
        }


# ─────────────────────────────────────────────────────────────
# Frame parsing — STN2120 STMA output
# ─────────────────────────────────────────────────────────────

# STMA output format (with headers/spaces on): "7E0 03 22 D0 02"
_FRAME_RE = re.compile(
    r"^([0-9A-Fa-f]{3})\s+((?:[0-9A-Fa-f]{2}\s*)+)$"
)


def parse_stma_line(line: str, timestamp: float = 0.0) -> Optional[CANFrame]:
    """Parse a single STMA output line into a CAN frame.

    Args:
        line: Raw text line from STMA (e.g. "7E0 03 22 D0 02")
        timestamp: Monotonic timestamp for this frame

    Returns:
        CANFrame or None if line isn't a valid CAN frame
    """
    line = line.strip()
    if not line:
        return None

    m = _FRAME_RE.match(line)
    if not m:
        return None

    arb_id = int(m.group(1), 16)
    data_hex = m.group(2).strip()
    data_bytes = bytes.fromhex(data_hex.replace(" ", ""))

    return CANFrame(
        timestamp=timestamp,
        arb_id=arb_id,
        data=data_bytes,
        raw_line=line,
    )


def parse_stma_output(raw_output: str) -> List[CANFrame]:
    """Parse multi-line STMA output into CAN frames."""
    frames = []
    base_time = time.monotonic()
    for i, line in enumerate(raw_output.splitlines()):
        frame = parse_stma_line(line, timestamp=base_time + i * 0.001)
        if frame:
            frames.append(frame)
    return frames


# ─────────────────────────────────────────────────────────────
# ISO-TP multi-frame reassembly
# ─────────────────────────────────────────────────────────────

def _is_single_frame(data: bytes) -> bool:
    """Check if this is an ISO-TP single frame (PCI type 0)."""
    return len(data) > 0 and (data[0] & 0xF0) == 0x00

def _is_first_frame(data: bytes) -> bool:
    """Check if this is an ISO-TP first frame (PCI type 1)."""
    return len(data) > 1 and (data[0] & 0xF0) == 0x10

def _is_consecutive_frame(data: bytes) -> bool:
    """Check if this is an ISO-TP consecutive frame (PCI type 2)."""
    return len(data) > 0 and (data[0] & 0xF0) == 0x20

def _is_flow_control(data: bytes) -> bool:
    """Check if this is an ISO-TP flow control frame (PCI type 3)."""
    return len(data) > 0 and (data[0] & 0xF0) == 0x30

def _single_frame_length(data: bytes) -> int:
    """Get payload length from a single frame."""
    return data[0] & 0x0F

def _first_frame_length(data: bytes) -> int:
    """Get total payload length from a first frame."""
    return ((data[0] & 0x0F) << 8) | data[1]


def reassemble_isotp(frames: List[CANFrame]) -> bytes:
    """Reassemble ISO-TP multi-frame response into complete payload.

    Args:
        frames: Ordered CAN frames from the same arb ID (response side)

    Returns:
        Complete reassembled UDS payload
    """
    if not frames:
        return b""

    first = frames[0]

    # Single frame
    if _is_single_frame(first.data):
        length = _single_frame_length(first.data)
        return first.data[1:1 + length]

    # Multi-frame: first frame + consecutive frames
    if _is_first_frame(first.data):
        total_length = _first_frame_length(first.data)
        payload = bytearray(first.data[2:])  # FF payload starts at byte 2

        for cf in frames[1:]:
            if _is_consecutive_frame(cf.data):
                payload.extend(cf.data[1:])  # CF payload starts at byte 1
            elif _is_flow_control(cf.data):
                continue  # Skip FC frames

        return bytes(payload[:total_length])

    # Fallback: just the data
    return first.data


# ─────────────────────────────────────────────────────────────
# UDS exchange extraction
# ─────────────────────────────────────────────────────────────

def extract_uds_exchanges(frames: List[CANFrame]) -> List[UDSExchange]:
    """Extract UDS request/response exchanges from raw CAN frames.

    Matches tester requests with ECU responses and decodes UDS service layer.
    Handles both single-frame and multi-frame (ISO-TP) responses.

    Args:
        frames: List of parsed CAN frames (chronological order)

    Returns:
        List of UDSExchange objects for each matched req/resp pair
    """
    exchanges: List[UDSExchange] = []

    # Track pending requests: request_arb_id -> (CANFrame, service, did)
    pending: Dict[int, Tuple[CANFrame, int, Optional[int]]] = {}
    # Track multi-frame responses: response_arb_id -> [frames]
    multiframe: Dict[int, List[CANFrame]] = {}

    for frame in frames:
        # Skip flow control
        if _is_flow_control(frame.data):
            continue

        if frame.is_request and len(frame.data) >= 2:
            # Parse the tester request
            if _is_single_frame(frame.data):
                payload = frame.data[1:1 + _single_frame_length(frame.data)]
            else:
                payload = frame.data[1:]  # First frame of multi-frame request (rare)

            if len(payload) < 1:
                continue

            service = payload[0]
            did = None
            if service == 0x22 and len(payload) >= 3:
                did = (payload[1] << 8) | payload[2]

            pending[frame.arb_id] = (frame, service, did)
            # Clear any old multi-frame tracking for the expected response
            multiframe.pop(frame.response_id, None)

        elif frame.is_response:
            req_arb_id = frame.request_id

            # Check if this is part of a multi-frame response
            if _is_first_frame(frame.data):
                multiframe[frame.arb_id] = [frame]
                continue
            elif _is_consecutive_frame(frame.data):
                if frame.arb_id in multiframe:
                    multiframe[frame.arb_id].append(frame)
                    # Check if we have enough consecutive frames
                    # We'll process when the next request or a gap occurs
                continue

            # Single-frame response — match with pending request
            if req_arb_id in pending:
                req_frame, req_service, req_did = pending.pop(req_arb_id)

                if _is_single_frame(frame.data):
                    resp_payload = frame.data[1:1 + _single_frame_length(frame.data)]
                else:
                    resp_payload = frame.data

                exchange = _build_exchange(
                    req_frame, frame, req_service, req_did, resp_payload
                )
                if exchange:
                    exchanges.append(exchange)

        # Process completed multi-frame responses
        completed_mf = []
        for resp_arb_id, mf_frames in multiframe.items():
            if len(mf_frames) >= 2:  # At least FF + 1 CF
                ff = mf_frames[0]
                total_len = _first_frame_length(ff.data)
                collected = len(ff.data) - 2  # FF data
                for cf in mf_frames[1:]:
                    if _is_consecutive_frame(cf.data):
                        collected += len(cf.data) - 1

                if collected >= total_len:
                    # Complete — reassemble
                    resp_payload = reassemble_isotp(mf_frames)
                    req_arb_id = resp_arb_id - 0x08

                    if req_arb_id in pending:
                        req_frame, req_service, req_did = pending.pop(req_arb_id)
                        exchange = _build_exchange(
                            req_frame, mf_frames[-1], req_service, req_did,
                            resp_payload
                        )
                        if exchange:
                            exchanges.append(exchange)
                    completed_mf.append(resp_arb_id)

        for arb_id in completed_mf:
            multiframe.pop(arb_id, None)

    return exchanges


def _build_exchange(
    req_frame: CANFrame,
    resp_frame: CANFrame,
    service: int,
    did: Optional[int],
    resp_payload: bytes,
) -> Optional[UDSExchange]:
    """Build a UDSExchange from matched request/response."""
    if len(resp_payload) < 1:
        return None

    resp_sid = resp_payload[0]
    positive = resp_sid == (service + 0x40)  # Positive response SID
    nrc = None

    if resp_sid == 0x7F and len(resp_payload) >= 3:
        # Negative response: 7F <service> <NRC>
        nrc = resp_payload[2]
        # Skip "response pending" (NRC 0x78)
        if nrc == 0x78:
            return None
        return UDSExchange(
            timestamp=req_frame.timestamp,
            module_addr=req_frame.arb_id,
            service=service,
            did=did,
            request_data=req_frame.data,
            response_data=resp_payload,
            positive=False,
            nrc=nrc,
        )

    if positive:
        # For service 0x22, response is: 62 <DID_HI> <DID_LO> <data...>
        response_data = resp_payload[3:] if service == 0x22 and len(resp_payload) > 3 else resp_payload[1:]
        return UDSExchange(
            timestamp=req_frame.timestamp,
            module_addr=req_frame.arb_id,
            service=service,
            did=did,
            request_data=req_frame.data,
            response_data=response_data,
            positive=True,
        )

    return None


# ─────────────────────────────────────────────────────────────
# Module name resolution
# ─────────────────────────────────────────────────────────────

# Known module addresses → name
_MODULE_NAMES: Dict[int, str] = {
    0x7E0: "PCM", 0x7E1: "TCM", 0x7E2: "ABS", 0x7E3: "SRS",
    0x7E4: "BCM", 0x7E5: "HVAC",
    # Ford MS-CAN
    0x720: "PCM-MS", 0x726: "APIM", 0x727: "ACM",
    0x760: "GEM", 0x765: "ABS-MS", 0x7D0: "AWD",
    0x740: "IPC", 0x7A0: "HVAC-MS", 0x7B0: "TPMS",
    0x730: "PSCM", 0x770: "ACM-MS",
    0x744: "DDM", 0x745: "PDM", 0x736: "PAM",
    0x724: "SCCM", 0x701: "GPSM",
    # GM
    0x7E2: "ABS/ESC", 0x244: "BCM-GM",
}


def module_name_for_addr(addr: int) -> str:
    """Get a human-readable module name for a CAN request address."""
    return _MODULE_NAMES.get(addr, f"0x{addr:03X}")


def bus_name_for_addr(addr: int) -> str:
    """Guess the bus name from the address."""
    if 0x700 <= addr <= 0x720:
        return "MS-CAN"
    if 0x724 <= addr <= 0x7CF:
        return "MS-CAN"
    return "HS-CAN"
