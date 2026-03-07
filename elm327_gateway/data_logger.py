"""
Data Logger — Continuous PID Recording with Triggers

Records live vehicle PID data to timestamped CSV/JSON files for later
analysis. Supports configurable triggers (PID threshold, time-based,
DTC appearance) and automatic session management.

Features:
 - Continuous PID sampling at configurable intervals (100ms-5s)
 - Trigger-based recording (start/stop on PID threshold, DTC event)
 - Multiple log formats: CSV (spreadsheet-friendly), JSON (machine-readable)
 - Session metadata (VIN, date, duration, trigger info)
 - Playback support (reload and analyze recorded sessions)
 - Circular buffer for pre-trigger data capture
 - Summary statistics per PID (min, max, avg, stdev)
 - Anomaly marking (values outside normal range)

Usage (via tool functions):
    elm327_start_logging(pids="RPM, SPEED, COOLANT_TEMP", interval_ms=500)
    elm327_stop_logging()
    elm327_list_logs()
    elm327_analyze_log(log_id="...")
"""

import csv
import io
import json
import logging
import math
import os
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DEFAULT_LOG_DIR = "backend/data/logs"
MAX_BUFFER_SIZE = 7200       # Max samples in memory (~1 hour at 500ms)
PRE_TRIGGER_BUFFER = 120     # Samples to keep before trigger fires (~60s at 500ms)


class LogFormat(str, Enum):
    CSV = "csv"
    JSON = "json"


class TriggerType(str, Enum):
    """Type of recording trigger."""
    MANUAL = "manual"               # Started/stopped manually
    PID_THRESHOLD = "pid_threshold"  # Start when PID exceeds threshold
    PID_RANGE = "pid_range"          # Start when PID leaves normal range
    DTC_EVENT = "dtc_event"          # Start when DTC appears
    TIME_WINDOW = "time_window"      # Record for a fixed time window


class TriggerOperator(str, Enum):
    GT = ">"
    GTE = ">="
    LT = "<"
    LTE = "<="
    EQ = "=="
    NEQ = "!="


@dataclass
class LogTrigger:
    """Defines when to start/stop recording."""
    trigger_type: TriggerType
    pid_name: str = ""                     # For PID-based triggers
    operator: TriggerOperator = TriggerOperator.GT
    threshold: float = 0.0                 # Threshold value
    duration_seconds: float = 0.0          # For TIME_WINDOW: how long to record
    description: str = ""


@dataclass
class PIDSample:
    """A single PID reading at a point in time."""
    timestamp: float         # epoch time
    pid_name: str
    value: float
    unit: str = ""
    raw_hex: str = ""


@dataclass
class LogEntry:
    """One row of logged data (all PIDs at one timestamp)."""
    timestamp: float
    elapsed_ms: int           # milliseconds since start
    values: Dict[str, Any]    # pid_name -> value
    units: Dict[str, str]     # pid_name -> unit
    anomalies: List[str] = field(default_factory=list)  # PIDs with out-of-range values


@dataclass
class LogSession:
    """Metadata and data for a complete logging session."""
    session_id: str
    start_time: float
    end_time: float = 0.0
    vin: str = ""
    vehicle_info: str = ""
    pids_logged: List[str] = field(default_factory=list)
    sample_interval_ms: int = 500
    trigger: Optional[LogTrigger] = None
    entries: List[LogEntry] = field(default_factory=list)
    format: LogFormat = LogFormat.CSV
    file_path: str = ""
    notes: str = ""

    @property
    def duration_seconds(self) -> float:
        if self.end_time > 0:
            return self.end_time - self.start_time
        return 0.0

    @property
    def sample_count(self) -> int:
        return len(self.entries)

    def to_summary(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "start_time": datetime.fromtimestamp(self.start_time).strftime("%Y-%m-%d %H:%M:%S"),
            "duration_seconds": round(self.duration_seconds, 1),
            "sample_count": self.sample_count,
            "pids_logged": self.pids_logged,
            "sample_interval_ms": self.sample_interval_ms,
            "vin": self.vin,
            "vehicle_info": self.vehicle_info,
            "file_path": self.file_path,
            "trigger": self.trigger.description if self.trigger else "manual",
        }


# ---------------------------------------------------------------------------
# Normal PID Ranges (for anomaly detection)
# ---------------------------------------------------------------------------

PID_NORMAL_RANGES: Dict[str, Tuple[float, float]] = {
    "RPM": (600, 6500),
    "SPEED": (0, 180),
    "COOLANT_TEMP": (-40, 120),
    "ENGINE_LOAD": (0, 100),
    "THROTTLE_POS": (0, 100),
    "INTAKE_TEMP": (-40, 80),
    "MAF": (0, 650),
    "TIMING_ADVANCE": (-60, 60),
    "SHORT_FUEL_TRIM_1": (-25, 25),
    "LONG_FUEL_TRIM_1": (-25, 25),
    "SHORT_FUEL_TRIM_2": (-25, 25),
    "LONG_FUEL_TRIM_2": (-25, 25),
    "FUEL_PRESSURE": (0, 800),
    "FUEL_LEVEL": (0, 100),
    "CATALYST_TEMP_B1S1": (100, 900),
    "CONTROL_MODULE_VOLTAGE": (11.0, 15.0),
    "BAROMETRIC_PRESSURE": (70, 110),
    "AMBIENT_AIR_TEMP": (-40, 60),
    "INTAKE_PRESSURE": (10, 255),
}


# ---------------------------------------------------------------------------
# PID Statistics Calculator
# ---------------------------------------------------------------------------

def calculate_pid_stats(values: List[float]) -> Dict[str, Any]:
    """Calculate min, max, avg, stdev, median for a list of values."""
    if not values:
        return {"count": 0}

    n = len(values)
    avg = sum(values) / n
    sorted_vals = sorted(values)
    median = sorted_vals[n // 2] if n % 2 == 1 else (sorted_vals[n // 2 - 1] + sorted_vals[n // 2]) / 2

    if n > 1:
        variance = sum((x - avg) ** 2 for x in values) / (n - 1)
        stdev = math.sqrt(variance)
    else:
        stdev = 0.0

    return {
        "count": n,
        "min": round(min(values), 2),
        "max": round(max(values), 2),
        "avg": round(avg, 2),
        "median": round(median, 2),
        "stdev": round(stdev, 2),
    }


# ---------------------------------------------------------------------------
# Live Data Logger
# ---------------------------------------------------------------------------

class DataLogger:
    """
    Manages PID data recording sessions.

    This class handles the recording lifecycle:
    1. Configure PIDs and triggers
    2. Start recording (stores samples in memory)
    3. Add samples as they arrive from the gateway/protocol
    4. Stop recording and save to file
    5. Analyze / playback recorded sessions
    """

    def __init__(self, log_dir: str = DEFAULT_LOG_DIR):
        self.log_dir = log_dir
        self._active_session: Optional[LogSession] = None
        self._buffer: List[LogEntry] = []
        self._pre_trigger_buffer: List[LogEntry] = []
        self._trigger_fired: bool = False

    @property
    def is_recording(self) -> bool:
        return self._active_session is not None

    @property
    def active_session(self) -> Optional[LogSession]:
        return self._active_session

    def start_session(
        self,
        pids: List[str],
        interval_ms: int = 500,
        vin: str = "",
        vehicle_info: str = "",
        trigger: Optional[LogTrigger] = None,
        log_format: LogFormat = LogFormat.CSV,
        notes: str = "",
    ) -> str:
        """
        Start a new recording session.

        Args:
            pids: List of PID names to record
            interval_ms: Sampling interval in milliseconds
            vin: Vehicle VIN
            vehicle_info: Vehicle description
            trigger: Optional trigger configuration
            log_format: Output format (CSV or JSON)
            notes: Free-text notes

        Returns:
            Session ID string
        """
        if self._active_session:
            raise RuntimeError("A recording session is already active. Stop it first.")

        session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        self._active_session = LogSession(
            session_id=session_id,
            start_time=time.time(),
            pids_logged=pids,
            sample_interval_ms=interval_ms,
            vin=vin,
            vehicle_info=vehicle_info,
            trigger=trigger,
            format=log_format,
            notes=notes,
        )
        self._buffer = []
        self._pre_trigger_buffer = []
        self._trigger_fired = trigger is None or trigger.trigger_type == TriggerType.MANUAL

        logger.info(f"Started logging session {session_id}: PIDs={pids}, interval={interval_ms}ms")
        return session_id

    def add_sample(self, pid_values: Dict[str, Any], pid_units: Optional[Dict[str, str]] = None) -> None:
        """
        Add a set of PID readings to the current session.

        Args:
            pid_values: Dict of pid_name -> numeric value
            pid_units: Optional dict of pid_name -> unit string
        """
        if not self._active_session:
            return

        now = time.time()
        elapsed_ms = int((now - self._active_session.start_time) * 1000)
        units = pid_units or {}

        # Check for anomalies
        anomalies = []
        for pid, val in pid_values.items():
            if pid in PID_NORMAL_RANGES and isinstance(val, (int, float)):
                lo, hi = PID_NORMAL_RANGES[pid]
                if val < lo or val > hi:
                    anomalies.append(pid)

        entry = LogEntry(
            timestamp=now,
            elapsed_ms=elapsed_ms,
            values=dict(pid_values),
            units=dict(units),
            anomalies=anomalies,
        )

        # Handle trigger logic
        if self._trigger_fired:
            self._buffer.append(entry)
            if len(self._buffer) > MAX_BUFFER_SIZE:
                self._buffer.pop(0)
        else:
            # Buffer pre-trigger data
            self._pre_trigger_buffer.append(entry)
            if len(self._pre_trigger_buffer) > PRE_TRIGGER_BUFFER:
                self._pre_trigger_buffer.pop(0)

            # Check trigger condition
            if self._check_trigger(pid_values):
                self._trigger_fired = True
                # Include pre-trigger buffer
                self._buffer = list(self._pre_trigger_buffer) + [entry]
                self._pre_trigger_buffer = []
                logger.info(f"Trigger fired! Including {PRE_TRIGGER_BUFFER} pre-trigger samples.")

    def _check_trigger(self, pid_values: Dict[str, Any]) -> bool:
        """Check if the recording trigger condition is met."""
        trigger = self._active_session.trigger if self._active_session else None
        if not trigger:
            return True

        if trigger.trigger_type == TriggerType.PID_THRESHOLD:
            val = pid_values.get(trigger.pid_name)
            if val is None:
                return False
            try:
                val = float(val)
            except (ValueError, TypeError):
                return False

            ops = {
                TriggerOperator.GT: val > trigger.threshold,
                TriggerOperator.GTE: val >= trigger.threshold,
                TriggerOperator.LT: val < trigger.threshold,
                TriggerOperator.LTE: val <= trigger.threshold,
                TriggerOperator.EQ: val == trigger.threshold,
                TriggerOperator.NEQ: val != trigger.threshold,
            }
            return ops.get(trigger.operator, False)

        if trigger.trigger_type == TriggerType.PID_RANGE:
            val = pid_values.get(trigger.pid_name)
            if val is None:
                return False
            try:
                val = float(val)
            except (ValueError, TypeError):
                return False
            normal = PID_NORMAL_RANGES.get(trigger.pid_name, (float('-inf'), float('inf')))
            return val < normal[0] or val > normal[1]

        return True

    def stop_session(self) -> Optional[LogSession]:
        """
        Stop the current recording session and save to file.

        Returns:
            The completed LogSession, or None if no session active
        """
        if not self._active_session:
            return None

        session = self._active_session
        session.end_time = time.time()
        session.entries = list(self._buffer)

        # Save to file
        file_path = self._save_session(session)
        session.file_path = file_path

        logger.info(
            f"Stopped session {session.session_id}: "
            f"{session.sample_count} samples, "
            f"{session.duration_seconds:.1f}s"
        )

        self._active_session = None
        self._buffer = []
        self._pre_trigger_buffer = []
        self._trigger_fired = False

        return session

    def _save_session(self, session: LogSession) -> str:
        """Save session data to file. Returns the file path."""
        os.makedirs(self.log_dir, exist_ok=True)

        if session.format == LogFormat.CSV:
            return self._save_csv(session)
        else:
            return self._save_json(session)

    def _save_csv(self, session: LogSession) -> str:
        """Save session as CSV file."""
        filename = f"log_{session.session_id}.csv"
        filepath = os.path.join(self.log_dir, filename)

        with open(filepath, "w", newline="") as f:
            writer = csv.writer(f)

            # Header comment rows
            writer.writerow([f"# Session: {session.session_id}"])
            writer.writerow([f"# VIN: {session.vin}"])
            writer.writerow([f"# Vehicle: {session.vehicle_info}"])
            writer.writerow([f"# Start: {datetime.fromtimestamp(session.start_time).isoformat()}"])
            writer.writerow([f"# Duration: {session.duration_seconds:.1f}s"])
            writer.writerow([f"# Samples: {session.sample_count}"])
            writer.writerow([f"# Interval: {session.sample_interval_ms}ms"])
            if session.notes:
                writer.writerow([f"# Notes: {session.notes}"])
            writer.writerow([])  # blank line

            # Column headers
            pids = session.pids_logged
            header = ["timestamp", "elapsed_ms"] + pids + ["anomalies"]
            writer.writerow(header)

            # Data rows
            for entry in session.entries:
                row = [
                    f"{entry.timestamp:.3f}",
                    entry.elapsed_ms,
                ]
                for pid in pids:
                    val = entry.values.get(pid, "")
                    row.append(val if val != "" else "N/A")
                row.append(";".join(entry.anomalies) if entry.anomalies else "")
                writer.writerow(row)

        return filepath

    def _save_json(self, session: LogSession) -> str:
        """Save session as JSON file."""
        filename = f"log_{session.session_id}.json"
        filepath = os.path.join(self.log_dir, filename)

        data = {
            "session": session.to_summary(),
            "statistics": self.compute_statistics(session),
            "data": [
                {
                    "timestamp": e.timestamp,
                    "elapsed_ms": e.elapsed_ms,
                    "values": e.values,
                    "units": e.units,
                    "anomalies": e.anomalies,
                }
                for e in session.entries
            ],
        }

        with open(filepath, "w") as f:
            json.dump(data, f, indent=2)

        return filepath

    def compute_statistics(self, session: Optional[LogSession] = None) -> Dict[str, Any]:
        """
        Compute statistics for each PID in the session.

        Args:
            session: LogSession to analyze (or current active session)

        Returns:
            Dict of pid_name -> statistics
        """
        sess = session or self._active_session
        if not sess:
            return {}

        entries = session.entries if session else self._buffer
        stats = {}

        for pid in sess.pids_logged:
            values = []
            for entry in entries:
                val = entry.values.get(pid)
                if val is not None:
                    try:
                        values.append(float(val))
                    except (ValueError, TypeError):
                        pass

            pid_stats = calculate_pid_stats(values)

            # Add anomaly count
            anomaly_count = sum(1 for e in entries if pid in e.anomalies)
            pid_stats["anomaly_count"] = anomaly_count

            # Add normal range info
            if pid in PID_NORMAL_RANGES:
                lo, hi = PID_NORMAL_RANGES[pid]
                pid_stats["normal_range"] = f"{lo}-{hi}"
                pid_stats["in_range_pct"] = round(
                    (1 - anomaly_count / max(len(values), 1)) * 100, 1
                )

            stats[pid] = pid_stats

        return stats

    def get_current_stats(self) -> Dict[str, Any]:
        """Get real-time statistics for the active recording session."""
        if not self._active_session:
            return {"error": "No active session"}

        return {
            "session_id": self._active_session.session_id,
            "duration_seconds": round(time.time() - self._active_session.start_time, 1),
            "samples_recorded": len(self._buffer),
            "trigger_fired": self._trigger_fired,
            "statistics": self.compute_statistics(),
        }


# ---------------------------------------------------------------------------
# Log File Management
# ---------------------------------------------------------------------------

def list_log_files(log_dir: str = DEFAULT_LOG_DIR) -> List[Dict[str, Any]]:
    """
    List all saved log files.

    Returns:
        List of dicts with file info (name, size, date, format)
    """
    if not os.path.exists(log_dir):
        return []

    results = []
    for fname in sorted(os.listdir(log_dir), reverse=True):
        if not (fname.endswith(".csv") or fname.endswith(".json")):
            continue
        fpath = os.path.join(log_dir, fname)
        stat = os.stat(fpath)
        results.append({
            "filename": fname,
            "file_path": fpath,
            "format": "csv" if fname.endswith(".csv") else "json",
            "size_bytes": stat.st_size,
            "size_kb": round(stat.st_size / 1024, 1),
            "modified": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
        })
    return results


def load_log_file(file_path: str) -> Dict[str, Any]:
    """
    Load and parse a log file for analysis/playback.

    Args:
        file_path: Path to a CSV or JSON log file

    Returns:
        Dict with session info, data, and statistics
    """
    if file_path.endswith(".json"):
        return _load_json_log(file_path)
    elif file_path.endswith(".csv"):
        return _load_csv_log(file_path)
    else:
        raise ValueError(f"Unsupported format: {file_path}")


def _load_json_log(file_path: str) -> Dict[str, Any]:
    """Load a JSON log file."""
    with open(file_path, "r") as f:
        data = json.load(f)

    # Recompute statistics if needed
    if "data" in data and "statistics" not in data:
        pid_values: Dict[str, List[float]] = defaultdict(list)
        for entry in data["data"]:
            for pid, val in entry.get("values", {}).items():
                try:
                    pid_values[pid].append(float(val))
                except (ValueError, TypeError):
                    pass
        data["statistics"] = {
            pid: calculate_pid_stats(vals) for pid, vals in pid_values.items()
        }

    return data


def _load_csv_log(file_path: str) -> Dict[str, Any]:
    """Load a CSV log file."""
    metadata = {}
    header = None
    rows = []

    with open(file_path, "r") as f:
        for line in f:
            line = line.strip()
            if line.startswith("# "):
                # Parse metadata
                parts = line[2:].split(": ", 1)
                if len(parts) == 2:
                    metadata[parts[0].strip().lower()] = parts[1].strip()
            elif not line:
                continue
            elif header is None:
                header = line.split(",")
            else:
                values = line.split(",")
                rows.append(values)

    if not header:
        return {"error": "Invalid CSV format", "file_path": file_path}

    # Parse into structured data
    pids = [h for h in header if h not in ("timestamp", "elapsed_ms", "anomalies")]
    data_entries = []
    pid_values: Dict[str, List[float]] = defaultdict(list)

    for row in rows:
        entry: Dict[str, Any] = {"values": {}}
        for i, h in enumerate(header):
            if i < len(row):
                if h == "timestamp":
                    entry["timestamp"] = float(row[i]) if row[i] else 0
                elif h == "elapsed_ms":
                    entry["elapsed_ms"] = int(row[i]) if row[i] else 0
                elif h == "anomalies":
                    entry["anomalies"] = row[i].split(";") if row[i] else []
                else:
                    try:
                        val = float(row[i])
                        entry["values"][h] = val
                        pid_values[h].append(val)
                    except (ValueError, TypeError):
                        entry["values"][h] = row[i]
        data_entries.append(entry)

    # Compute statistics
    statistics = {
        pid: calculate_pid_stats(vals) for pid, vals in pid_values.items()
    }

    return {
        "session": metadata,
        "pids": pids,
        "sample_count": len(data_entries),
        "statistics": statistics,
        "data": data_entries,
        "file_path": file_path,
    }


def analyze_log(file_path: str) -> str:
    """
    Analyze a log file and return a human-readable summary.

    Args:
        file_path: Path to log file

    Returns:
        Formatted analysis string
    """
    data = load_log_file(file_path)

    lines = []
    session = data.get("session", {})
    lines.append("## Data Log Analysis")
    lines.append("")

    if isinstance(session, dict):
        for key in ["session_id", "vin", "vehicle", "start", "duration", "samples", "interval"]:
            if key in session:
                lines.append(f"**{key.title()}:** {session[key]}")
        if "vehicle_info" in session:
            lines.append(f"**Vehicle:** {session['vehicle_info']}")
        if "sample_count" in session:
            lines.append(f"**Samples:** {session['sample_count']}")
        lines.append("")

    stats = data.get("statistics", {})
    if stats:
        lines.append("### PID Statistics")
        lines.append("")
        lines.append("| PID | Min | Max | Avg | Stdev | Anomalies |")
        lines.append("|-----|-----|-----|-----|-------|-----------|")
        for pid, s in sorted(stats.items()):
            if isinstance(s, dict) and "min" in s:
                anomaly = s.get("anomaly_count", 0)
                range_pct = s.get("in_range_pct", "N/A")
                lines.append(
                    f"| {pid} | {s['min']} | {s['max']} | {s['avg']} | "
                    f"{s['stdev']} | {anomaly} ({range_pct}% in range) |"
                )
        lines.append("")

    # Look for anomaly patterns
    data_entries = data.get("data", [])
    if data_entries:
        total_entries = len(data_entries)
        anomaly_entries = sum(1 for e in data_entries if e.get("anomalies"))
        if anomaly_entries > 0:
            lines.append(f"### Anomaly Summary")
            lines.append(f"")
            lines.append(f"**{anomaly_entries}** of {total_entries} samples had out-of-range values "
                        f"({round(anomaly_entries / total_entries * 100, 1)}%)")
            lines.append("")

            # Count anomaly frequency per PID
            anomaly_counts: Dict[str, int] = defaultdict(int)
            for e in data_entries:
                for a in e.get("anomalies", []):
                    anomaly_counts[a] += 1

            if anomaly_counts:
                lines.append("| PID | Anomaly Count | % of Samples |")
                lines.append("|-----|--------------|-------------|")
                for pid, count in sorted(anomaly_counts.items(), key=lambda x: -x[1]):
                    pct = round(count / total_entries * 100, 1)
                    lines.append(f"| {pid} | {count} | {pct}% |")
                lines.append("")

    return "\n".join(lines)


def delete_log(file_path: str) -> bool:
    """Delete a log file."""
    try:
        os.remove(file_path)
        return True
    except OSError:
        return False
