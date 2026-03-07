"""
Diagnostic Session State Management

Maintains state across tool calls so the LLM doesn't lose context.
The session tracks:
- Vehicle info
- All DTCs read (with timestamps)
- All PIDs read (with timestamps)
- Tests performed
- Working hypotheses
- Diagnostic progress

Each tool call can query and update this state, allowing the LLM to
build context over multiple tool calls.
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
from enum import Enum
import json

from .vin_decoder import decode_make_from_vin, decode_vin_full

logger = logging.getLogger(__name__)


class DiagnosticPhase(Enum):
    """Current phase of the diagnostic session."""
    NOT_STARTED = "not_started"
    CONNECTED = "connected"
    INITIAL_SCAN = "initial_scan"
    GATHERING_DATA = "gathering_data"
    TESTING = "testing"
    ANALYZING = "analyzing"
    COMPLETE = "complete"


@dataclass
class PIDReading:
    """A single PID reading with metadata."""
    name: str
    value: float
    unit: str
    timestamp: datetime
    context: str = ""  # e.g., "at idle", "during warmup", "at 2500 RPM"


@dataclass
class DTCReading:
    """A DTC reading with metadata."""
    code: str
    description: str
    category: str  # "stored", "pending", "permanent"
    timestamp: datetime
    freeze_frame: Optional[Dict[str, Any]] = None


@dataclass
class TestResult:
    """Result of a diagnostic test."""
    test_name: str
    instruction: str
    timestamp: datetime
    pids_monitored: List[str]
    data_collected: List[Dict[str, Any]]
    observations: List[str]
    duration: float


@dataclass
class Hypothesis:
    """A working diagnostic hypothesis."""
    diagnosis: str
    system: str
    confidence: float
    supporting_evidence: List[str]
    contradicting_evidence: List[str]
    tests_to_confirm: List[str]
    updated_at: datetime


@dataclass 
class DiagnosticSession:
    """
    Complete state of a diagnostic session.
    
    This is the "memory" that persists across tool calls.
    """
    # Session metadata
    session_id: str = ""
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    phase: DiagnosticPhase = DiagnosticPhase.NOT_STARTED
    
    # Vehicle info
    vehicle_year: str = ""
    vehicle_make: str = ""
    vehicle_model: str = ""
    vehicle_engine: str = ""
    vehicle_vin: str = ""
    vehicle_specs: Dict[str, str] = field(default_factory=dict)  # Full VPIC specs from VIN decode
    
    # Symptoms/complaints
    symptoms: List[str] = field(default_factory=list)
    tech_observations: List[str] = field(default_factory=list)
    
    # Data collected
    dtcs: List[DTCReading] = field(default_factory=list)
    pids: List[PIDReading] = field(default_factory=list)
    tests: List[TestResult] = field(default_factory=list)
    
    # NHTSA safety context (auto-populated when vehicle is identified)
    nhtsa_complaint_count: int = 0
    nhtsa_top_components: List[Dict[str, Any]] = field(default_factory=list)  # [{component, count, crashes, fires, deaths}]
    nhtsa_recalls: List[Dict[str, str]] = field(default_factory=list)  # [{campaign_number, component, summary, consequence, remedy, park_it}]
    nhtsa_safety_flags: Dict[str, Any] = field(default_factory=dict)  # {total_crashes, total_fires, total_deaths, total_injuries}
    nhtsa_context_loaded: bool = False
    
    # Analysis
    hypotheses: List[Hypothesis] = field(default_factory=list)
    ruled_out: List[str] = field(default_factory=list)
    
    # Freeze frame snapshot (populated by elm327_freeze_frame)
    freeze_frame_data: Optional[Dict[str, Any]] = None
    
    # Action log (what's been done)
    action_log: List[Tuple[datetime, str]] = field(default_factory=list)
    
    # Next steps (what needs to be done)
    next_steps: List[str] = field(default_factory=list)
    
    def log_action(self, action: str):
        """Log an action that was performed."""
        self.action_log.append((datetime.now(), action))
        self.updated_at = datetime.now()
    
    def add_dtc(self, code: str, description: str, category: str = "stored"):
        """Add a DTC to the session."""
        # Check if already exists
        for dtc in self.dtcs:
            if dtc.code == code and dtc.category == category:
                return  # Don't duplicate
        
        self.dtcs.append(DTCReading(
            code=code,
            description=description,
            category=category,
            timestamp=datetime.now()
        ))
        self.updated_at = datetime.now()
    
    def add_pid(self, name: str, value: float, unit: str, context: str = ""):
        """Add a PID reading to the session."""
        self.pids.append(PIDReading(
            name=name,
            value=value,
            unit=unit,
            timestamp=datetime.now(),
            context=context
        ))
        self.updated_at = datetime.now()
    
    def get_latest_pid(self, name: str) -> Optional[PIDReading]:
        """Get the most recent reading for a specific PID."""
        for pid in reversed(self.pids):
            if pid.name.upper() == name.upper():
                return pid
        return None
    
    def get_pid_history(self, name: str) -> List[PIDReading]:
        """Get all readings for a specific PID."""
        return [p for p in self.pids if p.name.upper() == name.upper()]
    
    def add_hypothesis(self, diagnosis: str, system: str, confidence: float, 
                      evidence: List[str], tests_to_confirm: List[str] = None):
        """Add or update a diagnostic hypothesis."""
        # Check if we already have this hypothesis
        for h in self.hypotheses:
            if h.diagnosis == diagnosis:
                # Update existing
                h.confidence = confidence
                h.supporting_evidence = evidence
                h.tests_to_confirm = tests_to_confirm or []
                h.updated_at = datetime.now()
                self.updated_at = datetime.now()
                return
        
        # Add new
        self.hypotheses.append(Hypothesis(
            diagnosis=diagnosis,
            system=system,
            confidence=confidence,
            supporting_evidence=evidence,
            contradicting_evidence=[],
            tests_to_confirm=tests_to_confirm or [],
            updated_at=datetime.now()
        ))
        self.updated_at = datetime.now()
    
    def rule_out(self, diagnosis: str, reason: str):
        """Rule out a diagnosis."""
        self.ruled_out.append(f"{diagnosis}: {reason}")
        
        # Remove from hypotheses if present
        self.hypotheses = [h for h in self.hypotheses if h.diagnosis != diagnosis]
        self.updated_at = datetime.now()
    
    def set_vehicle(self, year: str = None, make: str = None, model: str = None, 
                   engine: str = None, vin: str = None):
        """Set vehicle information.  Auto-derives make/model/year/engine from VIN."""
        if year:
            self.vehicle_year = year
        if make:
            self.vehicle_make = make
        if model:
            self.vehicle_model = model
        if engine:
            self.vehicle_engine = engine
        if vin:
            self.vehicle_vin = vin
            # VIN is authoritative – ALWAYS decode and overwrite vehicle info
            try:
                info = decode_vin_full(vin)
                if info.get("make"):
                    self.vehicle_make = info["make"]
                    logger.info(f"VIN decode → make: {self.vehicle_make}")
                if info.get("model"):
                    self.vehicle_model = info["model"]
                    logger.info(f"VIN decode → model: {self.vehicle_model}")
                if info.get("year"):
                    self.vehicle_year = info["year"]
                    logger.info(f"VIN decode → year: {self.vehicle_year}")
                if info.get("engine_desc"):
                    self.vehicle_engine = info["engine_desc"]
                    logger.info(f"VIN decode → engine: {self.vehicle_engine}")
                # Store full VPIC specs for enriched context
                _SPEC_KEYS = [
                    "valve_train", "engine_configuration", "engine_model",
                    "engine_hp", "engine_power_kw", "turbo", "cooling_type",
                    "displacement_l", "cylinders", "fuel_type",
                    "drive_type", "transmission", "body_class",
                    "electrification_level", "battery_type", "battery_kwh",
                    "brake_system", "abs", "esc", "traction_control",
                    "adaptive_cruise_control", "forward_collision_warning",
                    "lane_departure_warning", "lane_keeping_assist",
                    "blind_spot_warning", "backup_camera", "tpms_type",
                ]
                for key in _SPEC_KEYS:
                    val = info.get(key)
                    if val and str(val).strip():
                        self.vehicle_specs[key] = str(val).strip()
                if self.vehicle_specs:
                    logger.info(f"VIN decode → {len(self.vehicle_specs)} specs stored")
            except Exception as e:
                logger.debug(f"VIN full decode failed, falling back to WMI: {e}")
                # Fallback: at least get make from local WMI table
                if not self.vehicle_make:
                    local = decode_make_from_vin(vin)
                    if local:
                        self.vehicle_make = local
        self.updated_at = datetime.now()
    
    def get_vehicle_description(self) -> str:
        """Get formatted vehicle description."""
        parts = [self.vehicle_year, self.vehicle_make, self.vehicle_model]
        parts = [p for p in parts if p]
        desc = ' '.join(parts) if parts else "Unknown Vehicle"
        if self.vehicle_engine:
            desc += f" ({self.vehicle_engine})"
        return desc
    
    def add_symptom(self, symptom: str):
        """Add a reported symptom."""
        symptom = symptom.lower().strip()
        if symptom not in self.symptoms:
            self.symptoms.append(symptom)
            self.updated_at = datetime.now()
    
    def add_observation(self, observation: str):
        """Add a technician observation."""
        if observation not in self.tech_observations:
            self.tech_observations.append(observation)
            self.updated_at = datetime.now()
    
    def set_nhtsa_context(self, complaint_count: int,
                          top_components: List[Dict[str, Any]],
                          recalls: List[Dict[str, str]],
                          safety_flags: Dict[str, Any]):
        """
        Store NHTSA complaint/recall context for this vehicle.
        
        Called automatically when vehicle is identified (VIN decode or
        make/model/year provided). Gives the LLM safety context before
        it starts diagnosing.
        
        Args:
            complaint_count: Total NHTSA complaints for this vehicle
            top_components: Top complaint components with counts/severity
            recalls: Active recalls with campaign numbers and details
            safety_flags: Aggregate crash/fire/death/injury counts
        """
        self.nhtsa_complaint_count = complaint_count
        self.nhtsa_top_components = top_components
        self.nhtsa_recalls = recalls
        self.nhtsa_safety_flags = safety_flags
        self.nhtsa_context_loaded = True
        self.updated_at = datetime.now()
        logger.info(f"NHTSA context loaded: {complaint_count} complaints, "
                     f"{len(recalls)} recalls, "
                     f"{safety_flags.get('total_crashes', 0)} crashes")
    
    def get_summary(self) -> str:
        """
        Generate a comprehensive summary for the LLM.
        
        This is THE KEY FUNCTION - it provides the context the LLM needs
        to understand what has been done and what needs to be done next.
        """
        lines = []
        
        # Header
        lines.append("=" * 50)
        lines.append("📋 DIAGNOSTIC SESSION STATUS")
        lines.append("=" * 50)
        
        # Vehicle
        lines.append(f"\n🚗 **Vehicle:** {self.get_vehicle_description()}")
        if self.vehicle_vin:
            lines.append(f"   VIN: {self.vehicle_vin}")
        if self.vehicle_specs:
            specs = self.vehicle_specs
            spec_parts = []
            if specs.get("valve_train"):
                spec_parts.append(f"Valve Train: {specs['valve_train']}")
            if specs.get("engine_configuration"):
                spec_parts.append(f"Config: {specs['engine_configuration']}")
            if specs.get("engine_model"):
                spec_parts.append(f"Engine: {specs['engine_model']}")
            if specs.get("engine_hp"):
                spec_parts.append(f"{specs['engine_hp']} hp")
            if specs.get("turbo"):
                spec_parts.append(f"Turbo: {specs['turbo']}")
            if specs.get("drive_type"):
                spec_parts.append(f"Drive: {specs['drive_type']}")
            if specs.get("transmission"):
                spec_parts.append(f"Trans: {specs['transmission']}")
            if spec_parts:
                lines.append(f"   Specs: {' · '.join(spec_parts)}")
        
        # NHTSA Safety Context
        if self.nhtsa_context_loaded:
            lines.append(f"\n⚠️ **NHTSA Safety Data** ({self.nhtsa_complaint_count:,} complaints on file)")
            sf = self.nhtsa_safety_flags
            if sf.get("total_crashes") or sf.get("total_fires") or sf.get("total_deaths"):
                alert_parts = []
                if sf.get("total_crashes"):
                    alert_parts.append(f"{sf['total_crashes']:,} crashes")
                if sf.get("total_fires"):
                    alert_parts.append(f"{sf['total_fires']:,} fires")
                if sf.get("total_deaths"):
                    alert_parts.append(f"{sf['total_deaths']:,} deaths")
                if sf.get("total_injuries"):
                    alert_parts.append(f"{sf['total_injuries']:,} injuries")
                lines.append(f"   🚨 Safety events: {', '.join(alert_parts)}")
            if self.nhtsa_top_components:
                comp_strs = [f"{c['component']} ({c['count']})" 
                            for c in self.nhtsa_top_components[:5]]
                lines.append(f"   Top complaint areas: {', '.join(comp_strs)}")
            if self.nhtsa_recalls:
                lines.append(f"   🔴 **{len(self.nhtsa_recalls)} Active Recall(s):**")
                for r in self.nhtsa_recalls:
                    park_flag = " 🅿️PARK IT" if r.get("park_it") == "Y" else ""
                    lines.append(f"      • {r.get('campaign_number', 'N/A')}: "
                                f"{r.get('component', 'Unknown')}{park_flag}")
                    if r.get("summary"):
                        summary = r["summary"]
                        if len(summary) > 150:
                            summary = summary[:147] + "..."
                        lines.append(f"        {summary}")
        
        # Phase
        phase_emoji = {
            DiagnosticPhase.NOT_STARTED: "⚪",
            DiagnosticPhase.CONNECTED: "🟡",
            DiagnosticPhase.INITIAL_SCAN: "🟡",
            DiagnosticPhase.GATHERING_DATA: "🟡",
            DiagnosticPhase.TESTING: "🔵",
            DiagnosticPhase.ANALYZING: "🟣",
            DiagnosticPhase.COMPLETE: "🟢",
        }
        lines.append(f"\n{phase_emoji.get(self.phase, '⚪')} **Phase:** {self.phase.value.replace('_', ' ').title()}")
        
        # Symptoms
        if self.symptoms:
            lines.append(f"\n🩺 **Reported Symptoms:** {', '.join(self.symptoms)}")
        
        # DTCs
        if self.dtcs:
            lines.append(f"\n🔴 **DTCs Found ({len(self.dtcs)}):**")
            for dtc in self.dtcs:
                lines.append(f"   • {dtc.code}: {dtc.description} [{dtc.category}]")
        else:
            lines.append("\n✅ **No DTCs found**")
        
        # Recent PID readings (show latest values only, grouped)
        if self.pids:
            lines.append(f"\n📊 **Recent Sensor Data:**")
            seen = set()
            for pid in reversed(self.pids):
                if pid.name not in seen:
                    seen.add(pid.name)
                    context = f" ({pid.context})" if pid.context else ""
                    lines.append(f"   • {pid.name}: {pid.value:.1f} {pid.unit}{context}")
                    if len(seen) >= 10:  # Limit to 10 most recent PIDs
                        break
        
        # Hypotheses (working diagnoses)
        if self.hypotheses:
            lines.append(f"\n🧠 **Working Hypotheses:**")
            for h in sorted(self.hypotheses, key=lambda x: -x.confidence):
                conf_pct = h.confidence * 100
                emoji = "🔴" if conf_pct >= 70 else "🟡" if conf_pct >= 40 else "⚪"
                lines.append(f"   {emoji} {h.diagnosis} ({conf_pct:.0f}% confidence)")
                if h.supporting_evidence:
                    lines.append(f"      Evidence: {', '.join(h.supporting_evidence[:3])}")
        
        # Ruled out
        if self.ruled_out:
            lines.append(f"\n❌ **Ruled Out:**")
            for r in self.ruled_out[-5:]:  # Last 5 ruled out
                lines.append(f"   • {r}")
        
        # Tests performed
        if self.tests:
            lines.append(f"\n🔧 **Tests Performed ({len(self.tests)}):**")
            for t in self.tests[-5:]:  # Last 5 tests
                lines.append(f"   • {t.test_name}")
        
        # Next steps
        if self.next_steps:
            lines.append(f"\n➡️ **Recommended Next Steps:**")
            for i, step in enumerate(self.next_steps[:5], 1):
                lines.append(f"   {i}. {step}")
        
        # Recent actions
        if self.action_log:
            lines.append(f"\n📝 **Recent Actions:**")
            for ts, action in self.action_log[-5:]:
                lines.append(f"   • {action}")
        
        lines.append("\n" + "=" * 50)
        
        return '\n'.join(lines)
    
    def get_next_step_recommendation(self) -> str:
        """
        Recommend what the LLM should do next based on current state.
        
        This helps guide the LLM through the diagnostic process.
        """
        if self.phase == DiagnosticPhase.NOT_STARTED:
            return "Connect to the vehicle using elm327_connect()"
        
        if self.phase == DiagnosticPhase.CONNECTED and not self.dtcs:
            return "Read DTCs using elm327_read_dtcs()"
        
        if self.phase == DiagnosticPhase.INITIAL_SCAN and not self.pids:
            return "Read initial PIDs using elm327_read_pids('RPM, COOLANT_TEMP, STFT_B1, LTFT_B1')"
        
        # Have data but no hypotheses - analyze
        if (self.dtcs or self.pids) and not self.hypotheses:
            return "Analyze collected data using diagnostic_analyze()"
        
        # Have hypotheses but low confidence - suggest tests
        if self.hypotheses:
            top = max(self.hypotheses, key=lambda h: h.confidence)
            if top.confidence < 0.7 and top.tests_to_confirm:
                return f"Perform discriminating test: {top.tests_to_confirm[0]}"
        
        # Default
        return "Review session summary and determine next diagnostic step"
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization."""
        d = {
            'session_id': self.session_id,
            'phase': self.phase.value,
            'vehicle': {
                'year': self.vehicle_year,
                'make': self.vehicle_make,
                'model': self.vehicle_model,
                'engine': self.vehicle_engine,
                'vin': self.vehicle_vin,
            },
            'symptoms': self.symptoms,
            'dtcs': [{'code': d.code, 'description': d.description, 'category': d.category} 
                    for d in self.dtcs],
            'latest_pids': {p.name: {'value': p.value, 'unit': p.unit} 
                          for p in self.pids[-20:]},  # Last 20 readings
            'hypotheses': [{'diagnosis': h.diagnosis, 'confidence': h.confidence, 
                           'evidence': h.supporting_evidence} 
                         for h in self.hypotheses],
            'tests_performed': len(self.tests),
            'next_steps': self.next_steps,
        }
        if self.nhtsa_context_loaded:
            d['nhtsa'] = {
                'complaint_count': self.nhtsa_complaint_count,
                'top_components': self.nhtsa_top_components,
                'recalls': self.nhtsa_recalls,
                'safety_flags': self.nhtsa_safety_flags,
            }
        return d


# =============================================================================
# SESSION STORAGE - User-scoped with auto-expiration
# =============================================================================

import threading

# Thread lock for session access (web servers handle concurrent requests)
_session_lock = threading.Lock()

# Sessions keyed by user_id - each tech gets their own session
_sessions: Dict[str, DiagnosticSession] = {}
_session_timestamps: Dict[str, datetime] = {}

# Sessions expire after 2 hours of inactivity
SESSION_TIMEOUT_HOURS = 2


def _cleanup_expired_sessions():
    """Remove sessions that haven't been accessed in SESSION_TIMEOUT_HOURS."""
    # Note: Caller should hold _session_lock
    now = datetime.now()
    expired = [
        user_id for user_id, ts in _session_timestamps.items()
        if (now - ts).total_seconds() > SESSION_TIMEOUT_HOURS * 3600
    ]
    for user_id in expired:
        del _sessions[user_id]
        del _session_timestamps[user_id]


def get_session(user_id: str = "default") -> DiagnosticSession:
    """
    Get the diagnostic session for a specific user.
    
    Args:
        user_id: Unique identifier for the user (from Open WebUI __user__)
    
    Returns:
        The user's DiagnosticSession (creates one if doesn't exist)
    """
    with _session_lock:
        # Cleanup old sessions periodically
        _cleanup_expired_sessions()
        
        if user_id not in _sessions:
            _sessions[user_id] = DiagnosticSession(
                session_id=f"{user_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            )
        
        # Update access timestamp
        _session_timestamps[user_id] = datetime.now()
        
        return _sessions[user_id]


def reset_session(user_id: str = "default") -> DiagnosticSession:
    """
    Start a new diagnostic session for a user.
    
    Args:
        user_id: Unique identifier for the user
    
    Returns:
        Fresh DiagnosticSession
    """
    with _session_lock:
        _sessions[user_id] = DiagnosticSession(
            session_id=f"{user_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        )
        _session_timestamps[user_id] = datetime.now()
        return _sessions[user_id]


def get_session_summary(user_id: str = "default") -> str:
    """Get the session summary for a specific user."""
    return get_session(user_id).get_summary()


def get_active_session_count() -> int:
    """Get the number of active diagnostic sessions (for monitoring)."""
    _cleanup_expired_sessions()
    return len(_sessions)
