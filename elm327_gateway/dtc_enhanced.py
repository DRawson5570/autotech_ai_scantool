"""
Enhanced DTC Descriptions — Diagnostic Context Database

Provides rich diagnostic context for DTC codes beyond the basic SAE
description. For each code, includes:
- Common causes (ranked by frequency)
- Severity level (low / medium / high / critical)
- Drivability impact
- Recommended diagnostic steps
- Typical repair difficulty and cost range
- Related codes that often appear together

Data is loaded from scan_tool_data.db at import time.
"""

import json
import logging
import os
import sqlite3
from dataclasses import dataclass, field
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class EnhancedDTCInfo:
    """Rich diagnostic context for a single DTC."""
    code: str
    severity: str  # "low", "medium", "high", "critical"
    drivability_impact: str  # Brief description of how it affects driving
    common_causes: List[str]  # Ordered by frequency (most common first)
    diagnostic_steps: List[str]  # What a tech should check
    related_codes: List[str] = field(default_factory=list)  # Often co-occurring
    repair_difficulty: str = "medium"  # "easy", "medium", "hard", "specialist"
    typical_cost_range: str = ""  # e.g. "$100-$300"
    notes: str = ""  # Ford-specific or general tech tips

    def to_dict(self) -> dict:
        return {
            "code": self.code,
            "severity": self.severity,
            "drivability_impact": self.drivability_impact,
            "common_causes": self.common_causes,
            "diagnostic_steps": self.diagnostic_steps,
            "related_codes": self.related_codes,
            "repair_difficulty": self.repair_difficulty,
            "typical_cost_range": self.typical_cost_range,
            "notes": self.notes,
        }

    def format_markdown(self) -> str:
        """Render as markdown for chat display."""
        sev_icon = {
            "low": "🟢", "medium": "🟡", "high": "🟠", "critical": "🔴"
        }.get(self.severity, "⚪")

        lines = [
            f"**{self.code}** {sev_icon} Severity: {self.severity.upper()}",
            f"**Drivability:** {self.drivability_impact}",
        ]

        if self.common_causes:
            lines.append("**Common Causes (most likely first):**")
            for i, cause in enumerate(self.common_causes, 1):
                lines.append(f"  {i}. {cause}")

        if self.diagnostic_steps:
            lines.append("**Diagnostic Steps:**")
            for i, step_text in enumerate(self.diagnostic_steps, 1):
                lines.append(f"  {i}. {step_text}")

        if self.related_codes:
            lines.append(f"**Related Codes:** {', '.join(self.related_codes)}")

        if self.typical_cost_range:
            lines.append(f"**Typical Repair Cost:** {self.typical_cost_range} "
                        f"(difficulty: {self.repair_difficulty})")

        if self.notes:
            lines.append(f"**Tech Notes:** {self.notes}")

        return "\n".join(lines)


# ============================================================================
# Database-backed DTC store
# ============================================================================

def _get_db_path() -> str:
    """Locate scan_tool_data.db relative to this file."""
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "scan_tool_data.db")


def _load_enhanced_dtcs() -> Dict[str, EnhancedDTCInfo]:
    """Load all enhanced DTC entries from SQLite."""
    db_path = _get_db_path()
    if not os.path.exists(db_path):
        logger.warning("scan_tool_data.db not found at %s — enhanced DTCs empty", db_path)
        return {}

    result: Dict[str, EnhancedDTCInfo] = {}
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        for row in conn.execute("SELECT * FROM dtc_enhanced"):
            result[row["code"]] = EnhancedDTCInfo(
                code=row["code"],
                severity=row["severity"],
                drivability_impact=row["drivability_impact"],
                common_causes=json.loads(row["common_causes"]),
                diagnostic_steps=json.loads(row["diagnostic_steps"]),
                related_codes=json.loads(row["related_codes"]),
                repair_difficulty=row["repair_difficulty"],
                typical_cost_range=row["typical_cost_range"],
                notes=row["notes"],
            )
        conn.close()
        logger.info("Loaded %d enhanced DTCs from database", len(result))
    except Exception as e:
        logger.error("Failed to load enhanced DTCs from DB: %s", e)
    return result


ENHANCED_DTCS: Dict[str, EnhancedDTCInfo] = _load_enhanced_dtcs()


# ============================================================================
# Public API
# ============================================================================

def get_enhanced_dtc_info(dtc_code: str) -> Optional[EnhancedDTCInfo]:
    """
    Get enhanced diagnostic context for a DTC code.

    Returns None if no enhanced info is available for this code.
    """
    return ENHANCED_DTCS.get(dtc_code.upper())


def format_enhanced_dtc(dtc_code: str) -> Optional[str]:
    """
    Get a markdown-formatted enhanced description for a DTC.

    Returns None if no enhanced info is available.
    """
    info = get_enhanced_dtc_info(dtc_code)
    if info:
        return info.format_markdown()
    return None


def get_related_codes(dtc_code: str) -> List[str]:
    """Get codes that commonly appear with this DTC."""
    info = get_enhanced_dtc_info(dtc_code)
    if info:
        return info.related_codes
    return []


def get_all_enhanced_codes() -> List[str]:
    """Get list of all codes that have enhanced info."""
    return sorted(ENHANCED_DTCS.keys())
