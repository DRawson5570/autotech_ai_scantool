"""
Pre-loaded Module Maps by Vehicle Platform

Instead of slow 90-second broadcast scans, use known ECU addresses per platform.
Each map lists the modules typically present on a given vehicle platform,
their CAN bus, request/response addresses, and common DIDs.

Sources:
 - Ford Workshop Manuals (CD4, CD6, P552/P558, U611, etc.)
 - GM Service Information (Alpha, Omega, K2XX, T1XX, etc.)
 - Stellantis TechAuthority (CUSW, eLRS, etc.)
 - Toyota TIS (TNGA-K, TNGA-L, etc.)
 - Honda iN Service (Honda Global, etc.)
 - Hyundai GDS (N3, M3/I platforms, etc.)
 - BMW ISTA (CLAR, UKL, etc.)
 - VW ODIS (MQB, MLB, etc.)

Usage:
    from addons.scan_tool.module_maps import get_platform_modules, identify_platform

    platform = identify_platform(vin_info)  # e.g. "ford_cd4"
    modules = get_platform_modules(platform)
    # -> List of ModuleInfo with addresses, bus, DIDs
"""

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass
class ModuleInfo:
    """Known ECU module on a vehicle platform."""
    name: str                       # e.g. "PCM", "BCM", "ABS"
    full_name: str                  # e.g. "Powertrain Control Module"
    request_addr: int               # e.g. 0x7E0
    response_addr: int              # e.g. 0x7E8
    bus: str = "HS-CAN"             # HS-CAN, MS-CAN, SW-CAN
    common_dids: List[str] = field(default_factory=list)  # DIDs likely supported
    function_area: str = ""         # powertrain, body, chassis, network, infotainment
    optional: bool = False          # True if module is option-dependent


@dataclass
class PlatformMap:
    """Complete module map for a vehicle platform."""
    platform_id: str                # e.g. "ford_cd4"
    platform_name: str              # e.g. "Ford CD4 (Fusion/Edge/MKZ/MKX/Nautilus)"
    manufacturer: str               # ford, gm, stellantis, toyota, honda, hyundai, bmw, vw
    years: Tuple[int, int]          # (start_year, end_year)
    models: List[str]               # Vehicle models on this platform
    modules: List[ModuleInfo] = field(default_factory=list)
    notes: str = ""


# ---------------------------------------------------------------------------
# Ford Platforms
# ---------------------------------------------------------------------------

# ===========================================================================
# Database-backed module maps
# ===========================================================================

ALL_PLATFORMS: Dict[str, PlatformMap] = {}


def _load_module_maps() -> Dict[str, PlatformMap]:
    """Load platform module maps from scan_tool_data.db."""
    import json
    import os
    import sqlite3

    db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "scan_tool_data.db")
    if not os.path.exists(db_path):
        logger.warning("scan_tool_data.db not found — module maps empty")
        return {}

    result: Dict[str, PlatformMap] = {}
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        for row in conn.execute("SELECT * FROM module_maps"):
            modules_data = json.loads(row["modules"])
            modules = []
            for m in modules_data:
                modules.append(ModuleInfo(
                    name=m["name"],
                    full_name=m["full_name"],
                    request_addr=m["request_addr"],
                    response_addr=m["response_addr"],
                    bus=m.get("bus", "HS-CAN"),
                    common_dids=m.get("common_dids", []),
                    function_area=m.get("function_area", ""),
                    optional=m.get("optional", False),
                ))
            platform = PlatformMap(
                platform_id=row["platform_id"],
                platform_name=row["platform_name"],
                manufacturer=row["manufacturer"],
                years=(row["year_start"] or 2010, row["year_end"] or 2030),
                models=json.loads(row["models"]),
                modules=modules,
                notes=row["notes"],
            )
            result[platform.platform_id] = platform
        conn.close()
        logger.info("Loaded %d platform maps from database", len(result))
    except Exception as e:
        logger.error("Failed to load module maps from DB: %s", e)
    return result


ALL_PLATFORMS = _load_module_maps()

# Expose individual platform constants for backward compatibility
for _pid, _plat in ALL_PLATFORMS.items():
    globals()[_pid.upper()] = _plat


# ---------------------------------------------------------------------------
# VIN-to-Platform Mapping (built from ALL_PLATFORMS model lists)
# ---------------------------------------------------------------------------

_MODEL_PLATFORM_MAP: Dict[Tuple[str, str], str] = {}


def _build_model_map() -> None:
    """Build the VIN model→platform mapping from loaded platform data."""
    # Hard-coded mapping for exact model keywords — loaded from DB platform models
    _MAKE_ALIASES = {
        "lincoln": "ford",
        "mercury": "ford",
        "cadillac": "gm",
        "gmc": "gm",
        "buick": "gm",
        "chevrolet": "gm",
        "jeep": "stellantis",
        "chrysler": "stellantis",
        "dodge": "stellantis",
        "ram": "stellantis",
        "lexus": "toyota",
        "acura": "honda",
        "infiniti": "nissan",
        "genesis": "hyundai",
        "kia": "hyundai",
        "audi": "vw",
    }

    for pid, platform in ALL_PLATFORMS.items():
        mfr = platform.manufacturer
        for model_name in platform.models:
            model_lower = model_name.lower().strip()
            # Determine all makes that could map to this manufacturer
            makes = [mfr]
            for alias, target in _MAKE_ALIASES.items():
                if target == mfr:
                    makes.append(alias)
            for make in makes:
                _MODEL_PLATFORM_MAP[(make, model_lower)] = pid


_build_model_map()


def identify_platform(vin_info: Dict[str, Any]) -> Optional[str]:
    """
    Identify the vehicle platform from decoded VIN info.

    Args:
        vin_info: Dict from vin_decoder with keys like 'make', 'model', 'year'

    Returns:
        Platform ID string (e.g. 'ford_cd4') or None if unknown
    """
    make = (vin_info.get("make") or vin_info.get("manufacturer") or "").lower().strip()
    model = (vin_info.get("model") or "").lower().strip()
    year = vin_info.get("year", 0)

    # Try exact match first
    key = (make, model)
    if key in _MODEL_PLATFORM_MAP:
        platform_id = _MODEL_PLATFORM_MAP[key]
        platform = ALL_PLATFORMS.get(platform_id)
        if platform and platform.years[0] <= year <= platform.years[1]:
            return platform_id
        # Return anyway — might be close enough
        return platform_id

    # Try partial model match (e.g. "Silverado 1500" matches "silverado")
    for (m, mod), pid in _MODEL_PLATFORM_MAP.items():
        if m == make and mod in model:
            return pid

    # Try matching just by make to any platform
    for pid, platform in ALL_PLATFORMS.items():
        if platform.manufacturer == make:
            if platform.years[0] <= year <= platform.years[1]:
                return pid

    return None


def get_platform_modules(platform_id: str) -> List[ModuleInfo]:
    """
    Get the known module list for a platform.

    Args:
        platform_id: e.g. 'ford_cd4'

    Returns:
        List of ModuleInfo objects
    """
    platform = ALL_PLATFORMS.get(platform_id)
    if not platform:
        return []
    return platform.modules


def get_platform_info(platform_id: str) -> Optional[PlatformMap]:
    """Get full platform info."""
    return ALL_PLATFORMS.get(platform_id)


def list_platforms(manufacturer: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    List all available platform maps.

    Args:
        manufacturer: Optional filter by manufacturer

    Returns:
        List of platform summary dicts
    """
    results = []
    for pid, platform in ALL_PLATFORMS.items():
        if manufacturer and platform.manufacturer != manufacturer.lower():
            continue
        results.append({
            "platform_id": pid,
            "name": platform.platform_name,
            "manufacturer": platform.manufacturer,
            "years": f"{platform.years[0]}-{platform.years[1]}",
            "models": platform.models,
            "module_count": len(platform.modules),
        })
    return results


def get_fast_scan_addresses(platform_id: str) -> List[Dict[str, Any]]:
    """
    Get targeted scan addresses for fast module discovery.

    Instead of broadcasting to 0x7DF and scanning 0x600-0x7FF,
    this returns the exact addresses to probe for a known platform.

    Args:
        platform_id: e.g. 'ford_cd4'

    Returns:
        List of dicts with request_addr, response_addr, bus, name
    """
    modules = get_platform_modules(platform_id)
    return [
        {
            "name": m.name,
            "full_name": m.full_name,
            "request_addr": f"0x{m.request_addr:03X}",
            "response_addr": f"0x{m.response_addr:03X}",
            "bus": m.bus,
            "function_area": m.function_area,
            "optional": m.optional,
        }
        for m in modules
    ]
