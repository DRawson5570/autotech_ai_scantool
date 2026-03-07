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

FORD_CD4 = PlatformMap(
    platform_id="ford_cd4",
    platform_name="Ford CD4 (Fusion/Edge/MKZ/Lincoln)",
    manufacturer="ford",
    years=(2013, 2020),
    models=["Fusion", "Edge", "MKZ", "MKX", "Nautilus", "Continental", "MKS"],
    notes="CD4 is Ford's mid-size FWD/AWD platform. MS-CAN on pins 3+11.",
    modules=[
        ModuleInfo("PCM", "Powertrain Control Module", 0x7E0, 0x7E8, "HS-CAN",
                   ["F190", "F188", "DD01", "DD02", "DD04"], "powertrain"),
        ModuleInfo("TCM", "Transmission Control Module", 0x7E1, 0x7E9, "HS-CAN",
                   ["F190", "F188", "DD01"], "powertrain"),
        ModuleInfo("ABS", "Anti-lock Brake / Stability Control", 0x760, 0x768, "HS-CAN",
                   ["F190", "F188", "DD01"], "chassis"),
        ModuleInfo("EPAS", "Electric Power Assist Steering", 0x730, 0x738, "HS-CAN",
                   ["F190", "F188"], "chassis"),
        ModuleInfo("RCM", "Restraint Control Module (Airbag)", 0x737, 0x73F, "HS-CAN",
                   ["F190", "F188"], "chassis"),
        ModuleInfo("APIM", "Accessory Protocol Interface Module (SYNC)", 0x7D0, 0x7D8, "HS-CAN",
                   ["F190", "F188", "DE00"], "infotainment"),
        ModuleInfo("IPC", "Instrument Panel Cluster", 0x720, 0x728, "MS-CAN",
                   ["F190", "F188", "DD01", "DE00"], "body"),
        ModuleInfo("GEM", "Generic Electronic Module (BCM)", 0x726, 0x72E, "MS-CAN",
                   ["F190", "F188", "DE01", "DE02", "DE03"], "body"),
        ModuleInfo("DDM", "Driver Door Module", 0x740, 0x748, "MS-CAN",
                   ["F190", "F188"], "body"),
        ModuleInfo("PDM", "Passenger Door Module", 0x741, 0x749, "MS-CAN",
                   ["F190", "F188"], "body"),
        ModuleInfo("ACM", "Audio Control Module", 0x727, 0x72F, "MS-CAN",
                   ["F190", "F188"], "infotainment", optional=True),
        ModuleInfo("PAM", "Parking Aid Module", 0x736, 0x73E, "MS-CAN",
                   ["F190", "F188"], "body", optional=True),
        ModuleInfo("PSCM", "Power Steering Control Module", 0x730, 0x738, "MS-CAN",
                   ["F190", "F188"], "chassis", optional=True),
        ModuleInfo("HVAC", "HVAC Control Module", 0x733, 0x73B, "MS-CAN",
                   ["F190", "F188"], "body"),
        ModuleInfo("GPCM", "Glow Plug Control Module", 0x7EA, 0x7F2, "HS-CAN",
                   ["F190"], "powertrain", optional=True),
        ModuleInfo("TPMS", "Tire Pressure Monitoring", 0x724, 0x72C, "MS-CAN",
                   ["F190", "F188"], "chassis"),
        ModuleInfo("SCCM", "Steering Column Control Module", 0x724, 0x72C, "MS-CAN",
                   ["F190"], "body"),
        ModuleInfo("BECM", "Battery Energy Control Module", 0x7E4, 0x7EC, "HS-CAN",
                   ["F190"], "powertrain", optional=True),
    ],
)

FORD_P552 = PlatformMap(
    platform_id="ford_p552",
    platform_name="Ford P552/P558 (F-150 2015+, Expedition, Navigator)",
    manufacturer="ford",
    years=(2015, 2024),
    models=["F-150", "Expedition", "Navigator", "F-250", "F-350"],
    notes="Full-size truck/SUV platform. MS-CAN on pins 3+11.",
    modules=[
        ModuleInfo("PCM", "Powertrain Control Module", 0x7E0, 0x7E8, "HS-CAN",
                   ["F190", "F188", "DD01", "DD02"], "powertrain"),
        ModuleInfo("TCM", "Transmission Control Module", 0x7E1, 0x7E9, "HS-CAN",
                   ["F190", "F188"], "powertrain"),
        ModuleInfo("ABS", "Anti-lock Brake System", 0x760, 0x768, "HS-CAN",
                   ["F190", "F188", "DD01"], "chassis"),
        ModuleInfo("RCM", "Restraint Control Module", 0x737, 0x73F, "HS-CAN",
                   ["F190", "F188"], "chassis"),
        ModuleInfo("EPAS", "Electric Power Assist Steering", 0x730, 0x738, "HS-CAN",
                   ["F190"], "chassis"),
        ModuleInfo("APIM", "SYNC Module", 0x7D0, 0x7D8, "HS-CAN",
                   ["F190", "F188", "DE00"], "infotainment"),
        ModuleInfo("IPC", "Instrument Panel Cluster", 0x720, 0x728, "MS-CAN",
                   ["F190", "F188"], "body"),
        ModuleInfo("BCM", "Body Control Module", 0x726, 0x72E, "MS-CAN",
                   ["F190", "F188", "DE01", "DE02", "DE03"], "body"),
        ModuleInfo("DDM", "Driver Door Module", 0x740, 0x748, "MS-CAN",
                   ["F190"], "body"),
        ModuleInfo("PDM", "Passenger Door Module", 0x741, 0x749, "MS-CAN",
                   ["F190"], "body"),
        ModuleInfo("ACM", "Audio Control Module", 0x727, 0x72F, "MS-CAN",
                   ["F190"], "infotainment"),
        ModuleInfo("HVAC", "HVAC Module", 0x733, 0x73B, "MS-CAN",
                   ["F190"], "body"),
        ModuleInfo("TPMS", "Tire Pressure Monitoring", 0x724, 0x72C, "MS-CAN",
                   ["F190"], "chassis"),
        ModuleInfo("IPMB", "Image Processing Module B (camera)", 0x706, 0x70E, "HS-CAN",
                   ["F190"], "body", optional=True),
        ModuleInfo("PSCM", "Park Assist / Steering Module", 0x730, 0x738, "MS-CAN",
                   ["F190"], "chassis", optional=True),
        ModuleInfo("4X4", "Transfer Case Control Module", 0x762, 0x76A, "HS-CAN",
                   ["F190"], "powertrain", optional=True),
        ModuleInfo("RDCM", "Rear Door Control Module", 0x775, 0x77D, "MS-CAN",
                   ["F190"], "body", optional=True),
    ],
)

FORD_U611 = PlatformMap(
    platform_id="ford_u611",
    platform_name="Ford U611 (Transit Connect 2014+)",
    manufacturer="ford",
    years=(2014, 2023),
    models=["Transit Connect"],
    notes="Small van platform, shared with Focus/C-Max. MS-CAN pins 3+11.",
    modules=[
        ModuleInfo("PCM", "Powertrain Control Module", 0x7E0, 0x7E8, "HS-CAN",
                   ["F190", "F188", "DD01"], "powertrain"),
        ModuleInfo("TCM", "Transmission Control Module", 0x7E1, 0x7E9, "HS-CAN",
                   ["F190", "F188"], "powertrain"),
        ModuleInfo("ABS", "Anti-lock Brake System", 0x760, 0x768, "HS-CAN",
                   ["F190", "DD01"], "chassis"),
        ModuleInfo("RCM", "Restraint Control Module", 0x737, 0x73F, "HS-CAN",
                   ["F190"], "chassis"),
        ModuleInfo("IPC", "Instrument Panel Cluster", 0x720, 0x728, "MS-CAN",
                   ["F190", "F188"], "body"),
        ModuleInfo("GEM", "Generic Electronic Module", 0x726, 0x72E, "MS-CAN",
                   ["F190", "F188", "DE01", "DE02"], "body"),
        ModuleInfo("HVAC", "HVAC Module", 0x733, 0x73B, "MS-CAN",
                   ["F190"], "body"),
        ModuleInfo("EPAS", "Electric Power Steering", 0x730, 0x738, "HS-CAN",
                   ["F190"], "chassis"),
        ModuleInfo("DDM", "Driver Door Module", 0x740, 0x748, "MS-CAN",
                   ["F190"], "body"),
        ModuleInfo("PDM", "Passenger Door Module", 0x741, 0x749, "MS-CAN",
                   ["F190"], "body"),
        ModuleInfo("TPMS", "Tire Pressure Monitoring", 0x724, 0x72C, "MS-CAN",
                   ["F190"], "chassis"),
    ],
)


# ---------------------------------------------------------------------------
# GM Platforms
# ---------------------------------------------------------------------------

GM_K2XX = PlatformMap(
    platform_id="gm_k2xx",
    platform_name="GM K2XX (Silverado/Sierra/Tahoe/Suburban 2014-2019)",
    manufacturer="gm",
    years=(2014, 2019),
    models=["Silverado 1500", "Sierra 1500", "Tahoe", "Yukon", "Suburban", "Escalade"],
    notes="GM full-size truck. GMLAN MS-CAN at 33.3 kbps (pin 1) for some body modules.",
    modules=[
        ModuleInfo("ECM", "Engine Control Module", 0x7E0, 0x7E8, "HS-CAN",
                   ["F190", "F188", "DD01"], "powertrain"),
        ModuleInfo("TCM", "Transmission Control Module", 0x7E1, 0x7E9, "HS-CAN",
                   ["F190", "F188"], "powertrain"),
        ModuleInfo("EBCM", "Electronic Brake Control Module", 0x741, 0x749, "HS-CAN",
                   ["F190", "F188"], "chassis"),
        ModuleInfo("BCM", "Body Control Module", 0x741, 0x749, "HS-CAN",
                   ["F190", "F188", "DD01"], "body"),
        ModuleInfo("IPC", "Instrument Panel Cluster", 0x7C0, 0x7C8, "HS-CAN",
                   ["F190", "F188"], "body"),
        ModuleInfo("HVAC", "HVAC Control Module", 0x764, 0x76C, "HS-CAN",
                   ["F190"], "body"),
        ModuleInfo("SDM", "Sensing Diagnostic Module (Airbag)", 0x700, 0x708, "HS-CAN",
                   ["F190", "F188"], "chassis"),
        ModuleInfo("EPS", "Electric Power Steering", 0x730, 0x738, "HS-CAN",
                   ["F190"], "chassis"),
        ModuleInfo("TCCM", "Transfer Case Control Module", 0x7E4, 0x7EC, "HS-CAN",
                   ["F190"], "powertrain", optional=True),
        ModuleInfo("HMI", "Human-Machine Interface (radio)", 0x700, 0x708, "HS-CAN",
                   ["F190"], "infotainment"),
        ModuleInfo("OnStar", "OnStar Module", 0x710, 0x718, "HS-CAN",
                   ["F190"], "network", optional=True),
        ModuleInfo("TPMS", "Tire Pressure Monitor", 0x705, 0x70D, "HS-CAN",
                   ["F190"], "chassis"),
        ModuleInfo("PDM", "Passenger Door Module", 0x742, 0x74A, "HS-CAN",
                   ["F190"], "body", optional=True),
        ModuleInfo("DDM", "Driver Door Module", 0x743, 0x74B, "HS-CAN",
                   ["F190"], "body", optional=True),
    ],
)

GM_ALPHA = PlatformMap(
    platform_id="gm_alpha",
    platform_name="GM Alpha (ATS/CTS/CT4/CT5/Camaro)",
    manufacturer="gm",
    years=(2013, 2025),
    models=["ATS", "CTS", "CT4", "CT5", "Camaro"],
    notes="GM's RWD sedan/coupe platform. All on HS-CAN.",
    modules=[
        ModuleInfo("ECM", "Engine Control Module", 0x7E0, 0x7E8, "HS-CAN",
                   ["F190", "F188", "DD01"], "powertrain"),
        ModuleInfo("TCM", "Transmission Control Module", 0x7E1, 0x7E9, "HS-CAN",
                   ["F190", "F188"], "powertrain"),
        ModuleInfo("EBCM", "Electronic Brake Control Module", 0x741, 0x749, "HS-CAN",
                   ["F190", "F188"], "chassis"),
        ModuleInfo("BCM", "Body Control Module", 0x741, 0x749, "HS-CAN",
                   ["F190", "F188"], "body"),
        ModuleInfo("IPC", "Instrument Panel Cluster", 0x7C0, 0x7C8, "HS-CAN",
                   ["F190"], "body"),
        ModuleInfo("SDM", "Airbag Module", 0x700, 0x708, "HS-CAN",
                   ["F190"], "chassis"),
        ModuleInfo("EPS", "Electric Power Steering", 0x730, 0x738, "HS-CAN",
                   ["F190"], "chassis"),
        ModuleInfo("HVAC", "HVAC Module", 0x764, 0x76C, "HS-CAN",
                   ["F190"], "body"),
        ModuleInfo("HMI", "Infotainment Module", 0x700, 0x708, "HS-CAN",
                   ["F190"], "infotainment"),
        ModuleInfo("PDM", "Passenger Door Module", 0x742, 0x74A, "HS-CAN",
                   ["F190"], "body", optional=True),
    ],
)

GM_T1XX = PlatformMap(
    platform_id="gm_t1xx",
    platform_name="GM T1XX (Silverado/Sierra/Tahoe/Suburban 2019+)",
    manufacturer="gm",
    years=(2019, 2026),
    models=["Silverado 1500", "Sierra 1500", "Tahoe", "Yukon", "Suburban", "Escalade"],
    notes="Latest GM full-size truck platform. All HS-CAN.",
    modules=[
        ModuleInfo("ECM", "Engine Control Module", 0x7E0, 0x7E8, "HS-CAN",
                   ["F190", "F188"], "powertrain"),
        ModuleInfo("TCM", "Transmission Control Module", 0x7E1, 0x7E9, "HS-CAN",
                   ["F190", "F188"], "powertrain"),
        ModuleInfo("EBCM", "Electronic Brake Control Module", 0x741, 0x749, "HS-CAN",
                   ["F190"], "chassis"),
        ModuleInfo("BCM", "Body Control Module", 0x741, 0x749, "HS-CAN",
                   ["F190"], "body"),
        ModuleInfo("IPC", "Instrument Panel Cluster", 0x7C0, 0x7C8, "HS-CAN",
                   ["F190"], "body"),
        ModuleInfo("HVAC", "HVAC Module", 0x764, 0x76C, "HS-CAN",
                   ["F190"], "body"),
        ModuleInfo("SDM", "Airbag Module", 0x700, 0x708, "HS-CAN",
                   ["F190"], "chassis"),
        ModuleInfo("EPS", "Electric Power Steering", 0x730, 0x738, "HS-CAN",
                   ["F190"], "chassis"),
        ModuleInfo("TCCM", "Transfer Case Module", 0x7E4, 0x7EC, "HS-CAN",
                   ["F190"], "powertrain", optional=True),
        ModuleInfo("ACM", "A/C Compressor Module", 0x765, 0x76D, "HS-CAN",
                   ["F190"], "body", optional=True),
        ModuleInfo("TPMS", "Tire Pressure Monitor", 0x705, 0x70D, "HS-CAN",
                   ["F190"], "chassis"),
        ModuleInfo("RFA", "Remote Function Actuator", 0x740, 0x748, "HS-CAN",
                   ["F190"], "body"),
        ModuleInfo("VIP", "Vehicle Integration Processor", 0x7D0, 0x7D8, "HS-CAN",
                   ["F190"], "network"),
    ],
)


# ---------------------------------------------------------------------------
# Stellantis / FCA Platforms
# ---------------------------------------------------------------------------

STELLANTIS_CUSW = PlatformMap(
    platform_id="stellantis_cusw",
    platform_name="Stellantis CUSW (Cherokee/200/Renegade/Compass)",
    manufacturer="stellantis",
    years=(2014, 2025),
    models=["Cherokee", "Chrysler 200", "Renegade", "Compass", "ProMaster City"],
    notes="Compact/midsize unibody platform.",
    modules=[
        ModuleInfo("PCM", "Powertrain Control Module", 0x7E0, 0x7E8, "HS-CAN",
                   ["F190", "F188"], "powertrain"),
        ModuleInfo("TCM", "Transmission Control Module", 0x7E1, 0x7E9, "HS-CAN",
                   ["F190", "F188"], "powertrain"),
        ModuleInfo("ABS", "Anti-lock Brake Module", 0x747, 0x74F, "HS-CAN",
                   ["F190", "F188"], "chassis"),
        ModuleInfo("TIPM", "Totally Integrated Power Module", 0x740, 0x748, "HS-CAN",
                   ["F190", "F188"], "body"),
        ModuleInfo("ORC", "Occupant Restraint Controller", 0x700, 0x708, "HS-CAN",
                   ["F190"], "chassis"),
        ModuleInfo("IPC", "Instrument Panel Cluster", 0x742, 0x74A, "HS-CAN",
                   ["F190", "F188"], "body"),
        ModuleInfo("RADIO", "Radio/Head Unit", 0x710, 0x718, "HS-CAN",
                   ["F190"], "infotainment"),
        ModuleInfo("HVAC", "HVAC Module", 0x763, 0x76B, "HS-CAN",
                   ["F190"], "body"),
        ModuleInfo("EPS", "Electric Power Steering", 0x730, 0x738, "HS-CAN",
                   ["F190"], "chassis"),
        ModuleInfo("TPMS", "Tire Pressure Monitor", 0x705, 0x70D, "HS-CAN",
                   ["F190"], "chassis"),
        ModuleInfo("FDCM", "Front Door Control Module", 0x744, 0x74C, "HS-CAN",
                   ["F190"], "body", optional=True),
    ],
)

STELLANTIS_DS = PlatformMap(
    platform_id="stellantis_ds",
    platform_name="Stellantis DS (Ram 1500 2019+, Wagoneer)",
    manufacturer="stellantis",
    years=(2019, 2026),
    models=["Ram 1500", "Wagoneer", "Grand Wagoneer"],
    notes="Full-size truck/SUV platform with advanced electronics.",
    modules=[
        ModuleInfo("PCM", "Powertrain Control Module", 0x7E0, 0x7E8, "HS-CAN",
                   ["F190", "F188"], "powertrain"),
        ModuleInfo("TCM", "Transmission Control Module", 0x7E1, 0x7E9, "HS-CAN",
                   ["F190"], "powertrain"),
        ModuleInfo("ABS", "Anti-lock Brake Module", 0x747, 0x74F, "HS-CAN",
                   ["F190"], "chassis"),
        ModuleInfo("BCM", "Body Control Module", 0x740, 0x748, "HS-CAN",
                   ["F190", "F188"], "body"),
        ModuleInfo("ORC", "Occupant Restraint Controller", 0x700, 0x708, "HS-CAN",
                   ["F190"], "chassis"),
        ModuleInfo("IPC", "Instrument Panel Cluster", 0x742, 0x74A, "HS-CAN",
                   ["F190"], "body"),
        ModuleInfo("RADIO", "Head Unit / Uconnect", 0x710, 0x718, "HS-CAN",
                   ["F190"], "infotainment"),
        ModuleInfo("HVAC", "HVAC Module", 0x763, 0x76B, "HS-CAN",
                   ["F190"], "body"),
        ModuleInfo("EPS", "Electric Power Steering", 0x730, 0x738, "HS-CAN",
                   ["F190"], "chassis"),
        ModuleInfo("TCCM", "Transfer Case Control", 0x762, 0x76A, "HS-CAN",
                   ["F190"], "powertrain", optional=True),
        ModuleInfo("TPMS", "Tire Pressure Monitor", 0x705, 0x70D, "HS-CAN",
                   ["F190"], "chassis"),
        ModuleInfo("APGS", "Active Park Assist", 0x731, 0x739, "HS-CAN",
                   ["F190"], "chassis", optional=True),
    ],
)


# ---------------------------------------------------------------------------
# Toyota Platforms
# ---------------------------------------------------------------------------

TOYOTA_TNGA_K = PlatformMap(
    platform_id="toyota_tnga_k",
    platform_name="Toyota TNGA-K (Camry/RAV4/Highlander/Avalon)",
    manufacturer="toyota",
    years=(2018, 2026),
    models=["Camry", "RAV4", "Highlander", "Avalon", "ES", "Venza", "Sienna"],
    notes="Toyota's mid-size FWD/AWD platform. All HS-CAN at 500 kbps.",
    modules=[
        ModuleInfo("ECM", "Engine Control Module", 0x7E0, 0x7E8, "HS-CAN",
                   ["F190", "F188"], "powertrain"),
        ModuleInfo("ECT", "Electronically Controlled Transmission", 0x7E1, 0x7E9, "HS-CAN",
                   ["F190"], "powertrain"),
        ModuleInfo("VSC", "Vehicle Stability Control (ABS/TRC)", 0x750, 0x758, "HS-CAN",
                   ["F190"], "chassis"),
        ModuleInfo("SRS", "Supplemental Restraint System", 0x780, 0x788, "HS-CAN",
                   ["F190"], "chassis"),
        ModuleInfo("EPS", "Electric Power Steering", 0x7A0, 0x7A8, "HS-CAN",
                   ["F190"], "chassis"),
        ModuleInfo("METER", "Combination Meter (IPC)", 0x7C0, 0x7C8, "HS-CAN",
                   ["F190"], "body"),
        ModuleInfo("BCMB", "Body Control Module (Main Body ECU)", 0x750, 0x758, "HS-CAN",
                   ["F190"], "body"),
        ModuleInfo("AC", "Air Conditioning Amplifier", 0x744, 0x74C, "HS-CAN",
                   ["F190"], "body"),
        ModuleInfo("RADIO", "Audio/Display", 0x7C4, 0x7CC, "HS-CAN",
                   ["F190"], "infotainment"),
        ModuleInfo("SMART", "Smart Key ECU (Certification)", 0x78C, 0x794, "HS-CAN",
                   ["F190"], "body", optional=True),
        ModuleInfo("TPWS", "Tire Pressure Warning", 0x750, 0x758, "HS-CAN",
                   ["F190"], "chassis"),
        ModuleInfo("HV_ECU", "Hybrid Vehicle ECU", 0x7E2, 0x7EA, "HS-CAN",
                   ["F190"], "powertrain", optional=True),
    ],
)

TOYOTA_TNGA_F = PlatformMap(
    platform_id="toyota_tnga_f",
    platform_name="Toyota TNGA-F (Tundra/Sequoia/Land Cruiser 2022+)",
    manufacturer="toyota",
    years=(2022, 2026),
    models=["Tundra", "Sequoia", "Land Cruiser", "LX"],
    notes="Toyota's full-size body-on-frame platform. i-FORCE engine.",
    modules=[
        ModuleInfo("ECM", "Engine Control Module", 0x7E0, 0x7E8, "HS-CAN",
                   ["F190", "F188"], "powertrain"),
        ModuleInfo("ECT", "Transmission", 0x7E1, 0x7E9, "HS-CAN",
                   ["F190"], "powertrain"),
        ModuleInfo("VSC", "Vehicle Stability Control", 0x750, 0x758, "HS-CAN",
                   ["F190"], "chassis"),
        ModuleInfo("SRS", "Airbag Module", 0x780, 0x788, "HS-CAN",
                   ["F190"], "chassis"),
        ModuleInfo("EPS", "Electric Power Steering", 0x7A0, 0x7A8, "HS-CAN",
                   ["F190"], "chassis"),
        ModuleInfo("METER", "Instrument Cluster", 0x7C0, 0x7C8, "HS-CAN",
                   ["F190"], "body"),
        ModuleInfo("BCM", "Body Control", 0x750, 0x758, "HS-CAN",
                   ["F190"], "body"),
        ModuleInfo("RADIO", "Audio/Display", 0x7C4, 0x7CC, "HS-CAN",
                   ["F190"], "infotainment"),
        ModuleInfo("TCCM", "Transfer Case Module", 0x7E4, 0x7EC, "HS-CAN",
                   ["F190"], "powertrain", optional=True),
    ],
)


# ---------------------------------------------------------------------------
# Honda Platforms
# ---------------------------------------------------------------------------

HONDA_GLOBAL = PlatformMap(
    platform_id="honda_global",
    platform_name="Honda Global Small (Civic/HR-V/Fit 2016+)",
    manufacturer="honda",
    years=(2016, 2026),
    models=["Civic", "HR-V", "Fit", "Insight"],
    notes="Honda's compact platform. All HS-CAN.",
    modules=[
        ModuleInfo("ECM/PCM", "Powertrain Control Module", 0x7E0, 0x7E8, "HS-CAN",
                   ["F190", "F188"], "powertrain"),
        ModuleInfo("TCM", "Transmission Module", 0x7E1, 0x7E9, "HS-CAN",
                   ["F190"], "powertrain"),
        ModuleInfo("VSA", "Vehicle Stability Assist (ABS)", 0x750, 0x758, "HS-CAN",
                   ["F190"], "chassis"),
        ModuleInfo("SRS", "Airbag Module", 0x780, 0x788, "HS-CAN",
                   ["F190"], "chassis"),
        ModuleInfo("EPS", "Electric Power Steering", 0x7A0, 0x7A8, "HS-CAN",
                   ["F190"], "chassis"),
        ModuleInfo("MICU", "Multi-function Integrated Control Unit (BCM)", 0x740, 0x748, "HS-CAN",
                   ["F190"], "body"),
        ModuleInfo("GAUGE", "Gauge Control Module", 0x7C0, 0x7C8, "HS-CAN",
                   ["F190"], "body"),
        ModuleInfo("AC", "A/C Control Unit", 0x744, 0x74C, "HS-CAN",
                   ["F190"], "body"),
        ModuleInfo("AUDIO", "Audio Unit", 0x7C4, 0x7CC, "HS-CAN",
                   ["F190"], "infotainment"),
        ModuleInfo("TPMS", "Tire Pressure Monitor", 0x705, 0x70D, "HS-CAN",
                   ["F190"], "chassis"),
    ],
)

HONDA_LIGHT_TRUCK = PlatformMap(
    platform_id="honda_light_truck",
    platform_name="Honda Light Truck (CR-V/Pilot/Passport/Odyssey/Ridgeline)",
    manufacturer="honda",
    years=(2016, 2026),
    models=["CR-V", "Pilot", "Passport", "Odyssey", "Ridgeline", "MDX", "RDX"],
    notes="Honda's mid/full-size platform. All HS-CAN.",
    modules=[
        ModuleInfo("ECM/PCM", "Powertrain Control Module", 0x7E0, 0x7E8, "HS-CAN",
                   ["F190", "F188"], "powertrain"),
        ModuleInfo("TCM", "Transmission Module", 0x7E1, 0x7E9, "HS-CAN",
                   ["F190"], "powertrain"),
        ModuleInfo("VSA", "Vehicle Stability Assist", 0x750, 0x758, "HS-CAN",
                   ["F190"], "chassis"),
        ModuleInfo("SRS", "Airbag Module", 0x780, 0x788, "HS-CAN",
                   ["F190"], "chassis"),
        ModuleInfo("EPS", "Electric Power Steering", 0x7A0, 0x7A8, "HS-CAN",
                   ["F190"], "chassis"),
        ModuleInfo("MICU", "BCM (MICU)", 0x740, 0x748, "HS-CAN",
                   ["F190"], "body"),
        ModuleInfo("GAUGE", "Instrument Cluster", 0x7C0, 0x7C8, "HS-CAN",
                   ["F190"], "body"),
        ModuleInfo("AC", "A/C Control", 0x744, 0x74C, "HS-CAN",
                   ["F190"], "body"),
        ModuleInfo("AUDIO", "Audio Unit", 0x7C4, 0x7CC, "HS-CAN",
                   ["F190"], "infotainment"),
        ModuleInfo("TPMS", "Tire Pressure Monitor", 0x705, 0x70D, "HS-CAN",
                   ["F190"], "chassis"),
        ModuleInfo("SH-AWD", "SH-AWD/AWD Coupling Module", 0x7E4, 0x7EC, "HS-CAN",
                   ["F190"], "powertrain", optional=True),
    ],
)


# ---------------------------------------------------------------------------
# Hyundai / Kia Platforms
# ---------------------------------------------------------------------------

HYUNDAI_N3 = PlatformMap(
    platform_id="hyundai_n3",
    platform_name="Hyundai/Kia N3 (Sonata/K5/Tucson/Santa Fe/Sportage 2020+)",
    manufacturer="hyundai",
    years=(2020, 2026),
    models=["Sonata", "K5", "Tucson", "Santa Fe", "Sportage", "Sorento"],
    notes="Hyundai's 3rd-gen mid-size platform. All HS-CAN.",
    modules=[
        ModuleInfo("ECU", "Engine Control Unit", 0x7E0, 0x7E8, "HS-CAN",
                   ["F190", "F188"], "powertrain"),
        ModuleInfo("TCU", "Transmission Control Unit", 0x7E1, 0x7E9, "HS-CAN",
                   ["F190"], "powertrain"),
        ModuleInfo("ESC", "Electronic Stability Control", 0x750, 0x758, "HS-CAN",
                   ["F190"], "chassis"),
        ModuleInfo("SRS", "Airbag Module", 0x780, 0x788, "HS-CAN",
                   ["F190"], "chassis"),
        ModuleInfo("MDPS", "Motor Driven Power Steering", 0x7A0, 0x7A8, "HS-CAN",
                   ["F190"], "chassis"),
        ModuleInfo("BCM", "Body Control Module", 0x770, 0x778, "HS-CAN",
                   ["F190"], "body"),
        ModuleInfo("CLU", "Cluster (Instrument Panel)", 0x7C0, 0x7C8, "HS-CAN",
                   ["F190"], "body"),
        ModuleInfo("AVN", "Audio/Video/Navigation", 0x7C4, 0x7CC, "HS-CAN",
                   ["F190"], "infotainment"),
        ModuleInfo("FATC", "Full Auto Temperature Control", 0x764, 0x76C, "HS-CAN",
                   ["F190"], "body"),
        ModuleInfo("TPMS", "Tire Pressure Monitor", 0x705, 0x70D, "HS-CAN",
                   ["F190"], "chassis"),
        ModuleInfo("FPCM", "Fuel Pump Control Module", 0x7E4, 0x7EC, "HS-CAN",
                   ["F190"], "powertrain", optional=True),
        ModuleInfo("IBU", "Integrated Body Unit", 0x7A1, 0x7A9, "HS-CAN",
                   ["F190"], "body", optional=True),
    ],
)


# ---------------------------------------------------------------------------
# BMW Platforms
# ---------------------------------------------------------------------------

BMW_CLAR = PlatformMap(
    platform_id="bmw_clar",
    platform_name="BMW CLAR (3/4/5/6/7/8 Series, X3-X7, Z4 2017+)",
    manufacturer="bmw",
    years=(2017, 2026),
    models=["3 Series", "4 Series", "5 Series", "7 Series", "X3", "X4", "X5", "X6", "X7", "Z4"],
    notes="BMW cluster architecture. All HS-CAN via OBD (gateway may block some).",
    modules=[
        ModuleInfo("DME", "Digital Motor Electronics (Engine)", 0x7E0, 0x7E8, "HS-CAN",
                   ["F190", "F188"], "powertrain"),
        ModuleInfo("EGS", "Electronic Transmission Control", 0x7E1, 0x7E9, "HS-CAN",
                   ["F190"], "powertrain"),
        ModuleInfo("DSC", "Dynamic Stability Control", 0x760, 0x768, "HS-CAN",
                   ["F190"], "chassis"),
        ModuleInfo("ACSM", "Advanced Crash Safety Module (Airbag)", 0x700, 0x708, "HS-CAN",
                   ["F190"], "chassis"),
        ModuleInfo("EPS", "Electric Power Steering", 0x730, 0x738, "HS-CAN",
                   ["F190"], "chassis"),
        ModuleInfo("BDC", "Body Domain Controller", 0x740, 0x748, "HS-CAN",
                   ["F190", "F188"], "body"),
        ModuleInfo("KOMBI", "Instrument Cluster", 0x720, 0x728, "HS-CAN",
                   ["F190", "F188"], "body"),
        ModuleInfo("HU", "Head Unit (iDrive/NBT)", 0x7C4, 0x7CC, "HS-CAN",
                   ["F190"], "infotainment"),
        ModuleInfo("IHKA", "Integrated Automatic Heating/AC", 0x764, 0x76C, "HS-CAN",
                   ["F190"], "body"),
        ModuleInfo("RDC", "Tire Pressure Monitor", 0x705, 0x70D, "HS-CAN",
                   ["F190"], "chassis"),
        ModuleInfo("VTG", "Transfer Case Module", 0x7E4, 0x7EC, "HS-CAN",
                   ["F190"], "powertrain", optional=True),
        ModuleInfo("TCB", "Connectivity Box (telematics)", 0x710, 0x718, "HS-CAN",
                   ["F190"], "network", optional=True),
    ],
)


# ---------------------------------------------------------------------------
# VW / Audi Platforms
# ---------------------------------------------------------------------------

VW_MQB = PlatformMap(
    platform_id="vw_mqb",
    platform_name="VW MQB (Golf/Jetta/Tiguan/Atlas/A3/Q3)",
    manufacturer="vw",
    years=(2015, 2026),
    models=["Golf", "GTI", "Jetta", "Tiguan", "Atlas", "Taos", "A3", "Q3"],
    notes="VW transverse FWD/AWD platform. Gateway ECU may block OBD access to some modules.",
    modules=[
        ModuleInfo("ECM", "Engine Control Module", 0x7E0, 0x7E8, "HS-CAN",
                   ["F190", "F188"], "powertrain"),
        ModuleInfo("TCM", "Transmission Control Module", 0x7E1, 0x7E9, "HS-CAN",
                   ["F190"], "powertrain"),
        ModuleInfo("ABS/ESP", "ABS / Electronic Stability", 0x713, 0x77D, "HS-CAN",
                   ["F190"], "chassis"),
        ModuleInfo("AIRBAG", "Airbag Control Module", 0x715, 0x77F, "HS-CAN",
                   ["F190"], "chassis"),
        ModuleInfo("EPS", "Electric Power Steering", 0x712, 0x77C, "HS-CAN",
                   ["F190"], "chassis"),
        ModuleInfo("BCM", "Body Control Module", 0x740, 0x748, "HS-CAN",
                   ["F190"], "body"),
        ModuleInfo("KOMBI", "Instrument Cluster", 0x714, 0x77E, "HS-CAN",
                   ["F190"], "body"),
        ModuleInfo("INFOTAINMENT", "MIB3 Infotainment", 0x7C4, 0x7CC, "HS-CAN",
                   ["F190"], "infotainment"),
        ModuleInfo("CLIMATRONIC", "Climate Control", 0x764, 0x76C, "HS-CAN",
                   ["F190"], "body"),
        ModuleInfo("GW", "Gateway Module", 0x710, 0x718, "HS-CAN",
                   ["F190"], "network"),
        ModuleInfo("TPMS", "Tire Pressure Monitor", 0x705, 0x70D, "HS-CAN",
                   ["F190"], "chassis"),
        ModuleInfo("HALDEX", "Haldex AWD Module", 0x7E4, 0x7EC, "HS-CAN",
                   ["F190"], "powertrain", optional=True),
    ],
)

VW_MLB = PlatformMap(
    platform_id="vw_mlb",
    platform_name="VW MLB/MLBevo (A4-A8/Q5-Q8/Touareg/Cayenne)",
    manufacturer="vw",
    years=(2016, 2026),
    models=["A4", "A5", "A6", "A7", "A8", "Q5", "Q7", "Q8", "Touareg", "Cayenne", "Urus"],
    notes="VW/Audi longitudinal platform.",
    modules=[
        ModuleInfo("ECM", "Engine Control Module", 0x7E0, 0x7E8, "HS-CAN",
                   ["F190", "F188"], "powertrain"),
        ModuleInfo("TCM", "Transmission Control Module", 0x7E1, 0x7E9, "HS-CAN",
                   ["F190"], "powertrain"),
        ModuleInfo("ABS/ESP", "Electronic Stability", 0x713, 0x77D, "HS-CAN",
                   ["F190"], "chassis"),
        ModuleInfo("AIRBAG", "Airbag Module", 0x715, 0x77F, "HS-CAN",
                   ["F190"], "chassis"),
        ModuleInfo("EPS", "Electric Power Steering", 0x712, 0x77C, "HS-CAN",
                   ["F190"], "chassis"),
        ModuleInfo("BCM", "Body Control Module", 0x740, 0x748, "HS-CAN",
                   ["F190"], "body"),
        ModuleInfo("KOMBI", "Instrument Cluster", 0x714, 0x77E, "HS-CAN",
                   ["F190"], "body"),
        ModuleInfo("MIB", "Infotainment", 0x7C4, 0x7CC, "HS-CAN",
                   ["F190"], "infotainment"),
        ModuleInfo("CLIMATRONIC", "Climate Control", 0x764, 0x76C, "HS-CAN",
                   ["F190"], "body"),
        ModuleInfo("GW", "Gateway", 0x710, 0x718, "HS-CAN",
                   ["F190"], "network"),
        ModuleInfo("TPMS", "Tire Pressure Monitor", 0x705, 0x70D, "HS-CAN",
                   ["F190"], "chassis"),
        ModuleInfo("QUATTRO", "Quattro AWD Module", 0x7E4, 0x7EC, "HS-CAN",
                   ["F190"], "powertrain", optional=True),
    ],
)


# ---------------------------------------------------------------------------
# Nissan Platforms
# ---------------------------------------------------------------------------

NISSAN_CMF_CD = PlatformMap(
    platform_id="nissan_cmf_cd",
    platform_name="Nissan CMF-CD (Altima/Rogue/Murano/Pathfinder)",
    manufacturer="nissan",
    years=(2018, 2026),
    models=["Altima", "Rogue", "Murano", "Pathfinder", "QX50", "QX60"],
    notes="Nissan/Infiniti mid-size crossover platform.",
    modules=[
        ModuleInfo("ECM", "Engine Control Module", 0x7E0, 0x7E8, "HS-CAN",
                   ["F190", "F188"], "powertrain"),
        ModuleInfo("CVT", "CVT Control", 0x7E1, 0x7E9, "HS-CAN",
                   ["F190"], "powertrain"),
        ModuleInfo("ABS", "ABS/VDC Module", 0x750, 0x758, "HS-CAN",
                   ["F190"], "chassis"),
        ModuleInfo("SRS", "Airbag Module", 0x780, 0x788, "HS-CAN",
                   ["F190"], "chassis"),
        ModuleInfo("EPS", "Electric Power Steering", 0x7A0, 0x7A8, "HS-CAN",
                   ["F190"], "chassis"),
        ModuleInfo("BCM", "Body Control Module", 0x740, 0x748, "HS-CAN",
                   ["F190"], "body"),
        ModuleInfo("METER", "Instrument Cluster", 0x7C0, 0x7C8, "HS-CAN",
                   ["F190"], "body"),
        ModuleInfo("AV", "Audio/Visual Module", 0x7C4, 0x7CC, "HS-CAN",
                   ["F190"], "infotainment"),
        ModuleInfo("AC", "A/C Amplifier", 0x744, 0x74C, "HS-CAN",
                   ["F190"], "body"),
        ModuleInfo("TPMS", "Tire Pressure Monitor", 0x705, 0x70D, "HS-CAN",
                   ["F190"], "chassis"),
    ],
)


# ---------------------------------------------------------------------------
# Subaru Platforms
# ---------------------------------------------------------------------------

SUBARU_SGP = PlatformMap(
    platform_id="subaru_sgp",
    platform_name="Subaru Global Platform (Impreza/Crosstrek/Forester/Outback/Legacy 2017+)",
    manufacturer="subaru",
    years=(2017, 2026),
    models=["Impreza", "Crosstrek", "Forester", "Outback", "Legacy", "Ascent", "WRX", "BRZ"],
    notes="Subaru's unified platform with symmetrical AWD.",
    modules=[
        ModuleInfo("ECM", "Engine Control Module", 0x7E0, 0x7E8, "HS-CAN",
                   ["F190", "F188"], "powertrain"),
        ModuleInfo("TCM", "CVT/Transmission Module", 0x7E1, 0x7E9, "HS-CAN",
                   ["F190"], "powertrain"),
        ModuleInfo("VDC", "Vehicle Dynamics Control (ABS)", 0x750, 0x758, "HS-CAN",
                   ["F190"], "chassis"),
        ModuleInfo("SRS", "Airbag Module", 0x780, 0x788, "HS-CAN",
                   ["F190"], "chassis"),
        ModuleInfo("EPS", "Electric Power Steering", 0x7A0, 0x7A8, "HS-CAN",
                   ["F190"], "chassis"),
        ModuleInfo("BCM", "Body Integrated Unit", 0x740, 0x748, "HS-CAN",
                   ["F190"], "body"),
        ModuleInfo("METER", "Instrument Cluster", 0x7C0, 0x7C8, "HS-CAN",
                   ["F190"], "body"),
        ModuleInfo("STARLINK", "Audio / Starlink", 0x7C4, 0x7CC, "HS-CAN",
                   ["F190"], "infotainment"),
        ModuleInfo("AC", "HVAC Module", 0x744, 0x74C, "HS-CAN",
                   ["F190"], "body"),
        ModuleInfo("TPMS", "Tire Pressure Monitor", 0x705, 0x70D, "HS-CAN",
                   ["F190"], "chassis"),
        ModuleInfo("DCCD", "Driver Controlled Center Diff", 0x7E4, 0x7EC, "HS-CAN",
                   ["F190"], "powertrain", optional=True),
    ],
)


# ---------------------------------------------------------------------------
# Mazda Platforms
# ---------------------------------------------------------------------------

MAZDA_SCA = PlatformMap(
    platform_id="mazda_sca",
    platform_name="Mazda Skyactiv Architecture (Mazda3/CX-30/CX-5/CX-50/CX-9 2019+)",
    manufacturer="mazda",
    years=(2019, 2026),
    models=["Mazda3", "CX-30", "CX-5", "CX-50", "CX-9", "CX-90", "MX-5"],
    notes="Mazda's latest platform. HS-CAN at 500 kbps.",
    modules=[
        ModuleInfo("PCM", "Powertrain Control Module", 0x7E0, 0x7E8, "HS-CAN",
                   ["F190", "F188"], "powertrain"),
        ModuleInfo("TCM", "Transmission Module", 0x7E1, 0x7E9, "HS-CAN",
                   ["F190"], "powertrain"),
        ModuleInfo("DSC", "Dynamic Stability Control", 0x750, 0x758, "HS-CAN",
                   ["F190"], "chassis"),
        ModuleInfo("SAS", "Airbag Module", 0x780, 0x788, "HS-CAN",
                   ["F190"], "chassis"),
        ModuleInfo("EPS", "Electric Power Steering", 0x7A0, 0x7A8, "HS-CAN",
                   ["F190"], "chassis"),
        ModuleInfo("BSM", "Body System Module (BCM)", 0x740, 0x748, "HS-CAN",
                   ["F190"], "body"),
        ModuleInfo("IC", "Instrument Cluster", 0x7C0, 0x7C8, "HS-CAN",
                   ["F190"], "body"),
        ModuleInfo("CMU", "Connectivity Master Unit", 0x7C4, 0x7CC, "HS-CAN",
                   ["F190"], "infotainment"),
        ModuleInfo("HVAC", "Climate Control", 0x744, 0x74C, "HS-CAN",
                   ["F190"], "body"),
        ModuleInfo("TPMS", "Tire Pressure Monitor", 0x705, 0x70D, "HS-CAN",
                   ["F190"], "chassis"),
    ],
)


# ===========================================================================
# Platform Registry
# ===========================================================================

ALL_PLATFORMS: Dict[str, PlatformMap] = {
    # Ford
    "ford_cd4": FORD_CD4,
    "ford_p552": FORD_P552,
    "ford_u611": FORD_U611,
    # GM
    "gm_k2xx": GM_K2XX,
    "gm_alpha": GM_ALPHA,
    "gm_t1xx": GM_T1XX,
    # Stellantis
    "stellantis_cusw": STELLANTIS_CUSW,
    "stellantis_ds": STELLANTIS_DS,
    # Toyota
    "toyota_tnga_k": TOYOTA_TNGA_K,
    "toyota_tnga_f": TOYOTA_TNGA_F,
    # Honda
    "honda_global": HONDA_GLOBAL,
    "honda_light_truck": HONDA_LIGHT_TRUCK,
    # Hyundai / Kia
    "hyundai_n3": HYUNDAI_N3,
    # BMW
    "bmw_clar": BMW_CLAR,
    # VW / Audi
    "vw_mqb": VW_MQB,
    "vw_mlb": VW_MLB,
    # Nissan
    "nissan_cmf_cd": NISSAN_CMF_CD,
    # Subaru
    "subaru_sgp": SUBARU_SGP,
    # Mazda
    "mazda_sca": MAZDA_SCA,
}


# ---------------------------------------------------------------------------
# VIN-to-Platform Mapping
# ---------------------------------------------------------------------------

# Map (manufacturer, model_keyword) -> platform_id
# Used with parsed VIN info from vin_decoder.py
_MODEL_PLATFORM_MAP: Dict[Tuple[str, str], str] = {
    # Ford
    ("ford", "fusion"): "ford_cd4",
    ("ford", "edge"): "ford_cd4",
    ("lincoln", "mkz"): "ford_cd4",
    ("lincoln", "mkx"): "ford_cd4",
    ("lincoln", "nautilus"): "ford_cd4",
    ("lincoln", "continental"): "ford_cd4",
    ("lincoln", "mks"): "ford_cd4",
    ("ford", "f-150"): "ford_p552",
    ("ford", "f150"): "ford_p552",
    ("ford", "expedition"): "ford_p552",
    ("lincoln", "navigator"): "ford_p552",
    ("ford", "f-250"): "ford_p552",
    ("ford", "f-350"): "ford_p552",
    ("ford", "transit connect"): "ford_u611",
    # GM
    ("chevrolet", "silverado"): "gm_t1xx",
    ("gmc", "sierra"): "gm_t1xx",
    ("chevrolet", "tahoe"): "gm_t1xx",
    ("gmc", "yukon"): "gm_t1xx",
    ("chevrolet", "suburban"): "gm_t1xx",
    ("cadillac", "escalade"): "gm_t1xx",
    ("cadillac", "ats"): "gm_alpha",
    ("cadillac", "cts"): "gm_alpha",
    ("cadillac", "ct4"): "gm_alpha",
    ("cadillac", "ct5"): "gm_alpha",
    ("chevrolet", "camaro"): "gm_alpha",
    # Stellantis
    ("jeep", "cherokee"): "stellantis_cusw",
    ("chrysler", "200"): "stellantis_cusw",
    ("jeep", "renegade"): "stellantis_cusw",
    ("jeep", "compass"): "stellantis_cusw",
    ("ram", "1500"): "stellantis_ds",
    ("jeep", "wagoneer"): "stellantis_ds",
    ("jeep", "grand wagoneer"): "stellantis_ds",
    # Toyota
    ("toyota", "camry"): "toyota_tnga_k",
    ("toyota", "rav4"): "toyota_tnga_k",
    ("toyota", "highlander"): "toyota_tnga_k",
    ("toyota", "avalon"): "toyota_tnga_k",
    ("toyota", "venza"): "toyota_tnga_k",
    ("toyota", "sienna"): "toyota_tnga_k",
    ("lexus", "es"): "toyota_tnga_k",
    ("toyota", "tundra"): "toyota_tnga_f",
    ("toyota", "sequoia"): "toyota_tnga_f",
    ("toyota", "land cruiser"): "toyota_tnga_f",
    ("lexus", "lx"): "toyota_tnga_f",
    # Honda
    ("honda", "civic"): "honda_global",
    ("honda", "hr-v"): "honda_global",
    ("honda", "fit"): "honda_global",
    ("honda", "insight"): "honda_global",
    ("honda", "cr-v"): "honda_light_truck",
    ("honda", "pilot"): "honda_light_truck",
    ("honda", "passport"): "honda_light_truck",
    ("honda", "odyssey"): "honda_light_truck",
    ("honda", "ridgeline"): "honda_light_truck",
    ("acura", "mdx"): "honda_light_truck",
    ("acura", "rdx"): "honda_light_truck",
    # Hyundai / Kia
    ("hyundai", "sonata"): "hyundai_n3",
    ("hyundai", "tucson"): "hyundai_n3",
    ("hyundai", "santa fe"): "hyundai_n3",
    ("kia", "k5"): "hyundai_n3",
    ("kia", "sportage"): "hyundai_n3",
    ("kia", "sorento"): "hyundai_n3",
    # BMW
    ("bmw", "3 series"): "bmw_clar",
    ("bmw", "5 series"): "bmw_clar",
    ("bmw", "7 series"): "bmw_clar",
    ("bmw", "x3"): "bmw_clar",
    ("bmw", "x5"): "bmw_clar",
    ("bmw", "x7"): "bmw_clar",
    # VW
    ("volkswagen", "golf"): "vw_mqb",
    ("volkswagen", "gti"): "vw_mqb",
    ("volkswagen", "jetta"): "vw_mqb",
    ("volkswagen", "tiguan"): "vw_mqb",
    ("volkswagen", "atlas"): "vw_mqb",
    ("volkswagen", "taos"): "vw_mqb",
    ("audi", "a3"): "vw_mqb",
    ("audi", "q3"): "vw_mqb",
    ("audi", "a4"): "vw_mlb",
    ("audi", "a5"): "vw_mlb",
    ("audi", "a6"): "vw_mlb",
    ("audi", "q5"): "vw_mlb",
    ("audi", "q7"): "vw_mlb",
    ("audi", "q8"): "vw_mlb",
    # Nissan
    ("nissan", "altima"): "nissan_cmf_cd",
    ("nissan", "rogue"): "nissan_cmf_cd",
    ("nissan", "murano"): "nissan_cmf_cd",
    ("nissan", "pathfinder"): "nissan_cmf_cd",
    ("infiniti", "qx50"): "nissan_cmf_cd",
    ("infiniti", "qx60"): "nissan_cmf_cd",
    # Subaru
    ("subaru", "impreza"): "subaru_sgp",
    ("subaru", "crosstrek"): "subaru_sgp",
    ("subaru", "forester"): "subaru_sgp",
    ("subaru", "outback"): "subaru_sgp",
    ("subaru", "legacy"): "subaru_sgp",
    ("subaru", "ascent"): "subaru_sgp",
    ("subaru", "wrx"): "subaru_sgp",
    # Mazda
    ("mazda", "mazda3"): "mazda_sca",
    ("mazda", "cx-30"): "mazda_sca",
    ("mazda", "cx-5"): "mazda_sca",
    ("mazda", "cx-50"): "mazda_sca",
    ("mazda", "cx-9"): "mazda_sca",
    ("mazda", "cx-90"): "mazda_sca",
    ("mazda", "mx-5"): "mazda_sca",
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

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
