"""
Network Topology Map Renderer

Generates an interactive HTML visualization of the vehicle's CAN bus network,
showing all discovered ECU modules organized by bus type (HS-CAN, MS-CAN, SW-CAN).

The output is a self-contained HTML file with inline CSS/SVG — no external
dependencies. Designed to be embedded in chat responses or opened in a browser.
"""

import html
import json
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Module color/icon assignments by function area
# ---------------------------------------------------------------------------

MODULE_STYLES = {
    # Powertrain
    "PCM":  {"color": "#2196F3", "icon": "⚙️", "area": "Powertrain"},
    "ECM":  {"color": "#2196F3", "icon": "⚙️", "area": "Powertrain"},
    "TCM":  {"color": "#1976D2", "icon": "🔄", "area": "Powertrain"},
    "FICM": {"color": "#1565C0", "icon": "⛽", "area": "Powertrain"},

    # Body / Electrical
    "BCM":  {"color": "#4CAF50", "icon": "💡", "area": "Body"},
    "GEM":  {"color": "#4CAF50", "icon": "💡", "area": "Body"},
    "SJB":  {"color": "#388E3C", "icon": "🔌", "area": "Body"},
    "DDM":  {"color": "#66BB6A", "icon": "🚪", "area": "Body"},
    "PDM":  {"color": "#66BB6A", "icon": "🚪", "area": "Body"},
    "IPC":  {"color": "#81C784", "icon": "📊", "area": "Body"},
    "FCIM": {"color": "#A5D6A7", "icon": "🎛️", "area": "Body"},

    # Safety
    "ABS":  {"color": "#F44336", "icon": "🛑", "area": "Safety"},
    "RCM":  {"color": "#E53935", "icon": "🛡️", "area": "Safety"},
    "SRS":  {"color": "#EF5350", "icon": "🛡️", "area": "Safety"},
    "SDM":  {"color": "#EF5350", "icon": "🛡️", "area": "Safety"},
    "PSCM": {"color": "#C62828", "icon": "🎯", "area": "Safety"},
    "EPS":  {"color": "#C62828", "icon": "🎯", "area": "Safety"},
    "EBCM": {"color": "#D32F2F", "icon": "🛑", "area": "Safety"},

    # Climate
    "HVAC": {"color": "#FF9800", "icon": "❄️", "area": "Climate"},
    "DATC": {"color": "#FF9800", "icon": "❄️", "area": "Climate"},
    "ATC":  {"color": "#FF9800", "icon": "❄️", "area": "Climate"},
    "FHCM": {"color": "#FFA726", "icon": "🔥", "area": "Climate"},

    # Infotainment
    "APIM": {"color": "#9C27B0", "icon": "📱", "area": "Infotainment"},
    "ACM":  {"color": "#8E24AA", "icon": "🔊", "area": "Infotainment"},
    "FCDIM":{"color": "#AB47BC", "icon": "📺", "area": "Infotainment"},
    "Radio":{"color": "#9C27B0", "icon": "📻", "area": "Infotainment"},
    "SCCM": {"color": "#CE93D8", "icon": "🎚️", "area": "Infotainment"},

    # Chassis
    "AWD":  {"color": "#795548", "icon": "🚗", "area": "Chassis"},
    "TPMS": {"color": "#8D6E63", "icon": "🔵", "area": "Chassis"},
    "PAM":  {"color": "#A1887F", "icon": "📐", "area": "Chassis"},
    "IPMA": {"color": "#BCAAA4", "icon": "📷", "area": "Chassis"},

    # Communication
    "GPSM": {"color": "#607D8B", "icon": "📡", "area": "Communication"},
    "TCU":  {"color": "#607D8B", "icon": "📡", "area": "Communication"},
    "OnStar":{"color": "#546E7A", "icon": "📡", "area": "Communication"},
    "TDM":  {"color": "#78909C", "icon": "📡", "area": "Communication"},
}

DEFAULT_STYLE = {"color": "#9E9E9E", "icon": "📦", "area": "Other"}


def _get_module_style(name: str) -> Dict[str, str]:
    """Get color/icon for a module by name."""
    # Exact match
    if name in MODULE_STYLES:
        return MODULE_STYLES[name]
    # Partial match (e.g. "PCM-MS" matches "PCM")
    for key, style in MODULE_STYLES.items():
        if key in name:
            return style
    return DEFAULT_STYLE


def render_topology_html(
    modules: List[Dict[str, Any]],
    vin: str = "",
    vehicle_info: str = "",
) -> str:
    """
    Render a network topology map as self-contained HTML.

    Args:
        modules: List of module dicts with keys:
            - name: str (e.g. "PCM")
            - description: str (e.g. "Powertrain Control Module")
            - request_addr: str or int (e.g. "0x7E0")
            - response_addr: str or int (e.g. "0x7E8")
            - bus: str (e.g. "HS-CAN", "MS-CAN", "SW-CAN")
            - supported_pids: list (optional)
            - dids: dict (optional, DID name→value)
        vin: Vehicle VIN (optional)
        vehicle_info: Human-readable vehicle info (optional)

    Returns:
        Complete HTML string
    """
    # Organize modules by bus
    buses: Dict[str, List[Dict[str, Any]]] = {
        "HS-CAN": [],
        "MS-CAN": [],
        "SW-CAN": [],
    }

    for mod in modules:
        bus = mod.get("bus", "HS-CAN")
        if bus not in buses:
            buses[bus] = []
        buses[bus].append(mod)

    # Sort modules within each bus by address
    for bus in buses:
        buses[bus].sort(key=lambda m: _parse_addr(m.get("request_addr", 0)))

    # Count totals
    total_modules = len(modules)
    total_pids = sum(len(m.get("supported_pids", [])) for m in modules)
    total_dids = sum(len(m.get("dids", {})) for m in modules)

    # Build HTML
    title = vehicle_info or vin or "Vehicle Network"
    bus_sections = []
    for bus_name, bus_modules in buses.items():
        if not bus_modules:
            continue
        bus_sections.append(_render_bus_section(bus_name, bus_modules))

    bus_html = "\n".join(bus_sections)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Network Topology — {html.escape(title)}</title>
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: #0d1117;
    color: #c9d1d9;
    padding: 20px;
    min-height: 100vh;
}}
.header {{
    text-align: center;
    margin-bottom: 30px;
    padding: 20px;
    background: linear-gradient(135deg, #161b22, #1c2128);
    border-radius: 12px;
    border: 1px solid #30363d;
}}
.header h1 {{
    font-size: 1.6em;
    color: #f0f6fc;
    margin-bottom: 8px;
}}
.header .vin {{
    font-family: 'Courier New', monospace;
    font-size: 1.1em;
    color: #58a6ff;
    letter-spacing: 2px;
}}
.header .stats {{
    margin-top: 12px;
    display: flex;
    justify-content: center;
    gap: 30px;
    flex-wrap: wrap;
}}
.header .stat {{
    display: flex;
    flex-direction: column;
    align-items: center;
}}
.header .stat .num {{
    font-size: 1.8em;
    font-weight: bold;
    color: #58a6ff;
}}
.header .stat .label {{
    font-size: 0.85em;
    color: #8b949e;
}}
.bus-section {{
    margin-bottom: 24px;
    background: #161b22;
    border-radius: 12px;
    border: 1px solid #30363d;
    overflow: hidden;
}}
.bus-header {{
    display: flex;
    align-items: center;
    padding: 14px 20px;
    border-bottom: 1px solid #30363d;
    cursor: default;
}}
.bus-header .bus-icon {{
    width: 14px;
    height: 14px;
    border-radius: 50%;
    margin-right: 12px;
    flex-shrink: 0;
}}
.bus-header .bus-name {{
    font-weight: 600;
    font-size: 1.1em;
    color: #f0f6fc;
}}
.bus-header .bus-info {{
    margin-left: auto;
    font-size: 0.85em;
    color: #8b949e;
}}
.bus-line {{
    position: relative;
    padding: 20px 20px 20px 50px;
}}
.bus-line::before {{
    content: '';
    position: absolute;
    left: 36px;
    top: 0;
    bottom: 0;
    width: 3px;
    border-radius: 2px;
}}
.bus-hs .bus-line::before {{ background: linear-gradient(180deg, #58a6ff, #1f6feb); }}
.bus-ms .bus-line::before {{ background: linear-gradient(180deg, #f0883e, #d29922); }}
.bus-sw .bus-line::before {{ background: linear-gradient(180deg, #a371f7, #8957e5); }}
.bus-hs .bus-header .bus-icon {{ background: #58a6ff; box-shadow: 0 0 8px rgba(88,166,255,0.4); }}
.bus-ms .bus-header .bus-icon {{ background: #f0883e; box-shadow: 0 0 8px rgba(240,136,62,0.4); }}
.bus-sw .bus-header .bus-icon {{ background: #a371f7; box-shadow: 0 0 8px rgba(163,113,247,0.4); }}
.module-card {{
    position: relative;
    display: flex;
    align-items: flex-start;
    padding: 14px 16px;
    margin-bottom: 10px;
    background: #0d1117;
    border: 1px solid #30363d;
    border-radius: 10px;
    transition: border-color 0.2s, box-shadow 0.2s;
}}
.module-card:hover {{
    border-color: #58a6ff;
    box-shadow: 0 0 12px rgba(88,166,255,0.15);
}}
.module-card::before {{
    content: '';
    position: absolute;
    left: -18px;
    top: 22px;
    width: 14px;
    height: 2px;
    background: #30363d;
}}
.module-icon {{
    font-size: 1.5em;
    margin-right: 14px;
    flex-shrink: 0;
    width: 36px;
    text-align: center;
}}
.module-body {{
    flex: 1;
    min-width: 0;
}}
.module-name {{
    font-weight: 700;
    font-size: 1.05em;
    display: flex;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
}}
.module-name .name-text {{
    color: #f0f6fc;
}}
.module-name .addr {{
    font-family: 'Courier New', monospace;
    font-size: 0.8em;
    color: #8b949e;
    background: #21262d;
    padding: 2px 8px;
    border-radius: 4px;
}}
.module-desc {{
    font-size: 0.9em;
    color: #8b949e;
    margin-top: 4px;
}}
.module-badges {{
    display: flex;
    gap: 6px;
    margin-top: 8px;
    flex-wrap: wrap;
}}
.badge {{
    font-size: 0.75em;
    padding: 3px 8px;
    border-radius: 12px;
    background: #21262d;
    color: #c9d1d9;
    border: 1px solid #30363d;
    white-space: nowrap;
}}
.badge-pids {{ border-color: #1f6feb; color: #58a6ff; }}
.badge-dids {{ border-color: #238636; color: #3fb950; }}
.badge-area {{ border-color: #30363d; }}
.module-dids {{
    margin-top: 8px;
    padding-top: 8px;
    border-top: 1px solid #21262d;
    font-size: 0.8em;
    color: #8b949e;
    display: none;
}}
.module-card.expanded .module-dids {{
    display: block;
}}
.did-row {{
    display: flex;
    padding: 2px 0;
    gap: 8px;
}}
.did-name {{
    color: #58a6ff;
    min-width: 200px;
    flex-shrink: 0;
}}
.did-value {{
    color: #c9d1d9;
    word-break: break-all;
}}
.expand-btn {{
    cursor: pointer;
    font-size: 0.8em;
    color: #58a6ff;
    background: none;
    border: 1px solid #30363d;
    padding: 2px 10px;
    border-radius: 4px;
    margin-top: 6px;
    display: inline-block;
}}
.expand-btn:hover {{
    background: #21262d;
}}
.legend {{
    display: flex;
    gap: 16px;
    flex-wrap: wrap;
    justify-content: center;
    margin-top: 20px;
    padding: 16px;
    background: #161b22;
    border-radius: 10px;
    border: 1px solid #30363d;
}}
.legend-item {{
    display: flex;
    align-items: center;
    gap: 6px;
    font-size: 0.85em;
    color: #8b949e;
}}
.legend-dot {{
    width: 10px;
    height: 10px;
    border-radius: 50%;
}}
@media (max-width: 600px) {{
    body {{ padding: 10px; }}
    .bus-line {{ padding-left: 40px; }}
    .bus-line::before {{ left: 26px; }}
    .module-card::before {{ left: -14px; width: 10px; }}
}}
</style>
</head>
<body>

<div class="header">
    <h1>🔌 {html.escape(title)}</h1>
    {"<div class='vin'>VIN: " + html.escape(vin) + "</div>" if vin else ""}
    <div class="stats">
        <div class="stat">
            <span class="num">{total_modules}</span>
            <span class="label">Modules</span>
        </div>
        <div class="stat">
            <span class="num">{sum(1 for b, ml in buses.items() if ml)}</span>
            <span class="label">Buses</span>
        </div>
        <div class="stat">
            <span class="num">{total_pids}</span>
            <span class="label">PIDs</span>
        </div>
        <div class="stat">
            <span class="num">{total_dids}</span>
            <span class="label">DIDs</span>
        </div>
    </div>
</div>

{bus_html}

<div class="legend">
    <div class="legend-item"><div class="legend-dot" style="background:#58a6ff"></div>HS-CAN (500 kbps)</div>
    <div class="legend-item"><div class="legend-dot" style="background:#f0883e"></div>MS-CAN (125 kbps)</div>
    <div class="legend-item"><div class="legend-dot" style="background:#a371f7"></div>SW-CAN (33.3 kbps)</div>
</div>

<script>
document.querySelectorAll('.expand-btn').forEach(btn => {{
    btn.addEventListener('click', () => {{
        const card = btn.closest('.module-card');
        card.classList.toggle('expanded');
        btn.textContent = card.classList.contains('expanded') ? '▲ Hide DIDs' : '▼ Show DIDs';
    }});
}});
</script>

</body>
</html>"""


def _render_bus_section(bus_name: str, modules: List[Dict[str, Any]]) -> str:
    """Render a single bus section."""
    bus_info = {
        "HS-CAN": {"class": "bus-hs", "speed": "500 kbps", "pins": "Pins 6 + 14"},
        "MS-CAN": {"class": "bus-ms", "speed": "125 kbps", "pins": "Pins 3 + 11"},
        "SW-CAN": {"class": "bus-sw", "speed": "33.3 kbps", "pins": "Pin 1"},
    }
    info = bus_info.get(bus_name, {"class": "bus-hs", "speed": "?", "pins": "?"})

    module_cards = "\n".join(_render_module_card(m) for m in modules)

    return f"""
<div class="bus-section {info['class']}">
    <div class="bus-header">
        <div class="bus-icon"></div>
        <span class="bus-name">{html.escape(bus_name)}</span>
        <span class="bus-info">{info['speed']} · {info['pins']} · {len(modules)} module{'s' if len(modules) != 1 else ''}</span>
    </div>
    <div class="bus-line">
        {module_cards}
    </div>
</div>"""


def _render_module_card(mod: Dict[str, Any]) -> str:
    """Render a single module card."""
    name = mod.get("name", "Unknown")
    desc = mod.get("description", "")
    style = _get_module_style(name)

    # Format addresses
    req_addr = _format_addr(mod.get("request_addr", 0))
    resp_addr = _format_addr(mod.get("response_addr", 0))

    # Badges
    badges = []
    pids = mod.get("supported_pids", [])
    if pids:
        badges.append(f'<span class="badge badge-pids">{len(pids)} PIDs</span>')

    dids = mod.get("dids", {})
    if dids:
        badges.append(f'<span class="badge badge-dids">{len(dids)} DIDs</span>')

    badges.append(f'<span class="badge badge-area">{style["area"]}</span>')
    badges_html = "\n".join(badges)

    # DID details (expandable)
    did_section = ""
    if dids:
        did_rows = []
        for did_name, did_value in sorted(dids.items()):
            did_rows.append(
                f'<div class="did-row">'
                f'<span class="did-name">{html.escape(str(did_name))}</span>'
                f'<span class="did-value">{html.escape(str(did_value))}</span>'
                f'</div>'
            )
        did_section = f"""
        <button class="expand-btn">▼ Show DIDs</button>
        <div class="module-dids">
            {"".join(did_rows)}
        </div>"""

    return f"""
    <div class="module-card">
        <div class="module-icon">{style['icon']}</div>
        <div class="module-body">
            <div class="module-name">
                <span class="name-text" style="color:{style['color']}">{html.escape(name)}</span>
                <span class="addr">{req_addr} → {resp_addr}</span>
            </div>
            <div class="module-desc">{html.escape(desc)}</div>
            <div class="module-badges">
                {badges_html}
            </div>
            {did_section}
        </div>
    </div>"""


def _parse_addr(addr) -> int:
    """Parse an address to int for sorting."""
    if isinstance(addr, int):
        return addr
    try:
        return int(str(addr).replace("0x", ""), 16)
    except (ValueError, TypeError):
        return 0


def _format_addr(addr) -> str:
    """Format an address for display."""
    if isinstance(addr, int):
        return f"0x{addr:03X}"
    s = str(addr)
    if s.startswith("0x") or s.startswith("0X"):
        return s.upper()
    try:
        return f"0x{int(s, 16):03X}"
    except (ValueError, TypeError):
        return s


def render_topology_from_scan(scan_result: List[Any], vin: str = "", vehicle_info: str = "") -> str:
    """
    Convenience function: convert scan_modules() result to topology HTML.

    Args:
        scan_result: List of ECUModule objects or dicts from scan_modules()
        vin: Vehicle VIN
        vehicle_info: e.g. "2015 Lincoln MKS 3.7L V6"

    Returns:
        HTML string
    """
    modules = []
    for mod in scan_result:
        if hasattr(mod, "name"):
            # ECUModule dataclass
            modules.append({
                "name": mod.name,
                "description": mod.description,
                "request_addr": mod.request_addr,
                "response_addr": mod.response_addr,
                "bus": mod.bus,
                "supported_pids": mod.supported_pids if hasattr(mod, "supported_pids") else [],
                "dids": mod.module_info if hasattr(mod, "module_info") else {},
            })
        elif isinstance(mod, dict):
            modules.append(mod)

    return render_topology_html(modules, vin=vin, vehicle_info=vehicle_info)
