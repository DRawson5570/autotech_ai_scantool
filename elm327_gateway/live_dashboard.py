"""
Live Data Dashboard Renderer

Generates a self-contained HTML dashboard for real-time vehicle PID monitoring.
Features:
- Radial gauge widgets for critical parameters (RPM, speed, coolant temp)
- Bar gauges for fuel trims and O2 sensors
- Trend sparklines showing last 60 data points
- Color-coded status indicators (green/yellow/red)
- Auto-refresh via JavaScript polling every 1 second
- Configurable layout — drag-and-drop gauge reordering
- Print-friendly mode for snapshots

The output is standalone HTML with inline CSS/JS — no external dependencies.
Designed to be served from the gateway's /live-dashboard endpoint or opened
directly in a browser with manual data injection.
"""

import html
import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# PID display configuration — defines how each PID renders in the dashboard
# ---------------------------------------------------------------------------

PID_DISPLAY_CONFIG: Dict[str, Dict[str, Any]] = {
    # Engine Performance
    "RPM": {
        "label": "Engine RPM",
        "unit": "rpm",
        "min": 0,
        "max": 8000,
        "gauge_type": "radial",
        "zones": [
            {"min": 0, "max": 1000, "color": "#4CAF50"},      # idle — green
            {"min": 1000, "max": 3500, "color": "#8BC34A"},    # normal — light green
            {"min": 3500, "max": 5500, "color": "#FFC107"},    # elevated — yellow
            {"min": 5500, "max": 8000, "color": "#F44336"},    # redline — red
        ],
        "category": "Engine",
        "icon": "⚙️",
        "priority": 1,
    },
    "SPEED": {
        "label": "Vehicle Speed",
        "unit": "mph",
        "min": 0,
        "max": 160,
        "gauge_type": "radial",
        "zones": [
            {"min": 0, "max": 35, "color": "#4CAF50"},
            {"min": 35, "max": 70, "color": "#8BC34A"},
            {"min": 70, "max": 100, "color": "#FFC107"},
            {"min": 100, "max": 160, "color": "#F44336"},
        ],
        "category": "Engine",
        "icon": "🚗",
        "priority": 2,
    },
    "COOLANT_TEMP": {
        "label": "Coolant Temp",
        "unit": "°F",
        "min": -40,
        "max": 300,
        "gauge_type": "radial",
        "zones": [
            {"min": -40, "max": 140, "color": "#2196F3"},     # cold — blue
            {"min": 140, "max": 220, "color": "#4CAF50"},     # normal — green
            {"min": 220, "max": 250, "color": "#FFC107"},     # hot — yellow
            {"min": 250, "max": 300, "color": "#F44336"},     # overheating — red
        ],
        "category": "Engine",
        "icon": "🌡️",
        "priority": 3,
    },
    "ENGINE_LOAD": {
        "label": "Engine Load",
        "unit": "%",
        "min": 0,
        "max": 100,
        "gauge_type": "bar",
        "zones": [
            {"min": 0, "max": 50, "color": "#4CAF50"},
            {"min": 50, "max": 80, "color": "#FFC107"},
            {"min": 80, "max": 100, "color": "#F44336"},
        ],
        "category": "Engine",
        "icon": "📊",
        "priority": 4,
    },
    "THROTTLE_POS": {
        "label": "Throttle Position",
        "unit": "%",
        "min": 0,
        "max": 100,
        "gauge_type": "bar",
        "zones": [
            {"min": 0, "max": 60, "color": "#4CAF50"},
            {"min": 60, "max": 85, "color": "#FFC107"},
            {"min": 85, "max": 100, "color": "#F44336"},
        ],
        "category": "Engine",
        "icon": "🦶",
        "priority": 5,
    },
    "INTAKE_TEMP": {
        "label": "Intake Air Temp",
        "unit": "°F",
        "min": -40,
        "max": 250,
        "gauge_type": "bar",
        "zones": [
            {"min": -40, "max": 60, "color": "#2196F3"},
            {"min": 60, "max": 150, "color": "#4CAF50"},
            {"min": 150, "max": 200, "color": "#FFC107"},
            {"min": 200, "max": 250, "color": "#F44336"},
        ],
        "category": "Engine",
        "icon": "🌬️",
        "priority": 10,
    },
    "MAF": {
        "label": "Mass Air Flow",
        "unit": "g/s",
        "min": 0,
        "max": 250,
        "gauge_type": "bar",
        "zones": [
            {"min": 0, "max": 100, "color": "#4CAF50"},
            {"min": 100, "max": 200, "color": "#FFC107"},
            {"min": 200, "max": 250, "color": "#F44336"},
        ],
        "category": "Engine",
        "icon": "💨",
        "priority": 11,
    },
    "TIMING_ADVANCE": {
        "label": "Timing Advance",
        "unit": "°",
        "min": -10,
        "max": 60,
        "gauge_type": "bar",
        "zones": [
            {"min": -10, "max": 0, "color": "#F44336"},
            {"min": 0, "max": 40, "color": "#4CAF50"},
            {"min": 40, "max": 60, "color": "#FFC107"},
        ],
        "category": "Engine",
        "icon": "⏱️",
        "priority": 12,
    },

    # Fuel System
    "SHORT_FUEL_TRIM_1": {
        "label": "Short FT Bank 1",
        "unit": "%",
        "min": -30,
        "max": 30,
        "gauge_type": "trim",
        "zones": [
            {"min": -30, "max": -10, "color": "#F44336"},     # rich — red
            {"min": -10, "max": -5, "color": "#FFC107"},      # slightly rich — yellow
            {"min": -5, "max": 5, "color": "#4CAF50"},        # normal — green
            {"min": 5, "max": 10, "color": "#FFC107"},        # slightly lean — yellow
            {"min": 10, "max": 30, "color": "#F44336"},       # lean — red
        ],
        "category": "Fuel",
        "icon": "⛽",
        "priority": 6,
    },
    "LONG_FUEL_TRIM_1": {
        "label": "Long FT Bank 1",
        "unit": "%",
        "min": -30,
        "max": 30,
        "gauge_type": "trim",
        "zones": [
            {"min": -30, "max": -10, "color": "#F44336"},
            {"min": -10, "max": -5, "color": "#FFC107"},
            {"min": -5, "max": 5, "color": "#4CAF50"},
            {"min": 5, "max": 10, "color": "#FFC107"},
            {"min": 10, "max": 30, "color": "#F44336"},
        ],
        "category": "Fuel",
        "icon": "⛽",
        "priority": 7,
    },
    "SHORT_FUEL_TRIM_2": {
        "label": "Short FT Bank 2",
        "unit": "%",
        "min": -30,
        "max": 30,
        "gauge_type": "trim",
        "zones": [
            {"min": -30, "max": -10, "color": "#F44336"},
            {"min": -10, "max": -5, "color": "#FFC107"},
            {"min": -5, "max": 5, "color": "#4CAF50"},
            {"min": 5, "max": 10, "color": "#FFC107"},
            {"min": 10, "max": 30, "color": "#F44336"},
        ],
        "category": "Fuel",
        "icon": "⛽",
        "priority": 8,
    },
    "LONG_FUEL_TRIM_2": {
        "label": "Long FT Bank 2",
        "unit": "%",
        "min": -30,
        "max": 30,
        "gauge_type": "trim",
        "zones": [
            {"min": -30, "max": -10, "color": "#F44336"},
            {"min": -10, "max": -5, "color": "#FFC107"},
            {"min": -5, "max": 5, "color": "#4CAF50"},
            {"min": 5, "max": 10, "color": "#FFC107"},
            {"min": 10, "max": 30, "color": "#F44336"},
        ],
        "category": "Fuel",
        "icon": "⛽",
        "priority": 9,
    },
    "FUEL_PRESSURE": {
        "label": "Fuel Pressure",
        "unit": "psi",
        "min": 0,
        "max": 80,
        "gauge_type": "bar",
        "zones": [
            {"min": 0, "max": 25, "color": "#F44336"},
            {"min": 25, "max": 60, "color": "#4CAF50"},
            {"min": 60, "max": 80, "color": "#FFC107"},
        ],
        "category": "Fuel",
        "icon": "🔧",
        "priority": 13,
    },
    "FUEL_LEVEL": {
        "label": "Fuel Level",
        "unit": "%",
        "min": 0,
        "max": 100,
        "gauge_type": "bar",
        "zones": [
            {"min": 0, "max": 15, "color": "#F44336"},
            {"min": 15, "max": 30, "color": "#FFC107"},
            {"min": 30, "max": 100, "color": "#4CAF50"},
        ],
        "category": "Fuel",
        "icon": "⛽",
        "priority": 14,
    },

    # Oxygen Sensors
    "O2_B1S1": {
        "label": "O2 Bank1 Sen1",
        "unit": "V",
        "min": 0,
        "max": 1.1,
        "gauge_type": "bar",
        "zones": [
            {"min": 0, "max": 0.1, "color": "#2196F3"},
            {"min": 0.1, "max": 0.45, "color": "#4CAF50"},
            {"min": 0.45, "max": 0.9, "color": "#4CAF50"},
            {"min": 0.9, "max": 1.1, "color": "#FFC107"},
        ],
        "category": "O2 Sensors",
        "icon": "🔬",
        "priority": 15,
    },
    "O2_B1S2": {
        "label": "O2 Bank1 Sen2",
        "unit": "V",
        "min": 0,
        "max": 1.1,
        "gauge_type": "bar",
        "zones": [
            {"min": 0, "max": 0.1, "color": "#2196F3"},
            {"min": 0.1, "max": 0.45, "color": "#4CAF50"},
            {"min": 0.45, "max": 0.9, "color": "#4CAF50"},
            {"min": 0.9, "max": 1.1, "color": "#FFC107"},
        ],
        "category": "O2 Sensors",
        "icon": "🔬",
        "priority": 16,
    },

    # Emissions
    "CATALYST_TEMP_B1S1": {
        "label": "Catalyst Temp B1S1",
        "unit": "°F",
        "min": 0,
        "max": 1800,
        "gauge_type": "bar",
        "zones": [
            {"min": 0, "max": 400, "color": "#2196F3"},
            {"min": 400, "max": 1200, "color": "#4CAF50"},
            {"min": 1200, "max": 1600, "color": "#FFC107"},
            {"min": 1600, "max": 1800, "color": "#F44336"},
        ],
        "category": "Emissions",
        "icon": "🏭",
        "priority": 17,
    },

    # Electrical
    "CONTROL_MODULE_VOLTAGE": {
        "label": "Battery Voltage",
        "unit": "V",
        "min": 0,
        "max": 18,
        "gauge_type": "bar",
        "zones": [
            {"min": 0, "max": 11.5, "color": "#F44336"},
            {"min": 11.5, "max": 12.4, "color": "#FFC107"},
            {"min": 12.4, "max": 14.7, "color": "#4CAF50"},
            {"min": 14.7, "max": 18, "color": "#F44336"},
        ],
        "category": "Electrical",
        "icon": "🔋",
        "priority": 18,
    },
    "VOLTAGE": {
        "label": "Battery Voltage",
        "unit": "V",
        "min": 0,
        "max": 18,
        "gauge_type": "bar",
        "zones": [
            {"min": 0, "max": 11.5, "color": "#F44336"},
            {"min": 11.5, "max": 12.4, "color": "#FFC107"},
            {"min": 12.4, "max": 14.7, "color": "#4CAF50"},
            {"min": 14.7, "max": 18, "color": "#F44336"},
        ],
        "category": "Electrical",
        "icon": "🔋",
        "priority": 18,
    },
}


# Default PID groups for quick selection
PID_GROUPS = {
    "Essential": ["RPM", "SPEED", "COOLANT_TEMP", "ENGINE_LOAD"],
    "Fuel System": [
        "SHORT_FUEL_TRIM_1", "LONG_FUEL_TRIM_1",
        "SHORT_FUEL_TRIM_2", "LONG_FUEL_TRIM_2",
        "FUEL_PRESSURE", "FUEL_LEVEL",
    ],
    "Engine Performance": [
        "RPM", "THROTTLE_POS", "ENGINE_LOAD", "MAF",
        "TIMING_ADVANCE", "INTAKE_TEMP",
    ],
    "O2 Sensors": ["O2_B1S1", "O2_B1S2"],
    "Full Scan": list(PID_DISPLAY_CONFIG.keys()),
}


def _get_zone_color(value: float, zones: List[Dict]) -> str:
    """Return the color for a given value based on zone definitions."""
    for zone in zones:
        if zone["min"] <= value <= zone["max"]:
            return zone["color"]
    return "#9E9E9E"  # grey fallback


def render_live_dashboard(
    pids: Optional[List[str]] = None,
    vehicle_info: Optional[Dict[str, str]] = None,
    gateway_url: Optional[str] = None,
    refresh_interval: float = 1.0,
    initial_data: Optional[Dict[str, Dict]] = None,
) -> str:
    """Generate a self-contained HTML live data dashboard.

    Args:
        pids: List of PID names to display. If None, uses Essential group.
        vehicle_info: Dict with year/make/model/vin for the header.
        gateway_url: URL of the gateway for live polling (e.g. http://host:8327).
                     If None, dashboard shows static data only.
        refresh_interval: Seconds between polls (default 1.0).
        initial_data: Optional initial PID readings to display immediately.

    Returns:
        Complete HTML string — open in browser or embed in response.
    """
    if pids is None:
        pids = PID_GROUPS["Essential"]

    # Build gauge configs for JS
    gauge_configs = []
    for pid in pids:
        cfg = PID_DISPLAY_CONFIG.get(pid)
        if not cfg:
            # Create a generic gauge for unknown PIDs
            cfg = {
                "label": pid.replace("_", " ").title(),
                "unit": "",
                "min": 0,
                "max": 100,
                "gauge_type": "bar",
                "zones": [{"min": 0, "max": 100, "color": "#4CAF50"}],
                "category": "Other",
                "icon": "📊",
                "priority": 99,
            }
        gauge_configs.append({"pid": pid, **cfg})

    # Sort by priority
    gauge_configs.sort(key=lambda g: g.get("priority", 99))

    # Vehicle info header
    vi = vehicle_info or {}
    vehicle_header = ""
    if vi:
        parts = []
        if vi.get("year"):
            parts.append(str(vi["year"]))
        if vi.get("make"):
            parts.append(vi["make"])
        if vi.get("model"):
            parts.append(vi["model"])
        vehicle_header = " ".join(parts)

    vehicle_vin = vi.get("vin", "")

    configs_json = json.dumps(gauge_configs)
    initial_json = json.dumps(initial_data or {})
    gateway_url_js = json.dumps(gateway_url) if gateway_url else "null"
    pid_list_json = json.dumps(pids)
    pid_groups_json = json.dumps(PID_GROUPS)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Live Data Dashboard{' — ' + html.escape(vehicle_header) if vehicle_header else ''}</title>
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
    background: #0d1117;
    color: #c9d1d9;
    min-height: 100vh;
}}

/* Header */
.header {{
    background: linear-gradient(135deg, #161b22 0%, #1c2333 100%);
    border-bottom: 1px solid #30363d;
    padding: 12px 24px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    flex-wrap: wrap;
    gap: 12px;
}}
.header-left {{
    display: flex;
    align-items: center;
    gap: 16px;
}}
.header h1 {{
    font-size: 20px;
    font-weight: 600;
    color: #58a6ff;
}}
.header .vehicle-info {{
    font-size: 14px;
    color: #8b949e;
}}
.header .vehicle-info .vin {{
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 12px;
    color: #6e7681;
}}
.header-right {{
    display: flex;
    align-items: center;
    gap: 12px;
}}
.status-dot {{
    width: 10px;
    height: 10px;
    border-radius: 50%;
    display: inline-block;
    margin-right: 6px;
}}
.status-dot.connected {{ background: #3fb950; box-shadow: 0 0 6px #3fb950; }}
.status-dot.disconnected {{ background: #f85149; }}
.status-dot.polling {{ background: #d29922; animation: pulse 1s infinite; }}
@keyframes pulse {{ 0%,100% {{ opacity: 1; }} 50% {{ opacity: 0.4; }} }}

.status-text {{
    font-size: 13px;
    color: #8b949e;
}}

/* Controls Bar */
.controls {{
    background: #161b22;
    border-bottom: 1px solid #21262d;
    padding: 8px 24px;
    display: flex;
    align-items: center;
    gap: 12px;
    flex-wrap: wrap;
}}
.controls select, .controls button {{
    background: #21262d;
    color: #c9d1d9;
    border: 1px solid #30363d;
    border-radius: 6px;
    padding: 6px 12px;
    font-size: 13px;
    cursor: pointer;
}}
.controls button:hover {{ background: #30363d; }}
.controls button.active {{
    background: #238636;
    border-color: #2ea043;
    color: #fff;
}}
.controls button.danger {{
    background: #da3633;
    border-color: #f85149;
    color: #fff;
}}
.controls .spacer {{ flex: 1; }}
.controls .refresh-rate {{
    font-size: 12px;
    color: #6e7681;
}}

/* Gauge Grid */
.gauge-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
    gap: 16px;
    padding: 20px 24px;
}}

/* Gauge Card */
.gauge-card {{
    background: #161b22;
    border: 1px solid #21262d;
    border-radius: 12px;
    padding: 16px;
    position: relative;
    transition: border-color 0.3s, box-shadow 0.3s;
}}
.gauge-card:hover {{
    border-color: #388bfd;
    box-shadow: 0 0 12px rgba(56,139,253,0.1);
}}
.gauge-card.alarm {{
    border-color: #f85149;
    box-shadow: 0 0 16px rgba(248,81,73,0.2);
    animation: alarm-pulse 1.5s infinite;
}}
@keyframes alarm-pulse {{
    0%,100% {{ box-shadow: 0 0 16px rgba(248,81,73,0.2); }}
    50% {{ box-shadow: 0 0 24px rgba(248,81,73,0.4); }}
}}
.gauge-header {{
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 12px;
}}
.gauge-label {{
    font-size: 13px;
    font-weight: 600;
    color: #8b949e;
    display: flex;
    align-items: center;
    gap: 6px;
}}
.gauge-label .icon {{ font-size: 16px; }}
.gauge-category {{
    font-size: 10px;
    text-transform: uppercase;
    letter-spacing: 1px;
    color: #484f58;
    background: #21262d;
    padding: 2px 8px;
    border-radius: 4px;
}}

/* Radial Gauge */
.radial-gauge {{
    position: relative;
    width: 200px;
    height: 120px;
    margin: 0 auto 8px;
}}
.radial-gauge svg {{
    width: 100%;
    height: 100%;
}}
.gauge-value {{
    text-align: center;
    font-size: 36px;
    font-weight: 700;
    font-family: 'Consolas', 'Courier New', monospace;
    line-height: 1;
    margin-bottom: 4px;
}}
.gauge-unit {{
    text-align: center;
    font-size: 12px;
    color: #6e7681;
}}

/* Bar Gauge */
.bar-gauge {{
    height: 24px;
    background: #21262d;
    border-radius: 12px;
    overflow: hidden;
    position: relative;
    margin-bottom: 8px;
}}
.bar-gauge .fill {{
    height: 100%;
    border-radius: 12px;
    transition: width 0.3s ease, background-color 0.3s ease;
    min-width: 2px;
}}
.bar-gauge .marker {{
    position: absolute;
    top: -2px;
    bottom: -2px;
    width: 3px;
    background: #fff;
    border-radius: 2px;
    box-shadow: 0 0 4px rgba(0,0,0,0.5);
    transition: left 0.3s ease;
}}
.bar-value {{
    display: flex;
    justify-content: space-between;
    align-items: baseline;
}}
.bar-value .value {{
    font-size: 28px;
    font-weight: 700;
    font-family: 'Consolas', 'Courier New', monospace;
}}
.bar-value .unit {{
    font-size: 12px;
    color: #6e7681;
}}
.bar-value .minmax {{
    font-size: 11px;
    color: #484f58;
}}

/* Trim Gauge (centered zero) */
.trim-gauge {{
    height: 24px;
    background: #21262d;
    border-radius: 12px;
    overflow: hidden;
    position: relative;
    margin-bottom: 8px;
}}
.trim-gauge .center-line {{
    position: absolute;
    left: 50%;
    top: 0;
    bottom: 0;
    width: 2px;
    background: #484f58;
    z-index: 2;
}}
.trim-gauge .fill {{
    position: absolute;
    top: 0;
    height: 100%;
    transition: left 0.3s ease, width 0.3s ease, background-color 0.3s ease;
    border-radius: 0;
    min-width: 2px;
}}

/* Sparkline */
.sparkline-container {{
    height: 40px;
    margin-top: 8px;
    position: relative;
}}
.sparkline-container svg {{
    width: 100%;
    height: 100%;
}}
.sparkline-container .spark-label {{
    position: absolute;
    top: 0;
    right: 0;
    font-size: 10px;
    color: #484f58;
}}

/* Footer */
.footer {{
    text-align: center;
    padding: 16px;
    font-size: 11px;
    color: #484f58;
    border-top: 1px solid #21262d;
}}

/* Responsive */
@media (max-width: 640px) {{
    .gauge-grid {{ grid-template-columns: 1fr; padding: 12px; gap: 12px; }}
    .header {{ padding: 10px 12px; }}
    .controls {{ padding: 8px 12px; }}
}}

/* Print */
@media print {{
    body {{ background: #fff; color: #000; }}
    .gauge-card {{ border: 1px solid #ddd; break-inside: avoid; }}
    .controls {{ display: none; }}
    .gauge-value, .bar-value .value {{ color: #000; }}
}}
</style>
</head>
<body>

<div class="header">
    <div class="header-left">
        <h1>🏎️ Live Data Dashboard</h1>
        <div class="vehicle-info">
            {f'<span>{html.escape(vehicle_header)}</span>' if vehicle_header else ''}
            {f'<span class="vin">{html.escape(vehicle_vin)}</span>' if vehicle_vin else ''}
        </div>
    </div>
    <div class="header-right">
        <span class="status-dot disconnected" id="statusDot"></span>
        <span class="status-text" id="statusText">Disconnected</span>
    </div>
</div>

<div class="controls">
    <select id="presetSelect" onchange="loadPreset(this.value)">
        <option value="">-- Preset Groups --</option>
    </select>
    <button id="startBtn" onclick="togglePolling()">▶ Start</button>
    <button onclick="takeSnapshot()">📸 Snapshot</button>
    <button onclick="clearHistory()">🗑️ Clear History</button>
    <div class="spacer"></div>
    <div class="refresh-rate">
        <label>Interval:
            <select id="intervalSelect" onchange="setInterval_(parseFloat(this.value))">
                <option value="0.5">500ms</option>
                <option value="1" selected>1s</option>
                <option value="2">2s</option>
                <option value="5">5s</option>
            </select>
        </label>
    </div>
    <span class="refresh-rate" id="sampleCount">0 samples</span>
</div>

<div class="gauge-grid" id="gaugeGrid"></div>

<div class="footer">
    Autotech AI — Live Data Dashboard &bull;
    <span id="timestamp"></span>
</div>

<script>
// Configuration
const CONFIGS = {configs_json};
const INITIAL_DATA = {initial_json};
const GATEWAY_URL = {gateway_url_js};
const PID_LIST = {pid_list_json};
const PID_GROUPS = {pid_groups_json};
let REFRESH_MS = {int(refresh_interval * 1000)};

// State
let polling = false;
let pollTimer = null;
let history = {{}};   // pid -> [values]
const MAX_HISTORY = 60;
let sampleCount = 0;

// Initialize
document.addEventListener('DOMContentLoaded', () => {{
    buildGauges();
    populatePresets();
    if (INITIAL_DATA && Object.keys(INITIAL_DATA).length > 0) {{
        updateGauges(INITIAL_DATA);
    }}
}});

function populatePresets() {{
    const sel = document.getElementById('presetSelect');
    for (const [name, pids] of Object.entries(PID_GROUPS)) {{
        const opt = document.createElement('option');
        opt.value = name;
        opt.textContent = name + ' (' + pids.length + ' PIDs)';
        sel.appendChild(opt);
    }}
}}

function loadPreset(name) {{
    if (!name) return;
    // Reload page with new PID set — for gateway mode, change query params
    // For static mode, just show an alert
    alert('Preset: ' + name + '\\nPIDs: ' + PID_GROUPS[name].join(', ') +
          '\\n\\nTo change PIDs, re-generate the dashboard with the desired group.');
}}

function buildGauges() {{
    const grid = document.getElementById('gaugeGrid');
    grid.innerHTML = '';
    for (const cfg of CONFIGS) {{
        const card = document.createElement('div');
        card.className = 'gauge-card';
        card.id = 'card-' + cfg.pid;
        card.dataset.pid = cfg.pid;

        let gaugeHtml = '';
        if (cfg.gauge_type === 'radial') {{
            gaugeHtml = buildRadialGauge(cfg);
        }} else if (cfg.gauge_type === 'trim') {{
            gaugeHtml = buildTrimGauge(cfg);
        }} else {{
            gaugeHtml = buildBarGauge(cfg);
        }}

        card.innerHTML = `
            <div class="gauge-header">
                <span class="gauge-label">
                    <span class="icon">${{cfg.icon}}</span>
                    ${{cfg.label}}
                </span>
                <span class="gauge-category">${{cfg.category}}</span>
            </div>
            ${{gaugeHtml}}
            <div class="sparkline-container">
                <svg id="spark-${{cfg.pid}}" viewBox="0 0 240 40" preserveAspectRatio="none">
                    <polyline id="sparkline-${{cfg.pid}}" fill="none" stroke="#388bfd" stroke-width="1.5"
                              points="" vector-effect="non-scaling-stroke"/>
                </svg>
                <span class="spark-label" id="spark-label-${{cfg.pid}}"></span>
            </div>
        `;
        grid.appendChild(card);
        history[cfg.pid] = [];
    }}
}}

function buildRadialGauge(cfg) {{
    // SVG arc gauge — 180° sweep
    const cx = 100, cy = 100, r = 80;
    const startAngle = Math.PI;        // left (180°)
    const endAngle = 2 * Math.PI;      // right (360°)

    let arcs = '';
    for (const zone of cfg.zones) {{
        const zoneStart = startAngle + (zone.min - cfg.min) / (cfg.max - cfg.min) * Math.PI;
        const zoneEnd = startAngle + (zone.max - cfg.min) / (cfg.max - cfg.min) * Math.PI;
        const x1 = cx + r * Math.cos(zoneStart);
        const y1 = cy + r * Math.sin(zoneStart);
        const x2 = cx + r * Math.cos(zoneEnd);
        const y2 = cy + r * Math.sin(zoneEnd);
        const large = (zoneEnd - zoneStart) > Math.PI ? 1 : 0;
        arcs += `<path d="M${{x1}} ${{y1}} A${{r}} ${{r}} 0 ${{large}} 1 ${{x2}} ${{y2}}"
                       fill="none" stroke="${{zone.color}}" stroke-width="12" stroke-opacity="0.3"
                       stroke-linecap="round"/>`;
    }}

    return `
        <div class="radial-gauge">
            <svg viewBox="0 0 200 120">
                ${{arcs}}
                <line id="needle-${{cfg.pid}}" x1="100" y1="100" x2="20" y2="100"
                      stroke="#c9d1d9" stroke-width="3" stroke-linecap="round"
                      transform-origin="100 100"/>
            </svg>
        </div>
        <div class="gauge-value" id="value-${{cfg.pid}}" style="color: #6e7681">--</div>
        <div class="gauge-unit">${{cfg.unit}}</div>
    `;
}}

function buildBarGauge(cfg) {{
    return `
        <div class="bar-gauge">
            <div class="fill" id="fill-${{cfg.pid}}" style="width: 0%; background: #21262d"></div>
        </div>
        <div class="bar-value">
            <span>
                <span class="value" id="value-${{cfg.pid}}" style="color: #6e7681">--</span>
                <span class="unit">${{cfg.unit}}</span>
            </span>
            <span class="minmax">${{cfg.min}} — ${{cfg.max}}</span>
        </div>
    `;
}}

function buildTrimGauge(cfg) {{
    return `
        <div class="trim-gauge">
            <div class="center-line"></div>
            <div class="fill" id="fill-${{cfg.pid}}" style="left: 50%; width: 0%;"></div>
        </div>
        <div class="bar-value">
            <span>
                <span class="value" id="value-${{cfg.pid}}" style="color: #6e7681">--</span>
                <span class="unit">${{cfg.unit}}</span>
            </span>
            <span class="minmax">${{cfg.min}} — ${{cfg.max}}</span>
        </div>
    `;
}}

function updateGauges(data) {{
    // data: {{ PID_NAME: {{ value: number, unit: string }}, ... }}
    sampleCount++;
    document.getElementById('sampleCount').textContent = sampleCount + ' samples';
    document.getElementById('timestamp').textContent = new Date().toLocaleTimeString();

    for (const cfg of CONFIGS) {{
        const reading = data[cfg.pid];
        if (!reading) continue;

        const val = typeof reading === 'object' ? reading.value : reading;
        if (val === null || val === undefined) continue;

        const numVal = parseFloat(val);
        if (isNaN(numVal)) continue;

        // Update history
        history[cfg.pid].push(numVal);
        if (history[cfg.pid].length > MAX_HISTORY) history[cfg.pid].shift();

        // Get zone color
        const color = getZoneColor(numVal, cfg.zones);

        // Update value display
        const valueEl = document.getElementById('value-' + cfg.pid);
        if (valueEl) {{
            valueEl.textContent = formatValue(numVal, cfg);
            valueEl.style.color = color;
        }}

        // Update gauge visual
        if (cfg.gauge_type === 'radial') {{
            updateRadial(cfg, numVal, color);
        }} else if (cfg.gauge_type === 'trim') {{
            updateTrim(cfg, numVal, color);
        }} else {{
            updateBar(cfg, numVal, color);
        }}

        // Update sparkline
        updateSparkline(cfg.pid, cfg);

        // Alarm state
        const card = document.getElementById('card-' + cfg.pid);
        const zones = cfg.zones;
        const lastZone = zones[zones.length - 1];
        const isAlarm = (numVal >= lastZone.min && lastZone.color === '#F44336');
        card.classList.toggle('alarm', isAlarm);
    }}
}}

function formatValue(val, cfg) {{
    if (Math.abs(val) >= 1000) return Math.round(val).toLocaleString();
    if (Math.abs(val) < 1) return val.toFixed(3);
    if (Math.abs(val) < 10) return val.toFixed(1);
    return Math.round(val).toString();
}}

function getZoneColor(val, zones) {{
    for (const z of zones) {{
        if (val >= z.min && val <= z.max) return z.color;
    }}
    return '#6e7681';
}}

function updateRadial(cfg, val, color) {{
    const needle = document.getElementById('needle-' + cfg.pid);
    if (!needle) return;
    const pct = Math.max(0, Math.min(1, (val - cfg.min) / (cfg.max - cfg.min)));
    const angle = -180 + pct * 180;  // -180 to 0
    needle.setAttribute('transform', `rotate(${{angle}} 100 100)`);
    needle.setAttribute('stroke', color);

    // Redraw active arc
    const r = 80, cx = 100, cy = 100;
    const startAngle = Math.PI;
    const valAngle = startAngle + pct * Math.PI;
    const x1 = cx + r * Math.cos(startAngle);
    const y1 = cy + r * Math.sin(startAngle);
    const x2 = cx + r * Math.cos(valAngle);
    const y2 = cy + r * Math.sin(valAngle);
    const large = pct > 0.5 ? 1 : 0;
}}

function updateBar(cfg, val, color) {{
    const fill = document.getElementById('fill-' + cfg.pid);
    if (!fill) return;
    const pct = Math.max(0, Math.min(100,
        (val - cfg.min) / (cfg.max - cfg.min) * 100));
    fill.style.width = pct + '%';
    fill.style.background = color;
}}

function updateTrim(cfg, val, color) {{
    const fill = document.getElementById('fill-' + cfg.pid);
    if (!fill) return;
    // Center at 50%, extend left for negative, right for positive
    const range = cfg.max - cfg.min;
    const center = -cfg.min / range;  // normalized 0-1 position of zero
    const valNorm = (val - cfg.min) / range;

    if (val >= 0) {{
        fill.style.left = (center * 100) + '%';
        fill.style.width = ((valNorm - center) * 100) + '%';
    }} else {{
        fill.style.left = (valNorm * 100) + '%';
        fill.style.width = ((center - valNorm) * 100) + '%';
    }}
    fill.style.background = color;
}}

function updateSparkline(pid, cfg) {{
    const data = history[pid];
    if (data.length < 2) return;

    const svg = document.getElementById('spark-' + pid);
    const polyline = document.getElementById('sparkline-' + pid);
    if (!polyline) return;

    const w = 240, h = 40;
    const minV = Math.min(...data);
    const maxV = Math.max(...data);
    const range = maxV - minV || 1;

    const points = data.map((v, i) => {{
        const x = (i / (MAX_HISTORY - 1)) * w;
        const y = h - ((v - minV) / range) * (h - 4) - 2;
        return `${{x.toFixed(1)}},${{y.toFixed(1)}}`;
    }}).join(' ');

    polyline.setAttribute('points', points);

    // Color the sparkline by current zone
    const lastVal = data[data.length - 1];
    const color = getZoneColor(lastVal, cfg.zones);
    polyline.setAttribute('stroke', color);

    // Min/max label
    const label = document.getElementById('spark-label-' + pid);
    if (label) {{
        label.textContent = `${{minV.toFixed(1)}} — ${{maxV.toFixed(1)}}`;
    }}
}}

// Polling
function togglePolling() {{
    if (polling) {{
        stopPolling();
    }} else {{
        startPolling();
    }}
}}

function startPolling() {{
    if (!GATEWAY_URL) {{
        alert('No gateway URL configured. Dashboard is in static mode.');
        return;
    }}
    polling = true;
    document.getElementById('startBtn').textContent = '⏹ Stop';
    document.getElementById('startBtn').classList.add('danger');
    document.getElementById('statusDot').className = 'status-dot polling';
    document.getElementById('statusText').textContent = 'Polling...';
    doPoll();
}}

function stopPolling() {{
    polling = false;
    if (pollTimer) clearTimeout(pollTimer);
    pollTimer = null;
    document.getElementById('startBtn').textContent = '▶ Start';
    document.getElementById('startBtn').classList.remove('danger');
    document.getElementById('statusDot').className = 'status-dot disconnected';
    document.getElementById('statusText').textContent = 'Stopped';
}}

async function doPoll() {{
    if (!polling) return;
    try {{
        const pidStr = PID_LIST.join(',');
        const res = await fetch(GATEWAY_URL + '/pids', {{
            method: 'POST',
            headers: {{ 'Content-Type': 'application/json' }},
            body: JSON.stringify({{ pids: pidStr }})
        }});
        if (!res.ok) throw new Error('HTTP ' + res.status);
        const json = await res.json();

        // Transform gateway response to our format
        const data = {{}};
        if (json.readings) {{
            for (const [pid, reading] of Object.entries(json.readings)) {{
                data[pid] = {{ value: reading.value, unit: reading.unit }};
            }}
        }}

        updateGauges(data);
        document.getElementById('statusDot').className = 'status-dot connected';
        document.getElementById('statusText').textContent = 'Connected';
    }} catch (err) {{
        console.error('Poll error:', err);
        document.getElementById('statusDot').className = 'status-dot disconnected';
        document.getElementById('statusText').textContent = 'Error: ' + err.message;
    }}
    if (polling) {{
        pollTimer = setTimeout(doPoll, REFRESH_MS);
    }}
}}

function setInterval_(secs) {{
    REFRESH_MS = Math.max(250, secs * 1000);
}}

function clearHistory() {{
    for (const pid of Object.keys(history)) {{
        history[pid] = [];
    }}
    sampleCount = 0;
    document.getElementById('sampleCount').textContent = '0 samples';
    // Clear sparklines
    for (const cfg of CONFIGS) {{
        const polyline = document.getElementById('sparkline-' + cfg.pid);
        if (polyline) polyline.setAttribute('points', '');
        const label = document.getElementById('spark-label-' + cfg.pid);
        if (label) label.textContent = '';
    }}
}}

function takeSnapshot() {{
    // Create a printable snapshot
    const w = window.open('', '_blank');
    w.document.write('<html><head><title>Dashboard Snapshot</title>');
    w.document.write('<style>body {{ font-family: sans-serif; padding: 20px; }}');
    w.document.write('table {{ border-collapse: collapse; width: 100%; }}');
    w.document.write('th, td {{ border: 1px solid #ccc; padding: 8px; text-align: left; }}');
    w.document.write('th {{ background: #f5f5f5; }}');
    w.document.write('.alarm {{ color: red; font-weight: bold; }}</style></head><body>');
    w.document.write('<h2>Dashboard Snapshot — ' + new Date().toLocaleString() + '</h2>');
    w.document.write('<p>Samples collected: ' + sampleCount + '</p>');
    w.document.write('<table><tr><th>PID</th><th>Value</th><th>Unit</th><th>Min (session)</th><th>Max (session)</th></tr>');

    for (const cfg of CONFIGS) {{
        const data = history[cfg.pid];
        if (data.length === 0) continue;
        const last = data[data.length - 1];
        const min = Math.min(...data).toFixed(2);
        const max = Math.max(...data).toFixed(2);
        const zones = cfg.zones;
        const lastZone = zones[zones.length - 1];
        const isAlarm = (last >= lastZone.min && lastZone.color === '#F44336');
        w.document.write('<tr' + (isAlarm ? ' class="alarm"' : '') + '>');
        w.document.write('<td>' + cfg.label + '</td>');
        w.document.write('<td>' + last.toFixed(2) + '</td>');
        w.document.write('<td>' + cfg.unit + '</td>');
        w.document.write('<td>' + min + '</td>');
        w.document.write('<td>' + max + '</td>');
        w.document.write('</tr>');
    }}
    w.document.write('</table></body></html>');
    w.document.close();
    w.print();
}}
</script>
</body>
</html>"""
