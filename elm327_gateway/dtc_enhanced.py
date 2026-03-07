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

This supplements the 269-entry curated overlay in protocol.py and the
18,700-entry SAE database in dtc_database.py. Those provide "what the
code means"; this provides "what to do about it".

Coverage: ~250 of the most commonly encountered DTCs across all makes,
plus Ford/Lincoln-specific codes relevant to the 2015 Lincoln MKS.
"""

import logging
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
            for i, step in enumerate(self.diagnostic_steps, 1):
                lines.append(f"  {i}. {step}")

        if self.related_codes:
            lines.append(f"**Related Codes:** {', '.join(self.related_codes)}")

        if self.typical_cost_range:
            lines.append(f"**Typical Repair Cost:** {self.typical_cost_range} "
                        f"(difficulty: {self.repair_difficulty})")

        if self.notes:
            lines.append(f"**Tech Notes:** {self.notes}")

        return "\n".join(lines)


# ============================================================================
# Enhanced DTC Database
# ============================================================================

ENHANCED_DTCS: Dict[str, EnhancedDTCInfo] = {}


def _add(code, severity, impact, causes, steps, related=None,
         difficulty="medium", cost="", notes=""):
    """Helper to register an enhanced DTC entry."""
    ENHANCED_DTCS[code] = EnhancedDTCInfo(
        code=code, severity=severity, drivability_impact=impact,
        common_causes=causes, diagnostic_steps=steps,
        related_codes=related or [], repair_difficulty=difficulty,
        typical_cost_range=cost, notes=notes,
    )


# ---------------------------------------------------------------------------
# Fuel System / Air Metering (P0100-P0199)
# ---------------------------------------------------------------------------

_add("P0100", "medium", "Rough idle, stalling, poor acceleration",
     ["MAF sensor contaminated/dirty", "MAF connector loose or corroded",
      "Air leak between MAF and throttle body", "MAF sensor failed internally",
      "Wiring harness damage"],
     ["Check MAF connector and wiring for damage", "Clean MAF with MAF-specific cleaner",
      "Check for air leaks downstream of MAF", "Compare MAF reading to known-good at idle (~3-5 g/s)",
      "Swap-test MAF if available"],
     related=["P0101", "P0102", "P0103", "P0171", "P0174"],
     difficulty="easy", cost="$20-$300",
     notes="Ford 3.5/3.7L MAF sensors are prone to contamination from oiled aftermarket air filters")

_add("P0101", "medium", "Poor fuel economy, roughness, hesitation",
     ["MAF sensor dirty/contaminated", "Intake air leak after MAF",
      "Clogged air filter", "MAF sensor out of range"],
     ["Clean or replace MAF sensor", "Check for vacuum leaks with smoke test",
      "Replace air filter", "Read MAF g/s at idle and compare to spec"],
     related=["P0100", "P0171", "P0174"],
     difficulty="easy", cost="$20-$300")

_add("P0106", "medium", "Rough idle, surge, stalling",
     ["MAP sensor failed", "Vacuum hose cracked/disconnected",
      "MAP sensor wiring issue", "Exhaust leak near sensor"],
     ["Check vacuum supply to MAP sensor", "Inspect MAP sensor connector",
      "Compare MAP reading to BARO at key-on engine-off (should be ~29 inHg at sea level)",
      "Apply vacuum with hand pump — reading should change smoothly"],
     related=["P0107", "P0108"],
     difficulty="easy", cost="$30-$200")

_add("P0110", "low", "Minor — uses default IAT value",
     ["IAT sensor connector corroded", "IAT sensor open circuit",
      "Wiring harness damage", "IAT sensor failed"],
     ["Check IAT connector for corrosion", "Measure sensor resistance (should be ~2-3kΩ at 70°F)",
      "Check for 5V reference at connector with sensor unplugged"],
     related=["P0111", "P0112", "P0113"],
     difficulty="easy", cost="$15-$100")

_add("P0115", "medium", "May not reach closed loop, poor fuel economy",
     ["ECT sensor failed", "ECT connector corroded", "Wiring open/short",
      "Thermostat stuck (actual vs reported temp mismatch)"],
     ["Compare ECT reading to actual coolant temp with IR thermometer",
      "Measure sensor resistance (should be ~2.5kΩ at 68°F, ~300Ω at 200°F)",
      "Check 5V reference at connector", "Look for corrosion in connector"],
     related=["P0116", "P0117", "P0118", "P0125", "P0128"],
     difficulty="easy", cost="$15-$150")

_add("P0120", "high", "Limp mode activated, limited throttle response",
     ["TPS sensor failed", "TPS wiring issue", "Throttle body carbon buildup",
      "Accelerator pedal position sensor failure"],
     ["Check TPS voltage: ~0.5V closed, ~4.5V WOT", "Inspect for smooth voltage sweep",
      "Check wiring for chafing near throttle body", "Clean throttle body if sticky"],
     related=["P0121", "P0122", "P0123", "P2135"],
     difficulty="medium", cost="$50-$400",
     notes="Ford electronic throttle bodies sometimes need relearn after replacement — use bidirectional control or drive cycle")

_add("P0125", "low", "Extended warm-up, poor cold-start fuel economy",
     ["Thermostat stuck open", "ECT sensor inaccurate",
      "Cooling fan running continuously", "Low coolant level"],
     ["Check warm-up rate: should reach 190°F in 5-10 min of driving",
      "Compare ECT to actual temp with IR gun at thermostat housing",
      "Check thermostat for proper opening temperature"],
     related=["P0128", "P0115", "P0116"],
     difficulty="easy", cost="$30-$150")

_add("P0128", "low", "Slightly low operating temperature, poor heater performance",
     ["Thermostat stuck open or opening too early", "ECT sensor reading low",
      "Cooling fan relay stuck on"],
     ["Monitor coolant temp during warm-up — should reach 195-220°F",
      "Replace thermostat (most common fix)", "Verify cooling fan operation"],
     related=["P0125", "P0115"],
     difficulty="easy", cost="$30-$150",
     notes="Very common on Ford 3.5/3.7L — thermostat housing is plastic and can crack. Check for coolant leaks at housing.")

# ---------------------------------------------------------------------------
# Fuel Trim / O2 Sensors (P0130-P0175)
# ---------------------------------------------------------------------------

_add("P0130", "medium", "Poor fuel economy, rough running",
     ["O2 sensor failed (Bank 1 Sensor 1)", "O2 sensor wiring damage",
      "Exhaust leak near sensor", "Heater circuit failure"],
     ["Check O2 sensor voltage switching (should oscillate 0.1-0.9V)",
      "Inspect wiring and connector for heat damage",
      "Check for exhaust leaks upstream of sensor",
      "Measure heater resistance (should be 2-30Ω)"],
     related=["P0131", "P0132", "P0133", "P0135", "P0171"],
     difficulty="easy", cost="$50-$250")

_add("P0131", "medium", "Rich running, poor fuel economy, black smoke",
     ["O2 sensor (B1S1) stuck lean", "Exhaust leak upstream of sensor",
      "O2 sensor wiring fault (signal wire shorted to ground)",
      "Fuel pressure too low"],
     ["Check for exhaust leaks", "Monitor O2 sensor live data — should oscillate",
      "Check fuel pressure", "Inspect sensor wiring for damage"],
     related=["P0130", "P0171"],
     difficulty="easy", cost="$50-$250")

_add("P0133", "medium", "Sluggish response, poor fuel economy",
     ["O2 sensor (B1S1) slow response", "Exhaust leak before sensor",
      "Contaminated sensor (silicone, coolant, fuel additives)", "Aging sensor"],
     ["Monitor O2 sensor response time — should switch within 100ms",
      "Perform snap throttle test and watch O2 response",
      "Check for coolant leak into combustion chamber",
      "Replace sensor if over 100K miles"],
     related=["P0130", "P0171", "P0420"],
     difficulty="easy", cost="$50-$250")

_add("P0135", "low", "Extended warm-up time for closed loop",
     ["O2 heater element burned out", "Heater circuit fuse blown",
      "Wiring open/short", "PCM heater driver failure"],
     ["Check O2 heater fuse", "Measure heater resistance at connector (2-30Ω normal)",
      "Check for 12V supply to heater circuit", "Replace sensor if heater open"],
     related=["P0130", "P0155"],
     difficulty="easy", cost="$50-$200")

_add("P0141", "low", "Downstream O2 may not function properly for catalyst monitoring",
     ["O2 heater (B1S2) burned out", "Fuse blown", "Wiring damage"],
     ["Check heater fuse", "Measure heater resistance", "Check 12V supply",
      "Replace sensor if heater is open circuit"],
     related=["P0135", "P0161"],
     difficulty="easy", cost="$50-$200")

_add("P0171", "medium", "Lean running, rough idle, hesitation, poor power",
     ["Vacuum leak (intake gasket, PCV, brake booster line)",
      "MAF sensor dirty/contaminated", "Weak fuel pump / low fuel pressure",
      "Fuel injector(s) clogged", "Exhaust leak before O2 sensor",
      "Cracked/torn intake boot"],
     ["Check live STFT + LTFT — if LTFT > +15%, system is compensating for lean",
      "Smoke test for vacuum leaks", "Clean or replace MAF sensor",
      "Check fuel pressure (spec ~55-62 PSI for Ford 3.7L)",
      "Inspect PCV valve and hose", "Check intake manifold gaskets"],
     related=["P0174", "P0100", "P0101"],
     difficulty="medium", cost="$25-$500",
     notes="P0171+P0174 together = likely MAF or intake leak. P0171 alone = usually Bank 1 specific (intake gasket, injector)")

_add("P0174", "medium", "Lean running (Bank 2), rough idle, hesitation",
     ["Same causes as P0171 but Bank 2 specific",
      "Vacuum leak on Bank 2 side of intake",
      "MAF sensor dirty (affects both banks)", "Low fuel pressure (affects both banks)"],
     ["If P0171 is also set → suspect common cause (MAF, fuel, intake plenum leak)",
      "If P0174 alone → check Bank 2 intake runner gaskets, injectors",
      "Smoke test focusing on Bank 2 side"],
     related=["P0171", "P0100"],
     difficulty="medium", cost="$25-$500")

_add("P0172", "medium", "Rich running, poor fuel economy, possible black smoke",
     ["Leaking fuel injector(s)", "Faulty fuel pressure regulator (high pressure)",
      "MAF sensor reading low (PCM adds extra fuel)", "Purge valve stuck open",
      "O2 sensor reading incorrectly"],
     ["Check STFT + LTFT — if LTFT < -15%, system is trimming fuel down",
      "Check fuel pressure (should not exceed spec)", "Inspect injectors for leaks",
      "Disconnect EVAP purge and retest", "Clean/replace MAF sensor"],
     related=["P0175", "P0100"],
     difficulty="medium", cost="$50-$500")

_add("P0175", "medium", "Rich running (Bank 2), poor fuel economy",
     ["Same as P0172 but Bank 2", "Fuel pressure regulator issue",
      "Injector leak on Bank 2"],
     ["Same diagnostic approach as P0172", "Focus on Bank 2 injectors",
      "If both P0172+P0175 set → system-wide cause (fuel pressure, MAF, purge)"],
     related=["P0172"],
     difficulty="medium", cost="$50-$500")

# ---------------------------------------------------------------------------
# Ignition / Misfire (P0300-P0312)
# ---------------------------------------------------------------------------

_add("P0300", "high", "Rough running, shaking, flashing CEL, potential catalyst damage",
     ["Multiple cylinders misfiring", "Spark plugs worn/fouled",
      "Ignition coil(s) failing", "Vacuum leak(s)", "Low fuel pressure",
      "Head gasket failure (coolant in combustion)"],
     ["Check for cylinder-specific misfire codes (P0301-P0312)",
      "If random: check vacuum leaks, fuel pressure, MAF",
      "If specific cylinders: swap coils to another cylinder and see if misfire follows",
      "Check spark plug condition — fouled, worn, or gap incorrect",
      "Compression test if mechanical failure suspected"],
     related=["P0301", "P0302", "P0303", "P0304", "P0305", "P0306"],
     difficulty="medium", cost="$50-$1000+",
     notes="P0300 random misfire on Ford 3.5/3.7L commonly caused by carbon buildup on intake valves (direct injection), spark plugs, or ignition coils")

_add("P0301", "high", "Cylinder 1 misfire — rough running, shaking, reduced power",
     ["Ignition coil #1 weak/failed", "Spark plug #1 worn/fouled",
      "Fuel injector #1 clogged/dead", "Vacuum leak at cylinder 1 intake runner",
      "Low compression (valve, ring, or head gasket issue)"],
     ["Swap coil #1 with another cylinder — if misfire moves, replace coil",
      "Inspect/replace spark plug #1", "Check injector pulse with noid light",
      "If swaps don't move it: compression test, leak-down test"],
     related=["P0300"],
     difficulty="easy", cost="$30-$400",
     notes="Ford COP (coil-on-plug) — swap coils between cylinders to isolate. $25-60 per coil")

_add("P0302", "high", "Cylinder 2 misfire", ["Same as P0301 but cylinder 2"],
     ["Swap coil #2 to another cylinder", "Replace spark plug #2",
      "Check injector #2"], related=["P0300"], difficulty="easy", cost="$30-$400")

_add("P0303", "high", "Cylinder 3 misfire", ["Same as P0301 but cylinder 3"],
     ["Swap coil #3", "Replace spark plug #3", "Check injector #3"],
     related=["P0300"], difficulty="easy", cost="$30-$400")

_add("P0304", "high", "Cylinder 4 misfire", ["Same as P0301 but cylinder 4"],
     ["Swap coil #4", "Replace spark plug #4", "Check injector #4"],
     related=["P0300"], difficulty="easy", cost="$30-$400")

_add("P0305", "high", "Cylinder 5 misfire", ["Same as P0301 but cylinder 5"],
     ["Swap coil #5", "Replace spark plug #5", "Check injector #5"],
     related=["P0300"], difficulty="easy", cost="$30-$400")

_add("P0306", "high", "Cylinder 6 misfire", ["Same as P0301 but cylinder 6"],
     ["Swap coil #6", "Replace spark plug #6", "Check injector #6"],
     related=["P0300"], difficulty="easy", cost="$30-$400")

# ---------------------------------------------------------------------------
# Catalyst / Emissions (P0400-P0460)
# ---------------------------------------------------------------------------

_add("P0401", "medium", "May cause NOx-related smog failure",
     ["EGR passages clogged with carbon", "EGR valve stuck closed/failed",
      "EGR vacuum supply issue", "DPFE sensor failed (Ford-specific)"],
     ["Check EGR valve operation — should open with vacuum applied",
      "Clean EGR passages (very common on Ford)", "Test DPFE/EGR pressure sensor",
      "Check vacuum supply line to EGR valve", "Inspect EGR tube for blockage"],
     related=["P0402", "P0404", "P0405"],
     difficulty="medium", cost="$100-$400",
     notes="Ford DPFE sensors are a very common failure on older models. Replace with updated part number.")

_add("P0420", "medium", "Usually no drivability issue — emissions only",
     ["Catalytic converter efficiency below threshold",
      "Catalyst substrate degraded/contaminated", "Downstream O2 sensor issue",
      "Exhaust leak between cat and downstream O2", "Engine misfire history damaging cat"],
     ["Compare upstream vs downstream O2 sensor waveforms — downstream should be steady",
      "Check for exhaust leaks at cat connections",
      "Verify no active misfire codes (misfires destroy cats)",
      "Check for coolant/oil consumption contaminating the cat",
      "If cat is truly failed, replace (aftermarket $200-400, OEM $800-2000)"],
     related=["P0430", "P0133", "P0300"],
     difficulty="medium", cost="$200-$2000",
     notes="P0420 does NOT always mean cat replacement. Check O2 sensors and exhaust leaks first. Ford TSB 14-0180 covers cat degradation on 3.5/3.7L.")

_add("P0430", "medium", "Same as P0420 but Bank 2 catalyst",
     ["Same causes as P0420 but Bank 2 side"],
     ["Same diagnostic steps as P0420, focus on Bank 2"],
     related=["P0420"], difficulty="medium", cost="$200-$2000")

_add("P0440", "low", "No drivability impact — EVAP system issue",
     ["Gas cap loose or damaged", "EVAP canister purge valve malfunction",
      "EVAP canister vent valve issue", "EVAP hose cracked/disconnected"],
     ["Check gas cap seal and tighten", "Smoke test EVAP system",
      "Check purge valve operation", "Inspect EVAP hoses and connections"],
     related=["P0441", "P0442", "P0443", "P0446", "P0455", "P0456"],
     difficulty="easy", cost="$10-$300")

_add("P0442", "low", "No drivability impact — small EVAP leak",
     ["Gas cap seal worn", "Small crack in EVAP hose", "Purge valve minor leak",
      "Canister vent valve issue", "Fuel tank vent hose"],
     ["Replace gas cap and retest first ($5 fix)", "Smoke test EVAP system",
      "Inspect all EVAP hoses for cracks", "Check purge and vent solenoids"],
     related=["P0440", "P0456"],
     difficulty="easy", cost="$5-$250")

_add("P0443", "low", "No drivability impact",
     ["EVAP purge solenoid electrical fault", "Wiring open/short to purge valve",
      "PCM purge driver failure"],
     ["Check purge solenoid connector", "Measure solenoid coil resistance (~20-30Ω)",
      "Check PCM command signal with scope or bidirectional control"],
     related=["P0440", "P0441"],
     difficulty="easy", cost="$20-$150")

_add("P0455", "low", "No drivability impact — large EVAP leak",
     ["Gas cap missing or not sealing", "EVAP hose disconnected",
      "Purge or vent valve stuck open", "Fuel tank or filler neck leak"],
     ["Check gas cap first", "Smoke test will find large leaks quickly",
      "Inspect EVAP canister and all hoses from tank to purge valve"],
     related=["P0440", "P0442"],
     difficulty="easy", cost="$5-$300")

_add("P0456", "low", "No drivability impact — very small EVAP leak",
     ["Gas cap O-ring degraded", "Hairline crack in EVAP hose",
      "EVAP canister micro-crack", "Fuel tank seal issue"],
     ["Replace gas cap and drive 2 cycles", "Smoke test with sensitive detector",
      "These are VERY common — many shops just replace the gas cap first"],
     related=["P0442", "P0440"],
     difficulty="easy", cost="$5-$200",
     notes="P0456 is the most common DTC on modern vehicles. Gas cap replacement fixes ~50% of cases.")

# ---------------------------------------------------------------------------
# Transmission / Torque Converter (P0700-P0799)
# ---------------------------------------------------------------------------

_add("P0700", "high", "Transmission malfunction indicator — has sub-code in TCM",
     ["TCM has stored a DTC (this is just an indicator)",
      "Transmission solenoid issue", "Transmission fluid condition",
      "Wiring between TCM and PCM"],
     ["Read DTCs from TCM module specifically", "Check transmission fluid level and condition",
      "P0700 alone tells you nothing — must read TCM DTCs for actual fault"],
     related=["P0715", "P0720", "P0730", "P0750"],
     difficulty="medium", cost="$100-$3000+",
     notes="P0700 is a 'gateway' code — it just says 'TCM has a problem'. Always read TCM DTCs.")

_add("P0715", "high", "Harsh shifts, no speedometer, transmission errors",
     ["Input/turbine speed sensor failed", "Sensor wiring issue",
      "Transmission internal damage", "Connector corrosion"],
     ["Check input speed sensor connector", "Measure sensor resistance",
      "Compare input to output speed sensor readings",
      "Check for metallic debris on sensor (magnetic pickup)"],
     related=["P0700", "P0720"],
     difficulty="medium", cost="$100-$500")

_add("P0730", "high", "Incorrect gear ratio — slipping, incorrect shifts",
     ["Transmission fluid low or worn", "Internal clutch/band failure",
      "Solenoid body issue", "Torque converter clutch slip"],
     ["Check transmission fluid level AND condition (burnt smell = bad)",
      "Read all transmission DTCs", "Monitor gear ratio PIDs during drive",
      "May need solenoid body replacement or full rebuild"],
     related=["P0700", "P0715", "P0720"],
     difficulty="hard", cost="$500-$4000+")

_add("P0741", "medium", "TCC shudder, reduced fuel economy",
     ["Torque converter clutch stuck off or slipping",
      "Transmission fluid contaminated", "TCC solenoid failure",
      "Torque converter failure"],
     ["Check transmission fluid condition", "Monitor TCC slip rate PID",
      "Test TCC solenoid electrically", "Fluid change may help early-stage shudder"],
     related=["P0700", "P0740", "P0742"],
     difficulty="hard", cost="$200-$3000",
     notes="Ford 6F35 transmission in MKS — TCC shudder is common. Try Mercon LV fluid change first before solenoid body replacement.")

# ---------------------------------------------------------------------------
# OBD System Monitoring (P0400s-P0500s misc)
# ---------------------------------------------------------------------------

_add("P0505", "medium", "Unstable idle, stalling, surging",
     ["Idle Air Control (IAC) valve clogged/failed",
      "Throttle body carbon buildup (electronic TB)",
      "Vacuum leak", "PCM needs throttle body relearn"],
     ["Clean throttle body (electronic TB vehicles)", "Check for vacuum leaks",
      "Perform throttle body relearn procedure",
      "Check IAC valve if equipped (older vehicles)"],
     related=["P0506", "P0507"],
     difficulty="easy", cost="$20-$300",
     notes="Ford electronic throttle bodies need relearn after cleaning or replacement. Use KOER throttle relearn.")

_add("P0506", "medium", "Idle RPM lower than expected",
     ["Carbon buildup in throttle body", "Vacuum leak",
      "IAC valve sticking", "Low fuel pressure affecting idle"],
     ["Clean throttle body", "Check for vacuum leaks",
      "Perform idle relearn", "Check base idle setting"],
     related=["P0505", "P0507"],
     difficulty="easy", cost="$20-$200")

_add("P0507", "medium", "Idle RPM higher than expected",
     ["Vacuum leak (most common)", "Throttle body sticking open slightly",
      "IAC valve stuck open", "EVAP purge valve stuck open"],
     ["Smoke test for vacuum leaks", "Inspect throttle body for carbon",
      "Check EVAP purge valve — disconnect and retest idle",
      "Perform throttle body relearn"],
     related=["P0505", "P0506"],
     difficulty="easy", cost="$20-$300")

# ---------------------------------------------------------------------------
# Charging / Electrical (P0560-P0563)
# ---------------------------------------------------------------------------

_add("P0562", "medium", "Electrical issues, dim lights, warning lights",
     ["Weak/failing battery", "Alternator undercharging", "Bad ground connection",
      "Corroded battery terminals", "High parasitic draw"],
     ["Load test battery", "Check charging voltage (should be 13.5-14.5V running)",
      "Inspect battery cable connections", "Check alternator output",
      "Look for corroded ground straps"],
     related=["P0563"],
     difficulty="easy", cost="$20-$300")

_add("P0563", "medium", "Electrical spikes, possible module damage over time",
     ["Alternator overcharging", "Voltage regulator failure",
      "Loose battery connection causing voltage spikes"],
     ["Check charging voltage — should not exceed 14.8V",
      "If over 15V consistently: replace alternator/regulator",
      "Check battery connections for intermittent contact"],
     related=["P0562"],
     difficulty="easy", cost="$100-$500")

# ---------------------------------------------------------------------------
# Vehicle Speed / Vehicle Control (P0500-P0520)
# ---------------------------------------------------------------------------

_add("P0500", "high", "Speedometer inop, cruise control disabled, ABS/traction affected",
     ["Vehicle speed sensor (VSS) failed", "VSS wiring issue",
      "Tone ring damaged", "ABS module not sending speed signal"],
     ["Check VSS connector and wiring", "Scan ABS module for wheel speed DTCs",
      "Compare VSS reading to GPS speed", "Inspect tone ring for damage"],
     related=["P0501", "P0502", "P0503"],
     difficulty="medium", cost="$50-$300")

# ---------------------------------------------------------------------------
# Chassis Codes (C0xxx)
# ---------------------------------------------------------------------------

_add("C0035", "medium", "ABS warning light, ABS/traction may be disabled",
     ["Left front wheel speed sensor open/short", "Sensor air gap too wide",
      "Tone ring damaged or contaminated", "Wiring damage from road debris"],
     ["Inspect LF wheel speed sensor and wiring", "Check sensor air gap",
      "Clean sensor and tone ring", "Compare LF speed to other wheels with live data",
      "Measure sensor resistance (typically 1000-2500Ω)"],
     related=["C0040", "C0045", "C0050"],
     difficulty="easy", cost="$30-$200")

_add("C0040", "medium", "ABS warning light, ABS/traction may be disabled",
     ["Right front wheel speed sensor issue"],
     ["Same procedure as C0035 but right front"],
     related=["C0035"], difficulty="easy", cost="$30-$200")

_add("C0045", "medium", "ABS warning light, ABS/traction may be disabled",
     ["Left rear wheel speed sensor issue"],
     ["Same procedure as C0035 but left rear"],
     related=["C0035"], difficulty="easy", cost="$30-$200")

_add("C0050", "medium", "ABS warning light, ABS/traction may be disabled",
     ["Right rear wheel speed sensor issue"],
     ["Same procedure as C0035 but right rear"],
     related=["C0035"], difficulty="easy", cost="$30-$200")

_add("C0131", "high", "ABS pump motor circuit — ABS completely disabled",
     ["ABS pump motor relay", "ABS module internal failure",
      "Wiring to ABS pump", "Low voltage at ABS module"],
     ["Check ABS fuse and relay", "Measure voltage at ABS pump connector",
      "Check ABS module ground", "May need ABS module replacement"],
     related=["C0265", "C0266"],
     difficulty="hard", cost="$200-$1500")

# ---------------------------------------------------------------------------
# Network Communication (U0xxx)
# ---------------------------------------------------------------------------

_add("U0100", "high", "Multiple warning lights, limited functionality",
     ["CAN bus wiring fault", "PCM has lost communication",
      "PCM power/ground issue", "CAN bus terminated incorrectly"],
     ["Check CAN bus wiring — especially pins 6 and 14 at DLC",
      "Verify PCM power and ground circuits", "Check for voltage on CAN H (~2.5V) and CAN L (~2.5V) with key on",
      "Look for damaged wiring, rodent chew, aftermarket installs"],
     related=["U0101", "U0073"],
     difficulty="hard", cost="$100-$2000+",
     notes="U0100 = no talk from PCM. Check power/ground to PCM first. If multiple U-codes set in many modules, suspect a CAN bus backbone issue.")

_add("U0073", "critical", "Multiple modules offline, many warning lights",
     ["CAN bus backbone wiring failure", "CAN bus short to power or ground",
      "Failed module pulling bus down", "Damaged DLC connector"],
     ["Measure CAN bus termination resistance at DLC (should be ~60Ω between pins 6+14 for HS-CAN)",
      "Disconnect modules one at a time to isolate a failed module pulling the bus down",
      "Check CAN H and CAN L waveforms with oscilloscope",
      "Inspect wiring for damage, especially at connectors and harness pass-throughs"],
     related=["U0100", "U0101", "U0121", "U0140"],
     difficulty="hard", cost="$200-$2000+",
     notes="U0073 = CAN bus offline. This is serious. Usually a wiring issue or a single module shorting the bus.")

_add("U0101", "high", "Transmission may go to limp mode",
     ["TCM lost communication", "TCM power/ground failure", "CAN bus wiring at TCM",
      "TCM internal failure"],
     ["Check TCM power and ground", "Check CAN bus at TCM connector",
      "Verify TCM fuse", "If only U0101 (no other U-codes), TCM is likely the problem"],
     related=["U0100", "P0700"],
     difficulty="medium", cost="$100-$1500")

_add("U0121", "medium", "ABS/traction/stability control disabled",
     ["ABS module lost communication", "ABS module power/ground issue",
      "CAN bus wiring at ABS module", "ABS module failed"],
     ["Check ABS module fuse", "Verify power and ground at ABS connector",
      "Check CAN bus at ABS module", "If other U-codes present, may be bus issue"],
     related=["U0100", "U0073"],
     difficulty="medium", cost="$100-$1000")

_add("U0140", "medium", "BCM/GEM offline — lights, wipers, locks may not work properly",
     ["BCM/GEM module lost communication", "BCM power/ground failure",
      "CAN bus wiring at BCM", "BCM internal failure"],
     ["Check BCM/GEM fuse and power supply", "Verify CAN bus at BCM connector",
      "On Ford: GEM is usually on MS-CAN — check pins 3+11 at DLC"],
     related=["U0100", "U0073"],
     difficulty="medium", cost="$100-$800",
     notes="Ford GEM/SJB is on MS-CAN (125kbps). If only GEM shows U-code but HS-CAN modules are fine, check MS-CAN wiring specifically.")

_add("U0155", "medium", "Climate control non-functional",
     ["HVAC/IPC module lost communication", "Module power issue", "CAN bus wiring"],
     ["Check HVAC module fuse", "Verify power/ground", "Check CAN bus at module"],
     related=["U0140"], difficulty="medium", cost="$100-$600")

# ---------------------------------------------------------------------------
# Body Codes — Ford-Specific (B1xxx-B2xxx)
# ---------------------------------------------------------------------------

_add("B1317", "medium", "Intermittent electrical issues, module reset",
     ["Battery voltage exceeded high threshold", "Alternator overcharging",
      "Loose battery connection causing spikes"],
     ["Load test battery", "Check alternator output voltage",
      "Inspect battery cable connections for corrosion/looseness"],
     related=["B1318", "P0562", "P0563"],
     difficulty="easy", cost="$0-$300")

_add("B1318", "medium", "Intermittent module shutdowns, PATS issues",
     ["Battery voltage dropped below threshold", "Weak battery",
      "Excessive parasitic draw", "Poor ground connection"],
     ["Load test battery", "Check for parasitic draw (spec: <50mA after 30min sleep)",
      "Check charging system", "Inspect battery terminals and grounds"],
     related=["B1317"],
     difficulty="easy", cost="$0-$300")

_add("B1342", "high", "Module has detected an internal fault",
     ["ECU internal fault detected", "Software corruption", "Module failure",
      "Power/ground interruption during operation"],
     ["Note WHICH module set this code — it's a generic 'I'm broken' code",
      "Try clearing code and retesting", "Check module power and ground",
      "Module may need reprogramming or replacement"],
     related=[],
     difficulty="hard", cost="$200-$1500",
     notes="B1342 = 'ECU Is Faulted.' Can be caused by low battery during programming. Make sure battery is fully charged.")

_add("B1600", "high", "Vehicle may not start — PATS immobilizer",
     ["Unprogrammed key used", "PATS transceiver antenna issue",
      "Key transponder chip damaged", "Key not properly programmed"],
     ["Try a different programmed key", "Check PATS key count (need 2 programmed keys minimum for Ford)",
      "Inspect key transponder ring antenna around ignition",
      "May need IDS/FDRS to program new keys"],
     related=["B1601", "B1602", "B1681"],
     difficulty="specialist", cost="$100-$500",
     notes="Ford PATS requires 2 working keys to add a 3rd. If only 1 key works, need dealer-level tool to add keys.")

_add("B1601", "high", "PATS key format rejected — wrong key type",
     ["Wrong key type for this vehicle", "Key transponder malfunction",
      "PATS module configuration issue"],
     ["Verify correct key type for this vehicle", "Try known-good key",
      "May need PATS module reprogramming"],
     related=["B1600", "B1602"],
     difficulty="specialist", cost="$100-$500")

_add("B1681", "high", "Vehicle may not start — no PATS signal received",
     ["PATS transceiver module failed", "Antenna ring at ignition broken",
      "Wiring between antenna and PATS/PCM damaged"],
     ["Check antenna ring around ignition cylinder",
      "Inspect wiring from antenna to PATS module",
      "Test with a different programmed key to rule out key issue"],
     related=["B1600", "B1601"],
     difficulty="specialist", cost="$100-$400")

# ---------------------------------------------------------------------------
# P2xxx Extended Powertrain (Throttle, Turbo, Common Rail)
# ---------------------------------------------------------------------------

_add("P2135", "critical", "Limp mode — throttle body correlation error",
     ["Throttle position sensor disagreement", "Throttle body internal failure",
      "Wiring issue to throttle body (5V ref or signal)", "APP sensor failure"],
     ["Check throttle body connector — 6-pin for Ford", "Check 5V reference",
      "If throttle body replaced: perform relearn procedure",
      "Compare TPS1 vs TPS2 values — should track inversely",
      "Inspect wiring for chafing near throttle body"],
     related=["P0120", "P0121", "P0122", "P0123", "P2138"],
     difficulty="medium", cost="$200-$600",
     notes="P2135 on Ford = dual TPS signals disagree. Throttle body is a single unit on 3.5/3.7L — replace entire TB if internal failure.")

_add("P2138", "critical", "Limp mode — accelerator pedal sensor correlation error",
     ["APP sensor internal failure", "APP wiring issue", "APP connector corrosion",
      "Floor mat interfering with pedal"],
     ["Check APP sensor connector (at pedal assembly)",
      "Compare APP1 vs APP2 voltage — should track proportionally",
      "Inspect wiring harness routing under carpet/floor mat",
      "Replace APP sensor if voltage correlation is off"],
     related=["P2135", "P2122", "P2127"],
     difficulty="medium", cost="$100-$400")

_add("P2195", "medium", "Lean exhaust — post-cat O2 indicates lean",
     ["Exhaust leak after catalyst", "O2 sensor reading offset",
      "Catalyst substrate breakdown", "Fuel trim issue"],
     ["Check for exhaust leaks at cat connections and downstream",
      "Compare pre-cat vs post-cat O2 readings", "Check fuel trims"],
     related=["P2196", "P0171", "P0420"],
     difficulty="medium", cost="$50-$500")

_add("P2196", "medium", "Rich exhaust — post-cat O2 indicates rich",
     ["O2 sensor issue", "Catalyst substrate issue", "Rich fuel trim"],
     ["Check downstream O2 sensor", "Check fuel trims", "Inspect catalyst"],
     related=["P2195", "P0172", "P0420"],
     difficulty="medium", cost="$50-$500")

_add("P2610", "medium", "Engine stall timer performance",
     ["PCM internal timer issue", "Low battery during key cycle",
      "PCM power relay issue"],
     ["Check PCM power relay", "Check battery condition",
      "Clear and monitor — often a one-time event from weak battery"],
     related=[],
     difficulty="easy", cost="$0-$100",
     notes="Common on Ford after battery replacement or disconnect. Usually clears itself after several drive cycles.")


# ---------------------------------------------------------------------------
# Ignition System (P0200-P0299)
# ---------------------------------------------------------------------------

_add("P0200", "high", "Engine misfire, rough running, no-start possible",
     ["Injector driver circuit failure in PCM", "Common ground issue on injector harness",
      "Multiple injector wiring faults", "PCM internal failure"],
     ["Check injector fuse and relay", "Measure resistance at each injector (typically 11-18Ω)",
      "Check for 12V at injector connector with key on",
      "Test injector pulse with noid light while cranking"],
     related=["P0201", "P0202", "P0203", "P0204", "P0300"],
     difficulty="medium", cost="$50-$600")

_add("P0201", "high", "Cylinder 1 misfire, rough running",
     ["Injector #1 failed (open/short)", "Injector #1 connector issue",
      "Wiring fault to injector #1", "PCM driver failure"],
     ["Swap injector #1 with another cylinder — does code follow?",
      "Measure injector resistance (~12Ω typical)", "Check connector for fuel contamination",
      "Use noid light to verify injector pulse"],
     related=["P0300", "P0301"],
     difficulty="medium", cost="$80-$350")

_add("P0217", "critical", "Engine overheating — immediate stop required",
     ["Low coolant level", "Thermostat stuck closed", "Cooling fan inoperative",
      "Water pump failure", "Radiator clogged", "Head gasket failure"],
     ["STOP DRIVING IMMEDIATELY — risk of engine damage",
      "Check coolant level", "Verify cooling fan operation",
      "Check for coolant leaks", "Pressure-test cooling system",
      "Check for combustion gases in coolant (block test)"],
     related=["P0115", "P0116", "P0125", "P0128"],
     difficulty="medium", cost="$100-$3000",
     notes="If head gasket suspected, check for white exhaust smoke, oil/coolant mixing, and sustained high pressure in cooling system")

_add("P0218", "critical", "Transmission overheating — shift to neutral, coast to stop if possible",
     ["Transmission fluid low/burnt", "Transmission cooler blocked",
      "Heavy towing exceeding capacity", "Internal trans failure",
      "Converter clutch slipping"],
     ["Check transmission fluid level and condition (burnt smell = internal damage)",
      "Check trans cooler lines for kinks/blockage",
      "Verify trans cooler flow", "Check trans temp live data"],
     related=["P0700", "P0730"],
     difficulty="hard", cost="$200-$5000")

_add("P0230", "high", "No-start or stalling — no fuel delivery",
     ["Fuel pump relay failed", "Fuel pump wiring fault",
      "Fuel pump failed", "PCM not commanding pump on",
      "Inertia switch tripped (Ford)"],
     ["Check fuel pump relay — swap with known-good same-type relay",
      "Listen for fuel pump prime (2-sec buzz) at key-on",
      "Check fuel pump fuse", "Check inertia switch in trunk/kick panel (Ford)",
      "Measure fuel pressure (spec typically 35-65 psi)"],
     related=["P0231", "P0232"],
     difficulty="medium", cost="$50-$800",
     notes="Ford inertia switch (IFS) trips on impact — check behind right side kick panel or in trunk")

_add("P0299", "high", "Low turbo/supercharger boost — reduced power",
     ["Boost leak in charge air plumbing", "Wastegate stuck open",
      "Turbo bearing failure", "Intercooler leak",
      "Boost pressure sensor fault"],
     ["Smoke test charge air system for leaks",
      "Check wastegate actuator movement", "Listen for turbo whine/grinding",
      "Check intercooler boots and clamps",
      "Compare actual vs desired boost in live data"],
     related=["P0234", "P0235", "P0236"],
     difficulty="medium", cost="$100-$3000")

# ---------------------------------------------------------------------------
# Misfires (P0300-P0312) — expanded
# ---------------------------------------------------------------------------

_add("P0307", "high", "Cylinder 7 misfire — rough, vibration (V8/V10 engines)",
     ["Ignition coil #7 failed", "Spark plug #7 fouled/worn/gapped wrong",
      "Injector #7 fault", "Low compression cyl 7",
      "Valve train issue cyl 7"],
     ["Swap coil #7 with another cylinder — does code follow?",
      "Remove and inspect spark plug #7", "Check injector pulse with noid light",
      "Compression test cylinder 7"],
     related=["P0300", "P0308"],
     difficulty="medium", cost="$30-$500")

_add("P0308", "high", "Cylinder 8 misfire — rough, vibration (V8 engines)",
     ["Ignition coil #8 failed", "Spark plug #8 fouled/worn",
      "Injector #8 fault", "Low compression cyl 8"],
     ["Swap coil #8 with another cylinder — does code follow?",
      "Inspect spark plug #8", "Compression test cylinder 8"],
     related=["P0300", "P0307"],
     difficulty="medium", cost="$30-$500")

# ---------------------------------------------------------------------------
# Catalyst / EGR / Evap (P0400-P0499) — expanded
# ---------------------------------------------------------------------------

_add("P0400", "medium", "EGR flow malfunction — possible ping/knock",
     ["EGR valve stuck/clogged with carbon", "EGR passages blocked",
      "EGR vacuum supply issue (vacuum-operated)", "DPFE sensor failed (Ford)",
      "EGR valve position sensor fault"],
     ["Remove and inspect EGR valve for carbon buildup",
      "Clean EGR passages with carb cleaner and picks",
      "Check DPFE sensor hoses for cracks/disconnection (Ford)",
      "Command EGR open with scan tool — RPM should drop 200+ RPM"],
     related=["P0401", "P0402", "P0403", "P0405"],
     difficulty="medium", cost="$50-$400",
     notes="Ford DPFE sensor failure is VERY common and cheap to replace ($15-30 part)")

_add("P0402", "medium", "EGR flow excessive — rough idle, stalling",
     ["EGR valve stuck open", "EGR valve controlled by vacuum leak",
      "DPFE sensor reading incorrectly", "EVR solenoid stuck on"],
     ["Check if EGR valve fully closes at idle (RPM should be stable)",
      "Inspect vacuum lines to EGR", "Check DPFE sensor",
      "Command EGR closed with scan tool — idle should stabilize"],
     related=["P0400", "P0401"],
     difficulty="medium", cost="$50-$350")

_add("P0410", "medium", "Secondary air injection fault — emissions failure",
     ["Secondary air pump failed", "Air pump relay fault",
      "Check valve stuck/leaking", "Air hose disconnected/cracked",
      "One-way valve carbon-clogged"],
     ["Verify air pump runs when commanded (should hear it)",
      "Check air pump relay", "Inspect air pump hoses and check valves",
      "Check for exhaust in air pump hoses (check valve failed)"],
     related=["P0411", "P0412", "P0418"],
     difficulty="medium", cost="$100-$600")

_add("P0411", "medium", "Secondary air flow incorrect — system underperforming",
     ["Air pump weak/failing", "Air hose restriction",
      "Check valve partially stuck", "Air pump relay intermittent"],
     ["Same tests as P0410", "Check air pump output volume",
      "Inspect hoses for collapse under vacuum"],
     related=["P0410", "P0412"],
     difficulty="medium", cost="$100-$600")

_add("P0446", "medium", "EVAP vent control malfunction — possible fuel odor",
     ["Vent solenoid stuck open or closed", "Vent solenoid wiring issue",
      "Vent line clogged/kinked (spiders/mud daubers common)",
      "PCM driver fault"],
     ["Locate vent solenoid (usually near charcoal canister/fuel tank)",
      "Command vent solenoid and listen for click",
      "Check wiring and connector", "Inspect vent tube for blockage"],
     related=["P0440", "P0442", "P0455", "P0456"],
     difficulty="medium", cost="$50-$250")

_add("P0449", "medium", "EVAP vent valve solenoid circuit fault",
     ["Vent solenoid failed electrically", "Wiring open/short",
      "Connector corrosion", "PCM driver issue"],
     ["Check vent solenoid resistance (typically 20-30Ω)",
      "Verify 12V power at connector with key on",
      "Check ground circuit", "Check wiring for rodent damage"],
     related=["P0446", "P0455"],
     difficulty="easy", cost="$30-$200")

# ---------------------------------------------------------------------------
# Vehicle Speed / Idle Control (P0500-P0599) — expanded
# ---------------------------------------------------------------------------

_add("P0520", "medium", "Oil pressure sensor fault — warning light may illuminate",
     ["Oil pressure sensor/switch failed", "Wiring fault",
      "Connector corroded", "Actual low oil pressure"],
     ["Check engine oil level and condition FIRST",
      "Install mechanical oil pressure gauge to verify actual pressure",
      "If pressure OK, replace sensor/switch",
      "If pressure low, check oil pump and bearings"],
     related=["P0521", "P0522", "P0523"],
     difficulty="easy", cost="$30-$200",
     notes="Do NOT ignore oil pressure codes without verifying actual pressure. Running an engine with low oil pressure destroys bearings quickly.")

_add("P0524", "critical", "Oil pressure too low — STOP ENGINE IMMEDIATELY",
     ["Engine oil level critically low", "Oil pump failure",
      "Oil pickup screen clogged", "Excessive bearing wear",
      "Oil pressure sensor failure (verify before assuming)"],
     ["SHUT OFF ENGINE — do not drive", "Check oil level immediately",
      "Install mechanical gauge to verify", "If truly low, tow to shop",
      "Do NOT restart until cause is found"],
     related=["P0520", "P0521"],
     difficulty="specialist", cost="$100-$5000+",
     notes="Continuing to drive with low oil pressure will destroy the engine within minutes")

_add("P0530", "low", "A/C refrigerant pressure sensor fault",
     ["A/C pressure sensor failed", "Wiring issue",
      "A/C system empty/overcharged", "Connector corroded"],
     ["Check A/C pressures with manifold gauge set",
      "Check A/C pressure sensor connector",
      "Measure sensor reference voltage (5V)"],
     related=["P0531", "P0532", "P0533"],
     difficulty="easy", cost="$30-$200")

_add("P0560", "medium", "System voltage out of range — possible charging issue",
     ["Battery failing/weak", "Alternator undercharging/overcharging",
      "Battery cable connection loose/corroded",
      "PCM voltage sense wire issue"],
     ["Load-test battery", "Test alternator output (13.5-14.7V with engine running)",
      "Inspect battery terminals for corrosion",
      "Check PCM power and ground circuits"],
     related=["P0562", "P0563"],
     difficulty="easy", cost="$50-$500")

# ---------------------------------------------------------------------------
# Transmission (P0600-P0799) — expanded
# ---------------------------------------------------------------------------

_add("P0601", "high", "PCM internal memory error — drives normally until it doesn't",
     ["PCM internal failure", "PCM software corruption",
      "Low voltage during programming", "PCM connector issue"],
     ["Check battery voltage and PCM power supply",
      "Clear code and monitor — may need PCM reflash",
      "If persistent, PCM replacement likely needed",
      "Check all PCM connectors for corrosion"],
     related=["P0602", "P0606"],
     difficulty="specialist", cost="$200-$1200",
     notes="Before replacing PCM, try clearing code and reprogramming. Some aftermarket flashes can cause this.")

_add("P0603", "medium", "PCM KAM (Keep Alive Memory) error",
     ["Battery disconnected or went dead", "PCM power supply interrupted",
      "PCM internal fault"],
     ["Check battery condition and connections",
      "Clear code — if battery was recently disconnected, this is normal",
      "If returns without battery issue, suspect PCM"],
     related=["P0601", "P0606"],
     difficulty="easy", cost="$0-$1000",
     notes="Almost always caused by a dead battery or battery disconnect. Clears on its own after driving.")

_add("P0606", "high", "PCM processor fault — may cause drivability issues",
     ["PCM internal failure", "PCM power/ground issue",
      "Software corruption"],
     ["Check PCM power and ground circuits", "Try PCM reflash first",
      "If reflash doesn't fix, PCM replacement needed"],
     related=["P0601", "P0603"],
     difficulty="specialist", cost="$300-$1200")

_add("P0710", "medium", "Transmission fluid temp sensor fault",
     ["TFT sensor failed", "Wiring issue", "Connector corroded",
      "Trans fluid level low (sensor exposed to air)"],
     ["Check trans fluid level and condition",
      "Measure TFT sensor resistance (~1.5kΩ at 150°F)",
      "Check connector for ATF contamination"],
     related=["P0711", "P0712", "P0713"],
     difficulty="easy", cost="$30-$200")

_add("P0717", "high", "Transmission input/turbine speed sensor no signal",
     ["Input speed sensor failed", "Wiring open/short",
      "Connector damaged/contaminated with ATF",
      "Reluctor ring damaged"],
     ["Check sensor connector for ATF contamination",
      "Measure sensor resistance (typically 300-1200Ω)",
      "Check for AC voltage signal while cranking/running",
      "Inspect reluctor ring for damage"],
     related=["P0715", "P0718"],
     difficulty="medium", cost="$100-$400")

_add("P0720", "high", "Output speed sensor fault — incorrect speedometer reading",
     ["Output speed sensor failed", "Wiring damage",
      "VSS connector corroded", "Reluctor ring damaged"],
     ["Check sensor resistance", "Check for AC voltage output",
      "Inspect connector for contamination",
      "Compare to vehicle speed from ABS module"],
     related=["P0500", "P0721", "P0722"],
     difficulty="medium", cost="$100-$350")

_add("P0740", "medium", "Torque converter clutch circuit fault",
     ["TCC solenoid failed", "Wiring to TCC solenoid damaged",
      "Trans connector pin issue", "Internal trans damage"],
     ["Check TCC solenoid resistance through connector",
      "Command TCC on with scan tool — monitor slip",
      "Check trans connector for bent/corroded pins",
      "If electrical checks OK, internal repair needed"],
     related=["P0741", "P0742", "P0743"],
     difficulty="hard", cost="$150-$2500")

_add("P0750", "high", "Shift solenoid A fault — stuck in one gear",
     ["Shift solenoid A failed", "Solenoid wiring fault",
      "Trans connector issue", "Low/contaminated trans fluid"],
     ["Check trans fluid level and condition",
      "Check solenoid resistance at connector (~20-30Ω typical)",
      "Monitor shift solenoid commanded vs actual states",
      "If electrical OK, internal solenoid or valve body issue"],
     related=["P0751", "P0752", "P0753", "P0700"],
     difficulty="hard", cost="$150-$2000")

_add("P0755", "high", "Shift solenoid B fault — erratic shifting",
     ["Same causes as P0750 but for solenoid B"],
     ["Same diagnostic steps as P0750"],
     related=["P0756", "P0757", "P0758", "P0700"],
     difficulty="hard", cost="$150-$2000")

# ---------------------------------------------------------------------------
# Powertrain Generic / Electronic Throttle (P2000-P2999) — expanded
# ---------------------------------------------------------------------------

_add("P2004", "medium", "Intake manifold runner stuck open (Bank 1)",
     ["IMRC actuator motor failed", "IMRC linkage broken/stuck",
      "Carbon buildup in IMRC plates", "Wiring fault to IMRC actuator"],
     ["Check IMRC actuator motor — command it with scan tool",
      "Inspect linkage and plates for binding or broken components",
      "Clean carbon from IMRC plates", "Check actuator connector and wiring"],
     related=["P2005", "P2006", "P2007", "P2008"],
     difficulty="medium", cost="$100-$400",
     notes="Very common on Ford 3.5/3.7L Duratec engines. The IMRC actuator is on the intake manifold.")

_add("P2006", "medium", "Intake manifold runner stuck closed (Bank 1)",
     ["IMRC actuator stuck or failed", "IMRC plates welded shut by carbon",
      "IMRC linkage broken"],
     ["Same steps as P2004", "If plates are carbon-welded, soak with a good intake cleaner"],
     related=["P2004", "P2005", "P2007"],
     difficulty="medium", cost="$100-$400")

_add("P2008", "medium", "IMRC circuit open (Bank 1) — no drive to actuator",
     ["IMRC actuator wiring open circuit", "Connector fault",
      "IMRC actuator motor open internally", "PCM driver fault"],
     ["Check IMRC connector for corrosion", "Measure actuator motor resistance",
      "Check 12V supply and ground at connector with key on/running"],
     related=["P2004", "P2006", "P2009"],
     difficulty="easy", cost="$50-$350")

_add("P2096", "medium", "Post catalyst fuel trim too lean (Bank 1)",
     ["Exhaust leak between cat and rear O2", "Rear O2 sensor faulty",
      "Catalyst efficiency issue", "Fuel trim drift"],
     ["Check fuel trims — if STFT/LTFT bank 1 also lean, fix upstream issue first",
      "Inspect for exhaust leaks at cat-to-pipe connections",
      "Check rear O2 sensor operation", "Smoke-test exhaust if leak suspected"],
     related=["P2097", "P0420", "P0171"],
     difficulty="medium", cost="$100-$500")

_add("P2097", "medium", "Post catalyst fuel trim too rich (Bank 1)",
     ["Rear O2 sensor reading rich", "Oil consumption fouling cat",
      "Catalyst substrate damaged", "Upstream misfire contaminating cat"],
     ["Check for active misfires first", "Check oil consumption",
      "Monitor rear O2 voltage — should be relatively steady ~0.6-0.7V",
      "If upstream fuel trims are also rich, fix that first"],
     related=["P2096", "P0420", "P0172"],
     difficulty="medium", cost="$100-$500")

_add("P2100", "high", "Electronic throttle control motor circuit — limp mode",
     ["Throttle body motor failure", "Wiring harness damage near throttle",
      "Connector pins corroded/bent", "PCM driver fault"],
     ["Check throttle body connector for corrosion",
      "Measure motor resistance at connector",
      "Check for water intrusion in connector",
      "Throttle body replacement usually required"],
     related=["P2101", "P2102", "P2103", "P2135"],
     difficulty="medium", cost="$200-$600",
     notes="Ford electronic throttle body failures often accompany P2135 (TPS correlation)")

_add("P2101", "high", "Throttle actuator control range/performance — limp mode",
     ["Carbon buildup on throttle plate preventing full closure/opening",
      "Throttle body motor weak", "TPS signal issues"],
     ["Clean throttle body with throttle body cleaner",
      "Check TPS voltages at closed and WOT",
      "If cleaning doesn't fix, replace throttle body",
      "Perform throttle body relearn after service"],
     related=["P2100", "P2135"],
     difficulty="medium", cost="$150-$500")

_add("P2106", "high", "Throttle actuator control system — forced limited power",
     ["PCM detecting unsafe throttle condition", "Multiple throttle-related faults",
      "Accelerator pedal sensor inconsistency"],
     ["Check for other throttle-related codes FIRST — this is often secondary",
      "Check accelerator pedal sensor values",
      "Check throttle body operation"],
     related=["P2100", "P2101", "P2135", "P2138"],
     difficulty="medium", cost="$200-$600")

_add("P2110", "high", "Throttle actuator forced to idle — vehicle limited to idle speed",
     ["Safety fallback — PCM cannot trust throttle position",
      "Multiple TPS/APP sensor faults"],
     ["Diagnose root cause codes first (P2135, P2138, etc.)",
      "Clear codes and test drive — if returns, hardware failure",
      "Usually requires throttle body or APP sensor replacement"],
     related=["P2135", "P2138"],
     difficulty="medium", cost="$200-$600")

_add("P2111", "high", "Throttle stuck open — engine races",
     ["Throttle body internal fault (spring return broken)",
      "Carbon preventing plate closure", "Throttle motor runaway"],
     ["DO NOT DRIVE if throttle is actually stuck open",
      "Clean throttle body", "Check throttle plate for binding",
      "Replace throttle body if mechanical issue"],
     related=["P2112", "P2100", "P2101"],
     difficulty="medium", cost="$200-$600",
     notes="Safety critical — if throttle is truly stuck open, the engine may not shut off with the key. Use brake firmly and shift to neutral.")

_add("P2112", "high", "Throttle stuck closed — no acceleration",
     ["Throttle body motor failed", "Carbon buildup",
      "Frozen/seized throttle plate", "Wiring fault"],
     ["Clean throttle body", "Check for binding",
      "Replace throttle body if needed"],
     related=["P2111", "P2100", "P2101"],
     difficulty="medium", cost="$200-$600")

_add("P2119", "high", "Throttle body performance — unreliable throttle response",
     ["Throttle body motor inconsistent", "TPS signal noisy",
      "Wiring intermittent", "Carbon buildup causing sticking"],
     ["Clean throttle bore and plate", "Wiggle-test wiring while monitoring",
      "Check TPS voltage for dropout/noise",
      "Replace throttle body if cleaning doesn't resolve"],
     related=["P2100", "P2101", "P2135"],
     difficulty="medium", cost="$200-$600")

# ---------------------------------------------------------------------------
# Communication / Network Codes (U-codes) — expanded
# ---------------------------------------------------------------------------

_add("U0001", "high", "High-speed CAN bus communication fault — multiple systems affected",
     ["CAN bus wiring open/shorted", "Defective module pulling bus down",
      "CAN termination resistor missing", "Corroded CAN connector"],
     ["Measure CAN bus resistance at DLC pins 6+14 (~60Ω = both terminators OK)",
      "Use oscilloscope on CAN_H and CAN_L for proper differential signal",
      "Disconnect modules one at a time to find the one pulling bus down",
      "Check for water damage in body connectors"],
     related=["U0073", "U0100", "U0101", "U0121"],
     difficulty="specialist", cost="$100-$2000",
     notes="A shorted CAN bus can kill communication with ALL modules. Start by measuring bus resistance to narrow it down.")

_add("U0002", "high", "MS-CAN bus performance — body/comfort modules affected",
     ["MS-CAN wiring fault", "Module failure on MS-CAN network",
      "Connector corrosion (common in door jamb/kick panel areas)"],
     ["Measure MS-CAN resistance at DLC pins 3+11 (~60Ω)",
      "Check for water intrusion in connectors near doors/fenders",
      "Disconnect body modules one at a time"],
     related=["U0073", "U0140", "U0155"],
     difficulty="specialist", cost="$100-$1500",
     notes="Ford MS-CAN runs on DLC pins 3+11 at 125kbps. Check the BCM/GEM connector first — it's the hub.")

_add("U0010", "medium", "Medium-speed CAN bus A fault",
     ["CAN bus wiring issue", "Module communication failure",
      "Connector fault"],
     ["Check CAN bus resistance", "Inspect wiring for damage",
      "Disconnect modules to isolate fault"],
     related=["U0001", "U0002"],
     difficulty="specialist", cost="$100-$1500")

_add("U0028", "medium", "Vehicle communication bus A data rate performance",
     ["CAN bus timing issues", "Marginal bus condition",
      "EMI interference on CAN wiring"],
     ["Check CAN bus termination", "Route CAN wiring away from ignition components",
      "Check for aftermarket electronics on CAN bus"],
     related=["U0001", "U0073"],
     difficulty="specialist", cost="$100-$800")

_add("U0107", "medium", "Lost communication with TAC (Throttle Actuator Control)",
     ["Throttle body wiring fault", "Throttle body module failed",
      "CAN bus issue to throttle module"],
     ["Check throttle body connector", "Check CAN bus wiring to throttle",
      "Measure CAN signals at throttle body connector"],
     related=["P2100", "P2135", "U0100"],
     difficulty="medium", cost="$200-$600")

_add("U0131", "medium", "Lost communication with PSCM (Power Steering Control)",
     ["EPAS module failed", "CAN bus wiring to PSCM damaged",
      "PSCM connector corroded", "PSCM power supply issue"],
     ["Check PSCM power and ground", "Check CAN bus at PSCM connector",
      "Inspect wiring along steering column for damage"],
     related=["U0100", "C0131"],
     difficulty="medium", cost="$200-$1000")

_add("U0151", "medium", "Lost communication with RCM (Restraint Control Module/SRS)",
     ["RCM failed", "RCM connector under driver seat disconnected",
      "CAN wiring damage", "RCM power loss"],
     ["Check RCM connector under driver seat (most common fix)",
      "Check RCM fuse", "Check CAN wiring to RCM",
      "Airbag light will be on — SAFETY CRITICAL"],
     related=["U0100"],
     difficulty="medium", cost="$100-$800",
     notes="Airbag system will not deploy if RCM has no communication. Do not ignore this code.")

_add("U0164", "medium", "Lost communication with HVAC module",
     ["HVAC module failed", "HVAC connector corroded",
      "CAN bus wiring fault", "HVAC module power loss"],
     ["Check HVAC module connector (usually behind center dash panel)",
      "Check HVAC fuse", "Check CAN wiring to HVAC module"],
     related=["U0100"],
     difficulty="medium", cost="$150-$600")

_add("U0199", "medium", "Lost communication with door module A (usually driver door)",
     ["Door module failed", "Door harness flex break (very common in boot area)",
      "Connector corroded in door jamb", "Power/ground issue"],
     ["Check door wiring where it flexes in door jamb — #1 cause of failure",
      "Check door module connector for corrosion",
      "Check door module power supply and ground"],
     related=["U0155"],
     difficulty="medium", cost="$100-$500",
     notes="Door harness wires break from fatigue where they flex at the door hinge. Open the door boot and check each wire.")

_add("U0235", "medium", "Lost communication with front distance sensor (radar/camera)",
     ["Radar sensor misaligned", "Radar sensor module failed",
      "CAN wiring damaged", "Windshield replacement shifted camera bracket"],
     ["Check radar sensor behind front bumper for damage/misalignment",
      "Check front camera behind windshield (if ADAS equipped)",
      "Recalibrate after windshield replacement",
      "Check CAN wiring to sensor module"],
     related=["U0100"],
     difficulty="specialist", cost="$200-$1500",
     notes="Windshield replacement often requires ADAS recalibration ($150-300). Some shops miss this.")

_add("U0300", "medium", "Internal control module software incompatibility",
     ["Module not programmed for this vehicle", "Software level mismatch",
      "Incomplete reflash", "Wrong module installed"],
     ["Verify module part number matches vehicle application",
      "Check for TSBs requiring software update",
      "Reflash module to latest calibration"],
     related=["U0301"],
     difficulty="specialist", cost="$100-$500")

_add("U0401", "medium", "Invalid data received from ECM/PCM",
     ["PCM sending corrupt data", "CAN bus intermittent",
      "PCM software issue", "CAN wiring near ignition components"],
     ["Check CAN bus signal quality with oscilloscope",
      "Try PCM reflash", "Check for PCM TSBs",
      "Monitor CAN data for intermittent dropouts"],
     related=["U0100", "U0073"],
     difficulty="specialist", cost="$100-$1000")

# ---------------------------------------------------------------------------
# Body Codes (B) — expanded
# ---------------------------------------------------------------------------

_add("B1200", "low", "Climate control malfunction — blend door stuck",
     ["Blend door actuator motor failed", "Blend door mechanically stuck",
      "HVAC control module fault", "Wiring issue to actuator"],
     ["Command blend door from full hot to full cold with scan tool — listen for motor",
      "Check actuator motor connector", "Remove actuator and check door movement by hand",
      "Compare driver vs passenger temps for which door is stuck"],
     related=["B1201", "B1202"],
     difficulty="medium", cost="$50-$400",
     notes="Blend door actuators are behind the dash — labor is the main cost, not the part ($20-50).")

_add("B1213", "low", "Anti-theft issue — transponder signal not received",
     ["Key transponder chip failed", "PATS antenna ring around ignition damaged",
      "PATS module fault", "Wrong key being used"],
     ["Try all known keys — if one works, other key's chip is bad",
      "Check PATS antenna ring at ignition cylinder",
      "Use scan tool to check PATS key count and status",
      "Reprogram key if possible"],
     related=["B1600", "B1601", "B1681"],
     difficulty="specialist", cost="$50-$500",
     notes="Ford PATS — minimum 2 programmed keys required to add new keys without dealer tool")

_add("B1352", "medium", "Ignition key-in circuit fault — chime issues",
     ["Key-in switch in ignition cylinder failed", "Wiring fault",
      "Wrong key", "Ignition cylinder worn"],
     ["Check key-in switch operation", "Test with known-good key",
      "Check wiring from ignition cylinder to GEM/BCM"],
     related=[],
     difficulty="easy", cost="$30-$200")

_add("B2477", "medium", "Module configuration failure — module not programmed",
     ["Module replaced but not configured for vehicle",
      "Configuration data lost", "Programming interrupted"],
     ["Configure module using manufacturer scan tool (IDS/FDRS for Ford)",
      "If aftermarket module, verify compatibility",
      "Re-run as-built data configuration"],
     related=["U0300"],
     difficulty="specialist", cost="$100-$400",
     notes="Ford as-built data can be downloaded from Ford's OASIS website and written to modules using ForScan or IDS")

# ---------------------------------------------------------------------------
# Chassis Codes (C) — expanded
# ---------------------------------------------------------------------------

_add("C0031", "medium", "Left front wheel speed sensor circuit — ABS affected",
     ["Wheel speed sensor failed", "Sensor wiring damage (common on front axle)",
      "Sensor air gap incorrect", "Tone ring damaged/missing teeth",
      "Wheel bearing worn (sensor integral to bearing)"],
     ["Check sensor resistance (~1-2kΩ typical)", "Inspect tone ring for damage",
      "Check air gap", "Spin wheel by hand and monitor sensor AC voltage",
      "On vehicles with integral sensor/bearing, replace hub assembly"],
     related=["C0035", "C0040", "C0045", "C0050"],
     difficulty="medium", cost="$100-$500")

_add("C0055", "high", "Rear wheel speed sensor circuit — ABS/stability affected",
     ["Rear wheel speed sensor failed", "Wiring damage along axle/suspension",
      "Tone ring corroded/damaged", "Rear wheel bearing worn"],
     ["Same approach as C0031 but for rear axle",
      "Check for rust/corrosion on tone ring",
      "Inspect wiring along rear suspension for chafing"],
     related=["C0035", "C0040", "C0045", "C0050"],
     difficulty="medium", cost="$100-$500")

_add("C0060", "high", "Left front ABS solenoid valve circuit — ABS inoperative",
     ["ABS hydraulic modulator internal solenoid fault",
      "ABS module connector issue", "ABS module power supply problem"],
     ["Check ABS module connector for corrosion",
      "Check ABS module power and ground circuits",
      "Usually requires ABS modulator replacement ($300-800)"],
     related=["C0035", "C0040"],
     difficulty="hard", cost="$300-$1200")

_add("C0161", "medium", "ABS/TCS brake switch circuit fault",
     ["Brake light switch failed or misadjusted", "Brake switch wiring fault",
      "Brake switch connector issue"],
     ["Check brake light operation — the ABS module uses the same switch",
      "Adjust or replace brake light switch",
      "Check connector at brake pedal switch"],
     related=["C0131"],
     difficulty="easy", cost="$15-$100",
     notes="The brake switch tells the ABS, cruise, and brake lights that you're braking. One $15 switch affects multiple systems.")

_add("C0236", "medium", "Rear wheel speed signal erratic — intermittent ABS activations",
     ["Tone ring corroded (especially rear drums)", "Wheel bearing with excessive play",
      "Sensor loose", "Wiring chafing on suspension components"],
     ["Clean tone ring surface", "Check bearing play",
      "Verify sensor mounting torque", "Inspect wiring routing along suspension"],
     related=["C0035", "C0040", "C0050"],
     difficulty="medium", cost="$100-$400")

_add("C1145", "high", "Steering wheel position sensor fault — stability control affected",
     ["Steering angle sensor failed", "Steering angle sensor not calibrated",
      "Clock spring damaged", "Steering column connector issue"],
     ["Perform steering angle sensor calibration (full lock-to-lock-to-center)",
      "Check clock spring connector", "Check for steering column recalls",
      "Replace sensor if calibration doesn't work"],
     related=["C0131"],
     difficulty="medium", cost="$100-$600",
     notes="After alignment, battery disconnect, or steering work — always recalibrate the steering angle sensor")

_add("C1185", "medium", "ABS pump motor fault — ABS inoperative",
     ["ABS pump motor burned out", "ABS motor relay failed",
      "ABS module connector corrosion", "Low voltage to ABS module"],
     ["Check ABS motor relay", "Verify 12V to ABS motor",
      "Listen for pump when ABS engages (should hear brief buzz)",
      "If motor dead, modulator replacement needed"],
     related=["C0060"],
     difficulty="hard", cost="$400-$1500")

# ---------------------------------------------------------------------------
# Additional Common Powertrain Codes
# ---------------------------------------------------------------------------

_add("P0011", "medium", "Intake camshaft position timing — over-advanced (Bank 1)",
     ["Oil level low or dirty", "VVT solenoid (OCV) stuck/clogged",
      "Cam phaser worn/failed", "Oil passages clogged",
      "Timing chain stretched"],
     ["Check oil level and condition FIRST — low/dirty oil is #1 cause",
      "Replace oil and filter if overdue",
      "Check VVT solenoid for sludge", "Monitor cam timing vs target in live data",
      "If timing stays advanced after oil service, suspect phaser or chain"],
     related=["P0012", "P0021", "P0022", "P0014"],
     difficulty="medium", cost="$50-$2000",
     notes="On Ford 3.5/3.7L Duratec: cam phasers are a known weak point. Check TSBs. Regular oil changes prevent most phaser issues.")

_add("P0012", "medium", "Intake camshaft timing — over-retarded (Bank 1)",
     ["Oil level low or dirty", "VVT solenoid stuck retarded",
      "Oil flow restriction to phaser", "Timing chain slack"],
     ["Same approach as P0011 — start with oil level and condition",
      "Check VVT solenoid operation",
      "If chain noise on cold start, suspect timing chain stretch"],
     related=["P0011", "P0021", "P0022"],
     difficulty="medium", cost="$50-$2000")

_add("P0013", "medium", "Exhaust camshaft position actuator circuit (Bank 1)",
     ["VVT exhaust solenoid circuit fault", "Wiring open/short",
      "VVT solenoid failed electrically", "PCM driver fault"],
     ["Check VVT solenoid resistance (6-13Ω typical)",
      "Check 12V at solenoid connector", "Check ground circuit",
      "Check wiring for damage near exhaust heat"],
     related=["P0011", "P0014", "P0021", "P0023"],
     difficulty="medium", cost="$50-$400")

_add("P0014", "medium", "Exhaust camshaft timing — over-advanced (Bank 1)",
     ["Same oil-related causes as P0011 but for exhaust cam",
      "Exhaust VVT solenoid clogged", "Exhaust cam phaser issue"],
     ["Same approach as P0011: check oil, VVT solenoid, cam timing"],
     related=["P0011", "P0012", "P0013"],
     difficulty="medium", cost="$50-$2000")

_add("P0016", "high", "Crankshaft/camshaft position correlation — Bank 1 Sensor A",
     ["Timing chain jumped a tooth", "Timing chain stretched",
      "Cam phaser failure", "Crank sensor issue",
      "Cam sensor issue (verify before expensive chain job)"],
     ["Check cam/crank correlation in live data",
      "Listen for chain slap noise on cold start",
      "Inspect chain tensioner", "Verify cam and crank sensor signals",
      "Don't replace chain without confirming correlation is actually off"],
     related=["P0017", "P0011", "P0012", "P0341"],
     difficulty="hard", cost="$200-$3000",
     notes="Before doing a timing chain job, verify with oscilloscope that cam/crank correlation is actually off. Sometimes it's just a sensor issue.")

_add("P0017", "high", "Crankshaft/camshaft position correlation — Bank 1 Sensor B",
     ["Same causes as P0016 but for exhaust cam"],
     ["Same diagnostic approach as P0016"],
     related=["P0016", "P0011", "P0014"],
     difficulty="hard", cost="$200-$3000")

_add("P0030", "medium", "O2 sensor heater control circuit (Bank 1, Sensor 1)",
     ["O2 sensor heater element burned out", "O2 sensor connector corroded",
      "Heater circuit wiring fault", "O2 sensor fuse blown"],
     ["Check O2 sensor heater fuse", "Measure heater resistance at sensor connector (2-30Ω)",
      "Check for 12V to heater circuit", "Replace O2 sensor if heater open"],
     related=["P0031", "P0032", "P0130", "P0135"],
     difficulty="easy", cost="$50-$200")

_add("P0031", "medium", "O2 sensor heater circuit low (Bank 1, Sensor 1)",
     ["O2 sensor heater shorted low", "Wiring shorted to ground",
      "O2 sensor internal short"],
     ["Disconnect sensor and measure heater resistance",
      "Check wiring for short to ground", "Replace O2 sensor"],
     related=["P0030", "P0032", "P0135"],
     difficulty="easy", cost="$50-$200")

_add("P0036", "medium", "O2 sensor heater circuit (Bank 1, Sensor 2) — downstream",
     ["Downstream O2 sensor heater burned out", "Connector corroded",
      "Heater fuse blown", "Wiring damage from road debris"],
     ["Check O2 heater fuse", "Measure heater resistance",
      "Check connector (downstream sensor gets more road exposure)",
      "Replace downstream O2 sensor if heater open"],
     related=["P0037", "P0038", "P0141"],
     difficulty="easy", cost="$50-$200")

_add("P0050", "medium", "O2 sensor heater circuit (Bank 2, Sensor 1)",
     ["Same causes as P0030 but for Bank 2"],
     ["Same diagnostic approach as P0030 but for Bank 2 upstream O2 sensor"],
     related=["P0051", "P0052", "P0155"],
     difficulty="easy", cost="$50-$200")

_add("P0056", "medium", "O2 sensor heater circuit (Bank 2, Sensor 2)",
     ["Same causes as P0036 but for Bank 2"],
     ["Same approach, Bank 2 downstream sensor"],
     related=["P0057", "P0058", "P0161"],
     difficulty="easy", cost="$50-$200")

_add("P0150", "medium", "O2 sensor circuit (Bank 2, Sensor 1)",
     ["O2 sensor failed", "Exhaust leak near sensor", "Wiring damage",
      "Contaminated sensor (coolant/oil/silicone)"],
     ["Check O2 voltage switching", "Check for exhaust leaks",
      "Inspect wiring and connector", "Verify fuel trims Bank 2"],
     related=["P0151", "P0152", "P0153", "P0155", "P0174"],
     difficulty="easy", cost="$50-$250")

_add("P0155", "medium", "O2 sensor heater (Bank 2, Sensor 1) — heater inoperative",
     ["Heater element open", "Heater fuse", "Wiring issue", "Connector corroded"],
     ["Check heater fuse", "Measure heater resistance", "Check 12V at connector"],
     related=["P0150", "P0135"],
     difficulty="easy", cost="$50-$200")

_add("P0325", "medium", "Knock sensor 1 circuit — timing may retard",
     ["Knock sensor failed", "Knock sensor wiring fault",
      "Knock sensor mounting torque incorrect", "Engine noise causing false knock"],
     ["Check knock sensor connector", "Check sensor mounting (must be torqued to spec, typically 15 ft-lb)",
      "Check wiring for damage", "If excessive knock detected, check for carbon buildup, fuel quality"],
     related=["P0326", "P0327", "P0328", "P0332"],
     difficulty="medium", cost="$100-$400",
     notes="Knock sensors are typically under the intake manifold — labor is the main cost")

_add("P0335", "high", "Crankshaft position sensor A circuit — no-start possible",
     ["Crank sensor failed", "Crank sensor wiring damaged",
      "Reluctor ring on harmonic balancer damaged",
      "Harmonic balancer outer ring slipped"],
     ["Check for spark — if no spark, crank sensor is prime suspect",
      "Measure sensor resistance (~500-1500Ω typical)",
      "Check sensor connector for oil contamination",
      "Inspect harmonic balancer for rubber deterioration (outer ring slippage)"],
     related=["P0336", "P0016", "P0017"],
     difficulty="medium", cost="$50-$400",
     notes="If intermittent, may cause random stalling or extended cranking. Check wiring near exhaust for heat damage.")

_add("P0336", "medium", "Crankshaft position sensor performance — intermittent",
     ["Crank sensor air gap incorrect", "Reluctor ring damaged tooth",
      "Sensor intermittent", "Harmonic balancer wobble"],
     ["Check reluctor ring for missing/damaged teeth",
      "Check sensor air gap", "Check harmonic balancer for wobble",
      "Replace sensor if intermittent signal on scope"],
     related=["P0335", "P0016"],
     difficulty="medium", cost="$50-$400")

_add("P0340", "high", "Camshaft position sensor A circuit (Bank 1) — may cause no-start",
     ["Cam sensor failed", "Cam sensor wiring damaged",
      "Cam sensor connector issue", "Timing chain/belt jumped"],
     ["Check cam sensor connector", "Measure sensor resistance",
      "Verify timing chain/belt condition if equipped",
      "Check for spark and injector pulse"],
     related=["P0341", "P0016", "P0017"],
     difficulty="medium", cost="$50-$300")

_add("P0341", "medium", "Camshaft position sensor range/performance",
     ["Cam sensor signal out of spec", "Timing chain stretch",
      "VVT operation issue", "Cam sensor loosening"],
     ["Monitor cam position vs crank position correlation",
      "Check sensor mounting", "Check timing chain for stretch"],
     related=["P0340", "P0016", "P0011"],
     difficulty="medium", cost="$50-$300")

_add("P0345", "high", "Camshaft position sensor A circuit (Bank 2)",
     ["Same as P0340 but for Bank 2"],
     ["Same approach as P0340 — Bank 2 cam sensor"],
     related=["P0346", "P0340"],
     difficulty="medium", cost="$50-$300")

_add("P0351", "high", "Ignition coil A primary/secondary circuit",
     ["Ignition coil A (Cyl 1) failed", "Coil connector corroded",
      "Coil driver circuit in PCM", "Wiring fault"],
     ["Swap coil A with another cylinder — does code follow?",
      "Check coil connector for carbon tracking or corrosion",
      "Measure primary resistance (0.3-1.0Ω) and secondary (5-15kΩ)",
      "Check for 12V supply to coil"],
     related=["P0300", "P0301"],
     difficulty="easy", cost="$30-$200")

_add("P0352", "high", "Ignition coil B primary/secondary circuit",
     ["Same as P0351 for coil B"],
     ["Same swap-test approach for cylinder associated with coil B"],
     related=["P0300", "P0302"],
     difficulty="easy", cost="$30-$200")

_add("P0353", "high", "Ignition coil C primary/secondary circuit",
     ["Same as P0351 for coil C"],
     ["Same swap-test approach"],
     related=["P0300", "P0303"],
     difficulty="easy", cost="$30-$200")

_add("P0354", "high", "Ignition coil D primary/secondary circuit",
     ["Same as P0351 for coil D"],
     ["Same swap-test approach"],
     related=["P0300", "P0304"],
     difficulty="easy", cost="$30-$200")

_add("P0355", "high", "Ignition coil E primary/secondary circuit",
     ["Same as P0351 for coil E"],
     ["Same swap-test approach"],
     related=["P0300", "P0305"],
     difficulty="easy", cost="$30-$200")

_add("P0356", "high", "Ignition coil F primary/secondary circuit",
     ["Same as P0351 for coil F"],
     ["Same swap-test approach"],
     related=["P0300", "P0306"],
     difficulty="easy", cost="$30-$200")

_add("P0460", "low", "Fuel level sensor circuit — fuel gauge inaccurate",
     ["Fuel level sending unit failed", "Wiring corroded",
      "Fuel pump module connector issue", "Gauge cluster fault"],
     ["Compare scan tool fuel level reading to gauge",
      "Check wiring at fuel pump module connector (often on top of tank)",
      "Measure sending unit resistance (0-190Ω or 15-160Ω depending on make)",
      "If wiring and sending unit OK, suspect gauge cluster"],
     related=["P0461", "P0462", "P0463"],
     difficulty="medium", cost="$100-$600",
     notes="Fuel pump module is inside the tank — dropping the tank is the major labor cost")

_add("P0480", "medium", "Cooling fan 1 control circuit — fan may not run",
     ["Cooling fan relay failed", "Fan motor burned out",
      "Fan control module fault (if equipped)", "Wiring fault"],
     ["Check cooling fan relay — swap with identical relay nearby",
      "Apply 12V direct to fan motor to test",
      "Check PCM fan control output with scan tool",
      "On Ford, check fan speed control module if equipped"],
     related=["P0481", "P0217"],
     difficulty="medium", cost="$50-$500")

_add("P1000", "low", "OBD readiness — drive cycle not complete",
     ["Normal after DTC clear or battery disconnect", "Drive cycle not completed",
      "Pending fault preventing monitor completion"],
     ["Drive vehicle through OBD-II drive cycle",
      "Check for other pending codes blocking monitors",
      "This is NOT a fault code — it simply means readiness monitors haven't run yet"],
     related=[],
     difficulty="easy", cost="$0",
     notes="Ford-specific. This code means emission monitors haven't completed. Required to pass emissions inspection. Normal after codes cleared.")

_add("P1131", "medium", "Lack of HO2S1 switch — sensor indicates lean (Bank 1)",
     ["Vacuum leak on Bank 1", "Fuel injector issue Bank 1",
      "O2 sensor slow/lazy", "Exhaust leak"],
     ["Same approach as P0171 — check for vacuum leaks, fuel trims",
      "Smoke test intake manifold", "Check O2 sensor response time"],
     related=["P0171", "P0130"],
     difficulty="medium", cost="$50-$500",
     notes="Ford-specific P1 code. Functionally similar to P0171 lean condition.")

_add("P1151", "medium", "Lack of HO2S1 switch — sensor indicates lean (Bank 2)",
     ["Same causes as P1131 but for Bank 2"],
     ["Same approach as P0174"],
     related=["P0174", "P0150"],
     difficulty="medium", cost="$50-$500",
     notes="Ford-specific. Same as P1131 but Bank 2.")


# ---------------------------------------------------------------------------
# Fuel Injectors (P0202-P0208)
# ---------------------------------------------------------------------------

_add("P0202", "medium", "Misfire on cylinder 2, rough idle",
     ["Injector 2 circuit open/short", "Injector driver failed in PCM",
      "Wiring harness damage near cylinder 2", "Corroded connector pins",
      "Injector clogged or stuck open"],
     ["Check injector 2 connector for power and ground",
      "Measure injector resistance (11-18 ohms typical)",
      "Use NOID light to verify driver signal from PCM",
      "Swap injector with adjacent cylinder to isolate"],
     related=["P0200", "P0201", "P0300", "P0302"],
     difficulty="medium", cost="$100-$500",
     notes="Check for TSBs on injector connector corrosion. On Ford EcoBoost, check for carbon buildup.")

_add("P0203", "medium", "Misfire on cylinder 3, rough idle",
     ["Injector 3 circuit open/short", "Injector driver failed in PCM",
      "Wiring harness damage near cylinder 3", "Corroded connector pins",
      "Injector clogged or stuck open"],
     ["Check injector 3 connector for power and ground",
      "Measure injector resistance (11-18 ohms typical)",
      "Use NOID light to verify driver signal from PCM",
      "Swap injector with adjacent cylinder to isolate"],
     related=["P0200", "P0201", "P0300", "P0303"],
     difficulty="medium", cost="$100-$500")

_add("P0204", "medium", "Misfire on cylinder 4, rough idle",
     ["Injector 4 circuit open/short", "Injector driver failed in PCM",
      "Wiring harness damage near cylinder 4", "Corroded connector pins",
      "Injector clogged or stuck open"],
     ["Check injector 4 connector for power and ground",
      "Measure injector resistance (11-18 ohms typical)",
      "Use NOID light to verify driver signal from PCM",
      "Swap injector with adjacent cylinder to isolate"],
     related=["P0200", "P0201", "P0300", "P0304"],
     difficulty="medium", cost="$100-$500")

_add("P0205", "medium", "Misfire on cylinder 5, rough idle",
     ["Injector 5 circuit open/short", "Injector driver failed in PCM",
      "Wiring harness damage near cylinder 5", "Corroded connector pins"],
     ["Check injector 5 connector for power and ground",
      "Measure injector resistance (11-18 ohms typical)",
      "Use NOID light to verify driver signal from PCM",
      "Swap injector with adjacent cylinder to isolate"],
     related=["P0200", "P0300", "P0305"],
     difficulty="medium", cost="$100-$500")

_add("P0206", "medium", "Misfire on cylinder 6, rough idle",
     ["Injector 6 circuit open/short", "Injector driver failed in PCM",
      "Wiring harness damage near cylinder 6", "Corroded connector pins"],
     ["Check injector 6 connector for power and ground",
      "Measure injector resistance (11-18 ohms typical)",
      "Use NOID light to verify driver signal from PCM",
      "Swap injector with adjacent cylinder to isolate"],
     related=["P0200", "P0300", "P0306"],
     difficulty="medium", cost="$100-$500")

_add("P0207", "medium", "Misfire on cylinder 7, rough idle (V8 engines)",
     ["Injector 7 circuit open/short", "Injector driver failed in PCM",
      "Wiring harness damage near cylinder 7", "Corroded connector pins"],
     ["Check injector 7 connector for power and ground",
      "Measure injector resistance (11-18 ohms typical)",
      "Use NOID light to verify driver signal from PCM",
      "Swap injector with adjacent cylinder to isolate"],
     related=["P0200", "P0300", "P0307"],
     difficulty="medium", cost="$100-$500",
     notes="Applicable to V8 engines. Ford 5.0L Coyote — check for harness chafing on valve cover.")

_add("P0208", "medium", "Misfire on cylinder 8, rough idle (V8 engines)",
     ["Injector 8 circuit open/short", "Injector driver failed in PCM",
      "Wiring harness damage near cylinder 8", "Corroded connector pins"],
     ["Check injector 8 connector for power and ground",
      "Measure injector resistance (11-18 ohms typical)",
      "Use NOID light to verify driver signal from PCM",
      "Swap injector with adjacent cylinder to isolate"],
     related=["P0200", "P0300", "P0308"],
     difficulty="medium", cost="$100-$500",
     notes="Applicable to V8 engines.")

# ---------------------------------------------------------------------------
# Throttle / Pedal Position (P0219-P0223)
# ---------------------------------------------------------------------------

_add("P0219", "high", "Engine over-rev condition detected",
     ["Driver over-revving during aggressive driving", "Transmission downshift issue",
      "Sticking throttle body", "APP sensor intermittent",
      "PCM calibration issue"],
     ["Check freeze frame for RPM and gear — was it a legitimate over-rev?",
      "Inspect throttle body for sticking or carbon buildup",
      "Check APP sensor voltages through full pedal sweep",
      "Verify transmission shift points with scan tool"],
     related=["P0220", "P2135", "P0730"],
     difficulty="medium", cost="$50-$400",
     notes="Ford vehicles: check for TSBs related to throttle body calibration.")

_add("P0220", "high", "Limp mode possible, reduced throttle response",
     ["APP sensor 2 failed", "APP wiring damage/chafing",
      "Accelerator pedal assembly failure", "Connector corrosion at pedal"],
     ["Check APP sensor 2 voltage — should track with sensor 1",
      "Inspect pedal connector for corrosion or bent pins",
      "Monitor both APP sensors while slowly pressing pedal",
      "Check 5V reference and ground at pedal connector"],
     related=["P0221", "P0222", "P0223", "P2135", "P2138"],
     difficulty="medium", cost="$100-$350",
     notes="On Ford, the APP is part of the pedal assembly — replace as a unit.")

_add("P0221", "high", "Limp mode, erratic throttle response",
     ["APP sensor signal out of range", "Wiring harness damage",
      "Accelerator pedal assembly worn", "Connector corrosion"],
     ["Check APP sensor voltage range — compare to sensor 1",
      "Wiggle-test wiring while monitoring live data",
      "Inspect pedal connector for corrosion",
      "Replace pedal assembly if signal is erratic"],
     related=["P0220", "P0222", "P0223", "P2135"],
     difficulty="medium", cost="$100-$350")

_add("P0222", "high", "Limp mode activated, throttle limited to idle",
     ["APP sensor 2 circuit low voltage", "Open/short in APP wiring",
      "Pedal assembly failure", "Ground circuit problem"],
     ["Check APP sensor 2 voltage — should be ~0.5V at rest",
      "Verify 5V reference and ground at pedal connector",
      "Inspect wiring for chafing, especially near firewall pass-through",
      "Swap pedal assembly if wiring checks good"],
     related=["P0220", "P0221", "P0223", "P2138"],
     difficulty="medium", cost="$100-$350")

_add("P0223", "high", "Limp mode activated, throttle limited",
     ["APP sensor 2 circuit high voltage", "Short to voltage in APP wiring",
      "Pedal assembly failure", "5V reference shorted"],
     ["Check APP sensor 2 voltage — should not exceed 4.5V",
      "Look for short to voltage in wiring harness",
      "Check if 5V reference is feeding back through signal wire",
      "Replace pedal assembly if wiring is sound"],
     related=["P0220", "P0221", "P0222", "P2138"],
     difficulty="medium", cost="$100-$350")

# ---------------------------------------------------------------------------
# Fuel Pump / Turbo Boost (P0231-P0243)
# ---------------------------------------------------------------------------

_add("P0231", "high", "Engine stalls, no start, loss of power",
     ["Fuel pump relay failed", "Fuel pump driver module (FPDM) failed",
      "Wiring open between relay and pump", "Fuel pump failing internally",
      "Corroded ground at fuel pump"],
     ["Check fuel pump relay — swap with identical relay to test",
      "Measure voltage at fuel pump connector while cranking",
      "Check fuel pump driver module (Ford uses FPDM on many models)",
      "Listen for pump prime with key on — should hear 2-sec buzz"],
     related=["P0230", "P0232", "P0087"],
     difficulty="medium", cost="$100-$800",
     notes="Ford uses a Fuel Pump Driver Module (FPDM) — check TSB 08-22-4 for FPDM failures.")

_add("P0232", "medium", "Fuel pump runs continuously, possible flooding",
     ["Fuel pump relay stuck closed", "FPDM shorted internally",
      "Wiring short to power", "PCM fuel pump driver shorted"],
     ["Check if fuel pump runs with key on engine off for more than 2 seconds",
      "Swap fuel pump relay to test",
      "Disconnect FPDM and check for voltage at pump connector",
      "Inspect wiring for short to battery voltage"],
     related=["P0230", "P0231"],
     difficulty="medium", cost="$50-$400")

_add("P0233", "medium", "Intermittent stalling, loss of power at highway speed",
     ["Fuel pump circuit intermittent connection",
      "Corroded fuel pump connector (in-tank corrosion)",
      "FPDM intermittent failure", "Fuel pump relay intermittent"],
     ["Monitor fuel pump voltage with scan tool while driving",
      "Check fuel pump connector at tank for corrosion",
      "Wiggle-test wiring at FPDM and relay while monitoring",
      "Check fuel pressure with gauge — watch for pressure drops"],
     related=["P0230", "P0231", "P0232"],
     difficulty="hard", cost="$100-$800",
     notes="Intermittent fuel pump issues are notoriously hard to catch. Data-log fuel pressure during test drive.")

_add("P0234", "high", "Engine detuned, reduced power to protect engine from overboost",
     ["Wastegate stuck closed", "Boost control solenoid failed",
      "Boost pressure sensor reading high", "Turbo bearing failure causing uncontrolled spool",
      "Vacuum line to wastegate cracked/disconnected"],
     ["Check wastegate operation — should move freely",
      "Test boost control solenoid with scan tool bi-directional test",
      "Verify actual boost vs commanded boost with scan tool",
      "Inspect vacuum/pressure lines to wastegate actuator"],
     related=["P0235", "P0236", "P0299"],
     difficulty="hard", cost="$200-$2000",
     notes="Ford EcoBoost: common on 3.5L — check for wastegate rattle TSBs.")

_add("P0235", "medium", "Incorrect boost control, poor performance",
     ["Turbo boost pressure sensor A failed", "Sensor wiring open/short",
      "Boost leak causing inconsistent readings", "Sensor connector corroded"],
     ["Check boost sensor voltage at idle (~1.0-1.5V) and under boost (~3.5-4.5V)",
      "Inspect sensor connector for corrosion",
      "Check for boost leaks with smoke test on charge piping",
      "Compare MAP sensor reading to boost sensor"],
     related=["P0236", "P0237", "P0238", "P0234"],
     difficulty="medium", cost="$50-$300")

_add("P0236", "medium", "Boost control inaccurate, performance loss",
     ["Boost pressure sensor out of range", "Wiring issue",
      "Boost leak in charge piping", "Sensor contaminated with oil"],
     ["Check sensor voltage and compare to spec",
      "Verify no boost leaks with smoke test",
      "Inspect charge air cooler piping for looseness",
      "Replace sensor if readings are erratic"],
     related=["P0235", "P0237", "P0238"],
     difficulty="medium", cost="$50-$300")

_add("P0237", "medium", "Underboost detected, reduced power",
     ["Boost pressure sensor signal low", "Sensor wiring open",
      "Turbo wastegate stuck open", "Boost leak in intercooler piping"],
     ["Check sensor voltage — should not be below 0.5V",
      "Inspect wiring for opens", "Check wastegate for proper closure",
      "Smoke test charge piping for leaks"],
     related=["P0235", "P0236", "P0238", "P0299"],
     difficulty="medium", cost="$50-$400")

_add("P0238", "medium", "Overboost or sensor reading too high",
     ["Boost pressure sensor signal high", "Sensor wiring shorted to voltage",
      "Wastegate stuck closed", "Boost control solenoid failure"],
     ["Check sensor voltage — should not exceed 4.5V",
      "Look for short to power in wiring",
      "Test wastegate actuator movement",
      "Check boost solenoid with bi-directional control"],
     related=["P0235", "P0236", "P0237", "P0234"],
     difficulty="medium", cost="$50-$400")

_add("P0243", "medium", "Poor turbo response, boost control issues",
     ["Wastegate solenoid A circuit malfunction",
      "Solenoid coil open/shorted", "Wiring damage to solenoid",
      "PCM driver failure", "Vacuum line to solenoid disconnected"],
     ["Check wastegate solenoid resistance (typically 20-40 ohms)",
      "Verify 12V power at solenoid connector with key on",
      "Test PCM ground-side driver with DVOM",
      "Inspect vacuum lines to solenoid and wastegate"],
     related=["P0234", "P0299"],
     difficulty="medium", cost="$100-$500",
     notes="Ford EcoBoost: wastegate solenoids are common failure items on 2.0L and 3.5L.")

# ---------------------------------------------------------------------------
# Ignition / Misfire Extended (P0315-P0348)
# ---------------------------------------------------------------------------

_add("P0315", "medium", "CKP system variation not learned after repair",
     ["CKP variation learning procedure not performed",
      "Crankshaft reluctor wheel damaged", "CKP sensor air gap incorrect",
      "Flexplate/flywheel damaged"],
     ["Perform CKP variation learn procedure with scan tool",
      "Ensure engine reaches operating temp before procedure",
      "Check reluctor wheel for missing/damaged teeth",
      "Verify correct CKP sensor installation and air gap"],
     related=["P0335", "P0336", "P0300"],
     difficulty="medium", cost="$0-$200",
     notes="GM-specific: must run CKP relearn with Tech 2 or equivalent after replacing crank sensor, PCM, or engine work.")

_add("P0316", "medium", "Misfire detected on first 1000 revolutions after start",
     ["Weak ignition coil (fails when cold)", "Fuel injector leaking down overnight",
      "Low fuel pressure on initial crank", "Worn spark plugs",
      "Intake manifold gasket leak (cold shrinkage)"],
     ["Check for companion misfire codes (P0301-P0308)",
      "Monitor misfire counters on cold start — which cylinder?",
      "Check fuel pressure on first crank — should reach spec in <2 sec",
      "Inspect spark plugs for wear or fouling"],
     related=["P0300", "P0301", "P0302"],
     difficulty="medium", cost="$50-$500",
     notes="Ford common on 3.5L/3.7L — often coil-on-plug failure. Replace with Motorcraft only.")

_add("P0320", "high", "Engine may stall, no tach reading, hard start",
     ["Crankshaft position sensor failed", "Distributor pickup coil failed",
      "Wiring damage to CKP/distributor sensor", "Reluctor ring damaged",
      "PCM ignition input circuit issue"],
     ["Check for CKP sensor signal with scope during crank",
      "Inspect CKP sensor connector for corrosion",
      "Measure CKP sensor resistance (varies by make — check spec)",
      "Check reluctor ring for damage or debris"],
     related=["P0335", "P0336", "P0300"],
     difficulty="medium", cost="$50-$300")

_add("P0346", "medium", "Engine may run rough, possible no-start",
     ["Camshaft position sensor A circuit range/performance (Bank 2)",
      "Timing chain stretched on Bank 2", "CMP sensor air gap incorrect",
      "Reluctor wheel on camshaft damaged"],
     ["Compare CMP signal timing to CKP signal with scope",
      "Check timing chain tension on Bank 2",
      "Inspect CMP sensor and reluctor wheel",
      "Verify correct sensor installation and air gap"],
     related=["P0345", "P0340", "P0341", "P0016"],
     difficulty="hard", cost="$100-$1500",
     notes="On V6/V8 engines, Bank 2 timing chain stretch is common at high mileage.")

_add("P0347", "medium", "Engine may stall, misfire, no-start condition",
     ["CMP sensor A circuit low (Bank 2)", "Sensor wiring open/shorted to ground",
      "CMP sensor failed internally", "Connector corrosion"],
     ["Check CMP sensor connector for corrosion or damage",
      "Measure voltage at sensor connector — should have 5V ref and ground",
      "Inspect wiring for shorts to ground",
      "Replace CMP sensor if signal is absent"],
     related=["P0345", "P0346", "P0348"],
     difficulty="medium", cost="$50-$200")

_add("P0348", "medium", "Engine may stall, misfire, no-start condition",
     ["CMP sensor A circuit high (Bank 2)", "Sensor wiring shorted to voltage",
      "CMP sensor failed internally", "5V reference backfeed"],
     ["Check CMP sensor signal — should not exceed 5V",
      "Look for wiring shorts to power near cylinder head",
      "Test sensor with scope for correct waveform",
      "Check 5V reference circuit for shorts"],
     related=["P0345", "P0346", "P0347"],
     difficulty="medium", cost="$50-$200")

# ---------------------------------------------------------------------------
# Emissions Auxiliary (P0403-P0457)
# ---------------------------------------------------------------------------

_add("P0403", "medium", "EGR valve electrically failed, possible rough idle",
     ["EGR valve solenoid coil open/shorted", "EGR wiring damage",
      "PCM EGR driver circuit failed", "Connector corrosion at EGR valve"],
     ["Measure EGR solenoid resistance (varies by type, typically 20-40 ohms)",
      "Check for 12V power at EGR connector with key on",
      "Test PCM ground-side driver",
      "Inspect wiring for damage near exhaust manifold (heat damage common)"],
     related=["P0400", "P0401", "P0402", "P0404"],
     difficulty="medium", cost="$100-$400",
     notes="Wiring near exhaust is prone to heat damage — inspect insulation carefully.")

_add("P0404", "medium", "EGR system range/performance, rough idle or stalling",
     ["EGR valve stuck partially open", "EGR position sensor failed",
      "Carbon buildup in EGR valve preventing full closure",
      "EGR passages clogged with carbon"],
     ["Command EGR open/closed with scan tool — watch position sensor",
      "Remove EGR valve and inspect for carbon buildup",
      "Clean or replace EGR valve",
      "Clean EGR passages in intake manifold"],
     related=["P0400", "P0401", "P0402", "P0403"],
     difficulty="medium", cost="$100-$400",
     notes="Ford 6.0L/6.4L diesel: EGR cooler failure is extremely common. Check for coolant in EGR.")

_add("P0421", "high", "Catalyst efficiency below threshold (Bank 1)",
     ["Catalytic converter degraded or poisoned", "Exhaust leak before cat",
      "Engine misfire damaging catalyst", "Incorrect fuel mixture",
      "O2 sensor sluggish giving false reading"],
     ["Compare upstream vs downstream O2 sensor waveforms",
      "Downstream sensor should be nearly flat if cat is working",
      "Check for exhaust leaks before catalyst",
      "Verify no active misfire codes (misfires destroy cats)"],
     related=["P0420", "P0430", "P0431"],
     difficulty="hard", cost="$500-$2500",
     notes="Similar to P0420 but indicates more severe degradation. Check for root cause before replacing cat.")

_add("P0431", "high", "Catalyst efficiency below threshold (Bank 2) — warm-up",
     ["Catalytic converter degraded (Bank 2)", "Exhaust leak before Bank 2 cat",
      "Engine misfire on Bank 2 cylinders damaging catalyst",
      "Bank 2 O2 sensor sluggish"],
     ["Compare Bank 2 upstream vs downstream O2 sensor patterns",
      "Check for exhaust leaks before Bank 2 catalyst",
      "Verify no misfire codes on Bank 2 cylinders",
      "Check O2 sensor response times"],
     related=["P0430", "P0420", "P0421"],
     difficulty="hard", cost="$500-$2500")

_add("P0441", "medium", "EVAP system incorrect purge flow, possible fuel smell",
     ["Purge valve stuck open or closed", "Purge valve vacuum line cracked",
      "Charcoal canister saturated", "EVAP system leak",
      "Vent valve malfunction"],
     ["Command purge valve open/closed with scan tool — listen for click",
      "Check vacuum at purge valve — should hold vacuum when energized",
      "Smoke test EVAP system",
      "Inspect charcoal canister for saturation (fuel smell = saturated)"],
     related=["P0440", "P0442", "P0446", "P0455", "P0456"],
     difficulty="medium", cost="$50-$300")

_add("P0450", "low", "No drivability impact — EVAP monitoring affected",
     ["EVAP pressure sensor (FTP sensor) failed",
      "FTP sensor wiring open/short", "Connector corrosion at sensor",
      "Sensor reference voltage lost"],
     ["Check FTP sensor voltage — should change when gas cap is removed",
      "Verify 5V reference and ground at sensor connector",
      "Inspect connector for corrosion (sensor is on/near fuel tank)",
      "Replace sensor if voltage is stuck"],
     related=["P0451", "P0452", "P0453"],
     difficulty="medium", cost="$50-$200")

_add("P0451", "low", "EVAP pressure sensor range/performance — monitors affected",
     ["FTP sensor intermittent", "Wiring harness damage near fuel tank",
      "FTP sensor contaminated", "Loose or corroded connector"],
     ["Monitor FTP sensor readings — should be stable and responsive",
      "Wiggle-test wiring at sensor connector",
      "Check for intermittent connection at sensor",
      "Replace sensor if readings are erratic"],
     related=["P0450", "P0452", "P0453"],
     difficulty="medium", cost="$50-$200")

_add("P0452", "low", "EVAP pressure sensor circuit low — monitors affected",
     ["FTP sensor wiring open/shorted to ground", "FTP sensor failed low",
      "Connector pins corroded or bent", "Ground circuit issue"],
     ["Check FTP sensor voltage — should not be at 0V",
      "Inspect wiring for short to ground near fuel tank",
      "Check connector pins for corrosion",
      "Verify ground circuit integrity"],
     related=["P0450", "P0451", "P0453"],
     difficulty="easy", cost="$50-$200")

_add("P0453", "low", "EVAP pressure sensor circuit high — monitors affected",
     ["FTP sensor wiring shorted to voltage", "FTP sensor failed high",
      "5V reference backfeed", "Connector issue"],
     ["Check FTP sensor voltage — should not be at 5V",
      "Look for short to voltage in wiring",
      "Verify 5V reference is not backfeeding through signal wire",
      "Replace sensor if stuck high"],
     related=["P0450", "P0451", "P0452"],
     difficulty="easy", cost="$50-$200")

_add("P0457", "low", "EVAP system leak detected — loose fuel cap most common",
     ["Fuel cap not tightened properly", "Fuel cap seal cracked or worn",
      "Fuel cap missing", "EVAP line near filler neck cracked"],
     ["Tighten or replace fuel cap — clear code and drive",
      "Inspect fuel cap seal for cracks or wear",
      "If code returns, smoke test EVAP system",
      "Check filler neck area for cracks"],
     related=["P0455", "P0456", "P0440", "P0442"],
     difficulty="easy", cost="$5-$50",
     notes="Most common cause is simply a loose gas cap. Tighten and re-test before diagnosing further.")

# ---------------------------------------------------------------------------
# Speed / Idle Control Extended (P0501-P0532)
# ---------------------------------------------------------------------------

_add("P0501", "medium", "Speedometer may be inaccurate, ABS/TC issues possible",
     ["Vehicle speed sensor range/performance", "VSS erratic signal",
      "Tone ring on axle damaged", "VSS wiring intermittent"],
     ["Check VSS signal with scan tool — compare to actual speed",
      "Inspect tone ring on output shaft or axle for damage",
      "Check VSS wiring for intermittent connections",
      "Compare VSS to wheel speed sensors for discrepancies"],
     related=["P0500", "P0502", "P0503"],
     difficulty="medium", cost="$50-$300")

_add("P0502", "medium", "No speedometer reading, cruise control inoperative",
     ["VSS circuit low input", "VSS wiring open or shorted to ground",
      "VSS sensor failed", "Connector corrosion at transmission"],
     ["Check for VSS signal — should produce AC voltage while moving",
      "Inspect VSS connector at transmission for corrosion",
      "Measure VSS wiring continuity to PCM",
      "Replace VSS if no signal with known-good wiring"],
     related=["P0500", "P0501", "P0503"],
     difficulty="medium", cost="$50-$250")

_add("P0503", "medium", "Erratic speedometer, harsh shifting, ABS issues",
     ["VSS circuit intermittent/high input", "VSS generating noise",
      "Electromagnetic interference on signal wire", "Tone ring damaged"],
     ["Monitor VSS signal for erratic readings or dropouts",
      "Check for proper shielding on VSS signal wire",
      "Inspect tone ring for cracks or missing teeth",
      "Route VSS wiring away from ignition components"],
     related=["P0500", "P0501", "P0502"],
     difficulty="medium", cost="$50-$300")

_add("P0508", "medium", "Idle speed lower than expected, may stall",
     ["Idle air control (IAC) circuit low",
      "IAC valve stuck closed or carbon-fouled",
      "Wiring open to IAC valve", "Throttle body carbon buildup"],
     ["Check IAC valve operation — command open/closed with scan tool",
      "Clean throttle body and IAC passages",
      "Measure IAC coil resistance",
      "Check wiring from PCM to IAC valve"],
     related=["P0505", "P0506", "P0507", "P0509"],
     difficulty="easy", cost="$50-$250")

_add("P0509", "medium", "Idle speed higher than expected, fast idle",
     ["IAC circuit high", "IAC valve stuck open",
      "Vacuum leak causing high idle", "Wiring shorted to voltage"],
     ["Check for vacuum leaks with smoke test",
      "Command IAC closed with scan tool — idle should drop",
      "Inspect IAC valve for sticking in open position",
      "Check wiring for shorts to voltage"],
     related=["P0505", "P0506", "P0507", "P0508"],
     difficulty="easy", cost="$50-$250")

_add("P0521", "medium", "Oil pressure gauge may be inaccurate",
     ["Oil pressure sensor range/performance", "Sensor wiring intermittent",
      "Sensor contaminated with sealant", "Actual oil pressure issue"],
     ["Check actual oil pressure with mechanical gauge and compare to sensor",
      "Inspect sensor connector for oil contamination",
      "Check wiring for intermittent connections",
      "Replace sensor if mechanical gauge confirms good pressure"],
     related=["P0520", "P0522", "P0523"],
     difficulty="easy", cost="$20-$100")

_add("P0522", "high", "Oil pressure sensor circuit low — possible low oil pressure",
     ["Oil pressure sensor wiring shorted to ground", "Sensor failed low",
      "Actual low oil pressure (dangerous!)", "Connector corroded"],
     ["FIRST: verify actual oil pressure with mechanical gauge!",
      "If oil pressure is truly low, check oil level and pump",
      "If pressure is OK, inspect sensor wiring for shorts to ground",
      "Replace oil pressure sensor"],
     related=["P0520", "P0521", "P0523", "P0524"],
     difficulty="easy", cost="$20-$100",
     notes="CRITICAL: Always verify actual oil pressure mechanically before assuming sensor fault. Low oil pressure can destroy an engine.")

_add("P0523", "medium", "Oil pressure gauge reads high or erratic",
     ["Oil pressure sensor wiring shorted to voltage", "Sensor failed high",
      "5V reference backfeed", "Oil pressure relief valve stuck"],
     ["Check sensor voltage — should not be at 5V with engine off",
      "Verify with mechanical oil pressure gauge",
      "Inspect wiring for shorts to voltage",
      "Replace sensor if readings are stuck high"],
     related=["P0520", "P0521", "P0522"],
     difficulty="easy", cost="$20-$100")

_add("P0532", "low", "A/C may not engage, A/C pressure reading incorrect",
     ["A/C pressure sensor circuit low", "Sensor wiring open/shorted to ground",
      "A/C pressure sensor failed", "Low refrigerant causing valid low reading"],
     ["Check A/C refrigerant level first",
      "Check A/C pressure sensor voltage — should vary with system pressure",
      "Inspect wiring for damage or shorts",
      "Replace A/C pressure sensor if charge is confirmed good"],
     related=["P0530"],
     difficulty="easy", cost="$30-$150",
     notes="Verify refrigerant charge before replacing sensor — a legitimate low-charge condition can cause this code.")

# ---------------------------------------------------------------------------
# PCM / Internal Processor (P0600-P0650)
# ---------------------------------------------------------------------------

_add("P0600", "high", "Multiple drivability issues possible, communication errors",
     ["PCM internal serial communication error",
      "PCM power/ground issue causing internal resets",
      "Battery voltage too low during cranking",
      "PCM failing internally"],
     ["Check PCM power and ground circuits — should have battery voltage and <0.1V drop on grounds",
      "Check battery condition and charging system",
      "Clear code and monitor — single occurrence may be voltage dip",
      "If persistent, PCM may need replacement and reprogram"],
     related=["P0601", "P0602", "P0603", "P0606"],
     difficulty="hard", cost="$100-$1500",
     notes="Often caused by low battery voltage during crank. Check battery and charging system before condemning PCM.")

_add("P0602", "high", "PCM may default to backup calibration, reduced performance",
     ["PCM programming error", "PCM calibration corrupted",
      "Failed PCM reflash/update", "PCM memory failure"],
     ["Attempt PCM reprogram/reflash with latest calibration",
      "Check for TSBs requiring PCM update",
      "If reflash fails, PCM may need replacement",
      "Verify correct PCM part number for vehicle application"],
     related=["P0601", "P0603", "P0604", "P0605"],
     difficulty="hard", cost="$200-$1500",
     notes="Ford IDS/FDRS can reprogram PCM. Always install latest calibration. GM requires TIS2Web or equivalent.")

_add("P0604", "high", "PCM RAM failure, unpredictable behavior possible",
     ["PCM internal RAM memory error", "Power supply voltage issue",
      "PCM failing internally", "Corrosion on PCM connector"],
     ["Check PCM power and ground circuits thoroughly",
      "Inspect PCM connectors for corrosion or water intrusion",
      "Clear code — if returns, PCM likely needs replacement",
      "Verify no water leaks near PCM location"],
     related=["P0601", "P0603", "P0605", "P0606"],
     difficulty="hard", cost="$300-$1500",
     notes="Ford: check for water intrusion at PCM — common on F-150 with leaking windshield.")

_add("P0605", "high", "PCM ROM failure, may not start or run erratically",
     ["PCM internal ROM memory failure", "Corrupted PCM firmware",
      "PCM hardware failure", "Power supply issue"],
     ["Attempt PCM reprogram with factory tool",
      "Check all PCM power and ground circuits",
      "Inspect PCM for physical damage or burnt components",
      "Replace and reprogram PCM if reflash fails"],
     related=["P0601", "P0603", "P0604", "P0606"],
     difficulty="hard", cost="$300-$1500")

_add("P0607", "high", "PCM performance degraded, limp mode possible",
     ["PCM internal control module performance issue",
      "PCM overheating", "Power supply voltage fluctuation",
      "PCM hardware degradation"],
     ["Check PCM operating temperature — is it mounted near exhaust?",
      "Verify battery voltage stable under load",
      "Check all PCM power and ground pins",
      "Replace PCM if code persists after power/ground verification"],
     related=["P0606", "P0601", "P0605"],
     difficulty="hard", cost="$300-$1500",
     notes="If PCM is hot to the touch, check for nearby exhaust heat shields. Relocate if needed.")

_add("P0615", "high", "No-crank, starter relay circuit malfunction",
     ["Starter relay failed", "Starter relay wiring open/short",
      "Ignition switch failure", "PCM starter control driver failed",
      "Neutral safety switch malfunction"],
     ["Check starter relay — swap with identical relay to test",
      "Verify voltage at starter relay coil terminal with key in crank",
      "Check neutral safety / clutch pedal position switch",
      "Test ignition switch outputs in crank position"],
     related=["P0616", "P0617"],
     difficulty="medium", cost="$30-$500")

_add("P0616", "medium", "Starter engages weakly or not at all",
     ["Starter relay circuit low", "Relay coil wiring high resistance",
      "Relay control ground poor", "PCM driver weak"],
     ["Measure voltage at relay coil — should be near battery voltage",
      "Check relay ground circuit — should be <0.5V",
      "Test relay coil resistance",
      "Check PCM starter driver output"],
     related=["P0615", "P0617"],
     difficulty="medium", cost="$30-$300")

_add("P0617", "medium", "Starter may engage unexpectedly or stay engaged",
     ["Starter relay circuit high", "Relay stuck engaged",
      "Wiring short to power", "Ignition switch sticking in crank"],
     ["Check for relay stuck closed — starter should disengage after start",
      "Inspect wiring for shorts to battery voltage",
      "Test ignition switch — should return from crank to run position",
      "Replace relay if stuck"],
     related=["P0615", "P0616"],
     difficulty="medium", cost="$30-$300",
     notes="A stuck starter relay can damage the flywheel/flexplate ring gear. Address promptly.")

_add("P0627", "high", "No fuel pump operation, no-start condition",
     ["Fuel pump relay A open circuit", "Relay failed",
      "Wiring open between PCM and fuel pump relay",
      "PCM fuel pump driver failed", "Fuse blown"],
     ["Check fuel pump fuse first",
      "Swap fuel pump relay with identical relay to test",
      "Check for 12V at relay coil terminal with key on",
      "Verify PCM is commanding relay on — check ground side with DVOM"],
     related=["P0628", "P0629", "P0230", "P0231"],
     difficulty="medium", cost="$20-$400")

_add("P0628", "high", "Fuel pump may not run or run weakly, no-start or stall",
     ["Fuel pump relay A circuit low", "Relay coil wiring shorted to ground",
      "PCM fuel pump driver shorted", "Relay coil failed"],
     ["Check relay coil resistance — should be 50-100 ohms typically",
      "Inspect wiring for shorts to ground",
      "Test PCM command — should provide ground for relay coil",
      "Replace relay if coil is shorted"],
     related=["P0627", "P0629", "P0230"],
     difficulty="medium", cost="$20-$400")

_add("P0629", "medium", "Fuel pump may run continuously, possible fuel flooding",
     ["Fuel pump relay A circuit high", "Relay stuck closed",
      "Wiring short to voltage", "PCM driver shorted to power"],
     ["Check if fuel pump runs continuously with key on engine off",
      "Swap relay to test — if pump still runs, wiring short",
      "Inspect wiring for chafing against power sources",
      "Check PCM relay control driver"],
     related=["P0627", "P0628", "P0232"],
     difficulty="medium", cost="$20-$400")

_add("P0650", "low", "MIL (Check Engine Light) may not illuminate",
     ["MIL lamp bulb burned out", "MIL driver circuit in PCM failed",
      "Wiring open between PCM and instrument cluster",
      "Instrument cluster fault"],
     ["Check MIL bulb — should illuminate during key-on bulb check",
      "Verify PCM is commanding MIL on (scan tool should show MIL status)",
      "Check wiring from PCM to cluster",
      "Test MIL driver output at PCM connector"],
     related=["P0606"],
     difficulty="easy", cost="$5-$200",
     notes="A non-working MIL is a safety/emissions inspection failure. Fix even though it does not affect drivability.")

# ---------------------------------------------------------------------------
# Transmission Extended (P0705-P0748)
# ---------------------------------------------------------------------------

_add("P0705", "high", "Transmission may not shift properly, backup lights may not work",
     ["Transmission range sensor (TRS) malfunction",
      "TRS connector corroded or damaged", "TRS adjustment incorrect",
      "Internal transmission wiring fault"],
     ["Check TRS connector for corrosion — common on Ford transmissions",
      "Verify TRS adjustment — scan tool should show correct gear selection",
      "Check TRS resistance/voltage in each gear position",
      "On some Fords, TRS is part of the solenoid body — internal repair needed"],
     related=["P0706", "P0700"],
     difficulty="medium", cost="$50-$500",
     notes="Ford common issue: TRS connector on 5R55/6R80 corrodes. Check connector first before replacing sensor.")

_add("P0706", "medium", "Harsh or erratic shifting, gear indicator may be wrong",
     ["TRS signal out of range", "TRS misadjusted after transmission service",
      "Internal shift linkage issue", "TRS contaminated with fluid"],
     ["Verify TRS reads correct gear in each selector position",
      "Check TRS adjustment per service manual procedure",
      "Inspect shift linkage for loose or worn bushings",
      "Clean TRS if contaminated with transmission fluid"],
     related=["P0705", "P0700"],
     difficulty="medium", cost="$50-$400")

_add("P0716", "medium", "Harsh or erratic shifting, speedometer issues",
     ["Input/turbine speed sensor signal erratic",
      "Sensor contaminated with metallic debris",
      "Tone ring damaged", "Wiring intermittent at connector"],
     ["Check input speed sensor signal with scan tool — compare to engine RPM in each gear",
      "Inspect sensor tip for metallic debris (indicates internal trans wear)",
      "Check sensor connector at transmission for corrosion",
      "Replace sensor — they are inexpensive and external on most transmissions"],
     related=["P0715", "P0717", "P0720"],
     difficulty="medium", cost="$50-$200")

_add("P0721", "medium", "Harsh shifting, TCC shudder, speedometer error",
     ["Output speed sensor range/performance issue",
      "Sensor wiring intermittent", "Tone ring worn or damaged",
      "Sensor air gap too large"],
     ["Compare output speed sensor to VSS or wheel speed sensors",
      "Inspect sensor for debris on tip",
      "Check wiring for intermittent connections at connector",
      "Replace sensor — usually externally mounted on tail shaft"],
     related=["P0720", "P0715", "P0500"],
     difficulty="easy", cost="$30-$150")

_add("P0725", "medium", "Erratic shifting, harsh engagement, shudder",
     ["Engine speed input circuit malfunction",
      "CKP sensor signal not reaching TCM", "CKP sensor failing",
      "Wiring fault between PCM/CKP and TCM"],
     ["Check CKP sensor signal — TCM uses it for shift timing",
      "Verify CKP-related codes are not also present",
      "Check wiring between PCM and TCM for engine speed signal",
      "On integrated PCM/TCM (like Ford 6R80), check internal connections"],
     related=["P0335", "P0720", "P0715"],
     difficulty="medium", cost="$50-$400")

_add("P0731", "high", "Transmission slipping in 1st gear, flare on 1-2 shift",
     ["Low transmission fluid level", "Worn 1st gear clutch pack",
      "1st gear solenoid stuck or failed", "Valve body issue",
      "Internal seal leak"],
     ["Check transmission fluid level and condition (burnt smell = problem)",
      "Check line pressure in 1st gear — compare to spec",
      "Monitor slip RPM with scan tool — input vs output speed",
      "If fluid is burnt or has debris, internal repair likely needed"],
     related=["P0730", "P0732", "P0700"],
     difficulty="hard", cost="$200-$3500",
     notes="If fluid is dark and smells burnt, prepare customer for transmission rebuild/replacement.")

_add("P0732", "high", "Transmission slipping in 2nd gear",
     ["2nd gear clutch pack worn", "2nd gear solenoid failure",
      "Valve body 2nd gear circuit issue", "Low fluid or burnt fluid",
      "Internal seal leak"],
     ["Check fluid level and condition",
      "Monitor 2nd gear slip with scan tool",
      "Check line pressure in 2nd gear",
      "If internal damage confirmed, rebuild or replace transmission"],
     related=["P0730", "P0731", "P0733", "P0700"],
     difficulty="hard", cost="$200-$3500")

_add("P0733", "high", "Transmission slipping in 3rd gear",
     ["3rd gear clutch pack worn", "3rd gear solenoid failure",
      "Valve body issue", "Low transmission fluid",
      "Internal seal leak"],
     ["Check fluid level and condition",
      "Monitor 3rd gear ratio with scan tool — compare to spec",
      "Check line pressure in 3rd gear",
      "Perform stall test if applicable"],
     related=["P0730", "P0732", "P0734", "P0700"],
     difficulty="hard", cost="$200-$3500")

_add("P0734", "high", "Transmission slipping in 4th gear / overdrive",
     ["4th gear clutch pack worn", "Overdrive solenoid failure",
      "Valve body issue", "Accumulator piston worn",
      "Low fluid level"],
     ["Check fluid level and condition",
      "Monitor 4th gear slip with scan tool",
      "Check line pressure in 4th gear",
      "Ford 4R70W/5R55: check overdrive servo for wear"],
     related=["P0730", "P0733", "P0735", "P0700"],
     difficulty="hard", cost="$200-$3500",
     notes="Ford 4R70W: overdrive band/servo failure is a known weak point at higher mileages.")

_add("P0735", "high", "Transmission slipping in 5th gear (5+ speed trans)",
     ["5th gear clutch pack worn", "5th gear solenoid failure",
      "Valve body issue", "Low or contaminated fluid"],
     ["Check fluid level and condition",
      "Monitor 5th gear ratio with scan tool — compare to spec",
      "Check for TSBs on 5th gear issues for specific transmission",
      "If slipping confirmed, internal transmission repair needed"],
     related=["P0730", "P0734", "P0700"],
     difficulty="hard", cost="$200-$3500")

_add("P0743", "high", "TCC does not engage/disengage properly, overheating risk",
     ["TCC solenoid circuit malfunction", "TCC solenoid open/shorted",
      "Wiring to TCC solenoid damaged", "TCM/PCM TCC driver failed"],
     ["Measure TCC solenoid resistance (typically 10-25 ohms)",
      "Check for 12V power at solenoid connector",
      "Test PCM/TCM ground-side driver for TCC",
      "Check wiring through transmission case connector for damage"],
     related=["P0740", "P0741", "P0748"],
     difficulty="hard", cost="$100-$500",
     notes="TCC solenoid is internal to transmission on most vehicles — requires pan drop or valve body removal.")

_add("P0748", "high", "Harsh shifting, transmission overheating possible",
     ["Pressure control solenoid A circuit malfunction",
      "Solenoid failed electrically", "Wiring damage inside transmission",
      "TCM/PCM driver failed", "Connector corrosion at transmission case"],
     ["Check solenoid resistance at transmission connector",
      "Inspect connector at transmission case for corrosion",
      "Test PCM/TCM solenoid driver output",
      "Drop pan and inspect for debris (indicates internal failure)"],
     related=["P0740", "P0750", "P0700"],
     difficulty="hard", cost="$150-$800",
     notes="GM 4L60E/4L80E: pressure control solenoid failure is very common — available as external replacement on some models.")

# ---------------------------------------------------------------------------
# Additional U-Codes — Network Communication
# ---------------------------------------------------------------------------

_add("U0003", "high", "Multiple module communication failures, many DTCs possible",
     ["CAN bus high/low wires shorted together", "CAN bus backbone damaged",
      "Terminating resistor failed", "Module pulling bus down"],
     ["Check CAN bus voltage with DVOM — H should be ~2.5-3.5V, L should be ~1.5-2.5V",
      "Measure CAN bus termination resistance (should be ~60 ohms between H and L)",
      "Disconnect modules one at a time to find the one pulling bus down",
      "Inspect CAN bus wiring for damage, especially at connectors"],
     related=["U0001", "U0100", "U0073"],
     difficulty="hard", cost="$100-$1000",
     notes="CAN bus shorts can be very difficult to find. Start at the backbone splices and work outward.")

_add("U0019", "high", "Intermittent communication loss with multiple modules",
     ["CAN bus intermittent open or short",
      "Loose CAN bus connector at a module",
      "Wiring chafing causing intermittent contact",
      "Module with intermittent power loss"],
     ["Monitor CAN bus with scope for intermittent dropout",
      "Wiggle-test CAN connectors at each module while monitoring",
      "Check for TSBs on CAN bus connector issues for this vehicle",
      "Inspect wiring harness for chafing near steering column and under dash"],
     related=["U0001", "U0003", "U0073"],
     difficulty="hard", cost="$100-$800",
     notes="Ford: check CAN bus connectors behind the instrument panel — they are known for intermittent connections.")

_add("U0102", "medium", "Loss of communication with transfer case control module",
     ["Transfer case control module failed", "CAN bus wiring open to module",
      "Module power/ground issue", "Connector corrosion"],
     ["Check for power and ground at transfer case module connector",
      "Verify CAN bus voltage at module connector",
      "Check for CAN bus codes on other modules (network-wide issue?)",
      "Inspect connector for corrosion — exposed to road spray"],
     related=["U0100", "U0001"],
     difficulty="medium", cost="$100-$800",
     notes="Transfer case modules are exposed to road spray and salt — connector corrosion is common.")

_add("U0103", "medium", "Shifting issues, transmission in limp mode",
     ["Loss of communication with gear shift module",
      "Shift module wiring fault", "CAN bus issue to shift module",
      "Shift module failure"],
     ["Check shift module power and ground",
      "Verify CAN communication at shift module connector",
      "Check for other U-codes indicating network-wide issue",
      "Inspect wiring to shift module in center console"],
     related=["U0100", "U0101", "P0700"],
     difficulty="medium", cost="$100-$600")

_add("U0104", "medium", "Cruise control inoperative, speed data unavailable",
     ["Loss of communication with cruise control module",
      "Cruise control module failed", "CAN bus wiring fault",
      "Steering wheel clock spring failure (if integrated controls)"],
     ["Check cruise control module power and ground",
      "Verify CAN bus at module connector",
      "On vehicles with steering wheel controls, check clock spring",
      "Test cruise control switches for proper operation"],
     related=["U0100", "P0500"],
     difficulty="medium", cost="$50-$500")

_add("U0105", "medium", "Fuel level gauge inoperative, possible drivability issues",
     ["Loss of communication with fuel injector control module",
      "Module power/ground fault", "CAN bus wiring open",
      "Module failed internally"],
     ["Check module power and ground circuits",
      "Verify CAN bus present at module connector",
      "Check for related powertrain DTCs",
      "Inspect wiring for damage"],
     related=["U0100", "U0101"],
     difficulty="medium", cost="$100-$600")

_add("U0106", "medium", "Glow plug system inoperative (diesel), hard cold start",
     ["Loss of communication with glow plug control module",
      "Glow plug module failed", "CAN wiring to module damaged",
      "Module power supply fault"],
     ["Check glow plug module power and ground",
      "Verify CAN bus voltage at module connector",
      "Test glow plug module directly — some have self-test capability",
      "Common on Ford 6.0L/6.7L diesel — check for water intrusion in module connector"],
     related=["U0100", "U0101"],
     difficulty="medium", cost="$100-$500",
     notes="Ford diesel: glow plug control module is under the hood and exposed to moisture. Inspect connector closely.")

_add("U0109", "medium", "Fuel system issues, reduced power on diesel engines",
     ["Loss of communication with fuel pump control module",
      "FPDM power/ground fault", "CAN bus wiring to FPDM damaged",
      "FPDM failed internally"],
     ["Check FPDM power and ground — Ford FPDM is usually on frame rail",
      "Verify CAN bus at FPDM connector",
      "Inspect connector for corrosion (road exposure)",
      "Test fuel pump operation independently"],
     related=["U0100", "P0230", "P0231"],
     difficulty="medium", cost="$100-$500",
     notes="Ford: FPDM is mounted on the frame and exposed to road debris and corrosion.")

# ---------------------------------------------------------------------------
# Additional B-Codes — Body Control
# ---------------------------------------------------------------------------

_add("B0001", "high", "Driver frontal airbag circuit malfunction — SRS warning illuminated",
     ["Driver airbag clock spring failure", "Airbag module connector corroded",
      "Wiring harness damage in steering column",
      "Airbag module internal fault", "Steering column work disturbed connection"],
     ["DO NOT attempt repair without proper SRS training and tools",
      "Check clock spring continuity (most common cause)",
      "Inspect steering column connectors — disconnect battery first!",
      "Scan for all SRS codes before any repair"],
     related=["B0002", "B0010"],
     difficulty="hard", cost="$100-$800",
     notes="SAFETY CRITICAL: Always disconnect battery and wait 1 minute before working on airbag circuits. Clock spring fails after steering column service.")

_add("B0002", "high", "Passenger frontal airbag circuit malfunction — SRS warning illuminated",
     ["Passenger airbag module connector issue",
      "Wiring under passenger seat damaged", "Airbag module failure",
      "Connector corrosion from spilled liquids"],
     ["DO NOT attempt without SRS training — disconnect battery first",
      "Check connector under dash on passenger side",
      "Inspect wiring for damage — liquids spilled on dash can corrode connectors",
      "Scan for all SRS codes"],
     related=["B0001", "B0010"],
     difficulty="hard", cost="$100-$1000",
     notes="SAFETY CRITICAL: Disconnect battery before any SRS work.")

_add("B0010", "high", "Side airbag circuit malfunction — SRS warning illuminated",
     ["Side airbag wiring in seat damaged", "Seat connector corroded",
      "Airbag module failure", "Wiring pinched by seat track"],
     ["Disconnect battery — wait 1 minute before working on SRS",
      "Inspect seat side airbag connector under seat",
      "Check wiring harness in seat for pinch damage from seat track",
      "Verify seat connector mates properly — common cause after seat removal"],
     related=["B0001", "B0002", "B0020"],
     difficulty="hard", cost="$100-$800",
     notes="SAFETY CRITICAL: Most common after seat removal/reinstall — connector not fully seated.")

_add("B0020", "high", "Passenger presence detection fault — airbag may not deploy correctly",
     ["Occupant classification sensor (OCS) in seat failed",
      "OCS wiring damaged under seat", "OCS connector corroded",
      "Passenger seat foam deterioration affecting sensor"],
     ["Disconnect battery before SRS work",
      "Check OCS connector under passenger seat",
      "Inspect wiring for damage from seat track movement",
      "Check for TSBs — GM and Ford have OCS mat recalls/TSBs"],
     related=["B0001", "B0002", "B0010"],
     difficulty="hard", cost="$200-$1200",
     notes="Ford/GM: occupant classification sensor mats fail over time. Check for recall coverage before paying out of pocket.")

_add("B0028", "medium", "SRS warning light on — right front impact sensor fault",
     ["Front impact sensor failed", "Sensor wiring damaged in fender area",
      "Sensor connector corroded", "Collision repair did not properly reconnect sensor"],
     ["Disconnect battery before SRS work",
      "Inspect front impact sensor and wiring in fender/bumper area",
      "Check for prior collision repair — sensor may not have been reconnected",
      "Measure sensor circuit resistance per service manual"],
     related=["B0001", "B0010"],
     difficulty="medium", cost="$50-$300",
     notes="If vehicle was in a prior collision, impact sensors may have been damaged or not reconnected.")

_add("B0051", "low", "Interior temperature display may be inaccurate",
     ["Interior temperature sensor failed", "Sensor aspirator tube blocked",
      "Wiring issue to sensor", "A/C control module fault"],
     ["Locate interior temp sensor (usually in headliner or dash)",
      "Check sensor aspirator tube for blockage (lint, debris)",
      "Measure sensor resistance — should vary with temperature",
      "Check wiring from sensor to HVAC module"],
     related=["B0071"],
     difficulty="easy", cost="$20-$100")

_add("B0071", "low", "Outside temperature display incorrect or missing",
     ["Ambient temperature sensor failed", "Sensor wiring damaged",
      "Sensor located in bumper area — road debris damage",
      "Connector corrosion from road spray"],
     ["Check ambient temp sensor in front bumper area — compare to known temp",
      "Inspect wiring from sensor to cluster/BCM",
      "Measure sensor resistance (NTC thermistor — should decrease with heat)",
      "Check connector for corrosion"],
     related=["B0051"],
     difficulty="easy", cost="$15-$75",
     notes="Sensor is usually behind front bumper or grille — vulnerable to road debris and corrosion.")

_add("B0081", "low", "Sunroof inoperative or partially functional",
     ["Sunroof motor failed", "Sunroof track binding or obstructed",
      "Sunroof switch failure", "BCM sunroof driver circuit fault",
      "Sunroof drain clogged causing water damage to motor"],
     ["Check sunroof switch — does motor get power?",
      "Listen for motor noise when operating switch",
      "Inspect sunroof tracks for debris or binding",
      "Check sunroof drains — clogged drains cause water damage to motor"],
     related=["B0091"],
     difficulty="medium", cost="$100-$800")

_add("B0091", "low", "Power window inoperative or intermittent",
     ["Window motor failed", "Window regulator cable broken",
      "Window switch contacts worn", "BCM window circuit fault",
      "Wiring damage in door hinge area"],
     ["Check window switch with test light — power in all positions?",
      "Listen for motor noise when pressing switch",
      "Inspect wiring in door jamb flex area — common break point",
      "Test motor directly with jumper wires to confirm motor vs switch"],
     related=["B0081"],
     difficulty="medium", cost="$50-$400",
     notes="Most common failure point is wiring in the door jamb area where it flexes. Also check master switch contacts.")

_add("B0095", "low", "Wiper system malfunction, wipers inoperative or erratic",
     ["Wiper motor failure", "Wiper module/relay failure",
      "Wiper switch contact wear", "Wiring issue to wiper motor",
      "Wiper park switch in motor failed"],
     ["Check wiper fuse and relay first",
      "Test wiper motor with direct 12V — does it run?",
      "Check wiper switch continuity in each position",
      "Inspect wiring at wiper motor connector for corrosion"],
     related=[],
     difficulty="easy", cost="$50-$300")

_add("B1000", "medium", "BCM internal fault, multiple body functions may be affected",
     ["BCM internal processor error", "BCM power supply issue",
      "Software corruption", "Water intrusion into BCM"],
     ["Check BCM power and ground circuits",
      "Inspect BCM location for water intrusion signs",
      "Clear code and retest — may be a one-time glitch",
      "Reprogram BCM with latest calibration if available"],
     related=["B1001", "U0140"],
     difficulty="hard", cost="$200-$1000",
     notes="Ford BCM is often located in left kick panel — check for water leaks from windshield or A/C drain.")

_add("B1001", "medium", "BCM configuration error, features may not work correctly",
     ["BCM not properly configured for vehicle options",
      "BCM replaced without proper setup/programming",
      "Configuration data corrupted"],
     ["Reprogram BCM with factory tool (IDS/FDRS for Ford, Tech2 for GM)",
      "Verify correct BCM part number for vehicle",
      "Run module configuration/setup procedure",
      "Check for all option codes and ensure BCM matches"],
     related=["B1000", "U0140"],
     difficulty="hard", cost="$100-$600",
     notes="After BCM replacement, it MUST be programmed with the correct vehicle configuration. Aftermarket BCMs may not work.")

_add("B1015", "low", "Seat memory system malfunction — seats/mirrors may not adjust",
     ["Seat memory module failed", "Memory switch failure",
      "Seat position sensor fault", "Wiring harness damage under seat"],
     ["Check seat memory switch operation",
      "Inspect wiring under driver seat for pinch damage",
      "Test seat motor operation independently",
      "Check seat memory module power and ground"],
     related=["B1022"],
     difficulty="medium", cost="$50-$500")

_add("B1022", "low", "Driver seat position sensor fault — memory recall inaccurate",
     ["Seat position potentiometer worn",
      "Seat motor encoder failed", "Wiring damage under seat",
      "Connector corroded under seat"],
     ["Check seat position sensor connector under seat",
      "Move seat through full range — monitor sensor values with scan tool",
      "Inspect wiring for damage from seat track",
      "Replace sensor/motor if readings are erratic or absent"],
     related=["B1015"],
     difficulty="medium", cost="$100-$500")

_add("B1050", "medium", "Power steering assist malfunction (EPAS systems)",
     ["EPAS motor failure", "EPAS module internal fault",
      "Steering column torque sensor failure",
      "Wiring to EPAS module damaged", "Battery voltage too low for EPAS"],
     ["Check battery voltage — EPAS requires good voltage",
      "Check EPAS module connector for corrosion",
      "Read steering angle and torque sensor data with scan tool",
      "Verify EPAS motor operation — should assist when turning",
      "Check for TSBs — some Ford EPAS modules have recalls"],
     related=["C0131", "U0131"],
     difficulty="hard", cost="$200-$1500",
     notes="Ford/Lincoln: EPAS failures on 2011-2015 models prompted recalls. Check NHTSA recall database before repair.")

# ---------------------------------------------------------------------------
# Additional C-Codes — Chassis / ABS / Stability
# ---------------------------------------------------------------------------

_add("C0032", "medium", "ABS warning light on — RF wheel speed sensor issue",
     ["Right front wheel speed sensor failed", "Sensor wiring damaged",
      "Sensor air gap too large (worn bearing)", "Tone ring cracked or contaminated",
      "Wheel bearing play causing inconsistent signal"],
     ["Check RF wheel speed sensor resistance (typically 800-2000 ohms)",
      "Inspect sensor and tone ring for contamination or damage",
      "Check for wheel bearing play — excessive play = bad air gap",
      "Compare RF speed to other wheels with scan tool while driving"],
     related=["C0031", "C0035", "C0040"],
     difficulty="medium", cost="$50-$300",
     notes="A worn wheel bearing is a common root cause — the increased air gap causes erratic speed signals.")

_add("C0065", "medium", "ABS/stability warning on — rear brake pressure issue",
     ["Rear brake pressure sensor fault",
      "Brake pressure modulator valve issue", "Wiring to sensor damaged",
      "ABS hydraulic unit internal fault"],
     ["Check rear brake pressure sensor connector",
      "Verify rear brake pressure reading with scan tool — compare to front",
      "Inspect brake lines for restrictions or leaks",
      "Check ABS hydraulic unit for external leaks"],
     related=["C0050", "C0055", "C0060"],
     difficulty="hard", cost="$100-$800")

_add("C0070", "medium", "Stability control / traction control warning illuminated",
     ["Steering angle sensor calibration lost",
      "Steering angle sensor failed", "Clock spring affecting sensor signal",
      "Yaw rate sensor fault"],
     ["Perform steering angle sensor calibration/zero-point learning",
      "Check steering angle sensor data with scan tool — should read 0 when straight",
      "Turn lock-to-lock slowly — value should change smoothly",
      "If erratic, check clock spring continuity (may share connector)"],
     related=["C0131", "C0045"],
     difficulty="medium", cost="$50-$500",
     notes="Many vehicles require steering angle recalibration after alignment or suspension work.")

_add("C0100", "medium", "ABS/traction control warning illuminated",
     ["ABS module internal fault", "ABS pump motor failure",
      "ABS relay failed", "Low brake fluid triggering ABS warning",
      "ABS module power/ground issue"],
     ["Check brake fluid level — low fluid triggers ABS warning on some vehicles",
      "Check ABS fuse and relay",
      "Verify ABS module power and ground circuits",
      "Read ABS module DTCs — may need enhanced scanner for ABS-specific codes"],
     related=["C0131", "C0050", "C0060"],
     difficulty="hard", cost="$100-$1500")

_add("C0110", "medium", "ABS pump motor circuit fault",
     ["ABS pump motor failed", "ABS pump relay failed",
      "Wiring to pump motor damaged", "ABS module driver failed"],
     ["Check ABS pump relay — swap with identical relay to test",
      "Listen for pump motor operation during ABS event",
      "Check motor connector for power and ground",
      "If relay and wiring are good, ABS module likely needs replacement"],
     related=["C0100", "C0131"],
     difficulty="hard", cost="$200-$1500",
     notes="ABS pump motors can fail from age and corrosion. Module replacement is expensive — check for remanufactured units.")

_add("C0141", "medium", "Stability control disabled, VSC/ESC warning on",
     ["Yaw rate sensor fault", "Lateral acceleration sensor fault",
      "Steering angle sensor issue", "ABS module fault affecting stability system"],
     ["Read yaw rate and lateral G sensor data with scan tool",
      "Verify steering angle sensor is calibrated",
      "Check for wheel speed sensor codes — stability uses all 4",
      "Clear codes, drive in a circle — recheck for consistent readings"],
     related=["C0070", "C0131", "C0045"],
     difficulty="medium", cost="$100-$800",
     notes="After any yaw/lateral sensor replacement, recalibrate with factory tool. Drive in a circle pattern to verify.")



# ---------------------------------------------------------------------------
# Powertrain — Transmission Solenoids/Clutch Pressure (P0760-P0871)
# ---------------------------------------------------------------------------

_add("P0760", "high", "Shift solenoid C malfunction — harsh or no shifts",
     ["Shift solenoid C failed internally", "Wiring open/short to solenoid C",
      "Trans connector pin corroded or bent", "Low/contaminated trans fluid"],
     ["Check trans fluid level and condition first",
      "Measure solenoid C resistance at connector (~20-30Ω typical)",
      "Command solenoid on/off with scan tool and listen for click",
      "Inspect trans connector for ATF contamination or bent pins"],
     related=["P0761", "P0762", "P0763"],
     difficulty="hard", cost="$150-$2000",
     notes="Solenoid C typically controls 3rd/4th gear on many transmissions.")

_add("P0761", "high", "Shift solenoid C stuck off — gear ratio errors",
     ["Solenoid C mechanically stuck", "Valve body bore worn",
      "Debris in valve body blocking solenoid travel", "Internal trans wiring fault"],
     ["Monitor solenoid commanded state vs actual shift behavior",
      "Drop valve body and inspect solenoid — check for debris",
      "Check internal trans harness for damage",
      "Flush transmission if fluid is contaminated"],
     related=["P0760", "P0762", "P0700"],
     difficulty="hard", cost="$300-$2500",
     notes="Often a valve body replacement resolves both P0761 and related solenoid codes.")

_add("P0762", "high", "Shift solenoid C stuck on — wrong gear engagement",
     ["Solenoid C stuck energized", "Short in solenoid circuit",
      "Valve body bore wear allowing bypass", "TCM driver fault"],
     ["Check solenoid resistance — shorted coil will read near 0Ω",
      "Inspect wiring for short to power",
      "Check valve body for wear or scoring",
      "Monitor TCM driver output with scope"],
     related=["P0760", "P0761", "P0763"],
     difficulty="hard", cost="$300-$2500")

_add("P0763", "high", "Shift solenoid C electrical — circuit malfunction",
     ["Solenoid C wiring open or shorted", "Connector pin damage",
      "Solenoid coil failed", "TCM output driver issue"],
     ["Measure solenoid resistance at TCM connector (20-30Ω typical)",
      "Check for power and ground at solenoid connector with key on",
      "Wiggle-test harness while monitoring for intermittent",
      "If wiring good, suspect TCM driver failure"],
     related=["P0760", "P0761", "P0762"],
     difficulty="hard", cost="$150-$2000")

_add("P0765", "high", "Shift solenoid D malfunction — incorrect shifting",
     ["Shift solenoid D failed", "Wiring fault to solenoid D",
      "Trans connector corrosion", "Contaminated trans fluid"],
     ["Check trans fluid condition — burnt/dark fluid indicates wear",
      "Measure solenoid D resistance at connector",
      "Check for DTCs in TCM — look for companion codes",
      "Inspect valve body if electrical checks pass"],
     related=["P0766", "P0760", "P0700"],
     difficulty="hard", cost="$150-$2000")

_add("P0766", "high", "Shift solenoid D stuck off — delayed or missing shifts",
     ["Solenoid D mechanically stuck closed", "Valve body bore wear",
      "Debris blocking solenoid", "Internal wiring damage"],
     ["Monitor solenoid commanded position vs actual gear ratio",
      "Drop valve body and inspect solenoid D",
      "Check for metal debris in pan — indicates internal wear",
      "Flush and refill trans fluid if contamination found"],
     related=["P0765", "P0700"],
     difficulty="hard", cost="$300-$2500")

_add("P0770", "medium", "Shift solenoid E malfunction — overdrive issues",
     ["Solenoid E failed (overdrive/lockup control)", "Wiring issue",
      "Connector corrosion at trans case", "Low trans fluid"],
     ["Check trans fluid level and condition",
      "Measure solenoid E resistance at connector",
      "Check for lockup shudder or flare on highway",
      "Command overdrive on/off with scan tool to verify function"],
     related=["P0771", "P0740", "P0700"],
     difficulty="hard", cost="$150-$2000")

_add("P0771", "medium", "Shift solenoid E stuck off — no overdrive/lockup",
     ["Solenoid E mechanically stuck", "Valve body issue",
      "Debris in solenoid bore", "Trans fluid breakdown"],
     ["Check for TCC engagement — monitor slip at highway speed",
      "Drop valve body and check solenoid E",
      "Inspect for debris in solenoid bore",
      "Replace valve body solenoid pack if multiple solenoid codes present"],
     related=["P0770", "P0741"],
     difficulty="hard", cost="$300-$2500")

_add("P0775", "high", "Pressure control solenoid B malfunction",
     ["PCS B solenoid failed", "Wiring fault", "Trans fluid contamination",
      "Valve body bore wear"],
     ["Check trans fluid level and condition",
      "Measure PCS B solenoid resistance (~5-15Ω for PWM type)",
      "Monitor line pressure with scan tool — compare to spec",
      "If electrical OK, valve body removal for inspection needed"],
     related=["P0776", "P0745", "P0700"],
     difficulty="hard", cost="$200-$2500",
     notes="Pressure control solenoids are pulse-width modulated — ohms alone won't confirm function.")

_add("P0776", "high", "Pressure control solenoid B performance — shift quality issues",
     ["PCS B solenoid sluggish or weak", "Valve body wear",
      "Trans fluid varnish buildup", "Internal leak past solenoid"],
     ["Monitor actual vs commanded line pressure",
      "Check for flare, harsh, or soft shifts during 2-3 and 3-4",
      "Perform trans fluid flush and retest",
      "Drop valve body and inspect PCS B solenoid and bore"],
     related=["P0775", "P0700"],
     difficulty="hard", cost="$300-$2500")

_add("P0780", "high", "Shift malfunction — TCM detects incorrect gear ratio",
     ["Internal clutch pack wear", "Multiple solenoid issues",
      "Low trans fluid or wrong fluid type", "Valve body wear"],
     ["Check trans fluid level and condition",
      "Scan for companion transmission codes",
      "Monitor gear ratio PIDs — compare actual vs commanded ratio",
      "If multiple codes present, internal overhaul likely needed"],
     related=["P0700", "P0730", "P0731"],
     difficulty="hard", cost="$500-$3500",
     notes="P0780 is generic — always look at companion codes to narrow down which gear/clutch.")

_add("P0781", "high", "1-2 shift malfunction — slip or harsh 1-2 shift",
     ["1-2 clutch pack worn", "Shift solenoid stuck/weak",
      "Low trans fluid", "Valve body issue"],
     ["Check trans fluid level and condition",
      "Monitor 1-2 shift time and gear ratio during shift",
      "Check shift solenoid A/B commanded vs actual states",
      "Road test: note if shift is harsh, delayed, or slipping"],
     related=["P0780", "P0731", "P0750"],
     difficulty="hard", cost="$300-$3500")

_add("P0782", "high", "2-3 shift malfunction",
     ["2-3 clutch pack worn", "Solenoid sticking",
      "Valve body wear", "Incorrect trans fluid level"],
     ["Monitor gear ratio during 2-3 shift for flare/slip",
      "Check shift solenoid states during 2-3 transition",
      "Check trans fluid — degraded fluid causes valve sticking",
      "If fluid service doesn't resolve, valve body or rebuild needed"],
     related=["P0780", "P0732", "P0760"],
     difficulty="hard", cost="$300-$3500")

_add("P0783", "high", "3-4 shift malfunction",
     ["3-4 clutch pack worn", "Solenoid C or D issue",
      "Valve body bore wear", "Trans fluid varnish"],
     ["Monitor gear ratio during 3-4 shift",
      "Check solenoid C/D operation with scan tool",
      "Perform adaptive reset after fluid service",
      "Internal repair if clutch pack proven worn"],
     related=["P0780", "P0733", "P0760"],
     difficulty="hard", cost="$300-$3500")

_add("P0784", "high", "4-5 shift malfunction (5+ speed transmissions)",
     ["Overdrive clutch pack worn", "Solenoid E issue",
      "Valve body wear", "Contaminated trans fluid"],
     ["Monitor gear ratio during 4-5 shift",
      "Check solenoid E operation and resistance",
      "Check for TCC codes — TCC and OD share hydraulic circuits",
      "Road test at highway speeds in OD"],
     related=["P0780", "P0734", "P0770"],
     difficulty="hard", cost="$300-$3500")

_add("P0785", "high", "Shift timing solenoid malfunction — erratic shift timing",
     ["Shift timing solenoid failed", "Wiring or connector fault",
      "Valve body issue", "Trans fluid contamination"],
     ["Measure shift timing solenoid resistance",
      "Check solenoid connector for ATF contamination",
      "Monitor shift timing/quality with scan tool data",
      "Inspect valve body if electrical checks OK"],
     related=["P0786", "P0787", "P0788"],
     difficulty="hard", cost="$200-$2000")

_add("P0786", "medium", "Shift timing solenoid range/performance",
     ["Solenoid sluggish or intermittent", "Varnish buildup in bore",
      "Wiring intermittent", "Fluid degradation"],
     ["Road test monitoring shift quality metrics",
      "Check solenoid resistance hot and cold",
      "Flush trans fluid and retest",
      "If persistent, drop valve body for inspection"],
     related=["P0785", "P0787"],
     difficulty="hard", cost="$200-$2000")

_add("P0787", "high", "Shift timing solenoid low — circuit stuck low",
     ["Solenoid wiring shorted to ground", "Solenoid coil shorted internally",
      "TCM driver fault", "Connector water intrusion"],
     ["Check solenoid circuit for short to ground",
      "Measure solenoid resistance — very low reading indicates shorted coil",
      "Inspect connector for moisture/corrosion",
      "Check TCM output pin with multimeter"],
     related=["P0785", "P0788"],
     difficulty="hard", cost="$200-$2000")

_add("P0788", "high", "Shift timing solenoid high — circuit stuck high",
     ["Solenoid wiring open or shorted to power", "Solenoid coil open",
      "TCM driver issue", "Connector pin pushed back"],
     ["Measure solenoid resistance — open reading means coil failure",
      "Check wiring for open or short to B+",
      "Inspect connector pin tension and seating",
      "Check TCM pin for output"],
     related=["P0785", "P0787"],
     difficulty="hard", cost="$200-$2000")

_add("P0795", "high", "Pressure control solenoid C malfunction",
     ["PCS C solenoid failed", "Wiring fault to solenoid",
      "Valve body bore wear", "Trans fluid contamination"],
     ["Check trans fluid level and condition",
      "Measure PCS C resistance (~5-15Ω for PWM type)",
      "Monitor clutch apply pressures with scan tool",
      "Drop valve body if electrical tests pass"],
     related=["P0796", "P0797", "P0798"],
     difficulty="hard", cost="$200-$2500")

_add("P0796", "high", "Pressure control solenoid C performance — shift quality",
     ["PCS C sluggish", "Bore wear in valve body",
      "Fluid varnish restricting solenoid", "Internal leak past solenoid"],
     ["Monitor actual vs commanded pressure during shifts",
      "Check for flare or bind during specific gear changes",
      "Trans fluid flush and adaptive reset",
      "Valve body removal and inspection if not resolved"],
     related=["P0795", "P0797"],
     difficulty="hard", cost="$300-$2500")

_add("P0797", "high", "Pressure control solenoid C stuck off",
     ["PCS C mechanically stuck", "Wiring open circuit",
      "Solenoid bore blocked with debris", "Contaminated fluid"],
     ["Check PCS C circuit continuity from TCM to solenoid",
      "Command solenoid and monitor pressure response",
      "Drop valve body — inspect for debris or stuck solenoid",
      "Check trans pan for metal debris indicating internal wear"],
     related=["P0795", "P0798"],
     difficulty="hard", cost="$300-$2500")

_add("P0798", "high", "Pressure control solenoid C stuck on",
     ["PCS C solenoid stuck energized", "Short to power in wiring",
      "TCM driver shorted", "Valve body bore issue"],
     ["Check for short to power in PCS C circuit",
      "Measure solenoid resistance — look for short",
      "Monitor pressure — stuck-on PCS causes high pressure",
      "If wiring OK, suspect TCM or solenoid replacement"],
     related=["P0795", "P0797"],
     difficulty="hard", cost="$300-$2500")

_add("P0810", "high", "Clutch position control error (automated manual trans)",
     ["Clutch actuator motor failed", "Clutch position sensor fault",
      "Hydraulic clutch actuator leak", "TCM calibration issue"],
     ["Check clutch actuator operation — command with scan tool",
      "Check clutch position sensor signal voltage",
      "Inspect hydraulic lines for leaks if hydraulic actuator",
      "Attempt TCM adaptive reset / relearn"],
     related=["P0815", "P0816"],
     difficulty="hard", cost="$300-$2000",
     notes="Common on automated manual and dual-clutch transmissions (DCT/DSG).")

_add("P0815", "medium", "Upshift switch circuit malfunction",
     ["Upshift switch failed", "Wiring open/short", "Steering column connector issue",
      "Clockspring/spiral cable damaged (steering wheel-mounted controls)"],
     ["Check upshift switch for proper click and resistance change",
      "Check wiring continuity from switch to TCM",
      "Inspect steering column connectors",
      "Test switch with multimeter — should go low resistance when pressed"],
     related=["P0816", "P0810"],
     difficulty="easy", cost="$50-$400")

_add("P0816", "medium", "Downshift switch circuit malfunction",
     ["Downshift switch failed", "Wiring fault", "Connector corrosion",
      "Clockspring issue (steering wheel paddles)"],
     ["Check downshift switch for proper operation",
      "Measure switch circuit resistance",
      "Inspect steering wheel paddle connector",
      "Check clockspring if paddle-shift equipped"],
     related=["P0815", "P0810"],
     difficulty="easy", cost="$50-$400")

_add("P0820", "medium", "Gear lever X-Y position sensor circuit",
     ["Gear position sensor failed", "Wiring open or shorted",
      "Connector corrosion", "Shift linkage misadjusted"],
     ["Check gear position sensor connector for corrosion",
      "Measure sensor output voltages in each gear — compare to spec",
      "Check shift linkage adjustment",
      "Replace sensor if outputs erratic or missing"],
     related=["P0705", "P0706"],
     difficulty="medium", cost="$100-$500")

_add("P0825", "low", "Gear lever push-pull switch — manual mode switch fault",
     ["Push-pull switch failed", "Wiring issue",
      "Connector loose", "Shift knob switch mechanism broken"],
     ["Check switch operation with scan tool — monitor switch state PID",
      "Test switch with multimeter",
      "Inspect shift knob connector",
      "Replace switch assembly if faulty"],
     related=["P0820", "P0815"],
     difficulty="easy", cost="$50-$300")

_add("P0826", "low", "Up/down shift switch circuit — tiptronic mode",
     ["Up/down shift switch failed", "Wiring fault",
      "Connector issue", "Clock spring / spiral cable fault"],
     ["Monitor switch status PIDs with scan tool",
      "Check switch resistance changes when pressed",
      "Inspect connector and wiring for damage",
      "Replace switch or clockspring as needed"],
     related=["P0815", "P0816", "P0825"],
     difficulty="easy", cost="$50-$400")

_add("P0840", "high", "Transmission fluid pressure sensor/switch A circuit",
     ["Trans pressure sensor failed", "Wiring open/short",
      "Connector corrosion", "Low trans fluid level"],
     ["Check trans fluid level first",
      "Measure pressure sensor signal voltage — should vary with RPM/load",
      "Check connector for ATF contamination",
      "Compare sensor reading to actual line pressure (gauge test)"],
     related=["P0845", "P0700"],
     difficulty="medium", cost="$100-$400",
     notes="Many transmissions use internal pressure switches — access requires valve body removal.")

_add("P0845", "high", "Transmission fluid pressure sensor/switch B circuit",
     ["Pressure sensor B failed", "Wiring fault", "Connector corrosion",
      "Internal trans seal leak affecting pressure"],
     ["Check sensor B signal voltage",
      "Compare to sensor A reading — they should correlate",
      "Check connector for contamination",
      "Gauge-test actual line pressure at sensor B tap"],
     related=["P0840", "P0700"],
     difficulty="medium", cost="$100-$400")

_add("P0850", "medium", "Park/neutral position switch input circuit",
     ["PNP switch failed or misadjusted", "Wiring open/short",
      "Connector corroded", "Shift cable stretched"],
     ["Check PNP switch operation — monitor switch state in all positions",
      "Adjust PNP switch if adjustable",
      "Check shift cable for proper range of motion",
      "Replace PNP switch if not adjustable and reading wrong"],
     related=["P0705", "P0706"],
     difficulty="easy", cost="$50-$300",
     notes="A bad PNP switch can prevent starting if the PCM doesn't see Park or Neutral.")

_add("P0868", "high", "Transmission fluid pressure low",
     ["Trans fluid level low", "Trans fluid pump worn",
      "Internal seal leak", "Pressure regulator stuck/worn"],
     ["Check trans fluid level and condition — top off if low",
      "Monitor line pressure with scan tool and compare to spec",
      "Gauge-test line pressure at various RPMs",
      "If pressure low with full fluid, pump or internal leak suspected"],
     related=["P0869", "P0700"],
     difficulty="hard", cost="$200-$3500",
     notes="Low line pressure causes slipping and overheating — do not drive extensively.")

_add("P0869", "high", "Transmission fluid pressure high",
     ["Pressure regulator stuck closed", "Pressure control solenoid stuck on",
      "Valve body passages blocked", "TCM commanding excessive pressure"],
     ["Monitor commanded vs actual line pressure",
      "Check pressure control solenoid operation",
      "Check for debris in valve body passages",
      "Inspect pressure regulator valve for stuck/binding"],
     related=["P0868", "P0700"],
     difficulty="hard", cost="$200-$2500",
     notes="High line pressure causes harsh shifts and can damage clutch packs prematurely.")

_add("P0870", "high", "Transmission fluid pressure sensor/switch C circuit",
     ["Pressure sensor C failed", "Wiring fault",
      "Connector contaminated with ATF", "Sensor out of calibration"],
     ["Measure sensor C signal voltage and compare to spec",
      "Check connector for ATF seepage and corrosion",
      "Cross-reference with sensor A/B readings",
      "Replace sensor if signal erratic or missing"],
     related=["P0840", "P0845", "P0871"],
     difficulty="medium", cost="$100-$400")

_add("P0871", "high", "Transmission fluid pressure sensor/switch C range/performance",
     ["Sensor C reading out of expected range", "Intermittent wiring",
      "Internal pressure irregularity", "Sensor drift"],
     ["Compare sensor C reading under various conditions to spec",
      "Wiggle test wiring while monitoring signal",
      "Cross-reference with actual pressure gauge reading",
      "Replace sensor if readings don't correlate with actual pressure"],
     related=["P0870", "P0840"],
     difficulty="medium", cost="$100-$400")

# ---------------------------------------------------------------------------
# Powertrain — Enhanced/Manufacturer Specific (P2000-P2999)
# ---------------------------------------------------------------------------

_add("P2002", "medium", "Diesel particulate filter efficiency below threshold (Bank 1)",
     ["DPF clogged with soot/ash", "Failed DPF regeneration cycles",
      "DPF substrate cracked or melted", "Exhaust leak before DPF",
      "Pressure sensor hoses clogged"],
     ["Check DPF soot loading level with scan tool",
      "Attempt a forced regeneration",
      "Inspect DPF pressure sensor hoses for blockage",
      "Check for exhaust leaks before DPF",
      "If regen fails, DPF cleaning or replacement needed"],
     related=["P2463", "P244A"],
     difficulty="hard", cost="$300-$3000",
     notes="Frequent short trips prevent passive regen — highway driving helps burn off soot.")

_add("P2016", "medium", "Intake manifold runner position sensor/switch Bank 1 low",
     ["IMRC position sensor failed", "Wiring shorted to ground",
      "IMRC actuator stuck — sensor reads incorrectly", "Connector corrosion"],
     ["Check IMRC position sensor voltage at connector — should not be 0V",
      "Check wiring for short to ground",
      "Command IMRC actuator open/closed and monitor sensor",
      "Replace sensor or actuator as needed"],
     related=["P2017", "P2004", "P2006"],
     difficulty="medium", cost="$100-$500")

_add("P2017", "medium", "Intake manifold runner position sensor/switch Bank 1 high",
     ["IMRC position sensor circuit open", "Wiring open or shorted to 5V ref",
      "Sensor failed high", "Connector pin pushed back"],
     ["Check sensor voltage — stuck at 5V indicates open/high",
      "Check wiring for open circuit or short to reference",
      "Inspect connector pin seating",
      "Replace sensor if signal stays high"],
     related=["P2016", "P2004"],
     difficulty="medium", cost="$100-$500")

_add("P2067", "medium", "Fuel level sensor B circuit — incorrect fuel gauge reading",
     ["Fuel level sensor B failed", "Wiring open/short",
      "Fuel pump module connector corroded", "Fuel tank deformed"],
     ["Check fuel level sensor B resistance — compare to spec range",
      "Monitor sensor B PID while rocking vehicle (level should change)",
      "Inspect fuel pump module connector for corrosion",
      "Replace fuel level sender if resistance out of range"],
     related=["P2068", "P0461", "P0463"],
     difficulty="medium", cost="$100-$500")

_add("P2068", "medium", "Fuel level sensor B circuit low",
     ["Sensor B wiring shorted to ground", "Sensor float stuck at bottom",
      "Fuel pump module connector shorted", "Sensor card worn through"],
     ["Check sensor B circuit for short to ground",
      "Measure resistance at fuel pump connector — 0Ω = short",
      "Inspect fuel sender unit for stuck float",
      "Replace fuel level sender assembly"],
     related=["P2067", "P2069"],
     difficulty="medium", cost="$100-$500")

_add("P2069", "medium", "Fuel level sensor B circuit high",
     ["Sensor B wiring open", "Connector disconnected or corroded",
      "Sensor float stuck at top", "Ground circuit fault"],
     ["Check sensor B circuit continuity",
      "Check connector at tank — corrosion is common",
      "Measure resistance — open reading means wiring or sensor",
      "Check ground circuit for fuel pump module"],
     related=["P2067", "P2068"],
     difficulty="medium", cost="$100-$500")

_add("P2070", "medium", "Intake manifold tuning valve stuck open (Bank 2)",
     ["IMTV actuator stuck open", "Vacuum line cracked/disconnected",
      "Actuator diaphragm ruptured", "Carbon buildup on valve"],
     ["Check vacuum supply to IMTV actuator",
      "Apply vacuum to actuator — should hold and valve should close",
      "Inspect vacuum hose for cracks",
      "Clean or replace IMTV actuator"],
     related=["P2071", "P2004"],
     difficulty="medium", cost="$100-$500")

_add("P2071", "medium", "Intake manifold tuning valve stuck closed (Bank 2)",
     ["IMTV actuator stuck closed", "Vacuum actuator seized",
      "Carbon buildup causing binding", "Control solenoid fault"],
     ["Check IMTV solenoid operation — command with scan tool",
      "Inspect actuator for seized/stuck condition",
      "Clean carbon from valve plates",
      "Replace actuator if physically stuck"],
     related=["P2070", "P2006"],
     difficulty="medium", cost="$100-$500")

_add("P2072", "medium", "Electronic throttle control — engine idle speed too low on decel",
     ["Throttle body carbon buildup", "Idle air control issue",
      "Vacuum leak", "PCM calibration needs update"],
     ["Clean throttle body bore and plate",
      "Check for vacuum leaks — smoke test",
      "Perform idle relearn procedure after cleaning",
      "Check for PCM TSB/calibration update"],
     related=["P2073", "P2111", "P0506"],
     difficulty="easy", cost="$50-$300")

_add("P2073", "medium", "Manifold absolute pressure / mass air flow correlation — high airflow",
     ["Vacuum leak downstream of MAF", "MAF sensor reading too high",
      "MAP sensor inaccurate", "Intake gasket leak"],
     ["Compare MAF and MAP readings at idle — look for mismatch",
      "Check for intake leaks with propane or smoke test",
      "Clean or replace MAF sensor",
      "Check MAP sensor against known-good barometric pressure at KOEO"],
     related=["P2074", "P0101", "P0106"],
     difficulty="medium", cost="$50-$400")

_add("P2074", "medium", "MAP/MAF correlation — low airflow at idle",
     ["MAF sensor contaminated (reading low)", "Restricted air filter",
      "MAP sensor offset", "Exhaust restriction (clogged cat)"],
     ["Check air filter condition",
      "Clean MAF sensor with MAF cleaner",
      "Compare MAF g/s at idle to spec (3-5 g/s typical)",
      "Check exhaust backpressure if MAF reads OK"],
     related=["P2073", "P0101"],
     difficulty="easy", cost="$20-$400")

_add("P2075", "medium", "Intake manifold tuning valve position sensor/switch circuit",
     ["IMTV position sensor failed", "Wiring open/short",
      "Connector corroded", "Actuator not moving (sensor reads static)"],
     ["Check IMTV sensor voltage with key on",
      "Command actuator open/close and watch sensor change",
      "Check wiring and connector for damage",
      "Replace sensor or actuator assembly as needed"],
     related=["P2070", "P2071", "P2076"],
     difficulty="medium", cost="$100-$500")

_add("P2076", "medium", "Intake manifold tuning valve position not yet learned",
     ["IMTV relearn not performed after replacement", "Battery disconnect during relearn",
      "Actuator fault preventing relearn", "PCM issue"],
     ["Perform IMTV position relearn with scan tool",
      "Ensure battery is fully charged during relearn",
      "Verify actuator moves freely before attempting relearn",
      "If relearn fails, check for actuator fault codes"],
     related=["P2075", "P2070"],
     difficulty="easy", cost="$0-$150",
     notes="This code often clears after successful relearn — no parts needed.")

_add("P2077", "medium", "Intake manifold tuning valve position not reached",
     ["IMTV actuator weak or sticking", "Vacuum supply insufficient",
      "Carbon buildup restricting valve travel", "Linkage bent or broken"],
     ["Command IMTV and watch position sensor — does it reach target?",
      "Check vacuum supply to actuator",
      "Clean carbon from valve plates and bore",
      "Inspect linkage for damage"],
     related=["P2075", "P2076", "P2070"],
     difficulty="medium", cost="$100-$500")

_add("P2078", "medium", "MAP/MAF — throttle position correlation at higher load",
     ["Vacuum leak that worsens under load", "MAF sensor inaccurate at high flow",
      "Throttle position sensor drift", "Intake manifold gasket leak"],
     ["Road test monitoring MAF, MAP, and TP PIDs under acceleration",
      "Check for intake leaks — smoke test at idle and with applied vacuum",
      "Compare MAF reading at WOT to expected value for engine size",
      "Check TPS signal for smooth sweep — no dropouts"],
     related=["P2073", "P2074"],
     difficulty="medium", cost="$50-$500")

_add("P2098", "medium", "Post catalyst fuel trim too lean (Bank 2)",
     ["Exhaust leak near Bank 2 rear O2 sensor", "Rear O2 sensor (Bank 2) failed",
      "Catalytic converter inefficient (Bank 2)", "Fuel injector issue on Bank 2"],
     ["Check for exhaust leaks near Bank 2 downstream O2",
      "Monitor Bank 2 rear O2 sensor signal — should be relatively stable",
      "Compare Bank 2 fuel trims to Bank 1",
      "If cat is suspect, check cat efficiency with scan tool"],
     related=["P2099", "P2096", "P0420"],
     difficulty="medium", cost="$100-$1500")

_add("P2099", "medium", "Post catalyst fuel trim too rich (Bank 2)",
     ["Rear O2 sensor (Bank 2) biased rich", "Catalytic converter failing (Bank 2)",
      "Fuel injector leaking on Bank 2 cylinder", "EVAP purge issue"],
     ["Monitor Bank 2 rear O2 voltage — should stay around 0.6-0.7V",
      "Check for rich exhaust smell from Bank 2",
      "Compare Bank 2 LTFT to Bank 1",
      "Inspect Bank 2 injectors for leaking (fuel pressure drop test)"],
     related=["P2098", "P2097", "P0430"],
     difficulty="medium", cost="$100-$1500")

_add("P2103", "high", "Throttle actuator control motor circuit high — limp mode risk",
     ["Throttle body motor circuit shorted to power", "Wiring insulation damage",
      "Throttle body failure", "PCM driver issue"],
     ["Check throttle body motor connector — disconnect and check for voltage",
      "Inspect wiring for chafing/short to B+",
      "Measure motor winding resistance (typically 2-10Ω)",
      "Replace throttle body if wiring is intact"],
     related=["P2100", "P2101", "P2104"],
     difficulty="medium", cost="$200-$700")

_add("P2104", "high", "Throttle actuator control system — forced idle, safety mode",
     ["Multiple ETC faults causing PCM to default to idle",
      "Throttle body motor failure", "APP sensor disagreement",
      "Wiring harness damage near throttle body"],
     ["Check for companion ETC codes (P2100-P2112, P2135, P2138)",
      "Address root cause codes first — P2104 is usually a result code",
      "Check APP sensor correlation",
      "Check throttle body wiring — look for intermittent loose connections"],
     related=["P2100", "P2101", "P2105"],
     difficulty="medium", cost="$200-$800",
     notes="P2104 is often set alongside other ETC codes — fix the root cause code first.")

_add("P2105", "high", "Throttle actuator control system — forced engine shutdown",
     ["Critical ETC failure — PCM shuts engine down for safety",
      "Throttle stuck open with no TPS feedback",
      "APP and TPS completely disagree", "PCM internal fault"],
     ["This is a critical safety code — do NOT clear and drive",
      "Check for companion ETC codes",
      "Inspect throttle body — can it be commanded closed?",
      "Check APP sensors and TPS for signal",
      "PCM may need replacement if internal fault confirmed"],
     related=["P2104", "P2100", "P2106"],
     difficulty="hard", cost="$200-$1200",
     notes="Engine shutdown code — tow the vehicle, do not attempt to drive.")

_add("P2107", "high", "Throttle actuator control module processor — internal PCM fault",
     ["PCM internal processor error", "PCM power/ground issue",
      "Corrupted PCM software", "PCM hardware failure"],
     ["Check PCM power and ground circuits first",
      "Attempt PCM reflash/reprogramming",
      "Check for TSBs related to PCM software update",
      "If reflash fails, PCM replacement needed"],
     related=["P2106", "P2100"],
     difficulty="hard", cost="$300-$1200")

_add("P2108", "high", "Throttle actuator control module performance",
     ["PCM throttle control processor degraded", "Throttle response too slow",
      "Internal PCM calibration error", "Voltage supply issue to PCM"],
     ["Check PCM power supply voltage (battery and ignition feeds)",
      "Monitor throttle response time — commanded vs actual position",
      "Check for PCM reflash/update availability",
      "Replace PCM if performance doesn't improve after reflash"],
     related=["P2107", "P2100"],
     difficulty="hard", cost="$300-$1200")

_add("P2122", "critical", "Throttle/pedal position sensor D circuit low — limp mode",
     ["APP sensor D failed", "Wiring shorted to ground",
      "Connector pin corrosion", "Accelerator pedal assembly failure"],
     ["Check APP sensor D voltage — should be ~0.5V at rest",
      "Check wiring for short to ground",
      "Inspect accelerator pedal connector for corrosion or damage",
      "Replace accelerator pedal position sensor assembly if faulty"],
     related=["P2123", "P2125", "P2138"],
     difficulty="medium", cost="$100-$400",
     notes="APP sensors are non-serviceable — replace the entire pedal assembly.")

_add("P2123", "critical", "Throttle/pedal position sensor D circuit high — limp mode",
     ["APP sensor D circuit open", "Wiring open or shorted to 5V ref",
      "Connector disconnected", "Sensor internal failure"],
     ["Check APP sensor D voltage — stuck at 5V = open circuit",
      "Check wiring for open or short to reference voltage",
      "Inspect connector — pushed back pin or disconnected",
      "Replace accelerator pedal assembly"],
     related=["P2122", "P2125", "P2138"],
     difficulty="medium", cost="$100-$400")

_add("P2125", "critical", "Throttle/pedal position sensor E circuit low — limp mode",
     ["APP sensor E failed low", "Wiring shorted to ground",
      "Connector corrosion", "Pedal assembly failure"],
     ["Check APP sensor E voltage — should be ~1.0V at rest (2× sensor D)",
      "Check for short to ground in sensor E circuit",
      "Inspect pedal assembly connector",
      "Replace accelerator pedal assembly"],
     related=["P2122", "P2127", "P2138"],
     difficulty="medium", cost="$100-$400")

_add("P2127", "critical", "Throttle/pedal position sensor E circuit low input",
     ["APP sensor E circuit shorted low", "Wiring short to ground",
      "5V reference lost to sensor E", "Pedal assembly internal fault"],
     ["Check APP sensor E voltage at connector",
      "Verify 5V reference present at sensor E",
      "Check wiring for short to ground between PCM and sensor",
      "Replace pedal assembly if sensor or reference is bad"],
     related=["P2128", "P2125", "P2138"],
     difficulty="medium", cost="$100-$400")

_add("P2128", "critical", "Throttle/pedal position sensor E circuit high input",
     ["APP sensor E circuit open or shorted high", "Wiring open",
      "Connector pin backed out", "Sensor internal failure"],
     ["Check APP sensor E voltage — stuck at 5V indicates open/high",
      "Check wiring for open circuit",
      "Inspect connector for backed out pin",
      "Replace accelerator pedal assembly"],
     related=["P2127", "P2125", "P2138"],
     difficulty="medium", cost="$100-$400")

_add("P2130", "critical", "Throttle/pedal position sensor F circuit malfunction",
     ["APP sensor F failed", "Wiring open/short",
      "Connector corrosion", "Pedal assembly internal failure"],
     ["Check APP sensor F voltage and compare to sensors D and E",
      "Sensors should track proportionally — if F disagrees, sensor is bad",
      "Check wiring and connector for damage",
      "Replace accelerator pedal assembly"],
     related=["P2131", "P2138"],
     difficulty="medium", cost="$100-$400")

_add("P2131", "critical", "Throttle/pedal position sensor F circuit range/performance",
     ["APP sensor F reading out of expected range vs D/E",
      "Intermittent wiring issue", "Partial sensor failure",
      "Connector contact resistance"],
     ["Compare sensor F tracking against D and E at various positions",
      "Wiggle-test pedal and wiring while monitoring all 3 sensors",
      "Check connector pin tension",
      "Replace pedal assembly if sensor F drifts out of range"],
     related=["P2130", "P2138"],
     difficulty="medium", cost="$100-$400")

_add("P2133", "critical", "Throttle/pedal position sensor F circuit high — limp mode",
     ["APP sensor F open circuit", "Wiring open or short to reference",
      "Connector pin issue", "Sensor internal failure"],
     ["Check sensor F voltage — stuck high indicates open",
      "Check wiring continuity from PCM to sensor F",
      "Inspect connector for damage or backed-out pins",
      "Replace accelerator pedal assembly"],
     related=["P2134", "P2130", "P2138"],
     difficulty="medium", cost="$100-$400")

_add("P2134", "critical", "Throttle/pedal position sensor F circuit low — limp mode",
     ["APP sensor F shorted to ground", "Wiring short to ground",
      "Connector water intrusion", "Sensor failed low"],
     ["Check sensor F voltage — near 0V confirms low circuit",
      "Check wiring for short to ground",
      "Inspect connector for moisture/corrosion — floor mat can push water into pedal connector",
      "Replace accelerator pedal assembly"],
     related=["P2133", "P2130", "P2138"],
     difficulty="medium", cost="$100-$400",
     notes="Water intrusion at the pedal connector is common — check floor for leaks.")

_add("P2176", "low", "Throttle actuator control — idle position not learned",
     ["Throttle body replaced without relearn", "Battery disconnect during relearn",
      "Throttle body too dirty for valid relearn", "PCM update needed"],
     ["Clean throttle body bore and plate first",
      "Perform throttle body relearn with scan tool",
      "Ensure battery voltage >12V during relearn procedure",
      "If relearn keeps failing, replace throttle body"],
     related=["P2111", "P2112", "P2119"],
     difficulty="easy", cost="$0-$300",
     notes="Most vehicles require a specific relearn procedure — check service info.")

_add("P2177", "medium", "System too lean off idle (Bank 1) — lean under load",
     ["Vacuum leak that worsens under load", "Weak fuel pump — low pressure under demand",
      "Clogged fuel injector", "Intake manifold gasket leak"],
     ["Check fuel pressure at idle and under load (WOT snap test)",
      "Smoke test for vacuum/intake leaks",
      "Check fuel injector balance test",
      "Monitor STFT and LTFT under acceleration — lean spike = supply issue"],
     related=["P2178", "P0171", "P2187"],
     difficulty="medium", cost="$100-$800",
     notes="Unlike P0171 (overall lean), P2177 specifically triggers off-idle — suspect fuel delivery.")

_add("P2178", "medium", "System too rich off idle (Bank 1) — rich under load",
     ["Fuel injector leaking", "Fuel pressure regulator stuck high",
      "EVAP purge valve stuck open", "MAF sensor reading low (PCM adds too much fuel)"],
     ["Check fuel pressure — high pressure = regulator issue",
      "Check EVAP purge valve — disconnect and retest",
      "Monitor fuel trims off-idle — negative LTFT = rich",
      "Test MAF sensor accuracy at various airflows"],
     related=["P2177", "P0172", "P2188"],
     difficulty="medium", cost="$100-$800")

_add("P2179", "medium", "System too lean off idle (Bank 2)",
     ["Vacuum leak on Bank 2 side", "Fuel injector clogged (Bank 2)",
      "Weak fuel pump under demand", "Intake gasket leak Bank 2"],
     ["Smoke test concentrating on Bank 2 intake",
      "Check fuel pressure under load",
      "Fuel injector balance test — compare Bank 2 flow",
      "Compare Bank 2 trims to Bank 1 — Bank 2 only = local issue"],
     related=["P2177", "P0174", "P2189"],
     difficulty="medium", cost="$100-$800")

_add("P2187", "medium", "System too lean at idle (Bank 1)",
     ["Vacuum leak near idle air path", "PCV valve stuck open",
      "Brake booster hose leaking", "Intake gasket leak at idle port"],
     ["Smoke test at idle — concentrate on idle air circuit",
      "Check PCV valve and hoses",
      "Check brake booster hose for leak (hissing/RPM change)",
      "Monitor STFT at idle — high positive = lean"],
     related=["P2188", "P0171", "P2177"],
     difficulty="easy", cost="$50-$500",
     notes="P2187 is lean AT IDLE specifically — most often a small vacuum leak near the throttle body.")

_add("P2188", "medium", "System too rich at idle (Bank 1)",
     ["Fuel injector leaking (dripping at idle)", "Fuel pressure regulator leaking into vacuum line",
      "EVAP purge solenoid stuck open", "Faulty O2 sensor biasing rich"],
     ["Check for fuel in vacuum line at fuel pressure regulator",
      "Pull EVAP purge hose at idle — RPM change = purge stuck open",
      "Check fuel pressure at idle — should be per spec",
      "Injector leak-down test — pressure should hold 5+ minutes"],
     related=["P2187", "P0172", "P2178"],
     difficulty="medium", cost="$100-$600")

_add("P2189", "medium", "System too rich at idle (Bank 2)",
     ["Fuel injector leaking on Bank 2", "Fuel pressure regulator fault",
      "EVAP purge issue", "Bank 2 O2 sensor fault"],
     ["Perform fuel injector leak-down test",
      "Compare Bank 2 idle trims to Bank 1",
      "Check for fuel odor from Bank 2 exhaust",
      "Inspect Bank 2 injectors for visible fuel drip (engine off, key on)"],
     related=["P2188", "P0175", "P2179"],
     difficulty="medium", cost="$100-$600")

_add("P2190", "medium", "System too lean at idle (Bank 2)",
     ["Vacuum leak on Bank 2 intake", "Intake gasket leak Bank 2 side",
      "PCV hose leak on Bank 2", "Idle air leak near Bank 2 runners"],
     ["Smoke test Bank 2 intake runners and gaskets",
      "Check PCV system components on Bank 2 side",
      "Compare Bank 2 trims at idle to Bank 1",
      "Spray propane around Bank 2 intake — RPM rise = leak location"],
     related=["P2187", "P0174", "P2191"],
     difficulty="easy", cost="$50-$500")

_add("P2191", "medium", "System too lean at wide open throttle (Bank 2)",
     ["Fuel pump weak under high demand", "Fuel filter restricted",
      "Fuel injector clogged on Bank 2", "Fuel supply line restricted"],
     ["Check fuel pressure under WOT — pressure should not drop",
      "Check fuel filter for restriction (if serviceable)",
      "Fuel injector flow test on Bank 2",
      "Check fuel supply line for kink or restriction"],
     related=["P2179", "P2190", "P0174"],
     difficulty="medium", cost="$100-$800")

_add("P2197", "medium", "O2 sensor signal biased/stuck lean (Bank 2 Sensor 1)",
     ["Bank 2 upstream O2 sensor failed — reads lean",
      "Exhaust leak near Bank 2 sensor 1", "Wiring open in sensor circuit",
      "Sensor contaminated with coolant (head gasket leak)"],
     ["Monitor Bank 2 sensor 1 signal — should oscillate 0.1-0.9V",
      "If stuck low/near 0V, check for exhaust leak at manifold",
      "Snap throttle — sensor should respond quickly to rich command",
      "Check for white smoke/coolant loss indicating head gasket"],
     related=["P2198", "P2195", "P0174"],
     difficulty="medium", cost="$100-$400")

_add("P2198", "medium", "O2 sensor signal biased/stuck rich (Bank 2 Sensor 1)",
     ["Bank 2 upstream O2 sensor failed — reads rich",
      "Fuel injector leaking on Bank 2", "EVAP purge affecting Bank 2",
      "Sensor contaminated with silicone (RTV sealant)"],
     ["Monitor Bank 2 sensor 1 — stuck high/near 0.9V = biased rich",
      "Command fuel cut and watch sensor — should drop to 0V",
      "Check Bank 2 injectors for leaking",
      "Check for silicone contamination (recent gasket work with RTV?)"],
     related=["P2197", "P2196", "P0175"],
     difficulty="medium", cost="$100-$400")

_add("P2270", "low", "O2 sensor signal biased/stuck lean (Bank 1 Sensor 2)",
     ["Downstream O2 sensor (Bank 1) failed lean", "Exhaust leak near rear sensor",
      "Wiring issue in sensor circuit", "Catalytic converter inefficient"],
     ["Monitor Bank 1 sensor 2 — should be relatively steady ~0.6-0.7V",
      "If reading low, check for exhaust leak at cat-to-pipe joint",
      "Check sensor connector for corrosion",
      "Compare upstream vs downstream — downstream flat low may indicate bad cat"],
     related=["P2271", "P0420"],
     difficulty="easy", cost="$80-$300")

_add("P2271", "low", "O2 sensor signal biased/stuck rich (Bank 1 Sensor 2)",
     ["Downstream O2 sensor (Bank 1) failed rich", "Sensor contaminated",
      "Wiring short to voltage source", "Cat efficiency issue"],
     ["Monitor Bank 1 sensor 2 — stuck near 0.8-0.9V = biased rich",
      "Check sensor signal wire for short to B+ or reference",
      "Check for oil/coolant contamination at sensor tip",
      "Replace sensor and retest cat monitor readiness"],
     related=["P2270", "P0420"],
     difficulty="easy", cost="$80-$300")

_add("P2272", "low", "O2 sensor signal biased/stuck lean (Bank 2 Sensor 2)",
     ["Downstream O2 sensor (Bank 2) failed lean", "Exhaust leak at rear joint",
      "Sensor wiring open", "Cat losing efficiency (Bank 2)"],
     ["Monitor Bank 2 sensor 2 signal",
      "Check for exhaust leaks near catalyst outlet",
      "Inspect sensor connector and wiring",
      "Replace sensor and run catalyst monitor to completion"],
     related=["P2273", "P0430"],
     difficulty="easy", cost="$80-$300")

_add("P2273", "low", "O2 sensor signal biased/stuck rich (Bank 2 Sensor 2)",
     ["Downstream O2 sensor (Bank 2) failed rich", "Sensor contaminated",
      "Wiring issue", "Catalytic converter issue (Bank 2)"],
     ["Monitor Bank 2 sensor 2 — stuck near 0.9V = biased rich",
      "Check sensor connector for contamination or shorts",
      "Replace sensor and retest",
      "If code returns with new sensor, investigate cat efficiency"],
     related=["P2272", "P0430"],
     difficulty="easy", cost="$80-$300")

_add("P2274", "low", "O2 sensor signal biased/stuck lean negative current (Bank 2 Sensor 2)",
     ["Wideband/AF sensor aging (Bank 2 downstream)", "Sensor heater degraded",
      "Exhaust leak near sensor", "Wiring resistance too high"],
     ["Monitor sensor negative current reading with scan tool",
      "Check sensor heater operation (resistance and current draw)",
      "Check wiring resistance — should be <5Ω end-to-end",
      "Replace sensor if readings are inconsistent"],
     related=["P2272", "P2273", "P0430"],
     difficulty="easy", cost="$100-$350")

_add("P2279", "medium", "Intake air system leak — unmetered air entering engine",
     ["Vacuum hose cracked or disconnected", "Intake boot torn",
      "Intake manifold gasket leak", "PCV system leak",
      "Brake booster vacuum hose leaking"],
     ["Smoke test intake system for leaks",
      "Check intake boot/hose from MAF to throttle body for cracks",
      "Check PCV valve and hoses",
      "Check brake booster hose for vacuum leak",
      "Monitor MAF vs MAP correlation — mismatch indicates unmetered air"],
     related=["P2280", "P0171", "P0174"],
     difficulty="easy", cost="$20-$300",
     notes="This is a generic unmetered air code — the leak is between MAF and intake valves.")

_add("P2280", "medium", "Air flow restriction between air filter and MAF",
     ["Air filter severely clogged", "Airbox lid not sealed properly",
      "Aftermarket air filter not seating correctly", "Debris in air intake duct"],
     ["Check air filter condition — replace if dirty/clogged",
      "Ensure airbox lid is fully sealed and latched",
      "Inspect intake duct for debris or collapsed section",
      "If aftermarket filter, check for proper fit and seal"],
     related=["P2279", "P0101", "P0100"],
     difficulty="easy", cost="$15-$100",
     notes="Often just a dirty air filter — easiest fix in the book.")



# ---------------------------------------------------------------------------
# Powertrain — Transmission Solenoids/Clutch Pressure (P0760-P0871)
# ---------------------------------------------------------------------------

_add("P0760", "high", "Shift solenoid C malfunction — harsh or no shifts",
     ["Shift solenoid C failed internally", "Wiring open/short to solenoid C",
      "Trans connector pin corroded or bent", "Low/contaminated trans fluid"],
     ["Check trans fluid level and condition first",
      "Measure solenoid C resistance at connector (~20-30Ω typical)",
      "Command solenoid on/off with scan tool and listen for click",
      "Inspect trans connector for ATF contamination or bent pins"],
     related=["P0761", "P0762", "P0763"],
     difficulty="hard", cost="$150-$2000",
     notes="Solenoid C typically controls 3rd/4th gear on many transmissions.")

_add("P0761", "high", "Shift solenoid C stuck off — gear ratio errors",
     ["Solenoid C mechanically stuck", "Valve body bore worn",
      "Debris in valve body blocking solenoid travel", "Internal trans wiring fault"],
     ["Monitor solenoid commanded state vs actual shift behavior",
      "Drop valve body and inspect solenoid — check for debris",
      "Check internal trans harness for damage",
      "Flush transmission if fluid is contaminated"],
     related=["P0760", "P0762", "P0700"],
     difficulty="hard", cost="$300-$2500",
     notes="Often a valve body replacement resolves both P0761 and related solenoid codes.")

_add("P0762", "high", "Shift solenoid C stuck on — wrong gear engagement",
     ["Solenoid C stuck energized", "Short in solenoid circuit",
      "Valve body bore wear allowing bypass", "TCM driver fault"],
     ["Check solenoid resistance — shorted coil will read near 0Ω",
      "Inspect wiring for short to power",
      "Check valve body for wear or scoring",
      "Monitor TCM driver output with scope"],
     related=["P0760", "P0761", "P0763"],
     difficulty="hard", cost="$300-$2500")

_add("P0763", "high", "Shift solenoid C electrical — circuit malfunction",
     ["Solenoid C wiring open or shorted", "Connector pin damage",
      "Solenoid coil failed", "TCM output driver issue"],
     ["Measure solenoid resistance at TCM connector (20-30Ω typical)",
      "Check for power and ground at solenoid connector with key on",
      "Wiggle-test harness while monitoring for intermittent",
      "If wiring good, suspect TCM driver failure"],
     related=["P0760", "P0761", "P0762"],
     difficulty="hard", cost="$150-$2000")

_add("P0765", "high", "Shift solenoid D malfunction — incorrect shifting",
     ["Shift solenoid D failed", "Wiring fault to solenoid D",
      "Trans connector corrosion", "Contaminated trans fluid"],
     ["Check trans fluid condition — burnt/dark fluid indicates wear",
      "Measure solenoid D resistance at connector",
      "Check for DTCs in TCM — look for companion codes",
      "Inspect valve body if electrical checks pass"],
     related=["P0766", "P0760", "P0700"],
     difficulty="hard", cost="$150-$2000")

_add("P0766", "high", "Shift solenoid D stuck off — delayed or missing shifts",
     ["Solenoid D mechanically stuck closed", "Valve body bore wear",
      "Debris blocking solenoid", "Internal wiring damage"],
     ["Monitor solenoid commanded position vs actual gear ratio",
      "Drop valve body and inspect solenoid D",
      "Check for metal debris in pan — indicates internal wear",
      "Flush and refill trans fluid if contamination found"],
     related=["P0765", "P0700"],
     difficulty="hard", cost="$300-$2500")

_add("P0770", "medium", "Shift solenoid E malfunction — overdrive issues",
     ["Solenoid E failed (overdrive/lockup control)", "Wiring issue",
      "Connector corrosion at trans case", "Low trans fluid"],
     ["Check trans fluid level and condition",
      "Measure solenoid E resistance at connector",
      "Check for lockup shudder or flare on highway",
      "Command overdrive on/off with scan tool to verify function"],
     related=["P0771", "P0740", "P0700"],
     difficulty="hard", cost="$150-$2000")

_add("P0771", "medium", "Shift solenoid E stuck off — no overdrive/lockup",
     ["Solenoid E mechanically stuck", "Valve body issue",
      "Debris in solenoid bore", "Trans fluid breakdown"],
     ["Check for TCC engagement — monitor slip at highway speed",
      "Drop valve body and check solenoid E",
      "Inspect for debris in solenoid bore",
      "Replace valve body solenoid pack if multiple solenoid codes present"],
     related=["P0770", "P0741"],
     difficulty="hard", cost="$300-$2500")

_add("P0775", "high", "Pressure control solenoid B malfunction",
     ["PCS B solenoid failed", "Wiring fault", "Trans fluid contamination",
      "Valve body bore wear"],
     ["Check trans fluid level and condition",
      "Measure PCS B solenoid resistance (~5-15Ω for PWM type)",
      "Monitor line pressure with scan tool — compare to spec",
      "If electrical OK, valve body removal for inspection needed"],
     related=["P0776", "P0745", "P0700"],
     difficulty="hard", cost="$200-$2500",
     notes="Pressure control solenoids are pulse-width modulated — ohms alone won't confirm function.")

_add("P0776", "high", "Pressure control solenoid B performance — shift quality issues",
     ["PCS B solenoid sluggish or weak", "Valve body wear",
      "Trans fluid varnish buildup", "Internal leak past solenoid"],
     ["Monitor actual vs commanded line pressure",
      "Check for flare, harsh, or soft shifts during 2-3 and 3-4",
      "Perform trans fluid flush and retest",
      "Drop valve body and inspect PCS B solenoid and bore"],
     related=["P0775", "P0700"],
     difficulty="hard", cost="$300-$2500")

_add("P0780", "high", "Shift malfunction — TCM detects incorrect gear ratio",
     ["Internal clutch pack wear", "Multiple solenoid issues",
      "Low trans fluid or wrong fluid type", "Valve body wear"],
     ["Check trans fluid level and condition",
      "Scan for companion transmission codes",
      "Monitor gear ratio PIDs — compare actual vs commanded ratio",
      "If multiple codes present, internal overhaul likely needed"],
     related=["P0700", "P0730", "P0731"],
     difficulty="hard", cost="$500-$3500",
     notes="P0780 is generic — always look at companion codes to narrow down which gear/clutch.")

_add("P0781", "high", "1-2 shift malfunction — slip or harsh 1-2 shift",
     ["1-2 clutch pack worn", "Shift solenoid stuck/weak",
      "Low trans fluid", "Valve body issue"],
     ["Check trans fluid level and condition",
      "Monitor 1-2 shift time and gear ratio during shift",
      "Check shift solenoid A/B commanded vs actual states",
      "Road test: note if shift is harsh, delayed, or slipping"],
     related=["P0780", "P0731", "P0750"],
     difficulty="hard", cost="$300-$3500")

_add("P0782", "high", "2-3 shift malfunction",
     ["2-3 clutch pack worn", "Solenoid sticking",
      "Valve body wear", "Incorrect trans fluid level"],
     ["Monitor gear ratio during 2-3 shift for flare/slip",
      "Check shift solenoid states during 2-3 transition",
      "Check trans fluid — degraded fluid causes valve sticking",
      "If fluid service doesn't resolve, valve body or rebuild needed"],
     related=["P0780", "P0732", "P0760"],
     difficulty="hard", cost="$300-$3500")

_add("P0783", "high", "3-4 shift malfunction",
     ["3-4 clutch pack worn", "Solenoid C or D issue",
      "Valve body bore wear", "Trans fluid varnish"],
     ["Monitor gear ratio during 3-4 shift",
      "Check solenoid C/D operation with scan tool",
      "Perform adaptive reset after fluid service",
      "Internal repair if clutch pack proven worn"],
     related=["P0780", "P0733", "P0760"],
     difficulty="hard", cost="$300-$3500")

_add("P0784", "high", "4-5 shift malfunction (5+ speed transmissions)",
     ["Overdrive clutch pack worn", "Solenoid E issue",
      "Valve body wear", "Contaminated trans fluid"],
     ["Monitor gear ratio during 4-5 shift",
      "Check solenoid E operation and resistance",
      "Check for TCC codes — TCC and OD share hydraulic circuits",
      "Road test at highway speeds in OD"],
     related=["P0780", "P0734", "P0770"],
     difficulty="hard", cost="$300-$3500")

_add("P0785", "high", "Shift timing solenoid malfunction — erratic shift timing",
     ["Shift timing solenoid failed", "Wiring or connector fault",
      "Valve body issue", "Trans fluid contamination"],
     ["Measure shift timing solenoid resistance",
      "Check solenoid connector for ATF contamination",
      "Monitor shift timing/quality with scan tool data",
      "Inspect valve body if electrical checks OK"],
     related=["P0786", "P0787", "P0788"],
     difficulty="hard", cost="$200-$2000")

_add("P0786", "medium", "Shift timing solenoid range/performance",
     ["Solenoid sluggish or intermittent", "Varnish buildup in bore",
      "Wiring intermittent", "Fluid degradation"],
     ["Road test monitoring shift quality metrics",
      "Check solenoid resistance hot and cold",
      "Flush trans fluid and retest",
      "If persistent, drop valve body for inspection"],
     related=["P0785", "P0787"],
     difficulty="hard", cost="$200-$2000")

_add("P0787", "high", "Shift timing solenoid low — circuit stuck low",
     ["Solenoid wiring shorted to ground", "Solenoid coil shorted internally",
      "TCM driver fault", "Connector water intrusion"],
     ["Check solenoid circuit for short to ground",
      "Measure solenoid resistance — very low reading indicates shorted coil",
      "Inspect connector for moisture/corrosion",
      "Check TCM output pin with multimeter"],
     related=["P0785", "P0788"],
     difficulty="hard", cost="$200-$2000")

_add("P0788", "high", "Shift timing solenoid high — circuit stuck high",
     ["Solenoid wiring open or shorted to power", "Solenoid coil open",
      "TCM driver issue", "Connector pin pushed back"],
     ["Measure solenoid resistance — open reading means coil failure",
      "Check wiring for open or short to B+",
      "Inspect connector pin tension and seating",
      "Check TCM pin for output"],
     related=["P0785", "P0787"],
     difficulty="hard", cost="$200-$2000")

_add("P0795", "high", "Pressure control solenoid C malfunction",
     ["PCS C solenoid failed", "Wiring fault to solenoid",
      "Valve body bore wear", "Trans fluid contamination"],
     ["Check trans fluid level and condition",
      "Measure PCS C resistance (~5-15Ω for PWM type)",
      "Monitor clutch apply pressures with scan tool",
      "Drop valve body if electrical tests pass"],
     related=["P0796", "P0797", "P0798"],
     difficulty="hard", cost="$200-$2500")

_add("P0796", "high", "Pressure control solenoid C performance — shift quality",
     ["PCS C sluggish", "Bore wear in valve body",
      "Fluid varnish restricting solenoid", "Internal leak past solenoid"],
     ["Monitor actual vs commanded pressure during shifts",
      "Check for flare or bind during specific gear changes",
      "Trans fluid flush and adaptive reset",
      "Valve body removal and inspection if not resolved"],
     related=["P0795", "P0797"],
     difficulty="hard", cost="$300-$2500")

_add("P0797", "high", "Pressure control solenoid C stuck off",
     ["PCS C mechanically stuck", "Wiring open circuit",
      "Solenoid bore blocked with debris", "Contaminated fluid"],
     ["Check PCS C circuit continuity from TCM to solenoid",
      "Command solenoid and monitor pressure response",
      "Drop valve body — inspect for debris or stuck solenoid",
      "Check trans pan for metal debris indicating internal wear"],
     related=["P0795", "P0798"],
     difficulty="hard", cost="$300-$2500")

_add("P0798", "high", "Pressure control solenoid C stuck on",
     ["PCS C solenoid stuck energized", "Short to power in wiring",
      "TCM driver shorted", "Valve body bore issue"],
     ["Check for short to power in PCS C circuit",
      "Measure solenoid resistance — look for short",
      "Monitor pressure — stuck-on PCS causes high pressure",
      "If wiring OK, suspect TCM or solenoid replacement"],
     related=["P0795", "P0797"],
     difficulty="hard", cost="$300-$2500")

_add("P0810", "high", "Clutch position control error (automated manual trans)",
     ["Clutch actuator motor failed", "Clutch position sensor fault",
      "Hydraulic clutch actuator leak", "TCM calibration issue"],
     ["Check clutch actuator operation — command with scan tool",
      "Check clutch position sensor signal voltage",
      "Inspect hydraulic lines for leaks if hydraulic actuator",
      "Attempt TCM adaptive reset / relearn"],
     related=["P0815", "P0816"],
     difficulty="hard", cost="$300-$2000",
     notes="Common on automated manual and dual-clutch transmissions (DCT/DSG).")

_add("P0815", "medium", "Upshift switch circuit malfunction",
     ["Upshift switch failed", "Wiring open/short", "Steering column connector issue",
      "Clockspring/spiral cable damaged (steering wheel-mounted controls)"],
     ["Check upshift switch for proper click and resistance change",
      "Check wiring continuity from switch to TCM",
      "Inspect steering column connectors",
      "Test switch with multimeter — should go low resistance when pressed"],
     related=["P0816", "P0810"],
     difficulty="easy", cost="$50-$400")

_add("P0816", "medium", "Downshift switch circuit malfunction",
     ["Downshift switch failed", "Wiring fault", "Connector corrosion",
      "Clockspring issue (steering wheel paddles)"],
     ["Check downshift switch for proper operation",
      "Measure switch circuit resistance",
      "Inspect steering wheel paddle connector",
      "Check clockspring if paddle-shift equipped"],
     related=["P0815", "P0810"],
     difficulty="easy", cost="$50-$400")

_add("P0820", "medium", "Gear lever X-Y position sensor circuit",
     ["Gear position sensor failed", "Wiring open or shorted",
      "Connector corrosion", "Shift linkage misadjusted"],
     ["Check gear position sensor connector for corrosion",
      "Measure sensor output voltages in each gear — compare to spec",
      "Check shift linkage adjustment",
      "Replace sensor if outputs erratic or missing"],
     related=["P0705", "P0706"],
     difficulty="medium", cost="$100-$500")

_add("P0825", "low", "Gear lever push-pull switch — manual mode switch fault",
     ["Push-pull switch failed", "Wiring issue",
      "Connector loose", "Shift knob switch mechanism broken"],
     ["Check switch operation with scan tool — monitor switch state PID",
      "Test switch with multimeter",
      "Inspect shift knob connector",
      "Replace switch assembly if faulty"],
     related=["P0820", "P0815"],
     difficulty="easy", cost="$50-$300")

_add("P0826", "low", "Up/down shift switch circuit — tiptronic mode",
     ["Up/down shift switch failed", "Wiring fault",
      "Connector issue", "Clock spring / spiral cable fault"],
     ["Monitor switch status PIDs with scan tool",
      "Check switch resistance changes when pressed",
      "Inspect connector and wiring for damage",
      "Replace switch or clockspring as needed"],
     related=["P0815", "P0816", "P0825"],
     difficulty="easy", cost="$50-$400")

_add("P0840", "high", "Transmission fluid pressure sensor/switch A circuit",
     ["Trans pressure sensor failed", "Wiring open/short",
      "Connector corrosion", "Low trans fluid level"],
     ["Check trans fluid level first",
      "Measure pressure sensor signal voltage — should vary with RPM/load",
      "Check connector for ATF contamination",
      "Compare sensor reading to actual line pressure (gauge test)"],
     related=["P0845", "P0700"],
     difficulty="medium", cost="$100-$400",
     notes="Many transmissions use internal pressure switches — access requires valve body removal.")

_add("P0845", "high", "Transmission fluid pressure sensor/switch B circuit",
     ["Pressure sensor B failed", "Wiring fault", "Connector corrosion",
      "Internal trans seal leak affecting pressure"],
     ["Check sensor B signal voltage",
      "Compare to sensor A reading — they should correlate",
      "Check connector for contamination",
      "Gauge-test actual line pressure at sensor B tap"],
     related=["P0840", "P0700"],
     difficulty="medium", cost="$100-$400")

_add("P0850", "medium", "Park/neutral position switch input circuit",
     ["PNP switch failed or misadjusted", "Wiring open/short",
      "Connector corroded", "Shift cable stretched"],
     ["Check PNP switch operation — monitor switch state in all positions",
      "Adjust PNP switch if adjustable",
      "Check shift cable for proper range of motion",
      "Replace PNP switch if not adjustable and reading wrong"],
     related=["P0705", "P0706"],
     difficulty="easy", cost="$50-$300",
     notes="A bad PNP switch can prevent starting if the PCM doesn't see Park or Neutral.")

_add("P0868", "high", "Transmission fluid pressure low",
     ["Trans fluid level low", "Trans fluid pump worn",
      "Internal seal leak", "Pressure regulator stuck/worn"],
     ["Check trans fluid level and condition — top off if low",
      "Monitor line pressure with scan tool and compare to spec",
      "Gauge-test line pressure at various RPMs",
      "If pressure low with full fluid, pump or internal leak suspected"],
     related=["P0869", "P0700"],
     difficulty="hard", cost="$200-$3500",
     notes="Low line pressure causes slipping and overheating — do not drive extensively.")

_add("P0869", "high", "Transmission fluid pressure high",
     ["Pressure regulator stuck closed", "Pressure control solenoid stuck on",
      "Valve body passages blocked", "TCM commanding excessive pressure"],
     ["Monitor commanded vs actual line pressure",
      "Check pressure control solenoid operation",
      "Check for debris in valve body passages",
      "Inspect pressure regulator valve for stuck/binding"],
     related=["P0868", "P0700"],
     difficulty="hard", cost="$200-$2500",
     notes="High line pressure causes harsh shifts and can damage clutch packs prematurely.")

_add("P0870", "high", "Transmission fluid pressure sensor/switch C circuit",
     ["Pressure sensor C failed", "Wiring fault",
      "Connector contaminated with ATF", "Sensor out of calibration"],
     ["Measure sensor C signal voltage and compare to spec",
      "Check connector for ATF seepage and corrosion",
      "Cross-reference with sensor A/B readings",
      "Replace sensor if signal erratic or missing"],
     related=["P0840", "P0845", "P0871"],
     difficulty="medium", cost="$100-$400")

_add("P0871", "high", "Transmission fluid pressure sensor/switch C range/performance",
     ["Sensor C reading out of expected range", "Intermittent wiring",
      "Internal pressure irregularity", "Sensor drift"],
     ["Compare sensor C reading under various conditions to spec",
      "Wiggle test wiring while monitoring signal",
      "Cross-reference with actual pressure gauge reading",
      "Replace sensor if readings don't correlate with actual pressure"],
     related=["P0870", "P0840"],
     difficulty="medium", cost="$100-$400")

# ---------------------------------------------------------------------------
# Powertrain — Enhanced/Manufacturer Specific (P2000-P2999)
# ---------------------------------------------------------------------------

_add("P2002", "medium", "Diesel particulate filter efficiency below threshold (Bank 1)",
     ["DPF clogged with soot/ash", "Failed DPF regeneration cycles",
      "DPF substrate cracked or melted", "Exhaust leak before DPF",
      "Pressure sensor hoses clogged"],
     ["Check DPF soot loading level with scan tool",
      "Attempt a forced regeneration",
      "Inspect DPF pressure sensor hoses for blockage",
      "Check for exhaust leaks before DPF",
      "If regen fails, DPF cleaning or replacement needed"],
     related=["P2463", "P244A"],
     difficulty="hard", cost="$300-$3000",
     notes="Frequent short trips prevent passive regen — highway driving helps burn off soot.")

_add("P2016", "medium", "Intake manifold runner position sensor/switch Bank 1 low",
     ["IMRC position sensor failed", "Wiring shorted to ground",
      "IMRC actuator stuck — sensor reads incorrectly", "Connector corrosion"],
     ["Check IMRC position sensor voltage at connector — should not be 0V",
      "Check wiring for short to ground",
      "Command IMRC actuator open/closed and monitor sensor",
      "Replace sensor or actuator as needed"],
     related=["P2017", "P2004", "P2006"],
     difficulty="medium", cost="$100-$500")

_add("P2017", "medium", "Intake manifold runner position sensor/switch Bank 1 high",
     ["IMRC position sensor circuit open", "Wiring open or shorted to 5V ref",
      "Sensor failed high", "Connector pin pushed back"],
     ["Check sensor voltage — stuck at 5V indicates open/high",
      "Check wiring for open circuit or short to reference",
      "Inspect connector pin seating",
      "Replace sensor if signal stays high"],
     related=["P2016", "P2004"],
     difficulty="medium", cost="$100-$500")

_add("P2067", "medium", "Fuel level sensor B circuit — incorrect fuel gauge reading",
     ["Fuel level sensor B failed", "Wiring open/short",
      "Fuel pump module connector corroded", "Fuel tank deformed"],
     ["Check fuel level sensor B resistance — compare to spec range",
      "Monitor sensor B PID while rocking vehicle (level should change)",
      "Inspect fuel pump module connector for corrosion",
      "Replace fuel level sender if resistance out of range"],
     related=["P2068", "P0461", "P0463"],
     difficulty="medium", cost="$100-$500")

_add("P2068", "medium", "Fuel level sensor B circuit low",
     ["Sensor B wiring shorted to ground", "Sensor float stuck at bottom",
      "Fuel pump module connector shorted", "Sensor card worn through"],
     ["Check sensor B circuit for short to ground",
      "Measure resistance at fuel pump connector — 0Ω = short",
      "Inspect fuel sender unit for stuck float",
      "Replace fuel level sender assembly"],
     related=["P2067", "P2069"],
     difficulty="medium", cost="$100-$500")

_add("P2069", "medium", "Fuel level sensor B circuit high",
     ["Sensor B wiring open", "Connector disconnected or corroded",
      "Sensor float stuck at top", "Ground circuit fault"],
     ["Check sensor B circuit continuity",
      "Check connector at tank — corrosion is common",
      "Measure resistance — open reading means wiring or sensor",
      "Check ground circuit for fuel pump module"],
     related=["P2067", "P2068"],
     difficulty="medium", cost="$100-$500")

_add("P2070", "medium", "Intake manifold tuning valve stuck open (Bank 2)",
     ["IMTV actuator stuck open", "Vacuum line cracked/disconnected",
      "Actuator diaphragm ruptured", "Carbon buildup on valve"],
     ["Check vacuum supply to IMTV actuator",
      "Apply vacuum to actuator — should hold and valve should close",
      "Inspect vacuum hose for cracks",
      "Clean or replace IMTV actuator"],
     related=["P2071", "P2004"],
     difficulty="medium", cost="$100-$500")

_add("P2071", "medium", "Intake manifold tuning valve stuck closed (Bank 2)",
     ["IMTV actuator stuck closed", "Vacuum actuator seized",
      "Carbon buildup causing binding", "Control solenoid fault"],
     ["Check IMTV solenoid operation — command with scan tool",
      "Inspect actuator for seized/stuck condition",
      "Clean carbon from valve plates",
      "Replace actuator if physically stuck"],
     related=["P2070", "P2006"],
     difficulty="medium", cost="$100-$500")

_add("P2072", "medium", "Electronic throttle control — engine idle speed too low on decel",
     ["Throttle body carbon buildup", "Idle air control issue",
      "Vacuum leak", "PCM calibration needs update"],
     ["Clean throttle body bore and plate",
      "Check for vacuum leaks — smoke test",
      "Perform idle relearn procedure after cleaning",
      "Check for PCM TSB/calibration update"],
     related=["P2073", "P2111", "P0506"],
     difficulty="easy", cost="$50-$300")

_add("P2073", "medium", "Manifold absolute pressure / mass air flow correlation — high airflow",
     ["Vacuum leak downstream of MAF", "MAF sensor reading too high",
      "MAP sensor inaccurate", "Intake gasket leak"],
     ["Compare MAF and MAP readings at idle — look for mismatch",
      "Check for intake leaks with propane or smoke test",
      "Clean or replace MAF sensor",
      "Check MAP sensor against known-good barometric pressure at KOEO"],
     related=["P2074", "P0101", "P0106"],
     difficulty="medium", cost="$50-$400")

_add("P2074", "medium", "MAP/MAF correlation — low airflow at idle",
     ["MAF sensor contaminated (reading low)", "Restricted air filter",
      "MAP sensor offset", "Exhaust restriction (clogged cat)"],
     ["Check air filter condition",
      "Clean MAF sensor with MAF cleaner",
      "Compare MAF g/s at idle to spec (3-5 g/s typical)",
      "Check exhaust backpressure if MAF reads OK"],
     related=["P2073", "P0101"],
     difficulty="easy", cost="$20-$400")

_add("P2075", "medium", "Intake manifold tuning valve position sensor/switch circuit",
     ["IMTV position sensor failed", "Wiring open/short",
      "Connector corroded", "Actuator not moving (sensor reads static)"],
     ["Check IMTV sensor voltage with key on",
      "Command actuator open/close and watch sensor change",
      "Check wiring and connector for damage",
      "Replace sensor or actuator assembly as needed"],
     related=["P2070", "P2071", "P2076"],
     difficulty="medium", cost="$100-$500")

_add("P2076", "medium", "Intake manifold tuning valve position not yet learned",
     ["IMTV relearn not performed after replacement", "Battery disconnect during relearn",
      "Actuator fault preventing relearn", "PCM issue"],
     ["Perform IMTV position relearn with scan tool",
      "Ensure battery is fully charged during relearn",
      "Verify actuator moves freely before attempting relearn",
      "If relearn fails, check for actuator fault codes"],
     related=["P2075", "P2070"],
     difficulty="easy", cost="$0-$150",
     notes="This code often clears after successful relearn — no parts needed.")

_add("P2077", "medium", "Intake manifold tuning valve position not reached",
     ["IMTV actuator weak or sticking", "Vacuum supply insufficient",
      "Carbon buildup restricting valve travel", "Linkage bent or broken"],
     ["Command IMTV and watch position sensor — does it reach target?",
      "Check vacuum supply to actuator",
      "Clean carbon from valve plates and bore",
      "Inspect linkage for damage"],
     related=["P2075", "P2076", "P2070"],
     difficulty="medium", cost="$100-$500")

_add("P2078", "medium", "MAP/MAF — throttle position correlation at higher load",
     ["Vacuum leak that worsens under load", "MAF sensor inaccurate at high flow",
      "Throttle position sensor drift", "Intake manifold gasket leak"],
     ["Road test monitoring MAF, MAP, and TP PIDs under acceleration",
      "Check for intake leaks — smoke test at idle and with applied vacuum",
      "Compare MAF reading at WOT to expected value for engine size",
      "Check TPS signal for smooth sweep — no dropouts"],
     related=["P2073", "P2074"],
     difficulty="medium", cost="$50-$500")

_add("P2098", "medium", "Post catalyst fuel trim too lean (Bank 2)",
     ["Exhaust leak near Bank 2 rear O2 sensor", "Rear O2 sensor (Bank 2) failed",
      "Catalytic converter inefficient (Bank 2)", "Fuel injector issue on Bank 2"],
     ["Check for exhaust leaks near Bank 2 downstream O2",
      "Monitor Bank 2 rear O2 sensor signal — should be relatively stable",
      "Compare Bank 2 fuel trims to Bank 1",
      "If cat is suspect, check cat efficiency with scan tool"],
     related=["P2099", "P2096", "P0420"],
     difficulty="medium", cost="$100-$1500")

_add("P2099", "medium", "Post catalyst fuel trim too rich (Bank 2)",
     ["Rear O2 sensor (Bank 2) biased rich", "Catalytic converter failing (Bank 2)",
      "Fuel injector leaking on Bank 2 cylinder", "EVAP purge issue"],
     ["Monitor Bank 2 rear O2 voltage — should stay around 0.6-0.7V",
      "Check for rich exhaust smell from Bank 2",
      "Compare Bank 2 LTFT to Bank 1",
      "Inspect Bank 2 injectors for leaking (fuel pressure drop test)"],
     related=["P2098", "P2097", "P0430"],
     difficulty="medium", cost="$100-$1500")

_add("P2103", "high", "Throttle actuator control motor circuit high — limp mode risk",
     ["Throttle body motor circuit shorted to power", "Wiring insulation damage",
      "Throttle body failure", "PCM driver issue"],
     ["Check throttle body motor connector — disconnect and check for voltage",
      "Inspect wiring for chafing/short to B+",
      "Measure motor winding resistance (typically 2-10Ω)",
      "Replace throttle body if wiring is intact"],
     related=["P2100", "P2101", "P2104"],
     difficulty="medium", cost="$200-$700")

_add("P2104", "high", "Throttle actuator control system — forced idle, safety mode",
     ["Multiple ETC faults causing PCM to default to idle",
      "Throttle body motor failure", "APP sensor disagreement",
      "Wiring harness damage near throttle body"],
     ["Check for companion ETC codes (P2100-P2112, P2135, P2138)",
      "Address root cause codes first — P2104 is usually a result code",
      "Check APP sensor correlation",
      "Check throttle body wiring — look for intermittent loose connections"],
     related=["P2100", "P2101", "P2105"],
     difficulty="medium", cost="$200-$800",
     notes="P2104 is often set alongside other ETC codes — fix the root cause code first.")

_add("P2105", "high", "Throttle actuator control system — forced engine shutdown",
     ["Critical ETC failure — PCM shuts engine down for safety",
      "Throttle stuck open with no TPS feedback",
      "APP and TPS completely disagree", "PCM internal fault"],
     ["This is a critical safety code — do NOT clear and drive",
      "Check for companion ETC codes",
      "Inspect throttle body — can it be commanded closed?",
      "Check APP sensors and TPS for signal",
      "PCM may need replacement if internal fault confirmed"],
     related=["P2104", "P2100", "P2106"],
     difficulty="hard", cost="$200-$1200",
     notes="Engine shutdown code — tow the vehicle, do not attempt to drive.")

_add("P2107", "high", "Throttle actuator control module processor — internal PCM fault",
     ["PCM internal processor error", "PCM power/ground issue",
      "Corrupted PCM software", "PCM hardware failure"],
     ["Check PCM power and ground circuits first",
      "Attempt PCM reflash/reprogramming",
      "Check for TSBs related to PCM software update",
      "If reflash fails, PCM replacement needed"],
     related=["P2106", "P2100"],
     difficulty="hard", cost="$300-$1200")

_add("P2108", "high", "Throttle actuator control module performance",
     ["PCM throttle control processor degraded", "Throttle response too slow",
      "Internal PCM calibration error", "Voltage supply issue to PCM"],
     ["Check PCM power supply voltage (battery and ignition feeds)",
      "Monitor throttle response time — commanded vs actual position",
      "Check for PCM reflash/update availability",
      "Replace PCM if performance doesn't improve after reflash"],
     related=["P2107", "P2100"],
     difficulty="hard", cost="$300-$1200")

_add("P2122", "critical", "Throttle/pedal position sensor D circuit low — limp mode",
     ["APP sensor D failed", "Wiring shorted to ground",
      "Connector pin corrosion", "Accelerator pedal assembly failure"],
     ["Check APP sensor D voltage — should be ~0.5V at rest",
      "Check wiring for short to ground",
      "Inspect accelerator pedal connector for corrosion or damage",
      "Replace accelerator pedal position sensor assembly if faulty"],
     related=["P2123", "P2125", "P2138"],
     difficulty="medium", cost="$100-$400",
     notes="APP sensors are non-serviceable — replace the entire pedal assembly.")

_add("P2123", "critical", "Throttle/pedal position sensor D circuit high — limp mode",
     ["APP sensor D circuit open", "Wiring open or shorted to 5V ref",
      "Connector disconnected", "Sensor internal failure"],
     ["Check APP sensor D voltage — stuck at 5V = open circuit",
      "Check wiring for open or short to reference voltage",
      "Inspect connector — pushed back pin or disconnected",
      "Replace accelerator pedal assembly"],
     related=["P2122", "P2125", "P2138"],
     difficulty="medium", cost="$100-$400")

_add("P2125", "critical", "Throttle/pedal position sensor E circuit low — limp mode",
     ["APP sensor E failed low", "Wiring shorted to ground",
      "Connector corrosion", "Pedal assembly failure"],
     ["Check APP sensor E voltage — should be ~1.0V at rest (2× sensor D)",
      "Check for short to ground in sensor E circuit",
      "Inspect pedal assembly connector",
      "Replace accelerator pedal assembly"],
     related=["P2122", "P2127", "P2138"],
     difficulty="medium", cost="$100-$400")

_add("P2127", "critical", "Throttle/pedal position sensor E circuit low input",
     ["APP sensor E circuit shorted low", "Wiring short to ground",
      "5V reference lost to sensor E", "Pedal assembly internal fault"],
     ["Check APP sensor E voltage at connector",
      "Verify 5V reference present at sensor E",
      "Check wiring for short to ground between PCM and sensor",
      "Replace pedal assembly if sensor or reference is bad"],
     related=["P2128", "P2125", "P2138"],
     difficulty="medium", cost="$100-$400")

_add("P2128", "critical", "Throttle/pedal position sensor E circuit high input",
     ["APP sensor E circuit open or shorted high", "Wiring open",
      "Connector pin backed out", "Sensor internal failure"],
     ["Check APP sensor E voltage — stuck at 5V indicates open/high",
      "Check wiring for open circuit",
      "Inspect connector for backed out pin",
      "Replace accelerator pedal assembly"],
     related=["P2127", "P2125", "P2138"],
     difficulty="medium", cost="$100-$400")

_add("P2130", "critical", "Throttle/pedal position sensor F circuit malfunction",
     ["APP sensor F failed", "Wiring open/short",
      "Connector corrosion", "Pedal assembly internal failure"],
     ["Check APP sensor F voltage and compare to sensors D and E",
      "Sensors should track proportionally — if F disagrees, sensor is bad",
      "Check wiring and connector for damage",
      "Replace accelerator pedal assembly"],
     related=["P2131", "P2138"],
     difficulty="medium", cost="$100-$400")

_add("P2131", "critical", "Throttle/pedal position sensor F circuit range/performance",
     ["APP sensor F reading out of expected range vs D/E",
      "Intermittent wiring issue", "Partial sensor failure",
      "Connector contact resistance"],
     ["Compare sensor F tracking against D and E at various positions",
      "Wiggle-test pedal and wiring while monitoring all 3 sensors",
      "Check connector pin tension",
      "Replace pedal assembly if sensor F drifts out of range"],
     related=["P2130", "P2138"],
     difficulty="medium", cost="$100-$400")

_add("P2133", "critical", "Throttle/pedal position sensor F circuit high — limp mode",
     ["APP sensor F open circuit", "Wiring open or short to reference",
      "Connector pin issue", "Sensor internal failure"],
     ["Check sensor F voltage — stuck high indicates open",
      "Check wiring continuity from PCM to sensor F",
      "Inspect connector for damage or backed-out pins",
      "Replace accelerator pedal assembly"],
     related=["P2134", "P2130", "P2138"],
     difficulty="medium", cost="$100-$400")

_add("P2134", "critical", "Throttle/pedal position sensor F circuit low — limp mode",
     ["APP sensor F shorted to ground", "Wiring short to ground",
      "Connector water intrusion", "Sensor failed low"],
     ["Check sensor F voltage — near 0V confirms low circuit",
      "Check wiring for short to ground",
      "Inspect connector for moisture/corrosion — floor mat can push water into pedal connector",
      "Replace accelerator pedal assembly"],
     related=["P2133", "P2130", "P2138"],
     difficulty="medium", cost="$100-$400",
     notes="Water intrusion at the pedal connector is common — check floor for leaks.")

_add("P2176", "low", "Throttle actuator control — idle position not learned",
     ["Throttle body replaced without relearn", "Battery disconnect during relearn",
      "Throttle body too dirty for valid relearn", "PCM update needed"],
     ["Clean throttle body bore and plate first",
      "Perform throttle body relearn with scan tool",
      "Ensure battery voltage >12V during relearn procedure",
      "If relearn keeps failing, replace throttle body"],
     related=["P2111", "P2112", "P2119"],
     difficulty="easy", cost="$0-$300",
     notes="Most vehicles require a specific relearn procedure — check service info.")

_add("P2177", "medium", "System too lean off idle (Bank 1) — lean under load",
     ["Vacuum leak that worsens under load", "Weak fuel pump — low pressure under demand",
      "Clogged fuel injector", "Intake manifold gasket leak"],
     ["Check fuel pressure at idle and under load (WOT snap test)",
      "Smoke test for vacuum/intake leaks",
      "Check fuel injector balance test",
      "Monitor STFT and LTFT under acceleration — lean spike = supply issue"],
     related=["P2178", "P0171", "P2187"],
     difficulty="medium", cost="$100-$800",
     notes="Unlike P0171 (overall lean), P2177 specifically triggers off-idle — suspect fuel delivery.")

_add("P2178", "medium", "System too rich off idle (Bank 1) — rich under load",
     ["Fuel injector leaking", "Fuel pressure regulator stuck high",
      "EVAP purge valve stuck open", "MAF sensor reading low (PCM adds too much fuel)"],
     ["Check fuel pressure — high pressure = regulator issue",
      "Check EVAP purge valve — disconnect and retest",
      "Monitor fuel trims off-idle — negative LTFT = rich",
      "Test MAF sensor accuracy at various airflows"],
     related=["P2177", "P0172", "P2188"],
     difficulty="medium", cost="$100-$800")

_add("P2179", "medium", "System too lean off idle (Bank 2)",
     ["Vacuum leak on Bank 2 side", "Fuel injector clogged (Bank 2)",
      "Weak fuel pump under demand", "Intake gasket leak Bank 2"],
     ["Smoke test concentrating on Bank 2 intake",
      "Check fuel pressure under load",
      "Fuel injector balance test — compare Bank 2 flow",
      "Compare Bank 2 trims to Bank 1 — Bank 2 only = local issue"],
     related=["P2177", "P0174", "P2189"],
     difficulty="medium", cost="$100-$800")

_add("P2187", "medium", "System too lean at idle (Bank 1)",
     ["Vacuum leak near idle air path", "PCV valve stuck open",
      "Brake booster hose leaking", "Intake gasket leak at idle port"],
     ["Smoke test at idle — concentrate on idle air circuit",
      "Check PCV valve and hoses",
      "Check brake booster hose for leak (hissing/RPM change)",
      "Monitor STFT at idle — high positive = lean"],
     related=["P2188", "P0171", "P2177"],
     difficulty="easy", cost="$50-$500",
     notes="P2187 is lean AT IDLE specifically — most often a small vacuum leak near the throttle body.")

_add("P2188", "medium", "System too rich at idle (Bank 1)",
     ["Fuel injector leaking (dripping at idle)", "Fuel pressure regulator leaking into vacuum line",
      "EVAP purge solenoid stuck open", "Faulty O2 sensor biasing rich"],
     ["Check for fuel in vacuum line at fuel pressure regulator",
      "Pull EVAP purge hose at idle — RPM change = purge stuck open",
      "Check fuel pressure at idle — should be per spec",
      "Injector leak-down test — pressure should hold 5+ minutes"],
     related=["P2187", "P0172", "P2178"],
     difficulty="medium", cost="$100-$600")

_add("P2189", "medium", "System too rich at idle (Bank 2)",
     ["Fuel injector leaking on Bank 2", "Fuel pressure regulator fault",
      "EVAP purge issue", "Bank 2 O2 sensor fault"],
     ["Perform fuel injector leak-down test",
      "Compare Bank 2 idle trims to Bank 1",
      "Check for fuel odor from Bank 2 exhaust",
      "Inspect Bank 2 injectors for visible fuel drip (engine off, key on)"],
     related=["P2188", "P0175", "P2179"],
     difficulty="medium", cost="$100-$600")

_add("P2190", "medium", "System too lean at idle (Bank 2)",
     ["Vacuum leak on Bank 2 intake", "Intake gasket leak Bank 2 side",
      "PCV hose leak on Bank 2", "Idle air leak near Bank 2 runners"],
     ["Smoke test Bank 2 intake runners and gaskets",
      "Check PCV system components on Bank 2 side",
      "Compare Bank 2 trims at idle to Bank 1",
      "Spray propane around Bank 2 intake — RPM rise = leak location"],
     related=["P2187", "P0174", "P2191"],
     difficulty="easy", cost="$50-$500")

_add("P2191", "medium", "System too lean at wide open throttle (Bank 2)",
     ["Fuel pump weak under high demand", "Fuel filter restricted",
      "Fuel injector clogged on Bank 2", "Fuel supply line restricted"],
     ["Check fuel pressure under WOT — pressure should not drop",
      "Check fuel filter for restriction (if serviceable)",
      "Fuel injector flow test on Bank 2",
      "Check fuel supply line for kink or restriction"],
     related=["P2179", "P2190", "P0174"],
     difficulty="medium", cost="$100-$800")

_add("P2197", "medium", "O2 sensor signal biased/stuck lean (Bank 2 Sensor 1)",
     ["Bank 2 upstream O2 sensor failed — reads lean",
      "Exhaust leak near Bank 2 sensor 1", "Wiring open in sensor circuit",
      "Sensor contaminated with coolant (head gasket leak)"],
     ["Monitor Bank 2 sensor 1 signal — should oscillate 0.1-0.9V",
      "If stuck low/near 0V, check for exhaust leak at manifold",
      "Snap throttle — sensor should respond quickly to rich command",
      "Check for white smoke/coolant loss indicating head gasket"],
     related=["P2198", "P2195", "P0174"],
     difficulty="medium", cost="$100-$400")

_add("P2198", "medium", "O2 sensor signal biased/stuck rich (Bank 2 Sensor 1)",
     ["Bank 2 upstream O2 sensor failed — reads rich",
      "Fuel injector leaking on Bank 2", "EVAP purge affecting Bank 2",
      "Sensor contaminated with silicone (RTV sealant)"],
     ["Monitor Bank 2 sensor 1 — stuck high/near 0.9V = biased rich",
      "Command fuel cut and watch sensor — should drop to 0V",
      "Check Bank 2 injectors for leaking",
      "Check for silicone contamination (recent gasket work with RTV?)"],
     related=["P2197", "P2196", "P0175"],
     difficulty="medium", cost="$100-$400")

_add("P2270", "low", "O2 sensor signal biased/stuck lean (Bank 1 Sensor 2)",
     ["Downstream O2 sensor (Bank 1) failed lean", "Exhaust leak near rear sensor",
      "Wiring issue in sensor circuit", "Catalytic converter inefficient"],
     ["Monitor Bank 1 sensor 2 — should be relatively steady ~0.6-0.7V",
      "If reading low, check for exhaust leak at cat-to-pipe joint",
      "Check sensor connector for corrosion",
      "Compare upstream vs downstream — downstream flat low may indicate bad cat"],
     related=["P2271", "P0420"],
     difficulty="easy", cost="$80-$300")

_add("P2271", "low", "O2 sensor signal biased/stuck rich (Bank 1 Sensor 2)",
     ["Downstream O2 sensor (Bank 1) failed rich", "Sensor contaminated",
      "Wiring short to voltage source", "Cat efficiency issue"],
     ["Monitor Bank 1 sensor 2 — stuck near 0.8-0.9V = biased rich",
      "Check sensor signal wire for short to B+ or reference",
      "Check for oil/coolant contamination at sensor tip",
      "Replace sensor and retest cat monitor readiness"],
     related=["P2270", "P0420"],
     difficulty="easy", cost="$80-$300")

_add("P2272", "low", "O2 sensor signal biased/stuck lean (Bank 2 Sensor 2)",
     ["Downstream O2 sensor (Bank 2) failed lean", "Exhaust leak at rear joint",
      "Sensor wiring open", "Cat losing efficiency (Bank 2)"],
     ["Monitor Bank 2 sensor 2 signal",
      "Check for exhaust leaks near catalyst outlet",
      "Inspect sensor connector and wiring",
      "Replace sensor and run catalyst monitor to completion"],
     related=["P2273", "P0430"],
     difficulty="easy", cost="$80-$300")

_add("P2273", "low", "O2 sensor signal biased/stuck rich (Bank 2 Sensor 2)",
     ["Downstream O2 sensor (Bank 2) failed rich", "Sensor contaminated",
      "Wiring issue", "Catalytic converter issue (Bank 2)"],
     ["Monitor Bank 2 sensor 2 — stuck near 0.9V = biased rich",
      "Check sensor connector for contamination or shorts",
      "Replace sensor and retest",
      "If code returns with new sensor, investigate cat efficiency"],
     related=["P2272", "P0430"],
     difficulty="easy", cost="$80-$300")

_add("P2274", "low", "O2 sensor signal biased/stuck lean negative current (Bank 2 Sensor 2)",
     ["Wideband/AF sensor aging (Bank 2 downstream)", "Sensor heater degraded",
      "Exhaust leak near sensor", "Wiring resistance too high"],
     ["Monitor sensor negative current reading with scan tool",
      "Check sensor heater operation (resistance and current draw)",
      "Check wiring resistance — should be <5Ω end-to-end",
      "Replace sensor if readings are inconsistent"],
     related=["P2272", "P2273", "P0430"],
     difficulty="easy", cost="$100-$350")

_add("P2279", "medium", "Intake air system leak — unmetered air entering engine",
     ["Vacuum hose cracked or disconnected", "Intake boot torn",
      "Intake manifold gasket leak", "PCV system leak",
      "Brake booster vacuum hose leaking"],
     ["Smoke test intake system for leaks",
      "Check intake boot/hose from MAF to throttle body for cracks",
      "Check PCV valve and hoses",
      "Check brake booster hose for vacuum leak",
      "Monitor MAF vs MAP correlation — mismatch indicates unmetered air"],
     related=["P2280", "P0171", "P0174"],
     difficulty="easy", cost="$20-$300",
     notes="This is a generic unmetered air code — the leak is between MAF and intake valves.")

_add("P2280", "medium", "Air flow restriction between air filter and MAF",
     ["Air filter severely clogged", "Airbox lid not sealed properly",
      "Aftermarket air filter not seating correctly", "Debris in air intake duct"],
     ["Check air filter condition — replace if dirty/clogged",
      "Ensure airbox lid is fully sealed and latched",
      "Inspect intake duct for debris or collapsed section",
      "If aftermarket filter, check for proper fit and seal"],
     related=["P2279", "P0101", "P0100"],
     difficulty="easy", cost="$15-$100",
     notes="Often just a dirty air filter — easiest fix in the book.")


# ---------------------------------------------------------------------------
# Powertrain — Fuel/Air Metering (P0150-P0199 gaps)
# ---------------------------------------------------------------------------

_add("P0152", "medium", "O2 sensor circuit high voltage (Bank 2, Sensor 1)",
     ["O2 sensor shorted internally", "Fuel pressure too high",
      "Leaking fuel injector on Bank 2", "Wiring short to voltage"],
     ["Check O2 sensor live data — voltage should toggle 0.1-0.9V",
      "Inspect wiring for chafing against exhaust",
      "Check fuel pressure with gauge",
      "Swap sensor with known good if available"],
     related=["P0150", "P0153", "P0175"],
     difficulty="easy", cost="$50-$250",
     notes="High voltage stuck above 0.6V usually means rich condition or sensor failure.")

_add("P0153", "medium", "O2 sensor circuit slow response (Bank 2, Sensor 1)",
     ["O2 sensor lazy/contaminated", "Exhaust leak near sensor",
      "Fuel delivery issue", "Vacuum leak affecting Bank 2"],
     ["Check O2 sensor switching frequency — should toggle 6-8 times per 10 sec",
      "Compare Bank 1 vs Bank 2 sensor activity",
      "Check for exhaust leaks at manifold gasket",
      "Inspect for vacuum leaks on Bank 2 side"],
     related=["P0150", "P0152", "P0174"],
     difficulty="easy", cost="$50-$250",
     notes="Slow response is often an aging sensor. Replace and clear — recheck after drive cycle.")

_add("P0154", "medium", "O2 sensor circuit no activity (Bank 2, Sensor 1)",
     ["O2 sensor dead", "Open circuit in wiring", "Connector unplugged or corroded",
      "Fuse blown for O2 heater circuit"],
     ["Check connector for corrosion or damage",
      "Measure signal wire — should show voltage changes at idle",
      "Verify heater fuse is intact",
      "Check ground circuit continuity"],
     related=["P0150", "P0155", "P0174"],
     difficulty="easy", cost="$50-$250")

_add("P0156", "medium", "O2 sensor circuit malfunction (Bank 2, Sensor 2)",
     ["Downstream O2 sensor failed", "Exhaust leak after catalyst",
      "Wiring damage from heat or road debris", "Contaminated sensor"],
     ["Check O2 voltage — downstream should be relatively steady around 0.5-0.7V",
      "Inspect wiring routing — often near exhaust and road debris",
      "Check exhaust for leaks near sensor bung",
      "Replace sensor if readings are erratic"],
     related=["P0136", "P0430", "P0141"],
     difficulty="easy", cost="$50-$250")

_add("P0157", "medium", "O2 sensor circuit low voltage (Bank 2, Sensor 2)",
     ["O2 sensor failed lean", "Exhaust leak before sensor", "Open signal wire",
      "Ground circuit issue"],
     ["Check O2 sensor live data — should not be stuck below 0.1V",
      "Inspect for exhaust leaks between cat and sensor",
      "Check wiring continuity for signal and ground",
      "If sensor reads low after cat replacement, drive cycle may be needed"],
     related=["P0156", "P0158", "P0430"],
     difficulty="easy", cost="$50-$250")

_add("P0158", "medium", "O2 sensor circuit high voltage (Bank 2, Sensor 2)",
     ["O2 sensor shorted or contaminated", "Catalyst efficiency problem causing high downstream voltage",
      "Wiring short to voltage", "Coolant contamination of sensor"],
     ["Check downstream O2 voltage — should be steady, not mirroring upstream",
      "If mirroring upstream, cat is the issue (P0430 territory)",
      "Inspect wiring for chafing or melt",
      "Replace sensor and clear, drive cycle"],
     related=["P0156", "P0157", "P0430"],
     difficulty="easy", cost="$50-$250")

_add("P0159", "medium", "O2 sensor circuit slow response (Bank 2, Sensor 2)",
     ["Downstream O2 sensor aging", "Catalyst deterioration changing exhaust gas mix",
      "Exhaust leak near sensor", "Wiring resistance high"],
     ["Compare downstream switching rate to upstream — downstream should be slower/steadier",
      "If downstream mirrors upstream closely, suspect catalyst",
      "Check exhaust system integrity",
      "Replace sensor — relatively low cost part"],
     related=["P0156", "P0430"],
     difficulty="easy", cost="$50-$250")

_add("P0160", "medium", "O2 sensor circuit no activity (Bank 2, Sensor 2)",
     ["O2 sensor heater or element dead", "Open circuit in harness",
      "Connector corroded or disconnected", "ECM driver fault (rare)"],
     ["Verify connector is plugged in and not corroded",
      "Measure sensor resistance — should read ~10-20Ω heater",
      "Check for voltage at connector with engine running",
      "Swap sensor and retest"],
     related=["P0156", "P0161"],
     difficulty="easy", cost="$50-$250")

_add("P0161", "medium", "O2 sensor heater circuit malfunction (Bank 2, Sensor 2)",
     ["Heater element open circuit", "Fuse blown", "Relay fault",
      "Connector water intrusion"],
     ["Check heater fuse", "Measure heater resistance (typically 5-15Ω)",
      "Check for 12V B+ at heater connector with ignition on",
      "Inspect connector for water or corrosion damage"],
     related=["P0141", "P0156", "P0160"],
     difficulty="easy", cost="$50-$200")

_add("P0162", "medium", "O2 sensor circuit malfunction (Bank 2, Sensor 3)",
     ["Third O2 sensor failed (if equipped)", "Wiring damage",
      "Connector corroded", "Sensor contaminated"],
     ["Verify vehicle has a third sensor (some trucks, dual-cat systems)",
      "Check sensor voltage with scan tool",
      "Inspect wiring and connector",
      "Replace sensor if readings are out of range"],
     related=["P0156", "P0163"],
     difficulty="easy", cost="$50-$250",
     notes="Bank 2 Sensor 3 is only present on some vehicles with dual catalytic converters in series.")

_add("P0163", "medium", "O2 sensor circuit low voltage (Bank 2, Sensor 3)",
     ["Third O2 sensor biased lean", "Open signal circuit", "Exhaust leak",
      "Ground fault"],
     ["Check voltage with scan tool — should not be pegged low",
      "Verify wiring from ECM to sensor is intact",
      "Check for exhaust leaks near sensor",
      "Replace sensor if wiring checks out"],
     related=["P0162", "P0156"],
     difficulty="easy", cost="$50-$250")

_add("P0170", "medium", "Fuel trim malfunction (Bank 1) — engine running rich or lean",
     ["Vacuum leak", "MAF sensor dirty or failed", "Fuel pressure out of spec",
      "O2 sensor inaccurate", "Exhaust leak before O2 sensor"],
     ["Check fuel trims — LTFT should be within ±10%",
      "Inspect for vacuum leaks with smoke test",
      "Clean or test MAF sensor",
      "Check fuel pressure with gauge",
      "Check O2 sensor operation"],
     related=["P0171", "P0172", "P0173"],
     difficulty="medium", cost="$50-$500",
     notes="This is a 'parent' code — look for P0171/P0172 to determine lean vs rich direction.")

_add("P0173", "medium", "Fuel trim malfunction (Bank 2) — engine running rich or lean",
     ["Vacuum leak on Bank 2 side", "MAF sensor issue", "Fuel injector imbalance",
      "O2 sensor Bank 2 inaccurate", "Intake gasket leak"],
     ["Check LTFT Bank 2 — should be within ±10%",
      "Inspect Bank 2 intake manifold gasket area",
      "Check fuel injector balance test",
      "Check Bank 2 O2 sensor response",
      "Compare Bank 1 and Bank 2 trims — if only Bank 2 off, issue is bank-specific"],
     related=["P0174", "P0175", "P0170"],
     difficulty="medium", cost="$50-$500")

_add("P0176", "low", "Fuel composition sensor circuit malfunction — flex-fuel issue",
     ["Fuel composition sensor failed", "Wiring fault", "Sensor connector corroded",
      "Bad fuel or water contamination"],
     ["Check flex-fuel sensor connector",
      "Verify sensor voltage with scan tool",
      "Check wiring harness for damage",
      "Scan for stored freeze frame data — check fuel alcohol %"],
     related=["P0177", "P0178", "P0179"],
     difficulty="medium", cost="$100-$400",
     notes="Only applies to flex-fuel vehicles. Sensor reads ethanol content of fuel.")

_add("P0177", "low", "Fuel composition sensor circuit range/performance",
     ["Fuel composition sensor degraded", "Contaminated fuel",
      "Intermittent wiring connection", "Sensor out of calibration"],
     ["Check sensor output vs expected for fuel type",
      "Inspect connector for corrosion",
      "Check for water in fuel (drain and inspect)",
      "Replace sensor if readings are erratic"],
     related=["P0176", "P0178"],
     difficulty="medium", cost="$100-$400")

_add("P0178", "low", "Fuel composition sensor circuit low input",
     ["Sensor shorted to ground", "Wiring fault — open circuit on signal",
      "Fuel composition sensor failed", "Connector pin backed out"],
     ["Check voltage at sensor connector — should not be at 0V",
      "Inspect wiring for shorts to ground",
      "Check connector pin retention",
      "Replace sensor if circuit tests good"],
     related=["P0176", "P0179"],
     difficulty="medium", cost="$100-$400")

_add("P0179", "low", "Fuel composition sensor circuit high input",
     ["Sensor shorted to B+ voltage", "Wiring fault — short to power source",
      "Failed sensor", "ECM issue (rare)"],
     ["Check sensor voltage — should not be pegged at reference voltage",
      "Inspect wiring for shorts to power",
      "Disconnect sensor and check if voltage drops (ECM pull-down test)",
      "Replace sensor if wiring OK"],
     related=["P0176", "P0178"],
     difficulty="medium", cost="$100-$400")

_add("P0180", "low", "Fuel temperature sensor A circuit malfunction",
     ["Fuel temp sensor failed", "Wiring open or shorted",
      "Connector corrosion", "ECM input circuit fault"],
     ["Check fuel temp sensor reading — should track ambient/fuel temp",
      "Measure sensor resistance (NTC thermistor — decreases with temp)",
      "Check wiring continuity from sensor to ECM",
      "Check connector for fuel or moisture contamination"],
     related=["P0181", "P0182", "P0183"],
     difficulty="easy", cost="$50-$200",
     notes="Fuel temp sensor is used to calculate fuel density for injection timing. Often in or near fuel rail.")

_add("P0181", "low", "Fuel temperature sensor A range/performance",
     ["Sensor stuck or intermittent", "Sensor reading does not correlate with actual fuel temp",
      "Heat soak issue causing incorrect readings", "Wiring intermittent"],
     ["Compare fuel temp sensor reading with IAT at cold start — should be similar",
      "Monitor sensor during warm-up — should increase gradually",
      "Check connector for intermittent contact",
      "Replace sensor if readings don't track with fuel temp"],
     related=["P0180", "P0182"],
     difficulty="easy", cost="$50-$200")

_add("P0182", "low", "Fuel temperature sensor A circuit low",
     ["Sensor shorted to ground", "Wiring shorted", "Sensor internal short",
      "Connector terminal damage"],
     ["Check sensor voltage at ECM — should not be near 0V at normal temps",
      "Disconnect sensor — voltage should go high (open circuit)",
      "Check wiring for spots where it may be grounding against chassis",
      "Replace sensor if wiring is OK"],
     related=["P0180", "P0183"],
     difficulty="easy", cost="$50-$200")

_add("P0183", "low", "Fuel temperature sensor A circuit high",
     ["Sensor open circuit", "Connector disconnected or corroded",
      "Wiring open", "Sensor failed open"],
     ["Check connector — most common cause is a loose or corroded plug",
      "Measure sensor resistance — should read per spec chart at current temp",
      "Check wiring for opens from sensor to ECM",
      "Replace sensor if resistance is infinite"],
     related=["P0180", "P0182"],
     difficulty="easy", cost="$50-$200")

_add("P0190", "medium", "Fuel rail pressure sensor circuit malfunction — possible stalling",
     ["Fuel rail pressure sensor failed", "Wiring fault",
      "Connector corrosion", "Low fuel pressure causing sensor reading issues"],
     ["Check sensor 5V reference supply",
      "Check sensor ground circuit",
      "Monitor FRP sensor reading — compare with mechanical gauge",
      "Inspect connector for fuel contamination or corrosion"],
     related=["P0191", "P0192", "P0193"],
     difficulty="medium", cost="$100-$400",
     notes="On GDI engines, fuel rail pressure is critical. Sensor failure can cause hard start or no-start.")

_add("P0191", "medium", "Fuel rail pressure sensor range/performance — rough running possible",
     ["Fuel rail pressure sensor degraded", "Actual fuel pressure issue (weak pump, clogged filter)",
      "Sensor wiring intermittent", "Sensor not calibrated to actual pressure"],
     ["Compare sensor reading with mechanical fuel pressure gauge",
      "Check for fuel filter restriction",
      "Check fuel pump output volume and pressure",
      "Inspect sensor wiring for intermittent connection"],
     related=["P0190", "P0192", "P0193"],
     difficulty="medium", cost="$100-$500",
     notes="On GDI/HPFP systems, this often points to the high-pressure fuel pump rather than the sensor.")

_add("P0192", "medium", "Fuel rail pressure sensor circuit low — possible stalling or no-start",
     ["Sensor shorted to ground", "Wiring fault", "Low actual fuel pressure",
      "Fuel pump weak or failing"],
     ["Check sensor voltage — should not be near 0V with engine running",
      "Disconnect sensor — should go to 5V reference",
      "Check actual fuel pressure with gauge",
      "Inspect wiring for short to ground"],
     related=["P0190", "P0193"],
     difficulty="medium", cost="$100-$500")

_add("P0193", "medium", "Fuel rail pressure sensor circuit high — possible limp mode",
     ["Sensor shorted to reference voltage", "Wiring short to 5V line",
      "Sensor failed high", "Connector issue"],
     ["Check sensor voltage — should not be pegged at 5V",
      "Inspect wiring for short to 5V reference circuit",
      "Disconnect sensor — voltage should drop",
      "Replace sensor if circuit checks OK"],
     related=["P0190", "P0192"],
     difficulty="medium", cost="$100-$400")

# ---------------------------------------------------------------------------
# Powertrain — Ignition / Knock / Crank-Cam (P0326-P0399 gaps)
# ---------------------------------------------------------------------------

_add("P0326", "medium", "Knock sensor 1 circuit range/performance — timing may retard",
     ["Knock sensor degraded", "Incorrect sensor torque", "Engine mechanical noise",
      "Wiring harness open or high resistance"],
     ["Check knock sensor mounting torque (15 ft-lb typical)",
      "Inspect wiring for damage — often routed under intake",
      "Listen for abnormal engine noise (rod knock, piston slap)",
      "Check fuel quality — low octane causes real knock"],
     related=["P0325", "P0327", "P0328"],
     difficulty="medium", cost="$100-$400",
     notes="Range/performance means ECM sees signal but it's not in expected range. Check mechanical before condemning sensor.")

_add("P0327", "medium", "Knock sensor 1 circuit low — reduced power possible",
     ["Knock sensor failed open", "Wiring open circuit",
      "Connector corroded", "Sensor not making good contact with block"],
     ["Check connector — corrosion under intake is very common",
      "Measure sensor resistance if piezoelectric type (varies by make)",
      "Inspect mounting bolt — must contact clean metal on block",
      "Check wiring from sensor to ECM for continuity"],
     related=["P0325", "P0328"],
     difficulty="medium", cost="$100-$400",
     notes="Low input often means open circuit. Sensor is usually under the intake manifold — budget for labor.")

_add("P0328", "medium", "Knock sensor 1 circuit high — timing retard likely",
     ["Knock sensor shorted internally", "Wiring short to voltage",
      "Excessive engine mechanical noise producing real knock signal",
      "Wrong sensor installed (aftermarket mismatch)"],
     ["Check for real engine knock — carbon buildup, low octane, overheating",
      "Inspect wiring for shorts",
      "Verify correct part number for sensor",
      "Replace sensor and clear — drive and verify timing advance returns"],
     related=["P0325", "P0327"],
     difficulty="medium", cost="$100-$400")

_add("P0330", "medium", "Knock sensor 2 circuit malfunction (Bank 2) — timing may retard",
     ["Knock sensor 2 failed", "Wiring fault under intake manifold",
      "Sensor mounting issue", "Engine mechanical noise"],
     ["Check knock sensor 2 connector and wiring",
      "Verify sensor mounting torque",
      "Compare Bank 1 and Bank 2 knock values — if both high, suspect fuel or engine issue",
      "Replace sensor — typically requires intake manifold removal"],
     related=["P0331", "P0332", "P0325"],
     difficulty="medium", cost="$100-$400",
     notes="Bank 2 knock sensor is the second sensor — only on V6/V8/V10 engines.")

_add("P0331", "medium", "Knock sensor 2 circuit range/performance — reduced power",
     ["Knock sensor 2 degraded", "Wiring intermittent",
      "Wrong torque on sensor", "Engine noise on Bank 2"],
     ["Check sensor signal amplitude with scope if possible",
      "Inspect wiring and connector for corrosion",
      "Check sensor torque specification",
      "Compare Bank 2 knock sensor data with Bank 1"],
     related=["P0330", "P0332", "P0333"],
     difficulty="medium", cost="$100-$400")

_add("P0332", "medium", "Knock sensor 2 circuit low input — reduced power likely",
     ["Knock sensor 2 open circuit", "Wiring open", "Connector unplugged or corroded",
      "Sensor not seated on block properly"],
     ["Check connector — often buried under intake manifold",
      "Verify sensor mounting bolt is tight and contacting clean metal",
      "Check wiring continuity from sensor to ECM",
      "Replace sensor if circuit tests OK"],
     related=["P0330", "P0333"],
     difficulty="medium", cost="$100-$400")

_add("P0333", "medium", "Knock sensor 2 circuit high input — timing over-retarded",
     ["Knock sensor 2 shorted", "Engine mechanical knock on Bank 2",
      "Wiring short to power", "Wrong sensor type installed"],
     ["Check for real mechanical knock on Bank 2 cylinders",
      "Inspect wiring for shorts",
      "Verify sensor part number matches application",
      "Replace sensor and recheck timing advance after drive cycle"],
     related=["P0330", "P0332"],
     difficulty="medium", cost="$100-$400")

_add("P0337", "high", "Crankshaft position sensor A circuit low — intermittent stall possible",
     ["Crank sensor failed or intermittent", "Wiring short to ground",
      "Sensor air gap too large", "Reluctor ring damage"],
     ["Check crank sensor air gap — should be ~0.5-1.5mm",
      "Inspect wiring for shorts to ground near exhaust",
      "Measure sensor resistance (~500-1500Ω typical)",
      "Check reluctor ring on harmonic balancer for chips or debris"],
     related=["P0335", "P0336", "P0338"],
     difficulty="medium", cost="$50-$400",
     notes="Low input can cause intermittent stalling at random. If sensor checks OK, inspect the reluctor ring closely.")

_add("P0338", "high", "Crankshaft position sensor A circuit high — possible no-start",
     ["Crank sensor shorted internally", "Wiring short to B+ voltage",
      "Connector contamination", "ECM input circuit issue (rare)"],
     ["Inspect connector for oil or coolant contamination",
      "Check wiring for shorts to power",
      "Measure sensor output with scope during cranking",
      "Replace sensor if signal is absent or garbled"],
     related=["P0335", "P0337"],
     difficulty="medium", cost="$50-$400")

_add("P0342", "high", "Camshaft position sensor A circuit low (Bank 1) — possible no-start",
     ["Cam sensor failed", "Wiring short to ground", "Connector fault",
      "Timing chain jumped causing abnormal signal"],
     ["Check cam sensor connector for oil intrusion",
      "Inspect wiring for damage or shorts near valve cover",
      "Measure sensor signal with scope during cranking",
      "If timing chain suspected, check cam-to-crank correlation"],
     related=["P0340", "P0341", "P0343"],
     difficulty="medium", cost="$50-$400",
     notes="Oil leaking into the cam sensor connector is extremely common on many engines. Check the seal.")

_add("P0343", "high", "Camshaft position sensor A circuit high (Bank 1) — rough running",
     ["Cam sensor shorted", "Wiring short to reference voltage",
      "Connector corroded or contaminated", "ECM driver fault"],
     ["Check for 5V reference at sensor connector",
      "Inspect wiring for chafing or shorts near valve cover",
      "Disconnect sensor — voltage should drop",
      "Replace sensor if circuit tests OK"],
     related=["P0340", "P0342"],
     difficulty="medium", cost="$50-$400")

_add("P0344", "medium", "Camshaft position sensor A circuit intermittent (Bank 1)",
     ["Cam sensor intermittently failing", "Loose connector",
      "Wiring damage causing intermittent open/short", "Sensor air gap issue"],
     ["Wiggle-test connector and wiring while monitoring sensor signal",
      "Check connector pin tension — pins may be widened",
      "Inspect sensor for oil contamination",
      "Check for cam sensor reluctor wheel damage"],
     related=["P0340", "P0341", "P0016"],
     difficulty="medium", cost="$50-$400",
     notes="Intermittent cam sensor faults often cause random misfires or momentary stumbles during driving.")

_add("P0349", "medium", "Camshaft position sensor B circuit intermittent (Bank 2)",
     ["Cam sensor B intermittent failure", "Wiring damage (heat, chafing)",
      "Connector issue", "Sensor reluctor wheel chipped"],
     ["Wiggle-test connector and wiring while monitoring signal",
      "Inspect wiring routing near exhaust for heat damage",
      "Check sensor and reluctor for debris",
      "Replace sensor if tests are inconclusive"],
     related=["P0345", "P0346", "P0347", "P0348"],
     difficulty="medium", cost="$50-$400")

_add("P0350", "high", "Ignition coil primary/secondary circuit — misfire likely",
     ["Ignition coil failed", "Coil connector damaged", "Coil driver in ECM/ICM failed",
      "Wiring fault in coil circuit"],
     ["Check for spark at affected cylinder",
      "Measure coil primary resistance (~0.5-1.5Ω) and secondary (~5-15kΩ)",
      "Swap coil to another cylinder — does misfire follow?",
      "Check coil connector for corrosion or burn marks"],
     related=["P0351", "P0352", "P0300"],
     difficulty="easy", cost="$50-$300",
     notes="P0350 is a general code — some vehicles set individual coil codes P0351-P0358 instead.")

_add("P0357", "high", "Ignition coil G primary/secondary circuit — cylinder 7 misfire",
     ["Coil pack for cylinder 7 failed", "Connector corroded",
      "Spark plug fouled or gapped incorrectly", "Wiring from ECM to coil open"],
     ["Swap coil 7 with adjacent known-good coil — does code follow?",
      "Check spark plug condition — carbon fouled, oil fouled, worn gap?",
      "Inspect coil connector for signs of arcing or corrosion",
      "Check wiring from ECM to coil for continuity"],
     related=["P0307", "P0351", "P0300"],
     difficulty="easy", cost="$50-$200",
     notes="Only applicable to engines with 7+ cylinders (V8, V10). Coil-on-plug failures are common.")

_add("P0358", "high", "Ignition coil H primary/secondary circuit — cylinder 8 misfire",
     ["Coil pack for cylinder 8 failed", "Connector issue",
      "Spark plug worn or fouled", "Coil driver circuit fault"],
     ["Swap coil 8 with known-good from another cylinder",
      "Inspect spark plug for cylinder 8",
      "Check coil connector for moisture or corrosion",
      "Measure coil primary/secondary resistance"],
     related=["P0308", "P0351", "P0300"],
     difficulty="easy", cost="$50-$200")

_add("P0360", "high", "Ignition coil J primary/secondary circuit — cylinder 9 misfire",
     ["Ignition coil for cylinder 9 failed", "Wiring open/short",
      "Connector corroded", "ECM coil driver fault"],
     ["Swap coil with adjacent cylinder — see if code moves",
      "Check spark plug for cylinder 9",
      "Inspect connector and wiring",
      "Check coil resistance"],
     related=["P0300", "P0351"],
     difficulty="easy", cost="$50-$200",
     notes="Cylinder 9 — only on V10 engines (e.g., Ford 6.8L V10 in E-series/F-series).")

_add("P0361", "high", "Ignition coil K primary/secondary circuit — cylinder 10 misfire",
     ["Ignition coil for cylinder 10 failed", "Wiring or connector fault",
      "Spark plug deteriorated", "ECM coil driver issue"],
     ["Swap coil with another cylinder to confirm",
      "Inspect spark plug condition",
      "Check connector for arc marks or corrosion",
      "Measure coil resistance — compare with spec"],
     related=["P0300", "P0351"],
     difficulty="easy", cost="$50-$200",
     notes="V10 engines only. If multiple coil codes set, check shared power/ground circuit rather than individual coils.")

_add("P0362", "medium", "Ignition coil L primary/secondary circuit",
     ["Coil L failed internally", "Wiring open",
      "Connector issue", "ECM driver circuit fault"],
     ["Swap coil to verify — code should follow coil if coil is bad",
      "Check wiring from ECM to coil for continuity",
      "Inspect connector pins for damage",
      "Measure primary and secondary resistance"],
     related=["P0300", "P0351"],
     difficulty="easy", cost="$50-$200")

_add("P0363", "high", "Misfire detected — fuel injection disabled on cylinder",
     ["Persistent misfire causing ECM to disable injector", "Ignition coil failure",
      "Mechanical engine issue (low compression, bent valve)",
      "Fuel injector dead on affected cylinder"],
     ["Identify which cylinder is disabled (check freeze frame)",
      "Check ignition coil and spark plug on affected cylinder",
      "Perform compression test on affected cylinder",
      "Check fuel injector operation (noid light or resistance test)"],
     related=["P0300", "P0301", "P0302"],
     difficulty="medium", cost="$100-$1200",
     notes="This is a protective code — ECM cuts fuel to prevent catalyst damage from raw fuel. Fix the root misfire.")

_add("P0365", "high", "Camshaft position sensor B circuit (Bank 1) — possible stall",
     ["Cam sensor B failed", "Wiring fault",
      "Connector contaminated with oil", "Timing component failure"],
     ["Check cam sensor B connector for oil intrusion",
      "Measure sensor signal with scan tool",
      "Check wiring for damage or corrosion",
      "Verify cam timing with scope if dual-cam engine"],
     related=["P0340", "P0341", "P0366"],
     difficulty="medium", cost="$50-$400",
     notes="Bank 1 cam sensor B is typically the exhaust camshaft sensor on DOHC engines.")

_add("P0366", "medium", "Camshaft position sensor B range/performance (Bank 1)",
     ["Cam sensor B signal out of expected range", "Timing chain stretch causing cam drift",
      "Sensor air gap issue", "Reluctor ring damage"],
     ["Check cam-to-crank correlation with dual-trace scope",
      "If timing chain has high mileage, check for stretch",
      "Inspect sensor mounting and air gap",
      "Compare exhaust cam timing to intake cam timing"],
     related=["P0365", "P0016", "P0017"],
     difficulty="medium", cost="$50-$800",
     notes="On DOHC engines, this can indicate timing chain stretch affecting the exhaust cam specifically.")

_add("P0370", "high", "Timing reference high-resolution signal A malfunction",
     ["Timing reference sensor failed", "Reluctor/tone wheel damaged",
      "Wiring fault in timing circuit", "ECM timing input circuit failure"],
     ["Check crank trigger sensor and reluctor wheel",
      "Inspect wiring for damage near flexplate/flywheel area",
      "Scope the high-resolution timing signal during cranking",
      "Compare with crank sensor signal for consistency"],
     related=["P0335", "P0340"],
     difficulty="hard", cost="$200-$800",
     notes="High-resolution timing reference is used on some engines for precise fuel/spark timing. Rare code.")

_add("P0385", "high", "Crankshaft position sensor B circuit — possible no-start",
     ["Second crank sensor failed", "Wiring damage",
      "Sensor gap too large", "Reluctor ring issue"],
     ["Check second crank sensor connector and wiring",
      "Measure sensor resistance (~500-1500Ω)",
      "Inspect wiring route — often near starter and exhaust",
      "Check for metal debris on sensor tip (magnetic pickup)"],
     related=["P0335", "P0336"],
     difficulty="medium", cost="$50-$400",
     notes="Not all engines have two crank sensors. Common on some diesel and European applications.")

_add("P0390", "high", "Camshaft position sensor B circuit (Bank 2) — possible stall",
     ["Bank 2 exhaust cam sensor failed", "Wiring open or shorted",
      "Connector corroded with oil/moisture", "Cam reluctor wheel damage"],
     ["Check sensor connector — oil leaks from valve cover gasket are common",
      "Measure sensor signal during cranking",
      "Check wiring for damage near exhaust manifold",
      "Verify cam timing is correct"],
     related=["P0345", "P0391", "P0392"],
     difficulty="medium", cost="$50-$400")

_add("P0391", "medium", "Camshaft position sensor B range/performance (Bank 2)",
     ["Cam sensor B signal erratic on Bank 2", "Timing chain stretch on Bank 2 exhaust cam",
      "Sensor mounting issue", "Debris on reluctor wheel"],
     ["Check cam timing with scope — compare Bank 1 and Bank 2",
      "Inspect timing chain guides and tensioner",
      "Check sensor air gap and mounting bolt",
      "Clear and drive — recheck for pattern of failure"],
     related=["P0390", "P0392", "P0017"],
     difficulty="medium", cost="$50-$800")

_add("P0392", "high", "Camshaft position sensor B circuit low (Bank 2)",
     ["Cam sensor B shorted to ground", "Wiring fault",
      "Sensor failed internally", "Connector issue"],
     ["Check sensor connector for oil contamination",
      "Inspect wiring for shorts to ground near valve cover",
      "Measure sensor voltage — should not be near 0V during cranking",
      "Replace sensor if wiring OK"],
     related=["P0390", "P0393"],
     difficulty="medium", cost="$50-$400")

_add("P0393", "high", "Camshaft position sensor B circuit high (Bank 2)",
     ["Cam sensor B shorted to reference voltage", "Wiring short to 5V",
      "Sensor failed high", "Contaminated connector"],
     ["Check sensor voltage — should not be pegged at 5V",
      "Inspect wiring for short to reference circuit",
      "Disconnect sensor — voltage should change",
      "Replace sensor and verify signal during crank"],
     related=["P0390", "P0392"],
     difficulty="medium", cost="$50-$400")

# ---------------------------------------------------------------------------
# Powertrain — Emissions / EGR / Secondary Air / EVAP (P0405-P0470 gaps)
# ---------------------------------------------------------------------------

_add("P0405", "medium", "EGR sensor A circuit low — EGR position unknown",
     ["EGR position sensor failed", "Wiring short to ground",
      "Connector corroded", "EGR valve carbon-fouled affecting sensor"],
     ["Check EGR sensor voltage with KOEO — should be ~0.5-1.0V at rest",
      "Inspect connector for corrosion or carbon buildup",
      "Check wiring for short to ground",
      "Command EGR open with scan tool — voltage should increase"],
     related=["P0406", "P0400", "P0401"],
     difficulty="medium", cost="$100-$400",
     notes="Some EGR valves have integral position sensors. If sensor is part of the valve, replace the entire unit.")

_add("P0406", "medium", "EGR sensor A circuit high — possible stuck-open EGR",
     ["EGR position sensor shorted high", "Wiring short to 5V reference",
      "Sensor failed", "EGR valve physically stuck open"],
     ["Check EGR sensor voltage — should not be pegged at 5V",
      "Inspect for wiring shorts to reference voltage",
      "Command EGR closed with scan tool — voltage should drop to ~0.5V",
      "If valve is stuck open, engine will idle rough or stall"],
     related=["P0405", "P0402"],
     difficulty="medium", cost="$100-$400")

_add("P0412", "medium", "Secondary air injection switching valve A circuit — emissions failure",
     ["SAI switching valve solenoid failed", "Wiring open or shorted",
      "Relay fault", "Fuse blown"],
     ["Check SAI relay and fuse",
      "Measure voltage at switching valve connector with engine cold",
      "Check wiring continuity from relay to valve",
      "Listen for valve click when commanded"],
     related=["P0410", "P0411", "P0413"],
     difficulty="medium", cost="$100-$400",
     notes="SAI activates during cold start to help light off the catalytic converter. Common on VW/Audi, BMW, GM.")

_add("P0413", "medium", "Secondary air injection switching valve A circuit open",
     ["Switching valve solenoid open circuit", "Connector corroded",
      "Wiring break", "Valve coil burned out"],
     ["Measure solenoid resistance (typically 20-40Ω)",
      "Check connector pins for corrosion",
      "Check wiring continuity from ECM/relay to valve",
      "Replace valve if coil is open"],
     related=["P0410", "P0412", "P0414"],
     difficulty="medium", cost="$100-$400")

_add("P0414", "medium", "Secondary air injection switching valve A circuit shorted",
     ["Switching valve solenoid shorted", "Wiring short to ground or power",
      "Connector water intrusion", "Valve internal failure"],
     ["Measure solenoid resistance — should not be near 0Ω",
      "Inspect wiring for chafing or exposed conductors",
      "Check for water in connector",
      "Replace valve if shorted internally"],
     related=["P0410", "P0412", "P0413"],
     difficulty="medium", cost="$100-$400")

_add("P0415", "medium", "Secondary air injection switching valve B circuit — emissions only",
     ["SAI switching valve B failed", "Wiring fault",
      "Relay or fuse issue", "Valve stuck mechanically"],
     ["Check SAI system B relay and fuse",
      "Measure voltage at valve B connector",
      "Check wiring from relay to valve",
      "Inspect valve for physical damage or corrosion"],
     related=["P0410", "P0412"],
     difficulty="medium", cost="$100-$400")

_add("P0418", "medium", "Secondary air injection relay A circuit — SAI system inoperative",
     ["SAI relay failed", "Relay control circuit open",
      "Fuse blown", "ECM relay driver fault"],
     ["Check SAI relay — swap with identical relay to test",
      "Check relay fuse",
      "Measure voltage at relay coil terminal with engine cold start",
      "Check ECM relay control output"],
     related=["P0410", "P0411", "P0412"],
     difficulty="easy", cost="$30-$200",
     notes="Relay is often in the underhood fuse box. Swap-test with a known-good identical relay before replacing.")

_add("P0445", "low", "EVAP purge control valve circuit shorted — possible fuel odor",
     ["Purge solenoid shorted internally", "Wiring short to ground",
      "Connector water intrusion", "ECM driver circuit damaged"],
     ["Measure purge solenoid resistance (typically 20-40Ω)",
      "Check wiring for shorts to ground",
      "Inspect connector for moisture",
      "Replace solenoid if resistance is near 0Ω"],
     related=["P0443", "P0441", "P0446"],
     difficulty="easy", cost="$30-$150")

_add("P0447", "low", "EVAP vent control valve circuit open — EVAP monitors will not run",
     ["EVAP vent valve solenoid open circuit", "Connector corroded",
      "Wiring break — often near gas tank area", "Solenoid coil failed"],
     ["Check vent valve connector near charcoal canister",
      "Measure solenoid resistance (typically 15-30Ω)",
      "Check wiring continuity from ECM to vent valve",
      "Replace vent valve if coil is open"],
     related=["P0446", "P0449", "P0455"],
     difficulty="easy", cost="$30-$200",
     notes="Vent valve is usually near the charcoal canister, often under the vehicle near the fuel tank.")

_add("P0448", "low", "EVAP vent control valve circuit shorted — fuel odor possible",
     ["Vent valve solenoid shorted", "Wiring short to ground",
      "Water or dirt in connector", "Solenoid failed"],
     ["Measure vent valve resistance — should not be near 0Ω",
      "Inspect wiring for damage, especially undercar routing",
      "Check connector for contamination",
      "Replace vent valve if shorted"],
     related=["P0446", "P0447", "P0449"],
     difficulty="easy", cost="$30-$200")

_add("P0458", "low", "EVAP purge control valve circuit low — purge valve stuck open possible",
     ["Purge valve solenoid shorted to ground", "Wiring fault",
      "ECM low-side driver issue", "Valve stuck open (fuel vapors entering intake)"],
     ["Check purge valve connector voltage",
      "Measure solenoid resistance",
      "Check wiring for shorts to ground",
      "If valve stuck open, engine may run rich at idle — check fuel trims"],
     related=["P0443", "P0459", "P0441"],
     difficulty="easy", cost="$30-$150",
     notes="A stuck-open purge valve can cause rich idle and even a flooded start condition.")

_add("P0459", "low", "EVAP purge control valve circuit high — purge valve inoperative",
     ["Purge valve solenoid open circuit", "Wiring open",
      "Connector disconnected", "Solenoid coil failed"],
     ["Check purge valve connector — verify it's plugged in",
      "Measure solenoid resistance — infinite means open coil",
      "Check wiring from ECM to valve for opens",
      "Replace purge valve solenoid"],
     related=["P0443", "P0458", "P0441"],
     difficulty="easy", cost="$30-$150")

_add("P0461", "low", "Fuel level sensor circuit range/performance — fuel gauge erratic",
     ["Fuel level sender unit worn or sticking", "Float stuck or damaged",
      "Fuel sloshing causing erratic signal", "Wiring intermittent"],
     ["Monitor fuel level PID while driving — should be smooth, not jumping",
      "Check wiring connection at fuel pump module",
      "Tap on fuel tank while watching gauge — sender may be sticking",
      "Replace fuel level sender (usually part of fuel pump module)"],
     related=["P0460", "P0462", "P0463"],
     difficulty="medium", cost="$100-$500",
     notes="Fuel sender is inside the tank — often replaced with the fuel pump as an assembly.")

_add("P0462", "low", "Fuel level sensor circuit low input — gauge reads empty",
     ["Fuel level sender shorted to ground", "Wiring short to ground",
      "Sender worn through resistive element", "Connector corroded"],
     ["Check fuel level PID — should not be pegged at 0%",
      "Disconnect sender connector — gauge should go to full (or PID to max)",
      "Inspect wiring for shorts to ground",
      "Replace fuel pump module with sender if sender is faulty"],
     related=["P0460", "P0461", "P0463"],
     difficulty="medium", cost="$100-$500")

_add("P0463", "low", "Fuel level sensor circuit high input — gauge reads full constantly",
     ["Fuel level sender open circuit", "Connector disconnected or corroded",
      "Wiring open between sender and ECM/cluster", "Float stuck at full position"],
     ["Check if connector is plugged in at fuel pump module",
      "Measure sender resistance — should vary as fuel changes (typically 10-180Ω or 40-250Ω)",
      "Check wiring for opens",
      "Replace sender/fuel pump module if resistance is infinite"],
     related=["P0460", "P0461", "P0462"],
     difficulty="medium", cost="$100-$500")

_add("P0464", "low", "Fuel level sensor circuit intermittent — gauge bounces",
     ["Fuel level sender contact arm worn", "Intermittent wiring connection",
      "Connector with loose pin", "Fuel sloshing with weak signal ground"],
     ["Monitor fuel level PID during driving — note pattern of dropouts",
      "Wiggle-test connector at fuel pump module",
      "Check wiring and ground circuit for intermittent connection",
      "Replace sender unit if wiggle test causes signal dropout"],
     related=["P0460", "P0461"],
     difficulty="medium", cost="$100-$500")

_add("P0465", "low", "Purge flow sensor circuit malfunction — EVAP monitor affected",
     ["Purge flow sensor failed", "Wiring fault",
      "Connector corroded", "Vacuum leak in EVAP system"],
     ["Check purge flow sensor voltage with scan tool",
      "Inspect connector for corrosion",
      "Check wiring continuity",
      "Verify EVAP system integrity with smoke test"],
     related=["P0441", "P0443", "P0466"],
     difficulty="medium", cost="$100-$300",
     notes="Purge flow sensors are not used on all vehicles. Common on some older GM and European vehicles.")

_add("P0466", "low", "Purge flow sensor circuit range/performance",
     ["Purge flow sensor degraded", "EVAP system leak affecting flow readings",
      "Carbon canister saturated", "Purge valve not opening fully"],
     ["Compare flow sensor reading to purge valve command %",
      "Check for EVAP leaks with smoke test",
      "Inspect carbon canister for saturation (fuel contamination)",
      "Replace flow sensor if EVAP system checks OK"],
     related=["P0465", "P0441"],
     difficulty="medium", cost="$100-$300")

_add("P0467", "low", "Purge flow sensor circuit low input",
     ["Sensor shorted to ground", "Wiring short", "Sensor failed",
      "No vacuum at sensor (purge valve not opening)"],
     ["Check sensor voltage — should not be at 0V when purge is commanded",
      "Verify purge valve is opening (vacuum should be present)",
      "Inspect wiring for shorts to ground",
      "Replace sensor if circuit and purge valve check OK"],
     related=["P0465", "P0468"],
     difficulty="medium", cost="$100-$300")

_add("P0468", "low", "Purge flow sensor circuit high input",
     ["Sensor shorted to reference voltage", "Wiring short to power",
      "Sensor failed high", "Connector fault"],
     ["Check sensor voltage — should not be pegged at reference voltage",
      "Inspect wiring for shorts to 5V or 12V sources",
      "Disconnect sensor — voltage should change",
      "Replace sensor if circuit checks OK"],
     related=["P0465", "P0467"],
     difficulty="medium", cost="$100-$300")

_add("P0469", "low", "Purge flow sensor circuit intermittent",
     ["Sensor connection intermittent", "Wiring with broken strands",
      "Connector pin tension loss", "Sensor failing under heat"],
     ["Wiggle-test connector while monitoring sensor voltage",
      "Check wiring for damage — flex points are common failure areas",
      "Heat sensor with heat gun — check if it drops out",
      "Replace sensor if intermittent failure confirmed"],
     related=["P0465", "P0466"],
     difficulty="medium", cost="$100-$300")

_add("P0470", "low", "Exhaust pressure sensor circuit malfunction",
     ["Exhaust pressure sensor failed", "Sensor tube plugged with soot (diesel)",
      "Wiring fault", "Connector corroded"],
     ["Check exhaust pressure sensor voltage at idle — should read near-atmospheric",
      "Inspect sensor tube for soot plugging (diesel engines)",
      "Check wiring and connector",
      "Verify sensor 5V reference and ground"],
     related=["P0471", "P0472", "P0473"],
     difficulty="medium", cost="$100-$400",
     notes="Most common on diesels with DPF systems. Exhaust back-pressure sensor monitors DPF loading.")

# ---------------------------------------------------------------------------
# Powertrain — Turbo/Supercharger (P0241-P0254 extras)
# ---------------------------------------------------------------------------

_add("P0241", "medium", "Turbo/supercharger wastegate solenoid A low — boost control issue",
     ["Wastegate solenoid shorted to ground", "Wiring fault",
      "Solenoid coil damaged", "ECM driver issue"],
     ["Check wastegate solenoid connector voltage",
      "Measure solenoid resistance (typically 10-30Ω)",
      "Check wiring for shorts to ground",
      "Command solenoid with scan tool — listen/feel for actuation"],
     related=["P0243", "P0234", "P0299"],
     difficulty="medium", cost="$100-$400")

_add("P0242", "medium", "Turbo/supercharger wastegate solenoid A high — boost may be excessive",
     ["Wastegate solenoid open circuit", "Wiring open",
      "Connector corroded", "Solenoid coil burned out"],
     ["Measure solenoid resistance — infinite = open coil",
      "Check connector for corrosion near turbo (heat damage common)",
      "Check wiring from ECM to solenoid for opens",
      "Replace solenoid if open circuit confirmed"],
     related=["P0243", "P0234"],
     difficulty="medium", cost="$100-$400",
     notes="If wastegate cannot be controlled, boost may run unchecked — possible overboost and limp mode.")

_add("P0244", "medium", "Turbo/supercharger wastegate solenoid A intermittent — boost fluctuates",
     ["Loose solenoid connector", "Corroded wiring near turbo",
      "Solenoid sticking mechanically", "Heat damage to wiring"],
     ["Wiggle-test solenoid connector while monitoring boost",
      "Inspect wiring routing near turbo/exhaust for heat damage",
      "Command solenoid at various duty cycles — should respond smoothly",
      "Replace solenoid if intermittent confirmed"],
     related=["P0243", "P0241", "P0242"],
     difficulty="medium", cost="$100-$400")

_add("P0245", "medium", "Turbo/supercharger wastegate solenoid B low",
     ["Wastegate solenoid B shorted to ground", "Wiring fault",
      "Solenoid coil damaged", "Connector issue"],
     ["Check solenoid B connector and voltage",
      "Measure coil resistance",
      "Check wiring for shorts to ground",
      "Command solenoid B with scan tool"],
     related=["P0243", "P0246"],
     difficulty="medium", cost="$100-$400")

_add("P0246", "medium", "Turbo/supercharger wastegate solenoid B high — boost may be uncontrolled",
     ["Wastegate solenoid B open circuit", "Wiring open from heat damage",
      "Connector corroded or melted", "Solenoid coil failed"],
     ["Measure solenoid B resistance — infinite = open",
      "Inspect wiring near turbo for heat/melt damage",
      "Check connector for corrosion",
      "Replace solenoid if coil is open"],
     related=["P0243", "P0245", "P0247"],
     difficulty="medium", cost="$100-$400")

_add("P0247", "medium", "Turbo/supercharger wastegate solenoid B intermittent",
     ["Solenoid B connection loose", "Wiring damaged (heat, vibration)",
      "Solenoid sticking", "ECM driver intermittent"],
     ["Wiggle-test connector while monitoring boost PID",
      "Inspect wiring at heat-exposed areas",
      "Check solenoid actuation with commanded duty cycles",
      "Replace solenoid if intermittent faults persist"],
     related=["P0245", "P0246"],
     difficulty="medium", cost="$100-$400")

_add("P0248", "medium", "Turbo/supercharger wastegate solenoid B range/performance",
     ["Wastegate mechanical binding", "Solenoid partially stuck",
      "Carbon buildup on wastegate flap", "Boost reference hose leak"],
     ["Check boost pressure response to wastegate commands",
      "Inspect wastegate actuator rod for free movement",
      "Check vacuum/pressure lines to wastegate for leaks or cracks",
      "Remove and clean wastegate if carbon buildup suspected"],
     related=["P0243", "P0245", "P0246"],
     difficulty="medium", cost="$100-$600",
     notes="Wastegate flaps can carbon up on direct-injection turbocharged engines. Inspect mechanical movement.")

_add("P0250", "medium", "Turbo/supercharger wastegate solenoid C — third wastegate circuit fault",
     ["Wastegate solenoid C failed", "Wiring fault",
      "Connector issue", "ECM driver circuit fault"],
     ["Check solenoid C connector and voltage",
      "Measure coil resistance",
      "Check wiring continuity from ECM",
      "Inspect for heat damage near turbo assembly"],
     related=["P0243", "P0234"],
     difficulty="medium", cost="$100-$400",
     notes="Solenoid C is uncommon — found on some twin-turbo or variable-geometry turbo systems.")

_add("P0253", "high", "Injection pump fuel metering control A low (diesel) — reduced power",
     ["Fuel metering valve shorted to ground", "Wiring fault",
      "Metering valve solenoid damaged", "ECM driver issue"],
     ["Check fuel metering valve connector voltage",
      "Measure solenoid resistance (typically 2-8Ω)",
      "Check wiring for shorts to ground",
      "Command metering valve with scan tool — check for response"],
     related=["P0254", "P0251", "P0200"],
     difficulty="hard", cost="$200-$800",
     notes="Common on common-rail diesel engines. Metering valve controls fuel volume to high-pressure pump.")

_add("P0254", "high", "Injection pump fuel metering control A high (diesel) — limp mode",
     ["Fuel metering valve open circuit", "Wiring open",
      "Connector corroded", "Solenoid coil burned out from overheat"],
     ["Measure metering valve resistance — infinite = failed",
      "Check connector for heat or fuel damage",
      "Check wiring from ECM to valve for opens",
      "Replace metering valve if solenoid is open"],
     related=["P0253", "P0251"],
     difficulty="hard", cost="$200-$800",
     notes="If metering valve fails open, engine may not develop pressure. No-start or severe power loss likely.")


# ---------------------------------------------------------------------------
# Body Control (B-codes)
# ---------------------------------------------------------------------------

_add("B0024", "medium", "Driver frontal stage 2 deployment control — restraint warning lamp on",
     ["Clockspring fault", "Airbag module connector corroded",
      "Wiring harness open/short in steering column", "Airbag control module internal fault"],
     ["Scan for related B-codes and check freeze-frame",
      "Inspect clockspring connector at steering column",
      "Measure resistance at airbag module connector — compare to spec",
      "Check wiring from RCM to driver airbag squib for opens/shorts"],
     related=["B0020", "B0026"],
     difficulty="hard", cost="$150-$600",
     notes="Always disconnect battery and wait 60 seconds before working near airbag circuits. Never measure squib with powered ohmmeter.")

_add("B0026", "medium", "Driver frontal stage 3 deployment control — restraint lamp on",
     ["Clockspring damaged", "Airbag squib resistance out of range",
      "Wiring short to ground in column", "RCM internal fault"],
     ["Check for multiple B002x codes — indicates clockspring or RCM",
      "Inspect clockspring continuity with battery disconnected",
      "Measure squib circuit resistance (typically 1.8-3.2 ohms)",
      "Check for water intrusion at steering column connectors"],
     related=["B0024", "B0020", "B0028"],
     difficulty="hard", cost="$150-$700",
     notes="Multiple stage deployment codes together strongly suggest clockspring failure or steering column wiring damage.")

_add("B0030", "medium", "Right frontal crash sensor circuit — restraint system fault",
     ["Right front crash sensor damaged (collision history)",
      "Wiring to right front sensor open/shorted", "Connector corroded from water splash",
      "Sensor mounting bracket bent or loose"],
     ["Check vehicle history for prior right front collision repair",
      "Inspect sensor mounting — must be torqued to spec",
      "Check wiring from RCM to right front sensor for opens",
      "Measure sensor resistance at RCM connector"],
     related=["B0040", "B0001"],
     difficulty="medium", cost="$100-$400",
     notes="Front crash sensors are often damaged during fender repairs and not replaced. Always check crash sensor mounting after body work.")

_add("B0040", "medium", "Left frontal crash sensor circuit — restraint system fault",
     ["Left front crash sensor damaged", "Wiring harness pinched during repair",
      "Connector water intrusion", "Sensor bracket corroded or loose"],
     ["Check for prior left front collision repair history",
      "Inspect sensor mounting bracket for corrosion or damage",
      "Test wiring continuity from RCM to left front sensor",
      "Swap-test with right side sensor if identical part number"],
     related=["B0030", "B0001"],
     difficulty="medium", cost="$100-$400",
     notes="On trucks and SUVs, these sensors mount low and are susceptible to road salt corrosion.")

_add("B0060", "medium", "Right side crash sensor — side impact detection circuit fault",
     ["Side crash sensor damaged from side impact", "B-pillar wiring harness damaged",
      "Water intrusion in door or B-pillar connector", "RCM side channel fault"],
     ["Check for prior side impact repair on right side",
      "Inspect B-pillar connector — remove trim panel",
      "Check wiring from sensor to RCM for continuity",
      "Check for water in door or B-pillar cavity"],
     related=["B0062", "B0001"],
     difficulty="medium", cost="$100-$350",
     notes="Side impact sensors are behind B-pillar trim. Carefully remove trim — clips break easily on older vehicles.")

_add("B0062", "medium", "Left side crash sensor — side impact detection circuit fault",
     ["Side crash sensor failed or damaged", "B-pillar wiring chafed",
      "Connector corroded", "Prior side impact damage not fully repaired"],
     ["Inspect left B-pillar for prior repair evidence",
      "Remove B-pillar trim and check sensor connector",
      "Measure wiring continuity from sensor to RCM",
      "Compare resistance reading to right side sensor"],
     related=["B0060", "B0001"],
     difficulty="medium", cost="$100-$350",
     notes="If both B0060 and B0062 set together, suspect RCM fault rather than individual sensors.")

_add("B0070", "medium", "Right side deployment loop stage 1 — side airbag circuit fault",
     ["Side curtain airbag connector loose", "Wiring harness pinched in headliner",
      "Airbag squib resistance out of range", "RCM side output driver fault"],
     ["Disconnect battery and wait 60 seconds",
      "Check side curtain airbag connector at C-pillar",
      "Inspect headliner wiring for pinch points",
      "Measure squib resistance at RCM connector"],
     related=["B0072", "B0060"],
     difficulty="hard", cost="$200-$800",
     notes="Side curtain airbag wiring runs through the headliner. Sunroof installations commonly damage this wiring.")

_add("B0072", "medium", "Left side deployment loop stage 1 — side airbag circuit fault",
     ["Side curtain airbag connector corroded", "Headliner wiring damaged",
      "Squib circuit open or shorted", "RCM internal fault"],
     ["Disconnect battery — mandatory before any airbag work",
      "Remove A-pillar and headliner trim to access wiring",
      "Check connector at side curtain airbag module",
      "Measure squib resistance — typically 1.8-3.2 ohms"],
     related=["B0070", "B0062"],
     difficulty="hard", cost="$200-$800",
     notes="On vehicles with panoramic sunroofs, the side curtain wiring is particularly vulnerable to damage.")

_add("B0080", "medium", "Right seat-mounted side airbag deployment loop — seat airbag fault",
     ["Seat side airbag connector under seat disconnected",
      "Wiring chafed from seat track movement", "Squib open circuit",
      "Seat cover replacement damaged wiring"],
     ["Check connector under right front seat",
      "Inspect wiring along seat track for chafing",
      "Measure squib resistance at seat connector",
      "Check if aftermarket seat covers were installed (common cause)"],
     related=["B0082", "B0081"],
     difficulty="medium", cost="$150-$500",
     notes="Aftermarket seat covers are the #1 cause of seat-mounted airbag codes. They compress wiring and disconnect plugs.")

_add("B0082", "medium", "Left seat-mounted side airbag deployment loop — seat airbag fault",
     ["Seat side airbag connector disconnected under seat",
      "Wiring damaged by objects under seat", "Squib resistance out of range",
      "Seat frame corrosion affecting ground"],
     ["Check connector under left front seat — slide seat fully back",
      "Look for wiring damage from objects stored under seat",
      "Measure squib resistance and compare to spec",
      "Check seat frame ground connection"],
     related=["B0080", "B0081"],
     difficulty="medium", cost="$150-$500",
     notes="Instruct customer: never store items under front seats. Objects commonly damage airbag wiring harness.")

_add("B0085", "medium", "Passenger frontal stage 1 deployment loop — passenger airbag circuit",
     ["Passenger airbag connector fault at dash",
      "Wiring from RCM to passenger airbag damaged", "Squib resistance out of spec",
      "Dashboard removal/reinstall disturbed connections"],
     ["Check for recent dash removal (HVAC work, radio install)",
      "Inspect passenger airbag connector behind glove box",
      "Measure squib resistance — compare to driver side",
      "Check wiring from RCM through dash harness"],
     related=["B0024", "B0091"],
     difficulty="hard", cost="$200-$700",
     notes="Dash removal for heater core or blend door repairs commonly disturbs passenger airbag wiring.")

_add("B0092", "low", "Passenger seat position sensor circuit — occupant classification issue",
     ["Seat position sensor connector corroded", "Sensor out of calibration",
      "Wiring to occupant classification module damaged", "Seat track debris"],
     ["Check seat position sensor connector under seat",
      "Clear code and move seat through full range of travel",
      "Inspect wiring along seat track", "Check for seat track debris/obstruction"],
     related=["B0091", "B0095"],
     difficulty="easy", cost="$50-$250",
     notes="This code may cause the passenger airbag off light to illuminate. Clean seat tracks and check connectors first.")

_add("B0096", "low", "Occupant classification system malfunction — passenger airbag status unknown",
     ["Occupant classification module failed", "Seat bladder sensor leaking (weight detection)",
      "Wiring harness fault to OCS module", "Seat foam deteriorated over sensor"],
     ["Check passenger airbag off indicator behavior",
      "Inspect OCS module under passenger seat",
      "Test seat bladder pressure sensor if applicable",
      "Check wiring from seat to OCS module"],
     related=["B0092", "B0095"],
     difficulty="medium", cost="$200-$800",
     notes="On GM vehicles, OCS module replacement requires dealer-level recalibration with Tech2/GDS2.")

_add("B0100", "low", "Electronic frontal sensor module communication — data link issue",
     ["Front sensor module lost communication", "CAN bus wiring at sensor damaged",
      "Front sensor module power supply fault", "RCM not receiving sensor data"],
     ["Check front crash sensor CAN wiring",
      "Verify sensor module has power and ground",
      "Check for CAN bus network DTCs (U-codes)",
      "Inspect front sensor module connector for water intrusion"],
     related=["B0030", "B0040", "U0001"],
     difficulty="medium", cost="$100-$400",
     notes="This is a communication code — check CAN bus integrity before replacing sensors.")

_add("B0105", "low", "Rear crash sensor circuit — rear impact detection fault",
     ["Rear crash sensor damaged from rear collision", "Wiring in trunk/hatch area damaged",
      "Connector corroded from trunk water leak", "Sensor bracket loose"],
     ["Check for prior rear-end collision history",
      "Inspect trunk area for water intrusion",
      "Check rear crash sensor mounting and connector",
      "Test wiring from rear sensor to RCM"],
     related=["B0100", "B0001"],
     difficulty="medium", cost="$100-$350",
     notes="Trunk water leaks commonly corrode rear crash sensor connectors. Check trunk seal and drain tubes.")

_add("B0110", "low", "Rollover sensor circuit — rollover detection system fault",
     ["Rollover sensor failed", "Sensor mounting bracket shifted from impact",
      "Wiring to rollover sensor damaged", "RCM internal rollover channel fault"],
     ["Check rollover sensor — usually mounted on center console or headliner",
      "Inspect sensor mounting for proper orientation",
      "Verify wiring continuity from sensor to RCM",
      "Check for related crash sensor codes"],
     related=["B0100", "B0105"],
     difficulty="medium", cost="$100-$400",
     notes="Rollover sensors are sensitive to mounting angle. Even small bracket deformation can cause false codes.")

_add("B0115", "low", "Yaw rate/lateral acceleration sensor circuit — stability link to restraints",
     ["Yaw rate sensor fault affecting SRS system", "CAN communication issue to yaw sensor",
      "Sensor needs recalibration after replacement", "Wiring fault at sensor connector"],
     ["Check for concurrent C-codes (stability system)",
      "Verify yaw rate sensor communication on CAN bus",
      "Inspect sensor connector — typically center tunnel area",
      "If recently replaced, sensor may need zero-point calibration"],
     related=["B0110", "C0131"],
     difficulty="medium", cost="$150-$500",
     notes="This B-code sets when the SRS system can't read yaw data for rollover detection. Fix the yaw sensor C-code first.")

_add("B1100", "low", "Power window motor circuit — driver window inoperative or slow",
     ["Window motor brushes worn", "Window regulator binding or bent track",
      "Power window switch contact failure", "Wiring fault in door harness"],
     ["Check power and ground at window motor connector",
      "Operate switch — listen for motor running without glass movement (regulator issue)",
      "Test switch with voltmeter in both directions",
      "Check door harness flex area between door and body"],
     related=["B1110", "B1120"],
     difficulty="easy", cost="$50-$300",
     notes="Before replacing motor, lubricate window tracks with silicone spray. Binding regulators kill motors prematurely.")

_add("B1110", "low", "Power window motor circuit — passenger front window fault",
     ["Window motor failed", "Regulator cable frayed or broken",
      "Window switch fault", "Door harness wiring break at flex point"],
     ["Test motor by applying 12V directly (bypassing switch)",
      "Inspect regulator cables for fraying",
      "Check master switch passenger lock-out function",
      "Inspect door harness at body-to-door flex boot"],
     related=["B1100", "B1120"],
     difficulty="easy", cost="$50-$300",
     notes="On cable-type regulators, listen for motor spinning freely — indicates broken cable, not bad motor.")

_add("B1120", "low", "Power door lock circuit — door lock actuator fault",
     ["Door lock actuator motor failed", "Lock rod disconnected from actuator",
      "Door lock switch fault", "Wiring break in door harness at flex boot"],
     ["Operate lock — listen for actuator click without rod movement",
      "Check lock rod attachment at actuator",
      "Apply 12V directly to actuator to confirm motor function",
      "Inspect door harness at flex boot for broken wires"],
     related=["B1100", "B1110"],
     difficulty="easy", cost="$40-$200",
     notes="Most door lock actuator failures are mechanical (stripped gears), not electrical. Replace the actuator assembly.")


# ---------------------------------------------------------------------------
# Chassis (C-codes)
# ---------------------------------------------------------------------------

_add("C0020", "high", "ABS pump motor circuit — ABS pump inoperative",
     ["ABS pump motor failed", "Pump relay fault", "Wiring to pump motor open/shorted",
      "ABS module internal driver burned out"],
     ["Check ABS pump relay — swap with known-good relay",
      "Measure voltage at pump motor connector while commanding pump on with scan tool",
      "Check ground at ABS module — corrosion is common",
      "If power and ground are good but pump doesn't run, pump motor is failed"],
     related=["C0025", "C0031"],
     difficulty="hard", cost="$300-$1200",
     notes="ABS pump motor replacement often requires bleeding the ABS modulator with a scan tool. Budget for brake flush.")

_add("C0025", "high", "ABS pump motor circuit performance — pump doesn't build expected pressure",
     ["Pump motor weak (brushes worn)", "Brake fluid contaminated",
      "Internal check valve leak in ABS modulator", "Low brake fluid level"],
     ["Check brake fluid level and condition first",
      "Command pump on with scan tool — should hear strong steady hum",
      "Measure pump current draw — compare to spec (typically 10-20A)",
      "If pump runs but doesn't build pressure, check internal modulator valves"],
     related=["C0020", "C0031"],
     difficulty="hard", cost="$300-$1200",
     notes="Dark or contaminated brake fluid destroys ABS pump internals. Recommend fluid flush every 3 years to prevent repeat failure.")

_add("C0033", "high", "Right front wheel speed sensor circuit — ABS/traction control fault",
     ["Wheel speed sensor air gap too large", "Tone ring damaged or missing teeth",
      "Sensor wiring chafed at wheel well", "Sensor connector corroded"],
     ["Check right front wheel speed sensor output with scan tool — compare all 4 wheels",
      "Inspect tone ring for damage — remove wheel if needed",
      "Check sensor air gap — should be 0.5-1.5mm typically",
      "Inspect sensor connector and wiring through wheel well"],
     related=["C0036", "C0031"],
     difficulty="easy", cost="$50-$200",
     notes="Wheel speed sensor codes after brake work usually mean the tone ring was damaged during rotor removal. Check ring first.")

_add("C0036", "high", "Left front wheel speed sensor circuit — ABS/traction control disabled",
     ["Wheel speed sensor failed", "Tone ring cracked or missing teeth",
      "Wiring damage from road debris", "Hub bearing failing (integrated sensor)"],
     ["Compare all 4 wheel speed readings at 20 mph — erratic one is faulty",
      "Inspect left front tone ring through wheel opening",
      "Check sensor connector at inner fender for corrosion",
      "On integrated hub sensor designs, hub bearing replacement is required"],
     related=["C0033", "C0031"],
     difficulty="easy", cost="$50-$400",
     notes="Many modern vehicles integrate the wheel speed sensor into the hub bearing. Bearing replacement is the only fix.")

_add("C0041", "high", "Right rear wheel speed sensor circuit — ABS/stability fault",
     ["Wheel speed sensor gap contaminated with metallic debris",
      "Tone ring rust buildup (common on rear drums)",
      "Sensor wiring chafed at axle", "Sensor connector water intrusion"],
     ["Check right rear wheel speed with scan tool — should match left rear",
      "Clean tone ring surface — rust/debris accumulation is #1 cause on rears",
      "Inspect sensor and wiring at rear axle area",
      "Check connector for moisture — rear sensors are more exposed"],
     related=["C0046", "C0031"],
     difficulty="easy", cost="$50-$200",
     notes="Rear tone rings on drum brake vehicles accumulate rust that disrupts the sensor signal. Wire-brush the ring clean.")

_add("C0046", "high", "Left rear wheel speed sensor circuit — ABS/stability disabled",
     ["Wheel speed sensor failed", "Tone ring damaged from brake drum removal",
      "Wiring damaged along rear axle", "Hub bearing worn (integrated sensor type)"],
     ["Compare left rear to right rear speed readings on scan tool",
      "Inspect tone ring for physical damage",
      "Check wiring along rear axle routing — exposed to road hazards",
      "If integrated hub sensor, check for bearing play"],
     related=["C0041", "C0031"],
     difficulty="easy", cost="$50-$400",
     notes="On solid rear axles, tone ring is pressed on the axle shaft. Removal requires pulling the axle shaft.")

_add("C0051", "medium", "ABS solenoid valve circuit — valve response issue",
     ["ABS solenoid stuck or sluggish", "Wiring to solenoid intermittent",
      "ABS module internal driver fault", "Contaminated brake fluid gumming valve"],
     ["Check brake fluid condition — dark fluid causes solenoid sticking",
      "Command solenoid operation with scan tool — listen for clicks",
      "Check wiring at ABS module connector for corrosion",
      "If solenoid is internal to modulator, unit replacement is likely needed"],
     related=["C0050", "C0055"],
     difficulty="hard", cost="$300-$1000",
     notes="Internal ABS solenoid faults usually mean ABS modulator replacement. These are not individually serviceable on most vehicles.")

_add("C0056", "medium", "ABS solenoid valve rear circuit — rear brake ABS modulation fault",
     ["Rear ABS solenoid sticking", "Brake fluid contamination",
      "ABS modulator internal fault", "Wiring or connector issue at module"],
     ["Perform brake fluid flush and retest",
      "Command rear solenoid with scan tool",
      "Check ABS module connector for corrosion — typically underbody mounted",
      "Compare rear brake performance to front during ABS stop"],
     related=["C0051", "C0055"],
     difficulty="hard", cost="$300-$1000",
     notes="On trucks with rear ABS only (older models), this solenoid is in a standalone modulator on the frame rail.")

_add("C0061", "medium", "Traction control brake solenoid circuit — TCS inoperative",
     ["TCS solenoid in ABS module stuck", "Module driver fault",
      "Wiring issue at ABS/TCS module", "Brake fluid contamination affecting valve"],
     ["Check for concurrent ABS codes — shared system",
      "Command TCS solenoid with scan tool",
      "Flush brake fluid if dark or contaminated",
      "Check module connector — especially ground pins"],
     related=["C0060", "C0065"],
     difficulty="hard", cost="$300-$1000",
     notes="TCS and ABS share the same hydraulic modulator. TCS codes often appear alongside ABS solenoid codes.")

_add("C0071", "medium", "ABS enable relay circuit — ABS system cannot engage",
     ["ABS relay failed", "Relay control circuit open",
      "ABS fuse blown", "ABS module not commanding relay on"],
     ["Check ABS fuse in underhood fuse box",
      "Swap ABS relay with identical relay from same box",
      "Check for 12V at relay coil terminal when ignition is on",
      "If relay and fuse are OK, check ABS module relay driver output"],
     related=["C0070", "C0020"],
     difficulty="easy", cost="$20-$150",
     notes="Always check the simple stuff first — fuses and relays. An $8 relay is the cheapest ABS fix possible.")

_add("C0080", "medium", "Steering position sensor circuit — stability system degraded",
     ["Steering angle sensor needs calibration", "Sensor clock spring damaged",
      "CAN bus issue at sensor", "Sensor failed internally"],
     ["Clear code and perform steering angle sensor calibration with scan tool",
      "Drive in a circle both directions to auto-calibrate (some vehicles)",
      "Check clockspring — shares the same column wiring",
      "Check for CAN communication DTCs related to steering module"],
     related=["C0085", "C0131"],
     difficulty="medium", cost="$100-$500",
     notes="After any alignment or steering linkage work, a steering angle sensor calibration/reset is required on stability-equipped vehicles.")

_add("C0085", "medium", "Steering position sensor signal range — erratic steering angle data",
     ["Steering angle sensor out of calibration", "Sensor internal fault",
      "Wiring intermittent at clockspring", "CAN bus noise affecting signal"],
     ["Perform zero-point calibration with scan tool (mandatory first step)",
      "Monitor steering angle live data — should change smoothly with wheel turn",
      "Check for loose steering column components",
      "Inspect clockspring connector"],
     related=["C0080", "C0131"],
     difficulty="medium", cost="$100-$500",
     notes="This code commonly sets after tire rotation if TPMS relearn wasn't done, or after alignment. Calibrate sensor first.")

_add("C0090", "medium", "Lateral acceleration sensor — stability control reference fault",
     ["Lateral G sensor failed", "Sensor mounting shifted",
      "Wiring fault at sensor connector", "CAN bus communication issue"],
     ["Check lateral acceleration reading on scan tool — should be ~0g at rest on flat surface",
      "Inspect sensor mounting — usually under center console",
      "Check connector for corrosion or loose pins",
      "Verify CAN bus communication from sensor module"],
     related=["C0095", "C0131"],
     difficulty="medium", cost="$150-$400",
     notes="Lateral G sensor must be mounted level. If the mounting bracket is bent, replace it — don't try to shim.")

_add("C0095", "medium", "Yaw rate sensor circuit — stability system disabled",
     ["Yaw rate sensor failed", "Sensor needs zero-point recalibration",
      "Wiring or connector fault", "CAN bus communication error"],
     ["Check yaw rate on scan tool — should read 0°/s with vehicle stationary on flat ground",
      "Perform zero-point calibration with scan tool",
      "Inspect yaw rate sensor connector — center tunnel area",
      "Check for CAN bus DTCs that may be causing secondary fault"],
     related=["C0090", "C0131"],
     difficulty="medium", cost="$150-$500",
     notes="Many combined yaw/lateral G sensor modules require dealer-level scan tool for calibration. Aftermarket tools may not support it.")

_add("C0115", "medium", "ABS motor relay circuit — ABS motor cannot be powered",
     ["ABS motor relay failed or stuck open", "Relay control coil open",
      "Fuse for ABS motor circuit blown", "ABS module relay driver fault"],
     ["Check ABS motor relay — swap-test with identical relay",
      "Check fuse for ABS pump motor circuit",
      "Measure relay coil control signal from ABS module",
      "If relay is being commanded but not closing, replace relay"],
     related=["C0071", "C0020"],
     difficulty="easy", cost="$20-$200",
     notes="Some vehicles use separate relays for ABS motor and ABS valve power. Check both.")


# ---------------------------------------------------------------------------
# Network Communication (U-codes)
# ---------------------------------------------------------------------------

_add("U0005", "medium", "CAN bus high speed communication — bus off condition detected",
     ["CAN-H or CAN-L wire shorted to ground", "CAN bus terminating resistor open",
      "Module flooding bus with errors", "Wiring damage in main CAN backbone"],
     ["Measure CAN bus resistance at DLC — should be ~60 ohms (two 120-ohm terminators in parallel)",
      "Check for 2.5V on CAN-H and 2.5V on CAN-L at rest",
      "Disconnect modules one at a time to isolate faulty node",
      "Inspect CAN bus wiring harness for damage, chafing, or shorts"],
     related=["U0001", "U0008"],
     difficulty="hard", cost="$100-$800",
     notes="Bus-off means the bus was so corrupted the module stopped communicating. Start with resistance and voltage checks at the DLC.")

_add("U0008", "medium", "CAN bus slow speed communication — low-speed bus fault",
     ["LS-CAN wiring shorted", "Module pulling bus down",
      "Termination resistor fault on LS bus", "Connector corrosion at body module"],
     ["Measure LS-CAN bus resistance at DLC",
      "Check voltage levels on LS-CAN (single-wire: ~0V idle, ~5V dominant)",
      "Disconnect body control modules one at a time to isolate",
      "Inspect wiring to door modules, seat modules, and mirror modules"],
     related=["U0005", "U0001"],
     difficulty="hard", cost="$100-$600",
     notes="LS-CAN typically connects comfort modules (windows, mirrors, seats). These wires route through doors and are vulnerable to flex damage.")

_add("U0011", "medium", "Medium speed CAN communication — MS-CAN bus fault",
     ["MS-CAN backbone wiring damaged", "Module on MS-CAN pulling bus down",
      "Gateway module not forwarding messages", "Connector issue at accessible module"],
     ["Measure MS-CAN bus resistance at DLC pins 3 and 11",
      "Check for gateway module DTCs — it bridges HS and MS-CAN",
      "Disconnect MS-CAN modules (cluster, HVAC, audio) one at a time",
      "Inspect wiring behind dashboard where MS-CAN modules cluster together"],
     related=["U0005", "U0014"],
     difficulty="hard", cost="$100-$600",
     notes="Ford vehicles commonly use MS-CAN on pins 3/11 for cluster, HVAC, and audio. OBDLink MX+ can monitor MS-CAN directly.")

_add("U0014", "medium", "Medium speed CAN bus performance — intermittent MS-CAN faults",
     ["Intermittent wiring contact on MS-CAN", "Module brownout causing bus errors",
      "Poor connector contact at MS-CAN module", "CAN transceiver degrading in a module"],
     ["Monitor MS-CAN error counters if available",
      "Wiggle-test connectors while monitoring bus with scan tool",
      "Check power and ground supply to all MS-CAN modules",
      "Look for intermittent connection at DLC pins 3 and 11"],
     related=["U0011", "U0005"],
     difficulty="hard", cost="$100-$600",
     notes="Intermittent CAN codes are the hardest to diagnose. Use a CAN bus monitor to capture errors in real time.")

_add("U0020", "high", "Module communication timeout — generic module not responding on expected bus",
     ["Module powered off or fuse blown", "CAN bus wiring open to module",
      "Module internal failure", "Gateway not routing messages"],
     ["Check fuse for the affected module",
      "Verify module has battery power and ignition power",
      "Check CAN bus wiring continuity to the module",
      "If all modules lost, suspect bus issue or gateway failure"],
     related=["U0001", "U0100"],
     difficulty="medium", cost="$50-$500",
     notes="U0020 is a generic timeout code. Check which specific module is not responding — there may also be a specific U01xx code set.")

_add("U0029", "medium", "Communication bus initialization failure — bus did not wake up properly",
     ["Module stuck in sleep mode", "Wake-up signal wire open",
      "Battery voltage too low for bus startup", "Gateway/BCM not issuing wake-up"],
     ["Check battery voltage — must be above 10.5V for reliable CAN startup",
      "Verify ignition switch input to gateway/BCM",
      "Check wake-up circuit wiring if applicable",
      "Try disconnecting battery for 30 seconds to force module re-initialization"],
     related=["U0020", "U0001"],
     difficulty="medium", cost="$50-$300",
     notes="Low battery voltage is the most common cause. Parasitic drains can prevent proper bus wake-up on next start.")

_add("U0035", "medium", "CAN bus communication — door module bus segment fault",
     ["Door module CAN wiring damaged at flex boot", "Door module power loss",
      "Connector corroded from water intrusion into door",
      "Door module internal CAN transceiver fault"],
     ["Check door module fuse", "Inspect door harness at body-to-door flex boot",
      "Check for water in door — drain holes may be plugged",
      "Test CAN bus at door module connector"],
     related=["U0008", "B1120"],
     difficulty="medium", cost="$100-$400",
     notes="Door harness flex boots crack with age. Water enters and corrodes wiring. Check BOTH the boot and the door drain holes.")

_add("U0041", "medium", "CAN bus communication — body electrical segment fault",
     ["Body CAN wiring damaged at junction", "BCM not forwarding messages",
      "Fuse/power issue to body modules", "Connector corrosion under dash or at kick panel"],
     ["Check BCM fuses and power supply",
      "Inspect body bus wiring at junction points under dash",
      "Check for water intrusion at kick panel connectors",
      "Test CAN bus voltage at body module connectors"],
     related=["U0035", "U0001"],
     difficulty="medium", cost="$100-$500",
     notes="Body bus wiring often runs through the kick panel area, which is prone to water leaks from windshield seal or A/C drain.")

_add("U0050", "medium", "Communication with climate control module lost — HVAC not responding",
     ["HVAC control module fuse blown", "HVAC module internal failure",
      "CAN bus wiring to HVAC module damaged", "Module connector corroded"],
     ["Check HVAC module fuse", "Verify HVAC module has power and ground",
      "Check CAN bus wiring at HVAC module behind center dash",
      "Try unplugging and reconnecting HVAC module to reseat connector"],
     related=["U0055", "U0041"],
     difficulty="medium", cost="$100-$500",
     notes="On many vehicles, the HVAC module is on a sub-bus behind the radio/center stack. Check for aftermarket radio install issues.")

_add("U0055", "medium", "Accessory protocol interface module communication — comfort system link lost",
     ["Accessory module fuse blown", "Module CAN bus wiring open",
      "Module internal failure", "Connector water intrusion"],
     ["Check fuse for accessory protocol module",
      "Inspect module connector — location varies by manufacturer",
      "Check CAN bus wiring for continuity",
      "Monitor CAN bus traffic to confirm module is or isn't transmitting"],
     related=["U0050", "U0041"],
     difficulty="medium", cost="$100-$400",
     notes="This module handles seat memory, mirror memory, and keyless features on some platforms.")

_add("U0064", "medium", "Communication with rear HVAC module lost — rear climate inoperative",
     ["Rear HVAC module fuse blown", "CAN wiring to rear module damaged",
      "Rear HVAC module internal fault", "Auxiliary bus communication fault"],
     ["Check rear HVAC fuse — often in rear fuse panel or under rear seat",
      "Verify rear HVAC module power and ground",
      "Check CAN wiring running to rear of vehicle",
      "Test connector at rear HVAC module for corrosion"],
     related=["U0050", "U0041"],
     difficulty="medium", cost="$100-$500",
     notes="Rear HVAC CAN wiring runs under carpet and is susceptible to water damage from sunroof drains that overflow or clog.")

_add("U0070", "medium", "Communication with parking assist module lost — park sensors inoperative",
     ["Park assist module fuse blown", "Module connector corroded (trunk/hatch area)",
      "CAN bus wiring damaged at rear of vehicle", "Module internal failure"],
     ["Check park assist module fuse",
      "Inspect module — typically in trunk or behind rear bumper",
      "Check module connector for water intrusion",
      "Verify CAN bus wiring continuity to module"],
     related=["U0075", "U0041"],
     difficulty="easy", cost="$50-$400",
     notes="Park assist modules mounted behind the rear bumper are vulnerable to water and road salt. Check connector first.")

_add("U0075", "medium", "Communication with park assist front module — front park sensors inoperative",
     ["Front park assist module lost power", "Wiring damaged at front bumper area",
      "Module failed from water/heat exposure", "CAN bus fault to module"],
     ["Check module power supply and fuse",
      "Inspect front bumper area wiring — often damaged in minor front impacts",
      "Check CAN bus wiring to module",
      "Verify module is communicating on network with scan tool"],
     related=["U0070", "U0041"],
     difficulty="easy", cost="$50-$400",
     notes="Minor front impacts often damage park assist module wiring even when the bumper cover looks fine. Pull the cover and inspect.")

_add("U0110", "medium", "Communication with drive motor control module lost — EV/hybrid drive fault",
     ["HV drive motor controller fuse blown", "CAN bus wiring to motor controller damaged",
      "Motor controller internal fault", "HV interlock open"],
     ["Check HV system enable — all interlocks must be closed",
      "Verify module power supply including HV battery contactors",
      "Check CAN bus wiring to motor controller module",
      "Use manufacturer scan tool to check motor controller status"],
     related=["U0115", "U0100"],
     difficulty="hard", cost="$200-$2000",
     notes="HV system codes require HV safety training and equipment. Do not work on HV circuits without proper PPE and lockout procedure.")

_add("U0115", "medium", "Communication with electric motor/generator module — hybrid drivetrain link lost",
     ["Motor/generator control module communication lost",
      "CAN bus fault in HV system segment", "Module fuse or power relay open",
      "12V battery too low for module startup"],
     ["Check 12V battery voltage — hybrid systems are very sensitive to low 12V",
      "Verify HV battery is enabled and contactors are closed",
      "Check CAN wiring to motor/generator control module",
      "Inspect module connector — typically in engine bay or under floor"],
     related=["U0110", "U0100"],
     difficulty="hard", cost="$200-$2000",
     notes="On hybrids, a weak 12V battery causes cascading U-codes for all HV modules. Replace 12V battery first before chasing other codes.")

_add("U0122", "medium", "Communication with vehicle dynamics control module — stability system offline",
     ["Stability control module power loss", "CAN bus fault to module",
      "Module internal failure", "Low battery voltage"],
     ["Check stability control module fuse",
      "Verify module has 12V power and ground",
      "Check CAN bus wiring at module (usually near ABS modulator)",
      "Clear codes and test-drive to see if code returns"],
     related=["U0121", "C0131"],
     difficulty="medium", cost="$100-$800",
     notes="On most vehicles, ABS and stability share the same module. If U0122 sets with ABS codes, the combined module likely needs replacement.")

_add("U0126", "medium", "Communication with steering angle sensor module — stability inputs missing",
     ["Steering angle sensor unplugged", "Clockspring damaged affecting CAN line",
      "CAN wiring at steering column damaged", "Sensor module failed"],
     ["Check steering angle sensor connector at steering column",
      "Look for clockspring DTCs (B-codes) that may affect the same circuit",
      "Check CAN bus wiring at steering column — can be damaged during steering work",
      "Clear code and drive in circles to recalibrate if sensor was reconnected"],
     related=["U0122", "C0080"],
     difficulty="medium", cost="$100-$500",
     notes="This code commonly sets after steering column work (clockspring, lock cylinder, turn signal switch replacement).")

_add("U0141", "medium", "Communication with body control module A lost — multiple body functions down",
     ["BCM power supply fault", "Main CAN bus backbone wiring fault",
      "BCM internal failure", "Battery terminals corroded"],
     ["Check BCM fuses — there are typically 3-5 fuses for BCM functions",
      "Inspect battery terminals and ground connections",
      "Check CAN bus wiring at BCM connector — usually behind left kick panel",
      "If multiple modules are lost, suspect bus backbone or shared power/ground"],
     related=["U0140", "U0001"],
     difficulty="medium", cost="$100-$600",
     notes="BCM communication loss affects many systems simultaneously (lights, locks, windows). Always check power and grounds first.")

_add("U0152", "medium", "Communication with ride control module lost — adaptive suspension offline",
     ["Ride control module fuse blown", "CAN bus wiring damage",
      "Module connector corroded — typically chassis-mounted", "Module internal failure"],
     ["Check ride control module fuse",
      "Verify module has power and ground — module is usually chassis-mounted and exposed",
      "Check CAN bus wiring to module for chafing or corrosion",
      "Inspect module connector for water intrusion — common on underbody-mounted modules"],
     related=["U0151", "C0131"],
     difficulty="medium", cost="$100-$800",
     notes="Ride control modules mounted under the vehicle are exposed to road spray. Corroded connectors are the #1 cause of this code.")

_add("U0168", "medium", "Communication with vehicle security module — immobilizer link lost",
     ["Vehicle security module power loss", "CAN wiring to security module damaged",
      "Security module internal fault", "Key transponder communication issue"],
     ["Check security module fuse",
      "Verify module power and ground at connector",
      "Check if vehicle will start — security module fault may enable passive mode",
      "Check CAN bus wiring to security module (behind dash or steering column)"],
     related=["U0164", "U0140"],
     difficulty="medium", cost="$100-$600",
     notes="Security module communication loss can cause no-start or delayed start. Key relearn may be needed after repair.")


# ---------------------------------------------------------------------------
# Powertrain — Variable Valve Timing / VVT (P0010-P0049)
# ---------------------------------------------------------------------------

_add("P0010", "medium", "Intake camshaft position actuator circuit (Bank 1) — VVT solenoid circuit fault",
     ["VVT solenoid connector corroded", "Wiring to VVT solenoid open or shorted",
      "VVT solenoid coil failed (open/short)", "PCM driver circuit fault"],
     ["Check VVT solenoid connector for oil contamination and corrosion",
      "Measure solenoid coil resistance — typically 6-13 ohms",
      "Check wiring from PCM to solenoid for opens and shorts to ground",
      "Command solenoid with scan tool — listen for click"],
     related=["P0011", "P0012", "P0013"],
     difficulty="easy", cost="$30-$200",
     notes="This is a circuit code, not a timing code. Focus on wiring and solenoid resistance, not oil pressure or timing chain.")

_add("P0015", "medium", "Exhaust camshaft position timing over-retarded (Bank 1) — VVT timing fault",
     ["Oil passages clogged with sludge",
      "Exhaust VVT solenoid stuck or sluggish", "Timing chain stretched",
      "Low oil pressure to VVT actuator", "Wrong viscosity oil used"],
     ["Check engine oil level and condition — sludge is #1 cause",
      "Check oil pressure with mechanical gauge",
      "Monitor exhaust cam position vs. crank position on scan tool",
      "Command VVT solenoid and watch cam position change",
      "If chain stretched, check cam-crank correlation at idle"],
     related=["P0014", "P0013", "P0017"],
     difficulty="medium", cost="$50-$2000",
     notes="Oil change neglect is the root cause in most VVT timing codes. If passages are sludged, an engine flush may help. If chain is stretched, replacement is the only fix.")

_add("P0018", "high", "Crankshaft/camshaft position correlation — Bank 2 Sensor A over-range",
     ["Timing chain stretched on Bank 2", "Cam phaser failure",
      "VVT solenoid stuck on Bank 2", "Oil pressure loss to Bank 2 VVT system",
      "Incorrect cam timing after repair"],
     ["Verify cam-crank correlation on Bank 2 using scan tool angle data",
      "Check Bank 2 VVT solenoid operation — command on/off",
      "Inspect timing chain tensioner on Bank 2 side",
      "Compare Bank 1 and Bank 2 cam angles — large difference confirms Bank 2 issue"],
     related=["P0016", "P0019", "P0017"],
     difficulty="hard", cost="$500-$2500",
     notes="On V-engines, Bank 2 chain issues often require significant disassembly. Verify with cam angle data before tearing down the engine.")

_add("P0019", "high", "Crankshaft/camshaft position correlation — Bank 2 Sensor B over-range",
     ["Exhaust cam timing off on Bank 2", "Timing chain stretched (Bank 2 exhaust)",
      "Exhaust cam phaser failure", "VVT oil control valve stuck Bank 2 exhaust"],
     ["Check exhaust cam angle on Bank 2 vs. specification",
      "Compare Bank 2 exhaust cam angle to Bank 1 exhaust cam angle",
      "Command VVT solenoid for Bank 2 exhaust — watch for movement",
      "Inspect timing chain and tensioner on Bank 2 exhaust side"],
     related=["P0018", "P0017", "P0016"],
     difficulty="hard", cost="$500-$2500",
     notes="P0019 specifically targets the Bank 2 exhaust cam. Combined with P0018, it suggests complete Bank 2 timing chain failure.")

_add("P0020", "medium", "Intake camshaft position actuator circuit (Bank 2) — VVT solenoid circuit fault",
     ["VVT solenoid connector fault Bank 2", "Wiring open/shorted to solenoid",
      "Solenoid coil resistance out of spec", "PCM output driver fault"],
     ["Check Bank 2 intake VVT solenoid connector for oil contamination",
      "Measure solenoid resistance — compare to Bank 1 solenoid",
      "Check wiring from PCM to Bank 2 VVT solenoid",
      "Swap Bank 1 and Bank 2 solenoids to confirm solenoid vs. wiring issue"],
     related=["P0010", "P0021", "P0022"],
     difficulty="easy", cost="$30-$200",
     notes="Same solenoid design as Bank 1. If Bank 1 is working, swap solenoids as a diagnostic test.")

_add("P0021", "medium", "Intake camshaft position timing over-advanced (Bank 2) — VVT timing fault",
     ["VVT solenoid stuck in advanced position", "Oil sludge blocking return passage",
      "Cam phaser locking pin stuck", "Low oil pressure on Bank 2"],
     ["Check oil level and condition — sludge restricts VVT oil flow",
      "Monitor Bank 2 intake cam angle — compare to Bank 1",
      "Command VVT solenoid off — cam angle should return to base",
      "If cam stays advanced with solenoid off, phaser is stuck"],
     related=["P0022", "P0011", "P0020"],
     difficulty="medium", cost="$50-$2000",
     notes="If the cam phaser is stuck advanced, you'll hear a loud rattle on cold start. Phaser replacement requires timing cover removal.")

_add("P0022", "medium", "Intake camshaft position timing over-retarded (Bank 2) — VVT timing fault",
     ["VVT solenoid stuck in retarded position", "Oil passage blockage",
      "Timing chain stretched on Bank 2", "Low oil pressure"],
     ["Check oil level and condition first",
      "Monitor Bank 2 intake cam angle vs. spec",
      "Command VVT solenoid on — cam should advance",
      "If cam doesn't respond to solenoid command, check oil pressure to phaser"],
     related=["P0021", "P0012", "P0020"],
     difficulty="medium", cost="$50-$2000",
     notes="P0022 on Bank 2 with P0012 on Bank 1 together usually indicates system-wide oil flow problem — check oil pump and passages.")

_add("P0023", "medium", "Exhaust camshaft position actuator circuit (Bank 2) — VVT solenoid circuit fault",
     ["Exhaust VVT solenoid connector corroded Bank 2",
      "Wiring damage to Bank 2 exhaust solenoid", "Solenoid coil failed",
      "PCM exhaust VVT driver fault"],
     ["Check Bank 2 exhaust VVT solenoid connector",
      "Measure solenoid resistance and compare to spec",
      "Check wiring continuity from PCM to solenoid",
      "Swap with Bank 1 exhaust solenoid if same part number"],
     related=["P0013", "P0024", "P0025"],
     difficulty="easy", cost="$30-$200",
     notes="This is a circuit code for the Bank 2 exhaust VVT solenoid. Focus on electrical testing, not mechanical timing.")

_add("P0024", "medium", "Exhaust camshaft position timing over-advanced (Bank 2) — VVT timing fault",
     ["Oil sludge blocking VVT oil circuit", "Exhaust cam phaser stuck advanced",
      "VVT solenoid stuck open", "Low oil pressure to Bank 2 exhaust phaser"],
     ["Check oil condition — sludge is primary cause",
      "Monitor Bank 2 exhaust cam angle on scan tool",
      "Command exhaust VVT solenoid and observe cam response",
      "Compare Bank 2 exhaust to Bank 1 exhaust cam angles"],
     related=["P0025", "P0014", "P0023"],
     difficulty="medium", cost="$50-$2000",
     notes="Exhaust cam over-advanced causes rough idle and poor low-RPM torque. May set P0019 correlation code simultaneously.")

_add("P0025", "medium", "Exhaust camshaft position timing over-retarded (Bank 2) — VVT timing fault",
     ["Timing chain stretch on Bank 2", "Oil flow restriction to exhaust phaser",
      "VVT solenoid failed or stuck", "Cam phaser locking mechanism fault"],
     ["Check oil level and change interval history",
      "Monitor Bank 2 exhaust cam angle vs. commanded position",
      "Check timing chain tensioner — replace if extended fully",
      "Oil flush may help if sludge is suspected but not severe"],
     related=["P0024", "P0015", "P0023"],
     difficulty="medium", cost="$50-$2000",
     notes="Over-retarded exhaust cam reduces scavenging efficiency. Look for reduced power, poor emissions, and increased fuel consumption.")

_add("P0033", "medium", "Turbo/supercharger bypass valve control circuit — boost control fault",
     ["Bypass valve solenoid connector loose", "Solenoid coil open/shorted",
      "Wiring damage to bypass valve", "PCM output driver fault"],
     ["Check bypass valve solenoid connector for corrosion or oil contamination",
      "Measure solenoid resistance — typically 10-40 ohms",
      "Check wiring from PCM to bypass valve solenoid",
      "Command bypass valve with scan tool — listen for actuation"],
     related=["P0034", "P0299"],
     difficulty="easy", cost="$50-$300",
     notes="This is a circuit code. If the solenoid tests good electrically but boost is still wrong, check the valve mechanism for carbon buildup.")

_add("P0034", "medium", "Turbo/supercharger bypass valve control circuit low — signal low fault",
     ["Bypass valve solenoid shorted to ground", "Wiring short to ground",
      "PCM driver shorted internally", "Connector pin pushed back"],
     ["Check for short to ground on solenoid control wire",
      "Disconnect solenoid and check if code clears — if yes, solenoid is shorted",
      "Inspect wiring for chafing against engine/turbo components",
      "Check connector for backed-out or damaged pins"],
     related=["P0033", "P0299"],
     difficulty="easy", cost="$50-$300",
     notes="Circuit-low codes on boost control solenoids often caused by heat damage to wiring near the turbocharger. Relocate wiring if chafed.")

_add("P0037", "low", "HO2S heater control circuit low (Bank 1 Sensor 2) — downstream O2 heater",
     ["O2 sensor 2 heater element shorted", "Wiring shorted to ground",
      "Heater relay circuit fault", "O2 sensor connector water intrusion"],
     ["Check O2 sensor connector for water/corrosion",
      "Measure heater resistance at sensor connector — should be 2-15 ohms",
      "Check for short to ground in heater circuit wiring",
      "If resistance is very low (<1 ohm), heater element is shorted — replace sensor"],
     related=["P0038", "P0036"],
     difficulty="easy", cost="$50-$250",
     notes="Downstream O2 heater failures rarely affect drivability but will fail emissions. Replace sensor — heater is not separately serviceable.")

_add("P0038", "low", "HO2S heater control circuit high (Bank 1 Sensor 2) — downstream O2 heater",
     ["O2 sensor 2 heater element open", "Wiring open circuit",
      "Heater fuse blown", "Connector corroded causing high resistance"],
     ["Check O2 heater fuse (some vehicles have a dedicated fuse)",
      "Measure heater resistance — infinite/very high = open heater",
      "Check wiring from PCM/relay to sensor for opens",
      "Inspect sensor connector for corrosion or loose pins"],
     related=["P0037", "P0036"],
     difficulty="easy", cost="$50-$250",
     notes="Circuit-high on O2 heater usually means open circuit. Don't forget to check the fuse before replacing the sensor.")

_add("P0039", "medium", "Turbo/supercharger bypass valve control circuit range/performance",
     ["Bypass valve stuck partially open/closed from carbon",
      "Bypass valve actuator weak or sluggish", "Boost pressure not responding properly",
      "Vacuum line to bypass valve cracked"],
     ["Check vacuum/pressure lines to bypass valve actuator",
      "Command bypass valve with scan tool and monitor boost response",
      "Inspect bypass valve for carbon deposits — clean or replace",
      "Check for exhaust leaks near turbo that could affect bypass system"],
     related=["P0033", "P0034", "P0299"],
     difficulty="medium", cost="$100-$500",
     notes="Carbon buildup on the bypass valve is common on GDI turbo engines. Cleaning may be a temporary fix — valve replacement is more reliable.")

_add("P0040", "medium", "O2 sensor signals swapped Bank 1/Bank 2 — sensor wiring crossed",
     ["O2 sensor connectors swapped after engine work",
      "Wiring harness repaired with wrong routing", "Incorrect O2 sensor installed",
      "PCM seeing opposite bank signal on each bank"],
     ["Check O2 sensor connector locations — verify Bank 1 is on correct side",
      "Review recent repair history (exhaust, engine, O2 sensor replacement)",
      "Monitor O2 sensor signals on scan tool — banks should respond opposite during accel/decel",
      "Trace wiring from each sensor to verify correct bank routing"],
     related=["P0041", "P0171", "P0174"],
     difficulty="easy", cost="$0-$100",
     notes="This code almost always means someone plugged the O2 connectors into the wrong spots. Swap the connectors and clear the code.")

_add("P0041", "medium", "O2 sensor signals swapped Bank 1/Bank 2 Sensor 2 — downstream sensors crossed",
     ["Downstream O2 sensor connectors swapped", "Wiring error after exhaust repair",
      "Aftermarket exhaust routed wiring incorrectly", "Wrong sensor installed in wrong location"],
     ["Verify downstream O2 sensor connector routing — which side is which",
      "Check if exhaust work was recently performed",
      "Monitor Bank 1 and Bank 2 downstream sensor readings",
      "Swap connectors back to correct positions"],
     related=["P0040", "P0420", "P0430"],
     difficulty="easy", cost="$0-$100",
     notes="Downstream sensors swapped will cause false catalyst efficiency codes (P0420/P0430). Fix routing before chasing cat codes.")

_add("P0042", "low", "HO2S heater control circuit (Bank 1 Sensor 3) — third O2 heater fault",
     ["Third O2 sensor heater element failed", "Wiring to sensor 3 damaged",
      "Sensor connector corroded from exhaust heat/moisture", "Heater relay/fuse issue"],
     ["Check if vehicle has a third O2 sensor (dual-cat systems)",
      "Measure heater resistance at sensor connector",
      "Check wiring along exhaust path for heat damage",
      "Verify heater power supply fuse and relay"],
     related=["P0043", "P0044"],
     difficulty="easy", cost="$50-$250",
     notes="Third O2 sensor is typically after a second catalytic converter. Common on V6/V8 vehicles with dual exhaust and dual cats.")

_add("P0043", "low", "HO2S heater control circuit low (Bank 1 Sensor 3) — heater shorted",
     ["Sensor 3 heater shorted internally", "Wiring shorted to ground near exhaust",
      "Water intrusion at connector", "Heat damage to wiring insulation"],
     ["Measure heater resistance — very low reading confirms short",
      "Check wiring for chafing against exhaust components",
      "Inspect connector for water damage or corrosion",
      "Replace O2 sensor if heater is shorted"],
     related=["P0042", "P0044"],
     difficulty="easy", cost="$50-$250",
     notes="Wiring near the exhaust deteriorates from heat. Use high-temp wire loom when rerouting O2 sensor wiring.")

_add("P0044", "low", "HO2S heater control circuit high (Bank 1 Sensor 3) — heater open",
     ["Sensor 3 heater element burned open", "Wiring open circuit",
      "Connector corrosion causing infinite resistance", "Fuse blown for heater circuit"],
     ["Check heater fuse if there is a dedicated one",
      "Measure heater resistance — open/infinite confirms failed heater",
      "Check wiring continuity from relay/fuse to sensor",
      "Replace sensor — heater is internal and not repairable"],
     related=["P0042", "P0043"],
     difficulty="easy", cost="$50-$250",
     notes="High-mileage vehicles commonly burn out downstream O2 heaters. Replace the sensor as an assembly.")

_add("P0045", "medium", "Turbo/supercharger boost control solenoid circuit — boost solenoid fault",
     ["Boost control solenoid failed", "Connector corroded from engine bay environment",
      "Wiring to solenoid damaged by heat", "PCM boost control driver fault"],
     ["Locate boost control solenoid — usually on intake manifold or near turbo",
      "Check solenoid connector for corrosion",
      "Measure solenoid resistance — out of range = replace",
      "Command solenoid with scan tool — listen for click operation"],
     related=["P0046", "P0299", "P0234"],
     difficulty="easy", cost="$50-$300",
     notes="Boost control solenoids near the turbo fail from heat. Consider relocating or adding a heat shield after replacement.")

_add("P0046", "medium", "Turbo/supercharger boost control solenoid circuit range/performance",
     ["Boost solenoid sluggish or partially stuck",
      "Wastegate actuator binding from carbon/rust", "Vacuum line cracked or disconnected",
      "Solenoid internal diaphragm leaking"],
     ["Command boost solenoid duty cycle and monitor actual boost pressure",
      "Check vacuum/pressure lines to wastegate actuator for leaks",
      "Inspect wastegate actuator arm for free movement",
      "Replace solenoid if it actuates but response is delayed or partial"],
     related=["P0045", "P0299", "P0234"],
     difficulty="medium", cost="$75-$400",
     notes="Performance codes (vs. circuit codes) mean the solenoid works but boost response is wrong. Check the mechanical side — wastegate, lines, actuator.")

_add("P0047", "medium", "Turbo/supercharger boost control solenoid circuit low — signal low",
     ["Boost solenoid shorted to ground", "Wiring shorted to ground from heat damage",
      "PCM driver pin shorted", "Connector water intrusion"],
     ["Disconnect solenoid — if code changes to P0048 (high/open), solenoid is shorted",
      "Check wiring for heat damage near turbo manifold",
      "Inspect connector for water or oil contamination",
      "Check PCM connector pin for damage"],
     related=["P0045", "P0048"],
     difficulty="easy", cost="$50-$300",
     notes="Low-circuit codes on turbo solenoids are almost always heat damage to wiring insulation. Route wiring away from turbo heat sources.")

_add("P0048", "medium", "Turbo/supercharger boost control solenoid circuit high — signal high/open",
     ["Boost solenoid connector disconnected or corroded",
      "Wiring open circuit", "Solenoid coil open (burned out)",
      "PCM connector pin backed out"],
     ["Check solenoid connector — it may have vibrated loose",
      "Measure solenoid resistance — infinite = open coil, replace solenoid",
      "Check wiring continuity from PCM to solenoid",
      "Inspect PCM connector for backed-out pins"],
     related=["P0045", "P0047"],
     difficulty="easy", cost="$50-$300",
     notes="Vibration from the turbocharger can loosen connectors over time. Use connector retaining clips or zip-tie the connector in place.")

_add("P0049", "medium", "Turbo/supercharger turbine overspeed — turbo RPM exceeded safe limit",
     ["Wastegate stuck closed — not relieving boost",
      "Boost control solenoid stuck commanding full boost",
      "Wastegate actuator arm disconnected", "Exhaust restriction causing back-pressure surge"],
     ["Check wastegate operation — arm should move freely",
      "Verify boost pressure reading vs. spec — should not exceed maximum",
      "Check boost control solenoid — may be stuck energized",
      "Inspect turbo for shaft play or bearing damage from overspeed event"],
     related=["P0234", "P0045", "P0046"],
     difficulty="hard", cost="$200-$3000",
     notes="Turbo overspeed can cause bearing damage. After fixing the root cause, inspect the turbo for shaft play. Catch it early to avoid turbo replacement.")


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
