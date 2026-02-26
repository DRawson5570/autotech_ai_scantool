"""
VIN decoder — derive manufacturer (make) from the WMI (first 3 chars).

Uses a local lookup table for common automotive manufacturers, covering
~95% of vehicles a US shop will see.  For full decode (make, model, year,
engine) tries VPIC SQLite database first (offline), then falls back to
the free NHTSA vPIC API.

Usage:
    from addons.scan_tool.vin_decoder import decode_make_from_vin, decode_vin_full
    make = decode_make_from_vin("1FAHP3F20CL123456")  # -> "Ford"  (instant, offline)
    info = decode_vin_full("1FAHP3F20CL123456")       # -> {"make": "Ford", "model": "Focus", ...}
"""

import json
import logging
import os
import re
import sqlite3
import urllib.request
import urllib.error
from typing import Dict, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# WMI → Make  (first 3 characters of VIN)
#
# Entries are checked longest-prefix-first, so "1FA" beats "1F".
# Where multiple brands share a WMI group we map to the brand, not the
# parent corporation.  For DID-database purposes the calling code can
# normalise brands to a manufacturer group if needed (e.g. Chrysler/Dodge/Jeep/Ram).
# ---------------------------------------------------------------------------

_WMI_TABLE: dict[str, str] = {
    # ── Ford ──────────────────────────────────────────
    "1FA": "Ford",   "1FB": "Ford",   "1FC": "Ford",
    "1FD": "Ford",   "1FM": "Ford",   "1FT": "Ford",
    "1FV": "Ford",   "1ZV": "Ford",
    "2FA": "Ford",   "2FM": "Ford",   "2FT": "Ford",
    "3FA": "Ford",   "3FT": "Ford",
    "MAJ": "Ford",                     # Ford Thailand
    "NM0": "Ford",                     # Ford Turkey (Transit Connect, etc.)

    # ── Lincoln ───────────────────────────────────────
    "1LN": "Lincoln", "2LN": "Lincoln", "3LN": "Lincoln",
    "5LM": "Lincoln",

    # ── General Motors — Chevrolet ────────────────────
    "1G1": "Chevrolet", "1GC": "Chevrolet", "2G1": "Chevrolet",
    "3G1": "Chevrolet", "KL7": "Chevrolet",

    # ── GMC ───────────────────────────────────────────
    "1GT": "GMC", "2GT": "GMC", "3GT": "GMC",

    # ── Buick ─────────────────────────────────────────
    "1G4": "Buick", "2G4": "Buick",

    # ── Cadillac ──────────────────────────────────────
    "1G6": "Cadillac", "1GY": "Cadillac",

    # ── Pontiac (legacy) ──────────────────────────────
    "1G2": "Pontiac",

    # ── Chrysler / Stellantis ─────────────────────────
    "1C3": "Chrysler", "2C3": "Chrysler", "3C3": "Chrysler",
    "2C4": "Chrysler",

    # ── Dodge ─────────────────────────────────────────
    "1B3": "Dodge", "2B3": "Dodge", "3B3": "Dodge",
    "1B7": "Dodge", "2B7": "Dodge", "3B7": "Dodge",
    "1C4": "Dodge", "1C6": "Dodge",   # some overlap with Chrysler/Jeep — see Jeep below
    "2D3": "Dodge", "2D4": "Dodge", "2D7": "Dodge",

    # ── Jeep ──────────────────────────────────────────
    "1J4": "Jeep", "1J8": "Jeep",
    "1C4": "Jeep",   # modern Jeep (Cherokee/Compass/Wrangler JL use 1C4)
    # Note: 1C4 can be Chrysler or Jeep. 10th-char model year + 4th-8th resolve it.
    # For DID purposes, Jeep and Chrysler share the same FCA module set.

    # ── Ram ───────────────────────────────────────────
    "1C6": "Ram", "3C6": "Ram",
    "3D7": "Ram",

    # ── Toyota ────────────────────────────────────────
    "JTD": "Toyota", "JTE": "Toyota", "JTM": "Toyota",
    "JTN": "Toyota", "JTK": "Toyota", "JTL": "Toyota",
    "JTH": "Toyota",   # some Lexus badged under JTH
    "2T1": "Toyota", "2T3": "Toyota",
    "4T1": "Toyota", "4T3": "Toyota", "4T4": "Toyota",
    "5TD": "Toyota", "5TF": "Toyota", "5TN": "Toyota",

    # ── Lexus ─────────────────────────────────────────
    "JTJ": "Lexus",  "2T2": "Lexus",  "5TJ": "Lexus",
    "JTH": "Lexus",  # Lexus IS, RC, ES

    # ── Honda ─────────────────────────────────────────
    "JHM": "Honda", "1HG": "Honda", "2HG": "Honda",
    "5FN": "Honda", "5J6": "Honda", "19X": "Honda",

    # ── Acura ─────────────────────────────────────────
    "JH4": "Acura", "19U": "Acura",

    # ── Nissan ────────────────────────────────────────
    "JN1": "Nissan", "JN8": "Nissan",
    "1N4": "Nissan", "1N6": "Nissan",
    "3N1": "Nissan", "3N6": "Nissan",
    "5N1": "Nissan",

    # ── Infiniti ──────────────────────────────────────
    "JNK": "Infiniti",

    # ── Subaru ────────────────────────────────────────
    "JF1": "Subaru", "JF2": "Subaru", "4S3": "Subaru", "4S4": "Subaru",

    # ── Mazda ─────────────────────────────────────────
    "JM1": "Mazda", "JM3": "Mazda",
    "3MZ": "Mazda",

    # ── Mitsubishi ────────────────────────────────────
    "JA3": "Mitsubishi", "JA4": "Mitsubishi", "JA7": "Mitsubishi",
    "4A3": "Mitsubishi", "4A4": "Mitsubishi",

    # ── Hyundai ───────────────────────────────────────
    "KMH": "Hyundai", "5NP": "Hyundai", "5NM": "Hyundai",
    "KM8": "Hyundai",

    # ── Kia ───────────────────────────────────────────
    "KNA": "Kia", "KND": "Kia", "5XY": "Kia",

    # ── Genesis ───────────────────────────────────────
    "KMT": "Genesis",

    # ── BMW ───────────────────────────────────────────
    "WBA": "BMW", "WBS": "BMW", "WBY": "BMW",
    "5UX": "BMW", "5UJ": "BMW",

    # ── Mercedes-Benz ─────────────────────────────────
    "WDB": "Mercedes-Benz", "WDC": "Mercedes-Benz",
    "WDD": "Mercedes-Benz", "WDF": "Mercedes-Benz",
    "55S": "Mercedes-Benz", "4JG": "Mercedes-Benz",

    # ── Audi ──────────────────────────────────────────
    "WAU": "Audi", "WA1": "Audi",

    # ── Volkswagen ────────────────────────────────────
    "WVW": "Volkswagen", "WVG": "Volkswagen",
    "1VW": "Volkswagen", "3VW": "Volkswagen",

    # ── Porsche ───────────────────────────────────────
    "WP0": "Porsche", "WP1": "Porsche",

    # ── Volvo ─────────────────────────────────────────
    "YV1": "Volvo", "YV4": "Volvo", "7JR": "Volvo",

    # ── Tesla ─────────────────────────────────────────
    "5YJ": "Tesla", "7SA": "Tesla",

    # ── Rivian ────────────────────────────────────────
    "7PD": "Rivian",

    # ── Lucid ─────────────────────────────────────────
    "7LU": "Lucid",

    # ── Land Rover / Jaguar ───────────────────────────
    "SAL": "Land Rover", "SAJ": "Jaguar",

    # ── Mini ──────────────────────────────────────────
    "WMW": "Mini",

    # ── Fiat ──────────────────────────────────────────
    "ZFF": "Ferrari", "ZFA": "Fiat",
    "3C3": "Fiat",    # Fiat 500 (NA)

    # ── Suzuki ────────────────────────────────────────
    "JS1": "Suzuki", "JS2": "Suzuki",

    # ── Isuzu ─────────────────────────────────────────
    "JAA": "Isuzu", "JAL": "Isuzu",
}

# Pre-sorted longest-prefix first for greedy matching
_SORTED_WMIS = sorted(_WMI_TABLE.keys(), key=lambda k: (-len(k), k))


def decode_make_from_vin(vin: str) -> Optional[str]:
    """
    Return the vehicle make (brand name) from a VIN, or None if unknown.

    Checks local WMI table first; does NOT call external APIs.
    """
    if not vin or len(vin) < 3:
        return None
    vin = vin.strip().upper()
    wmi = vin[:3]

    # Exact 3-char lookup first
    if wmi in _WMI_TABLE:
        return _WMI_TABLE[wmi]

    # Try 2-char prefix (some WMI tables use 2)
    wmi2 = vin[:2]
    for prefix in _SORTED_WMIS:
        if wmi.startswith(prefix) or prefix.startswith(wmi2):
            return _WMI_TABLE[prefix]

    return None


def decode_manufacturer_group(make: str) -> str:
    """
    Map a brand name to its parent manufacturer group.

    Useful for DID-database scoping — brands under the same parent
    typically share the same module architecture and DID definitions.
    """
    _GROUPS = {
        "Ford": "Ford", "Lincoln": "Ford",
        "Chevrolet": "GM", "GMC": "GM", "Buick": "GM",
        "Cadillac": "GM", "Pontiac": "GM",
        "Chrysler": "Stellantis", "Dodge": "Stellantis",
        "Jeep": "Stellantis", "Ram": "Stellantis", "Fiat": "Stellantis",
        "Toyota": "Toyota", "Lexus": "Toyota",
        "Honda": "Honda", "Acura": "Honda",
        "Nissan": "Nissan", "Infiniti": "Nissan",
        "Hyundai": "Hyundai-Kia", "Kia": "Hyundai-Kia", "Genesis": "Hyundai-Kia",
        "BMW": "BMW", "Mini": "BMW",
        "Mercedes-Benz": "Mercedes-Benz",
        "Audi": "VAG", "Volkswagen": "VAG", "Porsche": "VAG",
        "Subaru": "Subaru", "Mazda": "Mazda", "Mitsubishi": "Mitsubishi",
        "Volvo": "Volvo",
        "Tesla": "Tesla", "Rivian": "Rivian", "Lucid": "Lucid",
        "Land Rover": "JLR", "Jaguar": "JLR",
    }
    return _GROUPS.get(make, make)


_VIN_PATTERN = re.compile(r"^[A-HJ-NPR-Z0-9]{17}$")


def is_valid_vin(vin: str) -> bool:
    """Quick check that a string looks like a 17-character VIN."""
    return bool(_VIN_PATTERN.match((vin or "").strip().upper()))


# ---------------------------------------------------------------------------
# VIN Year Decode (position 10)
# ---------------------------------------------------------------------------

_YEAR_CHAR_MAP: Dict[str, int] = {}
# 1980-2000: A=1980 ... Y=2000
for _i, _c in enumerate("ABCDEFGHJKLMNPRSTVWXY"):
    _YEAR_CHAR_MAP[_c] = 1980 + _i
# 2001-2009: 1=2001 ... 9=2009
for _i in range(1, 10):
    _YEAR_CHAR_MAP[str(_i)] = 2000 + _i
# 2010-2030: A=2010 ... (same letters cycle)
# Position 7 distinguishes pre/post-2010 in practice,
# but VPIC year-range matching resolves ambiguity.


def _decode_vin_year_char(ch: str) -> list:
    """
    Decode the 10th VIN character to possible model years.
    Returns a list of possible years, newer first (letters can mean 1980s or 2010s+).
    """
    ch = ch.upper()
    years = []
    base = _YEAR_CHAR_MAP.get(ch)
    if base is not None:
        # Letters cycle every 30 years (A=1980 or 2010, B=1981 or 2011, etc.)
        if base < 2001 and ch.isalpha():
            years.append(base + 30)  # Try newer year first (e.g. 2015 before 1985)
        years.append(base)
    return years


# ---------------------------------------------------------------------------
# VPIC SQLite Offline VIN Decode
# ---------------------------------------------------------------------------

# Try multiple possible locations for the VPIC database
_VPIC_DB_PATHS = [
    os.path.join(os.path.dirname(__file__), "..", "..", "odb_resources", "obdium", "backend", "data", "vpic.sqlite"),
    "/home/drawson/autotech_ai/odb_resources/obdium/backend/data/vpic.sqlite",
    "/prod/autotech_ai/odb_resources/obdium/backend/data/vpic.sqlite",
]

_vpic_db_path: Optional[str] = None


def _get_vpic_db_path() -> Optional[str]:
    """Find the VPIC SQLite database file."""
    global _vpic_db_path
    if _vpic_db_path is not None:
        return _vpic_db_path if os.path.exists(_vpic_db_path) else None
    for path in _VPIC_DB_PATHS:
        resolved = os.path.realpath(path)
        if os.path.exists(resolved):
            _vpic_db_path = resolved
            logger.debug(f"VPIC database found at {resolved}")
            return resolved
    logger.debug("VPIC database not found in any expected location")
    return None


def _match_pattern(key: str, pattern: str) -> bool:
    """
    Match a VIN key against a VPIC Pattern.Keys value.
    Pattern uses: * for single wildcard, [XY] for char class, [X-Z] for range.
    Converted from obdium's Rust implementation.
    """
    ki = 0
    pi = 0
    while pi < len(pattern):
        pc = pattern[pi]
        if pc == '*' or pc == '_':
            # Single character wildcard
            if ki >= len(key):
                return False
            ki += 1
            pi += 1
        elif pc == '%':
            # Match rest of string
            return True
        elif pc == '[':
            # Character class
            pi += 1
            negated = False
            if pi < len(pattern) and pattern[pi] == '^':
                negated = True
                pi += 1
            char_class = []
            while pi < len(pattern) and pattern[pi] != ']':
                c = pattern[pi]
                pi += 1
                if pi < len(pattern) and pattern[pi] == '-' and pi + 1 < len(pattern) and pattern[pi + 1] != ']':
                    pi += 1  # skip '-'
                    end = pattern[pi]
                    pi += 1
                    for ch in range(ord(c), ord(end) + 1):
                        char_class.append(chr(ch))
                else:
                    char_class.append(c)
            if pi < len(pattern):
                pi += 1  # skip ']'
            if ki >= len(key):
                return False
            kc = key[ki]
            contains = kc in char_class
            if (contains and negated) or (not contains and not negated):
                return False
            ki += 1
        else:
            # Literal character match
            if ki >= len(key):
                return False
            if key[ki] != pc:
                return False
            ki += 1
            pi += 1
    return ki >= len(key)


def _vin_to_key(vin: str) -> str:
    """
    Convert 17-char VIN to VPIC lookup key.
    Key = positions 4-8 + "|" + positions 10-17 (1-indexed).
    """
    return vin[3:8] + "|" + vin[9:17]


# Element IDs for fields we want to decode
_VPIC_ELEMENT_IDS = {
    5: "body_class",
    9: "cylinders",
    13: "displacement_l",
    15: "drive_type",
    24: "fuel_type",
    26: "make",
    27: "manufacturer",
    28: "model",
    29: "year",
    34: "series",
    37: "transmission",
    38: "trim",
    39: "vehicle_type",
}

# Lookup tables for resolving AttributeId → human-readable value
_VPIC_LOOKUP_TABLES = {
    "body_class": "BodyStyle",
    "drive_type": "DriveType",
    "fuel_type": "FuelType",
    "vehicle_type": "VehicleType",
    "transmission": "Transmission",
}


def _resolve_lookup(conn: sqlite3.Connection, table_name: str, attr_id: str) -> Optional[str]:
    """Resolve a lookup table value. AttributeId is the PK in the lookup table."""
    try:
        attr_int = int(attr_id)
        cursor = conn.execute(f"SELECT Name FROM [{table_name}] WHERE Id = ?", (attr_int,))
        row = cursor.fetchone()
        return row[0] if row else None
    except (ValueError, sqlite3.Error):
        return None


def decode_vin_vpic_offline(vin: str) -> Optional[Dict[str, str]]:
    """
    Decode a VIN using the local VPIC SQLite database.

    Implements the same decode algorithm as NHTSA's vPIC service:
    1. Extract WMI (first 3 chars) → find WMI ID
    2. Decode year from position 10 → find matching VinSchema
    3. Build key from VIN positions 4-8 + 10-17
    4. Match Pattern entries for the VinSchema against the key
    5. Resolve attribute values through lookup tables

    Returns:
        Dict with decoded fields (make, model, year, etc.) or None if
        VPIC database is unavailable or VIN cannot be decoded.
    """
    db_path = _get_vpic_db_path()
    if not db_path:
        return None

    vin = vin.strip().upper()
    if len(vin) != 17:
        return None

    wmi = vin[:3]
    year_char = vin[9]
    possible_years = _decode_vin_year_char(year_char)
    if not possible_years:
        return None

    key = _vin_to_key(vin)
    result: Dict[str, str] = {"vin": vin}

    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=5)
        conn.row_factory = sqlite3.Row

        # Step 1: Find WMI ID
        cursor = conn.execute(
            "SELECT w.Id, m.Name AS MakeName, mfr.Name AS MfgName "
            "FROM Wmi w "
            "LEFT JOIN Make m ON w.MakeId = m.Id "
            "LEFT JOIN Manufacturer mfr ON w.ManufacturerId = mfr.Id "
            "WHERE w.Wmi = ?",
            (wmi,)
        )
        wmi_row = cursor.fetchone()
        if not wmi_row:
            conn.close()
            return None

        wmi_id = wmi_row["Id"]
        if wmi_row["MakeName"]:
            result["make"] = wmi_row["MakeName"]
        if wmi_row["MfgName"]:
            result["manufacturer"] = wmi_row["MfgName"]

        # Step 2: Find matching VinSchema(s) for this WMI and year
        best_schema_id = None
        for year in possible_years:
            cursor = conn.execute(
                "SELECT wvs.VinSchemaId, vs.Name "
                "FROM Wmi_VinSchema wvs "
                "JOIN VinSchema vs ON wvs.VinSchemaId = vs.Id "
                "WHERE wvs.WmiId = ? "
                "AND wvs.YearFrom <= ? AND (wvs.YearTo >= ? OR wvs.YearTo IS NULL)",
                (wmi_id, year, year)
            )
            schemas = cursor.fetchall()
            if schemas:
                result["year"] = str(year)
                # Prefer the most specific schema (shortest year range)
                best_schema_id = schemas[0]["VinSchemaId"]
                break

        if not best_schema_id:
            # No year-specific schema found; still have make from WMI
            conn.close()
            return result if len(result) > 1 else None

        # Also collect all schemas for this WMI+year (some share patterns)
        schema_ids = []
        for year in possible_years:
            if str(year) == result.get("year"):
                cursor = conn.execute(
                    "SELECT wvs.VinSchemaId "
                    "FROM Wmi_VinSchema wvs "
                    "WHERE wvs.WmiId = ? "
                    "AND wvs.YearFrom <= ? AND (wvs.YearTo >= ? OR wvs.YearTo IS NULL)",
                    (wmi_id, year, year)
                )
                schema_ids = [row["VinSchemaId"] for row in cursor.fetchall()]
                break

        if not schema_ids:
            schema_ids = [best_schema_id]

        # Step 3: Match Pattern entries against the VIN key
        placeholders = ",".join("?" * len(schema_ids))
        for element_id, field_name in _VPIC_ELEMENT_IDS.items():
            if field_name in result and field_name in ("make", "year"):
                continue  # Already resolved
            cursor = conn.execute(
                f"SELECT Keys, AttributeId FROM Pattern "
                f"WHERE VinSchemaId IN ({placeholders}) AND ElementId = ?",
                (*schema_ids, element_id)
            )
            for row in cursor:
                pattern_keys = row["Keys"]
                attr_id = str(row["AttributeId"]).strip()
                # Convert pattern: * → single wildcard for matching
                # The key is VDS|serial (positions 4-8 | 10-17)
                # Pattern Keys match against VDS part or VDS|plant parts
                if _match_pattern(key, pattern_keys + "%" if "|" not in pattern_keys else pattern_keys):
                    # Resolve the value
                    if field_name == "model":
                        # Model AttributeId is a Model table ID
                        try:
                            model_cursor = conn.execute(
                                "SELECT Name FROM Model WHERE Id = ?", (int(attr_id),)
                            )
                            model_row = model_cursor.fetchone()
                            if model_row:
                                result["model"] = model_row["Name"]
                        except (ValueError, sqlite3.Error):
                            pass
                    elif field_name in _VPIC_LOOKUP_TABLES:
                        resolved = _resolve_lookup(conn, _VPIC_LOOKUP_TABLES[field_name], attr_id)
                        if resolved:
                            result[field_name] = resolved
                    elif field_name in ("cylinders", "displacement_l"):
                        result[field_name] = attr_id
                    elif field_name == "series":
                        result["series"] = attr_id
                    elif field_name == "trim":
                        result["trim"] = attr_id
                    break  # First match wins for this element

        conn.close()

        # Normalize make case
        if "make" in result:
            raw = result["make"]
            if raw.upper() in {"BMW", "GMC"}:
                result["make"] = raw.upper()
            else:
                result["make"] = raw.title()

        return result if len(result) > 1 else None

    except sqlite3.Error as e:
        logger.debug(f"VPIC SQLite error decoding VIN {vin[:6]}...: {e}")
        return None
    except Exception as e:
        logger.warning(f"Unexpected VPIC error decoding VIN {vin[:6]}...: {e}")
        return None


# ---------------------------------------------------------------------------
# Full VIN decode via NHTSA vPIC API (free, no key needed)
# ---------------------------------------------------------------------------

_NHTSA_URL = "https://vpic.nhtsa.dot.gov/api/vehicles/DecodeVin/{}?format=json"

# vPIC variable IDs we care about
_VPIC_FIELDS = {
    "Make":                 "make",
    "Model":                "model",
    "Model Year":           "year",
    "Displacement (L)":     "displacement_l",
    "Engine Number of Cylinders": "cylinders",
    "Fuel Type - Primary":  "fuel_type",
    "Drive Type":           "drive_type",
    "Body Class":           "body_class",
    "Vehicle Type":         "vehicle_type",
    "Plant City":           "plant_city",
    "Plant Country":        "plant_country",
    "Trim":                 "trim",
    "Series":               "series",
    "Engine Model":         "engine_model",
    "Transmission Style":   "transmission",
}


def decode_vin_full(vin: str, timeout: float = 3.0) -> Dict[str, str]:
    """
    Decode a VIN using offline VPIC database first, then NHTSA API fallback.

    Returns a dict with keys like:
      make, model, year, displacement_l, cylinders, fuel_type,
      drive_type, body_class, trim, engine_model, transmission, etc.

    Decode order:
      1. VPIC SQLite offline database (instant, no network)
      2. NHTSA vPIC REST API (if offline decode incomplete)
      3. Local WMI table (last resort for make)

    Args:
        vin: 17-character VIN
        timeout: HTTP timeout in seconds for NHTSA API (default 3s)

    Returns:
        Dict of decoded fields.  Always has at least "vin" key.
        "make" is always populated if the VIN is recognisable.
    """
    vin = (vin or "").strip().upper()
    result: Dict[str, str] = {"vin": vin}

    if not is_valid_vin(vin):
        # Still try local WMI decode for partial VINs
        local_make = decode_make_from_vin(vin)
        if local_make:
            result["make"] = local_make
        return result

    # --- Step 1: Try offline VPIC SQLite decode ---
    vpic_result = decode_vin_vpic_offline(vin)
    if vpic_result:
        result.update(vpic_result)
        logger.debug(f"VPIC offline decoded {len(vpic_result)} fields for VIN {vin[:6]}...")

    # Check if we have enough data (make + model at minimum)
    needs_api = "model" not in result or "year" not in result

    # --- Step 2: Try NHTSA API if offline was incomplete ---
    if needs_api:
        try:
            url = _NHTSA_URL.format(vin)
            req = urllib.request.Request(url, headers={"User-Agent": "AutotechAI/1.0"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))

            for item in data.get("Results", []):
                variable = item.get("Variable", "")
                value = (item.get("Value") or "").strip()
                if variable in _VPIC_FIELDS and value and value.lower() != "not applicable":
                    key = _VPIC_FIELDS[variable]
                    # Only fill in fields we don't already have from VPIC offline
                    if key not in result:
                        result[key] = value

        except (urllib.error.URLError, urllib.error.HTTPError, OSError, json.JSONDecodeError) as e:
            logger.debug(f"NHTSA vPIC API unavailable for VIN {vin[:6]}...: {e}")
        except Exception as e:
            logger.warning(f"Unexpected error decoding VIN {vin[:6]}...: {e}")
    else:
        logger.debug(f"VPIC offline decode sufficient for VIN {vin[:6]}..., skipping API call")

    # Normalise make to title case (NHTSA returns "FORD", we want "Ford")
    if "make" in result:
        raw = result["make"]
        # Handle special cases like "BMW", "GMC" that should stay uppercase
        if raw.upper() in {"BMW", "GMC"}:
            result["make"] = raw.upper()
        else:
            result["make"] = raw.title().replace("-", "-")  # "MERCEDES-BENZ" → "Mercedes-Benz"

    # Ensure make is populated — fall back to local WMI if API missed it
    if "make" not in result:
        local_make = decode_make_from_vin(vin)
        if local_make:
            result["make"] = local_make

    # Build a human-friendly engine description
    if "engine_desc" not in result:
        parts = []
        if result.get("displacement_l"):
            parts.append(f"{result['displacement_l']}L")
        if result.get("cylinders"):
            cyl = result["cylinders"]
            parts.append(f"V{cyl}" if int(cyl) >= 5 else f"I{cyl}" if int(cyl) <= 4 else f"{cyl}cyl")
        if result.get("fuel_type"):
            parts.append(result["fuel_type"])
        if parts:
            result["engine_desc"] = " ".join(parts)

    return result
