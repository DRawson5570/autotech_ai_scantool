"""
OEM Enhanced DID Categories — Database-backed

Loads manufacturer-specific DID catalogs from scan_tool_data.db.
Each OEM group (Ford, GM, Toyota, etc.) has categories of DIDs
that can be read via UDS service $22 (or $1A for legacy GM).

This module reconstructs the same dictionary structures that were
previously defined inline in openwebui_tool.py (~2,600 lines of data).

Exports:
    OEM_CATEGORIES: Dict[str, Dict] — oem_group → {cat_key: {name, dids, ...}}
    OEM_MAKE_MAP: Dict[str, Tuple] — make_name → (oem_group_display, categories_dict)
    GM_LEGACY_CATEGORIES: Dict — GM Legacy $1A categories (separate from modern GM)
"""

import json
import logging
import os
import sqlite3
from typing import Any, Dict, List, Tuple

logger = logging.getLogger(__name__)

# Type aliases
CategoriesDict = Dict[str, Dict[str, Any]]


def _get_db_path() -> str:
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "scan_tool_data.db")


def _load_oem_data() -> Tuple[Dict[str, CategoriesDict], Dict[str, tuple], CategoriesDict]:
    """
    Load all OEM DID data from scan_tool_data.db.

    Returns:
        (oem_categories, oem_make_map, gm_legacy_categories)
    """
    db_path = _get_db_path()
    oem_categories: Dict[str, CategoriesDict] = {}
    oem_make_map: Dict[str, tuple] = {}
    gm_legacy: CategoriesDict = {}

    if not os.path.exists(db_path):
        logger.warning("scan_tool_data.db not found at %s — OEM DIDs empty", db_path)
        return oem_categories, oem_make_map, gm_legacy

    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row

        # Load OEM DIDs grouped by oem_group + category
        rows = conn.execute(
            "SELECT oem_group, category, category_name, did_hex, "
            "service, module_addr, bus, mode01_pids "
            "FROM oem_dids ORDER BY oem_group, category, id"
        ).fetchall()

        for row in rows:
            oem_group = row["oem_group"]
            cat_key = row["category"]

            # Pick the right target dict
            if oem_group == "GM_Legacy":
                target = gm_legacy
            else:
                if oem_group not in oem_categories:
                    oem_categories[oem_group] = {}
                target = oem_categories[oem_group]

            if cat_key not in target:
                cat_info: Dict[str, Any] = {
                    "name": row["category_name"],
                    "dids": [],
                }
                # Add optional metadata if present
                if row["service"]:
                    cat_info["service"] = row["service"]
                if row["module_addr"]:
                    cat_info["module_addr"] = row["module_addr"]
                if row["bus"]:
                    cat_info["bus"] = row["bus"]
                mode01 = json.loads(row["mode01_pids"]) if row["mode01_pids"] else []
                if mode01:
                    cat_info["mode01_pids"] = mode01
                target[cat_key] = cat_info

            target[cat_key]["dids"].append(row["did_hex"])

        # Load make → OEM group mapping
        make_rows = conn.execute(
            "SELECT make, oem_group, display_name FROM oem_make_map"
        ).fetchall()
        for mrow in make_rows:
            make = mrow["make"]
            oem_group = mrow["oem_group"]
            display_name = mrow["display_name"] or oem_group
            cats = oem_categories.get(oem_group, {})
            oem_make_map[make] = (display_name, cats)

        conn.close()

        total_dids = sum(
            len(cat["dids"])
            for cats in oem_categories.values()
            for cat in cats.values()
        )
        legacy_dids = sum(len(cat["dids"]) for cat in gm_legacy.values())
        logger.info(
            "Loaded OEM DIDs: %d groups, %d DIDs + %d GM Legacy DIDs, %d make mappings",
            len(oem_categories), total_dids, legacy_dids, len(oem_make_map),
        )

    except Exception as e:
        logger.error("Failed to load OEM DIDs from DB: %s", e)

    return oem_categories, oem_make_map, gm_legacy


# Load at import time
OEM_CATEGORIES, OEM_MAKE_MAP, GM_LEGACY_CATEGORIES = _load_oem_data()
