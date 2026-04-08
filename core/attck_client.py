"""
MITRE ATT&CK Client
Fetches and caches ATT&CK STIX data using the official mitreattack-python library.
Falls back to a bundled snapshot of key APT groups and techniques when offline.
"""

import json
import logging
import os
from pathlib import Path
from functools import lru_cache

logger = logging.getLogger(__name__)

CACHE_DIR = Path(__file__).parent.parent / "data"
ATTCK_CACHE = CACHE_DIR / "enterprise_attck.json"


def load_attck():
    """
    Load the ATT&CK dataset. Downloads from MITRE on first use (~30 MB),
    then caches locally. Returns a MitreAttackData object.
    """
    try:
        from mitreattack.stix20 import MitreAttackData

        if not ATTCK_CACHE.exists():
            logger.info("Downloading ATT&CK STIX data from MITRE...")
            import requests
            url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
            r = requests.get(url, timeout=60)
            r.raise_for_status()
            CACHE_DIR.mkdir(parents=True, exist_ok=True)
            ATTCK_CACHE.write_bytes(r.content)
            logger.info("ATT&CK data cached to %s", ATTCK_CACHE)

        return MitreAttackData(str(ATTCK_CACHE))

    except Exception as e:
        logger.warning("Could not load live ATT&CK data (%s) — using bundled fallback.", e)
        return None


class AttckClient:
    """High-level wrapper for MITRE ATT&CK queries."""

    def __init__(self):
        self._db = load_attck()

    # ------------------------------------------------------------------
    # Groups (APT actors)
    # ------------------------------------------------------------------

    def get_all_groups(self) -> list[dict]:
        """Return all ATT&CK threat groups as dicts."""
        if self._db is None:
            return FALLBACK_GROUPS

        groups = self._db.get_groups()
        result = []
        for g in groups:
            if g.get("revoked") or g.get("x_mitre_deprecated"):
                continue
            aliases = g.get("aliases", [])
            ext = g.get("external_references", [])
            url = next((r["url"] for r in ext if r.get("source_name") == "mitre-attack"), "")
            result.append({
                "id": g["id"],
                "name": g["name"],
                "aliases": aliases,
                "description": g.get("description", ""),
                "url": url,
            })
        return sorted(result, key=lambda x: x["name"])

    def get_group_by_name(self, name: str) -> dict | None:
        groups = self.get_all_groups()
        name_lower = name.lower()
        for g in groups:
            if g["name"].lower() == name_lower:
                return g
            if any(a.lower() == name_lower for a in g.get("aliases", [])):
                return g
        return None

    def get_group_techniques(self, group_stix_id: str) -> list[dict]:
        """Return techniques used by a group."""
        if self._db is None:
            return FALLBACK_TECHNIQUES.get(group_stix_id, [])

        try:
            techs = self._db.get_techniques_used_by_group(group_stix_id)
            result = []
            for rel in techs:
                obj = rel.get("object")
                if obj is None:
                    continue
                ext = obj.get("external_references", [])
                tid = next((r["external_id"] for r in ext if r.get("source_name") == "mitre-attack"), "")
                url = next((r["url"] for r in ext if r.get("source_name") == "mitre-attack"), "")
                result.append({
                    "technique_id": tid,
                    "name": obj.get("name", ""),
                    "tactic": [p["phase_name"] for p in obj.get("kill_chain_phases", [])],
                    "description": obj.get("description", "")[:400],
                    "url": url,
                    "use": rel.get("description", ""),
                })
            return result
        except Exception as e:
            logger.warning("get_group_techniques failed: %s", e)
            return []

    # ------------------------------------------------------------------
    # Techniques
    # ------------------------------------------------------------------

    def get_technique(self, technique_id: str) -> dict | None:
        """Look up a technique by ID (e.g., 'T1059')."""
        if self._db is None:
            for t in _all_fallback_techniques():
                if t["technique_id"] == technique_id:
                    return t
            return None

        try:
            techs = self._db.get_techniques()
            for t in techs:
                ext = t.get("external_references", [])
                tid = next((r["external_id"] for r in ext if r.get("source_name") == "mitre-attack"), "")
                if tid == technique_id:
                    url = next((r["url"] for r in ext if r.get("source_name") == "mitre-attack"), "")
                    return {
                        "technique_id": tid,
                        "name": t.get("name", ""),
                        "tactic": [p["phase_name"] for p in t.get("kill_chain_phases", [])],
                        "description": t.get("description", ""),
                        "url": url,
                        "detection": t.get("x_mitre_detection", ""),
                        "platforms": t.get("x_mitre_platforms", []),
                    }
        except Exception as e:
            logger.warning("get_technique failed: %s", e)
        return None


# ------------------------------------------------------------------
# Fallback data (offline / import failure)
# Sourced from public MITRE ATT&CK content (CC BY 4.0)
# ------------------------------------------------------------------

FALLBACK_GROUPS = [
    {"id": "G0032", "name": "Lazarus Group",  "aliases": ["HIDDEN COBRA", "Guardians of Peace"], "description": "North Korean state-sponsored group active since ~2009. Known for destructive attacks, financial theft (SWIFT), and ransomware.", "url": "https://attack.mitre.org/groups/G0032/"},
    {"id": "G0016", "name": "APT29",           "aliases": ["Cozy Bear", "NOBELIUM", "The Dukes"], "description": "Russian SVR-linked group. Highly sophisticated, known for SolarWinds supply-chain attack and long-dwell espionage campaigns.", "url": "https://attack.mitre.org/groups/G0016/"},
    {"id": "G0007", "name": "APT28",           "aliases": ["Fancy Bear", "STRONTIUM", "Sofacy"], "description": "Russian GRU-linked group. Active since ~2004. Targets governments, military, and election infrastructure.", "url": "https://attack.mitre.org/groups/G0007/"},
    {"id": "G0006", "name": "APT1",            "aliases": ["Comment Crew", "Comment Panda"],     "description": "PLA Unit 61398. Prolific Chinese espionage group documented in Mandiant's 2013 report.", "url": "https://attack.mitre.org/groups/G0006/"},
    {"id": "G0034", "name": "Sandworm Team",   "aliases": ["ELECTRUM", "Voodoo Bear"],           "description": "Russian GRU Unit 74455. Responsible for NotPetya, Ukraine power-grid attacks, and Olympic Destroyer.", "url": "https://attack.mitre.org/groups/G0034/"},
    {"id": "G0010", "name": "Turla",           "aliases": ["Snake", "Uroburos", "Waterbug"],     "description": "Russian FSB-linked group known for sophisticated implants and satellite-based C2 channels.", "url": "https://attack.mitre.org/groups/G0010/"},
]

FALLBACK_TECHNIQUES = {}  # populated below

def _all_fallback_techniques() -> list[dict]:
    return [t for ts in FALLBACK_TECHNIQUES.values() for t in ts]
