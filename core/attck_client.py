"""
MITRE ATT&CK Client
Fetches and caches ATT&CK STIX data using the official mitreattack-python library.
Downloads a pinned release once, then runs offline from the cache.
"""

import logging
import re
from pathlib import Path

logger = logging.getLogger(__name__)

ATTCK_VERSION = "19.2"
CACHE_DIR = Path(__file__).parent.parent / "data"
ATTCK_CACHE = CACHE_DIR / "enterprise_attck.json"

_ATTCK_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/main"
    f"/enterprise-attack/enterprise-attack-{ATTCK_VERSION}.json"
)


def load_attck():
    """
    Load ATT&CK v{ATTCK_VERSION}. Downloads from MITRE on first use (~30 MB),
    then caches locally. Returns a MitreAttackData object.
    """
    try:
        from mitreattack.stix20 import MitreAttackData

        if not ATTCK_CACHE.exists():
            logger.info("Downloading ATT&CK %s STIX data from MITRE...", ATTCK_VERSION)
            import requests
            r = requests.get(_ATTCK_URL, timeout=60)
            r.raise_for_status()
            CACHE_DIR.mkdir(parents=True, exist_ok=True)
            ATTCK_CACHE.write_bytes(r.content)
            logger.info("ATT&CK data cached to %s", ATTCK_CACHE)

        return MitreAttackData(str(ATTCK_CACHE))

    except Exception as e:
        logger.error("Could not load ATT&CK data: %s", e)
        raise


class AttckClient:
    """High-level wrapper for MITRE ATT&CK queries."""

    def __init__(self):
        self._db = load_attck()

    # ------------------------------------------------------------------
    # Groups (APT actors)
    # ------------------------------------------------------------------

    def get_all_groups(self) -> list[dict]:
        """Return all ATT&CK threat groups as dicts."""
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
                # rel is {"object": technique, "relationships": [stix_rel, ...]};
                # group-specific procedure text is in the relationship objects.
                # Join all descriptions — a technique can have multiple relationships
                # (e.g., used in different campaigns) and [0] crashes on an empty list.
                rels = rel.get("relationships", [])
                raw_use = " ".join(
                    r.get("description", "") for r in rels if r.get("description")
                )
                use = re.sub(r'\s*\(Citation:[^)]+\)', '', raw_use).strip()
                result.append({
                    "technique_id": tid,
                    "name": obj.get("name", ""),
                    "tactic": [p["phase_name"] for p in obj.get("kill_chain_phases", [])],
                    "description": obj.get("description", "")[:400],
                    "url": url,
                    "use": use,
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


