"""
APT Campaign Analyzer
Reconstructs attack timelines, maps techniques to kill-chain phases,
and correlates TTPs across groups. All data sourced from public threat
intelligence (MITRE ATT&CK, open-source CTI reports).
"""

import logging
from collections import defaultdict
from .attck_client import AttckClient

logger = logging.getLogger(__name__)

# Display labels for ATT&CK tactic shortnames.
# Includes both v16.x "defense-evasion" and the v19.0 split ("stealth",
# "defense-impairment") so the template renders correctly regardless of
# which version is cached.
TACTIC_LABELS = {
    "reconnaissance": "Reconnaissance",
    "resource-development": "Resource Development",
    "initial-access": "Initial Access",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege-escalation": "Privilege Escalation",
    "defense-evasion": "Defense Evasion",   # pre-v19.0
    "stealth": "Stealth",                   # v19.0+
    "defense-impairment": "Defense Impairment",  # v19.0+
    "credential-access": "Credential Access",
    "discovery": "Discovery",
    "lateral-movement": "Lateral Movement",
    "collection": "Collection",
    "command-and-control": "Command & Control",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
}


def _tactic_order_from_matrix(db) -> list[str]:
    """
    Read tactic order directly from the ATT&CK matrix object in the STIX bundle.
    Raises RuntimeError if the matrix cannot be parsed — silent fallback to a
    hardcoded list masks exactly the kind of version-mismatch bug this fixes.
    """
    from stix2 import Filter
    matrices = db.src.query([Filter("type", "=", "x-mitre-matrix")])
    if not matrices:
        raise RuntimeError(
            "No x-mitre-matrix object found in ATT&CK STIX data. "
            "Delete data/enterprise_attck.json and re-run to download a fresh copy."
        )
    matrix = matrices[0]
    tactic_refs = list(matrix.get("tactic_refs", []))
    if not tactic_refs:
        raise RuntimeError("ATT&CK matrix object has no tactic_refs.")
    tactics = db.src.query([Filter("type", "=", "x-mitre-tactic")])
    id_to_shortname = {t["id"]: t.get("x_mitre_shortname", "") for t in tactics}
    order = [id_to_shortname[ref] for ref in tactic_refs if ref in id_to_shortname]
    if not order:
        raise RuntimeError(
            "Could not map tactic_refs to shortnames. "
            "The STIX data may be corrupt — delete the cache and re-download."
        )
    return order


class CampaignAnalyzer:
    def __init__(self):
        self.client = AttckClient()
        self.tactic_order = _tactic_order_from_matrix(self.client._db)

    def analyze_group(self, group_name: str) -> dict:
        """
        Full analysis of an APT group:
        - Technique list mapped to kill-chain phases
        - Tactic coverage heatmap data
        - Detection opportunities per phase
        Returns a structured dict ready for the web interface.
        """
        group = self.client.get_group_by_name(group_name)
        if group is None:
            raise ValueError(f"Group not found: {group_name}")

        techniques = self.client.get_group_techniques(group["id"])
        phase_map = self._map_to_phases(techniques)
        coverage = self._tactic_coverage(phase_map)
        detection_ops = self._detection_opportunities(phase_map)
        tactic_coverage_pct = self._tactic_coverage_pct(phase_map)

        return {
            "group": group,
            "technique_count": len(techniques),
            "techniques": techniques,
            "phase_map": phase_map,
            "tactic_order": self.tactic_order,
            "tactic_labels": TACTIC_LABELS,
            "coverage": coverage,
            "detection_opportunities": detection_ops,
            "tactic_coverage_pct": tactic_coverage_pct,
        }

    def compare_groups(self, group_names: list[str]) -> dict:
        """
        Compare TTP overlap between multiple APT groups.
        Returns shared techniques and unique-to-each coverage.
        """
        analyses = {}
        for name in group_names:
            try:
                analyses[name] = self.analyze_group(name)
            except ValueError as e:
                logger.warning(e)

        if len(analyses) < 2:
            return {"error": "Need at least 2 valid group names to compare."}

        # Technique ID sets per group
        tech_sets = {
            name: {t["technique_id"] for t in a["techniques"]}
            for name, a in analyses.items()
        }
        names = list(tech_sets.keys())
        shared = tech_sets[names[0]].intersection(*[tech_sets[n] for n in names[1:]])

        unique = {name: tech_sets[name] - shared for name in names}

        return {
            "groups": list(analyses.keys()),
            "shared_techniques": sorted(shared),
            "shared_count": len(shared),
            "unique": {n: sorted(ids) for n, ids in unique.items()},
            "tactic_coverage": {n: a["coverage"] for n, a in analyses.items()},
        }

    def _map_to_phases(self, techniques: list[dict]) -> dict[str, list[dict]]:
        phase_map: dict[str, list] = defaultdict(list)
        for t in techniques:
            for tactic in t.get("tactic", []):
                phase_map[tactic].append(t)
        return dict(phase_map)

    def _tactic_coverage(self, phase_map: dict) -> list[dict]:
        return [
            {
                "tactic": t,
                "label": TACTIC_LABELS.get(t, t.replace("-", " ").title()),
                "count": len(phase_map.get(t, [])),
            }
            for t in self.tactic_order
        ]

    def _detection_opportunities(self, phase_map: dict) -> list[dict]:
        """
        Map each tactic to high-value detection data sources and strategies.
        Guidance is per tactic, sourced from MITRE ATT&CK data sources.
        """
        DETECTION_MAP = {
            "initial-access":        {"sources": ["Email gateway logs", "Web proxy logs", "Endpoint telemetry"], "strategy": "Monitor for spearphishing attachments, unusual external connections, and drive-by download indicators."},
            "execution":             {"sources": ["Process creation logs (Sysmon 1)", "Script block logging", "Command-line auditing"], "strategy": "Alert on LOLBin abuse (mshta, wscript, certutil), encoded PowerShell, and unusual parent-child process chains."},
            "persistence":           {"sources": ["Registry auditing", "Scheduled task logs", "Service creation events (7045)"], "strategy": "Baseline autorun locations; alert on new run keys, services, and scheduled tasks created by non-admin processes."},
            "privilege-escalation":  {"sources": ["Security event logs (4672, 4673)", "Sysmon process access"], "strategy": "Monitor token manipulation, UAC bypass patterns, and named pipe impersonation."},
            # v16.x combined tactic — kept for caches that pre-date v19.0
            "defense-evasion":       {"sources": ["Sysmon logs", "AV/EDR telemetry", "File integrity monitoring"], "strategy": "Detect timestomping, process hollowing (unusual memory allocations), and signed binary proxy execution."},
            # v19.0 split: Defense Evasion → Stealth + Defense Impairment
            "stealth":               {"sources": ["Sysmon logs", "File integrity monitoring", "EDR telemetry"], "strategy": "Detect process masquerading (binaries named to mimic system processes), timestomping, process hollowing, and signed binary proxy execution."},
            "defense-impairment":    {"sources": ["AV/EDR telemetry", "Windows Event Log (7045, 4657)", "Endpoint configuration monitoring"], "strategy": "Alert on AMSI bypass strings, security tool termination, event log clearing (EID 1102/104), and registry changes that disable security products."},
            "credential-access":     {"sources": ["LSASS access events (Sysmon 10)", "4624/4625 logon events", "SAM/NTDS auditing"], "strategy": "Alert on lsass.exe memory reads from non-system processes, unusual Kerberoasting activity, and credential dumping tools."},
            "discovery":             {"sources": ["Process creation", "Network connections", "Active Directory query logs"], "strategy": "High-volume enumeration of AD objects, net commands, and LDAP queries from non-admin workstations."},
            "lateral-movement":      {"sources": ["4648 explicit logon events", "SMB/RDP logs", "WMI activity logs"], "strategy": "Alert on pass-the-hash patterns, unusual RDP from workstation-to-workstation, and WMI remote execution."},
            "collection":            {"sources": ["File access auditing", "DLP telemetry", "Clipboard monitoring"], "strategy": "Large-scale file reads from sensitive directories, archive creation (zip/rar), and unusual access to email stores."},
            "command-and-control":   {"sources": ["DNS query logs", "Proxy/firewall logs", "NetFlow data"], "strategy": "Detect beaconing (regular intervals), DNS tunneling (high-entropy subdomains), and traffic to newly-registered domains."},
            "exfiltration":          {"sources": ["Proxy/firewall logs", "DLP", "Cloud audit logs"], "strategy": "Alert on large outbound transfers, uploads to cloud storage from unusual processes, and DNS/ICMP tunneling."},
            "impact":                {"sources": ["Event logs 1102/104 (log clearing)", "VSS auditing", "Backup system alerts"], "strategy": "Monitor for shadow copy deletion (vssadmin delete), mass file encryption, and system log clearing."},
        }
        result = []
        for tactic, techs in phase_map.items():
            det = DETECTION_MAP.get(tactic, {"sources": ["General telemetry"], "strategy": "Review vendor-specific detection guidance."})
            result.append({
                "tactic": tactic,
                "label": TACTIC_LABELS.get(tactic, tactic),
                "technique_count": len(techs),
                "detection_sources": det["sources"],
                "detection_strategy": det["strategy"],
            })
        return sorted(result, key=lambda x: self.tactic_order.index(x["tactic"]) if x["tactic"] in self.tactic_order else 99)

    def _tactic_coverage_pct(self, phase_map: dict) -> dict:
        """Documented tactic coverage (%) — what fraction of ATT&CK tactics MITRE has
        documented at least one technique for this group. Reflects documentation
        depth, not threat severity."""
        total = len(self.tactic_order)
        covered = sum(1 for t in self.tactic_order if phase_map.get(t))
        pct = round(covered / total * 100) if total else 0
        return {
            "covered_tactics": covered,
            "total_tactics": total,
            "coverage_pct": pct,
        }
