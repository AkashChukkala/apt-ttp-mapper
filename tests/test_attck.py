"""
Tests guarding the bugs fixed in this project.

Requires the ATT&CK cache to be present (it is downloaded on first run).
Run with:  pytest tests/
"""

import re
import sys
from pathlib import Path

# Allow imports from the project root without installing the package.
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from core.attck_client import AttckClient
from core.campaign_analyzer import CampaignAnalyzer, _tactic_order_from_matrix


@pytest.fixture(scope="module")
def client():
    return AttckClient()


@pytest.fixture(scope="module")
def analyzer():
    return CampaignAnalyzer()


# ---------------------------------------------------------------------------
# Tactic order matches the live data
# ---------------------------------------------------------------------------

def test_every_tactic_in_tactic_order(client, analyzer):
    """Every tactic slug that appears in the downloaded data must be present
    in the tactic order so the sort in _detection_opportunities never falls
    back to position 99."""
    all_tactics = set()
    for group in client.get_all_groups():
        for tech in client.get_group_techniques(group["id"]):
            for tactic in tech.get("tactic", []):
                all_tactics.add(tactic)
    missing = all_tactics - set(analyzer.tactic_order)
    assert not missing, f"Tactics in data but missing from tactic_order: {missing}"


def test_tactic_order_from_matrix_matches_analyzer(client, analyzer):
    """_tactic_order_from_matrix should return the same list CampaignAnalyzer loaded."""
    order = _tactic_order_from_matrix(client._db)
    assert order == analyzer.tactic_order


def test_v19_tactic_split_in_labels(analyzer):
    """v19.0 split tactics must have display labels so the template never shows a raw slug."""
    from core.campaign_analyzer import TACTIC_LABELS
    for tactic in analyzer.tactic_order:
        assert tactic in TACTIC_LABELS, (
            f"Tactic '{tactic}' is in the live data but has no entry in TACTIC_LABELS. "
            "Add it so the dashboard doesn't show raw slugs."
        )


# ---------------------------------------------------------------------------
# APT29 procedure text is non-empty
# ---------------------------------------------------------------------------

def test_apt29_has_procedure_text(client):
    """get_group_techniques must read descriptions from rel['relationships'],
    not the outer wrapper, so the 'use' field should be non-empty for APT29."""
    group = client.get_group_by_name("APT29")
    assert group is not None, "APT29 not found in live data"

    techniques = client.get_group_techniques(group["id"])
    assert techniques, "APT29 returned no techniques"

    non_empty_uses = [t for t in techniques if t.get("use")]
    assert non_empty_uses, (
        "All 'use' fields are empty for APT29 — procedure text is not being read "
        "from rel['relationships']."
    )


def test_use_field_has_no_citations(client):
    """Citation markers like (Citation: Foo2020) must be stripped before display."""
    group = client.get_group_by_name("APT29")
    assert group is not None
    techniques = client.get_group_techniques(group["id"])
    for tech in techniques:
        use = tech.get("use", "")
        assert not re.search(r'\(Citation:', use), (
            f"Citation marker not stripped in technique {tech['technique_id']}: {use[:100]}"
        )


# ---------------------------------------------------------------------------
# Coverage never exceeds 100 %
# ---------------------------------------------------------------------------

def test_coverage_never_exceeds_100(analyzer):
    """_tactic_coverage_pct must always return coverage_pct <= 100."""
    # Use a well-documented group to exercise the full path.
    result = analyzer.analyze_group("APT29")
    pct = result["tactic_coverage_pct"]["coverage_pct"]
    assert pct <= 100, f"Coverage {pct}% exceeds 100%"
    assert pct >= 0


def test_coverage_covered_tactics_le_total(analyzer):
    result = analyzer.analyze_group("APT28")
    cov = result["tactic_coverage_pct"]
    assert cov["covered_tactics"] <= cov["total_tactics"]
