#!/usr/bin/env python3
"""
Crimson Phoenix — APT Campaign Analysis & Blue Team Training Platform
CLI interface.

Usage:
    python phoenix.py groups                      # List all ATT&CK groups
    python phoenix.py analyze "APT29"             # Analyze a group's TTPs
    python phoenix.py compare "APT29" "APT28"     # Compare two groups
    python phoenix.py scenarios                   # List training scenarios
    python phoenix.py scenario sc-001             # Show a specific scenario
    python phoenix.py web                         # Start the web dashboard
"""

import argparse
import json
import sys
import logging


def setup_logging(verbose: bool = False):
    logging.basicConfig(
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        level=logging.DEBUG if verbose else logging.WARNING,
    )


def cmd_groups(_args):
    from core.attck_client import AttckClient
    client = AttckClient()
    groups = client.get_all_groups()
    print(f"\n{'Name':<25} {'Aliases'}")
    print("-" * 70)
    for g in groups:
        aliases = ", ".join(g.get("aliases", [])[:2])
        print(f"  {g['name']:<23} {aliases}")
    print(f"\n{len(groups)} groups total\n")


def cmd_analyze(args):
    from core.campaign_analyzer import CampaignAnalyzer
    analyzer = CampaignAnalyzer()
    try:
        result = analyzer.analyze_group(args.group)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    g = result["group"]
    cov = result["tactic_coverage_pct"]
    print(f"\n{'='*65}")
    print(f"  {g['name']}  ({', '.join(g.get('aliases', [])[:2])})")
    print(f"{'='*65}")
    print(f"  Techniques  : {result['technique_count']}")
    print(f"  Tactic coverage: {cov['coverage_pct']}%  ({cov['covered_tactics']}/{cov['total_tactics']} tactics)")
    print(f"\n  Tactic breakdown:")
    for t in result["coverage"]:
        bar = "█" * t["count"] if t["count"] else "·"
        print(f"    {t['label']:<32} {t['count']:>3}  {bar[:20]}")

    # Sample procedure text (the 'use' field, populated from relationship descriptions)
    with_use = [t for t in result["techniques"] if t.get("use")]
    if with_use:
        print(f"\n  Sample procedures ({len(with_use)} techniques have group-specific text):")
        for t in with_use[:5]:
            preview = t["use"][:110].rstrip()
            suffix = "…" if len(t["use"]) > 110 else ""
            print(f"    {t['technique_id']}  {t['name']}")
            print(f"      {preview}{suffix}")

    print(f"\n  Detection guidance: {len(result['detection_opportunities'])} tactics")
    print()

    if args.json:
        print(json.dumps(result, indent=2))


def cmd_compare(args):
    from core.campaign_analyzer import CampaignAnalyzer
    analyzer = CampaignAnalyzer()
    result = analyzer.compare_groups(args.groups)
    if "error" in result:
        print(f"Error: {result['error']}", file=sys.stderr)
        sys.exit(1)

    print(f"\nComparing: {', '.join(result['groups'])}")
    print(f"Shared techniques: {result['shared_count']}")
    if result["shared_techniques"]:
        print(f"  {', '.join(result['shared_techniques'][:20])}")
    print()
    for name, unique in result["unique"].items():
        print(f"  Unique to {name}: {len(unique)} techniques")


def cmd_scenarios(args):
    from core.training_scenarios import get_all_scenarios, get_scenarios_by_difficulty
    if args.difficulty:
        scenarios = get_scenarios_by_difficulty(args.difficulty)
    else:
        scenarios = get_all_scenarios()

    print(f"\n{'ID':<10} {'Difficulty':<14} {'Tactic':<25} Title")
    print("-" * 80)
    for s in scenarios:
        print(f"  {s['id']:<8} {s['difficulty']:<12} {s['tactic']:<23} {s['title']}")
    print()


def cmd_scenario(args):
    from core.training_scenarios import get_scenario
    s = get_scenario(args.id)
    if s is None:
        print(f"Scenario not found: {args.id}", file=sys.stderr)
        sys.exit(1)

    print(f"\n{'='*65}")
    print(f"  [{s['id']}] {s['title']}")
    print(f"  APT: {s['apt_group']}  |  {s['difficulty']}  |  {s['technique_id']}")
    print(f"{'='*65}")
    print(f"\n{s['scenario_description']}\n")
    print("Observables:")
    for obs in s["observables"]:
        print(f"  · {obs}")
    print("\nAnalysis Questions:")
    for i, (q, a) in enumerate(zip(s["questions"], s["answers"]), 1):
        print(f"\n  {i}. {q}")
        print(f"     → {a}")
    print("\nMitigations:")
    for m in s["mitigations"]:
        print(f"  ✓ {m}")
    print()


def cmd_web(_args):
    import subprocess
    print("Starting Crimson Phoenix web dashboard at http://localhost:5002")
    subprocess.run([sys.executable, "web/app.py"])


def main():
    parser = argparse.ArgumentParser(
        description="Crimson Phoenix — APT Campaign Analysis & Blue Team Training"
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("groups", help="List all ATT&CK threat groups").set_defaults(func=cmd_groups)

    p_analyze = sub.add_parser("analyze", help="Analyze an APT group's TTPs")
    p_analyze.add_argument("group", help='Group name, e.g. "APT29"')
    p_analyze.add_argument("--json", action="store_true")
    p_analyze.set_defaults(func=cmd_analyze)

    p_compare = sub.add_parser("compare", help="Compare multiple APT groups")
    p_compare.add_argument("groups", nargs="+", help="Group names to compare")
    p_compare.set_defaults(func=cmd_compare)

    p_sc = sub.add_parser("scenarios", help="List blue team training scenarios")
    p_sc.add_argument("--difficulty", choices=["Beginner", "Intermediate", "Advanced"])
    p_sc.set_defaults(func=cmd_scenarios)

    p_one = sub.add_parser("scenario", help="Show a specific scenario")
    p_one.add_argument("id", help="Scenario ID, e.g. sc-001")
    p_one.set_defaults(func=cmd_scenario)

    sub.add_parser("web", help="Launch the web dashboard").set_defaults(func=cmd_web)

    args = parser.parse_args()
    setup_logging(args.verbose)
    args.func(args)


if __name__ == "__main__":
    main()
