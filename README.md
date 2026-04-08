# Crimson Phoenix — APT Campaign Analysis & Blue Team Training Platform

Threat intelligence research tool for analyzing APT group TTPs, mapping
kill-chain coverage, identifying detection opportunities, and running
structured blue team training scenarios. All data sourced from public
threat intelligence (MITRE ATT&CK, open-source CTI reports).

## Features

- **APT group analysis** — technique mapping, kill-chain coverage heatmap, severity scoring
- **Group comparison** — TTP overlap and unique-technique analysis across multiple actors
- **Detection guidance** — per-tactic data sources and detection strategies
- **Blue team training** — scenario-based exercises with observables, analysis questions, and mitigations
- **MITRE ATT&CK integration** — live data via `mitreattack-python`; falls back to bundled data offline
- **Web dashboard** — interactive Plotly charts; training scenario explorer

## Installation

```bash
pip install -r requirements.txt
```

ATT&CK STIX data (~30 MB) downloads automatically on first run and caches to `data/`.

## Usage

### CLI

```bash
python phoenix.py groups                      # List all ATT&CK threat groups
python phoenix.py analyze "APT29"             # Full TTP analysis + detection guidance
python phoenix.py analyze "Lazarus Group" --json  # Machine-readable output
python phoenix.py compare "APT29" "APT28"    # Compare TTP overlap
python phoenix.py scenarios                   # List training scenarios
python phoenix.py scenario sc-001             # Show scenario with Q&A
python phoenix.py web                         # Launch web dashboard
```

### Web dashboard

```bash
cd web && python app.py
# Open http://localhost:5002
```

## Training scenarios included

| ID | Difficulty | Technique | APT |
|----|-----------|-----------|-----|
| sc-001 | Beginner | T1566.001 Spearphishing Attachment | APT28 |
| sc-002 | Intermediate | T1003.001 LSASS Memory Dump | APT29 |
| sc-003 | Beginner | T1053.005 Scheduled Task Persistence | Lazarus Group |
| sc-004 | Advanced | T1071.004 DNS Tunneling C2 | Turla |

## Project structure

```
CrimsonPhoenix/
├── core/
│   ├── attck_client.py          # MITRE ATT&CK API wrapper + offline fallback
│   ├── campaign_analyzer.py     # TTP mapping, coverage scoring, detection guidance
│   └── training_scenarios.py   # Blue team scenario library
├── web/
│   ├── app.py                   # Flask dashboard (port 5002)
│   └── templates/               # index.html (analysis), training.html (scenarios)
├── phoenix.py                   # CLI entry point
├── requirements.txt
└── README.md
```

## Data sources

All group and technique data is sourced from [MITRE ATT&CK](https://attack.mitre.org/)
(CC BY 4.0). Campaign descriptions reference publicly available threat intelligence reports
from Mandiant, CrowdStrike, CISA advisories, and academic research.
