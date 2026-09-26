# apt-ttp-mapper

A command-line tool for mapping MITRE ATT&CK threat group TTPs, comparing
actor overlap, and running structured blue team detection exercises.

**ATT&CK version:** 19.2  
All group and technique data is sourced from [MITRE ATT&CK](https://attack.mitre.org/) (CC BY 4.0).

## Features

- **APT group analysis** — technique list mapped to kill-chain phases, tactic coverage
- **Group comparison** — TTP overlap and unique-technique analysis across multiple actors
- **Detection guidance** — per-tactic data sources and detection strategies
- **Blue team training** — scenario-based exercises with observables, analysis questions, and mitigations
- **Web dashboard** — interactive Plotly charts; training scenario explorer

## Installation

```bash
pip install -r requirements.txt
```

ATT&CK STIX data (~30 MB) is downloaded from MITRE on first run and cached to
`data/enterprise_attck.json`. Subsequent runs are fully offline.  
To force a re-download, delete `data/enterprise_attck.json`.

## Usage

### CLI

```bash
python ttp_mapper.py groups                          # List all ATT&CK threat groups
python ttp_mapper.py analyze "APT29"                 # Full TTP analysis + detection guidance
python ttp_mapper.py analyze "Lazarus Group" --json  # Machine-readable output
python ttp_mapper.py compare "APT29" "APT28"         # Compare TTP overlap
python ttp_mapper.py scenarios                       # List training scenarios
python ttp_mapper.py scenario sc-001                 # Show scenario with Q&A
python ttp_mapper.py web                             # Launch web dashboard
```

### Sample output

```
$ python ttp_mapper.py analyze "APT29"

Group: APT29 (Cozy Bear / NOBELIUM)
Techniques documented: 195
Tactic coverage: 93% (13/14 tactics)

Tactic breakdown:
  Reconnaissance          :  5 techniques
  Initial Access          :  5 techniques
  Execution               : 13 techniques
  Persistence             : 26 techniques
  ...
```

### Web dashboard

```bash
cd web && python app.py
# Open http://localhost:5002
```

## Training scenarios

| ID | Difficulty | Technique | APT |
|----|-----------|-----------|-----|
| sc-001 | Beginner | T1566.001 Spearphishing Attachment (.docm) | APT28 |
| sc-002 | Intermediate | T1003.001 LSASS Memory Dump | APT29 |
| sc-003 | Beginner | T1053.005 Scheduled Task Persistence | Lazarus Group |
| sc-004 | Advanced | T1071.004 DNS Tunneling C2 | Turla |

## Tests

```bash
pytest tests/
```

The first run downloads ATT&CK data before the test suite runs (~30 s on a
fast connection). Subsequent runs are fast.

## Project structure

```
apt-ttp-mapper/
├── core/
│   ├── attck_client.py          # MITRE ATT&CK API wrapper
│   ├── campaign_analyzer.py     # TTP mapping, coverage, detection guidance
│   └── training_scenarios.py   # Blue team scenario library
├── tests/
│   └── test_attck.py            # Regression tests for fixed bugs
├── web/
│   ├── app.py                   # Flask dashboard (port 5002)
│   └── templates/               # index.html (analysis), training.html (scenarios)
├── ttp_mapper.py                # CLI entry point
├── requirements.txt             # Exact pinned versions (pip freeze)
└── README.md
```

## Limitations

- **Detection guidance is per tactic, not per group.** The same detection
  strategies are shown for every group that uses a given tactic.
- **Scenarios are hand-written.** The four training scenarios are static;
  they are not generated from live ATT&CK data.
- **Coverage reflects MITRE documentation depth**, not actual threat
  activity. A group with 95% tactic coverage means MITRE has documented
  techniques across 95% of tactics — not that the group actively uses all of them.
- **ATT&CK version is pinned.** Update `ATTCK_VERSION` in
  `core/attck_client.py` and delete the cache to pull a newer release.

## Data sources

Group and technique data: [MITRE ATT&CK](https://attack.mitre.org/) (CC BY 4.0).  
Campaign descriptions reference publicly available threat intelligence from
Mandiant, CrowdStrike, CISA advisories, and academic research.
