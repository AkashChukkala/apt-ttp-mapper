"""
Crimson Phoenix — Flask web dashboard
APT campaign analysis and blue team training interface.
"""

import sys
import logging
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from flask import Flask, render_template, request, jsonify

from core.campaign_analyzer import CampaignAnalyzer
from core.attck_client import AttckClient
from core.training_scenarios import get_all_scenarios, get_scenario, get_scenarios_by_difficulty

app = Flask(__name__)
logger = logging.getLogger(__name__)

_analyzer = None
_client = None

def get_analyzer():
    global _analyzer
    if _analyzer is None:
        _analyzer = CampaignAnalyzer()
    return _analyzer

def get_client():
    global _client
    if _client is None:
        _client = AttckClient()
    return _client


# ------------------------------------------------------------------
# Pages
# ------------------------------------------------------------------

@app.route("/")
def index():
    groups = get_client().get_all_groups()
    scenarios = get_all_scenarios()
    return render_template("index.html", groups=groups, scenarios=scenarios)


@app.route("/training")
def training():
    difficulty = request.args.get("difficulty", "")
    if difficulty:
        scenarios = get_scenarios_by_difficulty(difficulty)
    else:
        scenarios = get_all_scenarios()
    return render_template("training.html", scenarios=scenarios, difficulty=difficulty)


# ------------------------------------------------------------------
# API
# ------------------------------------------------------------------

@app.route("/api/groups")
def api_groups():
    return jsonify(get_client().get_all_groups())


@app.route("/api/analyze/<group_name>")
def api_analyze(group_name: str):
    try:
        result = get_analyzer().analyze_group(group_name)
        # Limit technique descriptions for payload size
        for t in result.get("techniques", []):
            t["description"] = t["description"][:300] if t["description"] else ""
        return jsonify(result)
    except ValueError as e:
        return jsonify({"error": str(e)}), 404
    except Exception as e:
        logger.exception("Analysis error for %s", group_name)
        return jsonify({"error": "Analysis failed"}), 500


@app.route("/api/compare", methods=["POST"])
def api_compare():
    data = request.get_json(silent=True) or {}
    groups = data.get("groups", [])
    if len(groups) < 2:
        return jsonify({"error": "Provide at least 2 group names"}), 400
    result = get_analyzer().compare_groups(groups)
    return jsonify(result)


@app.route("/api/scenario/<scenario_id>")
def api_scenario(scenario_id: str):
    s = get_scenario(scenario_id)
    if s is None:
        return jsonify({"error": "Scenario not found"}), 404
    return jsonify(s)


@app.route("/health")
def health():
    return jsonify({"status": "ok", "service": "CrimsonPhoenix"})


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    app.run(host="0.0.0.0", port=5002, debug=False)
