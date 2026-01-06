from __future__ import annotations

import json
from functools import lru_cache
from importlib import resources
from typing import Any, Dict, List, Optional


def _read_json_resource(package: str, name: str) -> Dict[str, Any]:
    with resources.files(package).joinpath(name).open("r", encoding="utf-8") as f:
        return json.load(f)


@lru_cache(maxsize=1)
def load_mitre_map() -> Dict[str, Any]:
    return _read_json_resource("logdefender.data", "mitre_map.json")


@lru_cache(maxsize=1)
def load_triage_playbook() -> Dict[str, Any]:
    return _read_json_resource("logdefender.data", "triage_playbook.json")


def get_mitre_for_rule(rule_id: str) -> Optional[Dict[str, Any]]:
    return load_mitre_map().get(rule_id)


def get_playbook_for_rule(rule_id: str) -> Optional[Dict[str, Any]]:
    return load_triage_playbook().get(rule_id)


def format_mitre_line(mitre: Dict[str, Any]) -> str:
    tactic = mitre.get("tactic")
    techniques: List[Dict[str, Any]] = mitre.get("techniques") or []
    tech_str = ", ".join(
        f"{t.get('id', '').strip()} {t.get('name', '').strip()}".strip()
        for t in techniques
        if (t.get("id") or t.get("name"))
    )

    if tactic and tech_str:
        return f"{tactic} — {tech_str}"
    if tactic:
        return str(tactic)
    if tech_str:
        return tech_str
    return "(não mapeado)"
