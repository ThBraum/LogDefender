from __future__ import annotations

import json
from pathlib import Path
from typing import List

from logdefender.knowledge_base import get_mitre_for_rule, get_playbook_for_rule
from logdefender.models import Alert


def write_alerts_json(alerts: List[Alert], out_dir: str | Path) -> Path:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    out_path = out_dir / "alerts.json"

    payload = []
    for alert in alerts:
        row = alert.model_dump(by_alias=True)
        row["mitre"] = get_mitre_for_rule(alert.rule_id)
        row["triage_playbook"] = get_playbook_for_rule(alert.rule_id)
        payload.append(row)

    out_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, default=str), encoding="utf-8"
    )
    return out_path
