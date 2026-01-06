from __future__ import annotations

import json
from pathlib import Path
from typing import List

from logdefender.models import Alert


def write_alerts_json(alerts: List[Alert], out_dir: str | Path) -> Path:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    out_path = out_dir / "alerts.json"
    payload = [a.model_dump(by_alias=True) for a in alerts]

    out_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, default=str), encoding="utf-8"
    )
    return out_path
