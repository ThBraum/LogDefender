from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import List

from logdefender.models import Alert, Event


def write_report_md(events: List[Event], alerts: List[Alert], out_dir: str | Path) -> Path:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    sev = Counter(a.severity for a in alerts)
    top_ips = Counter(e.ip for e in events).most_common(10)
    top_paths = Counter(e.path for e in events).most_common(10)

    lines = []
    lines.append("# LogDefender Report\n")
    lines.append(f"- Total events: **{len(events)}**\n")
    lines.append(
        f"- Alerts: **{len(alerts)}** (high={sev.get('high',0)}, medium={sev.get('medium',0)}, low={sev.get('low',0)})\n"
    )

    lines.append("\n## Top IPs\n")
    for ip, n in top_ips:
        lines.append(f"- `{ip}`: {n}\n")

    lines.append("\n## Top Paths\n")
    for path, n in top_paths:
        lines.append(f"- `{path}`: {n}\n")

    lines.append("\n## Alerts\n")
    for a in alerts:
        lines.append(f"\n### {a.rule_id} — {a.title}\n")
        lines.append(f"- Severity: **{a.severity}**\n")
        lines.append(f"- Window: `{a.first_seen.isoformat()}` → `{a.last_seen.isoformat()}`\n")
        lines.append(f"- Count: **{a.count}**\n")
        if a.entities:
            lines.append(f"- Entities: `{a.entities}`\n")

    out_path = out_dir / "report.md"
    out_path.write_text("".join(lines), encoding="utf-8")
    return out_path
