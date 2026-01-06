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
    lines.append("# Relatório LogDefender\n")
    lines.append(f"- Total de eventos: **{len(events)}**\n")
    lines.append(
        f"- Alertas: **{len(alerts)}** (alto={sev.get('high',0)}, médio={sev.get('medium',0)}, baixo={sev.get('low',0)})\n"
    )

    lines.append("\n## IPs mais frequentes\n")
    for ip, n in top_ips:
        lines.append(f"- `{ip}`: {n}\n")

    lines.append("\n## Paths mais frequentes\n")
    for path, n in top_paths:
        lines.append(f"- `{path}`: {n}\n")

    lines.append("\n## Alertas\n")
    for a in alerts:
        lines.append(f"\n### {a.rule_id} — {a.title}\n")
        if a.alert_id:
            lines.append(f"- ID do alerta: `{a.alert_id}`\n")
        lines.append(f"- Severidade: **{a.severity}**\n")
        lines.append(f"- Confiança: **{a.confidence:.2f}**\n")
        lines.append(f"- Janela: `{a.first_seen.isoformat()}` → `{a.last_seen.isoformat()}`\n")
        lines.append(f"- Janela de tempo: **{a.time_window_seconds}s**\n")
        lines.append(f"- Contagem de eventos: **{a.count}**\n")
        if a.entities:
            lines.append(f"- Entidades: `{a.entities}`\n")
        if a.recommended_actions:
            lines.append("- Ações recomendadas:\n")
            for action in a.recommended_actions:
                lines.append(f"  - {action}\n")

    out_path = out_dir / "report.md"
    out_path.write_text("".join(lines), encoding="utf-8")
    return out_path
