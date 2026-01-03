from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import List

from logdefender.detectors.brute_force import detect_bruteforce
from logdefender.detectors.high_4xx import detect_high_4xx_rate
from logdefender.detectors.scanning import detect_scanning
from logdefender.detectors.sensitive_endpoints import detect_sensitive_endpoints
from logdefender.detectors.suspicious_ua import detect_suspicious_user_agents
from logdefender.models import Alert, Event
from logdefender.parsers.nginx_jsonl import parse_nginx_jsonl
from logdefender.reporting.json_alerts import write_alerts_json
from logdefender.reporting.markdown import write_report_md


@dataclass(frozen=True)
class AnalysisResult:
    events: List[Event]
    alerts: List[Alert]
    alerts_path: Path
    report_path: Path


def run_analysis(input_path: str | Path, out_dir: str | Path) -> AnalysisResult:
    input_path = Path(input_path)
    out_dir = Path(out_dir)

    events = list(parse_nginx_jsonl(input_path))
    events.sort(key=lambda e: e.ts)

    alerts: List[Alert] = []
    alerts.extend(detect_bruteforce(events))
    alerts.extend(detect_high_4xx_rate(events))
    alerts.extend(detect_scanning(events))
    alerts.extend(detect_sensitive_endpoints(events))
    alerts.extend(detect_suspicious_user_agents(events))

    alerts_path = write_alerts_json(alerts, out_dir)
    report_path = write_report_md(events, alerts, out_dir)

    return AnalysisResult(
        events=events,
        alerts=alerts,
        alerts_path=alerts_path,
        report_path=report_path,
    )
