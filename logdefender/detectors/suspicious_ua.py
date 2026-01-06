from __future__ import annotations

import re
from collections import defaultdict
from typing import List
from logdefender.models import Alert, Event


def _clamp01(value: float) -> float:
    return max(0.0, min(1.0, value))


DEFAULT_PATTERNS = [
    r"\bcurl\b",
    r"\bwget\b",
    r"\bpython-requests\b",
    r"\bsqlmap\b",
    r"\bnmap\b",
    r"\bdirbuster\b",
]


def detect_suspicious_user_agents(events: List[Event], patterns: List[str] | None = None) -> List[Alert]:
    patterns = patterns or DEFAULT_PATTERNS
    regexes = [re.compile(p, re.IGNORECASE) for p in patterns]

    per_ip = defaultdict(list)
    for e in events:
        if not e.user_agent:
            continue
        if any(rx.search(e.user_agent) for rx in regexes):
            per_ip[e.ip].append(e)

    if not per_ip:
        return []

    alerts: List[Alert] = []
    for ip, hits in per_ip.items():
        first = min(h.ts for h in hits)
        last = max(h.ts for h in hits)
        time_window_seconds = max(0, int((last - first).total_seconds()))

        count = len(hits)
        if count >= 50:
            severity = "high"
        elif count >= 10:
            severity = "medium"
        else:
            severity = "low"

        ua_values = [h.user_agent for h in hits if h.user_agent]
        unique_uas = sorted(set(ua_values))

        # heurística simples baseada em ferramentas frequentemente automatizadas
        confidence = 0.60
        if any(ua and ("sqlmap" in ua.lower() or "nmap" in ua.lower() or "dirbuster" in ua.lower()) for ua in unique_uas):
            confidence += 0.20
        if any(ua and ("python-requests" in ua.lower() or "curl" in ua.lower() or "wget" in ua.lower()) for ua in unique_uas):
            confidence += 0.10
        if count >= 10:
            confidence += 0.05
        confidence = _clamp01(confidence)

        alerts.append(
            Alert(
                rule_id="SUSPICIOUS_UA",
                title="User-Agent suspeito detectado",
                severity=severity,
                confidence=confidence,
                first_seen=first,
                last_seen=last,
                time_window=time_window_seconds,
                event_count=count,
                entities={"ip": ip, "user_agent": unique_uas[:5], "patterns": patterns},
                evidence=[
                    {
                        "ts": h.ts,
                        "ip": h.ip,
                        "username": h.username,
                        "method": h.method,
                        "path": h.path,
                        "status": h.status,
                        "user_agent": h.user_agent,
                    }
                    for h in hits[:20]
                ],
                recommended_actions=[
                    "Validar se o User-Agent é esperado (healthcheck, monitoramento, integração)",
                    "Correlacionar com 4xx/scan e acessos a endpoints sensíveis do mesmo IP",
                    "Se não autorizado, bloquear IP/UA no WAF e aplicar rate-limit",
                    "Revisar logs da aplicação para sinais de exploração automatizada",
                ],
            )
        )

    return alerts
