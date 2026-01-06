from __future__ import annotations

from collections import defaultdict
from typing import List
from logdefender.models import Alert, Event


def _clamp01(value: float) -> float:
    return max(0.0, min(1.0, value))


DEFAULT_SENSITIVE = [
    "/admin",
    "/wp-admin",
    "/.env",
    "/.git",
    "/actuator",
]


def detect_sensitive_endpoints(
    events: List[Event], sensitive: List[str] | None = None
) -> List[Alert]:
    sensitive = sensitive or DEFAULT_SENSITIVE
    hits = [e for e in events if any(e.path.startswith(s) for s in sensitive)]
    if not hits:
        return []

    per_ip = defaultdict(list)
    for e in hits:
        per_ip[e.ip].append(e)

    alerts: List[Alert] = []
    for ip, evs in per_ip.items():
        first = min(h.ts for h in evs)
        last = max(h.ts for h in evs)
        time_window_seconds = max(0, int((last - first).total_seconds()))

        success_hits = sum(1 for e in evs if e.status < 400)
        unique_paths = len({e.path for e in evs})

        confidence = 0.75
        if success_hits > 0:
            confidence += 0.15
        if any(e.user_agent and ("sqlmap" in e.user_agent.lower() or "nmap" in e.user_agent.lower()) for e in evs):
            confidence += 0.05
        confidence = _clamp01(confidence)

        alerts.append(
            Alert(
                rule_id="SENSITIVE_ENDPOINT_ACCESS",
                title="Acesso a endpoints sensíveis",
                severity="high",
                confidence=confidence,
                first_seen=first,
                last_seen=last,
                time_window=time_window_seconds,
                event_count=len(evs),
                entities={
                    "ip": ip,
                    "unique_paths": unique_paths,
                    "endpoints": sensitive,
                },
                evidence=[
                    {
                        "ts": e.ts,
                        "ip": e.ip,
                        "username": e.username,
                        "method": e.method,
                        "path": e.path,
                        "status": e.status,
                        "user_agent": e.user_agent,
                    }
                    for e in evs[:20]
                ],
                recommended_actions=[
                    "Confirmar se o endpoint existe/exposto e se o acesso foi bloqueado (403/404) ou bem-sucedido",
                    "Correlacionar com autenticação e outras atividades do mesmo IP",
                    "Se não autorizado, bloquear IP e revisar regras de WAF/ACL",
                    "Revisar hardening (desabilitar .env/.git, proteger /admin, etc.)",
                ],
            )
        )

    return alerts
