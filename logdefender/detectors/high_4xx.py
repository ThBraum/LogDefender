from __future__ import annotations

from collections import defaultdict
from typing import List

from logdefender.models import Alert, Event


def _clamp01(value: float) -> float:
    return max(0.0, min(1.0, value))


def detect_high_4xx_rate(
    events: List[Event],
    min_requests: int = 50,
    ratio_threshold: float = 0.6,
) -> List[Alert]:
    per_ip = defaultdict(list)
    for e in events:
        per_ip[e.ip].append(e)

    alerts: List[Alert] = []
    for ip, evs in per_ip.items():
        if len(evs) < min_requests:
            continue
        total = len(evs)
        bad = sum(1 for e in evs if 400 <= e.status < 500)
        ratio = bad / total

        if ratio >= ratio_threshold:
            first = min(e.ts for e in evs)
            last = max(e.ts for e in evs)

            unique_paths = len({e.path for e in evs})
            suspicious_ua_hits = sum(
                1
                for e in evs
                if e.user_agent
                and ("python-requests" in e.user_agent.lower() or "curl" in e.user_agent.lower())
            )

            if bad >= 500 and ratio >= 0.9:
                severity = "high"
            elif bad >= 200 and ratio >= 0.8:
                severity = "medium"
            else:
                severity = "low"

            confidence = 0.45
            if unique_paths >= 80:
                confidence += 0.25
            elif unique_paths >= 30:
                confidence += 0.15
            if suspicious_ua_hits >= 5:
                confidence += 0.10
            confidence = _clamp01(confidence)

            time_window_seconds = max(0, int((last - first).total_seconds()))
            alerts.append(
                Alert(
                    rule_id="HIGH_4XX_RATE",
                    title="Alta taxa de 4xx por IP",
                    severity=severity,
                    confidence=confidence,
                    first_seen=first,
                    last_seen=last,
                    time_window=time_window_seconds,
                    event_count=bad,
                    entities={
                        "ip": ip,
                        "total_requests": total,
                        "event_count": bad,
                        "ratio": round(ratio, 3),
                        "unique_paths": unique_paths,
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
                        "Validar se é tráfego legítimo com erro (deploy, rota quebrada) vs varredura",
                        "Checar distribuição de paths (muitos 404/403 diferentes aumenta suspeita)",
                        "Se não autorizado, aplicar rate-limit/bloqueio e correlacionar com alertas de scanning",
                        "Revisar rotas 4xx mais frequentes e endurecer respostas/headers",
                    ],
                )
            )

    return alerts
