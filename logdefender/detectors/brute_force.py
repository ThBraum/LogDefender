from __future__ import annotations

from collections import defaultdict, deque
from datetime import timedelta
from typing import Deque, Dict, List, Tuple

from logdefender.models import Alert, Event


def _clamp01(value: float) -> float:
    return max(0.0, min(1.0, value))


def detect_bruteforce(
    events: List[Event],
    window_seconds: int = 300,
    threshold: int = 10,
    status_codes: tuple[int, ...] = (401, 403, 429),
    login_prefixes: tuple[str, ...] = ("/login", "/auth", "/signin"),
) -> List[Alert]:
    window = timedelta(seconds=window_seconds)

    candidates = [
        e
        for e in events
        if e.status in status_codes and any(e.path.startswith(p) for p in login_prefixes)
    ]
    if not candidates:
        return []

    # agrupa por IP (e username se tiver)
    groups: Dict[Tuple[str, str], List[Event]] = defaultdict(list)
    for e in candidates:
        key = (e.ip, e.username or "-")
        groups[key].append(e)

    alerts: List[Alert] = []
    for (ip, user), evs in groups.items():
        evs.sort(key=lambda x: x.ts)
        q: Deque[Event] = deque()

        for e in evs:
            q.append(e)
            while q and (e.ts - q[0].ts) > window:
                q.popleft()

            if len(q) >= threshold:
                first = q[0].ts
                last = q[-1].ts

                attempts = len(q)
                if attempts >= 50:
                    severity = "high"
                else:
                    severity = "medium"

                user_value = None if user == "-" else user
                user_agents = sorted({x.user_agent for x in q if x.user_agent})
                paths = sorted({x.path for x in q})
                statuses = sorted({x.status for x in q})

                confidence = 0.65
                if user_value:
                    confidence += 0.15
                if any(s == 429 for s in statuses):
                    confidence += 0.05
                if any(ua and ("curl" in ua.lower() or "python-requests" in ua.lower()) for ua in user_agents):
                    confidence += 0.15
                confidence = _clamp01(confidence)

                alerts.append(
                    Alert(
                        rule_id="BRUTE_FORCE",
                        title="Possível força bruta em endpoint de autenticação",
                        severity=severity,
                        confidence=confidence,
                        first_seen=first,
                        last_seen=last,
                        time_window=window_seconds,
                        event_count=attempts,
                        entities={
                            "ip": ip,
                            "user": user_value,
                            "paths": paths[:10],
                            "user_agent": user_agents[:5],
                        },
                        evidence=[
                            {
                                "ts": x.ts,
                                "ip": x.ip,
                                "username": x.username,
                                "method": x.method,
                                "path": x.path,
                                "status": x.status,
                                "user_agent": x.user_agent,
                            }
                            for x in list(q)[-20:]
                        ],
                        recommended_actions=[
                            "Validar se o IP/UA é esperado (VPN, monitoramento, pentest autorizado)",
                            "Checar tentativas no IdP/app e existência de login bem-sucedido após o burst",
                            "Aplicar rate-limit/ban temporário no IP e revisar regras de WAF/Fail2ban",
                            "Se houver usuário alvo, considerar reset de senha e exigir MFA",
                        ],
                    )
                )
                q.clear()
                break

    return alerts
