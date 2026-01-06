from __future__ import annotations

from collections import defaultdict, deque
from datetime import timedelta
from typing import Deque, Dict, List

from logdefender.models import Alert, Event


def _clamp01(value: float) -> float:
    return max(0.0, min(1.0, value))


def detect_scanning(
    events: List[Event],
    window_seconds: int = 300,
    threshold: int = 60,
    status_codes: tuple[int, ...] = (404, 403),
) -> List[Alert]:
    window = timedelta(seconds=window_seconds)

    per_ip: Dict[str, List[Event]] = defaultdict(list)
    for e in events:
        if e.status in status_codes:
            per_ip[e.ip].append(e)

    alerts: List[Alert] = []
    for ip, evs in per_ip.items():
        evs.sort(key=lambda x: x.ts)
        q: Deque[Event] = deque()
        paths = set()

        for e in evs:
            q.append(e)
            paths.add(e.path)

            while q and (e.ts - q[0].ts) > window:
                old = q.popleft()
                paths = {x.path for x in q}

            if len(q) >= threshold:
                burst = len(q)
                unique_paths = len(paths)
                if burst >= 200:
                    severity = "high"
                else:
                    severity = "medium"

                statuses = {x.status for x in q}
                confidence = 0.70
                if unique_paths >= 40:
                    confidence += 0.10
                if 404 in statuses and 403 in statuses:
                    confidence += 0.05
                if any(
                    x.user_agent
                    and ("nmap" in x.user_agent.lower() or "dirbuster" in x.user_agent.lower())
                    for x in q
                ):
                    confidence += 0.10
                confidence = _clamp01(confidence)

                alerts.append(
                    Alert(
                        rule_id="SCAN_4XX",
                        title="Possível varredura de paths (muitas respostas 4xx)",
                        severity=severity,
                        confidence=confidence,
                        first_seen=q[0].ts,
                        last_seen=q[-1].ts,
                        time_window=window_seconds,
                        event_count=burst,
                        entities={"ip": ip, "unique_paths": unique_paths},
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
                            "Verificar se o IP pertence a scanner autorizado (VA, monitoramento, red team)",
                            "Checar padrões de paths (ex.: wordlist) e correlacionar com WAF/IDS",
                            "Aplicar bloqueio/rate-limit temporário se não autorizado",
                            "Revisar exposição de rotas e harden de endpoints sensíveis",
                        ],
                    )
                )
                q.clear()
                break

    return alerts
