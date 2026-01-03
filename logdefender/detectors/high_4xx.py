from __future__ import annotations

from collections import defaultdict
from typing import List

from logdefender.models import Alert, Event


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
            alerts.append(
                Alert(
                    rule_id="HIGH_4XX_RATE",
                    title="High 4xx rate per IP",
                    severity="low",
                    first_seen=first,
                    last_seen=last,
                    count=bad,
                    entities={"ip": ip, "total_requests": total, "ratio": round(ratio, 3)},
                    evidence=[
                        {"ts": e.ts.isoformat(), "path": e.path, "status": e.status}
                        for e in evs[:20]
                    ],
                )
            )

    return alerts
