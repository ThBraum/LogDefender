from __future__ import annotations

from collections import defaultdict, deque
from datetime import timedelta
from typing import Deque, Dict, List

from logdefender.models import Alert, Event


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
                alerts.append(
                    Alert(
                        rule_id="SCAN_4XX",
                        title="Possible path scanning (many 4xx responses)",
                        severity="medium",
                        first_seen=q[0].ts,
                        last_seen=q[-1].ts,
                        count=len(q),
                        entities={"ip": ip, "unique_paths": len(paths)},
                        evidence=[
                            {"ts": x.ts.isoformat(), "path": x.path, "status": x.status}
                            for x in list(q)[-20:]
                        ],
                    )
                )
                q.clear()
                break

    return alerts
