from __future__ import annotations

from collections import defaultdict, deque
from datetime import timedelta
from typing import Deque, Dict, List, Tuple

from logdefender.models import Alert, Event


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
                alerts.append(
                    Alert(
                        rule_id="BRUTE_FORCE",
                        title="Possible brute force on authentication endpoint",
                        severity="high",
                        first_seen=first,
                        last_seen=last,
                        count=len(q),
                        entities={"ip": ip, "username": None if user == "-" else user},
                        evidence=[
                            {"ts": x.ts.isoformat(), "path": x.path, "status": x.status}
                            for x in list(q)[-20:]
                        ],
                    )
                )
                q.clear()
                break

    return alerts
