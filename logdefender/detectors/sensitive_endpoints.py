from __future__ import annotations

from typing import Iterable, List
from logdefender.models import Alert, Event


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

    first = min(h.ts for h in hits)
    last = max(h.ts for h in hits)

    return [
        Alert(
            rule_id="SENSITIVE_ENDPOINT_ACCESS",
            title="Access to sensitive endpoints",
            severity="high",
            first_seen=first,
            last_seen=last,
            count=len(hits),
            entities={"endpoints": sensitive},
            evidence=[
                {"ts": h.ts.isoformat(), "ip": h.ip, "path": h.path, "status": h.status}
                for h in hits[:20]
            ],
        )
    ]
