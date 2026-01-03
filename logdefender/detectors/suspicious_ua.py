from __future__ import annotations

import re
from typing import List
from logdefender.models import Alert, Event


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

    hits = []
    for e in events:
        if not e.user_agent:
            continue
        if any(rx.search(e.user_agent) for rx in regexes):
            hits.append(e)

    if not hits:
        return []

    first = min(h.ts for h in hits)
    last = max(h.ts for h in hits)

    return [
        Alert(
            rule_id="SUSPICIOUS_UA",
            title="Suspicious User-Agent detected",
            severity="medium",
            first_seen=first,
            last_seen=last,
            count=len(hits),
            entities={"patterns": patterns},
            evidence=[{"ts": h.ts.isoformat(), "ip": h.ip, "ua": h.user_agent, "path": h.path} for h in hits[:20]],
        )
    ]
