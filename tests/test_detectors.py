from datetime import datetime, timedelta, timezone

from logdefender.detectors.brute_force import detect_bruteforce
from logdefender.models import Event


def test_bruteforce_triggers():
    base = datetime(2026, 1, 3, 0, 0, 0, tzinfo=timezone.utc)
    events = []
    for i in range(12):
        events.append(
            Event(
                ts=base + timedelta(seconds=i * 10),
                ip="1.2.3.4",
                method="POST",
                path="/login",
                status=401,
                user_agent="curl/8.0",
                raw={},
            )
        )

    alerts = detect_bruteforce(events, window_seconds=300, threshold=10)
    assert len(alerts) >= 1
    assert alerts[0].rule_id == "BRUTE_FORCE"
