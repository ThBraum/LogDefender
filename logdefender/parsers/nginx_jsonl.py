from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Iterator, Optional

from logdefender.models import Event


def _parse_ts(value: str) -> datetime:
    if not value:
        return datetime.now(timezone.utc)
    value = value.replace("Z", "+00:00")
    return datetime.fromisoformat(value)


def parse_nginx_jsonl(path: str | Path) -> Iterator[Event]:
    path = Path(path)

    with path.open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue

            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            ip = str(data.get("remote_addr") or data.get("ip") or "")
            ts_raw = str(data.get("time_iso8601") or data.get("ts") or "")
            method = str(data.get("request_method") or data.get("method") or "")
            path_ = str(data.get("request_uri") or data.get("path") or "")
            status = int(data.get("status") or 0)
            ua = data.get("http_user_agent") or data.get("user_agent")
            username = data.get("remote_user") or data.get("username")

            if not ip or not method or not path_ or status == 0:
                continue

            yield Event(
                ts=_parse_ts(ts_raw),
                ip=ip,
                method=method.upper(),
                path=path_,
                status=status,
                user_agent=str(ua) if ua else None,
                username=str(username) if username else None,
                raw=data,
            )
