from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field, model_validator


class Event(BaseModel):
    ts: datetime
    ip: str
    method: str
    path: str
    status: int
    user_agent: Optional[str] = None
    username: Optional[str] = None
    raw: Dict[str, Any] = Field(default_factory=dict)


class EvidenceItem(BaseModel):
    ts: datetime
    ip: Optional[str] = None
    username: Optional[str] = None
    method: Optional[str] = None
    path: Optional[str] = None
    status: Optional[int] = None
    user_agent: Optional[str] = None
    raw: Optional[Dict[str, Any]] = None


class Alert(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    alert_id: Optional[str] = None
    rule_id: str
    title: str
    severity: str  # "low" | "medium" | "high"
    confidence: float = Field(ge=0.0, le=1.0)
    first_seen: datetime
    last_seen: datetime
    time_window_seconds: int = Field(alias="time_window", ge=0)
    count: int = Field(alias="event_count", ge=0)
    entities: Dict[str, Any] = Field(default_factory=dict)
    evidence: List[EvidenceItem] = Field(default_factory=list)
    recommended_actions: List[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _set_alert_id_if_missing(self) -> "Alert":
        if self.alert_id:
            return self

        entities_json = json.dumps(self.entities, sort_keys=True, ensure_ascii=False, default=str)
        fingerprint = "|".join(
            [
                self.rule_id,
                self.first_seen.isoformat(),
                self.last_seen.isoformat(),
                str(self.time_window_seconds),
                str(self.count),
                entities_json,
            ]
        )
        self.alert_id = hashlib.sha1(fingerprint.encode("utf-8")).hexdigest()[:16]
        return self
