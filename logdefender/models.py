from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class Event(BaseModel):
    ts: datetime
    ip: str
    method: str
    path: str
    status: int
    user_agent: Optional[str] = None
    username: Optional[str] = None
    raw: Dict[str, Any] = Field(default_factory=dict)


class Alert(BaseModel):
    rule_id: str
    title: str
    severity: str  # "low" | "medium" | "high"
    first_seen: datetime
    last_seen: datetime
    count: int
    entities: Dict[str, Any] = Field(default_factory=dict)
    evidence: List[Dict[str, Any]] = Field(default_factory=list)
