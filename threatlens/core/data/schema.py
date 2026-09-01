from __future__ import annotations

from typing import Any
from pydantic import BaseModel, Field, field_validator

from .utils import _to_iso_utc


class NormalizedEvent(BaseModel):
    event_uid: str = Field(...)
    event_id: int | None = Field(None)
    timestamp: str | None = Field(None)
    host: str | None = Field(None)
    process_name: str | None = Field(None)
    process_id: int | None = Field(None)
    parent_process: str | None = Field(None)
    command_line: str | None = Field(None)
    user: str | None = Field(None)
    tactic_hint: str | None = Field(None)
    raw: dict[str, Any] = Field(...)

    @field_validator('event_uid')
    @classmethod
    def check_event_uid(cls, v: str) -> str:
        if not v or ':' not in v:
            raise ValueError('event_uid must be non-empty and in format file:lineno')
        return v

    @field_validator('event_id')
    @classmethod
    def check_event_id(cls, v: int | None) -> int | None:
        if v is None:
            return None
        if not (0 <= v <= 65535):
            raise ValueError('event_id out of range 0..65535')
        return v

    @field_validator('timestamp')
    @classmethod
    def check_timestamp(cls, v: str | None) -> str | None:
        if v is None:
            return None
        iso = _to_iso_utc(v)
        if iso is None:
            raise ValueError('timestamp is not a parseable ISO8601/UTC string')
        return iso

    @field_validator('process_id')
    @classmethod
    def check_process_id(cls, v: int | None) -> int | None:
        if v is None:
            return None
        if v < 0:
            raise ValueError('process_id must be >= 0')
        return v
