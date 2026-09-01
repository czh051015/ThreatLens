from __future__ import annotations

import json
from datetime import timezone
from pathlib import Path
from typing import Any
from pydantic import ValidationError

from .schema import NormalizedEvent
from .utils import _to_iso_utc


# _to_iso_utc moved to utils.py


def _safe_int(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _coalesce(*values: Any) -> Any:
    for value in values:
        if value is not None and value != '':
            return value
    return None


def load_telemetry_events(path: str | Path) -> list[dict[str, Any]]:
    """Parse Mordor JSONL event files into the normalized schema used by analysis/eval."""
    source = Path(path)
    events: list[dict[str, Any]] = []

    with source.open('r', encoding='utf-8') as fh:
        for lineno, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            raw = json.loads(line)

            event_id = _safe_int(_coalesce(raw.get('EventID'), raw.get('event_id')))
            timestamp = _coalesce(raw.get('@timestamp'), raw.get('EventTime'), raw.get('event_time'))
            host = _coalesce(raw.get('Hostname'), raw.get('host'), raw.get('HostName'))
            process_name = _coalesce(
                raw.get('Image'),
                raw.get('process_name'),
                raw.get('ProcessName'),
                raw.get('ImageName'),
            )
            process_id = _safe_int(_coalesce(raw.get('ProcessId'), raw.get('process_id')))
            parent_process = _coalesce(raw.get('ParentImage'), raw.get('parent_image'), raw.get('ParentProcessName'))
            command_line = _coalesce(raw.get('CommandLine'), raw.get('command_line'))
            user = _coalesce(raw.get('User'), raw.get('user'), raw.get('AccountName'))

            event = {
                'event_uid': f'{source.name}:{lineno}',  # 02 §5.1：事件唯一标识，跨数据集唯一、可反查 raw
                'event_id': event_id,
                'timestamp': _to_iso_utc(timestamp),
                'host': host,
                'process_name': process_name,
                'process_id': process_id,
                'parent_process': parent_process,
                'command_line': command_line,
                'user': user,
                'tactic_hint': None,
                'raw': raw,
            }
            try:
                norm = NormalizedEvent(**event)
            except ValidationError as exc:
                raise ValueError(f'{source.name}:{lineno}: {exc}') from exc
            events.append(norm.model_dump())

    return events


if __name__ == '__main__':
    path = Path(__file__).resolve().parents[3] / 'edr' / 'data' / 'telemetry' / 'empire_mimikatz_logonpasswords_2020-08-07103224.json'
    data = load_telemetry_events(path)
    print(f'loaded {len(data)} telemetry events')
    print(data[0])
