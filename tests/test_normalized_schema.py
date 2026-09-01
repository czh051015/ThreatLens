from __future__ import annotations

import pytest

from threatlens.core.data.schema import NormalizedEvent


def test_valid_event_minimal():
    ev = {
        'event_uid': 'file.json:1',
        'event_id': 123,
        'timestamp': '2020-01-01T00:00:00Z',
        'host': 'host1',
        'process_name': None,
        'process_id': None,
        'parent_process': None,
        'command_line': None,
        'user': None,
        'tactic_hint': None,
        'raw': {'a': 1},
    }
    n = NormalizedEvent(**ev)
    assert n.event_uid == 'file.json:1'


@pytest.mark.parametrize('bad', [
    {'event_uid': '', 'event_id': 1, 'timestamp': '2020-01-01T00:00:00Z', 'raw': {}},
    {'event_uid': 'a', 'event_id': 1, 'timestamp': 'bad-ts', 'raw': {}},
    {'event_uid': 'file.json:1', 'event_id': 999999, 'timestamp': '2020-01-01T00:00:00Z', 'raw': {}},
])
def test_invalid_samples(bad):
    base = {
        'event_uid': 'file.json:1',
        'event_id': 1,
        'timestamp': '2020-01-01T00:00:00Z',
        'host': None,
        'process_name': None,
        'process_id': None,
        'parent_process': None,
        'command_line': None,
        'user': None,
        'tactic_hint': None,
        'raw': {},
    }
    base.update(bad)
    with pytest.raises(Exception):
        NormalizedEvent(**base)
