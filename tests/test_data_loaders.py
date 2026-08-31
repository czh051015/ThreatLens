from pathlib import Path

from threatlens.core.data import (
    load_attack_techniques,
    load_sigma_technique_index,
    load_telemetry_events,
)


ROOT = Path(__file__).resolve().parents[1]


def test_attack_loader_builds_dictionary():
    techniques = load_attack_techniques(ROOT / 'edr' / 'data' / 'attack' / 'enterprise-attack.json')

    assert len(techniques) >= 800
    assert 'T1003.001' in techniques
    assert techniques['T1003.001']['name']
    assert isinstance(techniques['T1003.001']['tactics'], list)


def test_telemetry_loader_normalizes_jsonl_events():
    events = load_telemetry_events(ROOT / 'edr' / 'data' / 'telemetry' / 'empire_mimikatz_logonpasswords_2020-08-07103224.json')

    assert len(events) > 0
    event = events[0]
    assert 'event_id' in event
    assert 'timestamp' in event
    assert 'host' in event
    assert 'process_name' in event
    assert 'raw' in event


def test_sigma_loader_extracts_attack_tags():
    mapping = load_sigma_technique_index(ROOT / 'edr' / 'data' / 'sigma' / '_src' / 'rules' / 'windows')

    assert 'T1003.001' in mapping
    assert len(mapping['T1003.001']) >= 1
