from __future__ import annotations

import json

from threatlens.core.mcp.server import lens_analyze, lens_gold_check, lens_report


def test_lens_analyze_valid_path():
    result = lens_analyze('edr/data/telemetry/empire_launcher_vbs_2020-09-04160940.json')
    assert 'error' not in result
    assert 'summary' in result
    assert 'techniques' in result
    assert 'chain' in result
    assert len(result['chain']) > 0


def test_lens_analyze_missing_file():
    result = lens_analyze('does/not/exist.json')
    assert 'error' in result


def test_lens_report_valid_chain_json():
    chain = {
        'summary': '测试摘要',
        'techniques': {'T1059.001': {'name': 'PowerShell', 'tactics': ['execution']}},
        'chain': [
            {
                'tactic': 'execution',
                'technique': 'T1059.001',
                'first_seen': '2020-01-01T00:00:00Z',
                'evidence': ['file.json:1'],
            }
        ],
    }
    result = lens_report(json.dumps(chain), mock=True)
    assert 'report' in result
    assert '攻击链分析报告' in result['report']
    assert 'T1059.001' in result['report']


def test_lens_gold_check_basic():
    payload = {
        'predictions': {
            'dataset.json': ['T1059.001', 'T1003.001'],
        }
    }
    result = lens_gold_check(json.dumps(payload))
    assert 'precision' in result
    assert 'recall' in result
    assert 'stage_recall' in result
    assert 0.0 <= result['precision'] <= 1.0
    assert 0.0 <= result['recall'] <= 1.0
