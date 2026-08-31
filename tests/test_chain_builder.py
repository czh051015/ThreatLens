"""chain_builder 单测（02 §8 验收：chain_builder / 去噪 / 证据回溯 / 4 阶段链）。"""

from threatlens.core.analysis.chain_builder import (
    SCORE_THRESHOLD,
    TOP_K_EVIDENCE,
    build_chain,
    score_event,
)
from threatlens.core.analysis.sigma_matcher import MatchResult

PHASE_ORDER = ['execution', 'credential-access', 'discovery', 'lateral-movement']

ATTACK_LIB = {
    'T1059.001': {'name': 'PowerShell', 'tactics': ['execution', 'command-and-control']},
    'T1003.001': {'name': 'LSASS Memory', 'tactics': ['credential-access']},
    'T1087': {'name': 'Account Discovery', 'tactics': ['discovery']},
    'T1021.002': {'name': 'SMB/Admin Shares', 'tactics': ['lateral-movement']},
}


def _event(event_uid: str, process: str | None = None, command_line: str | None = None,
           parent: str | None = None, timestamp: str = '2026-01-01T00:00:00Z') -> dict:
    return {
        'event_uid': event_uid,
        'event_id': 1,
        'timestamp': timestamp,
        'process_name': process,
        'parent_process': parent,
        'command_line': command_line,
        'raw': {},
    }


def _match(event_uid: str, technique: str = 'T1059.001') -> MatchResult:
    return MatchResult(event_uid=event_uid, rule_path='x.yml', technique_id=technique, matched={})


# -- score_event（§5.4 打分表） ----------------------------------------------

def test_hard_exclude_system_processes():
    for name in ('System', 'smss.exe', 'csrss.exe', 'wininit.exe'):
        assert score_event(_event('u1', process=name), []) == 0.0


def test_downweight_system_process():
    assert score_event(_event('u1', process='svchost.exe'), []) == 0.3
    assert score_event(_event('u1', process='lsass.exe'), []) == 0.3


def test_payload_keywords_boost():
    assert score_event(_event('u1', command_line='powershell -enc AAA'), []) == 3.0


def test_suspicious_parent_boost():
    assert score_event(_event('u1', parent=r'C:\Windows\System32\wscript.exe'), []) == 2.0


def test_system_service_parent_downweight():
    assert score_event(_event('u1', process='child.exe', parent=r'C:\Windows\System32\svchost.exe'), []) == 0.0


def test_suspicious_launch_path_boost():
    assert score_event(_event('u1', process=r'C:\Users\pgustavo\AppData\Local\Temp\evil.exe'), []) == 3.0


# -- build_chain（聚合 / 去噪 / 两层时间线 / 结构） ----------------------------

def _chain(pairs: list[tuple[dict, list[MatchResult]]]):
    return build_chain(pairs, ATTACK_LIB, PHASE_ORDER)


def test_noisy_events_filtered_by_threshold():
    pairs = [
        (_event('u1', process='System'), [_match('u1')]),                 # 硬排除 0
        (_event('u2', process='svchost.exe'), [_match('u2')]),            # 0.3 < 阈值
        (_event('u3', command_line='-enc x'), [_match('u3')]),            # 3.0 保留
    ]
    chain = _chain(pairs)
    assert [e['evidence'] for e in chain['chain'] if e['technique'] == 'T1059.001'][0] == ['u3']


def test_evidence_dedup_same_event_same_technique():
    pairs = [(_event('u1', command_line='-enc x'), [_match('u1'), _match('u1')])]
    chain = _chain(pairs)
    evidence = chain['chain'][0]['evidence']
    assert evidence == ['u1']


def test_evidence_top_k_cap():
    pairs = [( _event(f'u{i}', command_line='-enc x'), [_match(f'u{i}')]) for i in range(1, 8)]
    chain = _chain(pairs)
    evidence = chain['chain'][0]['evidence']
    assert len(evidence) == TOP_K_EVIDENCE


def test_two_layer_timeline_phases_beat_timestamps():
    """两层时间线（§5.3）：跨数据集按战术阶段排，不按时间戳全局排。"""
    pairs = [
        (_event('ca.json:1', timestamp='2026-03-01T00:00:00Z'), [_match('ca.json:1', 'T1003.001')]),
        (_event('ex.json:1', timestamp='2026-01-01T00:00:00Z'), [_match('ex.json:1', 'T1059.001')]),
    ]
    chain = _chain(pairs)
    order = [e['technique'] for e in chain['chain']]
    assert order == ['T1059.001', 'T1003.001']  # 战术顺序优先于时间


def test_chain_structure_and_summary():
    pairs = [
        (_event('ex.json:1', timestamp='2026-01-01T00:00:00Z'), [_match('ex.json:1', 'T1059.001')]),
        (_event('lm.json:1', timestamp='2026-02-01T00:00:00Z'), [_match('lm.json:1', 'T1021.002')]),
    ]
    chain = _chain(pairs)
    assert set(chain.keys()) == {'chain', 'techniques', 'summary'}
    assert chain['techniques']['T1059.001']['name'] == 'PowerShell'
    assert '覆盖 2 个战术阶段' in chain['summary']


def test_evidence_traceable_back_to_event_uid():
    pairs = [(_event('u9.json:42', command_line='-enc x'), [_match('u9.json:42')])]
    chain = _chain(pairs)
    assert chain['chain'][0]['evidence'] == ['u9.json:42']
    assert chain['chain'][0]['first_seen'] == '2026-01-01T00:00:00Z'
