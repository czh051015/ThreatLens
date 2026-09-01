"""04 §12.5 验收：冲突证据复核单测。

- mock：primary/dropped 分支 + 金标不裁决断言；
- find_conflict_groups：反向映射 + 全金标组跳过 + 含金标组保留；
- 解析健壮性：任何异常 → 保持原状（不误删）；
- 金标硬约束：dropped 中归一化为金标的技术被强制移除（recall 100%）。
"""

import json

import pytest

from threatlens.core.evaluation.conflict_review import (
    ConflictDecision,
    ConflictGroup,
    build_conflict_context,
    conflict_review,
    find_conflict_groups,
    mock_conflict_decision,
    parse_conflict_decision,
)
from threatlens.core.evaluation.metrics import normalize_technique


def _chain(technique_evidence: dict[str, list[str]]) -> dict:
    """构造最小链：{技术: [事件...]} → chain 结构。"""
    return {'chain': [
        {'tactic': 'execution', 'technique': tid, 'first_seen': '', 'evidence': uids}
        for tid, uids in technique_evidence.items()
    ]}


def _group(*techniques: str, uid: str = 'e1') -> ConflictGroup:
    return ConflictGroup(event_uid=uid, techniques=list(techniques))


# -- find_conflict_groups（§12.2 反向映射） -------------------------------------

def test_find_conflict_groups_shared_event_two_techniques():
    chain = _chain({'T1112': ['e1', 'e2'], 'T1059.005': ['e1', 'e3']})
    groups = find_conflict_groups(chain, {'T1059'})
    assert [g.event_uid for g in groups] == ['e1']
    assert groups[0].techniques == ['T1112', 'T1059.005']


def test_find_conflict_groups_all_gold_skipped():
    """全部候选都是金标 → 无非金标可裁 → 不送审（省调用）。"""
    chain = _chain({'T1087': ['e1'], 'T1087.001': ['e1'], 'T1059': ['e2']})
    assert find_conflict_groups(chain, {'T1087', 'T1059'}) == []


def test_find_conflict_groups_with_gold_candidate_kept():
    """含金标候选的组照送：金标在 dropped 处被强制保留（§12.3）。"""
    chain = _chain({'T1087': ['e1'], 'T1033': ['e1']})
    groups = find_conflict_groups(chain, {'T1087'})
    assert len(groups) == 1 and groups[0].techniques == ['T1087', 'T1033']


# -- mock 三分支（§12.5 验收：primary/dropped 分支） -----------------------------

def _find_uid_for_branch(branch: int) -> tuple[str, list[str]]:
    """找到使 mock_conflict_decision 落到指定分支的 (事件, 候选)。"""
    candidates = ['T1055', 'T1112']
    for i in range(500):
        group = ConflictGroup(event_uid=f'u{i}', techniques=candidates)
        digest = __import__('hashlib').md5(f'u{i}:{"|".join(candidates)}'.encode()).hexdigest()
        if int(digest, 16) % 3 == branch:
            return f'u{i}', candidates
    pytest.fail(f'500 个候选内未找到分支 {branch}')


def test_mock_conflict_decision_three_branches():
    for branch in (0, 1, 2):
        uid, candidates = _find_uid_for_branch(branch)
        d = mock_conflict_decision(ConflictGroup(uid, candidates))
        assert d.source == 'mock' and d.reason
        if branch == 0:
            assert d.primary == candidates[0] and d.dropped == candidates[1:]
        elif branch == 1:
            assert d.primary == candidates[-1] and d.dropped == [candidates[0]]
        else:
            assert d.primary == candidates[0] and d.dropped == []


def test_mock_conflict_decision_deterministic():
    group = _group('T1055', 'T1112')
    assert mock_conflict_decision(group) == mock_conflict_decision(group)


# -- 解析健壮性 -----------------------------------------------------------------

def test_parse_conflict_decision_normal_and_fenced():
    d = parse_conflict_decision(
        '```json\n{"primary": "T1112", "dropped": ["T1059.005"], "reason": "该批事件为注册表写入"}\n```',
        ['T1059.005', 'T1112'])
    assert d.primary == 'T1112' and d.dropped == ['T1059.005']
    assert d.reason == '该批事件为注册表写入'


def test_parse_conflict_decision_invalid_json_keeps_status_quo():
    d = parse_conflict_decision('胡言乱语', ['T1112', 'T1055'])
    assert d.primary is None and d.dropped == []  # 不误删


def test_parse_conflict_decision_hallucinated_primary():
    """LLM 输出候选外的技术 ID → 不裁决（保持原状）。"""
    d = parse_conflict_decision('{"primary": "T9999", "dropped": ["T1112"]}', ['T1112', 'T1055'])
    assert d.primary is None and d.dropped == []


def test_parse_conflict_decision_dropped_normalized():
    d = parse_conflict_decision('{"primary": "T1112", "dropped": ["T1059.005", "T1059.001", "幻觉"]}',
                                ['T1059.005', 'T1059.001', 'T1112'])
    assert d.dropped == ['T1059.005', 'T1059.001']  # 候选外 / 与 primary 冲突的排除


def test_parse_conflict_decision_dropped_contains_primary_removed():
    d = parse_conflict_decision('{"primary": "T1112", "dropped": ["T1112"]}', ['T1112', 'T1055'])
    assert d.dropped == []  # 自相矛盾 → 防呆


# -- 金标硬约束（recall 100% 硬约束代码化） ---------------------------------------

def test_gold_technique_never_dropped():
    """LLM 说 dropped=[金标] → 过滤语义：金标永不因裁决被剔除。"""
    d = ConflictDecision(primary='T1087', dropped=['T1087', 'T1033'], reason='r', source='llm')
    gold = {'T1087'}
    filtered = [t for t in d.dropped if normalize_technique(t) not in gold]
    assert filtered == ['T1033']
    assert normalize_technique('T1087') in gold  # 金标本身永不被裁


def test_conflict_review_mock_gold_filtered():
    """mock 裁决 dropped 里的金标被移除。"""
    group = _group('T1087', 'T1033')  # T1087 金标
    d = conflict_review(group, gold_normalized={'T1087'}, mock=True)
    assert all(normalize_technique(t) not in {'T1087'} for t in d.dropped)


# -- 审计 + 兜底 -----------------------------------------------------------------

def test_conflict_review_appends_audit_record(tmp_path):
    log = tmp_path / 'conflicts_agent.jsonl'
    records: list[dict] = []
    d = conflict_review(_group('T1055', 'T1112'), mock=True, gold_normalized=set(),
                        event_fields={'event_uid': 'e1', 'process_name': 'cmd.exe'},
                        log_path=log, records=records)
    record = json.loads(log.read_text(encoding='utf-8').splitlines()[0])
    assert record['kind'] == 'conflict'
    assert record['candidates'] == ['T1055', 'T1112']
    assert record['primary'] == d.primary and record['dropped'] == d.dropped
    assert 'context' in record and 'latency_sec' in record
    assert len(records) == 1


def test_conflict_review_api_failure_keeps_status_quo(monkeypatch, tmp_path):
    def boom(*args, **kwargs):
        raise ConnectionError('网络不可达')

    monkeypatch.setattr('threatlens.core.evaluation.conflict_review._call_deepseek_conflict', boom)
    d = conflict_review(_group('T1055', 'T1112'), api_key='sk-test', gold_normalized=set())
    assert d.primary is None and d.dropped == []  # 保持原状，不误删
    assert d.source == 'fallback'


def test_build_conflict_context_contract_fields():
    ctx = build_conflict_context(
        _group('T1055', 'T1112'),
        {'event_uid': 'e1', 'process_name': 'cmd.exe', 'tactic_hint': 'credential-access', 'extra': 1},
        attack_lib={'T1055': {'name': 'Process Injection'}, 'T1112': {'name': 'Modify Registry'}},
    )
    assert set(ctx['event'].keys()) == {'event_uid', 'process_name'}  # tactic_hint 不进上下文（防背答案）
    assert ctx['candidates'][0]['technique_name'] == 'Process Injection'
