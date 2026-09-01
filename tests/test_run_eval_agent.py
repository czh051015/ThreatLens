"""04 §8 验收：run_eval_agent 单测（低分筛选 §4 + review 注入红线 + mock 端到端可复现）。

架构红线（04 §3）：review=None 时输出与纯脚本版逐字节一致；LLM 只控制低分命中的去留。
"""

import json
import os

import pytest

from threatlens.core.analysis.chain_builder import build_chain
from threatlens.core.analysis.run_demo import SIGMA_ROOT
from threatlens.core.analysis.sigma_matcher import MatchResult, build_rule_cache
from threatlens.core.evaluation.llm_review import ReviewItem, build_context
from threatlens.core.evaluation.run_eval_agent import (
    collect_evidence,
    load_env_file,
    render_agent_report,
    run_eval_agent,
    screen_review_items,
)


def _event(uid: str, process: str = 'cmd.exe', ts: str = '2020-01-01T00:00:00Z') -> dict:
    return {
        'event_uid': uid,
        'process_name': process,
        'command_line': '',
        'parent_process': 'C:\\Windows\\explorer.exe',
        'timestamp': ts,
    }


def _match(tid: str) -> MatchResult:
    return MatchResult(event_uid='', rule_path=f'sigma\\{tid}.yml', technique_id=tid)


# -- §4 低分筛选 ---------------------------------------------------------------

def test_screen_review_items_gold_high_score_skipped():
    gold = {'T1003'}
    evidence = {
        ('T1003', 'e1'): {'score': 2.0},   # 金标高分解过（recall 100% 已确认）
        ('T1003', 'e2'): {'score': 0.5},   # 金标低分 → 送审
        ('T1055', 'e3'): {'score': 4.0},   # 非金标一律送审
        ('T1685', 'e4'): {'score': 1.0},
    }
    assert screen_review_items(evidence, gold) == [('T1003', 'e2'), ('T1055', 'e3'), ('T1685', 'e4')]


# -- 架构红线：review 注入不触碰确定性主干 -----------------------------------------

def _pairs():
    """两条证据 → 一个技术（模拟 02 主干输入）。"""
    events = [
        (_event('a1', ts='2020-01-01T00:00:00Z'), [_match('T1055')]),
        (_event('a2', ts='2020-01-01T00:00:01Z'), [_match('T1055')]),
    ]
    lib = {'T1055': {'name': 'Process Injection', 'tactics': ['defense-evasion']}}
    return events, lib


def test_build_chain_review_drop_removes_only_that_evidence():
    pairs, lib = _pairs()
    review = {('T1055', 'a1'): {'action': 'drop', 'verdict': 'benign', 'reason': 'r', 'confidence': 0.9, 'source': 'llm'}}
    chain = build_chain(pairs, lib, ['defense-evasion'], review=review)
    assert chain['chain'][0]['evidence'] == ['a2']  # a1 被剔除，a2 保留
    assert 'a1' in chain['review']['T1055']  # drop 也记录（解释缺失）


def test_build_chain_review_drop_all_evidence_removes_technique():
    pairs, lib = _pairs()
    review = {('T1055', 'a1'): {'action': 'drop', 'verdict': 'benign', 'reason': 'r', 'confidence': 0.9, 'source': 'llm'},
              ('T1055', 'a2'): {'action': 'drop', 'verdict': 'benign', 'reason': 'r', 'confidence': 0.9, 'source': 'llm'}}
    chain = build_chain(pairs, lib, ['defense-evasion'], review=review)
    assert chain['chain'] == []
    assert 'T1055' not in chain['techniques']


def test_build_chain_review_keep_and_flag_keep_evidence():
    pairs, lib = _pairs()
    review = {('T1055', 'a1'): {'action': 'keep', 'verdict': 'attack', 'reason': 'r', 'confidence': 0.9, 'source': 'llm'},
              ('T1055', 'a2'): {'action': 'flag', 'verdict': 'unknown', 'reason': 'r', 'confidence': 0.5, 'source': 'llm'}}
    chain = build_chain(pairs, lib, ['defense-evasion'], review=review)
    assert sorted(chain['chain'][0]['evidence']) == ['a1', 'a2']


def test_build_chain_without_review_byte_identical():
    """红线：review=None 与不传 review 输出完全一致（LLM 不碰确定性主干）。"""
    pairs, lib = _pairs()
    a = build_chain(pairs, lib, ['defense-evasion'])
    b = build_chain(pairs, lib, ['defense-evasion'], review=None)
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)
    assert 'review' not in a  # 无复核元数据


# -- .env 加载 ------------------------------------------------------------------

def test_load_env_file_sets_and_never_overrides(monkeypatch, tmp_path):
    p = tmp_path / '.env'
    p.write_text('# 注释\nDEEPSEEK_API_KEY=abc\n\nOTHER=def\n', encoding='utf-8')
    monkeypatch.delenv('DEEPSEEK_API_KEY', raising=False)
    monkeypatch.setenv('OTHER', 'keep-me')
    load_env_file(p)
    assert os.environ['DEEPSEEK_API_KEY'] == 'abc'
    assert os.environ['OTHER'] == 'keep-me'  # setdefault：已存在的 key 不被覆盖


def test_load_env_file_missing_path_is_noop(tmp_path):
    load_env_file(tmp_path / 'nonexistent.env')  # 不崩溃


# -- 报告渲染 -------------------------------------------------------------------

def _fake_result() -> dict:
    def metrics(precision: float, recall: float) -> dict:
        return {
            'gold_techniques_normalized': ['T1003', 'T1021', 'T1059', 'T1087'],
            'predicted_techniques_normalized': ['T1003', 'T1021', 'T1033', 'T1059', 'T1087', 'T1685'],
            'technique_metrics': {'hits': ['T1003', 'T1021', 'T1059', 'T1087'],
                                  'extra_techniques': ['T1033', 'T1685'], 'missed_techniques': [],
                                  'precision': precision, 'recall': recall},
            'stage_metrics': {'gold_stages': ['execution'], 'observed_stages': ['execution'],
                              'stage_recall': 1.0, 'stage_order_consistency': 1.0},
        }

    return {
        'mock': True,
        'gold': {'techniques': ['T1059.001', 'T1003.001'], 'techniques_normalized': ['T1003', 'T1021', 'T1059', 'T1087'],
                 'stages': ['execution', 'credential-access']},
        'agent': {
            'rules_variant': 'official', 'rule_count': 2815,
            'review_stats': {'reviewed': 106, 'by_verdict': {'attack': 39, 'benign': 34, 'unknown': 33},
                             'dropped': 34, 'kept_with_reason': 72},
            'dropped_techniques': ['T1033', 'T1526', 'T1685'],
            'chain_summary': '共识别 12 个技术，覆盖 4 个战术阶段',
            'technique_count': 12,
            'metrics': metrics(0.444, 1.0),
            'chain_visible_reviews': [
                {'technique_id': 'T1685', 'event_uid': 'f.json:918', 'score': 1.0,
                 'verdict': 'benign', 'reason': '常规用户执行', 'confidence': 0.5, 'source': 'mock'},
            ],
        },
        'v2': {
            'chain_summary': '共识别 12 个技术，覆盖 4 个战术阶段',
            'technique_count': 12,
            'metrics': metrics(0.40, 1.0),
            'dropped_techniques': ['T1685'],
        },
        'conflict': {
            'groups_reviewed': 8,
            'groups_remaining': 5,
            'dropped': [['T1033', 'f.json:1820']],
            'decisions': [
                {'event_uid': 'f.json:148', 'candidates': ['T1526', 'T1087', 'T1083'],
                 'primary': 'T1087', 'dropped': ['T1526', 'T1083'], 'reason': 'Seatbelt 为主机侦察', 'source': 'llm'},
            ],
        },
        'baseline_v1': {'precision': 0.364, 'recall': 1.0, 'stage_recall': 1.0,
                        'stage_order_consistency': 1.0, 'technique_count_normalized': 11,
                        'decision': 'llm-low-score-review'},
    }


def test_render_agent_report_deterministic():
    assert render_agent_report(_fake_result()) == render_agent_report(_fake_result())


def test_render_agent_report_marks_delta_and_dropped():
    text = render_agent_report(_fake_result())
    assert '36.4%' in text and '40.0%' in text and '44.4%' in text
    assert '+8.0pp' in text  # 0.444 - 0.364
    assert '`T1685`' in text and '`T1033`' in text
    assert '送审 106 条' in text
    assert '8 组' in text and '5 组' in text  # 冲突收敛（§12.5）
    assert 'Seatbelt 为主机侦察' in text  # 裁决 reason 落地
    assert 'Agent 比脚本强' in text or 'precision 提升' in text


def test_render_agent_report_warns_on_recall_drop():
    r = _fake_result()
    r['agent']['metrics'] = {
        **r['agent']['metrics'],
        'technique_metrics': {**r['agent']['metrics']['technique_metrics'], 'precision': 0.36, 'recall': 0.75},
    }
    text = render_agent_report(r)
    assert '⚠️ recall 下降' in text


# -- §8 验收：mock 端到端可复现 ---------------------------------------------------

def test_run_eval_agent_mock_end_to_end(tmp_path):
    """mock 全流程（04 §8 + §12.5）：recall 100%、precision 逐级提升、产物落盘、可复现。"""
    result = run_eval_agent(mock=True, out_dir=tmp_path)

    # 验收：三级指标（mock 确定性数字）
    a = result['agent']['metrics']['technique_metrics']          # v3 冲突裁决后
    v2 = result['v2']['metrics']['technique_metrics']            # v2 低分复核后
    b = result['baseline_v1']
    assert result['mock'] is True
    assert a['recall'] == v2['recall'] == b['recall'] == 1.0     # recall 永不下降（金标硬约束）
    assert b['precision'] < v2['precision'] < a['precision']     # 0.364 < 0.40 < 0.50（确定性）
    assert result['agent']['review_stats']['reviewed'] == 106
    assert result['agent']['dropped_techniques'] == ['T1033', 'T1526', 'T1685']  # 链 diff 语义
    assert all(r['reason'] for r in result['agent']['chain_visible_reviews'])

    # §12.5 验收：冲突收敛 + 裁决记录带 reason
    conf = result['conflict']
    assert conf['groups_reviewed'] == 8 and conf['groups_remaining'] == 5  # 与文档热点吻合
    assert all(record['reason'] for record in conf['decisions'])

    # 验收：产物落盘 + v3 快照（v2 快照为历史固化物）
    for name in ('metrics_agent.json', 'report_agent.md'):
        assert (tmp_path / name).exists(), name
        assert (tmp_path / 'baseline' / 'v3-agent-conflict-review' / name).exists(), name

    # 04 §13 验收：报告解释层（纯展示层）产物 + 完整性（链上技术 100% 覆盖）
    report_md = tmp_path / 'agent_attack_chain_report.md'
    assert report_md.exists(), 'agent_attack_chain_report.md 未生成（§13 接入）'
    text = report_md.read_text(encoding='utf-8')
    assert '攻击链分析报告' in text
    mj = json.loads((tmp_path / 'metrics_agent.json').read_text(encoding='utf-8'))
    raw_techs = mj['agent']['metrics']['predicted_techniques_raw']
    missing = [t for t in raw_techs if f'### {t}' not in text]
    assert not missing, f'报告缺失技术: {missing}（§13.4 完整性）'
    # 纯展示层红线：报告生成不改变指标（mock 可复现已在下方断言）

    # 验收：metrics 文件不含载荷原文（完整上下文只在 jsonl 审计日志）
    mj = json.loads((tmp_path / 'metrics_agent.json').read_text(encoding='utf-8'))
    assert all('context' not in r for r in mj['agent']['chain_visible_reviews'])
    assert all('context' not in r for r in mj['conflict']['decisions'])

    # 验收：可复现（md5 确定性 mock）——同输入重跑指标一致
    result2 = run_eval_agent(mock=True, out_dir=tmp_path)
    assert result2['agent']['metrics'] == result['agent']['metrics']
    assert result2['agent']['review_stats'] == result['agent']['review_stats']
    assert result2['conflict'] == result['conflict']


def test_real_evidence_context_non_empty():
    """回归（真实 API 首跑发现）：送审上下文必须携带事件字段。

    修复前 `_CONTEXT_FIELDS` 用 Sigma 大写字段名、事件从 `raw` 取 →
    `context['event']` 为空 → LLM 只看到技术 ID → 全判 unknown，precision 无法提升。
    """
    rule_cache = build_rule_cache(SIGMA_ROOT, include_custom=False)
    _, evidence = collect_evidence(rule_cache)
    (technique_id, event_uid), entry = next(iter(evidence.items()))
    ctx = build_context(
        ReviewItem(technique_id, event_uid, entry['score'], sorted(entry['rule_paths']), entry['event'])
    )
    assert ctx['event'], f"context['event'] 为空: {technique_id} {event_uid}"
    assert any(k in ctx['event'] for k in ('process_name', 'command_line', 'parent_process'))
