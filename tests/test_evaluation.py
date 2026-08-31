"""03 评测口径单测 + 端到端产物测试（§7 验收 1-3 自动化）。"""

import json

import pytest

from threatlens.core.evaluation.metrics import (
    PRECISION_LOW,
    RECALL_LOW,
    compute_stage_metrics,
    compute_technique_metrics,
    decide_next_step,
    metrics_from_chain,
    normalize_technique,
    normalize_technique_set,
)
from threatlens.core.evaluation.run_eval import render_report, run_eval


# -- §3.2 技术 ID 归一化 ------------------------------------------------------

def test_normalize_technique_child_to_parent():
    assert normalize_technique('T1059.001') == 'T1059'
    assert normalize_technique('T1021.002') == 'T1021'
    assert normalize_technique('T1087') == 'T1087'


def test_normalize_technique_set_dedups_parent_child():
    """归并口径：T1087 与 T1087.001 不重复计（03 §7 验收）。"""
    assert normalize_technique_set({'T1087', 'T1087.001'}) == {'T1087'}


# -- §3.3 技术识别准确率 ------------------------------------------------------

def test_technique_metrics_precision_recall():
    gold = {'T1059', 'T1003', 'T1087', 'T1021'}
    predicted = {'T1059', 'T1003', 'T1087', 'T1033', 'T1055', 'T1112', 'T1526', 'T1531', 'T1685', 'T1083'}
    m = compute_technique_metrics(predicted, gold)
    assert m['hits'] == ['T1003', 'T1059', 'T1087']
    assert m['recall'] == pytest.approx(3 / 4)
    assert m['precision'] == pytest.approx(3 / 10)
    assert m['missed_techniques'] == ['T1021']
    assert 'T1033' in m['extra_techniques']


def test_technique_metrics_empty_predicted():
    m = compute_technique_metrics(set(), {'T1059'})
    assert m['precision'] == 0.0 and m['recall'] == 0.0


# -- §3.4 链还原完整度 --------------------------------------------------------

def test_stage_metrics_perfect_order():
    gold = ['execution', 'credential-access', 'discovery', 'lateral-movement']
    predicted = ['execution', 'credential-access', 'discovery', 'discovery', 'lateral-movement']
    m = compute_stage_metrics(predicted, gold)
    assert m['stage_recall'] == 1.0
    # observed = [execution, credential-access, discovery, lateral-movement]，6 对全一致 → 1.0
    assert m['stage_order_consistency'] == 1.0


def test_stage_metrics_single_inversion():
    gold = ['execution', 'credential-access', 'discovery', 'lateral-movement']
    predicted = ['execution', 'discovery', 'credential-access', 'lateral-movement']  # (discovery, credential-access) 倒序
    m = compute_stage_metrics(predicted, gold)
    assert m['stage_recall'] == 1.0
    assert m['stage_order_consistency'] == 0.8333  # 5/6，metric 内部取 4 位小数


def test_stage_metrics_reversed_order():
    gold = ['execution', 'credential-access', 'discovery', 'lateral-movement']
    predicted = ['lateral-movement', 'discovery', 'execution']
    m = compute_stage_metrics(predicted, gold)
    assert m['stage_recall'] == 3 / 4
    # observed=[lateral-movement, discovery, execution] 全部逆序 → 0.0
    assert m['stage_order_consistency'] == 0.0


def test_stage_metrics_partial_and_missing():
    gold = ['execution', 'credential-access', 'discovery', 'lateral-movement']
    predicted = ['impact', 'discovery', 'execution']  # 金标外阶段忽略
    m = compute_stage_metrics(predicted, gold)
    assert m['stage_recall'] == 0.5
    assert m['observed_stages'] == ['discovery', 'execution']
    assert m['stage_order_consistency'] == 0.0  # discovery 在 execution 前，逆序


def test_stage_metrics_under_two_shared_stages_returns_none():
    gold = ['execution', 'credential-access', 'discovery', 'lateral-movement']
    assert compute_stage_metrics(['execution'], gold)['stage_order_consistency'] is None
    assert compute_stage_metrics([], gold)['stage_order_consistency'] is None


# -- metrics_from_chain 装配 --------------------------------------------------

def test_metrics_from_chain_normalizes_both_sides():
    chain = {
        'chain': [
            {'tactic': 'execution', 'technique': 'T1059.001'},
            {'tactic': 'discovery', 'technique': 'T1087'},
            {'tactic': 'discovery', 'technique': 'T1087.001'},
        ],
        'techniques': {'T1059.001': {}, 'T1087': {}, 'T1087.001': {}, 'T1531': {}},
    }
    m = metrics_from_chain(chain, ['T1059.001', 'T1087.001'], ['execution', 'discovery'])
    assert m['predicted_techniques_normalized'] == ['T1059', 'T1087', 'T1531']  # 父子归并为 1
    assert m['technique_metrics']['hits'] == ['T1059', 'T1087']  # 不重复计、不误判
    assert m['stage_metrics']['stage_recall'] == 1.0


# -- §6 决策规则 ---------------------------------------------------------------

def _decision_metrics(recall: float, precision: float) -> dict:
    return {'technique_metrics': {'recall': recall, 'precision': precision}}


def test_decision_low_recall_expand_rules():
    d = decide_next_step(_decision_metrics(recall=RECALL_LOW - 0.25, precision=0.9))
    assert d['decision'] == 'expand-rules'


def test_decision_high_recall_low_precision_llm_review():
    d = decide_next_step(_decision_metrics(recall=1.0, precision=PRECISION_LOW - 0.1))
    assert d['decision'] == 'llm-low-score-review'


def test_decision_high_both_pivot_explainability():
    d = decide_next_step(_decision_metrics(recall=1.0, precision=0.9))
    assert d['decision'] == 'pivot-to-explainability'


# -- §7 验收：端到端产物 -------------------------------------------------------

def test_run_eval_end_to_end_artifacts(tmp_path):
    """03 §7 验收 1-3：metrics.json 含两版指标、归并口径生效、report.md 有 pivot 判断。"""
    result = run_eval(out_dir=tmp_path)

    # 验收 1：两套指标同出（版本分离红线）
    assert set(result['versions']) == {'official', 'official+custom'}
    for variant in ('official', 'official+custom'):
        tm = result['versions'][variant]['metrics']['technique_metrics']
        sm = result['versions'][variant]['metrics']['stage_metrics']
        for key in ('precision', 'recall'):
            assert 0.0 <= tm[key] <= 1.0
        for key in ('stage_recall', 'stage_order_consistency'):
            assert sm[key] is None or 0.0 <= sm[key] <= 1.0

    # 验收 2：归并口径生效——原始 ID 里有父子同时命中，归并后 T1087 只计一次
    metrics_json = json.loads((tmp_path / 'metrics.json').read_text(encoding='utf-8'))
    raw = metrics_json['versions']['official']['metrics']['predicted_techniques_raw']
    normalized = metrics_json['versions']['official']['metrics']['predicted_techniques_normalized']
    assert 'T1087' in raw and 'T1087.001' in raw
    assert normalized.count('T1087') == 1
    assert 'T1087.001' not in normalized

    # 验收 3：report.md 给出 pivot 判断与理由
    report = (tmp_path / 'report.md').read_text(encoding='utf-8')
    assert 'llm-low-score-review' in report or 'expand-rules' in report or 'pivot-to-explainability' in report
    assert '版本分离' in report

    # 两版规则数差恰为 1 条自定义规则
    o = metrics_json['versions']['official']['rule_count']
    c = metrics_json['versions']['official+custom']['rule_count']
    assert c - o == 1


def test_render_report_deterministic():
    """同输入渲染结果一致（可重跑复现的组成单元）。"""
    a = render_report({'gold': {'techniques': ['T1'], 'techniques_normalized': ['T1'], 'stages': ['execution']},
                       'versions': {'official': _fake_version(), 'official+custom': _fake_version()}})
    b = render_report({'gold': {'techniques': ['T1'], 'techniques_normalized': ['T1'], 'stages': ['execution']},
                       'versions': {'official': _fake_version(), 'official+custom': _fake_version()}})
    assert a == b


def _fake_version() -> dict:
    return {
        'rules_variant': 'official',
        'rule_count': 1,
        'technique_count': 1,
        'stage_count': 1,
        'summary': 'synthetic',
        'technique_evidence': {'T1': ['a.json:1']},
        'metrics': {
            'gold_techniques_normalized': ['T1'],
            'predicted_techniques_normalized': ['T1'],
            'predicted_techniques_raw': ['T1'],
            'technique_metrics': {'hits': ['T1'], 'extra_techniques': [], 'missed_techniques': [],
                                  'precision': 1.0, 'recall': 1.0},
            'stage_metrics': {'gold_stages': ['execution'], 'observed_stages': ['execution'],
                              'stage_recall': 1.0, 'stage_order_consistency': None},
        },
        'decision': {'decision': 'pivot-to-explainability', 'reason': 'synthetic'},
    }
