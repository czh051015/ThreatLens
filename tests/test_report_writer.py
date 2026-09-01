"""06 §4/§5 验收：report_writer 真实 LLM 分支（防幻觉过滤 + 失败降级）。

覆盖：
- mock 分支（回归，§13）
- 真实分支有 key → 走 _call_llm（monkeypatch 假响应，不真调外网）
- 幻觉过滤：LLM 输出的技术 ID ∉ chain 技术集 → 整行剔除 + 审计记录
- 无 key / _call_llm 异常 → mock-fallback（不抛异常）
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from threatlens.core.analysis import report_writer
from threatlens.core.analysis.report_writer import API_KEY_ENV, build_report


def _chain() -> dict:
    return {
        'summary': '发现 2 个技术，覆盖 2 个战术阶段',
        'techniques': {
            'T1059.001': {'name': 'PowerShell', 'tactics': ['execution']},
            'T1003.001': {'name': 'LSASS Memory', 'tactics': ['credential-access']},
        },
        'chain': [
            {'technique': 'T1059.001', 'tactic': 'execution', 'first_seen': '2020-01-01T00:00:00Z',
             'evidence': ['file.json:1']},
            {'technique': 'T1003.001', 'tactic': 'credential-access', 'first_seen': '2020-01-01T00:00:01Z',
             'evidence': ['file.json:2']},
        ],
    }


def _last_audit() -> dict:
    log = Path('evaluation/reports_agent.jsonl')
    lines = log.read_text(encoding='utf-8').strip().splitlines()
    return json.loads(lines[-1])


def test_build_report_minimal():
    r = build_report(_chain(), {}, mock=True)
    assert '攻击链分析报告' in r
    assert 'T1059.001' in r


def test_real_branch_hallucination_filtered(monkeypatch):
    """真实分支：LLM 响应含幻觉技术 T9999 → 整行剔除 + 审计告警；chain 内技术保留。"""
    monkeypatch.setenv(API_KEY_ENV, 'sk-test')
    fake_report = (
        '# 攻击链分析报告\n'
        '## 摘要\n'
        '发现 T1059.001 与 T9999 的活动。\n'          # 幻觉 T9999 混在正常句子里
        '## 详情\n'
        '### T1059.001 — PowerShell\n'
        '证据 file.json:1\n'
        '### T9999 — 编造技术\n'                       # 幻觉标题
        '证据 file.json:999\n'
    )
    monkeypatch.setattr(report_writer, '_call_llm', lambda *a, **k: fake_report)

    out = build_report(_chain(), {}, mock=False)

    assert 'T9999' not in out, '幻觉技术应被剔除'
    assert 'T1059.001' in out, 'chain 内技术应保留'
    rec = _last_audit()
    assert rec['source'] == 'llm'
    assert rec['hallucinated_lines_removed'] >= 1, '审计应记录剔除行数'
    assert rec['removed_example'], '审计应记录被剔除样例'


def test_real_branch_no_key_falls_back(monkeypatch):
    """无 key → mock-fallback，不抛异常、报告仍生成。"""
    monkeypatch.delenv(API_KEY_ENV, raising=False)
    monkeypatch.setattr(report_writer, '_call_llm', lambda *a, **k: pytest.fail('不应调用 LLM'))

    out = build_report(_chain(), {}, mock=False)

    assert '攻击链分析报告' in out
    assert _last_audit()['source'] == 'mock-fallback'


def test_real_branch_llm_error_falls_back(monkeypatch):
    """_call_llm 抛异常 → mock-fallback，不抛异常。"""
    monkeypatch.setenv(API_KEY_ENV, 'sk-test')

    def boom(*a, **k):
        raise RuntimeError('network down')

    monkeypatch.setattr(report_writer, '_call_llm', boom)

    out = build_report(_chain(), {}, mock=False)

    assert '攻击链分析报告' in out
    assert _last_audit()['source'] == 'mock-fallback'
