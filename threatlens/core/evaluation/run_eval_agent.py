"""04 §6：Agent 版评测 —— 脚本主干 + LLM 低分复核。

用法：
    python -m threatlens.core.evaluation.run_eval_agent           # 真实 API（读 DEEPSEEK_API_KEY / 根 .env）
    python -m threatlens.core.evaluation.run_eval_agent --mock    # 确定性假 LLM（无外网，可复现）

产物（04 §4/§6/§9）：
- `evaluation/metrics_agent.json`：复核后指标 + 送审统计（同一金标、同一归并口径 §3）；
- `evaluation/report_agent.md`：与 v1 脚本版对比表（precision/recall/阶段召回/可解释性）；
- `evaluation/reviews_agent.jsonl`：每次 LLM 调用记录（输入快照 + 输出 + 耗时，可审计）；
- `evaluation/baseline/v2-agent-lowscore-review/`：本版快照（复制保存，只读）。

架构红线（04 §3）：LLM 只在脚本判定完成之后复核低分命中——benign 剔除、
attack/unknown 保留并附 reason；不改变确定性判定本身，规则集与打分原样。
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from threatlens.core.analysis.chain_builder import SCORE_THRESHOLD, build_chain, score_event
from threatlens.core.analysis.run_demo import (
    ATTACK_PATH,
    ATOMIC_ROOT,
    DATASETS,
    GOLD_TECHNIQUES,
    PHASE_ORDER,
    ROOT,
    SIGMA_ROOT,
    TELEMETRY_ROOT,
    run_demo,
)
from threatlens.core.analysis.sigma_matcher import build_rule_cache, match_all
from threatlens.core.data import load_attack_techniques, load_telemetry_events
from threatlens.core.data.load_atomic import load_atomic_chain

from .llm_review import API_KEY_ENV, ReviewItem, llm_review
from .metrics import metrics_from_chain, normalize_technique

EVAL_ROOT = ROOT / 'evaluation'

#: 低分定义（04 §4）：沿用 §5.4 去噪阈值。链内金标命中分数均 ≥ 阈值，
#: 故实际送审 = 非金标技术的全部命中（金标 recall 100%，无需送审）。
REVIEW_SCORE_THRESHOLD = SCORE_THRESHOLD


def load_env_file(env_path: str | Path) -> None:
    """根 `.env`（KEY=VALUE）→ os.environ（key 已存在则跳过）。不入库（.gitignore 覆盖）。"""
    path = Path(env_path)
    if not path.exists():
        return
    for line in path.read_text(encoding='utf-8').splitlines():
        line = line.strip()
        if not line or line.startswith('#') or '=' not in line:
            continue
        key, _, value = line.partition('=')
        os.environ.setdefault(key.strip(), value.strip())


def collect_evidence(
    rule_cache: dict[int | str, list],
) -> tuple[list[tuple[dict, list]], dict[tuple[str, str], dict[str, Any]]]:
    """跑 4 数据集匹配，返回 (events_with_matches, 逐(技术,事件)证据表)。

    证据表：{ (technique_id, event_uid): {'score', 'rule_paths', 'event'} }，
    score 与 build_chain 内部一致（同一 score_event 打分），rule_paths 供送审上下文。
    """
    pairs: list[tuple[dict, list]] = []
    evidence: dict[tuple[str, str], dict[str, Any]] = {}
    for filename in DATASETS:
        events = load_telemetry_events(TELEMETRY_ROOT / filename)
        hits = match_all(events, rule_cache)
        print(f'[agent] {filename}: {len(events)} events, '
              f'{sum(1 for v in hits.values() if v)} with matches')
        for event in events:
            ms = hits.get(event['event_uid'], [])
            pairs.append((event, ms))
            if not ms:
                continue
            score = score_event(event, ms)
            if score < SCORE_THRESHOLD:
                continue
            for m in ms:
                key = (m.technique_id, event['event_uid'])
                entry = evidence.setdefault(key, {'score': score, 'rule_paths': set(), 'event': event})
                entry['rule_paths'].add(m.rule_path)
    return pairs, evidence


def screen_review_items(
    evidence: dict[tuple[str, str], dict[str, Any]],
    gold_normalized: set[str],
) -> list[tuple[str, str]]:
    """04 §4 低分筛选：非金标技术的全部命中 + 分数低于阈值的金标命中。"""
    items: list[tuple[str, str]] = []
    for (technique_id, event_uid), entry in evidence.items():
        is_gold = normalize_technique(technique_id) in gold_normalized
        if is_gold and entry['score'] >= REVIEW_SCORE_THRESHOLD:
            continue  # 金标高分命中：已确认，不进 LLM（§2/§4 省成本、保确定性）
        items.append((technique_id, event_uid))
    return sorted(items)


def run_eval_agent(
    *,
    mock: bool = False,
    out_dir: str | Path | None = None,
    include_custom: bool = False,
) -> dict:
    """04 §6 全流程：主干 → 筛低分 → llm_review → 复核后重算指标 → 产物 + v2 快照。"""
    attack_lib = load_attack_techniques(ATTACK_PATH)
    gold = load_atomic_chain(ATOMIC_ROOT, GOLD_TECHNIQUES, attack_lib)
    gold_stages = list(dict.fromkeys(
        t for tech in gold for t in tech['tactics'] if t in PHASE_ORDER
    ))
    gold_normalized = {normalize_technique(t) for t in GOLD_TECHNIQUES}

    rule_cache = build_rule_cache(SIGMA_ROOT, include_custom=include_custom)
    print(f'[agent] rule cache: {sum(len(v) for v in rule_cache.values())} entries')
    pairs, evidence = collect_evidence(rule_cache)

    # 脚本链（一致性校验：应与 v1 相同）
    chain_script = build_chain(pairs, attack_lib, PHASE_ORDER)
    script_metrics = metrics_from_chain(chain_script, GOLD_TECHNIQUES, gold_stages)
    print(f'[agent] script chain: {chain_script["summary"]} '
          f'(precision={script_metrics["technique_metrics"]["precision"]:.3f}, '
          f'recall={script_metrics["technique_metrics"]["recall"]:.3f})')

    # 低分筛选（§4）→ 逐条复核
    items = screen_review_items(evidence, gold_normalized)
    api_key = os.environ.get(API_KEY_ENV)
    if not mock and not api_key:
        print(f'[agent] WARNING: 未设置 {API_KEY_ENV}，将使用 mock 判定（source=mock）')
    out = Path(out_dir) if out_dir else EVAL_ROOT
    out.mkdir(parents=True, exist_ok=True)
    log_path = out / 'reviews_agent.jsonl'
    log_path.unlink(missing_ok=True)  # 每次评测重生成，保证审计日志与本次运行对应

    review: dict[tuple[str, str], dict[str, Any]] = {}
    review_records: list[dict[str, Any]] = []
    print(f'[agent] reviewing {len(items)} low-score hits (mock={mock})')
    for technique_id, event_uid in items:
        entry = evidence[(technique_id, event_uid)]
        item = ReviewItem(
            technique_id=technique_id,
            event_uid=event_uid,
            score=entry['score'],
            rule_paths=sorted(entry['rule_paths']),
            event_fields=entry['event'],  # 项目事件模型顶层字段（build_context 白名单过滤）
        )
        decision = llm_review(item, api_key, mock=mock, attack_lib=attack_lib,
                              log_path=log_path, records=review_records)
        action = 'drop' if decision.verdict == 'benign' else ('flag' if decision.verdict == 'unknown' else 'keep')
        review[(technique_id, event_uid)] = {
            'action': action,
            'verdict': decision.verdict,
            'reason': decision.reason,
            'confidence': decision.confidence,
            'source': decision.source,
        }
        print(f'  {event_uid} {technique_id} score={entry["score"]:.1f} → {decision.verdict} ({decision.reason[:60]})')

    # 复核后重建链 → 指标（同一金标、同一归并口径，03 §3）
    chain = build_chain(pairs, attack_lib, PHASE_ORDER, review=review)
    metrics = metrics_from_chain(chain, GOLD_TECHNIQUES, gold_stages)

    verdicts: dict[str, int] = {}
    for decision in review.values():
        verdicts[decision['verdict']] = verdicts.get(decision['verdict'], 0) + 1

    # 被整体剔除的技术 = 脚本链里有、复核后链里没有（链 diff，非单条证据剔除）
    dropped_techniques = sorted(set(chain_script['techniques']) - set(chain['techniques']))

    result = {
        'schema_version': '1.0',
        'mock': mock,
        'gold': {
            'techniques': GOLD_TECHNIQUES,
            'techniques_normalized': sorted(gold_normalized),
            'stages': gold_stages,
        },
        'agent': {
            'rules_variant': 'official+custom' if include_custom else 'official',
            'rule_count': sum(len(v) for v in rule_cache.values()),
            'review_stats': {
                'reviewed': len(items),
                'by_verdict': verdicts,
                'dropped': sum(1 for d in review.values() if d['action'] == 'drop'),
                'kept_with_reason': sum(1 for d in review.values() if d['action'] in ('keep', 'flag')),
            },
            'dropped_techniques': dropped_techniques,
            'chain_summary': chain['summary'],
            'technique_count': len(chain['techniques']),
            'metrics': metrics,
            # 链上可见的复核命中（决定指标的那部分），供报告明细；完整记录见 reviews_agent.jsonl
            'chain_visible_reviews': _chain_visible_reviews(chain_script, chain, review_records),
        },
        'baseline_v1': {
            'precision': script_metrics['technique_metrics']['precision'],
            'recall': script_metrics['technique_metrics']['recall'],
            'stage_recall': script_metrics['stage_metrics']['stage_recall'],
            'stage_order_consistency': script_metrics['stage_metrics']['stage_order_consistency'],
            'technique_count_normalized': len(script_metrics['predicted_techniques_normalized']),
            'decision': 'llm-low-score-review',
        },
    }

    result['log_path'] = str(log_path)
    (out / 'metrics_agent.json').write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    (out / 'report_agent.md').write_text(render_agent_report(result), encoding='utf-8')
    _snapshot_v2(out)
    print(f'metrics_agent written to {out / "metrics_agent.json"}')
    print(f'report_agent written to {out / "report_agent.md"}')
    print(f'reviews log written to {log_path}')

    return result


def _snapshot_v2(out: Path) -> None:
    """固化 v2 快照（evaluation/baseline/README.md 约定：复制保存，只读）。

    只复制小文件产物：reviews_agent.jsonl 是逐次调用的审计日志，
    本次运行完整内容留在 evaluation/ 根目录，不入快照。
    """
    snapshot = out / 'baseline' / 'v2-agent-lowscore-review'
    snapshot.mkdir(parents=True, exist_ok=True)
    for name in ('metrics_agent.json', 'report_agent.md'):
        src = out / name
        try:
            (snapshot / name).write_bytes(src.read_bytes())
        except OSError:
            print(f'[agent] WARNING: 快照复制 {name} 失败（沙箱文件锁），跳过')


def _chain_visible_reviews(
    chain_script: dict,
    chain_agent: dict,
    records: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """链上可见的复核判定：脚本链/复核链任一证据列表里出现的 (技术, 事件)。

    这些是决定指标对比的那部分判定；其余记录留在 `reviews_agent.jsonl` 审计日志。
    """
    def visible_ids(chain: dict) -> set[tuple[str, str]]:
        out: set[tuple[str, str]] = set()
        for entry in chain.get('chain', []):
            for uid in entry.get('evidence', []):
                out.add((entry['technique'], uid))
        return out

    visible = visible_ids(chain_script) | visible_ids(chain_agent)
    # 只保留判定字段：完整输入快照（含 CommandLine 等原文）在 reviews_agent.jsonl 审计日志里
    keep = ('technique_id', 'event_uid', 'score', 'verdict', 'reason', 'confidence', 'source')
    return [{k: r[k] for k in keep} for r in records if (r['technique_id'], r['event_uid']) in visible]


def render_agent_report(result: dict) -> str:
    """04 §6 对比表：v1 脚本版 vs v2 Agent 版（Δ）+ 送审明细 + 人工核对区。"""
    agent = result['agent']
    base = result['baseline_v1']
    a_tech = agent['metrics']['technique_metrics']
    a_stage = agent['metrics']['stage_metrics']
    b_tech = {'precision': base['precision'], 'recall': base['recall']}

    def pct(x: float) -> str:
        return f'{x * 100:.1f}%'

    def delta(a: float, b: float) -> str:
        d = a - b
        return f'{d * 100:+.1f}pp' if abs(d) > 1e-9 else '—'

    lines: list[str] = []
    lines.append('# ThreatLens · Agent 版评测报告（04 LLM 低分复核）')
    lines.append('')
    lines.append('> 对应说明书：`docs/开发说明/04-LLM复核层.md`；生成方式：`python -m threatlens.core.evaluation.run_eval_agent`'
                 + ('（`--mock` 确定性假 LLM）' if result['mock'] else '（真实 API，temperature=0）'))
    lines.append('')
    lines.append('## 1. 对比表（v1 脚本版 vs v2 Agent 版）')
    lines.append('')
    lines.append('| 指标 | v1 脚本版 | v2 Agent 版 | Δ |')
    lines.append('|---|---|---|---|')
    lines.append(f'| precision | {pct(b_tech["precision"])} | {pct(a_tech["precision"])} | {delta(a_tech["precision"], b_tech["precision"])} |')
    lines.append(f'| recall | {pct(b_tech["recall"])} | {pct(a_tech["recall"])} | {delta(a_tech["recall"], b_tech["recall"])} |')
    lines.append(f'| 阶段召回 | {pct(base["stage_recall"])} | {pct(a_stage["stage_recall"])} | {delta(a_stage["stage_recall"], base["stage_recall"])} |')
    lines.append(f'| 阶段顺序一致率 | {base["stage_order_consistency"]} | {a_stage["stage_order_consistency"]} | — |')
    a_norm_count = len(agent['metrics']['predicted_techniques_normalized'])
    lines.append(f'| 识别技术（归并后） | {base["technique_count_normalized"]} | {a_norm_count} | '
                 f'{a_norm_count - base["technique_count_normalized"]:+d} |')
    lines.append(f'| 可解释性 | 无 | 送审 {agent["review_stats"]["reviewed"]} 条，保留 {agent["review_stats"]["kept_with_reason"]} 条均带 reason | 新增维度 |')
    lines.append('')
    lines.append('## 2. 送审统计（§4 低分筛选）')
    lines.append('')
    by = agent['review_stats']['by_verdict']
    lines.append(f"- 送审 {agent['review_stats']['reviewed']} 条（非金标技术的全部命中 + 分数低于阈值 {1.0} 的金标命中）："
                 + ' / '.join(f'{k}={v}' for k, v in sorted(by.items())) + f"；剔除 {agent['review_stats']['dropped']} 条")
    if agent['dropped_techniques']:
        lines.append('- 因复核链上证据被全部剔除的技术：`' + '` / `'.join(agent['dropped_techniques']) + '`')
    else:
        lines.append('- 无技术被剔除。')
    lines.append('')
    lines.append('## 3. 判定明细与人工核对区（§6 辅助：抽查链上可见判定）')
    lines.append('')
    lines.append(f'> 仅列链上可见命中（脚本链/复核链证据列表中出现过的，决定指标的那部分，共 '
                 f'{len(agent["chain_visible_reviews"])} 条）；全部 {agent["review_stats"]["reviewed"]} 条送审记录见 '
                 '`evaluation/reviews_agent.jsonl`。')
    lines.append('')
    lines.append('| 技术 | 事件 | score | verdict | 置信 | reason |')
    lines.append('|---|---|---|---|---|---|')
    for record in agent['chain_visible_reviews']:
        lines.append(f"| {record['technique_id']} | `{record['event_uid']}` | {record['score']:.1f} | "
                     f"{record['verdict']} | {record['confidence']:.1f} | {record['reason']} |")
    lines.append('')
    lines.append('## 4. 结论')
    lines.append('')
    if a_tech['precision'] > b_tech['precision'] and a_tech['recall'] == b_tech['recall']:
        verdict_line = f"Agent 版 precision 提升 {delta(a_tech['precision'], b_tech['precision'])}（降噪生效），recall 持平——“Agent 比脚本强”的量化证据成立。"
    elif a_tech['recall'] < b_tech['recall']:
        verdict_line = '⚠️ recall 下降——复核误删了金标证据，需检查对应 verdict（红线：LLM 不改变确定性判定，误删需人工复核修正）。'
    else:
        verdict_line = 'precision 未提升——LLM 复核确认了非金标命中（多为真实攻击行为），降噪空间有限；Agent 价值在可解释性（reason 落地），需人工核对后定论。'
    lines.append(f'**{verdict_line}**')
    lines.append('')
    lines.append(f'- 可解释性：送审 {agent["review_stats"]["reviewed"]} 条均有 reason（链上 `review` 元数据可查）；'
                 f'本次调用记录见 `evaluation/reviews_agent.jsonl`（输入快照 + 输出 + 耗时）。')
    lines.append('- 复现：mock 模式全确定性；真实 API 模式 `temperature=0` + jsonl 审计兜底。')
    lines.append('')
    return '\n'.join(lines)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='04 Agent 版评测：脚本主干 + LLM 低分复核')
    parser.add_argument('--mock', action='store_true', help='用确定性假 LLM（无外网，可复现）')
    args = parser.parse_args()
    if hasattr(sys.stdout, 'reconfigure'):  # Windows GBK 控制台中文乱码兜底
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    load_env_file(ROOT / '.env')  # DEEPSEEK_API_KEY 兜底加载（不入库）
    result = run_eval_agent(mock=args.mock)
    a = result['agent']['metrics']['technique_metrics']
    b = result['baseline_v1']
    print(f"\n[v1] precision={b['precision']:.3f} recall={b['recall']:.3f} "
          f"→ [v2] precision={a['precision']:.3f} recall={a['recall']:.3f}")
    sys.exit(0)
