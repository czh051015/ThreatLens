"""03 §3 评测口径：技术 ID 归并 + precision/recall + 阶段召回 + 阶段顺序一致率。

全部函数为纯函数（不碰文件系统），run_eval.py 负责装配数据；
指标可单测，保证与 03 §3 口径一一对应。
"""

from __future__ import annotations

from typing import Any, Iterable

#: §6 决策规则中"高/低"的量化口径（03 表格的确定性落地）
RECALL_LOW = 1.0   # recall < 1.0（金标未全覆盖）即视为"低"→ 规则覆盖不足
PRECISION_LOW = 0.5  # precision < 0.5 视为"低"→ LLM 空间在降噪/去误报


def normalize_technique(tech_id: str) -> str:
    """子技术 → 父技术归并（03 §3.2）：`T1059.001` → `T1059`；无子级原样返回。"""
    return tech_id.split('.', 1)[0] if '.' in tech_id else tech_id


def normalize_technique_set(tech_ids: Iterable[str]) -> set[str]:
    """gold 与 predicted 都归并后再比，避免父子技术同行为被拆开计数。"""
    return {normalize_technique(t) for t in tech_ids}


def compute_technique_metrics(predicted: set[str], gold: set[str]) -> dict[str, Any]:
    """03 §3.3：precision = |gold ∩ predicted| / |predicted|；recall = |gold ∩ predicted| / |gold|。

    入参须已归并（normalize_technique_set）。
    """
    hits = gold & predicted
    precision = len(hits) / len(predicted) if predicted else 0.0
    recall = len(hits) / len(gold) if gold else 0.0
    return {
        'hits': sorted(hits),
        'extra_techniques': sorted(predicted - gold),
        'missed_techniques': sorted(gold - predicted),
        'precision': round(precision, 4),
        'recall': round(recall, 4),
    }


def compute_stage_metrics(predicted_stages: list[str], gold_stages: list[str]) -> dict[str, Any]:
    """03 §3.4 链还原完整度。

    - `stage_recall` = |gold ∩ predicted| / |gold|（predicted 取集合）；
    - `stage_order_consistency`：predicted 链中**金标阶段**的相对顺序与 gold
      链顺序一致的比例——pairwise 两两比较（金标阶段外的阶段不参与）。
      共同阶段 < 2 个时无 pair 可判 → None（避免除零与假 1.0）。
    """
    gold_order = list(dict.fromkeys(gold_stages))  # 保序去重
    gold_set = set(gold_order)
    # observed：predicted 链中属于金标的阶段，按首次出现顺序保序去重
    observed = list(dict.fromkeys(s for s in predicted_stages if s in gold_set))

    stage_recall = len(observed) / len(gold_set) if gold_set else 0.0

    consistency: float | None = None
    if len(observed) >= 2:
        gold_pos = {s: i for i, s in enumerate(gold_order)}
        pairs = [(observed[i], observed[j]) for i in range(len(observed)) for j in range(i + 1, len(observed))]
        consistent = sum(1 for a, b in pairs if gold_pos[a] < gold_pos[b])
        consistency = round(consistent / len(pairs), 4)

    return {
        'gold_stages': gold_order,
        'observed_stages': observed,
        'stage_recall': round(stage_recall, 4),
        'stage_order_consistency': consistency,
    }


def metrics_from_chain(chain: dict[str, Any], gold_techniques: list[str], gold_stages: list[str]) -> dict[str, Any]:
    """从 AttackChain dict 计算全套指标（03 §5.4 第 4 步）。

    - predicted = `chain.techniques` 键集（归并后）；gold 同口径归并；
    - predicted_stages = `chain.chain[].tactic`（保序）。
    """
    predicted = normalize_technique_set(chain['techniques'].keys())
    gold = normalize_technique_set(gold_techniques)
    technique = compute_technique_metrics(predicted, gold)
    stage = compute_stage_metrics([e['tactic'] for e in chain['chain']], gold_stages)
    return {
        'gold_techniques_normalized': sorted(gold),
        'predicted_techniques_normalized': sorted(predicted),
        'predicted_techniques_raw': sorted(chain['techniques'].keys()),
        'technique_metrics': technique,
        'stage_metrics': stage,
    }


def decide_next_step(metrics: dict[str, Any]) -> dict[str, str]:
    """03 §6 决策规则（Q2 pivot 逻辑，量化落地）。

    | 条件 | 决策 |
    |---|---|
    | recall < RECALL_LOW | `expand-rules`：规则覆盖不足，优先扩规则 |
    | recall 高 且 precision < PRECISION_LOW | `llm-low-score-review`：LLM 定位为低分证据复核 |
    | 双高 | `pivot-to-explainability`：LLM 加不上去，pivot 到解释性叙事 |
    """
    recall = metrics['technique_metrics']['recall']
    precision = metrics['technique_metrics']['precision']
    if recall < RECALL_LOW:
        decision = 'expand-rules'
        reason = f'recall={recall} < {RECALL_LOW}（金标未全覆盖）→ 规则覆盖不足，优先扩规则，再谈 LLM'
    elif precision < PRECISION_LOW:
        decision = 'llm-low-score-review'
        reason = f'recall={recall} 高、precision={precision} < {PRECISION_LOW} → LLM 空间在降噪/去误报，解释层定位为"低分证据复核"'
    else:
        decision = 'pivot-to-explainability'
        reason = f'precision/recall 双高（{precision}/{recall}）→ LLM 加不上去，pivot 到"可解释性/冲突推理/证据链"叙事'
    return {'decision': decision, 'reason': reason}
