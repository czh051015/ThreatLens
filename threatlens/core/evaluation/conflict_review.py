"""04 §12：冲突证据复核（P2 三期）——对共享事件的技术组裁决主技术。

与低分复核（llm_review.py）互补的第二个 LLM 介入点：
- 低分复核（§3–§10）：按可疑性分数降噪；
- 冲突复核（§12）：同一事件被 ≥2 个技术归属 → 裁决主技术，剔除非金标归属。

管道（§12.3）：脚本主干 → 低分复核 → 冲突组重算 → 冲突裁决 → AttackChain。
裁决结果并入 llm_review 的 `review` dict（(technique_id, event_uid) → action=drop），
build_chain 语义零改动。

金标硬约束（§12.3/§12.5）：金标技术永不因裁决被 drop（recall 100% 硬约束，
代码在 `conflict_review` 返回时强制过滤 dropped）。
失败兜底：解析/调用异常 → primary=None、dropped=[]（保持原状，不误删）。
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .llm_review import DEEPSEEK_BASE_URL, DEEPSEEK_MODEL, _CONTEXT_FIELDS
from .metrics import normalize_technique

CONFLICT_SYSTEM_PROMPT = (
    '你是安全分析助手。给定一个事件及其候选 ATT&CK 技术标签，'
    '判断该事件最可能属于哪个技术（primary），并列出应被剔除的技术标签（dropped）。'
    '只依据证据字段和通用安全知识，不要臆测。输出 JSON：primary 取一个候选技术 ID，'
    'dropped 取候选技术 ID 列表，reason 不超过一句话。'
)


@dataclass
class ConflictGroup:
    """一个冲突事件：被 ≥2 个技术共享证据。"""

    event_uid: str
    techniques: list[str]  # 候选技术（按链顺序）


@dataclass
class ConflictDecision:
    primary: str | None  # None = 裁决失败/保持原状
    dropped: list[str]  # 应剔除的技术（已过滤金标，永不含金标）
    reason: str
    source: str  # llm | mock | fallback


# ---------------------------------------------------------------------------
# 冲突组发现（§12.2 反向映射；基于复核后链，§12.3）
# ---------------------------------------------------------------------------

def find_conflict_groups(
    chain: dict[str, Any],
    gold_normalized: set[str] | frozenset[str],
) -> list[ConflictGroup]:
    """复核后链 → 事件反向映射 → 冲突组（被 ≥2 个技术共享证据的事件）。

    - 基于**低分复核后**的链重算：低分已剔除的一方，冲突自动消失（§12.3）；
    - 全部候选都是金标技术的组无非金标可裁 → 跳过（省调用）；
    - 含金标候选的组照常送出：金标在 `conflict_review` 返回值处被强制保留，
      裁决对象是组内的非金标归属（§12.3 "金标不参与裁决"的代码化）。
    """
    uid_to_techniques: dict[str, list[str]] = {}
    for entry in chain.get('chain', []):
        for uid in entry.get('evidence', []):
            uid_to_techniques.setdefault(uid, []).append(entry['technique'])

    groups: list[ConflictGroup] = []
    for uid in sorted(uid_to_techniques):
        techniques = uid_to_techniques[uid]
        if len(techniques) < 2:
            continue
        if all(normalize_technique(t) in gold_normalized for t in techniques):
            continue  # 无非金标可裁
        groups.append(ConflictGroup(event_uid=uid, techniques=techniques))
    return groups


# ---------------------------------------------------------------------------
# 上下文组装（§12.4：事件字段 + 候选技术列表）
# ---------------------------------------------------------------------------

def build_conflict_context(
    group: ConflictGroup,
    event_fields: dict[str, Any],
    attack_lib: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """事件关键字段（白名单，同 llm_review）+ 候选技术（ID/名称）。"""
    return {
        'event': {k: v for k, v in event_fields.items() if k in _CONTEXT_FIELDS},
        'candidates': [
            {'technique_id': t, 'technique_name': (attack_lib or {}).get(t, {}).get('name', '')}
            for t in group.techniques
        ],
    }


# ---------------------------------------------------------------------------
# 输出解析（健壮性：任何异常 → 保持原状，不误删）
# ---------------------------------------------------------------------------

def parse_conflict_decision(content: str, candidates: list[str]) -> ConflictDecision:
    """解析裁决 JSON；primary 不在候选/dropped 含 primary → 规范化处理。"""
    text = (content or '').strip()
    if text.startswith('```'):
        text = text.strip('`')
        if text.startswith('json'):
            text = text[4:]
        text = text.strip()
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return ConflictDecision(None, [], '', 'llm')
    if not isinstance(data, dict):
        return ConflictDecision(None, [], '', 'llm')

    primary = data.get('primary')
    if primary not in candidates:
        # 幻觉技术 ID → 裁决整体不可信 → 保持原状（不误删）
        return ConflictDecision(None, [], str(data.get('reason', ''))[:200], 'llm')
    dropped_raw = data.get('dropped', [])
    if not isinstance(dropped_raw, list):
        dropped_raw = []
    dropped = [t for t in dropped_raw if t in candidates and t != primary]
    return ConflictDecision(primary, dropped, str(data.get('reason', ''))[:200], 'llm')


# ---------------------------------------------------------------------------
# 调用（mock 先行 / 真实 API；复用 llm_review 的 HTTP 骨架）
# ---------------------------------------------------------------------------

def mock_conflict_decision(group: ConflictGroup) -> ConflictDecision:
    """确定性假裁决：md5(事件+候选) 轮换三分支（可复现，单测覆盖三态）。

    分支 0：primary=第一个候选，dropped=其余；分支 1：primary=最后一个，
    dropped=第一个；分支 2：存疑保持（不 drop）。
    """
    digest = hashlib.md5(
        f'{group.event_uid}:{"|".join(group.techniques)}'.encode('utf-8')
    ).hexdigest()
    branch = int(digest, 16) % 3
    if branch == 0:
        return ConflictDecision(group.techniques[0], group.techniques[1:],
                                'mock 确定性响应：主技术为第一个候选', 'mock')
    if branch == 1:
        return ConflictDecision(group.techniques[-1], [group.techniques[0]],
                                'mock 确定性响应：主技术为最后一个候选', 'mock')
    return ConflictDecision(group.techniques[0], [],
                            'mock 确定性响应：证据存疑，保持原状', 'mock')


def _call_deepseek_conflict(context: dict[str, Any], api_key: str, timeout: int) -> ConflictDecision:
    """真实裁决：OpenAI 兼容 /chat/completions（stdlib urllib，零新增依赖）。"""
    import urllib.error
    import urllib.request

    candidates = [c['technique_id'] for c in context['candidates']]
    payload = {
        'model': DEEPSEEK_MODEL,
        'messages': [
            {'role': 'system', 'content': CONFLICT_SYSTEM_PROMPT},
            {'role': 'user', 'content': json.dumps(context, ensure_ascii=False)},
        ],
        'temperature': 0,
    }
    request = urllib.request.Request(
        f'{DEEPSEEK_BASE_URL}/chat/completions',
        data=json.dumps(payload).encode('utf-8'),
        headers={
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {api_key}',
        },
        method='POST',
    )
    with urllib.request.urlopen(request, timeout=timeout) as resp:
        body = json.loads(resp.read().decode('utf-8'))
    content = body['choices'][0]['message']['content']
    return parse_conflict_decision(content, candidates)


def conflict_review(
    group: ConflictGroup,
    api_key: str | None = None,
    *,
    mock: bool = False,
    gold_normalized: set[str] | frozenset[str] = frozenset(),
    attack_lib: dict[str, dict[str, Any]] | None = None,
    event_fields: dict[str, Any] | None = None,
    log_path: str | Path | None = None,
    records: list[dict[str, Any]] | None = None,
    timeout: int = 30,
) -> ConflictDecision:
    """裁决一个冲突组：组装上下文 → 调用（mock/真实）→ 金标硬约束 → 审计记录。

    - 金标硬约束：dropped 中归一化为金标的技术被强制移除（recall 100%）；
    - 真实模式下 API/解析异常 → 保持原状（primary=None, dropped=[]，不误删）；
    - `log_path` 非空时把调用记录**追加**到 JSONL（输入快照 + 输出 + 耗时）。
    """
    context = build_conflict_context(group, event_fields or {}, attack_lib)
    t0 = time.time()
    if mock or not api_key:
        decision = mock_conflict_decision(group)
    else:
        try:
            decision = _call_deepseek_conflict(context, api_key, timeout)
        except Exception as exc:  # 网络/鉴权/解析 → 保持原状，不误删
            decision = ConflictDecision(None, [], f'LLM 调用失败：{exc}', 'fallback')
    decision.dropped = [
        t for t in decision.dropped if normalize_technique(t) not in gold_normalized
    ]
    latency = round(time.time() - t0, 3)

    record = {
        'kind': 'conflict',
        'event_uid': group.event_uid,
        'candidates': group.techniques,
        'context': context,
        'primary': decision.primary,
        'dropped': decision.dropped,
        'reason': decision.reason,
        'source': decision.source,
        'latency_sec': latency,
    }
    if log_path is not None:
        with Path(log_path).open('a', encoding='utf-8') as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + '\n')
    if records is not None:
        records.append(record)

    return decision
