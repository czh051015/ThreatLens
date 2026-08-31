"""04 §5：LLM 低分证据复核层（单一函数，非多 Agent）。

设计：
- **mock 先行**：`DEEPSEEK_API_KEY` 缺失或 `mock=True` 时用确定性假响应跑通链路
  （单测不依赖外网）；mock 判定由 (技术, 事件) 的 md5 决定，跨进程可复现。
- **真实调用**：OpenAI 兼容 `/chat/completions`（DeepSeek `deepseek-chat`），
  `temperature=0` 保可复现；key 走环境变量 `DEEPSEEK_API_KEY`（不入库，§7 密钥泄露）。
- **审计**：每次调用落 `evaluation/reviews_agent.jsonl`（输入快照 + 输出 + 耗时）。
- **失败兜底**：网络/JSON 解析失败一律 `unknown`（不误删，§7 幻觉/误判缓解）；
  LLM 只复核低分命中，不参与确定性判定主干（架构红线 §3）。
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

DEEPSEEK_BASE_URL = 'https://api.deepseek.com'
DEEPSEEK_MODEL = 'deepseek-chat'
API_KEY_ENV = 'DEEPSEEK_API_KEY'

VALID_VERDICTS = ('attack', 'benign', 'unknown')

SYSTEM_PROMPT = (
    '你是安全分析助手。给定一条规则命中及其证据事件，判断该命中是否真实支持对应 '
    'ATT&CK 技术。只依据证据字段判断，不要臆测。输出 JSON：verdict 取 '
    'attack/benign/unknown，reason 不超过一句话。'
)

#: 送审上下文携带的证据字段（§5 契约；项目事件模型为小写蛇形顶层字段，
#: 对应 Sigma 检测字段 Image/CommandLine 等；事件里没有的字段自然省略）。
#: 注意：不带 tactic_hint（数据集的攻击阶段标注）——那是测试集结论，
#: 放进上下文等于把答案写进考题（§7 prompt 背答案 / §8 验收强制）。
_CONTEXT_FIELDS = (
    'event_uid', 'event_id', 'timestamp',
    'process_name', 'command_line', 'parent_process', 'process_id',
    'user', 'host',
)

_MOCK_VERDICTS = ('attack', 'benign', 'unknown')


@dataclass
class ReviewItem:
    """一条待复核命中：(技术, 事件) 粒度。"""

    technique_id: str
    event_uid: str
    score: float
    rule_paths: list[str]
    event_fields: dict[str, Any]


@dataclass
class ReviewDecision:
    verdict: str  # attack | benign | unknown
    reason: str
    confidence: float
    source: str  # llm | mock | fallback


# ---------------------------------------------------------------------------
# 上下文组装（§5 输入契约）
# ---------------------------------------------------------------------------

def build_context(item: ReviewItem, attack_lib: dict[str, dict[str, Any]] | None = None) -> dict[str, Any]:
    """组装 LLM 用户消息：技术 ID/名称 + 命中规则名 + 证据字段 + 打分。"""
    return {
        'technique_id': item.technique_id,
        'technique_name': (attack_lib or {}).get(item.technique_id, {}).get('name', ''),
        'rule_names': [Path(p).name for p in item.rule_paths],
        'score': item.score,
        'event': {k: v for k, v in item.event_fields.items() if k in _CONTEXT_FIELDS},
    }


# ---------------------------------------------------------------------------
# 输出解析（健壮性：§8 验收 JSON 解析）
# ---------------------------------------------------------------------------

def parse_verdict(content: str) -> ReviewDecision:
    """解析 LLM 输出为结构化判定；任何异常 → unknown（不误删兜底）。"""
    verdict, reason, confidence = 'unknown', '', 0.0
    text = (content or '').strip()
    # 去掉 ```json ... ``` 围栏（LLM 常见输出形态）
    if text.startswith('```'):
        text = text.strip('`')
        if text.startswith('json'):
            text = text[4:]
        text = text.strip()
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        data = None
    if isinstance(data, dict):
        if data.get('verdict') in VALID_VERDICTS:
            verdict = data['verdict']
        reason = str(data.get('reason', ''))[:200]
        try:
            confidence = max(0.0, min(1.0, float(data.get('confidence', 0.0))))
        except (TypeError, ValueError):
            confidence = 0.0
    return ReviewDecision(verdict=verdict, reason=reason, confidence=confidence, source='llm')


# ---------------------------------------------------------------------------
# 调用（mock 先行 / 真实 API）
# ---------------------------------------------------------------------------

def mock_verdict(item: ReviewItem) -> ReviewDecision:
    """确定性假响应：md5(技术+事件) 轮换 attack/benign/unknown（跨进程可复现）。"""
    digest = hashlib.md5(f'{item.technique_id}:{item.event_uid}'.encode('utf-8')).hexdigest()
    verdict = _MOCK_VERDICTS[int(digest, 16) % 3]
    return ReviewDecision(verdict=verdict, reason=f'mock 确定性响应（{verdict}）', confidence=0.5, source='mock')


def _call_deepseek(context: dict[str, Any], api_key: str, timeout: int) -> ReviewDecision:
    """真实调用：OpenAI 兼容 /chat/completions（stdlib urllib，零新增依赖）。"""
    import urllib.error
    import urllib.request

    payload = {
        'model': DEEPSEEK_MODEL,
        'messages': [
            {'role': 'system', 'content': SYSTEM_PROMPT},
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
    return parse_verdict(content)


def llm_review(
    item: ReviewItem,
    api_key: str | None = None,
    *,
    mock: bool = False,
    attack_lib: dict[str, dict[str, Any]] | None = None,
    log_path: str | Path | None = None,
    records: list[dict[str, Any]] | None = None,
    timeout: int = 30,
) -> ReviewDecision:
    """复核一条命中：组装上下文 → 调用（mock/真实）→ 结构化判定 → 审计记录。

    - 真实模式下 API/网络异常 → `unknown` 兜底（来源标记 `fallback`），不抛异常；
    - `log_path` 非空时把调用记录**追加**到 JSONL（输入快照 + 输出 + 耗时）；
    - `records` 非空时同一记录同步进内存列表（报告渲染用，避免读回刚写入的文件）。
    """
    context = build_context(item, attack_lib)
    t0 = time.time()
    if mock or not api_key:
        decision = mock_verdict(item)
    else:
        try:
            decision = _call_deepseek(context, api_key, timeout)
        except Exception as exc:  # 网络/鉴权/解析 → 兜底 unknown，不误删
            decision = ReviewDecision(verdict='unknown', reason=f'LLM 调用失败：{exc}', confidence=0.0, source='fallback')
    latency = round(time.time() - t0, 3)

    record = {
        'technique_id': item.technique_id,
        'event_uid': item.event_uid,
        'score': item.score,
        'rule_paths': item.rule_paths,
        'context': context,
        'verdict': decision.verdict,
        'reason': decision.reason,
        'confidence': decision.confidence,
        'source': decision.source,
        'latency_sec': latency,
    }
    if log_path is not None:
        with Path(log_path).open('a', encoding='utf-8') as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + '\n')
    if records is not None:
        records.append(record)

    return decision
