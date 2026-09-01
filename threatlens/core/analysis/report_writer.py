from __future__ import annotations

import json
import re
import time
import os
from pathlib import Path
from typing import Any

from threatlens.core.evaluation.llm_review import DEEPSEEK_BASE_URL, DEEPSEEK_MODEL, API_KEY_ENV

REPORT_SYSTEM_PROMPT = (
    '你是安全分析报告撰写者。将给定的结构化攻击链 JSON 转成分析师可读的中文 Markdown 报告。'
    ' 硬约束：只依据给定 JSON，不得臆测或添加链上不存在的事实；报告中出现的技术 ID 必须来自输入 JSON 的 techniques 集合；不得引用数据集名称或测试集结论。'
)

_TECH_RE = re.compile(r"\bT\d+(?:\.\d+)?\b")


def _mock_render_from_chain(chain: dict, reviews: dict | None) -> str:
    lines: list[str] = []
    lines.append('# 攻击链分析报告（自动生成，mock）')
    lines.append('')
    lines.append('## 摘要')
    lines.append(chain.get('summary', '无摘要'))
    lines.append('')
    lines.append('## 攻击链详情')
    techniques = chain.get('techniques', {})
    for entry in chain.get('chain', []):
        tech = entry.get('technique')
        name = techniques.get(tech, {}).get('name', '')
        lines.append(f"### {tech} — {name}")
        lines.append(f"- 战术: {entry.get('tactic')}")
        lines.append(f"- 首次出现: {entry.get('first_seen')}")
        # list evidence with optional review reason
        lines.append('- 证据:')
        for uid in entry.get('evidence', []):
            reason = None
            if reviews:
                # reviews keys may be (tech, uid)
                key = (tech, uid)
                r = reviews.get(key)
                if r:
                    reason = r.get('reason')
            if reason:
                lines.append(f"  - `{uid}` — reason: {reason}")
            else:
                lines.append(f"  - `{uid}`")
        lines.append('')
    lines.append('## 证据附录（原始事件 UID 列表）')
    lines.append('\n'.join(sorted({uid for e in chain.get('chain', []) for uid in e.get('evidence', [])})))
    return '\n'.join(lines)


def build_report(chain: dict, reviews: dict | None = None, *, out_path: str | Path | None = None, mock: bool = True) -> str:
    """将结构化 AttackChain 转成 Markdown 报告。

    - mock=True 时使用内置确定性渲染（无外网），适合单测与开发阶段。
    - 将调用记录落 `evaluation/reports_agent.jsonl`（审计）。
    """
    report_before = ''
    source = 'mock'
    if mock:
        report = _mock_render_from_chain(chain, reviews)
        source = 'mock'
    else:
        # prefer environment variable
        api_key = os.environ.get(API_KEY_ENV)
        # call real LLM when key present
        if not api_key:
            report = _mock_render_from_chain(chain, reviews)
            source = 'mock-fallback'
        else:
            try:
                report = _call_llm(chain, reviews, api_key)
                source = 'llm'
            except Exception:
                report = _mock_render_from_chain(chain, reviews)
                source = 'mock-fallback'
    report_before = report

    # write audit log
    root = Path(__file__).resolve().parents[3] / 'evaluation'
    root.mkdir(parents=True, exist_ok=True)
    log = root / 'reports_agent.jsonl'
    # hallucination filter: remove any line that mentions tech IDs not in chain
    valid_techs = set(chain.get('techniques', {}).keys())
    removed_lines: list[str] = []
    kept_lines: list[str] = []
    for line in report.splitlines():
        ids = _TECH_RE.findall(line)
        if ids and any(i not in valid_techs for i in ids):
            removed_lines.append(line)
        else:
            kept_lines.append(line)
    report_after = '\n'.join(kept_lines)

    record = {
        'ts': time.time(),
        'source': source,
        'chain_summary': chain.get('summary'),
        'technique_count': len(chain.get('techniques', {})),
        'report_length_before': len(report_before),
        'report_length_after': len(report_after),
        'hallucinated_lines_removed': len(removed_lines),
        'removed_example': removed_lines[:3],
    }
    try:
        with log.open('a', encoding='utf-8') as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + '\n')
    except OSError:
        pass

    if out_path:
        p = Path(out_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(report_after, encoding='utf-8')

    return report_after


def _call_llm(chain: dict, reviews: dict | None, api_key: str, timeout: int = 30) -> str:
    """调用 DeepSeek/OpenAI 兼容接口，返回生成文本（str）。

    抛出异常由调用方处理并降级到 mock。
    """
    import os as _os
    import urllib.request as _request

    payload = {
        'model': DEEPSEEK_MODEL,
        'messages': [
            {'role': 'system', 'content': REPORT_SYSTEM_PROMPT},
            {'role': 'user', 'content': json.dumps({'chain': chain, 'reviews': reviews}, ensure_ascii=False)},
        ],
        'temperature': 0,
    }
    req = _request.Request(
        f'{DEEPSEEK_BASE_URL}/chat/completions',
        data=json.dumps(payload).encode('utf-8'),
        headers={
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {api_key}',
        },
        method='POST',
    )
    with _request.urlopen(req, timeout=timeout) as resp:
        body = json.loads(resp.read().decode('utf-8'))
    return body['choices'][0]['message']['content']
