"""03 评测（P2 baseline 摸底）：版本分离 → evaluation/metrics.json + report.md。

用法：python -m threatlens.core.evaluation.run_eval
产物：
- `evaluation/metrics.json`：官方版 + 官方+自定义版两套指标（全确定性，无时间戳）；
- `evaluation/report.md`：数字 + 版本对比 + §6 pivot 判断。

流程对应 03 §5：取金标 → 跑两版 AttackChain → 算指标 → 写产物。
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from threatlens.core.analysis.run_demo import (
    ATTACK_PATH,
    ATOMIC_ROOT,
    GOLD_TECHNIQUES,
    PHASE_ORDER,
    ROOT,
    run_demo,
)
from threatlens.core.data import load_attack_techniques
from threatlens.core.data.load_atomic import load_atomic_chain

from .metrics import decide_next_step, metrics_from_chain, normalize_technique_set

EVAL_ROOT = ROOT / 'evaluation'
METRICS_PATH = EVAL_ROOT / 'metrics.json'
REPORT_PATH = EVAL_ROOT / 'report.md'

#: 版本分离红线（03 §3.5）：官方版为主数字（简历），官方+自定义版为 demo 完整性数字
VARIANTS = [
    ('official', False),
    ('official+custom', True),
]


def run_eval(write_files: bool = True, out_dir: str | Path | None = None) -> dict:
    """03 §5 评测流程：金标 → 两版 AttackChain → 指标 → 产物。

    - `out_dir=None` → 写默认 `evaluation/`；测试可传 tmp 目录隔离产物。
    """
    # 1. 取金标（§5.1）
    attack_lib = load_attack_techniques(ATTACK_PATH)
    gold = load_atomic_chain(ATOMIC_ROOT, GOLD_TECHNIQUES, attack_lib)
    gold_stages = list(dict.fromkeys(
        t for tech in gold for t in tech['tactics'] if t in PHASE_ORDER
    ))

    # 2-3. 官方版 / 官方+自定义版（§5.2 / §5.3）
    versions: dict[str, dict] = {}
    for variant, include_custom in VARIANTS:
        chain = run_demo(include_custom=include_custom, write_output=False)
        metrics = metrics_from_chain(chain, GOLD_TECHNIQUES, gold_stages)
        versions[variant] = {
            'rules_variant': chain['meta']['rules_variant'],
            'rule_count': chain['meta']['rule_count'],
            'technique_count': len(chain['techniques']),
            'stage_count': len({e['tactic'] for e in chain['chain']}),
            'summary': chain['summary'],
            'technique_evidence': {e['technique']: e['evidence'] for e in chain['chain']},
            'metrics': metrics,
            'decision': decide_next_step(metrics),
        }

    result = {
        'schema_version': '1.0',
        'gold': {
            'techniques': GOLD_TECHNIQUES,
            'techniques_normalized': sorted(normalize_technique_set(GOLD_TECHNIQUES)),
            'stages': gold_stages,
        },
        'versions': versions,
    }

    if write_files:
        out = Path(out_dir) if out_dir else EVAL_ROOT
        out.mkdir(parents=True, exist_ok=True)
        (out / 'metrics.json').write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
        (out / 'report.md').write_text(render_report(result), encoding='utf-8')
        print(f'metrics written to {out / "metrics.json"}')
        print(f'report written to {out / "report.md"}')
    return result


def render_report(result: dict) -> str:
    """03 §5.5 评测报告：数字 + 版本对比 + 结论（§6 pivot 判断）。确定性生成。"""
    g = result['gold']
    v = result['versions']
    official, custom = v['official'], v['official+custom']

    tm_o, tm_c = official['metrics']['technique_metrics'], custom['metrics']['technique_metrics']
    sm_o, sm_c = official['metrics']['stage_metrics'], custom['metrics']['stage_metrics']

    def pct(x: float) -> str:
        return f'{x * 100:.1f}%'

    lines: list[str] = []
    lines.append('# ThreatLens · P2 Baseline 摸底评测报告')
    lines.append('')
    lines.append('> 对应说明书：`docs/开发说明/03-评测.md`（P2 baseline 摸底）')
    lines.append('> 生成方式：`python -m threatlens.core.evaluation.run_eval`（全确定性，可重跑复现）')
    lines.append('')
    lines.append('## 1. 评测口径（03 §3）')
    lines.append('')
    lines.append('- 金标：`' + '` / `'.join(g['techniques']) + '`（`load_atomic_chain` 从 Atomic 提取）')
    lines.append('- 技术 ID 归并（§3.2）：子技术→父技术，gold 与 predicted 同口径 → `' + '` / `'.join(g['techniques_normalized']) + '`')
    lines.append('- 金标阶段顺序：' + ' → '.join(g['stages']))
    lines.append('- 输入遥测：4 数据集 9050 事件；主干确定性流水线，全程无 LLM')
    lines.append('')
    lines.append('## 2. 指标对比（版本分离红线 §3.5）')
    lines.append('')
    lines.append('| 指标 | 官方规则版（主数字） | 官方+自定义版（demo 完整性） |')
    lines.append('|---|---|---|')
    lines.append(f'| 规则数 | {official["rule_count"]} | {custom["rule_count"]} |')
    lines.append(f'| 识别技术（原始） | {official["technique_count"]} | {custom["technique_count"]} |')
    lines.append(f'| 识别技术（归并后） | {len(official["metrics"]["predicted_techniques_normalized"])} | {len(custom["metrics"]["predicted_techniques_normalized"])} |')
    lines.append(f'| precision | {pct(tm_o["precision"])} | {pct(tm_c["precision"])} |')
    lines.append(f'| recall | {pct(tm_o["recall"])} | {pct(tm_c["recall"])} |')
    lines.append(f'| 阶段召回 | {pct(sm_o["stage_recall"])} | {pct(sm_c["stage_recall"])} |')
    lines.append(f'| 阶段顺序一致率 | {sm_o["stage_order_consistency"]} | {sm_c["stage_order_consistency"]} |')
    lines.append(f'| §6 决策 | `{official["decision"]["decision"]}` | `{custom["decision"]["decision"]}` |')
    lines.append('')
    lines.append('## 3. 明细（原始 ID，未归并——§8 防“看起来都对”）')
    lines.append('')
    for label, entry, sm in (('官方规则版', official, sm_o), ('官方+自定义版', custom, sm_c)):
        m = entry['metrics']
        tm = m['technique_metrics']
        lines.append(f'### {label}')
        lines.append('')
        lines.append('- predicted 原始 ID：`' + '` / `'.join(m['predicted_techniques_raw']) + '`')
        lines.append('- 命中（归并后）：`' + '` / `'.join(tm['hits']) + '`' if tm['hits'] else '- 命中（归并后）：（无）')
        lines.append('- 漏检：`' + '` / `'.join(tm['missed_techniques']) + '`' if tm['missed_techniques'] else '- 漏检：（无）')
        lines.append('- 额外（非金标）：`' + '` / `'.join(tm['extra_techniques']) + '`' if tm['extra_techniques'] else '- 额外：（无）')
        lines.append('- 阶段观察（金标阶段按序）：' + '、'.join(sm['observed_stages']))
        lines.append('')
    lines.append('## 4. 结论与 pivot 判断（§6 决策规则）')
    lines.append('')
    lines.append(f'- **官方规则版**（主数字）：{official["decision"]["reason"]}。')
    lines.append(f'- **官方+自定义版**：{custom["decision"]["reason"]}。')
    if tm_o['missed_techniques']:
        lines.append(f'- 官方版漏检项 `{"/".join(tm_o["missed_techniques"])}` 对应金标阶段缺失——根因是官方 Sigma 规则对该攻击行为无命中（规则覆盖缺口，非误报问题），需优先扩规则。')
    if tm_c['missed_techniques'] and set(tm_c['missed_techniques']) != set(tm_o['missed_techniques']):
        lines.append(f'- 官方+自定义版额外补足漏检项：`{"/".join(tm_c["missed_techniques"])}`。')
    lines.append(f'- 两版 precision 均偏低（官方 {pct(tm_o["precision"])}）：额外技术 {len(tm_o["extra_techniques"])} 个——部分是真实攻击行为（不在 demo 链金标范围），部分是规则泛化误报；**这正是 LLM 解释层“低分证据复核”的输入空间**。')
    lines.append('')
    if tm_o['recall'] >= 1.0 and tm_c['recall'] >= 1.0:
        coverage = '两版 recall 均达标（金标技术全覆盖）'
    else:
        coverage = 'recall 未完全达标（金标有缺口，优先扩规则）'
    lines.append(f'**结论**：确定性 baseline 摸底完成——{coverage}、precision 偏低（~{pct(tm_c["precision"])}）→ LLM 解释层按“低分证据复核”定位（§6 决策规则），主干确定性叙事不变，主数字以官方规则版为准。')
    lines.append('')
    lines.append('## 5. 版本分离说明（§3.5 红线）')
    lines.append('')
    lines.append('- 官方规则版 = `_src/rules/windows/` 全部可解析规则，简历主数字。')
    lines.append('- 官方+自定义版 = 官方 + `threatlens/core/analysis/sigma_custom_rules/credentials_access_powershell_lsass.yml`（T1003.001 自定义规则，实测 4 数据集唯一命中 `empire_mimikatz_logonpasswords_2020-08-07103224.json:2451`、零误报）。')
    lines.append('- 两版数字分开报告，禁止只报合并数字（防循环论证）。')
    lines.append('')
    lines.append('### 两版证据差异（逐技术 evidence 集变化）')
    lines.append('')
    ev_o, ev_c = official['technique_evidence'], custom['technique_evidence']
    diffs = []
    for technique in sorted(set(ev_o) | set(ev_c)):
        added = sorted(set(ev_c.get(technique, [])) - set(ev_o.get(technique, [])))
        dropped = sorted(set(ev_o.get(technique, [])) - set(ev_c.get(technique, [])))
        if added or dropped:
            diffs.append((technique, added, dropped))
    if diffs:
        for technique, added, dropped in diffs:
            lines.append(f'- `{technique}`：'
                         + (f'新增 {len(added)} 条证据（{added[0]} 等）' if added else '')
                         + ('；' if added and dropped else '')
                         + (f'减少 {len(dropped)} 条证据（{dropped[0]} 等）' if dropped else ''))
    else:
        lines.append('- 两版 evidence 集完全相同。')
    lines.append('')
    return '\n'.join(lines)


if __name__ == '__main__':
    if hasattr(sys.stdout, 'reconfigure'):  # Windows GBK 控制台中文乱码兜底
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    result = run_eval()
    for variant, entry in result['versions'].items():
        tm = entry['metrics']['technique_metrics']
        sm = entry['metrics']['stage_metrics']
        print(f'[{variant}] {entry["summary"]} | precision={tm["precision"]:.3f} '
              f'recall={tm["recall"]:.3f} | stage_recall={sm["stage_recall"]:.3f} '
              f'| decision={entry["decision"]["decision"]}')
    sys.exit(0)
