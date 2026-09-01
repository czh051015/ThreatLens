"""02 §9.5：4 阶段 demo 首跑 —— 4 数据集全流程 → 第一份 AttackChain JSON。

用法：python -m threatlens.core.analysis.run_demo
输出：outputs/attack_chain_demo.json（含 summary 与 4 阶段链）
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

from threatlens.core.analysis.chain_builder import build_chain
from threatlens.core.analysis.sigma_matcher import build_rule_cache, match_all
from threatlens.core.data import load_attack_techniques, load_telemetry_events
from threatlens.core.data.load_atomic import load_atomic_chain
from threatlens.core.analysis.report_writer import build_report

ROOT = Path(__file__).resolve().parents[3]

#: demo 链战术阶段顺序（02 §5.3 两层时间线的数据集间排序）
PHASE_ORDER = ['execution', 'credential-access', 'discovery', 'lateral-movement']

#: 4 数据集（ADR-001 §3.2）
DATASETS = [
    'empire_launcher_vbs_2020-09-04160940.json',
    'empire_mimikatz_logonpasswords_2020-08-07103224.json',
    'cmd_seatbelt_group_user_2020-11-0216391814.json',
    'covenant_copy_smb_CreateRequest_2020-09-22145302.json',
]

#: 金标技术列表（Atomic 目录粒度：T1087 只有 T1087.001 子目录）
GOLD_TECHNIQUES = ['T1059.001', 'T1003.001', 'T1087.001', 'T1021.002']

SIGMA_ROOT = ROOT / 'edr' / 'data' / 'sigma' / '_src' / 'rules' / 'windows'
TELEMETRY_ROOT = ROOT / 'edr' / 'data' / 'telemetry'
ATTACK_PATH = ROOT / 'edr' / 'data' / 'attack' / 'enterprise-attack.json'
ATOMIC_ROOT = ROOT / 'edr' / 'data' / 'atomic' / '_src' / 'atomics'


def run_demo(
    out_path: str | Path | None = None,
    *,
    include_custom: bool = True,
    write_output: bool = True,
) -> dict:
    """全流程：规则缓存 → 4 数据集匹配 → 链重建 → AttackChain dict。

    - `include_custom=False`：仅官方规则（03 §3.5 版本分离红线的"官方版"）；
    - `write_output=False`：不落盘（03 评测跑两版链时复用，避免覆盖 demo 产物）。
    """
    t_start = time.time()

    attack_lib = load_attack_techniques(ATTACK_PATH)
    t0 = time.time()
    rule_cache = build_rule_cache(SIGMA_ROOT, include_custom=include_custom)
    print(f'[demo] rule cache: {sum(len(v) for v in rule_cache.values())} entries in {time.time() - t0:.1f}s')

    all_pairs: list[tuple[dict, list]] = []
    for filename in DATASETS:
        events = load_telemetry_events(TELEMETRY_ROOT / filename)
        t0 = time.time()
        hits = match_all(events, rule_cache)
        print(f'[demo] {filename}: {len(events)} events, '
              f'{sum(1 for v in hits.values() if v)} with matches, {time.time() - t0:.1f}s')
        for event in events:
            all_pairs.append((event, hits.get(event['event_uid'], [])))

    chain = build_chain(all_pairs, attack_lib, PHASE_ORDER)
    chain['meta'] = {
        'datasets': DATASETS,
        'rule_count': sum(len(v) for v in rule_cache.values()),
        'rules_variant': 'official+custom' if include_custom else 'official',
        'elapsed_sec': round(time.time() - t_start, 1),
        'gold_techniques': GOLD_TECHNIQUES,
    }

    if write_output:
        out = Path(out_path) if out_path else ROOT / 'outputs' / 'attack_chain_demo.json'
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(chain, ensure_ascii=False, indent=2), encoding='utf-8')
        print(f'chain written to {out}')
        # 同步生成 Markdown 报告（开发阶段 mock）
        report_out = ROOT / 'outputs' / 'attack_chain_report.md'
        build_report(chain, {}, out_path=report_out, mock=True)
        print(f'report written to {report_out}')

    print('\n' + chain['summary'])
    return chain


def _print_chain(chain: dict) -> None:
    for entry in chain['chain']:
        name = chain['techniques'].get(entry['technique'], {}).get('name', '')
        print(f"  {entry['tactic']:<18} {entry['technique']:<12} {name}  "
              f"({len(entry['evidence'])} evidence, first {entry['first_seen']})")
        for uid in entry['evidence']:
            print(f'      - {uid}')


if __name__ == '__main__':
    if hasattr(sys.stdout, 'reconfigure'):  # Windows GBK 控制台中文乱码兜底
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    chain = run_demo()
    _print_chain(chain)
    sys.exit(0)
