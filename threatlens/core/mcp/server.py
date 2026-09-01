from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

try:
    from mcp import FastMCP
except Exception:  # pragma: no cover - allow import even if mcp not installed
    FastMCP = None

from threatlens.core.analysis.run_demo import (
    ATTACK_PATH,
    ATOMIC_ROOT,
    SIGMA_ROOT,
    TELEMETRY_ROOT,
    PHASE_ORDER,
    ROOT,
)
from threatlens.core.analysis.sigma_matcher import build_rule_cache, match_all
from threatlens.core.data import load_attack_techniques, load_telemetry_events
from threatlens.core.analysis.chain_builder import build_chain
from threatlens.core.analysis.report_writer import build_report
from threatlens.core.evaluation.metrics import metrics_from_chain


def lens_analyze(telemetry_path: str, include_custom: bool = False) -> dict[str, Any]:
    """Analyze a telemetry JSONL and return AttackChain dict. Errors returned as {'error': '...'}"""
    p = Path(telemetry_path)
    if not p.exists():
        return {'error': f'file not found: {telemetry_path}'}

    try:
        attack_lib = load_attack_techniques(ATTACK_PATH)
        rule_cache = build_rule_cache(SIGMA_ROOT, include_custom=include_custom)
        events = load_telemetry_events(p)
        hits = match_all(events, rule_cache)
        all_pairs: list[tuple[dict, list]] = []
        for event in events:
            all_pairs.append((event, hits.get(event['event_uid'], [])))
        chain = build_chain(all_pairs, attack_lib, PHASE_ORDER)
        return chain
    except Exception as exc:
        return {'error': str(exc)}


def lens_report(chain_json: str, mock: bool = True) -> dict[str, Any]:
    """Generate Markdown report from chain JSON string. Returns {'report': str} or {'error':...} ."""
    try:
        chain = json.loads(chain_json)
    except Exception as exc:
        return {'error': f'invalid chain_json: {exc}'}
    try:
        report = build_report(chain, None, out_path=None, mock=mock)
        return {'report': report}
    except Exception as exc:
        return {'error': str(exc)}


def lens_gold_check(predictions_json: str) -> dict[str, Any]:
    """Compare predictions against ThreatLens gold and return simple metrics.

    Expects input like: '{"predictions": {"dataset.json": ["T1059.001", ...]}}'
    Aggregates predicted techniques across datasets and compares with GOLD_TECHNIQUES used by project.
    """
    try:
        data = json.loads(predictions_json)
    except Exception as exc:
        return {'error': f'invalid predictions_json: {exc}'}
    preds = data.get('predictions', {})
    if not isinstance(preds, dict):
        return {'error': 'predictions must be a dict mapping dataset->list'}
    predicted_set = set()
    for v in preds.values():
        if isinstance(v, list):
            predicted_set.update(v)
    # load project gold techniques from atomic (use run_demo GOLD_TECHNIQUES if present)
    try:
        from threatlens.core.analysis.run_demo import GOLD_TECHNIQUES
    except Exception:
        GOLD_TECHNIQUES = []
    attack_lib = load_attack_techniques(ATTACK_PATH)
    gold_chain = []
    try:
        from threatlens.core.data.load_atomic import load_atomic_chain
        gold_chain = load_atomic_chain(ATOMIC_ROOT, GOLD_TECHNIQUES, attack_lib)
    except Exception:
        gold_chain = []
    gold_stages = list(dict.fromkeys(t for tech in gold_chain for t in tech.get('tactics', []) if t in PHASE_ORDER))
    # craft minimal chain dict for metrics_from_chain
    chain = {
        'techniques': {t: {} for t in predicted_set},
        'chain': [{'tactic': s, 'technique': next(iter(predicted_set)) if predicted_set else '', 'evidence': []} for s in gold_stages] or [],
    }
    metrics = metrics_from_chain(chain, GOLD_TECHNIQUES, gold_stages)
    # return top-level numbers
    tech = metrics['technique_metrics']
    stage = metrics['stage_metrics']
    return {
        'precision': tech['precision'],
        'recall': tech['recall'],
        'stage_recall': stage['stage_recall'],
        'details': metrics,
    }


def _register_with_mcp():
    if FastMCP is None:
        print('warning: mcp package not installed; server will not register MCP tools')
        return None
    m = FastMCP('threatlens')
    m.register_function(lens_analyze, 'lens_analyze')
    m.register_function(lens_report, 'lens_report')
    m.register_function(lens_gold_check, 'lens_gold_check')
    return m


def main():
    m = _register_with_mcp()
    if m is None:
        print('mcp not available — server provides local CLI for testing')
        import argparse

        parser = argparse.ArgumentParser()
        parser.add_argument('--analyze', help='path to telemetry JSONL')
        parser.add_argument('--report', help='path to chain json file')
        parser.add_argument('--gold', help='path to predictions json file')
        args = parser.parse_args()
        if args.analyze:
            out = lens_analyze(args.analyze)
            print(json.dumps(out, ensure_ascii=False, indent=2))
        elif args.report:
            chain_json = Path(args.report).read_text(encoding='utf-8')
            print(json.dumps(lens_report(chain_json, mock=True), ensure_ascii=False))
        elif args.gold:
            preds = Path(args.gold).read_text(encoding='utf-8')
            print(json.dumps(lens_gold_check(preds), ensure_ascii=False))
        else:
            print('no action specified')
    else:
        print('starting MCP server (stdio)...')
        m.run()


if __name__ == '__main__':
    main()
