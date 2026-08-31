from __future__ import annotations

import json
from pathlib import Path
from typing import Any


# enterprise-attack.json 数据源含非标准战术名（stealth×212 / defense-impairment×56），
# 映射回 ATT&CK 标准战术，保证 P2 战术覆盖率统计与报告口径一致（2026-08-31 实测）。
TACTIC_ALIASES = {
    'stealth': 'defense-evasion',
    'defense-impairment': 'defense-evasion',
}


def load_attack_techniques(path: str | Path) -> dict[str, dict[str, Any]]:
    """Load ATT&CK STIX and expose a simple technique_id -> metadata lookup."""
    source = Path(path)
    with source.open('r', encoding='utf-8') as fh:
        bundle = json.load(fh)

    techniques: dict[str, dict[str, Any]] = {}
    for obj in bundle.get('objects', []):
        if obj.get('type') != 'attack-pattern':
            continue

        ext_refs = obj.get('external_references', []) or []
        technique_id = None
        for ref in ext_refs:
            ref_id = ref.get('external_id')
            if ref_id and ref_id.startswith('T'):
                technique_id = ref_id
                break

        if not technique_id:
            continue

        tactics = []
        for phase in obj.get('kill_chain_phases', []) or []:
            phase_name = phase.get('phase_name')
            if phase_name:
                tactics.append(TACTIC_ALIASES.get(phase_name, phase_name))

        techniques[technique_id] = {
            'id': technique_id,
            'name': obj.get('name', ''),
            'description': obj.get('description', ''),
            'tactics': tactics,
            'stix_id': obj.get('id', ''),
        }

    return techniques


if __name__ == '__main__':
    path = Path(__file__).resolve().parents[3] / 'edr' / 'data' / 'attack' / 'enterprise-attack.json'
    data = load_attack_techniques(path)
    print(f'loaded {len(data)} attack techniques')
    print(data['T1003.001'])
