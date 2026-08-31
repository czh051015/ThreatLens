from __future__ import annotations

import re
from pathlib import Path
from typing import Any

try:
    import yaml
except ModuleNotFoundError:  # pragma: no cover - handled in runtime env when tests install dependencies
    yaml = None


def _iter_sigma_rules(root: str | Path):
    root_path = Path(root)
    for path in sorted(root_path.rglob('*.yml')):
        yield path


def _extract_technique_ids(rule: dict[str, Any]) -> list[str]:
    if not isinstance(rule, dict):
        return []
    tags = rule.get('tags') or []
    tech_ids: list[str] = []
    for tag in tags:
        if not isinstance(tag, str):
            continue
        tag = tag.strip()
        if tag.startswith('attack.'):
            match = re.search(r't(\d{4}(?:\.\d+)?)', tag, re.I)
            if match:
                tech_ids.append(f'T{match.group(1)}')
    return tech_ids


def load_sigma_technique_index(root: str | Path) -> dict[str, list[str]]:
    """Index Sigma rules by ATT&CK technique IDs extracted from their tags."""
    if yaml is None:
        raise ModuleNotFoundError('PyYAML is required to parse Sigma rules; install pyyaml.')

    index: dict[str, list[str]] = {}
    for path in _iter_sigma_rules(root):
        with path.open('r', encoding='utf-8') as fh:
            rule = yaml.safe_load(fh) or {}
        for technique_id in _extract_technique_ids(rule):
            index.setdefault(technique_id, []).append(str(path))
    return index


if __name__ == '__main__':
    mapping = load_sigma_technique_index(Path(__file__).resolve().parents[3] / 'edr' / 'data' / 'sigma' / '_src' / 'rules' / 'windows')
    print(f'loaded {len(mapping)} technique keys')
    print(mapping.get('T1003.001', [])[:3])
