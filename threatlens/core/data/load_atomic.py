"""金标 loader（02 §4.6）：从 Atomic Red Team 提取"已知技术列表"供 P2 eval 对照。

Atomic 的 `_src/atomics/Txxxx/<Txxxx>.yaml` 只含 attack_technique + display_name，
不含 tactics；tactics 从 ATT&CK 库（attack_lib）补全（可选参数，缺省为空）。
注意：Atomic 目录按技术组织（如 T1087.001），传入的 technique_ids 需与
目录实际存在的小粒度 ID 一致。
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

try:
    import yaml
except ModuleNotFoundError:  # pragma: no cover
    yaml = None


def load_atomic_chain(
    atomic_root: str | Path,
    technique_ids: list[str],
    attack_lib: dict[str, dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """提取指定技术列表的金标信息：{id, name, tactics}。"""
    if yaml is None:
        raise ModuleNotFoundError('PyYAML is required to parse Atomic files; install pyyaml.')

    root = Path(atomic_root)
    attack_lib = attack_lib or {}

    result: list[dict[str, Any]] = []
    for technique_id in technique_ids:
        yaml_path = root / technique_id / f'{technique_id}.yaml'
        if not yaml_path.exists():
            continue  # 目录不存在（如父级技术 T1087 只有子目录）→ 跳过
        with yaml_path.open('r', encoding='utf-8') as fh:
            data = yaml.safe_load(fh) or {}
        result.append({
            'id': data.get('attack_technique', technique_id),
            'name': data.get('display_name', ''),
            'tactics': attack_lib.get(technique_id, {}).get('tactics', []),
        })
    return result


if __name__ == '__main__':
    attack = None
    try:
        from .load_attack import load_attack_techniques

        attack = load_attack_techniques(
            Path(__file__).resolve().parents[3] / 'edr' / 'data' / 'attack' / 'enterprise-attack.json'
        )
    except ImportError:
        pass
    chain = load_atomic_chain(
        Path(__file__).resolve().parents[3] / 'edr' / 'data' / 'atomic' / '_src' / 'atomics',
        ['T1059.001', 'T1003.001', 'T1087.001', 'T1021.002'],
        attack,
    )
    for item in chain:
        print(item['id'], item['name'], item['tactics'])
