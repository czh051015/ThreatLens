"""Sigma-lite 正向匹配引擎（02 §4.4）。

职责：事件 → 候选技术 + 证据三元组（{technique_id ← rule_path ← event_uid}）。

支持范围（02 §2 的 MVP 子集 + 经确认的 Sigma-lite 扩展）：
- 字段条件：等值（`field: value`）、`|contains`（子串，含 `|contains|all`）、`|endswith`（后缀）；
- selection 结构：dict = AND，list = OR；
- condition 子集：`selection` / `1 of sel*` / `all of sel*` / `None of sel*` /
  `A or B` / `A and not 1 of filter*`（含逗号列表与 `*` 通配前缀）。
- 不支持的语法（`|re`、`|startswith`、base64、相关性、plain keywords 等）在
  build_rule_cache 时**整体跳过该规则**，保证主干 100% 确定性、无半匹配。

性能：build_rule_cache 按 EventID 建反向缓存（02 §5.2），运行期按事件的
event_id 取候选规则子集，再逐条正向比对。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import yaml
except ModuleNotFoundError:  # pragma: no cover - same fallback as load_sigma
    yaml = None

#: 字段修饰符 → 求值函数名；None 表示等值
_SUPPORTED_MODIFIERS = frozenset({None, 'contains', 'contains|all', 'endswith'})

#: logsource.category（product=windows）→ Sysmon / Security 事件号映射，
#: 用于无显式 EventID 条件的规则做缓存 key。Security 服务用 4688（进程创建）。
_CATEGORY_EVENT_IDS: dict[str, list[int]] = {
    'process_creation': [1, 4688],
    'process_termination': [5],
    'driver_load': [6],
    'image_load': [7],
    'create_remote_thread': [8],
    'raw_access_thread': [9],
    'process_access': [10],
    'file_creation': [11],
    'registry_add': [12],
    'registry_set': [13],
    'registry_delete': [12, 13, 14],
    'file_delete': [23],
    'file_change': [2],
    'network_connection': [3],
    'dns_query': [22],
    'pipe_created': [17],
    'pipe_connected': [18],
    'wmi_event': [19, 20, 21],
    'clipboard_capture': [24],
    'process_tampering': [25],
    'file_delete_detected': [26],
    'security_auditing': [5152, 5154, 5156, 5157, 5158, 5140, 5142, 5145, 4663, 4656],
}

_CATCHALL = '__catchall__'  # 无法按 EventID 归类的规则放在此桶，逐事件比对

#: 自定义规则根（02 §5.6 / ADR-003 决策 2）：matcher 加载时合并官方根 + 自定义根
CUSTOM_RULES_ROOT = Path(__file__).resolve().parent / 'sigma_custom_rules'


def _extract_technique_ids(rule: dict[str, Any]) -> list[str]:
    """从 tags 提取 attack.txxxx 技术 ID（与 load_sigma 口径一致）。"""
    ids: list[str] = []
    for tag in rule.get('tags') or []:
        if not isinstance(tag, str):
            continue
        tag = tag.strip()
        if tag.startswith('attack.'):
            m = re.search(r't(\d{4}(?:\.\d+)?)', tag, re.I)
            if m:
                ids.append(f'T{m.group(1)}')
    return ids


def _to_str(value: Any) -> str:
    # 注意：不做 strip —— Sigma 模式里的首尾空白是有效字符
    # （如 proc_creation_win_susp_double_extension 的 '      .exe' 空格缩进反混淆）
    if value is None:
        return ''
    return str(value).lower()


def _field_condition_matches(event: dict[str, Any], field: str, modifier: str | None, value: Any) -> bool:
    """单字段条件求值。event 指 raw 事件字典（原始字段名）。"""
    raw = event.get(field)
    if raw is None:
        return False

    if modifier is None:  # 等值：字符串大小写不敏感；数字按字符串比（EventID 10 == '10'）
        if isinstance(value, list):
            return any(_field_condition_matches(event, field, None, v) for v in value)
        return _to_str(raw) == _to_str(value)

    if modifier == 'contains':
        haystack = _to_str(raw)
        values = value if isinstance(value, list) else [value]
        return any(_to_str(v) in haystack for v in values)

    if modifier == 'contains|all':
        haystack = _to_str(raw)
        values = value if isinstance(value, list) else [value]
        return all(_to_str(v) in haystack for v in values)

    if modifier == 'endswith':
        haystack = _to_str(raw)
        values = value if isinstance(value, list) else [value]
        return any(haystack.endswith(_to_str(v)) for v in values)

    return False  # 其他修饰符在解析期已跳过，不会到这里


def _selection_matches(event: dict[str, Any], selection: Any) -> bool:
    """selection 求值：dict = AND；list = OR（各元素为候选 dict）。"""
    if isinstance(selection, list):
        if not selection:
            return False
        return any(_selection_matches(event, item) for item in selection if isinstance(item, dict))
    if not isinstance(selection, dict):
        return False
    for raw_field, value in selection.items():
        if '|' in raw_field:
            field, modifier = raw_field.split('|', 1)
        else:
            field, modifier = raw_field, None
        if modifier not in _SUPPORTED_MODIFIERS:
            return False  # 解析期已拦截，防御性兜底
        if not _field_condition_matches(event, field, modifier, value):
            return False
    return True


@dataclass
class _Rule:
    """一条已解析、可求值的规则（Sigma-lite 子集内）。"""

    path: str
    title: str
    technique_ids: list[str]
    event_ids: list[int]
    selections: dict[str, Any]
    condition_tokens: list[Any]  # RPN 表达式（见 _compile_condition）


# ---------------------------------------------------------------------------
# condition 表达式解析（极简子集 → RPN 求值）
#   grammar: expr := or_expr
#            or_expr := and_expr ('or' and_expr)*
#            and_expr := unary ('and' unary)*
#            unary := 'not' unary | '(' expr ')' | atom
#            atom := NAME | COUNT 'of' (NAME (',' NAME)* | NAME '*')
# ---------------------------------------------------------------------------

_TOKEN_RE = re.compile(r"\(|\)|[A-Za-z_][A-Za-z0-9_]*\*?|\d+|,")
_NAME_RE = re.compile(r'[A-Za-z_][A-Za-z0-9_]*')

_OPERATOR_PRECEDENCE = {'or': 1, 'and': 2}


def _tokenize_condition(expr: str) -> list[str] | None:
    tokens = [t for t in _TOKEN_RE.findall(expr)]
    # 校验：还原后应包含原表达式的全部有效字符
    leftover = re.sub(r'\s+', '', expr)
    rebuilt = ''.join(tokens)
    return tokens if rebuilt == leftover else None


def _compile_condition(tokens: list[str]) -> list[Any] | None:
    """把 token 流转成 RPN（逆波兰）。语法不支持时返回 None（该规则跳过）。"""
    out: list[Any] = []
    stack: list[str] = []

    def push_atom(name: str) -> bool:
        if not _NAME_RE.fullmatch(name):
            return False  # 裸选择名不允许通配符
        out.append(('sel', name))
        return True

    i = 0
    n = len(tokens)
    while i < n:
        tok = tokens[i]
        if tok == '(':
            stack.append(tok)
        elif tok == ')':
            while stack and stack[-1] != '(':
                out.append(('op', stack.pop()))
            if not stack:
                return None
            stack.pop()
        elif tok in _OPERATOR_PRECEDENCE:
            while stack and stack[-1] in _OPERATOR_PRECEDENCE and _OPERATOR_PRECEDENCE[stack[-1]] >= _OPERATOR_PRECEDENCE[tok]:
                out.append(('op', stack.pop()))
            stack.append(tok)
        elif tok == 'not':
            stack.append('not')
        elif tok in ('1', 'all', 'none'):
            if i + 1 >= n or tokens[i + 1] != 'of':
                return None
            mode = {'1': 'any', 'all': 'all', 'none': 'none'}[tok]
            i += 2
            names: list[str] = []
            while i < n and (_NAME_RE.match(tokens[i]) or tokens[i] == ','):
                if tokens[i] == ',':
                    i += 1
                    continue
                if tokens[i] in _OPERATOR_PRECEDENCE or tokens[i] in ('not', '1', 'all', 'none', 'of'):
                    break  # 运算符/计数关键字不是选择名
                names.append(tokens[i])
                i += 1
            if not names:
                return None
            out.append(('count', mode, tuple(names)))
            continue
        elif _NAME_RE.fullmatch(tok):
            if not push_atom(tok):
                return None
        else:
            return None
        i += 1

    while stack:
        top = stack.pop()
        if top == '(':
            return None
        out.append(('op', top))
    return out


def _resolve_selection_names(pattern: str, selections: dict[str, Any]) -> list[str]:
    """把选择名模式（含尾部 `*` 通配）展开为实际存在的 selection 名。"""
    if pattern.endswith('*'):
        prefix = pattern[:-1]
        return [name for name in selections if name.startswith(prefix)]
    return [pattern] if pattern in selections else []


def _eval_condition(tokens: list[Any], selections: dict[str, Any], event: dict[str, Any]) -> bool:
    """RPN 求值。选择名不存在：`any`/原子引用 = False；`all`/`none` 空集 = True。"""
    stack: list[bool] = []

    def sel_value(name: str) -> bool:
        if name in selections:
            return _selection_matches(event, selections[name])
        return False

    for item in tokens:
        kind = item[0]
        if kind == 'sel':
            stack.append(sel_value(item[1]))
        elif kind == 'count':
            _, mode, patterns = item
            names: list[str] = []
            for pattern in patterns:
                names.extend(_resolve_selection_names(pattern, selections))
            if mode == 'any':
                stack.append(any(sel_value(name) for name in names))
            elif mode == 'all':
                stack.append(all(sel_value(name) for name in names))
            else:  # none
                stack.append(not any(sel_value(name) for name in names))
        else:  # op / not
            op = item[1]
            if op == 'not':
                stack.append(not stack.pop())
            elif op == 'and':
                rhs, lhs = stack.pop(), stack.pop()
                stack.append(lhs and rhs)
            elif op == 'or':
                rhs, lhs = stack.pop(), stack.pop()
                stack.append(lhs or rhs)
    return bool(stack[-1]) if stack else False


# ---------------------------------------------------------------------------
# 规则解析
# ---------------------------------------------------------------------------

def _collect_explicit_event_ids(selections: dict[str, Any]) -> list[int]:
    """扫描所有 selection 里的 EventID 等值条件（含 OR-list 分支）。"""
    ids: list[int] = []

    def visit(node: Any) -> None:
        if isinstance(node, list):
            for item in node:
                visit(item)
        elif isinstance(node, dict):
            for field, value in node.items():
                base = field.split('|', 1)[0]
                if base == 'EventID' and ('|' not in field) and isinstance(value, (int, str, list)):
                    values = value if isinstance(value, list) else [value]
                    for v in values:
                        if isinstance(v, bool):
                            continue
                        try:
                            ids.append(int(v))
                        except (TypeError, ValueError):
                            continue

    for sel in selections.values():
        visit(sel)
    return ids


def _parse_rule(path: str | Path, data: dict[str, Any]) -> _Rule | None:
    """解析一条规则；任何不支持的元素都返回 None（整条跳过，保持确定性）。"""
    detection = data.get('detection')
    if not isinstance(detection, dict):
        return None
    condition_expr = detection.get('condition')
    if not isinstance(condition_expr, str):
        return None

    technique_ids = _extract_technique_ids(data)
    if not technique_ids:
        return None

    selections: dict[str, Any] = {}
    for name, sel in detection.items():
        if name == 'condition':
            continue
        if not isinstance(sel, (dict, list)):
            return None  # plain keywords 等不支持的结构
        if isinstance(sel, dict):
            for raw_field in sel:
                modifier = raw_field.split('|', 1)[1] if '|' in raw_field else None
                if modifier not in _SUPPORTED_MODIFIERS:
                    return None
        elif isinstance(sel, list):
            for alt in sel:
                if not isinstance(alt, dict):
                    return None
                for raw_field in alt:
                    modifier = raw_field.split('|', 1)[1] if '|' in raw_field else None
                    if modifier not in _SUPPORTED_MODIFIERS:
                        return None
        selections[name] = sel

    tokens = _tokenize_condition(condition_expr)
    if tokens is None:
        return None
    rpn = _compile_condition(tokens)
    if rpn is None:
        return None

    event_ids = _collect_explicit_event_ids(selections)
    if not event_ids:
        logsource = data.get('logsource') or {}
        category = logsource.get('category')
        product = logsource.get('product')
        if product == 'windows' and category in _CATEGORY_EVENT_IDS:
            event_ids = _CATEGORY_EVENT_IDS[category]
        elif category == 'process_creation' and logsource.get('service') == 'security':
            event_ids = [4688]
        else:
            event_ids = []  # 无法归类 → catchall 桶

    return _Rule(
        path=str(path),
        title=str(data.get('title', '')),
        technique_ids=technique_ids,
        event_ids=event_ids,
        selections=selections,
        condition_tokens=rpn,
    )


# ---------------------------------------------------------------------------
# 对外接口（02 §4.4 签名）
# ---------------------------------------------------------------------------

def build_rule_cache(
    rules_root: str | Path | None,
    include_custom: bool = True,
    extra_rule_dicts: list[dict[str, Any]] | None = None,
) -> dict[int | str, list[_Rule]]:
    """预解析 Sigma 规则 → EventID → 规则子集缓存。

    - `rules_root`：官方 sigma 规则根目录（如 .../rules/windows）；
    - `include_custom=True`：合并自定义根 `sigma_custom_rules/`（02 §5.6 双根合并）；
      `False` → 仅官方规则（03 §3.5 版本分离红线的"官方版"）。
    - `extra_rule_dicts`：附加自写规则（已解析 dict），测试用合成规则走这里。
    - 返回 dict 的 key 为 int（EventID）或 `__catchall__`（不限定事件类型）。
    """
    if yaml is None:
        raise ModuleNotFoundError('PyYAML is required to parse Sigma rules; install pyyaml.')

    cache: dict[int | str, list[_Rule]] = {}

    sources: list[tuple[str, dict[str, Any]]] = []
    roots: list[Path] = []
    if rules_root is not None:
        roots.append(Path(rules_root))
    if include_custom and CUSTOM_RULES_ROOT.is_dir():
        roots.append(CUSTOM_RULES_ROOT)
    for root in roots:
        for path in sorted(root.rglob('*.yml')):
            with path.open('r', encoding='utf-8') as fh:
                data = yaml.safe_load(fh) or {}
            sources.append((str(path), data))
    for idx, data in enumerate(extra_rule_dicts or []):
        sources.append((f'<extra:{idx}>', data))

    for path, data in sources:
        rule = _parse_rule(path, data)
        if rule is None:
            continue
        keys = rule.event_ids if rule.event_ids else [_CATCHALL]
        for key in keys:
            cache.setdefault(key, []).append(rule)

    return cache


def match_event(event: dict[str, Any], rule_cache: dict[int | str, list[_Rule]]) -> list[MatchResult]:
    """单事件匹配：按 event_id 取候选规则子集（含 catchall 桶），逐条正向比对。"""
    event_id = event.get('event_id')
    candidates: list[_Rule] = []
    try:
        candidates = list(rule_cache.get(int(event_id), []))  # 兼容字符串形式的 event_id
    except (TypeError, ValueError):
        pass
    candidates.extend(rule_cache.get(_CATCHALL, []))

    results: list[MatchResult] = []
    for rule in candidates:
        if not _eval_condition(rule.condition_tokens, rule.selections, event.get('raw', {})):
            continue
        matched = _collect_matched_fields(rule.selections, event.get('raw', {}))
        for technique_id in rule.technique_ids:
            results.append(MatchResult(
                event_uid=event.get('event_uid', ''),
                rule_path=rule.path,
                technique_id=technique_id,
                matched=matched,
            ))
    return results


def _collect_matched_fields(selections: dict[str, Any], raw: dict[str, Any]) -> dict[str, Any]:
    """提取命中条件里实际命中的字段→值（证据三元组用，02 §6.2）。"""
    matched: dict[str, Any] = {}
    for sel in selections.values():
        nodes = sel if isinstance(sel, list) else [sel]
        for node in nodes:
            if not isinstance(node, dict):
                continue
            for raw_field, value in node.items():
                modifier = raw_field.split('|', 1)[1] if '|' in raw_field else None
                if modifier not in _SUPPORTED_MODIFIERS:
                    continue
                if _field_condition_matches(raw, raw_field.split('|', 1)[0], modifier, value):
                    matched.setdefault(raw_field, value)
    return matched


def match_all(events: list[dict[str, Any]], rule_cache: dict[int | str, list[_Rule]]) -> dict[str, list[MatchResult]]:
    """批量匹配 → {event_uid: [MatchResult, ...]}。"""
    return {event.get('event_uid', ''): match_event(event, rule_cache) for event in events}


# ---------------------------------------------------------------------------
# 数据类（02 §6.2）
# ---------------------------------------------------------------------------

@dataclass
class MatchResult:
    """证据三元组：事件 ↔ 规则 ↔ 技术。"""

    event_uid: str
    rule_path: str
    technique_id: str
    matched: dict[str, Any] = field(default_factory=dict)
