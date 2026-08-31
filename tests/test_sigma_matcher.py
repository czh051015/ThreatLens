"""sigma_matcher 单测（02 §8 验收：sigma_matcher / event_uid）。"""

from pathlib import Path

import pytest

from threatlens.core.analysis.sigma_matcher import CUSTOM_RULES_ROOT, build_rule_cache, match_all, match_event
from threatlens.core.data import load_telemetry_events

ROOT = Path(__file__).resolve().parents[1]
SIGMA_ROOT = ROOT / 'edr' / 'data' / 'sigma' / '_src' / 'rules' / 'windows'
TELEMETRY = ROOT / 'edr' / 'data' / 'telemetry'

# ---------------------------------------------------------------------------
# 合成规则（走 build_rule_cache 全链路，不 mock）
# ---------------------------------------------------------------------------

BASE_RULE = {
    'title': 'synthetic',
    'tags': ['attack.execution', 'attack.t1059.001'],
    'logsource': {'category': 'process_creation', 'product': 'windows'},
    'detection': {'selection': {'EventID': 1}, 'condition': 'selection'},
}


def _event(**overrides) -> dict:
    raw = {
        'EventID': 1,
        'Image': r'C:\Windows\System32\powershell.exe',
        'CommandLine': '"powershell.exe" -enc ABC',
    }
    raw.update(overrides)
    return {
        'event_uid': 'synthetic.json:1',
        'event_id': raw.get('EventID'),
        'timestamp': '2026-01-01T00:00:00Z',
        'raw': raw,
    }


def _cache(*rules) -> dict:
    # 合成规则隔离：include_custom=False，避免混入真实自定义根（sigma_custom_rules/）
    return build_rule_cache(None, include_custom=False, extra_rule_dicts=list(rules))


# -- 条件类型 ---------------------------------------------------------------

def test_eq_condition_int_and_string_forms():
    cache = _cache(BASE_RULE)
    assert match_event(_event(EventID=1), cache)
    assert match_event(_event(EventID='1'), cache)  # 字符串形式的整型等值
    assert not match_event(_event(EventID=10), cache)


def test_contains_and_endswith():
    rule = {
        **BASE_RULE,
        'detection': {
            'selection': {
                'EventID': 1,
                'CommandLine|contains': ['-enc'],
                'Image|endswith': '\\powershell.exe',
            },
            'condition': 'selection',
        },
    }
    cache = _cache(rule)
    assert match_event(_event(), cache)
    assert not match_event(_event(CommandLine='whoami /user'), cache)
    assert not match_event(_event(Image=r'C:\Tools\p.exe'), cache)


def test_contains_case_insensitive():
    rule = {**BASE_RULE, 'detection': {'selection': {'CommandLine|contains': '-ENC'}, 'condition': 'selection'}}
    cache = _cache(rule)
    assert match_event(_event(CommandLine='-enc xyz'), cache)


def test_contains_all_requires_every_substring():
    rule = {
        **BASE_RULE,
        'detection': {
            'selection': {'CommandLine|contains|all': ['-enc', 'ABC']},
            'condition': 'selection',
        },
    }
    cache = _cache(rule)
    assert match_event(_event(), cache)
    assert not match_event(_event(CommandLine='-enc DEF'), cache)


# -- 空白是有效字符（回归：proc_creation_win_susp_double_extension 的 '      .exe'）--

def test_whitespace_is_significant_in_patterns():
    rule = {
        **BASE_RULE,
        'detection': {'selection': {'Image|endswith': '      .exe'}, 'condition': 'selection'},
    }
    cache = _cache(rule)
    # 6 空格 + .exe 不能误命中 whoami.exe（修复前 .strip() 会剥成 '.exe' 导致误报）
    assert not match_event(_event(Image=r'C:\Windows\System32\whoami.exe'), cache)
    assert match_event(_event(Image=r'C:\evil\report      .exe'), cache)


def test_trailing_space_pattern_preserved():
    rule = {
        **BASE_RULE,
        'detection': {'selection': {'CommandLine|contains': '-enc '}, 'condition': 'selection'},
    }
    cache = _cache(rule)
    assert match_event(_event(CommandLine='-enc ABC'), cache)
    assert not match_event(_event(CommandLine='-enco'), cache)


# -- selection 结构与 condition 语法 -----------------------------------------

def test_selection_list_is_or():
    rule = {
        **BASE_RULE,
        'detection': {
            'selection': [
                {'Image|endswith': '\\powershell.exe'},
                {'Image|endswith': '\\cmd.exe'},
            ],
            'condition': 'selection',
        },
    }
    cache = _cache(rule)
    assert match_event(_event(Image=r'C:\Windows\System32\cmd.exe'), cache)


def test_condition_or():
    rule = {
        **BASE_RULE,
        'detection': {
            'selection_a': {'Image|endswith': '\\powershell.exe'},
            'selection_b': {'CommandLine|contains': 'whoami'},
            'condition': 'selection_a or selection_b',
        },
    }
    cache = _cache(rule)
    assert match_event(_event(), cache)  # a 命中
    assert match_event(_event(Image=r'C:\x\cmd.exe', CommandLine='whoami /all'), cache)  # b 命中
    assert not match_event(_event(Image=r'C:\x\cmd.exe', CommandLine='dir'), cache)


def test_condition_1_of_wildcard():
    rule = {
        **BASE_RULE,
        'detection': {
            'selection_1': {'Image|endswith': '\\powershell.exe'},
            'selection_2': {'CommandLine|contains': 'whoami'},
            'condition': '1 of selection_*',
        },
    }
    cache = _cache(rule)
    assert match_event(_event(Image=r'C:\Windows\System32\powershell.exe', CommandLine='dir'), cache)
    assert not match_event(_event(Image=r'C:\x\cmd.exe', CommandLine='dir'), cache)


def test_condition_all_of_wildcard_and_not_filters():
    rule = {
        **BASE_RULE,
        'detection': {
            'selection_a': {'CommandLine|contains': '-enc'},
            'selection_b': {'Image|endswith': '\\powershell.exe'},
            'filter_main_noise': {'CommandLine|contains': 'bypass'},
            'condition': 'all of selection_* and not 1 of filter_main_*',
        },
    }
    cache = _cache(rule)
    assert match_event(_event(), cache)
    assert not match_event(_event(CommandLine='-enc ABC bypass'), cache)


def test_condition_not_1_of_with_no_matching_filter_passes():
    rule = {
        **BASE_RULE,
        'detection': {
            'selection': {'CommandLine|contains': '-enc'},
            'filter_optional_none': {'Image|contains': 'does-not-exist'},
            'condition': 'selection and not 1 of filter_optional_*',
        },
    }
    cache = _cache(rule)
    assert match_event(_event(), cache)


# -- 不支持的语法整体跳过 ----------------------------------------------------

def test_unsupported_re_modifier_rule_skipped():
    rule = {
        **BASE_RULE,
        'detection': {'selection': {'CommandLine|re': r'^powershell.*-enc'}, 'condition': 'selection'},
    }
    cache = _cache(rule)
    assert match_event(_event(), cache) == []


def test_unsupported_condition_syntax_rule_skipped():
    rule = {**BASE_RULE, 'detection': {'selection': {'EventID': 1}, 'condition': 'selection and 2 of selection_*'}}
    cache = _cache(rule)
    assert match_event(_event(), cache) == []


# -- 缓存按 EventID 归类 ------------------------------------------------------

def test_cache_keyed_by_event_id():
    rule = {**BASE_RULE, 'detection': {'selection': {'EventID': 1}, 'condition': 'selection'}}
    cache = _cache(rule)
    assert len(cache.get(1, [])) == 1
    assert cache.get(10, []) == []


def test_catchall_bucket_for_unkeyable_rules():
    rule = {
        **BASE_RULE,
        'logsource': {'product': 'windows'},  # 无 category → 无法映射 EventID
        'detection': {'selection': {'CommandLine|contains': '-enc'}, 'condition': 'selection'},
    }
    cache = _cache(rule)
    assert match_event(_event(), cache)  # catchall 桶仍会比对
    assert match_event(_event(EventID=10), cache)  # 与事件类型无关


# -- 自定义根（02 §5.6 / ADR-003 决策 2：双根合并） ---------------------------

def test_custom_rules_root_loaded_by_default():
    """include_custom 默认 True：自定义根 YAML 合并进缓存（EventID 10 桶）。"""
    custom = build_rule_cache(None)
    rules = [r for r in custom.get(10, []) if CUSTOM_RULES_ROOT in Path(r.path).parents]
    assert len(rules) == 1
    assert rules[0].technique_ids == ['T1003.001']


def test_include_custom_false_excludes_custom_root():
    """版本分离（03 §3.5）：include_custom=False → 不含自定义根规则。"""
    official = build_rule_cache(None, include_custom=False)
    assert not any(CUSTOM_RULES_ROOT in Path(r.path).parents for bucket in official.values() for r in bucket)


def test_custom_rule_zero_false_positives():
    """ADR-003 决策 2 实证：双字段自定义规则在 4 数据集唯一命中 line 2451。"""
    custom = build_rule_cache(None)
    total = 0
    for filename in ['empire_launcher_vbs_2020-09-04160940.json',
                     'empire_mimikatz_logonpasswords_2020-08-07103224.json',
                     'cmd_seatbelt_group_user_2020-11-0216391814.json',
                     'covenant_copy_smb_CreateRequest_2020-09-22145302.json']:
        events = load_telemetry_events(TELEMETRY / filename)
        hits = [uid for uid, ms in match_all(events, custom).items() if ms]
        total += len(hits)
        for uid in hits:
            assert uid == 'empire_mimikatz_logonpasswords_2020-08-07103224.json:2451'
    assert total == 1


# -- 集成：02 §8 验收锚点（真实规则 + 真实数据） ------------------------------

@pytest.fixture(scope='module')
def real_cache():
    return build_rule_cache(SIGMA_ROOT)


@pytest.mark.parametrize(
    ('filename', 'lineno', 'want'),
    [
        ('empire_launcher_vbs_2020-09-04160940.json', 259, 'T1059.001'),
        ('empire_mimikatz_logonpasswords_2020-08-07103224.json', 2451, 'T1003.001'),
        ('cmd_seatbelt_group_user_2020-11-0216391814.json', 148, 'T1087'),
        ('covenant_copy_smb_CreateRequest_2020-09-22145302.json', 62, 'T1021.002'),
    ],
)
def test_acceptance_anchor_hits(real_cache, filename, lineno, want):
    """02 §8 验收：4 个锚点事件各自命中目标技术。"""
    events = load_telemetry_events(TELEMETRY / filename)
    uid = f'{filename}:{lineno}'
    got = {m.technique_id for m in match_all(events, real_cache).get(uid, [])}
    assert want in got, f'{uid} 未命中 {want}，实际 {got}'


def test_official_only_version_misses_custom_anchor():
    """03 §3.5 版本分离：官方版丢 T1003.001 锚点，其余 3 锚点不丢。"""
    official = build_rule_cache(SIGMA_ROOT, include_custom=False)
    cases = [
        ('empire_launcher_vbs_2020-09-04160940.json', 259, 'T1059.001', True),
        ('empire_mimikatz_logonpasswords_2020-08-07103224.json', 2451, 'T1003.001', False),  # 自定义规则盲区
        ('cmd_seatbelt_group_user_2020-11-0216391814.json', 148, 'T1087', True),
        ('covenant_copy_smb_CreateRequest_2020-09-22145302.json', 62, 'T1021.002', True),
    ]
    for filename, lineno, want, should_hit in cases:
        events = load_telemetry_events(TELEMETRY / filename)
        uid = f'{filename}:{lineno}'
        got = {m.technique_id for m in match_all(events, official).get(uid, [])}
        assert (want in got) == should_hit, f'{uid}: {want} in {got} 但期望 should_hit={should_hit}'


def test_event_uid_unique_per_file():
    """02 §8 验收：event_uid 同文件内不重复。"""
    events = load_telemetry_events(TELEMETRY / 'empire_mimikatz_logonpasswords_2020-08-07103224.json')
    uids = [e['event_uid'] for e in events]
    assert all(e['event_uid'] for e in events)
    assert len(uids) == len(set(uids))
