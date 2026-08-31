"""04 §8 验收：llm_review 单测（mock 三分支 + JSON 解析健壮性 + 审计日志）。

不依赖外网：真实调用路径用 monkeypatch 替身验证请求形状（model/temperature/鉴权头），
网络失败路径验证 unknown 兜底（不误删）。
"""

import hashlib
import json

import pytest

from threatlens.core.evaluation.llm_review import (
    DEEPSEEK_BASE_URL,
    DEEPSEEK_MODEL,
    VALID_VERDICTS,
    ReviewDecision,
    ReviewItem,
    _call_deepseek,
    build_context,
    llm_review,
    mock_verdict,
    parse_verdict,
)


def _item(tid: str = 'T1059.001', uid: str = 'e1', score: float = 2.0,
          fields: dict | None = None) -> ReviewItem:
    return ReviewItem(
        technique_id=tid,
        event_uid=uid,
        score=score,
        rule_paths=['C:\\rules\\sigma\\proc_creation_win_mimikatz.yml'],
        event_fields=fields if fields is not None else {
            'event_uid': uid,
            'event_id': '1',
            'process_name': 'cmd.exe',
            'command_line': 'whoami',
            'parent_process': 'C:\\Windows\\explorer.exe',
        },
    )


def _find_uid_for(verdict: str) -> str:
    """找到使 mock_verdict 落到指定分支的事件 ID（md5 确定性，跨进程可复现）。"""
    for i in range(500):
        uid = f'u{i}'
        if mock_verdict(_item(uid=uid)).verdict == verdict:
            return uid
    pytest.fail(f'500 个候选内未找到 {verdict} 分支的事件 ID')


# -- §8 验收：mock 三分支 ------------------------------------------------------

def test_mock_verdict_covers_three_branches():
    seen = {mock_verdict(_item(uid=_find_uid_for(v))).verdict for v in VALID_VERDICTS}
    assert seen == set(VALID_VERDICTS)


def test_mock_verdict_deterministic_and_cross_process():
    uid = _find_uid_for('benign')
    d1 = mock_verdict(_item(uid=uid))
    d2 = mock_verdict(_item(uid=uid))
    assert d1.verdict == d2.verdict == 'benign'
    assert d1.reason == d2.reason  # 同输入 → 同输出（可复现验收）


def test_llm_review_mock_mode_ignores_api_key():
    d = llm_review(_item(), api_key='sk-fake', mock=True)
    assert d.source == 'mock'
    assert d.verdict in VALID_VERDICTS
    assert d.reason  # 每条判定都带 reason（可解释性落地）


# -- §8 验收：JSON 解析健壮性 ---------------------------------------------------

def test_parse_verdict_fenced_json():
    d = parse_verdict('```json\n{"verdict": "attack", "reason": "载荷特征明显", "confidence": 0.9}\n```')
    assert d.verdict == 'attack'
    assert d.reason == '载荷特征明显'
    assert d.confidence == pytest.approx(0.9)


def test_parse_verdict_plain_json():
    d = parse_verdict('{"verdict": "benign", "reason": "常规运维", "confidence": 0.7}')
    assert d.verdict == 'benign' and d.confidence == pytest.approx(0.7)


def test_parse_verdict_invalid_json_falls_back_unknown():
    d = parse_verdict('这根本不是 JSON，模型在胡言乱语')
    assert d.verdict == 'unknown' and d.reason == '' and d.confidence == 0.0
    assert d.source == 'llm'  # 解析成功路径的标记；unknown 由兜底语义保证不误删


def test_parse_verdict_invalid_verdict_value():
    d = parse_verdict('{"verdict": "maybe", "reason": "r", "confidence": 0.5}')
    assert d.verdict == 'unknown'  # 非法值 → unknown 而非执行错误
    assert d.reason == 'r' and d.confidence == pytest.approx(0.5)  # 其余字段照常


def test_parse_verdict_confidence_clamped():
    assert parse_verdict('{"verdict": "attack", "confidence": 1.7}').confidence == 1.0
    assert parse_verdict('{"verdict": "attack", "confidence": -0.3}').confidence == 0.0
    assert parse_verdict('{"verdict": "attack", "confidence": "高"}').confidence == 0.0


def test_parse_verdict_reason_truncated_to_200():
    d = parse_verdict('{"verdict": "attack", "reason": "' + 'x' * 300 + '"}')
    assert len(d.reason) == 200


# -- §5 上下文组装 ---------------------------------------------------------------

def test_build_context_filters_to_contract_fields():
    item = _item(fields={'event_uid': 'e1', 'process_name': 'cmd.exe',
                         'command_line': 'whoami', 'NotInContract': 'drop-me'})
    ctx = build_context(item)
    assert set(ctx['event'].keys()) == {'event_uid', 'process_name', 'command_line'}
    assert ctx['technique_name'] == ''  # 未传 attack_lib
    assert ctx['rule_names'] == ['proc_creation_win_mimikatz.yml']
    assert ctx['score'] == 2.0


def test_build_context_technique_name_from_attack_lib():
    item = _item(tid='T1059.001')
    ctx = build_context(item, attack_lib={'T1059.001': {'name': 'Command and Scripting Interpreter'}})
    assert ctx['technique_name'] == 'Command and Scripting Interpreter'


# -- §5 真实调用形状（无外网，monkeypatch 替身） ---------------------------------

def test_call_deepseek_request_shape_and_parse(monkeypatch):
    import urllib.request

    captured = {}

    class FakeResp:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def read(self):
            return json.dumps({
                'choices': [{'message': {'content': '{"verdict":"benign","reason":"r","confidence":0.8}'}}],
            }).encode('utf-8')

    def fake_urlopen(request, timeout=None):
        captured['url'] = request.full_url
        captured['headers'] = request.headers
        captured['payload'] = json.loads(request.data)
        return FakeResp()

    monkeypatch.setattr(urllib.request, 'urlopen', fake_urlopen)
    d = _call_deepseek({'technique_id': 'T1059.001'}, api_key='sk-test', timeout=5)

    assert captured['url'] == f'{DEEPSEEK_BASE_URL}/chat/completions'
    assert captured['headers']['Authorization'] == 'Bearer sk-test'
    assert captured['payload']['model'] == DEEPSEEK_MODEL
    assert captured['payload']['temperature'] == 0  # 可复现性
    assert d.verdict == 'benign' and d.source == 'llm'


def test_llm_review_api_failure_falls_back_unknown(monkeypatch, tmp_path):
    """网络/鉴权异常 → unknown 兜底（source=fallback），不抛异常、不误删。"""

    def boom(*args, **kwargs):
        raise ConnectionError('网络不可达')

    monkeypatch.setattr('threatlens.core.evaluation.llm_review._call_deepseek', boom)
    d = llm_review(_item(), api_key='sk-test', log_path=tmp_path / 'reviews.jsonl')
    assert d.verdict == 'unknown'
    assert d.source == 'fallback'
    assert d.confidence == 0.0
    assert 'LLM 调用失败' in d.reason


# -- §5 审计日志 -----------------------------------------------------------------

def test_llm_review_appends_audit_record(tmp_path):
    log = tmp_path / 'reviews_agent.jsonl'
    records: list[dict] = []
    d = llm_review(_item(uid='audit-e1'), api_key=None, mock=True,
                   log_path=log, records=records)

    line = json.loads(log.read_text(encoding='utf-8').splitlines()[0])
    assert line['verdict'] == d.verdict
    assert line['reason'] == d.reason
    assert line['technique_id'] == 'T1059.001'
    assert line['event_uid'] == 'audit-e1'
    assert 'context' in line  # 输入快照（可审计）
    assert 'latency_sec' in line
    assert len(records) == 1 and records[0]['event_uid'] == 'audit-e1'


def test_llm_review_no_log_path_is_noop():
    d = llm_review(_item(), mock=True)
    assert d.source == 'mock'  # log_path 缺省时不崩溃
