"""链重建（02 §4.5）：证据聚合 + 打分去噪 + 两层时间线 + 攻击链输出。

流程：
1. 逐事件打分（§5.4 去噪打分表，硬编码）；
2. 分数 < 阈值（1.0）的命中不参与链重建（降权优先于硬删）；
3. 按技术聚合证据，每技术保留 top-K（5）条最高分证据，按分数排序；
4. 两层时间线（§5.3）：数据集内按 timestamp 取 first_seen；数据集间按
   战术阶段顺序（phase_order）排链，跨数据集日期不可比不做全局时间排序；
5. 输出 AttackChain（§6.3，P2 eval 直接消费）。
"""

from __future__ import annotations

from typing import Any

from .sigma_matcher import MatchResult

#: 分数阈值：低于此分数的命中不进链
SCORE_THRESHOLD = 1.0

#: 每技术最多保留的证据条数（§5.4 聚合去重）
TOP_K_EVIDENCE = 5

#: 硬排除：系统引导进程自身创建事件（§5.4，score=0）
HARD_EXCLUDE_PROCESSES = frozenset({'system', 'smss.exe', 'csrss.exe', 'wininit.exe'})

#: 降权 ×0.3：常见系统进程行为
DOWNWEIGHT_PROCESSES = frozenset({'svchost.exe', 'lsass.exe'})

#: 谱系 -1：父进程为系统服务（父链全系统服务 → 降权）
SYSTEM_PARENT_PROCESSES = frozenset({
    'svchost.exe', 'services.exe', 'wininit.exe', 'smss.exe', 'csrss.exe',
    'lsass.exe', 'winlogon.exe', 'spoolsv.exe', 'system',
})

#: 提权 +2：攻击载荷特征（命令行关键词）
PAYLOAD_KEYWORDS = ('mimikatz', '-ma lsass', '-enc', 'base64')

#: 提权 +2：从临时/用户目录启动
SUSPICIOUS_LAUNCH_PATHS = ('%temp%', 'appdata')

#: 谱系 +1：父进程为脚本宿主 / PowerShell
SUSPICIOUS_PARENTS = ('wscript', 'cscript', 'powershell')


def score_event(event: dict[str, Any], matches: list[MatchResult]) -> float:
    """事件可疑性打分（§5.4 分层规则，硬编码）。

    规则顺序：硬排除（0）→ 降权（×0.3）→ 谱系（±1）→ 载荷特征（+2）。
    matches 参数保留以兼容调用签名；打分只看事件本身字段。
    """
    process_name = (event.get('process_name') or '').strip().lower()
    command_line = (event.get('command_line') or '').lower()
    parent_process = (event.get('parent_process') or '').strip().lower()
    parent_basename = parent_process.rsplit('\\', 1)[-1].lower()  # 全路径 → 裸进程名

    # 硬排除：系统引导进程自身创建事件
    if process_name in HARD_EXCLUDE_PROCESSES:
        return 0.0

    score = 1.0

    # 降权：常见系统进程行为
    if process_name in DOWNWEIGHT_PROCESSES:
        score *= 0.3

    # 谱系：父进程链异常
    if any(kw in parent_process for kw in SUSPICIOUS_PARENTS):
        score += 1
    elif parent_basename in SYSTEM_PARENT_PROCESSES:
        score -= 1

    # 提权：攻击载荷特征
    if any(kw in command_line for kw in PAYLOAD_KEYWORDS):
        score += 2
    if any(path in (process_name + command_line) for path in SUSPICIOUS_LAUNCH_PATHS):
        score += 2

    return score


def build_chain(
    events_with_matches: list[tuple[dict[str, Any], list[MatchResult]]],
    attack_lib: dict[str, dict[str, Any]],
    phase_order: list[str],
    review: dict[tuple[str, str], dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """打分去噪 → 按技术聚合 → 两层时间线 → AttackChain（§6.3 结构）。

    `review`（可选，04 LLM 复核层）：{(technique_id, event_uid): {'action': ...}}，
    - action='drop'：该条证据不进链（LLM 判 benign → 降噪）；
    - action='keep'/'flag'：保留（attack/unknown），reason 记入 chain['review']。
    默认 None 时输出与纯脚本版逐字节一致（架构红线：LLM 不碰确定性判定主干）。
    """
    # 1. 打分 + 过滤，聚合成 {technique_id: [(score, event_uid, timestamp), ...]}
    agg: dict[str, list[tuple[float, str, str]]] = {}
    for event, matches in events_with_matches:
        if not matches:
            continue
        score = score_event(event, matches)
        if score < SCORE_THRESHOLD:
            continue
        uid = event.get('event_uid', '')
        timestamp = event.get('timestamp') or ''
        for m in matches:
            if review is not None and review.get((m.technique_id, uid), {}).get('action') == 'drop':
                continue  # LLM 复核判 benign，降噪
            agg.setdefault(m.technique_id, []).append((score, uid, timestamp))

    # 2. 每技术 top-K 证据，按分数降序（§5.4 证据列表按分数排序）
    technique_evidence: dict[str, list[dict[str, Any]]] = {}
    for technique_id, entries in agg.items():
        # 同一事件被多条规则命中同一技术 → 按 event_uid 去重，保留最高分
        entries.sort(key=lambda e: e[0], reverse=True)
        seen: set[str] = set()
        deduped: list[tuple[float, str, str]] = []
        for entry in entries:
            if entry[1] not in seen:
                seen.add(entry[1])
                deduped.append(entry)
        evidence = [{'event_uid': uid, 'score': round(score, 2)} for score, uid, _ in deduped[:TOP_K_EVIDENCE]]
        first_seen = min((ts for _, _, ts in entries if ts), default='')
        technique_evidence[technique_id] = {'evidence': evidence, 'first_seen': first_seen}

    # 3. 两层时间线：数据集间按战术阶段顺序；数据集内已由 first_seen 表达
    def tactic_of(technique_id: str) -> str:
        tactics = attack_lib.get(technique_id, {}).get('tactics') or []
        for tactic in phase_order:
            if tactic in tactics:
                return tactic
        return tactics[0] if tactics else ''

    def phase_rank(item: tuple[str, dict[str, Any]]) -> tuple[int, str]:
        _, meta = item
        tactic = tactic_of(item[0])
        if tactic in phase_order:
            return (0, f'{phase_order.index(tactic):02d}-{meta["first_seen"]}')
        return (1, f'zz-{meta["first_seen"]}')  # 阶段外技术排在后部

    chain_entries = []
    for technique_id, meta in sorted(technique_evidence.items(), key=phase_rank):
        chain_entries.append({
            'tactic': tactic_of(technique_id),
            'technique': technique_id,
            'first_seen': meta['first_seen'],
            'evidence': [e['event_uid'] for e in meta['evidence']],
        })

    # 4. techniques 字典 + summary
    techniques = {
        tid: {
            'name': attack_lib.get(tid, {}).get('name', ''),
            'tactics': attack_lib.get(tid, {}).get('tactics', []),
        }
        for tid in technique_evidence
    }
    covered_phases = len({e['tactic'] for e in chain_entries if e['tactic'] in phase_order})
    summary = f'共识别 {len(chain_entries)} 个技术，覆盖 {covered_phases} 个战术阶段'

    result: dict[str, Any] = {
        'chain': chain_entries,
        'techniques': techniques,
        'summary': summary,
    }

    # LLM 复核元数据（可选）：保留/存疑命中的判定与理由；drop 的也记录（解释缺失）
    if review:
        reviewed: dict[str, dict[str, Any]] = {}
        for (technique_id, uid), decision in review.items():
            reviewed.setdefault(technique_id, {})[uid] = decision
        result['review'] = reviewed

    return result
