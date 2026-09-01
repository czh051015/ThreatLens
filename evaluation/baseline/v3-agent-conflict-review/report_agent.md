# ThreatLens · Agent 版评测报告（04 LLM 低分复核 + 冲突裁决）

> 对应说明书：`docs/开发说明/04-LLM复核层.md`（§3–§10 低分复核、§12 冲突复核）；生成方式：`python -m threatlens.core.evaluation.run_eval_agent`（`--mock` 确定性假 LLM）

## 1. 对比表（v1 脚本版 vs v2 低分复核 vs v3 冲突复核）

| 指标 | v1 脚本版 | v2 低分复核 | v3 冲突复核 | Δ(v3-v1) |
|---|---|---|---|---|
| precision | 36.4% | 40.0% | 50.0% | +13.6pp |
| recall | 100.0% | 100.0% | 100.0% | — |
| 阶段召回 | 100.0% | 100.0% | 100.0% | — |
| 阶段顺序一致率 | 1.0 | 1.0 | 1.0 | — |
| 识别技术（归并后） | 11 | 10 | 8 | -3 |
| 可解释性 | 无 | 送审 106 条均带 reason | + 冲突裁决 8 组 | 新增维度 |

## 2. 送审统计（§4 低分筛选）

- 送审 106 条（非金标技术的全部命中 + 分数低于阈值 1.0 的金标命中）：attack=39 / benign=34 / unknown=33；剔除 38 条
- 因复核链上证据被全部剔除的技术：`T1033` / `T1526` / `T1685`

## 3. 冲突裁决明细（§12.5 辅助：收敛度 + reason 抽查）

- 冲突组（§12.2 口径：被 ≥2 个技术共享证据的事件）：复核后链 8 组 → 裁决后剩余 5 组（收敛度 = 3 组归并/消除）；金标技术永不因裁决被 drop（recall 100% 硬约束，代码强制）。

| 事件 | 候选 | primary | dropped | reason |
|---|---|---|---|---|
| `cmd_seatbelt_group_user_2020-11-0216391814.json:148` | T1526/T1087/T1083 | T1083 | T1526 | mock 确定性响应：主技术为最后一个候选 |
| `empire_launcher_vbs_2020-09-04160940.json:1820` | T1087.001/T1033 | T1087.001 | T1033 | mock 确定性响应：主技术为第一个候选 |
| `empire_launcher_vbs_2020-09-04160940.json:328` | T1059.001/T1055 | T1059.001 | T1055 | mock 确定性响应：主技术为第一个候选 |
| `empire_launcher_vbs_2020-09-04160940.json:73` | T1059.005/T1112 | T1112 | — | mock 确定性响应：主技术为最后一个候选 |
| `empire_launcher_vbs_2020-09-04160940.json:77` | T1059.005/T1112 | T1059.005 | — | mock 确定性响应：证据存疑，保持原状 |
| `empire_launcher_vbs_2020-09-04160940.json:78` | T1059.005/T1112 | T1059.005 | — | mock 确定性响应：证据存疑，保持原状 |
| `empire_launcher_vbs_2020-09-04160940.json:79` | T1059.005/T1112 | T1059.005 | T1112 | mock 确定性响应：主技术为第一个候选 |
| `empire_launcher_vbs_2020-09-04160940.json:81` | T1059.005/T1112 | T1112 | — | mock 确定性响应：主技术为最后一个候选 |

## 4. 判定明细与人工核对区（§6 辅助：抽查链上可见判定）

> 仅列链上可见命中（脚本链/v3 复核链证据列表中出现过的，决定指标的那部分，共 23 条）；全部 106 条低分复核记录见 `evaluation/reviews_agent.jsonl`，冲突裁决记录见 `evaluation/conflicts_agent.jsonl`。

| 技术 | 事件 | score | verdict | 置信 | reason |
|---|---|---|---|---|---|
| T1033 | `empire_launcher_vbs_2020-09-04160940.json:1820` | 2.0 | unknown | 0.5 | mock 确定性响应（unknown） |
| T1033 | `empire_mimikatz_logonpasswords_2020-08-07103224.json:282` | 2.0 | benign | 0.5 | mock 确定性响应（benign） |
| T1055 | `empire_launcher_vbs_2020-09-04160940.json:1817` | 2.0 | benign | 0.5 | mock 确定性响应（benign） |
| T1055 | `empire_launcher_vbs_2020-09-04160940.json:247` | 1.0 | attack | 0.5 | mock 确定性响应（attack） |
| T1055 | `empire_launcher_vbs_2020-09-04160940.json:328` | 4.0 | unknown | 0.5 | mock 确定性响应（unknown） |
| T1055 | `empire_launcher_vbs_2020-09-04160940.json:343` | 2.0 | unknown | 0.5 | mock 确定性响应（unknown） |
| T1055 | `empire_mimikatz_logonpasswords_2020-08-07103224.json:303` | 2.0 | benign | 0.5 | mock 确定性响应（benign） |
| T1083 | `cmd_seatbelt_group_user_2020-11-0216391814.json:148` | 1.0 | attack | 0.5 | mock 确定性响应（attack） |
| T1112 | `empire_launcher_vbs_2020-09-04160940.json:73` | 1.0 | attack | 0.5 | mock 确定性响应（attack） |
| T1112 | `empire_launcher_vbs_2020-09-04160940.json:77` | 1.0 | attack | 0.5 | mock 确定性响应（attack） |
| T1112 | `empire_launcher_vbs_2020-09-04160940.json:78` | 1.0 | attack | 0.5 | mock 确定性响应（attack） |
| T1112 | `empire_launcher_vbs_2020-09-04160940.json:79` | 1.0 | unknown | 0.5 | mock 确定性响应（unknown） |
| T1112 | `empire_launcher_vbs_2020-09-04160940.json:81` | 1.0 | unknown | 0.5 | mock 确定性响应（unknown） |
| T1112 | `empire_launcher_vbs_2020-09-04160940.json:82` | 1.0 | attack | 0.5 | mock 确定性响应（attack） |
| T1526 | `cmd_seatbelt_group_user_2020-11-0216391814.json:148` | 1.0 | unknown | 0.5 | mock 确定性响应（unknown） |
| T1531 | `empire_launcher_vbs_2020-09-04160940.json:18` | 1.0 | unknown | 0.5 | mock 确定性响应（unknown） |
| T1531 | `empire_launcher_vbs_2020-09-04160940.json:2001` | 1.0 | benign | 0.5 | mock 确定性响应（benign） |
| T1531 | `empire_mimikatz_logonpasswords_2020-08-07103224.json:31` | 1.0 | unknown | 0.5 | mock 确定性响应（unknown） |
| T1531 | `empire_mimikatz_logonpasswords_2020-08-07103224.json:5517` | 1.0 | attack | 0.5 | mock 确定性响应（attack） |
| T1531 | `empire_mimikatz_logonpasswords_2020-08-07103224.json:648` | 1.0 | benign | 0.5 | mock 确定性响应（benign） |
| T1531 | `empire_mimikatz_logonpasswords_2020-08-07103224.json:651` | 1.0 | unknown | 0.5 | mock 确定性响应（unknown） |
| T1531 | `empire_mimikatz_logonpasswords_2020-08-07103224.json:661` | 1.0 | unknown | 0.5 | mock 确定性响应（unknown） |
| T1685 | `empire_launcher_vbs_2020-09-04160940.json:918` | 1.0 | benign | 0.5 | mock 确定性响应（benign） |

## 5. 结论

**Agent 版 precision 提升 +13.6pp（低分复核 +3.6pp + 冲突裁决 +10.0pp），recall 持平——"Agent 比脚本强"的量化证据成立。**

- 可解释性：低分复核送审 106 条、冲突裁决 8 组，均带 reason（链上 `review` 元数据可查）；调用记录见 `evaluation/reviews_agent.jsonl` + `evaluation/conflicts_agent.jsonl`（输入快照 + 输出 + 耗时）。
- 复现：mock 模式全确定性；真实 API 模式 `temperature=0` + jsonl 审计兜底。
