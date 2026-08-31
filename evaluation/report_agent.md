# ThreatLens · Agent 版评测报告（04 LLM 低分复核）

> 对应说明书：`docs/开发说明/04-LLM复核层.md`；生成方式：`python -m threatlens.core.evaluation.run_eval_agent`（真实 API，temperature=0）

## 1. 对比表（v1 脚本版 vs v2 Agent 版）

| 指标 | v1 脚本版 | v2 Agent 版 | Δ |
|---|---|---|---|
| precision | 36.4% | 44.4% | +8.1pp |
| recall | 100.0% | 100.0% | — |
| 阶段召回 | 100.0% | 100.0% | — |
| 阶段顺序一致率 | 1.0 | 1.0 | — |
| 识别技术（归并后） | 11 | 9 | -2 |
| 可解释性 | 无 | 送审 106 条，保留 87 条均带 reason | 新增维度 |

## 2. 送审统计（§4 低分筛选）

- 送审 106 条（非金标技术的全部命中 + 分数低于阈值 1.0 的金标命中）：attack=3 / benign=19 / unknown=84；剔除 19 条
- 因复核链上证据被全部剔除的技术：`T1055` / `T1526`

## 3. 判定明细与人工核对区（§6 辅助：抽查链上可见判定）

> 仅列链上可见命中（脚本链/复核链证据列表中出现过的，决定指标的那部分，共 21 条）；全部 106 条送审记录见 `evaluation/reviews_agent.jsonl`。

| 技术 | 事件 | score | verdict | 置信 | reason |
|---|---|---|---|---|---|
| T1033 | `empire_launcher_vbs_2020-09-04160940.json:1820` | 2.0 | attack | 0.0 | whoami.exe 由 powershell.exe 启动，且命令行为查询当前用户，符合 T1033 系统所有者/用户发现行为。 |
| T1033 | `empire_mimikatz_logonpasswords_2020-08-07103224.json:282` | 2.0 | attack | 0.0 | whoami.exe /user 命令用于查询当前用户信息，符合 T1033 系统所有者/用户发现技术，且由 powershell 启动，与规则命中场景一致。 |
| T1055 | `empire_launcher_vbs_2020-09-04160940.json:1817` | 2.0 | benign | 0.0 | 证据仅显示执行了系统命令 whoami.exe，无任何进程注入行为，与 T1055 技术无关。 |
| T1055 | `empire_launcher_vbs_2020-09-04160940.json:247` | 1.0 | benign | 0.0 | 证据显示 WScript.exe 启动 VBS 脚本，无进程注入迹象，且规则名指向可疑镜像缺失，但事件中无相关证据。 |
| T1055 | `empire_launcher_vbs_2020-09-04160940.json:328` | 4.0 | benign | 0.0 | 证据显示的是 PowerShell 执行编码命令，但未包含任何进程注入相关的 API 调用或行为，因此不构成 T1055 进程注入。 |
| T1055 | `empire_launcher_vbs_2020-09-04160940.json:343` | 2.0 | benign | 0.0 | 命令行为conhost.exe的正常启动参数，不涉及进程注入行为。 |
| T1055 | `empire_mimikatz_logonpasswords_2020-08-07103224.json:303` | 2.0 | benign | 0.0 | 命令行为 whoami /user，是正常的用户信息查询，与进程注入技术无关。 |
| T1083 | `cmd_seatbelt_group_user_2020-11-0216391814.json:148` | 1.0 | attack | 0.0 | Seatbelt.exe 是已知的侦察工具，其 '-group=user' 参数会枚举用户、目录和文件信息，直接对应 T1083 文件与目录发现技术。 |
| T1112 | `empire_launcher_vbs_2020-09-04160940.json:73` | 1.0 | unknown | 0.0 | 证据仅显示 wscript.exe 运行了 launcher.vbs，未包含任何注册表修改操作的具体信息，无法确认是否命中 T1112。 |
| T1112 | `empire_launcher_vbs_2020-09-04160940.json:77` | 1.0 | unknown | 0.0 | 证据仅包含进程名和用户，无注册表操作的具体键值或行为，无法确认是否修改注册表。 |
| T1112 | `empire_launcher_vbs_2020-09-04160940.json:78` | 1.0 | unknown | 0.0 | 证据仅包含进程名和用户，无注册表操作的具体键值或行为，无法确认是否修改注册表。 |
| T1112 | `empire_launcher_vbs_2020-09-04160940.json:79` | 1.0 | unknown | 0.0 | 证据仅包含进程名和用户，无注册表操作的具体键值或行为，无法确认是否修改注册表。 |
| T1112 | `empire_launcher_vbs_2020-09-04160940.json:81` | 1.0 | unknown | 0.0 | 证据仅包含进程名和用户，未提供注册表修改的具体键值或操作，无法确认是否真实支持T1112。 |
| T1526 | `cmd_seatbelt_group_user_2020-11-0216391814.json:148` | 1.0 | benign | 0.0 | Seatbelt 的 -group=user 枚举本地用户信息，属于主机侦察而非云服务发现，且无云环境证据。 |
| T1531 | `covenant_copy_smb_CreateRequest_2020-09-22145302.json:301` | 1.0 | unknown | 0.0 | 事件仅包含用户注销日志（4634），无证据表明账户被删除或访问权限被移除，无法确认与T1531相关。 |
| T1531 | `empire_launcher_vbs_2020-09-04160940.json:18` | 1.0 | unknown | 0.0 | 事件仅包含用户注销日志（Event ID 4634），无证据表明账户被删除或禁用，无法确认与T1531相关。 |
| T1531 | `empire_launcher_vbs_2020-09-04160940.json:2001` | 1.0 | benign | 0.0 | 事件仅为用户注销（Event ID 4634），不涉及账户删除或访问权限移除，与T1531技术无关。 |
| T1531 | `empire_mimikatz_logonpasswords_2020-08-07103224.json:31` | 1.0 | benign | 0.0 | 事件ID 4634是用户注销事件，与账户访问删除（T1531）无关，且规则名称与证据不匹配。 |
| T1531 | `empire_mimikatz_logonpasswords_2020-08-07103224.json:648` | 1.0 | benign | 0.0 | 事件ID 4634是用户注销事件，与账户访问移除（T1531）无关，且规则名称与证据不匹配。 |
| T1531 | `empire_mimikatz_logonpasswords_2020-08-07103224.json:651` | 1.0 | benign | 0.0 | 事件ID 4634是用户注销事件，与账户访问删除（T1531）无关，且规则名与证据不匹配。 |
| T1685 | `empire_launcher_vbs_2020-09-04160940.json:918` | 1.0 | unknown | 0.0 | 证据字段中缺少进程、命令行等关键信息，无法确认是否发生AMSI绕过行为。 |

## 4. 结论

**Agent 版 precision 提升 +8.1pp（降噪生效），recall 持平——“Agent 比脚本强”的量化证据成立。**

- 可解释性：送审 106 条均有 reason（链上 `review` 元数据可查）；本次调用记录见 `evaluation/reviews_agent.jsonl`（输入快照 + 输出 + 耗时）。
- 复现：mock 模式全确定性；真实 API 模式 `temperature=0` + jsonl 审计兜底。
