# ThreatLens · P2 Baseline 摸底评测报告

> 对应说明书：`docs/开发说明/03-评测.md`（P2 baseline 摸底）
> 生成方式：`python -m threatlens.core.evaluation.run_eval`（全确定性，可重跑复现）

## 1. 评测口径（03 §3）

- 金标：`T1059.001` / `T1003.001` / `T1087.001` / `T1021.002`（`load_atomic_chain` 从 Atomic 提取）
- 技术 ID 归并（§3.2）：子技术→父技术，gold 与 predicted 同口径 → `T1003` / `T1021` / `T1059` / `T1087`
- 金标阶段顺序：execution → credential-access → discovery → lateral-movement
- 输入遥测：4 数据集 9050 事件；主干确定性流水线，全程无 LLM

## 2. 指标对比（版本分离红线 §3.5）

| 指标 | 官方规则版（主数字） | 官方+自定义版（demo 完整性） |
|---|---|---|
| 规则数 | 2815 | 2816 |
| 识别技术（原始） | 13 | 13 |
| 识别技术（归并后） | 11 | 11 |
| precision | 36.4% | 36.4% |
| recall | 100.0% | 100.0% |
| 阶段召回 | 100.0% | 100.0% |
| 阶段顺序一致率 | 1.0 | 1.0 |
| §6 决策 | `llm-low-score-review` | `llm-low-score-review` |

## 3. 明细（原始 ID，未归并——§8 防“看起来都对”）

### 官方规则版

- predicted 原始 ID：`T1003.001` / `T1021.002` / `T1033` / `T1055` / `T1059.001` / `T1059.005` / `T1083` / `T1087` / `T1087.001` / `T1112` / `T1526` / `T1531` / `T1685`
- 命中（归并后）：`T1003` / `T1021` / `T1059` / `T1087`
- 漏检：（无）
- 额外（非金标）：`T1033` / `T1055` / `T1083` / `T1112` / `T1526` / `T1531` / `T1685`
- 阶段观察（金标阶段按序）：execution、credential-access、discovery、lateral-movement

### 官方+自定义版

- predicted 原始 ID：`T1003.001` / `T1021.002` / `T1033` / `T1055` / `T1059.001` / `T1059.005` / `T1083` / `T1087` / `T1087.001` / `T1112` / `T1526` / `T1531` / `T1685`
- 命中（归并后）：`T1003` / `T1021` / `T1059` / `T1087`
- 漏检：（无）
- 额外（非金标）：`T1033` / `T1055` / `T1083` / `T1112` / `T1526` / `T1531` / `T1685`
- 阶段观察（金标阶段按序）：execution、credential-access、discovery、lateral-movement

## 4. 结论与 pivot 判断（§6 决策规则）

- **官方规则版**（主数字）：recall=1.0 高、precision=0.3636 < 0.5 → LLM 空间在降噪/去误报，解释层定位为"低分证据复核"。
- **官方+自定义版**：recall=1.0 高、precision=0.3636 < 0.5 → LLM 空间在降噪/去误报，解释层定位为"低分证据复核"。
- 两版 precision 均偏低（官方 36.4%）：额外技术 7 个——部分是真实攻击行为（不在 demo 链金标范围），部分是规则泛化误报；**这正是 LLM 解释层“低分证据复核”的输入空间**。

**结论**：确定性 baseline 摸底完成——两版 recall 均达标（金标技术全覆盖）、precision 偏低（~36.4%）→ LLM 解释层按“低分证据复核”定位（§6 决策规则），主干确定性叙事不变，主数字以官方规则版为准。

## 5. 版本分离说明（§3.5 红线）

- 官方规则版 = `_src/rules/windows/` 全部可解析规则，简历主数字。
- 官方+自定义版 = 官方 + `threatlens/core/analysis/sigma_custom_rules/credentials_access_powershell_lsass.yml`（T1003.001 自定义规则，实测 4 数据集唯一命中 `empire_mimikatz_logonpasswords_2020-08-07103224.json:2451`、零误报）。
- 两版数字分开报告，禁止只报合并数字（防循环论证）。

### 两版证据差异（逐技术 evidence 集变化）

- `T1003.001`：新增 1 条证据（empire_mimikatz_logonpasswords_2020-08-07103224.json:2451 等）
