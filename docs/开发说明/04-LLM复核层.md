# ThreatLens 开发说明书 · 04 LLM 复核层（Agent 版）

> 文档编号：04 / 主题：LLM 复核层（Agent 版）
> 版本：v0.2（补 prompt 通用性红线，防循环论证）
> 日期：2026-08-31
> 状态：设计定稿，待编码（`llm_review` / `run_eval_agent`）
> 关联：`03-评测.md`（baseline 数字与口径）、`02-分析引擎.md`（主干与打分）、`ADR-003`
> 体例：承接 01–03，同一文档体系

---

## 1. 背景与目标（Why）

P2 一期 baseline 摸底完成（快照 `evaluation/baseline/v1-script-baseline/`）：

| 指标 | 脚本版（官方规则，主数字） |
|---|---|
| precision | 36.4% |
| recall | 100% |
| 阶段召回 / 顺序一致率 | 100% / 1.0 |
| 03 §6 决策 | `llm-low-score-review` |

**结论**：脚本主干识别能力已满（recall 100%），但 precision 偏低（36.4%）——13 个技术里 9 个非金标，部分是规则泛化误报。

本说明书目标：实现 **LLM 低分证据复核层**（Agent 版），把误报剔掉、把"为什么"讲出来，产出与 baseline 的**对比表**——这是"Agent 比脚本强"的可量化证据（precision 提升 + 可解释性）。

---

## 2. 范围（Scope & Non-goals）

**In scope**
- 低分命中筛选（"低分"定义）。
- `llm_review()`：组装上下文 → 调 LLM → 结构化判定（`verdict` + `reason`）。
- Agent 版评测跑法（`run_eval_agent.py`）与对比表。
- baseline 快照机制（`evaluation/baseline/`，v1 已固化）。

**Non-goals**
- **不做多智能体编排**：复核层是单一函数，不是多 Agent 系统。
- **不改主干规则/打分**：确定性主干原样保留，是架构兜底。
- **不覆盖高分命中**：高分=已确认，不进 LLM（省成本、保确定性）。
- **LLM 不参与判定主干**：复核结果只影响低分命中的过滤/标注，**不改变确定性判定本身**（红线，见 §3）。

---

## 3. 架构与数据流

```
脚本主干（02，原样）→ 打分（§5.4）→ 命中集合
                                      │
                        ┌─────────────┴─────────────┐
                        │ 高分命中（已确认）          │ 低分命中（灰色地带）
                        │ → 不进 LLM，直接保留        │ → 送 llm_review
                        └─────────────┴─────────────┘
                                              │
                                     llm_review（Agent）
                                              │
                          verdict=attack ────→ 保留 + 附 reason（证据标注）
                          verdict=benign  ────→ 过滤（降噪）
                          verdict=unknown ────→ 保留 + 标"存疑"（不误删兜底）
                                              │
                                              ▼
                                   AttackChain（Agent 版）→ 评测对比
```

**架构红线**：LLM 只在"脚本判定完成之后"做低分复核——即使 LLM 全错，主链的确定性判定也不受影响（它只影响低分命中的去留）。这就是"主干脚本 + AI 三支点"里 AI 的定位：**在脚本解决不了的地方补，不碰脚本能解决的**。

---

## 4. 低分命中的定义（筛选）

初版建议（量小、可控、对 baseline 数字敏感）：

- **复核对象 = 非金标技术的全部命中**（demo 链 4 技术之外的那 9 个技术），外加分数低于阈值的金标命中。
- 理由：precision 低的来源正是那 9 个非金标技术；金标技术 recall 已 100%，无需送 LLM。
- 分数阈值沿用 §5.4 去噪阈值（如 1.0），`score_event` 打分 < 阈值视为低分。

> 筛选逻辑在 `run_eval_agent.py` 内实现，metrics 输出时保留"送审/未送审"统计。

---

## 5. LLM 接口与 Prompt 契约

| 项 | 约定 |
|---|---|
| 模型 | DeepSeek API（`deepseek-chat`）；key 走环境变量 `DEEPSEEK_API_KEY`（不入库） |
| 调用方式 | OpenAI 兼容 `/chat/completions`，`temperature=0`（固定，保可复现） |
| 输入上下文 | 技术 ID/名称 + 命中规则名 + 证据事件关键字段（`event_uid`/`event_id`/`Image`/`CommandLine`/`TargetImage`/`AccessMask`）+ 打分 |
| 输出格式 | 严格 JSON：`{"verdict": "attack"\|"benign"\|"unknown", "reason": "<一句话>", "confidence": 0-1}` |
| 调用记录 | 每次调用落 `evaluation/reviews_agent.jsonl`（输入快照 + 输出 + 耗时），可审计 |

**Prompt 骨架**（system）：
> 你是安全分析助手。给定一条规则命中及其证据事件，判断该命中是否真实支持对应 ATT&CK 技术。只依据证据字段判断，不要臆测。输出 JSON：verdict 取 attack/benign/unknown，reason 不超过一句话。

> ⚠️ **Prompt 通用性红线**：prompt 内**禁止**引用测试集名称、具体技术或数据集的判定结论（如"seatbelt 是良性"、"mimikatz 数据集"）——只允许通用安全领域知识。否则 precision 提升即"背答案"（循环论证），§8 验收强制检查。

**mock 先行**：开发阶段用 `reviews_agent.jsonl` 的假响应跑通链路，再切真实 API（单测不依赖外网）。

---

## 6. 评测（Agent 版跑法）

- **同一金标、同一归并口径**（03 §3，保证与 baseline 可比）。
- `run_eval_agent.py`：跑主干 → 筛低分 → `llm_review` → 复核后重算指标 → `evaluation/metrics_agent.json`。
- **对比表**（写入 `evaluation/report_agent.md`）：

| 指标 | v1 脚本版 | v2 Agent 版 | Δ |
|---|---|---|---|
| precision | 36.4% | 待跑 | 预期 ↑（降噪） |
| recall | 100% | 待跑 | 预期 =（不动金标） |
| 阶段召回 | 100% | 待跑 | 预期 = |
| 可解释性 | 无 | reason 非空 | 新增维度 |

- **复核准确率（辅助）**：抽 N 条 LLM 判定，人工核对 verdict 是否正确（记录于 report_agent.md）。
- 跑完复制快照 `evaluation/baseline/v2-agent-lowscore-review/`。

---

## 7. 风险与约束

| 风险 | 说明 / 缓解 |
|---|---|
| LLM 不可复现 | `temperature=0` + 调用落 `reviews_agent.jsonl`；复核只影响低分，主链确定性兜底 |
| 幻觉/误判 | `unknown` 兜底（不误删，标存疑）；误删最坏情况=漏掉非金标技术，不影响金标 recall |
| **prompt 背答案（循环论证）** ⚠️ | prompt 若暗示"某某技术是误报"= 把答案写进考题，precision 提升不可信；必须只用通用安全知识（§5 契约 + §8 验收强制） |
| 成本/延迟 | 只复核低分命中（9 技术级），量小可控 |
| 密钥泄露 | `DEEPSEEK_API_KEY` 环境变量，`.gitignore` 已覆盖（无 .env 入库） |
| 对比不可信 | baseline 快照 v1 已固化，同口径同金标，diff 对比 |

---

## 8. 验收标准

- [ ] `llm_review()` 单测（mock）：attack / benign / unknown 三分支 + JSON 解析健壮性。
- [ ] `run_eval_agent` 跑通，产出 `evaluation/metrics_agent.json` + `report_agent.md` 对比表。
- [ ] **prompt 通用性（防背答案）**：`llm_review` 的 prompt 只含安全领域通用知识，**不得引用测试集名称/具体技术或数据集结论**（如"seatbelt 是良性"）；代码评审抽查 prompt 文本确认无泄漏——否则 precision 提升即循环论证。
- [ ] Agent 版 precision 高于 baseline（36.4%），recall 不下降（=100%）。
- [ ] 链上低分技术均带 `reason`（可解释性落地）。
- [ ] 快照 `v2-agent-lowscore-review/` 固化；全流程可复现。

---

## 9. 实现指引（首跑顺序）

1. **快照 baseline**（已完成：`evaluation/baseline/v1-script-baseline/`）。
2. **`llm_review.py`**：`build_context()` + `call_llm()`（mock 先行）+ `parse_verdict()`，落 `reviews_agent.jsonl`。
3. **`run_eval_agent.py`**：低分筛选（§4）→ `llm_review` → 重算指标（复用 03 口径函数）→ `metrics_agent.json`。
4. **对比表**：与 v1 快照 diff，写 `report_agent.md`。
5. **测试**：`test_llm_review.py`（mock）+ `test_run_eval_agent.py`。
6. **快照 v2**：复制为 `evaluation/baseline/v2-agent-lowscore-review/`。

---

## 10. 关联文档与后续

- baseline 口径：`03-评测.md`（§3 口径、§3.5 版本分离）。
- 主干与打分：`02-分析引擎.md`（§4.5、§5.4）。
- 决策依据：`ADR-003`；本说明书实施中的关键决策（如低分定义、LLM 介入点）视情况落 ADR-004。
- 后续：LLM 解释层可扩展为"冲突证据复核"（P2 三期）；P3 IoC 富集。

*本说明书对应规划书 P2 二期：Agent 版（脚本主干 + LLM 低分复核）→ 与 baseline 对比，产出"Agent 比脚本强"的可量化证据。*

---

## 12. 二期：冲突证据复核（P2 三期 · 已实现）

> 状态：已实现（2026-09-01，真实 API 验收：v3 precision 57.1%，recall 100%）。
> 代码：`threatlens/core/evaluation/conflict_review.py`（并入 `run_eval_agent` 管道）。

### 12.1 背景与定位
低分复核（§3–§10）按**可疑性分数**降噪；但 FP 的另一来源是**证据归属歧义**——同一批事件被多条规则指向不同技术，错误归属成为非金标 FP。本二期补**冲突裁决**：对共享事件的技术组，裁决主技术、剔除非金标归属，继续提 precision。

**定位**：与低分复核互补的第二个 LLM 介入点（同一证据的多个解释 → 裁决），非层级叠加；两个介入点 + 报告解释 = "LLM 三介入点架构"完整落地。

### 12.2 冲突定义与实测基线（2026-09-01 实测）
- **冲突事件** = 被 ≥2 个技术共享证据的事件（`technique_evidence` 反向映射）。
- **实测**：10 条冲突事件 / 23 条有证据事件（43%）。热点：
  - `T1059.005 × T1112`：launcher_vbs :73/:77/:78/:79/:81（5 条）
  - `T1083 × T1087 × T1526`：seatbelt :148（一条三标签，T1526/T1083 为非金标 FP）
  - `T1033 × T1087.001`：:1820 / mimikatz:282（T1033 非金标）
  - `T1055 × T1059.001`（:328）、`T1059.001 × T1685`（:918）
- 此清单作为验收数据（冲突裁决后清单应显著收敛）。

### 12.3 管道设计（避免重复劳动）
```
脚本主干 → 低分复核（§3）→ 冲突组重算 → 冲突裁决（本二期）→ AttackChain
```
- 先跑低分复核（已剔 T1055/T1526 等）→ 剩余命中中**重新计算共享事件** → 只送仍存在的冲突组（低分已剔掉的一方，冲突自动消失，不重复送）。
- 金标技术命中**不参与裁决**（recall 100% 硬约束）——裁决对象限定为非金标技术共享的冲突组。

### 12.4 裁决接口与 Prompt
- 输入：冲突事件组（`event_uid` + 证据字段）+ 候选技术列表（各技术的规则名/名称）。
- 输出（复用 llm_review 调用骨架，`temperature=0` + 审计）：
  ```json
  {"primary": "T1112", "dropped": ["T1059.005"], "reason": "该批事件为注册表写入，非 VBS 执行"}
  ```
- **防背答案红线沿用**（§5/§7/§8）：prompt 禁止引用测试集名称/具体技术结论。
- 失败兜底：裁决失败保持原状（不误删），仅标注存疑。

### 12.5 评测与验收
- 指标：冲突裁决后 precision（实测 **57.1%**，≥44.4% 达成）、**recall 保持 100%（硬约束，实测达成）**。
- 附加：冲突收敛度（实测：复核后 9 组 → 裁决后 2 组，7 条裁决 drop）、裁决 reason 抽查（报告 §3）。
- 快照：`evaluation/baseline/v3-agent-conflict-review/`（已固化，真实 API 运行）。
- 验收：
  - [x] `conflict_review` 单测（mock：primary/dropped 分支 + 金标不裁决断言）
  - [x] 管道串联后 run_eval_agent 产物更新（v3）
  - [x] precision 提升（36.4%→44.4%→57.1%）、recall=100%、冲突清单收敛（9→2 组）
  - [x] prompt 防背答案抽查通过（system prompt 仅通用安全知识；context 白名单不含 tactic_hint）

### 12.6 实现指引
1. `conflict_review.py`：事件→技术反向映射（复用 12.2 逻辑）→ 冲突组筛选（排除已剔/金标）→ 裁决。
2. `run_eval_agent.py` 管道加一段（低分复核 → 冲突裁决）。
3. 评测对比 v2（44.4%）vs v3 → 快照。
4. 测试 + prompt 抽查。

---

## 13. 三期：报告解释层（LLM 介入点③ · mock 版已实现）

> 状态：**mock 模板渲染版已实现**（2026-09-01，接入 run_demo + run_eval_agent，纯展示层指标不变验证通过）；**真实 LLM 版见 `06-报告真实LLM版.md`（待编码）**——`build_report(mock=False)` 目前仍走模板渲染（`report_writer.py:54` TODO）。

### 13.1 背景与定位
前两个介入点（①低分复核、②冲突裁决）已实现并贡献 precision 提升（36.4%→57.1%）。本介入点解决**结果可读性**：把结构化 `AttackChain`（JSON）转成**人类可读的自然语言攻击链报告**。

**定位**：LLM 三介入点架构的最后一块，与 ①② 有本质区别——**不参与判定、不剔任何技术、不改任何指标**，纯"呈现层"。它回答的不是"是不是攻击"，而是"这次攻击是什么、证据是什么、怎么向人讲清楚"。

**价值**：
- 产品价值：SOC 分析师要的是能读的报告，不是 JSON；
- 简历价值："LLM 三介入点架构"（复核/裁决/报告）正式闭环，规划书 P1 交付第 4 条补齐；
- 低风险：纯展示层，precision/recall 数字不动（验收硬约束）。

### 13.2 范围（Scope & Non-goals）
**In scope**
- `report_writer()`：`AttackChain + reviews → Markdown 报告`。
- 接入：`run_demo` / `run_eval_agent` 跑完自动写 `outputs/attack_chain_report.md`。
- 测试（mock + 真实链抽查）。

**Non-goals**
- 不改判定、不参与评测指标（指标不变是验收项）。
- 不做自动处置/修复建议（规划书 Non-goals）。
- 不做多模态/PDF 导出（保持 Markdown 文本）。
- 报告不接实时流（离线报告）。

### 13.3 设计

**13.3.1 输入输出**
- 输入：`AttackChain`（`techniques` / `chain[]` / `evidence[]` / `summary`）+ 复核/裁决 `reviews`（含 reason）。
- 输出：Markdown 报告，结构：
  ```
  # 攻击链分析报告
  ## 摘要（2-3 句：发现 X 战术阶段攻击链，涉及 N 个技术，置信说明）
  ## 攻击链叙述（按战术阶段顺序：
      每个技术：名称 + 战术 + 首现时间 + 证据 event_uid + 该技术被复核/裁决的 reason）
  ## 证据附录（可选：关键事件明细）
  ```

**13.3.2 Prompt 契约**
- system：安全分析报告撰写者，把给定结构化攻击链转成**分析师可读的中文报告**；**只依据给定 JSON 内容**，不得臆测、不得添加未在证据中出现的事实（防幻觉）；不引用测试集/数据集名称（防背答案红线沿用 §5）。
- 输入：AttackChain JSON + reviews。
- 输出：Markdown 文本。
- `temperature=0`（可复现）；审计落 `evaluation/reports_agent.jsonl`（可选，含输入快照+输出+耗时）。

**13.3.3 与指标的关系（红线）**
- 报告是**纯展示层**：v1/v2/v3 的 precision/recall/阶段召回**完全不变**，验收断言。

### 13.4 验收标准
- [ ] `report_writer()` 单测（mock：合法 Markdown 输出、字段齐全）。
- [ ] 真实 demo 链生成报告：技术/战术/证据/裁决 reason 与 chain 一一对应，抽查无幻觉（未出现链上不存在的事实）。
- [ ] **指标不变**：生成报告前后 precision/recall 数字一致（纯展示层断言）。
- [ ] prompt 防背答案抽查通过（不含数据集名/测试集结论）。
- [ ] 全量测试保持；规划书 P1 介入点③状态改 ✓（验证后）。

### 13.5 实现指引
1. `threatlens/core/analysis/report_writer.py`：`build_report(chain, attack_lib, reviews) -> str`（复用 llm_review 的调用骨架：`temperature=0` + 审计 + 失败兜底返回结构化降级文本）。
2. `run_demo.py` / `run_eval_agent.py` 末尾接入：跑完自动写 `outputs/attack_chain_report.md`。
3. `tests/test_report_writer.py`：mock 分支 + 真实链抽查。
4. 验证指标不变 + prompt 抽查 → 更新规划书介入点③状态。

> ⚠️ **真实 LLM 版未实现**：`report_writer.py:54` 的 `mock=False` 分支仍走模板渲染（TODO）。真实 DeepSeek 调用（含防幻觉校验、失败降级、验收）见独立说明书 **`06-报告真实LLM版.md`**——本说明书只覆盖 mock 模板版。
