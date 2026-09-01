# ThreatLens 开发说明书 · 06 报告解释层真实 LLM 版

> 文档编号：06 / 主题：报告解释层真实 LLM 版
> 版本：v0.1
> 日期：2026-09-01
> 状态：设计定稿，待编码
> 关联：`04-LLM复核层.md`（§13 报告解释层 mock 版）、`01-数据准备.md`（§7）、`简历-2026秋招.md`
> 体例：承接 01–05，同一文档体系

---

## 1. 背景与目标（Why）

04 §13 报告解释层（LLM 介入点③）当前仅实现 **mock 模板渲染**：`report_writer.py:54` 的真实 LLM 调用是 `# TODO` 占位，`build_report(mock=False)` 仍走模板渲染（仅标注 `mock-fallback`）。

**欠账定性**：LLM 三介入点中 ①低分复核、②冲突裁决均已真实调用 DeepSeek API，③报告解释若停留在模板渲染，"LLM 三介入点"严格说是"两个半"，简历说法站不住。

**本说明书目标**：`build_report(mock=False)` 走真实 DeepSeek API，生成分析师可读的中文攻击链报告；三介入点全部真实闭环。

---

## 2. 范围（Scope & Non-goals）

**In scope**
- `_call_llm()`：真实 DeepSeek 调用（复用 `llm_review` 骨架）。
- **防幻觉自动校验**：报告中的技术 ID 必须 ⊆ 输入 chain 技术集（代码级校验，不靠 prompt）。
- 失败降级（mock-fallback，报告不丢失）；审计落 `evaluation/reports_agent.jsonl`。
- 单测（monkeypatch 假 API 响应）。

**Non-goals**
- **不改判定/不碰指标**：纯展示层，precision/recall 不变是验收硬约束。
- 不做多模态 / PDF 导出（保持 Markdown 文本）。
- mock 渲染版保留（作为降级与单测确定性依赖）。

---

## 3. 设计

### 3.1 调用设计（复用 llm_review 骨架）

| 项 | 约定 |
|---|---|
| API | DeepSeek `deepseek-chat`，OpenAI 兼容 `/chat/completions`，`temperature=0` |
| key | 环境变量 `DEEPSEEK_API_KEY`（根 `.env` 兜底加载，不入库） |
| 审计 | 调用落 `evaluation/reports_agent.jsonl`（追加：输入 chain 摘要 + 输出 + 耗时） |
| 失败兜底 | 无 key / 网络失败 / 解析异常 → 返回 mock 渲染结果，`source='mock-fallback'` 标注 |

### 3.2 Prompt 契约（防幻觉 + 防背答案）

- **system**：你是安全分析报告撰写者。将给定的结构化攻击链 JSON 转成**分析师可读的中文 Markdown 报告**，包含：摘要、攻击链叙述（按战术阶段：技术名/战术/首现时间/证据/复核与裁决理由）、证据附录。
  **硬约束：① 只依据给定 JSON，不得臆测或添加链上不存在的事实；② 报告中出现的所有技术 ID 必须来自给定 JSON 的 techniques 集合；③ 不得引用数据集名称或测试集结论（防背答案，04 §5 红线沿用）。**
- 输入：`AttackChain` JSON（techniques / chain / summary）+ 复核/裁决 reviews（reason）。
- 输出：Markdown 文本。

### 3.3 防幻觉自动校验（代码级，不只靠 prompt）

- 生成后扫描报告中的 `T\d+(\.\d+)?` 技术 ID：
  - 全部 ∈ chain 技术集 → 通过；
  - 存在 ∉ chain 技术集 → **从报告中剔除该行并告警**（记录到审计日志）。
- 效果："报告事实 ⊆ 链上事实"成为**可自动断言的工程校验**，而非"希望 LLM 别编"。

### 3.4 失败降级

`mock=False` 调用链：真实调用失败（无 key/网络/JSON 异常）→ 回退 `_mock_render_from_chain`（模板），`source='mock-fallback'`，报告仍生成、不抛异常。

---

## 4. 验收标准

- [ ] `build_report(mock=False)` 真实调用：有 key 时生成真实报告，审计落 `reports_agent.jsonl`。
- [ ] 失败兜底：无 key / 网络失败 → mock-fallback，报告仍生成（不抛异常）。
- [ ] **防幻觉校验**：注入含幻觉技术 ID 的假 LLM 响应 → 幻觉技术被剔除 + 告警（单测断言）。
- [ ] 指标不变（纯展示层，04 §13.4 断言沿用）。
- [ ] mock 分支全部现有测试保持；全量测试绿。

---

## 5. 实现指引

1. `report_writer.py`：
   - `_call_llm(chain, reviews, api_key)`：复用 llm_review 的 HTTP 调用模式（urllib + `/chat/completions` + `temperature=0`）；
   - `_extract_report_techs(report)` + `_filter_hallucinated(report, valid_techs)`：§3.3 校验；
   - `build_report(mock=False)` 分支：真实调用 → 幻觉过滤 → 审计；失败 → mock-fallback。
2. 单测（`tests/test_report_writer.py` 扩充）：
   - monkeypatch 假 API 响应 → 验证真实分支生成 + 幻觉剔除 + 告警；
   - 无 key → 验证 mock-fallback（不抛异常）。
3. 跑全量测试 + 指标不变验证。
4. 更新 04 §13 状态（真实 LLM 版完成）+ 规划书介入点③改 ✓。

---

## 6. 关联与后续

- 骨架：`04-LLM复核层.md` §13（mock 版已实现，本说明书补真实调用）。
- 红线：防背答案（04 §5/§7/§8）、纯展示层指标不变（04 §13.4）。
- 后续：P2 三期冲突复核已闭环；本说明书完成后 LLM 三介入点全部真实。

*本说明书补 04 §13 欠账：报告解释层从 mock 模板升级为真实 LLM 生成，三介入点彻底真实闭环。*
