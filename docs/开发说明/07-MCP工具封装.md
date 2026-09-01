# ThreatLens 开发说明书 · 07 MCP 工具封装

> 文档编号：07 / 主题：MCP 工具封装
> 版本：v0.1
> 日期：2026-09-01
> 状态：设计定稿，待编码
> 关联：`02-分析引擎.md`（分析管道）、`04-LLM复核层.md`（报告解释）、`06-报告真实LLM版.md`
> 体例：承接 01–06，同一文档体系

---

## 1. 背景与目标（Why）

ThreatLens 目前是命令行工具（`run_demo` / `run_eval_agent`）。为让**任意 AI client（Claude Desktop / Cursor / 自研 Agent）能通过标准协议调用**分析能力，封装为 MCP（Model Context Protocol）工具。

**价值**：
- AI 应用开发岗的核心技能展示（MCP 是当下 AI 应用集成标准）；
- 分析能力从"命令行"变成"可被程序调用"——`lens_*` 工具可被任何 MCP client 发现和调用；
- 复用现有代码（分析管道、报告生成），只加协议层。

---

## 2. 范围（Scope & Non-goals）

**In scope**
- MCP server（Python，stdio transport）：声明 3 个 `lens_*` 工具。
- 工具契约：参数 / 输出 / 错误处理。
- 接入说明：MCP client 如何配置连接。

**Non-goals**
- 不做远程部署（HTTP/SSE）——起步用 stdio，本地调用。
- 不重写核心分析逻辑（server 只做协议层，调现有函数）。
- 不做多 agent 编排、不做输入格式解析（EVTX/XML）。
- 不做鉴权/权限控制（本地个人工具；远程化时另议）。

---

## 3. 架构

```
[AI Client（Claude Desktop / Cursor / 任意 MCP client）]
        │  MCP 协议（stdio，JSON-RPC）
        ▼
[MCP Server: threatlens/core/mcp/server.py]
        │  调用现有函数
        ▼
[现有管道：load_telemetry → sigma_matcher → chain_builder → report_writer]
```

- Server 只做"协议层"：接收 MCP 调用 → 转成内部函数调用 → 返回结构化结果。
- 核心逻辑零改动，复用 `run_demo.py` / `run_eval_agent.py` 里的构建函数。

---

## 4. 工具契约（lens_* 工具）

### 4.1 `lens_analyze`（核心）

分析一份遥测文件，返回攻击链结果。

| 参数 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `telemetry_path` | str | ✅ | 本地 JSONL 遥测文件路径（Mordor 格式） |
| `include_custom` | bool | ❌ | 是否包含自定义规则（默认 False） |

**输出**（AttackChain JSON）：
```json
{
  "summary": "共识别 10 个技术，覆盖 4 个战术阶段",
  "techniques": {"T1059.001": {"name": "PowerShell", "tactics": ["execution"]}},
  "chain": [
    {"tactic": "execution", "technique": "T1059.001",
     "first_seen": "...", "evidence": ["file.json:259", "..."]}
  ]
}
```

**错误处理**：文件不存在 / 格式非法 → 返回错误消息（不抛异常，MCP 工具规范）。

> 设计决策：`lens_analyze` 走**确定性主干**（无 LLM）——快、可复现，供 client 快速判断。

### 4.2 `lens_report`

生成人类可读的 Markdown 攻击链报告。

| 参数 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `chain_json` | str | ✅ | `lens_analyze` 返回的 AttackChain JSON 字符串 |
| `mock` | bool | ❌ | 报告渲染模式（默认 True；False 走真实 LLM，需 DEEPSEEK_API_KEY） |

**输出**：Markdown 字符串（摘要 + 攻击链详情 + 证据）。

### 4.3 `lens_gold_check`

把"任意引擎的预测技术列表"和 ThreatLens 金标对比打分（Benchmark 入口）。

| 参数 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `predictions_json` | str | ✅ | `{"predictions": {"<数据集文件名>": ["T1059.001", ...]}}` |

**输出**：
```json
{"precision": 0.571, "recall": 1.0, "stage_recall": 1.0}
```

> 口径与 `evaluation/metrics.py` 一致（同一金标、同一归并）。

---

## 5. 实现设计

### 5.1 技术选型
- Python 官方 SDK：`pip install mcp`（`FastMCP` 类，声明式工具注册，stdio transport）。
- 依赖新增：`mcp`（写入 requirements.txt）。
- 复用：`threatlens.core.analysis.run_demo`（构建函数）、`report_writer.build_report`、`evaluation.metrics`（打分函数）。

### 5.2 文件结构
```
threatlens/
└── core/
    └── mcp/
        ├── __init__.py
        └── server.py      # FastMCP 实例 + 3 个工具注册（协议层，调现有函数）
```

### 5.3 启动方式
```bash
python -m threatlens.core.mcp.server        # stdio 模式，等 client 连接
```

### 5.4 工具实现要点
- 每个工具函数：参数校验（缺失/类型错 → 返回 `{"error": "..."}`）→ 调内部函数 → 返回结构化结果。
- `lens_analyze` 内部：`load_telemetry_events(path)` → `build_rule_cache` + `match_all` → `build_chain` → 返回 chain。
- `lens_report` 内部：`json.loads(chain_json)` → `build_report(chain, reviews, mock=mock)`。
- `lens_gold_check` 内部：复用 `metrics_from_chain` 的判分逻辑，对比金标。
- 纯函数、无状态：每次调用独立，不做缓存（保持确定性）。

---

## 6. 配置与使用（client 侧）

MCP client 通过 JSON 配置连接（stdio server）：

```json
{
  "mcpServers": {
    "threatlens": {
      "command": "D:\\AIWorkspace\\ThreatLens\\.venv\\Scripts\\python.exe",
      "args": ["-m", "threatlens.core.mcp.server"],
      "cwd": "D:\\AIWorkspace\\ThreatLens"
    }
  }
}
```

配置示例适配 Claude Desktop / Cursor / WorkBuddy 等支持 MCP 的 client。配置后 client 应能：
1. 列出工具（`lens_analyze` / `lens_report` / `lens_gold_check`）；
2. 调用 `lens_analyze` 传入遥测路径 → 得到攻击链；
3. 调用 `lens_report` 把攻击链转成报告。

---

## 7. 验收标准

- [ ] `python -m threatlens.core.mcp.server` 正常启动（stdio，不报错）。
- [ ] MCP client（或 `mcp` SDK 调试工具）能列出 3 个工具。
- [ ] `lens_analyze`：传入真实遥测文件路径 → 返回 AttackChain（含技术/链/证据）。
- [ ] `lens_report`：传入 chain JSON → 返回 Markdown 报告。
- [ ] `lens_gold_check`：传入预测 JSON → 返回 precision/recall（与现有评测口径一致）。
- [ ] 错误路径：不存在文件 / 非法 JSON → 返回 error，不崩溃。
- [ ] 现有测试不破坏（全量测试绿）。

---

## 8. 实现指引

1. `pip install mcp`（写入 requirements.txt）。
2. 新建 `threatlens/core/mcp/__init__.py` + `server.py`：
   - `FastMCP("threatlens")`；
   - 注册 3 个工具（§4 契约）；
   - `if __name__ == '__main__': mcp.run()`（stdio 默认）。
3. 本地调试：用 `mcp` SDK 的 client 测试工具调用（或 Claude Desktop 配置 §6）。
4. 新增测试（可选）：server 工具函数直接单测（绕过 MCP 传输层，测函数本身）。
5. 全量测试 + README 补"MCP 使用"章节。

---

## 9. 风险与边界

| 风险 | 说明 / 缓解 |
|---|---|
| 文件路径暴露 | 工具接收本地路径——个人本地工具可接受；远程化需加白名单/权限（Non-goals） |
| stdio 阻塞 | server 是长驻进程，等 client 调用；调试时注意进程管理 |
| MCP SDK 版本 | 用官方 `mcp` 包最新稳定版；API 若有变动以官方文档为准 |
| 报告真实 LLM | `lens_report mock=False` 需 `DEEPSEEK_API_KEY`（环境变量，不入库）；失败自动降级 mock（06 设计） |
| 核心逻辑回归 | server 只调现有函数，全量测试兜底 |

---

## 10. 关联与后续

- 分析管道：`02-分析引擎.md`（§4 模块契约）。
- 报告生成：`06-报告真实LLM版.md`（mock/真实分支）。
- 打分口径：`03-评测.md`（§3 口径、金标定义）。
- 后续：HTTP/SSE transport（远程调用）、鉴权、输入格式解析（EVTX）——均按需推进。

*本说明书让 ThreatLens 的分析能力通过 MCP 协议暴露给任意 AI client——AI 应用集成能力展示。*
