# evaluation/baseline/ — 历史基线快照（只读）

> 约定：`evaluation/` 根目录的 `metrics.json` / `report.md` 是**当前最新结果**（`run_eval` 每次覆盖）；
> `baseline/` 下是按版本固化的**历史快照**（复制保存，不再被覆盖），供跨版本对比。

## 快照列表

| 目录 | 版本 | 说明 | 日期 |
|---|---|---|---|
| `v1-script-baseline/` | v1 脚本版 | 纯规则主干（无 LLM），P2 baseline 摸底结果 | 2026-08-31 |

## 快照命名规范

`v<序号>-<方案>-<描述>/`，例：`v1-script-baseline`、`v2-agent-lowscore-review`。
每个快照目录内含：`metrics.json` + `report.md`（+ 可选 `reviews_agent.jsonl` 等调用记录）。

## v1 快照关键数字（2026-08-31）

- 规则：官方版 2815 条 / 官方+自定义版 2816 条
- 两版：precision=36.4%、recall=100%、阶段召回 100%、顺序一致率 1.0
- 决策：`llm-low-score-review`（LLM 定位 = 低分证据复核）
- 复现：`python -m threatlens.core.evaluation.run_eval`（连跑两遍逐字节一致）

## 对比方法

新版本（如 Agent 版）跑完后，复制为 `vN-.../`，然后与 v1 逐字段对比（precision/recall/阶段召回/证据明细），结果写入对应 `report.md` 的对比表。
