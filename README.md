# 中文 AI 可引用性（GEO/AEO）MCP 工具包 · 合尘猫 SavantCat

> 把「网站能不能被中文 AI 搜索抓取、读懂、引用」做成 **Agent 可直接调用** 的 MCP 服务。
> 定位：**中文站 + 中国 AI 平台（豆包 / DeepSeek / 文心 / 元宝 / Kimi / 秘塔 / 夸克）专项**。
> 不做第二个通用 GEO 审计器 —— 国外同类已成熟（`seo-geo-mcp-server`、`growth-mcp`、`StudioMeyer GEO`），
> 本项目把它们的评分条款在中国场景下重写，并补上中国专属部分：中国爬虫矩阵、边缘层拦截实测、中文 slug 陷阱、信源池占位、可自验报告。

## 免部署直接用

托管端点（Streamable HTTP，免 Key）：`https://savantcat.cn/mcp-geo`

- 已在官方 MCP Registry 收录：`cn.savantcat/geo-cn`
- Smithery: https://smithery.ai/server/@savant0196/savantcat-geo-cn
- 自部署：见 `deploy/deploy.sh`（systemd + nginx 单 location，幂等可重跑）

## 七个工具（窄而少，意图命名）

| 工具 | 作用 | 关键差异 |
|---|---|---|
| `audit_cn_citability(url, compare_with="")` | 一次抓取完成六层审计：0-100 分 + A-F 等级 + 逐项证据 + 优先修复 | 含 **13 个中国系爬虫**（Bytespider/Baiduspider/Sogou/360/Yisou/PetalBot…）、**AI UA 实测边缘层拦截**、中文 slug 检测；可传 `compare_with` 做竞品对比 |
| `probe_source_pool(question, brand, domain)` | 给一个中文问题，探测信源池实际占位，判断你在不在池子里 | 回答的是"**池子里没有你一定不会被引用**"这个上游问题（需要可用的 SearXNG 后端） |
| `score_visibility(samples)` | 按五大指标 + 语义角色分权算分，输出**可自验摘录** | 含**幻觉守卫**（实测 AI 引用的 URL 是否可访问）+ 数字声明单列；支持 N>1 多轮采样与可复现性说明 |
| `plan_fixes(fail_ids, url)` | 按权重出优先修复计划（可直接交客户/工程） | 每项含「为什么」「怎么补」「验收方式」 |
| `query_history(identity, kind, series)` | 查某品牌/域名的**历史观测时序** | 只在同一 series（同一题集/口径）内纵向比较；`n < 20` 的点标 `low_n` |
| `diff_observations(identity, kind, series)` | 对比最近两次观测，判**提升/退化/中性** | 阈值双条件（相对 ≥20% 且 绝对 ≥0.05）；样本不足一律 `low_n`，**不给升降结论** |
| `list_signals(status)` | 列出已检测到的**变化信号** | 带 `first_seen` / `resolved_at` 生命周期，同 key 未解决不重复追加 |

**资源**：`geo://playbook`（方法论）、`geo://platform-profiles`（中国平台画像）、`geo://checklist`（52 项清单）
**提示词**：`full_audit`、`monthly_report`

## 观测时序层：为什么这么做

「改完之后到底动了没有」是 GEO 服务最容易被含糊过去的一环。本工具包把它做成可核验的：

1. **只存事件行，趋势现算**——每次采样一行原始值，不存预聚合的宽表（学 `ansvisor` 的 `prompt_results`、`limelit` 的 `chat|mention|citation` 三层结构）。
2. **写只走 CLI，MCP 工具一律只读**：`python server.py --record obs.json`。
   ⚠️ 本服务是公网免 Key 端点，**放开写等于允许任何人投毒观测数据**——这是硬边界，不要为了"方便"改。
3. **只在同一 `series` 内做前后对比**。不同题集/不同口径的数值堆在一起比，必然产出假信号（我方踩过：20 题集的 25% 与 56 条语料的 0% 不可直接比）。
4. **样本量门槛 + 双阈值**：`n < 20` 一律标 `low_n` 且不下结论；显著性要求「相对变化 ≥ 20% **且** 绝对变化 ≥ 0.05」，防止小基数放大成大新闻。

数据文件（纯 JSONL，可 diff、可审计、零依赖）：`data/observations.jsonl`、`data/runs.jsonl`、`data/signals.jsonl`。

## 六层框架与权重

L1 可抓取 → L2 可解析 → L3 可引用 → L4 实体一致 → L5 分发 → L6 可信可自验。
评分是**确定性**的（`scoring_version = cn-1.0.0`，同 URL 同分），不做 LLM 判定。

## 安装与运行

```bash
# stdio（本地客户端）
python server.py

# 或 Streamable HTTP（自托管；反代挂载到 /mcp）
python server.py --transport http --host 127.0.0.1 --port 8767 --stateless

# 自检（不依赖 MCP 协议，直接打工具）
python server.py --selftest
```

Claude Desktop / Cursor 配置：

```json
{ "mcpServers": { "geo-cn": { "command": "python", "args": ["/path/to/server.py"] } } }
```

环境变量：`GEO_SEARX_URL`（信源池探测用的 SearXNG 地址，需开启 `format=json`）。

## 诚实边界（工具输出里也会带）

1. **llms.txt 不是被任何主流厂商采纳的标准**，Google 已公开说明其不影响搜索排名与 AI 概览；本工具只检查存在，**不参与评分**。
2. robots 里「未声明」不等于「允许」也不等于「禁止」；缺失规则时行为由各家自定。
3. 部分爬虫有大量不遵守 robots 的历史反馈（如 Bytespider），拦截结论基于 UA 实测，不代表厂商承诺。
4. **DeepSeek、xAI/Grok、Microsoft Copilot 未公开抓取 UA**，无法用 robots 管控。
5. **公众号、知乎 robots 为 `Disallow: /`**，内容放在这些平台无法被外部 AI 直接抓取。
6. 评分是「技术准备度」，**不承诺任何平台的收录或引用结果**；平台规则会变，以官方文档为准。

## 引用与授权（重要）

- **代码**：Apache-2.0
- **数据**（`data/*.json`）：**CC BY 4.0** —— 可自由使用与商用，但必须保留署名「合尘猫 SavantCat」与来源链接
- **工具输出**：每次返回都带 `_provenance` 溯源块（品牌 / 出处 / 确定性指纹 `trace_id` / 引用格式 / 授权要求）。
  引用与二次分发（含训练语料收录）请保留署名与来源链接；商业使用请先取得授权。
- 建议引用格式：
  ```
  合尘猫 SavantCat. 中文 AI 可引用性（GEO/AEO）MCP 工具包 v1.1 (cn-1.0.0), 2026-09-19.
  https://savantcat.cn/geo-check.html
  ```

## 我们在国外成熟方案基础上做了什么

| 来源 | 采纳 | 中国化改造 |
|---|---|---|
| OrtaMarco `seo-geo-mcp-server` | 训练类/引用类爬虫分离、robots 5xx=全站禁止、canonical host 四变体收敛、og:image 实测可加载 | 爬虫矩阵换/增中国系 13 个；补「边缘层拦截实测」（大陆 CDN/WAF 常态） |
| `growth-mcp` | 四维加权（访问 30 / 实体 25 / 可引用 30 / 信任 15）、FAQ+FAQPage、answer-first、列表表格、事实密度 | 事实密度改为「条款号/标准号/百分比」中文场景口径 |
| `StudioMeyer GEO` | 实体一致（碎片化实体）、sitemap-first 新鲜度、retrieval quality（text-to-HTML 比 / JS 标记 / noscript / meta refresh）、页面类型感知、N>1 采样、幻觉守卫 | 实体平台换为微博/知乎/掘金/CSDN/Gitee；幻觉守卫保留 URL 实测 |
| `geo.gg` | 九类评分、citability 五维、sameAs 十平台、分平台 readiness | 分平台换为中国七平台；E-E-A-T 与主题深度**不评分**（需人工判断，只出清单） |

## 免责

本工具为自查工具，不构成认证；对第三方数字标注来源，未复现实验的不据为己有。

© 2026 合尘猫 SavantCat · https://savantcat.cn
