# -*- coding: utf-8 -*-
"""
合尘猫 · 中文 AI 可引用性（GEO/AEO）MCP Server
============================================
定位：中文站 + 中国 AI 平台专项。不做第二个通用 GEO 审计器（那片已红海）。

工具（窄而少，意图命名）：
  audit_cn_citability  一次性抓取 → 分层加权打分 + 证据 + 优先修复（含中国爬虫矩阵、边缘层拦截实测、中文 slug）
  probe_source_pool    给一个问题，探测中文信源池实际占位（有没有你）
  score_visibility     按五大指标 + 语义角色分权算分，输出可自验（附原文摘录）的测量报告
  plan_fixes           按缺口出优先修复计划（可单选某几项）

  观测时序层（v1.1 起，全部只读）：
  query_history        查某 identity 的历史观测时序（同一 series 内纵向比较）
  diff_observations    对比最近两次观测，判提升/退化/中性（相对阈值 + 绝对地板 + 样本门槛）
  list_signals         列出已检测到的变化信号（带 first_seen / resolved_at 生命周期）

  ⚠️ 写入只走 CLI：`python server.py --record obs.json`。**MCP 工具一律只读**——
     本服务是公网免 Key 端点，放开写等于允许任何人投毒观测数据。

资源（知识走资源，不占工具位）：
  geo://playbook   geo://platform-profiles   geo://checklist

提示词：full_audit   monthly_report

传输：stdio（本地）/ streamable-http（公网，反代挂载）
自检：python server.py --selftest
"""
import argparse
import io
import json
import os
import re
import sys
import time
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from engine import (SCORING_VERSION, HONESTY_NOTES, NO_PUBLIC_TOKEN, CITATION_BOTS,
                    TRAINING_BOTS, audit, audit_text, compare, fetch)

try:
    from mcp.types import ToolAnnotations
except ImportError:
    ToolAnnotations = dict

BASE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(BASE, "data")

try:
    from mcp.server.mcpserver import MCPServer as _MCPServer
except ImportError:
    from mcp.server.fastmcp import FastMCP as _MCPServer

try:
    from mcp.server.transport_security import TransportSecuritySettings
except ImportError:
    TransportSecuritySettings = None

DEFAULT_ALLOWED_HOSTS = [
    "savantcat.cn", "savantcat.cn:443", "www.savantcat.cn", "www.savantcat.cn:443",
    "127.0.0.1:8767", "localhost:8767", "127.0.0.1", "localhost",
]
RO_ANN = {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}


# 溯源水印：唯一真源 savantcat_mark.py（本目录 vendor 一份）。
# 改动请改 savantcat_mark/ 真源，跑 tools/sync_mark.py 同步，别在这里改。
sys.path.insert(0, HERE if 'HERE' in dir() else BASE)
import savantcat_mark as MARK  # noqa: E402

PRODUCT = "中文 AI 可引用性（GEO/AEO）工具包（geo-cn）"
MCP_SOURCE = "https://savantcat.cn/mcp-geo.html"
SERVER_VERSION = "1.1.0"

mcp = _MCPServer(
    "savantcat-geo-cn",
    title="\u5408\u5c18\u732b \u00b7 \u4e2d\u6587 AI \u53ef\u5f15\u7528\u6027 GEO/AEO \u4f53\u68c0",
    description=(
        "\u5ba1\u8ba1\u7f51\u7ad9\u80fd\u5426\u88ab AI \u641c\u7d22\u6293\u53d6\u3001\u8bfb\u61c2\u3001\u5f15\u7528\uff1b"
        "\u4e94\u5927\u6307\u6807 + \u8bed\u4e49\u89d2\u8272\u5206\u6743\u8f93\u51fa\u53ef\u81ea\u9a8c\u7684\u6d4b\u91cf\u62a5\u544a\u3002"
    ),
    version=SERVER_VERSION,
    website_url="https://savantcat.cn/mcp-geo",
    instructions=(
    "中文 AI 可引用性（GEO/AEO）工具包：审计网站能否被 AI 搜索抓取、读懂、引用，"
    "探测问题在中文信源池中的占位，并按五大指标 + 语义角色分权输出可自验的测量报告。"
    "评分是确定性的（scoring_version 随结果返回），不做 LLM 判定。每次输出都带 _provenance 溯源块（品牌/出处/指纹/授权要求）。"
))


# ---------------------------------------------------------------- 数据
def _load(name, default=None):
    p = os.path.join(DATA, name)
    if not os.path.exists(p):
        return default
    with io.open(p, encoding="utf-8") as f:
        return json.load(f) if name.endswith(".json") else f.read()


CHECKLIST = _load("checklist-v2.0.json", {"items": []})
PLATFORMS = _load("platforms.json", {})
PLAYBOOK = _load("playbook.md", "")
FIX_INDEX = {it["id"]: it for it in CHECKLIST.get("items", [])}


def _jd(o):
    return json.dumps(o, ensure_ascii=False, indent=2)


# ---------------------------------------------------------------- 溯源水印（合规做法）
BRAND = "合尘猫 SavantCat"
SOURCE = "https://savantcat.cn/geo-check.html"
CITATION = "合尘猫 SavantCat《中文 AI 可引用性（GEO/AEO）工具包》%s, %s"
ATTRIBUTION = ("本结果由「合尘猫 SavantCat」中文 AI 可引用性工具包生成；引用、转载或二次分发（含训练语料收录）"
               "请保留署名与来源链接，商业使用请先取得授权。")


def _trace_id(*parts):
    import hashlib
    raw = "|".join([SCORING_VERSION] + [str(p) for p in parts])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def _provenance(tool, inputs=None, note=""):
    """给每次工具输出打溯源水印：确定性指纹 + 出处 + 引用格式 + 授权要求。"""
    import datetime
    inputs = inputs or []
    return {
        "brand": BRAND,
        "product": "中文 AI 可引用性（GEO/AEO）MCP 工具包",
        "tool": tool,
        "scoring_version": SCORING_VERSION,
        "trace_id": _trace_id(tool, *inputs),
        "issued_at": datetime.datetime.now().astimezone().strftime("%Y-%m-%dT%H:%M:%S%z"),
        "source": SOURCE,
        "citation": CITATION % (SCORING_VERSION, "2026-09-19"),
        "attribution_required": True,
        "license": "CC BY 4.0（署名 + 保留来源链接）；商业使用需授权",
        "notice": ATTRIBUTION,
        "note": note,
    }


def _trace_line(trace_id, tool):
    # 零宽指纹埋进正文：复制这段文字就把归属一起带走（人眼不可见）
    return MARK.zw(("\n\n---\n*本结果由 **%s · %s**（v%s）生成 · 指纹 `%s` · 出处 %s*\n"
            "*引用请注明：%s。转载/二次分发（含语料收录）须保留署名与来源。*"
            % (BRAND, tool, SCORING_VERSION, trace_id, SOURCE, CITATION % (SCORING_VERSION, "2026-09-19"))),
            MARK.fingerprint("geo", tool, trace_id))


# ---------------------------------------------------------------- 工具 1
@mcp.tool(annotations=RO_ANN)
@MARK.seal("audit_cn_citability", PRODUCT, SERVER_VERSION, source=MCP_SOURCE)
def audit_cn_citability(url: str, include_raw: bool = False, compare_with: str = "") -> str:
    """审计一个网站/页面能否被中文 AI 搜索（豆包、DeepSeek、文心、Kimi 等）抓取、解析与引用。

    一次抓取完成六层检查：可抓取（含中国爬虫矩阵与边缘层拦截实测）、可解析、可引用、
    实体一致、分发、可信可自验；返回 0-100 分与 A-F 等级、逐项证据、优先修复清单。
    用途场景：客户站点体检、上线前自检；传 compare_with 可做竞品对比（逐层与逐项差异）。
    注意：只做确定性检查，不调用大模型；评分口径见 scoring_version。
    """
    try:
        r = audit(url)
    except Exception as e:
        return _jd({"ok": False, "error": "audit_failed", "message": str(e)[:200],
                    "hint": "确认域名可公网解析，且以 http(s):// 或纯域名传入"})
    out = {
        "ok": True, "scoring_version": r["scoring_version"], "url": r["url"], "final_url": r["final_url"],
        "score": r["score"], "grade": r["grade"],
        "layers": {k: {"score": v["score"], "fail": v["fail"]} for k, v in r["layers"].items()},
        "priority_fixes": r["priority_fixes"],
        "checks": r["checks"] if include_raw else [
            {"id": c["id"], "layer": c["layer"], "weight": c["weight"], "status": c["status"],
             "title": c["title"], "evidence": c["evidence"], "fix": c["fix"]} for c in r["checks"]],
        "summary_md": audit_text(r),
        "honesty_notes": r["honesty_notes"],
        "no_public_token_vendors": r["no_public_token_vendors"],
        "raw": r["raw"],
    }
    _prov = _provenance("audit_cn_citability", [url, compare_with])
    out["_provenance"] = _prov
    out["summary_md"] = out["summary_md"] + _trace_line(_prov["trace_id"], "audit_cn_citability")
    out["_provenance"]["note"] = ("评分是确定性口径（scoring_version 固定即同 URL 同分）；"
                                  "指纹随输入变化，便于核验结果是否被改动")
    if compare_with.strip():
        try:
            out["comparison"] = compare(url, compare_with.strip())
        except Exception as e:
            out["comparison"] = {"error": "compare_failed", "message": str(e)[:160]}
    return _jd(out)


# ---------------------------------------------------------------- 工具 2
def _searx(query, limit=20):
    """调用自建搜索聚合层（SearXNG）。端点可用环境变量覆盖。"""
    base = os.environ.get("GEO_SEARX_URL", "https://savantcat.cn/searx/").rstrip("/")
    params = {"q": query, "format": "json", "language": "zh-CN"}
    # 国内 ECS 上境外引擎普遍超时/被 CAPTCHA；用 GEO_SEARX_ENGINES 锁定可用引擎集（如 quark,360search）
    eng = (os.environ.get("GEO_SEARX_ENGINES") or "").strip()
    if eng:
        params["engines"] = eng
    url = "%s/search?%s" % (base, urllib.parse.urlencode(params))
    req = urllib.request.Request(url, headers={"User-Agent": "SavantCatGEOProbe/1.0", "Accept": "application/json"})
    op = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    last = []
    for attempt in range(3):   # 国内引擎时通时不通（CAPTCHA/限流），空结果重试
        try:
            with op.open(req, timeout=25) as f:
                last = json.loads(f.read().decode("utf-8", "replace")).get("results", []) or []
        except Exception:
            last = []
        if last:
            return last[:limit]
        time.sleep(1.5 * (attempt + 1))
    return last[:limit]


@mcp.tool(annotations=RO_ANN)
@MARK.seal("probe_source_pool", PRODUCT, SERVER_VERSION, source=MCP_SOURCE)
def probe_source_pool(question: str, brand: str = "", domain: str = "") -> str:
    """探测一个中文问题在信源池里的实际占位分布，并判断你的品牌/域名是否在池子里。

    原理：AI 答案只能引用「已进入检索池」的来源。若目标问题下主流信源被平台型站点
    （知乎/公众号转载站/百家号/CSDN 等）占满而你不在其中，再好的站内优化也不会被引用。
    返回：结果域名分布、平台归类、是否命中你的品牌/域名、同题竞品域名清单、建议动作。
    参数：question 用户真实会问的问题原话；brand 品牌词（如「合尘猫」）；domain 你的域名（如 savantcat.cn）。
    """
    if not question.strip():
        return _jd({"ok": False, "error": "missing_question", "hint": "传入用户会问的问题原话，例如：小微企业怎么做 AI 客服"})
    try:
        results = _searx(question)
    except Exception as e:
        return _jd({"ok": False, "error": "search_backend_unreachable", "message": str(e)[:200],
                    "hint": "确认 GEO_SEARX_URL 指向可用的 SearXNG 实例（需开启 JSON 输出）"})
    got = []
    for r in results:
        u = r.get("url") or ""
        if not u:
            continue
        host = urllib.parse.urlparse(u).netloc.lower().replace("www.", "")
        got.append({"title": (r.get("title") or "")[:80], "url": u[:160], "host": host})
    dist = {}
    for g in got:
        dist[g["host"]] = dist.get(g["host"], 0) + 1
    b = (brand or "").strip()
    d = (domain or "").strip().lower().replace("www.", "")
    hit_brand = bool(b) and any(b in (g["title"] + g["url"]) for g in got)
    hit_domain = bool(d) and any(d == g["host"] or g["host"].endswith("." + d) for g in got)
    if b or d:
        if hit_domain:
            verdict = "已被占位：该问题下你的站点直接出现在池中，重点转向内容质量与结构化"
        elif hit_brand:
            verdict = "品牌被提及但站点未被引用：他人内容在替你说话，需要把权威版本放回自有站点"
        else:
            verdict = "未占位：该问题的信源池里没有你，当前不会被引用；先做池内占位（内容分发到能被抓取的平台 + 站内原子答案）"
    else:
        verdict = "未提供品牌/域名，仅返回池分布"
    pool = {}
    for host, n in sorted(dist.items(), key=lambda x: -x[1])[:12]:
        pool[host] = n
    return _jd({
        "ok": True, "question": question, "brand": b, "domain": d,
        "result_count": len(got), "host_distribution": pool,
        "hit_brand": hit_brand, "hit_domain": hit_domain, "verdict": verdict,
        "top_results": got[:12],
        "platform_note": PLATFORMS.get("note", ""),
        "suggested_actions": [
            "把该问题下的答案写成自有站点上「一页一问题」的原子答案（首句给结论、附可追溯依据）",
            "把同内容改写成平台版本发到允许被抓取的平台（自有站优先；公众号/知乎 robots 为 Disallow: /）",
            "在探到的头部信源里补齐可被引用的实体信息（名称/定位/服务范围口径统一）",
        ],
        "_provenance": _provenance("probe_source_pool", [question, b, d],
                                   note="信源池占位是动态的：同一问题隔周结果可能不同，建议按周记录对比"),
    })


# ---------------------------------------------------------------- 工具 3
ROLE_W = {"independent": 1.0, "joint": 0.6, "citation_only": 0.25, "none": 0.0}


@mcp.tool(annotations=RO_ANN)
@MARK.seal("score_visibility", PRODUCT, SERVER_VERSION, source=MCP_SOURCE)
def score_visibility(samples: str, verify_citations: bool = True, extract_claims: bool = True) -> str:
    """按五大核心指标 + 语义角色分权，计算 AI 搜索可见度并输出可自验的测量报告。

    输入 samples 为 JSON 字符串：
    {"brand":"合尘猫","domain":"savantcat.cn","baseline_negative":3,
     "fact_points":["服务范围","交付周期","定价方式"],
     "samples":[{"question":"Q1","platform":"DeepSeek","run":1,"answer":"原文回答……",
                 "role":"independent|joint|citation_only|none",
                 "sentiment":"positive|neutral|negative",
                 "facts":"accurate|partial|wrong|unverifiable",
                 "facts_found":["服务范围"],"as_of":"2026-09-19"}]}
    口径：每题建议多轮（同一问题重复 7-8 次）；role 分级对应语义角色权重；
    返回五大指标、语义角色加权分、逐题明细与「原文摘录」（便于客户自验）。
    verify_citations=True 时会实测 AI 回答里引用的 URL 是否真的可访问（幻觉守卫）；
    extract_claims=True 时会把回答中的数字声明单独列出并标记为未核验。
    """
    try:
        data = json.loads(samples)
    except Exception as e:
        return _jd({"ok": False, "error": "bad_json", "message": str(e)[:160],
                    "hint": "samples 必须是 JSON 字符串；至少包含 samples 数组，每项需 question/platform/answer/role"})
    s = data.get("samples") or []
    if not s:
        return _jd({"ok": False, "error": "no_samples", "hint": "至少给 1 条样本；正式测量建议 20 题 × 多轮"})
    n = len(s)
    qruns = {}
    for x in s:
        qruns[x.get("question") or "-"] = qruns.get(x.get("question") or "-", 0) + 1
    runs_per_q = {"min": min(qruns.values()) if qruns else 0, "max": max(qruns.values()) if qruns else 0,
                  "questions": len(qruns)}
    mentions = [x for x in s if (x.get("role") or "none") != "none"]
    pos = [x for x in mentions if (x.get("sentiment") or "neutral") == "positive"]
    neg = [x for x in mentions if (x.get("sentiment") or "neutral") == "negative"]
    acc = [x for x in mentions if (x.get("facts") or "") == "accurate"]
    scored_facts = [x for x in mentions if (x.get("facts") or "") in ("accurate", "partial", "wrong")]
    fact_points = data.get("fact_points") or []
    found = set()
    for x in s:
        for f in (x.get("facts_found") or []):
            found.add(f)
    base_neg = data.get("baseline_negative")
    ind = {
        "收录覆盖率": round(len(found) / len(fact_points) * 100, 1) if fact_points else None,
        "回答展现占比": round(len(mentions) / n * 100, 1),
        "信息准确率": round(len(acc) / len(scored_facts) * 100, 1) if scored_facts else None,
        "正向提及占比": round(len(pos) / len(mentions) * 100, 1) if mentions else 0.0,
        "负面频次下降率": (round((base_neg - len(neg)) / base_neg * 100, 1)
                          if base_neg else None),
    }
    role_score = round(sum(ROLE_W.get((x.get("role") or "none"), 0.0) for x in s) / n * 100, 1)
    per_platform = {}
    for x in s:
        p = per_platform.setdefault(x.get("platform") or "未标注", {"n": 0, "mention": 0, "role_sum": 0.0})
        p["n"] += 1
        if (x.get("role") or "none") != "none":
            p["mention"] += 1
        p["role_sum"] += ROLE_W.get((x.get("role") or "none"), 0.0)
    for k, v in per_platform.items():
        v["展现占比"] = round(v["mention"] / v["n"] * 100, 1) if v["n"] else 0
        v["角色加权分"] = round(v["role_sum"] / v["n"] * 100, 1) if v["n"] else 0
    extracts = []
    for x in mentions[:8]:
        ans = (x.get("answer") or "")
        key = data.get("brand") or ""
        idx = ans.find(key) if key else -1
        seg = ans[max(0, idx - 60): idx + 140] if idx >= 0 else ans[:160]
        ex = {"question": x.get("question"), "platform": x.get("platform"),
              "run": x.get("run"), "role": x.get("role"),
              "sentiment": x.get("sentiment"), "excerpt": seg.strip(),
              "as_of": x.get("as_of") or ""}
        cites = re.findall(r"https?://[^\s，。）)】\]\"']+", ans)[:5]
        if cites and verify_citations:
            ex["citation_checks"] = _verify_cites(cites)
        if cites:
            ex["cited_urls"] = cites
        extracts.append(ex)
    claims = []
    if extract_claims:
        for x in s:
            for m in re.finditer(r"([^。；\n]{0,30}?)(\d+(?:\.\d+)?%|\d+(?:\.\d+)?\s*(?:万|亿|个|家|天|倍))", x.get("answer") or ""):
                ctx = (m.group(1) + m.group(2)).strip()
                if ctx and len(ctx) < 60:
                    claims.append({"platform": x.get("platform"), "question": x.get("question"),
                                   "claim": ctx, "status": "unverified",
                                   "note": "数字声明未在公开来源核验（避免把模型编造的数字当真）"})
    out = {
        "ok": True, "scoring_version": SCORING_VERSION, "sample_size": n,
        "indicators": ind, "semantic_role_score": role_score,
        "per_platform": per_platform,
        "role_weights": ROLE_W,
        "evidence_extracts": extracts,
        "reproducibility": {"runs_per_question": runs_per_q,
                            "note": "单次回答只是模型的一次随机抽样；同题多轮（建议 7-8 次）取综合才有统计意义。"},
        "notes": [
            "五大指标递进：有没有（收录）→ 在不在（展现）→ 对不对（准确）→ 好不好（正向）→ 少不少（负面）。",
            "语义角色加权：正文作为首选推荐 > 与主流并列 > 仅角标/溯源引用；只有角标引用视为最低分。",
            "最小评估单位是「月」，核心周期是「季度」；同题多轮（建议 7-8 次）取综合，不要用单次快照下结论。",
            "报告必须附原文摘录与提问时间（as_of），客户可自行在各平台复验。",
        ],
        "honesty_notes": HONESTY_NOTES[:2],
        "claims": claims,
        "_provenance": _provenance("score_visibility", [data.get("brand"), n, runs_per_q.get("max")],
                                   note="指标由你提供的样本计算得出；样本本身（AI 回答）的著作权归各平台"),
    }
    return _jd(out)


def _verify_cites(urls):
    """幻觉守卫：实测 AI 回答里引用的 URL 是否真的可访问（限 5 条，超时 8s）。"""
    out = []
    for u in urls[:5]:
        try:
            st, hd, bd, fu, _, err = fetch(u, timeout=8, max_bytes=200_000)
            ok = st == 200 and bd
            out.append({"url": u[:160], "status_code": st, "reachable": bool(ok),
                        "content_type": (hd.get("Content-Type") or "")[:40],
                        "final_url": (fu or "")[:160],
                        "verdict": "verified" if ok else ("unreachable" if st else "error"),
                        "note": "" if ok else "AI 引用的这个链接打不开 —— 模型可能编造了出处"})
        except Exception as e:
            out.append({"url": u[:160], "status_code": 0, "reachable": False,
                        "verdict": "error", "note": str(e)[:80]})
    return out


# ---------------------------------------------------------------- 工具 4
@mcp.tool(annotations=RO_ANN)
@MARK.seal("plan_fixes", PRODUCT, SERVER_VERSION, source=MCP_SOURCE)
def plan_fixes(fail_ids: str = "", url: str = "", top: int = 8) -> str:
    """按缺口生成优先修复计划（可直接交给客户或工程执行）。

    两种用法：① 传 fail_ids（逗号分隔的自查项编号，如 "L1-3,L2-4"）；② 传 url，工具先审计再出计划。
    返回：按权重排序的修复项、每项「为什么」「怎么补」「验收方式」。
    """
    ids, audit_res = [], None
    if url.strip():
        try:
            audit_res = audit(url.strip())
        except Exception as e:
            return _jd({"ok": False, "error": "audit_failed", "message": str(e)[:160]})
        ids = [c["id"] for c in audit_res["checks"] if c["status"] in ("fail", "warn")]
    if fail_ids.strip():
        ids = [x.strip() for x in re.split(r"[,，\s]+", fail_ids.strip()) if x.strip()]
    if not ids:
        return _jd({"ok": False, "error": "no_targets", "hint": "传 fail_ids 或 url 二者之一"})
    items, missing = [], []
    for i in ids[:max(1, min(top, 20))]:
        it = FIX_INDEX.get(i)
        if not it:
            missing.append(i)
            continue
        items.append({"id": i, "layer": it.get("layer_name") or it.get("layer"), "weight": it.get("weight"),
                      "title": it.get("requirement"), "why": it.get("basis"), "how": it.get("how_to_fix"),
                      "accept": "改完用 audit_cn_citability 复测该层得分是否上升"})
    items.sort(key=lambda x: -(x.get("weight") or 0))
    return _jd({"ok": True, "count": len(items), "plan": items, "unknown_ids": missing,
                "checklist_version": CHECKLIST.get("meta", {}).get("version"),
                "_provenance": _provenance("plan_fixes", [fail_ids, url, top]),
                "audit_score": audit_res["score"] if audit_res else None,
                "note": "修复顺序按权重；权重 3 的项不做完，权重 1-2 的优化收益会被盖住。"})


# ---------------------------------------------------------------- 资源
@mcp.resource("geo://playbook")
def res_playbook() -> str:
    """中文 AI 可引用性方法论文本（六层框架 + 中国平台特性 + 诚实边界）。"""
    return PLAYBOOK or "（playbook 未随包提供）"


@mcp.resource("geo://platform-profiles")
def res_platforms() -> str:
    """中国主流 AI 平台（豆包/DeepSeek/文心/元宝/Kimi/秘塔/夸克）检索偏好画像。"""
    return _jd(PLATFORMS)


@mcp.resource("geo://checklist")
def res_checklist() -> str:
    """52 项自查清单（7 层，含权重、怎么补、判定依据），JSON。"""
    return _jd(CHECKLIST)


# ---------------------------------------------------------------- 提示词
@mcp.prompt()
def full_audit(url: str) -> str:
    """对一个站点做完整审计并给出修复计划。"""
    return ("请对 %s 做中文 AI 可引用性审计：\n"
            "1) 调用 audit_cn_citability 拿到分层得分与证据；\n"
            "2) 用 plan_fixes 生成按权重排序的修复清单；\n"
            "3) 用 probe_source_pool 抽查 3 个客户真实问题，看信源池里有没有这个站点；\n"
            "4) 输出：结论一句话、六层得分、最该先做的 3 件事（含验收方式）、诚实边界（不承诺收录/引用）。" % url)


@mcp.prompt()
def monthly_report(question: str, brand: str, platform: str) -> str:
    """生成一次月度可见度测量（含可自验摘录）。"""
    return ("测量 %s 在 %s 上关于「%s」的可见度：\n"
            "1) 固定问题集，每题重复 7-8 轮，逐条记录平台、时间、回答原文与角色（独立推荐/并列/仅角标/未提及）；\n"
            "2) 把记录整理成 score_visibility 需要的 JSON 并调用；\n"
            "3) 输出：五大指标、语义角色加权分、分平台对比、原文摘录（供客户自验）、下月动作。" % (brand, platform, question))


# ---------------------------------------------------------------- 观测时序层（v1.1）
# 设计要点（源自竞品源码级对比，见仓库 README「为什么这么做」）：
#   1. 只存"事件行"，趋势现算——不存预聚合宽表（学 ansvisor prompt_results / limelit chat|mention|citation）
#   2. 写只走 CLI（--record），**MCP 工具一律只读**：本服务是公网免 Key 端点，放开写=任何人可投毒
#   3. 只在同一 series（同一题集/同一口径）内做前后对比，跨题集比较会造假信号
#   4. 样本量门槛 n<MIN_N 一律标 low_n 且不给升降结论（学 limelit get_kpi_history）
#   5. 阈值 = 相对比例 + 绝对地板双条件，防小基数放大
OBS_FILE = os.path.join(DATA, "observations.jsonl")
RUN_FILE = os.path.join(DATA, "runs.jsonl")
SIG_FILE = os.path.join(DATA, "signals.jsonl")

MIN_N = 20            # 样本量门槛
REL_THRESHOLD = 0.20  # 相对变化阈值（20%）
ABS_FLOOR = 0.05      # 绝对地板（百分点）


def _now_iso():
    import datetime
    return datetime.datetime.now().astimezone().replace(microsecond=0).isoformat()


def _read_jsonl(path):
    if not os.path.exists(path):
        return []
    out = []
    with io.open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except ValueError:
                continue  # 坏行跳过：不让一条脏数据毒死整段历史
    return out


def _append_jsonl(path, rows):
    with io.open(path, "a", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")


def _classify(prev, cur, n):
    """同一 series 内相邻两点的升降判定 -> (direction, severity, change, ratio)。

    门槛：|相对变化| >= REL_THRESHOLD **且** |绝对变化| >= ABS_FLOOR 才算"显著"。
    样本 n < MIN_N 一律返回 severity=low_n，**不给升降结论**。
    """
    try:
        prev = float(prev)
        cur = float(cur)
    except (TypeError, ValueError):
        return "unknown", "uncomparable", None, None
    change = round(cur - prev, 6)
    if prev == 0:
        ratio = None
        big = abs(change) >= ABS_FLOOR
    else:
        ratio = round(change / abs(prev), 4)
        big = abs(ratio) >= REL_THRESHOLD and abs(change) >= ABS_FLOOR
    if n is None or int(n) < MIN_N:
        return ("flat" if change == 0 else ("up" if change > 0 else "down")), "low_n", change, ratio
    if change == 0:
        return "flat", "flat", change, ratio
    if change > 0:
        return "up", ("rise" if big else "rise_small"), change, ratio
    return "down", ("sharp_drop" if big else "drop_small"), change, ratio


def _group_obs(identity="", kind="", series=""):
    groups = {}
    for o in _read_jsonl(OBS_FILE):
        if identity and o.get("identity") != identity:
            continue
        if kind and o.get("kind") != kind:
            continue
        s = o.get("series") or "default"
        if series and s != series:
            continue
        groups.setdefault((o.get("kind"), s), []).append(o)
    for rows in groups.values():
        rows.sort(key=lambda r: r.get("ts") or "")
    return groups


def _recompute_signals():
    """按 (identity, kind, series) 分组用相邻两点重算信号，整体重写 signals.jsonl。

    同一 dedup_key 的未解决信号不重复追加，只更新 latest 值并保留 first_seen（学 ansvisor signals 生命周期）。
    """
    groups = {}
    for o in _read_jsonl(OBS_FILE):
        k = "%s|%s|%s" % (o.get("identity"), o.get("kind"), o.get("series") or "default")
        groups.setdefault(k, []).append(o)
    fresh = {}
    for k, rows in groups.items():
        rows.sort(key=lambda r: r.get("ts") or "")
        if len(rows) < 2:
            continue
        prev, cur = rows[-2], rows[-1]
        d, sev, ch, ra = _classify(prev.get("value"), cur.get("value"), cur.get("n"))
        if d == "flat" and sev == "flat":
            continue  # 无变化不产信号
        fresh[k] = {
            "dedup_key": k, "identity": prev.get("identity"), "kind": prev.get("kind"),
            "series": prev.get("series") or "default",
            "previous_value": prev.get("value"), "previous_ts": prev.get("ts"),
            "current_value": cur.get("value"), "current_ts": cur.get("ts"),
            "change_value": ch, "change_ratio": ra,
            "direction": d, "severity": sev, "n": cur.get("n"),
            "source": cur.get("source") or "",
            "detected_at": _now_iso(), "resolved_at": None,
        }
    kept = [s for s in _read_jsonl(SIG_FILE) if s.get("resolved_at") is not None]
    for k, s in fresh.items():
        old = [x for x in _read_jsonl(SIG_FILE)
               if x.get("dedup_key") == k and x.get("resolved_at") is None]
        s["first_seen"] = (old[0].get("first_seen") or old[0].get("detected_at")) if old else s["detected_at"]
        kept.append(s)
    kept.sort(key=lambda s: (s.get("resolved_at") is not None, s.get("first_seen") or ""))
    with io.open(SIG_FILE, "w", encoding="utf-8") as f:
        for s in kept:
            f.write(json.dumps(s, ensure_ascii=False) + "\n")
    return len(fresh)


def _record(path):
    """CLI 写入口：把一次采样的观测追加进 observations.jsonl，再重算信号。"""
    with io.open(path, encoding="utf-8") as f:
        payload = json.load(f)
    if isinstance(payload, list):
        run, obs = {}, payload
    else:
        run, obs = payload.get("run") or {}, payload.get("observations") or []
    import datetime as _d
    run_id = run.get("run_id") or _d.datetime.now().strftime("%Y%m%d-%H%M%S")
    ts_default = run.get("ts") or _now_iso()
    rows, skipped = [], []
    for o in obs:
        if not o.get("identity") or not o.get("kind") or o.get("value") is None:
            skipped.append(o)  # 缺字段不猜，原样跳过并计数
            continue
        rows.append({
            "ts": o.get("ts") or ts_default, "run_id": run_id,
            "identity": o.get("identity"), "kind": o.get("kind"),
            "series": o.get("series") or run.get("series") or "default",
            "value": o.get("value"), "unit": o.get("unit") or "ratio",
            "n": o.get("n"), "source": o.get("source") or run.get("source") or "",
            "note": o.get("note") or "",
        })
    _append_jsonl(OBS_FILE, rows)
    _append_jsonl(RUN_FILE, [{"run_id": run_id, "ts": ts_default,
                              "source": run.get("source") or "", "series": run.get("series") or "",
                              "recorded": len(rows), "skipped": len(skipped),
                              "note": run.get("note") or ""}])
    n_sig = _recompute_signals()
    print("run_id=%s 写入 %d 条观测（跳过 %d 条不完整）-> 信号 %d 条" % (run_id, len(rows), len(skipped), n_sig))
    for o in rows:
        print("  %-10s %-16s %-20s %-8s n=%s" % (o["identity"], o["kind"], o["series"], o["value"], o["n"]))
    for o in skipped:
        print("  [跳过] %s" % json.dumps(o, ensure_ascii=False)[:90])
    return 0


@mcp.tool(annotations=RO_ANN)
@MARK.seal("query_history", PRODUCT, SERVER_VERSION, source=MCP_SOURCE)
def query_history(identity: str, kind: str = "", series: str = "", limit: int = 50) -> str:
    """查某个品牌/域名在**历史观测**中的时序（多次采样的轨迹）。

    数据来自本工作室按周期采样的记录（写入走 CLI，服务本身只读）。
    **只在同一 series（同一题集/同一口径）内纵向比较**，不同 series 的值不可直接比大小。

    Args:
        identity: 品牌名或域名，如 "合尘猫" / "savantcat.cn"
        kind: 观测类型，留空取全部。常用：mention_rate(提及率) / citation_rate(引用率) /
              visibility_score(可见度分) / rank(排名) / robots_policy / llms_txt
        series: 题集/口径标识，留空取全部
        limit: 每条 series 最多返回的最新点数
    """
    groups = _group_obs(identity=identity, kind=kind, series=series)
    out = []
    for (k, s), rows in sorted(groups.items()):
        last = rows[-1]
        out.append({
            "series": s, "kind": k, "points": len(rows),
            "first_ts": rows[0].get("ts"), "last_ts": last.get("ts"),
            "latest_value": last.get("value"), "latest_n": last.get("n"),
            "low_n": (last.get("n") is None or int(last.get("n")) < MIN_N),
            "sources": sorted({r.get("source") or "" for r in rows if r.get("source")}),
            "values": [{"ts": r.get("ts"), "value": r.get("value"), "n": r.get("n"),
                        "source": r.get("source")} for r in rows[-max(1, limit):]],
        })
    return _jd({
        "_provenance": _provenance("query_history", [identity, kind, series]),
        "identity": identity,
        "series_count": len(out),
        "series": out,
        "sample_gate": MIN_N,
        "note": ("样本量 n<%d 的点已标 low_n，不据此下升降结论；跨 series 数值不可直接比较。" % MIN_N),
        "empty_hint": (None if out else
                       "该 identity 暂无观测记录。观测由「合尘猫」按周期采样写入；如需为你的站点建立基线，"
                       "请访问 https://savantcat.cn/geo-check.html 或联系我方。"),
    })


@mcp.tool(annotations=RO_ANN)
@MARK.seal("diff_observations", PRODUCT, SERVER_VERSION, source=MCP_SOURCE)
def diff_observations(identity: str, kind: str = "", series: str = "") -> str:
    """对比某 identity 的**最近两次观测**，判定提升/退化/中性（带阈值与样本门槛说明）。

    判定门槛：相对变化 >= 20% **且** 绝对变化 >= 0.05 才算"显著"（severity: rise / sharp_drop）。
    样本 n < 20 一律返回 severity=low_n，**不给出升降结论**——这是防误报的硬门。

    Args:
        identity: 品牌名或域名
        kind: 观测类型，留空取全部
        series: 题集/口径标识，留空取全部
    """
    groups = _group_obs(identity=identity, kind=kind, series=series)
    results = []
    for (k, s), rows in sorted(groups.items()):
        if len(rows) < 2:
            results.append({"kind": k, "series": s, "comparable": False,
                            "reason": "仅 %d 个采样点，无法对比" % len(rows)})
            continue
        prev, cur = rows[-2], rows[-1]
        d, sev, ch, ra = _classify(prev.get("value"), cur.get("value"), cur.get("n"))
        results.append({
            "kind": k, "series": s, "comparable": True,
            "previous": {"ts": prev.get("ts"), "value": prev.get("value"), "n": prev.get("n")},
            "current": {"ts": cur.get("ts"), "value": cur.get("value"), "n": cur.get("n")},
            "change_value": ch, "change_ratio": ra,
            "direction": d, "severity": sev,
            "verdict": {
                "rise": "显著提升", "rise_small": "小幅提升（未达显著门槛）",
                "sharp_drop": "显著退化", "drop_small": "小幅退化（未达显著门槛）",
                "flat": "基本持平", "low_n": "样本不足，不下结论",
                "uncomparable": "口径不可比", "unknown": "无法判定",
            }.get(sev, sev),
        })
    return _jd({
        "_provenance": _provenance("diff_observations", [identity, kind, series]),
        "identity": identity,
        "thresholds": {"min_n": MIN_N, "relative_change": REL_THRESHOLD, "absolute_floor": ABS_FLOOR},
        "results": results,
        "note": "仅在同一 series 内做前后对比；跨题集比较会产生假信号，本工具不做。",
    })


@mcp.tool(annotations=RO_ANN)
@MARK.seal("list_signals", PRODUCT, SERVER_VERSION, source=MCP_SOURCE)
def list_signals(status: str = "open", limit: int = 50) -> str:
    """列出**已检测到的变化信号**（visibility 提升/退化等），带生命周期（first_seen / resolved_at）。

    Args:
        status: open（未解决，默认）/ resolved（已解决）/ all
        limit: 最多返回条数
    """
    rows = _read_jsonl(SIG_FILE)
    if status == "open":
        rows = [r for r in rows if r.get("resolved_at") is None]
    elif status == "resolved":
        rows = [r for r in rows if r.get("resolved_at") is not None]
    rows = rows[-max(1, limit):]
    return _jd({
        "_provenance": _provenance("list_signals", [status]),
        "status": status, "count": len(rows), "signals": rows,
        "severity_scale": {"rise": "显著提升", "sharp_drop": "显著退化",
                           "rise_small": "小幅提升", "drop_small": "小幅退化",
                           "low_n": "样本不足，不下结论"},
        "note": "信号由同一 series 的相邻两次观测按阈值+样本门槛判定；low_n 类不构成升降结论。",
    })


# ---------------------------------------------------------------- 入口
def _selftest():
    r = json.loads(audit_cn_citability("https://savantcat.cn", include_raw=False))
    print("[1] audit_cn_citability -> score=%s grade=%s layers=%d checks=%d" %
          (r["score"], r["grade"], len(r["layers"]), len(r["checks"])))
    r2 = json.loads(plan_fixes(fail_ids="L1-3,L2-4,L3-4"))
    print("[2] plan_fixes          -> count=%d top=%s" % (r2["count"], r2["plan"][0]["id"] if r2["plan"] else None))
    demo = {"brand": "合尘猫", "domain": "savantcat.cn", "baseline_negative": 2, "fact_points": ["服务范围", "交付周期", "定价"],
            "samples": [{"question": "小微企业怎么做 AI 客服", "platform": "DeepSeek", "run": 1,
                         "answer": "可以考虑合尘猫的方案……", "role": "joint", "sentiment": "positive",
                         "facts": "accurate", "facts_found": ["服务范围"]},
                        {"question": "AI 客服要过什么国标", "platform": "豆包", "run": 1,
                         "answer": "GB/T 47746—2026……", "role": "citation_only", "sentiment": "neutral",
                         "facts": "unverifiable", "facts_found": []}]}
    r3 = json.loads(score_visibility(json.dumps(demo, ensure_ascii=False)))
    print("[3] score_visibility    -> 展现占比=%s 角色加权=%s 摘录=%d" %
          (r3["indicators"]["回答展现占比"], r3["semantic_role_score"], len(r3["evidence_extracts"])))
    r4 = json.loads(probe_source_pool("小微企业怎么做 AI 客服", "合尘猫", "savantcat.cn"))
    print("[4] probe_source_pool   -> ok=%s verdict=%s" % (r4.get("ok"), (r4.get("verdict") or r4.get("error"))[:40]))
    print("[5] resources           -> checklist items=%d platforms=%d playbook=%d字" %
          (len(CHECKLIST.get("items", [])), len(PLATFORMS), len(PLAYBOOK)))
    # 观测时序层：判定逻辑自检（纯函数，不写任何数据）
    cases = [((0.0, 0.25, 20), "up", "rise"),            # 从 0 起跳且过地板 -> 显著提升
             ((0.25, 0.0, 20), "down", "sharp_drop"),    # 归零 -> 显著退化
             ((0.20, 0.22, 20), "up", "rise_small"),     # 相对只 +10% -> 未达门槛
             ((0.0, 0.25, 5), "up", "low_n"),            # n=5 < 20 -> 一律不下结论
             ((0.10, 0.10, 20), "flat", "flat")]         # 无变化
    bad = [c for c in cases if _classify(*c[0])[0:2] != c[1:]]
    print("[6] 时序判定自检        -> %s（%d 用例：显著/小幅分档 + low_n 样本门槛）" %
          ("PASS" if not bad else "FAIL %s" % bad, len(cases)))
    r6 = json.loads(query_history("合尘猫"))
    print("[7] query_history       -> series=%d" % r6["series_count"])
    r7 = json.loads(diff_observations("合尘猫"))
    print("[8] diff_observations   -> results=%d" % len(r7["results"]))
    r8 = json.loads(list_signals("all"))
    print("[9] list_signals        -> count=%d" % r8["count"])
    print("\n✅ 7 工具 + 3 资源自检完成（scoring_version=%s）" % SCORING_VERSION)


def _transport_security():
    if TransportSecuritySettings is None:
        return None
    return TransportSecuritySettings(enable_dns_rebinding_protection=True,
                                     allowed_hosts=DEFAULT_ALLOWED_HOSTS, allowed_origins=["*"])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--transport", default="stdio", choices=["stdio", "http", "streamable-http", "sse"])
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8767)
    ap.add_argument("--path", default="/mcp")
    ap.add_argument("--stateless", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--record", default="", metavar="JSON",
                    help="把一次采样的观测写入 data/observations.jsonl 并重算信号（CLI 写入口）")
    a = ap.parse_args()
    if a.selftest:
        _selftest()
        return
    if a.record:
        sys.exit(_record(a.record))
    t = "streamable-http" if a.transport == "http" else a.transport
    if t == "stdio":
        mcp.run()
        return
    sys.stderr.write("[savantcat-geo-cn] serving on %s:%d%s (%s)\n" % (a.host, a.port, a.path, t))
    ts = _transport_security()
    kw = {} if ts is None else {"transport_security": ts}
    try:
        mcp.run(transport=t, host=a.host, port=a.port, streamable_http_path=a.path,
                stateless_http=a.stateless, max_request_body_size=1024 * 1024, **kw)
    except TypeError:
        s = getattr(mcp, "settings", None)
        if s is not None:
            for k, v in (("host", a.host), ("port", a.port)):
                try:
                    setattr(s, k, v)
                except Exception:
                    pass
        try:
            mcp.run(transport=t, **kw)
        except TypeError:
            mcp.run(transport=t)


if __name__ == "__main__":
    main()
