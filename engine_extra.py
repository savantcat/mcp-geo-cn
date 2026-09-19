# -*- coding: utf-8 -*-
"""
engine_extra —— 把国外成熟 GEO 工具的评分条款（按可判定性筛选）并入我们的引擎
================================================================================
来源与采纳（标注清楚，避免"抄了不认"）：
  · OrtaMarco `seo-geo-mcp-server`：geo_audit 七项权重（crawler 25 / SSR 20 / schema 15 /
    extractable 15 / authorship 10 / freshness 8 / depth 7）；robots 5xx=disallow-all；
    canonical host 四变体收敛；og:image 实测可加载；训练类 vs 引用类爬虫分离；
    vendor 自认"不可执行"的 robots 块单列。
  · abhi725 `growth-mcp`：Access&indexability 30% / Entity&structure 25% /
    Citation-ready content 30%（FAQ、问句标题、answer-first、列表表格、事实密度）/ Trust 15%。
  · StudioMeyer GEO：实体一致（碎片化实体 = 引用少 2.8×）、sitemap-first 新鲜度、
    retrieval quality（text-to-HTML 比、JS 依赖标记、noscript 兜底、meta refresh、canonical 错配）、
    页面类型感知权重（KDD 2024）、N>1 采样、幻觉守卫（核验 LLM 引用的 URL）。
  · geo.gg：九类评分（citability 的五个维度、品牌权威五平台、schema sameAs 十平台、
    E-E-A-T 含一票项、分平台 readiness、主题覆盖六维）。
本模块只加"能确定性判定"的部分；需要 LLM 判断的（E-E-A-T 主观项、主题覆盖深度）不评分，只给人工清单。
"""
import json
import re
import urllib.parse

# 厂商文档自认「可能忽略 robots」的爬虫（报告为不可执行，而不是干净的 block）
UNENFORCEABLE = {
    "Perplexity-User": "厂商文档称可能忽略 robots.txt",
    "ChatGPT-User": "厂商文档称可能忽略 robots.txt",
    "meta-externalfetcher": "厂商文档称可能忽略 robots.txt",
}
# 厂商未公开 UA、无法用 robots 管控
NO_TOKEN_VENDORS = ["DeepSeek（未公开抓取 UA）", "xAI / Grok", "Microsoft Copilot（沿用 Bing 索引）"]
# 实体关联的十平台（国外口径），中国场景替换/补入：微博、知乎、掘金、CSDN、公众号、Gitee、B站
SAMEAS_CANONICAL_CN = ["weibo.com", "zhihu.com", "juejin.cn", "csdn.net", "gitee.com", "bilibili.com",
                       "xiaohongshu.com", "douban.com", "github.com", "baike.baidu.com"]
# 权威中文信源（做"引用强度"判定的白名单）
AUTHORITY_CN = ["gov.cn", "samr.gov.cn", "openstd.samr.gov.cn", "miit.gov.cn", "cac.gov.cn", "std.samr.gov.cn",
                "edu.cn", "ac.cn", "cssn.cn", "cnki.net", "arxiv.org", "w3.org", "schema.org"]


def _add(ck, cid, layer, weight, status, evidence, fix, title):
    ck.append({"id": cid, "layer": layer, "weight": weight, "status": status,
               "title": title, "evidence": evidence, "fix": fix})


def extra_checks(html, headers, lds, txt, origin, fetch, url, ck):
    """在 engine.audit 里被调用；fetch 为 engine.fetch（复用 SSRF 防护与 UA）。"""
    types = set()
    blob = json.dumps(lds, ensure_ascii=False)

    # ---------- L2-7 meta robots / X-Robots-Tag（noindex/nosnippet 是隐形杀手）----------
    mrob = re.findall(r'(?is)<meta[^>]+name=["\']robots["\'][^>]*content=["\']([^"\']+)', html)
    xrob = (headers.get("X-Robots-Tag") or "")
    bad = [v for v in mrob + [xrob] if re.search(r"noindex|none|nosnippet|noarchive", v, re.I)]
    if bad:
        _add(ck, "L1-7", "L1", 3, "fail", "检测到禁止索引/摘要指令：%s" % "；".join(bad)[:80],
             "移除 noindex/nosnippet（AI 与搜索引擎一致地尊重它）", "未被 noindex 拦截")
    else:
        _add(ck, "L1-7", "L1", 3, "ok", "无 noindex/nosnippet（meta robots：%s；X-Robots-Tag：%s）"
             % (",".join(mrob)[:40] or "无", xrob[:40] or "无"), "", "未被 noindex 拦截")

    # ---------- L1-8 robots.txt 异常：5xx 视同全站禁止 ----------
    st_r, _, body_r, _, _, _ = fetch(origin + "/robots.txt")
    if st_r and st_r >= 500:
        _add(ck, "L1-8", "L1", 3, "fail", "robots.txt 返回 %d —— 搜索引擎按「全站禁止」处理" % st_r,
             "修复 robots.txt 的可达性（服务端错误比缺失严重得多）", "robots.txt 状态健康")
    elif st_r == 200 and re.search(r"(?m)^\s*Disallow:\s*/\s*$", body_r.decode("utf-8", "replace") or ""):
        _add(ck, "L1-8", "L1", 3, "fail", "robots.txt 存在 `Disallow: /` 全站禁止",
             "确认这是有意为之；若是历史遗留，删除该行", "robots.txt 状态健康")
    else:
        _add(ck, "L1-8", "L1", 3, "ok", "robots.txt HTTP %s，无全站禁止" % st_r, "", "robots.txt 状态健康")

    # ---------- L2-8 canonical host 四变体收敛 ----------
    p = urllib.parse.urlparse(url)
    host = p.netloc.lower()
    apex = host[4:] if host.startswith("www.") else host
    variants = ["http://" + apex, "https://" + apex, "http://www." + apex, "https://www." + apex]
    codes = []
    for v in variants[:4]:
        s2, _, _, fu, _, _ = fetch(v, timeout=8)
        codes.append("%s→%s" % (v.replace("://", "://")[:26], s2))
    uniq = set(c.split("→")[1] for c in codes)
    moved = [c for c in codes if c.split("→")[1] in ("301", "302", "0")]
    if len(uniq) == 1 and "200" in uniq:
        _add(ck, "L2-8", "L2", 2, "ok", "四变体均 %s（%s）" % (uniq.pop(), "；".join(codes)), "", "主机名规范收敛")
    else:
        _add(ck, "L2-8", "L2", 2, "warn", "四变体状态不一致：%s" % "；".join(codes),
             "把 http/https 与 apex/www 收敛到唯一规范地址（301），避免权重分散", "主机名规范收敛")

    # ---------- L2-9 og:image 实测可加载 ----------
    ogi = re.search(r'(?is)<meta[^>]+property=["\']og:image["\'][^>]*content=["\']([^"\']+)', html)
    if ogi:
        img = urllib.parse.urljoin(url, ogi.group(1))
        si, hi, bi, _, _, ei = fetch(img, timeout=8)
        ctype = (hi.get("Content-Type") or "")
        if si == 200 and ("image" in ctype or len(bi) > 1000):
            _add(ck, "L2-9", "L2", 1, "ok", "og:image 可加载（HTTP %s，%s，%d 字节）" % (si, ctype[:30], len(bi)), "", "og:image 真实可用")
        else:
            _add(ck, "L2-9", "L2", 1, "warn", "og:image 不可用（HTTP %s %s）" % (si, ctype[:30]),
                 "修好 og:image（社交与部分抓取器会取它作摘要图）", "og:image 真实可用")
    else:
        _add(ck, "L2-9", "L2", 1, "warn", "未设置 og:image", "补 og:image 并确认可公开访问", "og:image 真实可用")

    # ---------- L3-6 列表与表格（可被整段摘走的结构）----------
    lists, tables = len(re.findall(r"(?is)<(ul|ol)[^>]*>", html)), len(re.findall(r"(?is)<table[^>]*>", html))
    dt = len(re.findall(r"(?is)<(dl|dt)[^>]*>", html))
    tot = lists + tables + dt
    _add(ck, "L3-6", "L3", 2, "ok" if tot >= 3 else "warn",
         "列表 %d 个、表格 %d 个、定义列表 %d 个" % (lists, tables, dt),
         "" if tot >= 3 else "把要点做成列表/表格（模型最易整块摘走，正文长段落最难）", "有可摘走的结构")

    # ---------- L3-7 text-to-HTML 比 / 薄内容 ----------
    ratio = len(txt) / max(len(html), 1)
    words = len(re.findall(r"[\u4e00-\u9fff]|[a-zA-Z]+", txt))
    if ratio < 0.03 or words < 200:
        _add(ck, "L3-7", "L3", 2, "fail", "正文/HTML 比 %.3f，正文 %d 字 —— 偏薄或模板占比重" % (ratio, words),
             "提高有效正文占比（多写事实与依据，或把无关模板移出正文区）", "正文充实度")
    elif ratio < 0.06 or words < 600:
        _add(ck, "L3-7", "L3", 2, "warn", "正文/HTML 比 %.3f，正文 %d 字" % (ratio, words),
             "补足到能独立回答该页主题的篇幅", "正文充实度")
    else:
        _add(ck, "L3-7", "L3", 2, "ok", "正文/HTML 比 %.3f，正文 %d 字" % (ratio, words), "", "正文充实度")

    # ---------- L3-8 自包含（不依赖上下文）----------
    dep = re.findall(r"如上所述|如前所述|接着上文|见上一节|详见下文|上文提到", txt)
    _add(ck, "L3-8", "L3", 2, "ok" if not dep else "warn",
         "上下文依赖表述 %d 处%s" % (len(dep), ("：" + "、".join(dep[:3])) if dep else ""),
         "" if not dep else "去掉「如上所述」类表述（模型抓的是单页，摘走一段必须能独立读懂）", "段落自包含")

    # ---------- L3-9 图片 alt 覆盖率 ----------
    imgs = re.findall(r"(?is)<img\b[^>]*>", html)
    if imgs:
        noalt = [i for i in imgs if not re.search(r'alt\s*=\s*["\'][^"\']+["\']', i)]
        cov = 1 - len(noalt) / len(imgs)
        _add(ck, "L3-9", "L3", 1, "ok" if cov >= 0.8 else "warn",
             "图片 %d 张，有 alt 的占 %.0f%%" % (len(imgs), cov * 100),
             "" if cov >= 0.8 else "给图片补 alt（文本通道仍是 AI 读图的主要方式）", "图片 alt 覆盖")

    # ---------- L4-4 实体碎片化（只看实体节点的 name；FAQ 的 name 不算）----------
    ENT_TYPES = ("Organization", "Person", "LocalBusiness", "Brand", "WebSite")
    ent_names = []

    def _collect(o):
        if isinstance(o, dict):
            t = o.get("@type")
            ts = t if isinstance(t, list) else [t]
            if any(x in ENT_TYPES for x in ts if x) and isinstance(o.get("name"), str):
                ent_names.append(o["name"].strip())
            for v in o.values():
                _collect(v)
        elif isinstance(o, list):
            for v in o:
                _collect(v)

    for n in lds:
        _collect(n)
    variants = set(ent_names)
    if not variants:
        _add(ck, "L4-4", "L4", 2, "warn", "结构化数据里没有可核验的实体名称（Organization/Person）",
             "补 Organization 或 Person 的 name，作为模型确认「你是谁」的依据", "实体名称唯一")
    elif len(variants) >= 3:
        _add(ck, "L4-4", "L4", 2, "warn", "实体名称有 %d 种表述：%s" % (len(variants), "、".join(list(variants)[:4])),
             "统一实体名称口径（碎片化实体会让模型认不出是同一个主体）", "实体名称唯一")
    elif len(variants) == 2 and not any(set(variants) == {a, b} and a in b for a, b in
                                        [(x, y) for x in variants for y in variants]):
        _add(ck, "L4-4", "L4", 2, "warn", "实体名称有 2 种表述：%s（若非「全称/简称」关系建议统一）"
             % "、".join(sorted(variants)), "确认是「品牌名 + 品牌全称」的从属关系，否则统一口径", "实体名称唯一")
    else:
        _add(ck, "L4-4", "L4", 2, "ok", "实体名称口径一致：%s" % "、".join(sorted(variants)[:3]), "", "实体名称唯一")

    # ---------- L4-5 sameAs 覆盖中文平台 ----------
    urls_in_blob = re.findall(r'https?://[^"\s]+', blob)
    hit = sorted({d for d in SAMEAS_CANONICAL_CN if any(d in u for u in urls_in_blob)})
    _add(ck, "L4-5", "L4", 2, "ok" if len(hit) >= 3 else "warn",
         "sameAs 命中的中文平台：%s（%d 个）" % ("、".join(hit) or "无", len(hit)),
         "" if len(hit) >= 3 else "把微博/知乎/掘金/CSDN/Gitee 等主页补进 sameAs（中国平台是 AI 的主要信源池）", "sameAs 覆盖中文平台")

    # ---------- L3-10 引用强度（外链权威 + 引语 + 统计）----------
    ext = re.findall(r'href=["\']https?://([^/"\']+)', html)
    auth = sorted({h for h in ext if any(h.endswith(a) or ("." + a) in h for a in AUTHORITY_CN)})
    quotes = len(re.findall(r"[「『\"][^「『\"]{6,60}[」』\"]", txt))
    stats = len(re.findall(r"\d+(?:\.\d+)?%|\d{4}年|第[一二三四五六七八九十百]+条", txt))
    score = (2 if auth else 0) + (1 if quotes >= 2 else 0) + (1 if stats >= 5 else 0)
    _add(ck, "L3-10", "L3", 2, "ok" if score >= 3 else "warn",
         "权威外链 %d 个%s；引语 %d 处；统计/条款 %d 处" % (len(auth), ("（" + "、".join(auth[:3]) + "）") if auth else "", quotes, stats),
         "" if score >= 3 else "补权威出处（政府/标准/学术）、他人原话引语、可核对数字——这三样是论文验证过的引用提升项", "引用强度（依据+引语+数字）")

    # ---------- L5-5 访问文件清单（存在性报告，不计分）----------
    access = {}
    for f in ("/robots.txt", "/sitemap.xml", "/llms.txt", "/ai.txt", "/indexnow.json", "/rss.xml", "/feed.xml"):
        s3, _, _, _, _, _ = fetch(origin + f, timeout=8)
        access[f] = s3
    presents = [k for k, v in access.items() if v == 200]
    _add(ck, "L5-5", "L5", 0, "info", "AI 相关访问文件：%s" % ("、".join(presents) or "无"),
         "按需补 sitemap.xml / rss.xml；llms.txt 与 ai.txt 保留无害但别投入", "访问文件清单（不计分）")

    # ---------- L5-6 sitemap-first 新鲜度 ----------
    s4, _, b4, _, _, _ = fetch(origin + "/sitemap.xml", timeout=10)
    lm = re.findall(r"<lastmod>\s*([0-9]{4}-[0-9]{2}-[0-9]{2})", b4.decode("utf-8", "replace") if b4 else "")
    recent = sorted(lm)[-1] if lm else ""
    if recent:
        y = int(recent[:4])
        _add(ck, "L5-6", "L5", 2, "ok" if y >= 2026 else "warn",
             "sitemap 最新 lastmod：%s（共 %d 条含 lastmod）" % (recent, len(lm)),
             "" if y >= 2026 else "更新 sitemap 的 lastmod（新鲜度是引用机会信号）", "内容新鲜度")
    else:
        _add(ck, "L5-6", "L5", 2, "warn", "sitemap 未提供 lastmod", "补 lastmod；常青页按季度刷新可重回引用圈", "内容新鲜度")

    # ---------- L6-4 页面类型感知（KDD 2024：不同页型权重不同）----------
    tset = set()
    for n in lds:
        if isinstance(n, dict):
            t = n.get("@type")
            tset |= set(t if isinstance(t, list) else [t] if t else [])
    guess = ("文章页" if re.search(r"/(blog|articles?|posts?|answers?|knowledge)", url)
             else "产品/服务页" if re.search(r"/(product|service|pricing|tools?)", url)
             else "首页" if urllib.parse.urlparse(url).path in ("", "/") else "普通页")
    _add(ck, "L6-4", "L6", 0, "info",
         "页面类型（结构化推断）：%s；JSON-LD 类型：%s" % (guess, "、".join(sorted(x for x in tset if x))[:80]),
         "文章页重 5 字段+日期；产品/服务页重 Offer/FAQ；首页重 Organization+事实段。按页型配权重才是成熟做法",
         "页面类型识别（不计分）")

    # ---------- L6-5 需要人工判断的项（不评分，只列清单）----------
    _add(ck, "L6-5", "L6", 0, "info",
         "以下项需人工/LLM 判断，本工具不评分：E-E-A-T（经验/专业/权威/可信，含一票项）、主题覆盖深度（核心概念/场景/实施/对比/价格/趋势六维）、分平台答案差异",
         "用 score_visibility 的 N>1 采样 + 人工复核去做，别用单一模型的一次回答下结论", "人工判断项清单（不计分）")
    return ck
