# -*- coding: utf-8 -*-
"""
合尘猫 · 中文 AI 可引用性审计引擎（engine）
=========================================
只做「确定性、可当场复算、带证据」的检查；不调用任何大模型、不臆测。
设计约束（照 2026 MCP 规范）：
  - 每个检查返回 {id, layer, weight, status, evidence, fix}
  - SSRF 防护（拒私网/环回/链路本地，逐跳校验）、响应体积上限、固定 UA、超时
  - 结果带 scoring_version，可复现
中国平台专项：AI 爬虫矩阵含字节/百度/搜狗/360 系；边缘层拦截实测；中文 slug 检查。
"""
import gzip
import io
import ipaddress
import json
import re
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib

SCORING_VERSION = "cn-1.0.0"
UA = "SavantCatGEOAudit/1.0 (+https://savantcat.cn/geo-check.html)"
MAX_BYTES = 3 * 1024 * 1024
TIMEOUT = 12

# ---- AI 爬虫矩阵：引用类（决定能否被 AI 答案引用）/ 训练类（决定是否进模型）----
CITATION_BOTS = {
    "OAI-SearchBot": "ChatGPT 搜索索引",
    "ChatGPT-User": "ChatGPT 实时抓取",
    "PerplexityBot": "Perplexity 索引",
    "ClaudeBot": "Claude 抓取",
    "Claude-User": "Claude 实时抓取",
    "Bytespider": "豆包/字节系",
    "Baiduspider": "百度（文心/百度AI）",
    "Baiduspider-render": "百度渲染",
    "Sogou web spider": "搜狗（腾讯系）",
    "360Spider": "360",
    "YisouSpider": "夸克/UC",
    "PetalBot": "华为花瓣搜索",
    "Googlebot": "Google AI 概览依赖索引",
}
TRAINING_BOTS = {"GPTBot": "OpenAI 训练", "CCBot": "Common Crawl", "anthropic-ai": "Anthropic 训练",
                 "Google-Extended": "Gemini 训练", "Applebot-Extended": "Apple 训练"}
# 无公开 UA 文档、无法通过 robots 管控的厂商（如实标注，不假装能管）
NO_PUBLIC_TOKEN = ["xAI / Grok", "Microsoft Copilot（沿用 Bing 索引）", "DeepSeek（未公开抓取 UA）"]

HONESTY_NOTES = [
    "llms.txt 不是被任何主流厂商采纳的标准，本工具只检查其存在与形状，不参与评分。",
    "robots.txt 里「未声明」不等于「允许」，也不等于「禁止」：缺失规则时行为由各家自行决定，本工具按「未声明」如实标注。",
    "Bytespider 等部分爬虫有大量不遵守 robots 的历史反馈，本工具的拦截结论基于 UA 实测，不代表厂商承诺。",
    "公众号、知乎等平台 robots 为 Disallow: /，内容放在这些平台无法被 AI 直接抓取。",
]


# ------------------------------------------------------------------ 抓取
class FetchError(Exception):
    pass


def _guard(url):
    p = urllib.parse.urlparse(url)
    if p.scheme not in ("http", "https"):
        raise FetchError("只支持 http/https")
    host = p.hostname or ""
    if not host or "." not in host:
        raise FetchError("域名无效：%s" % host)
    try:
        infos = socket.getaddrinfo(host, None)
    except Exception as e:
        raise FetchError("DNS 解析失败：%s（%s）" % (host, e))
    for info in infos:
        ip = info[4][0]
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if a.is_private or a.is_loopback or a.is_link_local or a.is_reserved or a.is_multicast:
            raise FetchError("拒绝访问内网/保留地址：%s" % ip)
    return p


def fetch(url, ua=UA, timeout=TIMEOUT, max_bytes=MAX_BYTES, redirect_limit=6):
    """抓取并返回 (status, headers, body_bytes, final_url, hops, error)。逐跳做 SSRF 校验。"""
    hops = 0
    cur = url
    while True:
        p = _guard(cur)
        req = urllib.request.Request(cur, headers={
            "User-Agent": ua, "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8", "Accept-Encoding": "gzip, deflate",
        })
        op = urllib.request.build_opener(
            urllib.request.HTTPRedirectHandler() if False else urllib.request.HTTPRedirectHandler(),
            urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=ssl.create_default_context()))
        try:
            with op.open(req, timeout=timeout) as f:
                raw = f.read(max_bytes + 1)
                enc = (f.headers.get("Content-Encoding") or "").lower()
                if "gzip" in enc:
                    try:
                        raw = gzip.decompress(raw)
                    except Exception:
                        pass
                elif "deflate" in enc:
                    try:
                        raw = zlib.decompress(raw, -zlib.MAX_WBITS)
                    except Exception:
                        pass
                return f.status, dict(f.headers), raw[:max_bytes], f.geturl(), hops, None
        except urllib.error.HTTPError as e:
            body = b""
            try:
                body = e.read(max_bytes)
            except Exception:
                pass
            if e.code in (301, 302, 303, 307, 308) and hops < redirect_limit:
                loc = e.headers.get("Location") or ""
                if loc:
                    hops += 1
                    cur = urllib.parse.urljoin(cur, loc)
                    continue
            return e.code, dict(e.headers or {}), body, cur, hops, None
        except Exception as e:
            return 0, {}, b"", cur, hops, str(e)[:160]


# ------------------------------------------------------------------ HTML 工具
def visible_text(html):
    s = re.sub(r"(?is)<(script|style|noscript|svg|template)[^>]*>.*?</\1>", " ", html)
    s = re.sub(r"(?is)<!--.*?-->", " ", s)
    s = re.sub(r"(?s)<[^>]+>", " ", s)
    s = s.replace("&nbsp;", " ").replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">")
    return re.sub(r"\s+", " ", s).strip()


def decode(raw, headers):
    ct = (headers.get("Content-Type") or "").lower()
    if "gb" in ct or "gb2312" in ct or "gbk" in ct:
        for c in ("gb18030", "gbk"):
            try:
                return raw.decode(c)
            except Exception:
                pass
    for c in ("utf-8", "gb18030"):
        try:
            return raw.decode(c)
        except Exception:
            pass
    return raw.decode("utf-8", "replace")


def ld_json(html):
    out = []
    for m in re.finditer(r'(?is)<script[^>]+type=["\']application/ld\+json["\'][^>]*>(.*?)</script>', html):
        try:
            out.append(json.loads(m.group(1).strip()))
        except Exception:
            out.append({"_parse_error": m.group(1)[:120]})
    return out


def ld_types(node, acc=None):
    acc = acc if acc is not None else []
    if isinstance(node, dict):
        t = node.get("@type")
        if isinstance(t, str):
            acc.append(t)
        elif isinstance(t, list):
            acc += [x for x in t if isinstance(x, str)]
        for v in node.values():
            ld_types(v, acc)
    elif isinstance(node, list):
        for v in node:
            ld_types(v, acc)
    return acc


def robot_rules(txt):
    """极简 robots 解析：返回 {ua: {'allow':[], 'disallow':[], 'declared':bool}}"""
    groups, cur = {}, []
    for line in (txt or "").splitlines():
        line = line.split("#")[0].strip()
        if not line or ":" not in line:
            continue
        k, v = line.split(":", 1)
        k, v = k.strip().lower(), v.strip()
        if k == "user-agent":
            cur = [v]
            groups.setdefault(v, {"allow": [], "disallow": [], "declared": True})
        elif k in ("allow", "disallow") and cur:
            for ua in cur:
                groups[ua][k].append(v)
    return groups


def _match_rule(path, rules):
    """最长匹配优先（robots 标准做法），返回 'deny'/'allow'/None"""
    best, res = -1, None
    for pat in rules.get("disallow", []):
        if pat and path.startswith(pat.replace("*", "")) and len(pat) > best:
            best, res = len(pat), "deny"
    for pat in rules.get("allow", []):
        if pat and path.startswith(pat.replace("*", "")) and len(pat) >= best and pat:
            best, res = len(pat), "allow"
    return res


def bot_allowed(groups, bot, path="/"):
    """按 robots 语义给 UA 判定：专属组 > 通配组 > 未声明。"""
    for key in list(groups.keys()):
        if key == "*" or bot.lower().startswith(key.lower()) or key.lower().startswith(bot.lower()):
            r = _match_rule(path, groups[key])
            if r:
                return r, key
    if "*" in groups:
        r = _match_rule(path, groups["*"])
        if r:
            return r, "*"
    return "undeclared", None


# ------------------------------------------------------------------ 检查项
def _ck(cid, layer, weight, status, evidence, fix, title):
    return {"id": cid, "layer": layer, "weight": weight, "status": status,
            "title": title, "evidence": evidence, "fix": fix}


def audit(url, timeout=TIMEOUT):
    if not url.startswith("http"):
        url = "https://" + url
    p = urllib.parse.urlparse(url)
    origin = "%s://%s" % (p.scheme, p.netloc)
    checks, raw_meta = [], {}

    # ---------- L1 可抓取 ----------
    st, hd, body, final, hops, err = fetch(url, timeout=timeout)
    html = decode(body, hd) if body else ""
    txt = visible_text(html)
    raw_meta.update({"status": st, "final_url": final, "hops": hops, "bytes": len(body),
                     "ttfb_ms": None, "visible_text_chars": len(txt), "error": err})

    if err or st == 0:
        checks.append(_ck("L1-1", "L1", 3, "fail", "首页抓取失败：%s" % (err or "未知"), "修复服务器可达性与 TLS 配置后再测", "首页可被抓取"))
    elif st >= 400:
        checks.append(_ck("L1-1", "L1", 3, "fail", "首页返回 HTTP %d" % st, "确保首页 200（AI 爬虫不处理错误页）", "首页可被抓取"))
    else:
        checks.append(_ck("L1-1", "L1", 3, "ok", "首页 HTTP %d，%d 字节，%d 跳" % (st, len(body), hops), "", "首页可被抓取"))

    # 跳转链
    if hops == 0:
        checks.append(_ck("L1-2", "L1", 2, "ok", "无重定向，直达", "", "跳转链 ≤3 跳"))
    elif hops <= 2:
        checks.append(_ck("L1-2", "L1", 2, "warn", "经过 %d 次跳转" % hops, "把重定向收敛到 1 跳内，直接给最终地址（AI 爬虫容忍度低于搜索引擎）", "跳转链 ≤3 跳"))
    else:
        checks.append(_ck("L1-2", "L1", 2, "fail", "经过 %d 次跳转" % hops, "重定向过多会丢失抓取，收敛到 1-2 跳", "跳转链 ≤3 跳"))

    # robots.txt + AI 爬虫矩阵
    rs, rh, rb, _, _, rerr = fetch(origin + "/robots.txt", timeout=timeout)
    rtxt = decode(rb, rh) if rb else ""
    groups = robot_rules(rtxt) if rs == 200 else {}
    if rs != 200:
        checks.append(_ck("L1-3", "L1", 3, "warn", "robots.txt 缺失（HTTP %s）" % rs,
                          "补一份 robots.txt：显式 Allow AI 爬虫并写 Sitemap 地址；缺失时各家行为不一致", "robots.txt 存在且放行 AI 爬虫"))
    else:
        blocked = []
        for b in CITATION_BOTS:
            r, _k = bot_allowed(groups, b)
            if r == "deny":
                blocked.append(b)
        if blocked:
            checks.append(_ck("L1-3", "L1", 3, "fail", "robots 拦截了引用类爬虫：%s" % "、".join(blocked),
                              "在 robots.txt 为这些 UA 分组 Allow（它们决定你能否被 AI 答案引用）", "robots.txt 放行引用类 AI 爬虫"))
        else:
            decl = [b for b in CITATION_BOTS if any(k.lower().startswith(b.lower()[:6]) for k in groups)]
            checks.append(_ck("L1-3", "L1", 3, "ok" if decl else "warn",
                              "未拦截引用类爬虫；显式声明的有 %d/%d 个%s" % (len(decl), len(CITATION_BOTS),
                                                                            "" if decl else "（建议显式声明）"),
                              "" if decl else "把主要引用类爬虫显式 Allow 一次，便于审计与排障", "robots.txt 放行引用类 AI 爬虫"))

    # 边缘层/UA 实测：换个 AI 爬虫 UA 再抓，比对
    st_bot, _, body_bot, _, _, err_bot = fetch(url, ua="Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot)", timeout=timeout)
    if st_bot and st_bot != st:
        checks.append(_ck("L1-4", "L1", 3, "fail", "AI 爬虫 UA 实测返回 %s，普通 UA 返回 %s —— 边缘层/WAF 很可能在拦 AI" % (st_bot, st),
                          "在白名单放行 AI 爬虫 UA（CDN/WAF 规则优先于 robots.txt）", "AI 爬虫 UA 实测可达"))
    else:
        checks.append(_ck("L1-4", "L1", 3, "ok", "AI 爬虫 UA 实测返回 %s，与普通 UA 一致" % (st_bot or "?（无响应）"), "", "AI 爬虫 UA 实测可达"))

    # JS 空壳
    if len(txt) < 200:
        checks.append(_ck("L1-5", "L1", 3, "fail", "剥除脚本后可见正文仅 %d 字符 —— 内容很可能靠 JS 渲染" % len(txt),
                          "把关键内容服务端渲染/静态化（AI 爬虫不执行 JavaScript）", "正文在 HTML 中可见"))
    elif len(txt) < 600:
        checks.append(_ck("L1-5", "L1", 3, "warn", "剥除脚本后可见正文 %d 字符，偏少" % len(txt),
                          "确认核心结论不依赖 JS 注入", "正文在 HTML 中可见"))
    else:
        checks.append(_ck("L1-5", "L1", 3, "ok", "剥除脚本后可见正文 %d 字符" % len(txt), "", "正文在 HTML 中可见"))

    # 中文 slug
    sm_st, sm_hd, sm_b, _, _, _ = fetch(origin + "/sitemap.xml", timeout=timeout)
    sm = decode(sm_b, sm_hd) if sm_b and sm_st == 200 else ""
    locs = re.findall(r"<loc>\s*([^<\s]+)", sm)
    cjk = [u for u in locs if re.search(r"[\u4e00-\u9fff]", urllib.parse.unquote(u))]
    if cjk:
        checks.append(_ck("L1-6", "L1", 2, "fail", "sitemap 里有 %d 个中文/非 ASCII slug（如 %s）—— 中文路径极易 404" % (len(cjk), cjk[0][:60]),
                          "改用纯英文 slug，并把旧地址 301 到新地址", "URL 使用 ASCII slug"))
    else:
        checks.append(_ck("L1-6", "L1", 2, "ok", "sitemap %d 条，无中文 slug" % len(locs), "", "URL 使用 ASCII slug"))

    # ---------- L2 可解析 ----------
    tm = re.search(r"(?is)<title[^>]*>(.*?)</title>", html)
    title = (tm.group(1).strip() if tm else "")
    dm = re.search(r'(?is)<meta[^>]+name=["\']description["\'][^>]*content=["\'](.*?)["\']', html)
    desc = (dm.group(1).strip() if dm else "")
    if not title:
        checks.append(_ck("L2-1", "L2", 3, "fail", "缺 <title>", "补 30-60 字的唯一标题", "有唯一 title"))
    elif len(title) > 90:
        checks.append(_ck("L2-1", "L2", 3, "warn", "title %d 字，偏长：%s" % (len(title), title[:60]), "收敛到 60 字内，把结论前置", "有唯一 title"))
    else:
        checks.append(_ck("L2-1", "L2", 3, "ok", "title %d 字：%s" % (len(title), title[:70]), "", "有唯一 title"))
    if not desc:
        checks.append(_ck("L2-2", "L2", 3, "fail", "缺 meta description", "补 60-120 字 description（模型判断是否引用你的首选字段）", "有完整 meta description"))
    elif len(desc) < 40:
        checks.append(_ck("L2-2", "L2", 3, "warn", "description 仅 %d 字（可能被引号截断）：%s" % (len(desc), desc), "description 里的英文引号要转义，否则属性被提前截断", "有完整 meta description"))
    else:
        checks.append(_ck("L2-2", "L2", 3, "ok", "description %d 字" % len(desc), "", "有完整 meta description"))

    h1 = re.findall(r"(?is)<h1[^>]*>(.*?)</h1>", html)
    h2 = re.findall(r"(?is)<h2[^>]*>(.*?)</h2>", html)
    h3 = re.findall(r"(?is)<h3[^>]*>(.*?)</h3>", html)
    if len(h1) == 1 and (len(h2) + len(h3)) >= 3:
        checks.append(_ck("L2-3", "L2", 2, "ok", "H1×1、H2×%d、H3×%d" % (len(h2), len(h3)), "", "标题层级清晰"))
    else:
        checks.append(_ck("L2-3", "L2", 2, "warn" if h1 else "fail", "H1×%d、H2×%d、H3×%d" % (len(h1), len(h2), len(h3)),
                          "一页一个 H1；正文用 H2/H3 分层（模型按标题层级切分）", "标题层级清晰"))

    lds = ld_json(html)
    types = ld_types(lds)
    org = any(t == "Organization" for t in types)
    site = any(t == "WebSite" for t in types)
    same_as = []
    for n in lds:
        for m in re.finditer(r'"sameAs"\s*:\s*(\[[^\]]*\]|"[^"]*")', json.dumps(n, ensure_ascii=False)):
            same_as += re.findall(r'https?://[^"\s\]]+', m.group(1))
    if not lds:
        checks.append(_ck("L2-4", "L2", 3, "fail", "页面没有任何 JSON-LD", "至少加 Organization 与 WebSite；列表/产品页按类型加 BreadcrumbList/ItemList/FAQPage", "有结构化数据"))
    else:
        checks.append(_ck("L2-4", "L2", 3, "ok" if org else "warn",
                          "JSON-LD %d 块，类型：%s%s" % (len(lds), "、".join(sorted(set(types))[:8]),
                                                        "；sameAs %d 条" % len(same_as) if same_as else ""),
                          "" if org else "补 Organization（name/url/logo/sameAs），并在 sameAs 里放真实可访问主页",
                          "有结构化数据（含 Organization）"))
    lang = re.search(r'(?is)<html[^>]+lang=["\']([^"\']+)', html)
    checks.append(_ck("L2-5", "L2", 2, "ok" if lang else "warn",
                      "html lang=%s" % (lang.group(1) if lang else "未声明"),
                      "" if lang else "声明 lang（如 zh-CN），否则可能被误判语种", "声明语言"))
    can = re.search(r'(?is)<link[^>]+rel=["\']canonical["\'][^>]*href=["\']([^"\']+)', html)
    checks.append(_ck("L2-6", "L2", 2, "ok" if can else "warn",
                      "canonical: %s" % (can.group(1)[:70] if can else "未设置"),
                      "" if can else "加 canonical 避免重复内容分散权重", "有 canonical"))

    # ---------- L3 可引用 ----------
    qh = [h for h in h2 + h3 if re.search(r"[？?]$|吗|如何|怎么|为什么|哪些|是否|什么", re.sub(r"<[^>]+>", "", h))]
    checks.append(_ck("L3-1", "L3", 3, "ok" if len(qh) >= 2 else "warn",
                      "问题式小标题 %d 个" % len(qh), "" if len(qh) >= 2 else "把小标题改成用户会问的原话（答案引擎按问句匹配）", "有问答式结构"))
    first = txt[:300]
    conclusiony = bool(re.search(r"是|为|指|表|需要|应当|可以|不|无需", first)) and len(first) > 80
    checks.append(_ck("L3-2", "L3", 3, "ok" if conclusiony else "warn",
                      "首段 %d 字，%s" % (len(first), "含结论式表述" if conclusiony else "未见明确结论"),
                      "" if conclusiony else "首段直接给结论（模型常只摘一句，别让它猜）", "首段给结论"))
    stats = len(re.findall(r"\d+(?:\.\d+)?%|\d{4}年|\d+\.\d+|\d{2,}", txt))
    checks.append(_ck("L3-3", "L3", 2, "ok" if stats >= 5 else "warn",
                      "正文数字/统计 %d 处" % stats,
                      "" if stats >= 5 else "补可核对的数字、条款号、日期（带依据的段落最易被引用）", "含可核对的事实与数字"))
    faq = any(t == "FAQPage" for t in types)
    checks.append(_ck("L3-4", "L3", 2, "ok" if faq else "warn", "FAQPage：%s" % ("有" if faq else "无"),
                      "" if faq else "把 3-5 个真实客户问题做成 FAQ 并加 FAQPage 结构化", "有 FAQ 结构化"))
    dated = bool(re.search(r"\d{4}-\d{2}-\d{2}|\d{4}年\d{1,2}月", txt)) or any(
        isinstance(n, dict) and ("dateModified" in json.dumps(n) or "datePublished" in json.dumps(n)) for n in lds)
    checks.append(_ck("L3-5", "L3", 2, "ok" if dated else "warn", "页面可见/结构化日期：%s" % ("有" if dated else "无"),
                      "" if dated else "补 datePublished/dateModified 并在页面显示更新时间", "有可核对的日期"))

    # ---------- L4 实体一致 ----------
    if org:
        names = re.findall(r'"name"\s*:\s*"([^"]+)"', json.dumps(lds, ensure_ascii=False))
        h1t = re.sub(r"<[^>]+>", "", h1[0]).strip() if h1 else ""
        checks.append(_ck("L4-1", "L4", 2, "ok" if names else "warn",
                          "Organization/结构化 name：%s；H1：%s" % ("、".join(names[:3]) or "无", h1t[:40]),
                          "" if names else "补 name，确保与页面标题口径一致", "实体表述一致"))
    else:
        checks.append(_ck("L4-1", "L4", 2, "warn", "未发现 Organization 实体声明", "补 Organization 与 sameAs（全网口径统一是信任基础）", "实体表述一致"))
    checks.append(_ck("L4-2", "L4", 2, "ok" if len(same_as) >= 2 else "warn",
                      "sameAs %d 条%s" % (len(same_as), ("：" + "、".join(x[:40] for x in same_as[:3])) if same_as else ""),
                      "" if len(same_as) >= 2 else "把微博/知乎/CSDN/掘金等主页放进 sameAs（模型据此确认是同一个人/品牌）", "跨平台实体关联"))
    who = bool(re.search(r"我们是谁|关于我们|成立于|团队|About", txt))
    checks.append(_ck("L4-3", "L4", 2, "ok" if who else "warn", "「我们是谁」事实段：%s" % ("有" if who else "未见"),
                      "" if who else "首页放 3-6 行可整段摘引的事实陈述（做什么、服务谁、边界）", "有可摘引的事实段"))

    # ---------- L5 分发 ----------
    checks.append(_ck("L5-1", "L5", 3, "ok" if sm_st == 200 and locs else "fail",
                      "sitemap.xml HTTP %s，%d 条 loc" % (sm_st, len(locs)),
                      "" if locs else "补 sitemap.xml 并提交给各搜索引擎", "有 sitemap 且条目有效"))
    checked = locs[:6]
    bad = []
    for u in checked:
        s2, _, _, _, _, _ = fetch(u, ua="Mozilla/5.0 (compatible; Baiduspider-test)", timeout=timeout)
        if s2 != 200:
            bad.append("%s→%s" % (u[-42:], s2))
    checks.append(_ck("L5-2", "L5", 3, "ok" if not bad else "fail",
                      "抽查 %d 条 sitemap URL，%s" % (len(checked), "全部 200" if not bad else "异常：" + "；".join(bad[:3])),
                      "" if not bad else "sitemap 里的 404 直接伤害收录，逐条清理", "sitemap 条目可达"))
    ll_st, _, ll_b, _, _, _ = fetch(origin + "/llms.txt", timeout=timeout)
    checks.append(_ck("L5-3", "L5", 0, "ok" if ll_st == 200 else "info",
                      "llms.txt：%s（%s）" % ("存在" if ll_st == 200 else "不存在", HONESTY_NOTES[0][:38]),
                      "保留无害，但不要为它投入资源", "llms.txt（不计分）"))
    rss_st, _, _, _, _, _ = fetch(origin + "/rss.xml", timeout=timeout)
    checks.append(_ck("L5-4", "L5", 2, "ok" if rss_st == 200 else "warn", "rss.xml：%s" % ("存在" if rss_st == 200 else "无"),
                      "" if rss_st == 200 else "输出 rss.xml，给聚合器与爬虫一个发现新内容的通道", "有 RSS/Feed"))

    # ---------- L6 可信与可自验 ----------
    ad = bool(re.search(r'"(Person|author)"', json.dumps(lds, ensure_ascii=False))) or bool(re.search(r"作者|签\s*名|合尘猫", txt))
    checks.append(_ck("L6-1", "L6", 2, "ok" if ad else "warn", "作者/署名信号：%s" % ("有" if ad else "未见"),
                      "" if ad else "补作者署名与作者页（E-E-A-T 是 AI 眼里的权重）", "有作者署名"))
    cite = bool(re.search(r"引用|出处|来源：|参考文献|条款号|第[一二三四五六七八九十]+条", txt))
    checks.append(_ck("L6-2", "L6", 3, "ok" if cite else "warn", "可追溯依据信号：%s" % ("有" if cite else "未见"),
                      "" if cite else "关键结论写清依据（标准号/条款号/官方数据），最易被引用也最难被伪造", "结论可追溯"))
    opend = bool(re.search(r"/data/|\.json|\.csv|开放数据|下载", txt))
    checks.append(_ck("L6-3", "L6", 2, "ok" if opend else "warn", "开放数据/可下载：%s" % ("有" if opend else "未见"),
                      "" if opend else "把可复用的表/模型做成可下载的开放数据，别人引用时会更倾向指向你", "有开放数据"))

    # ---------- 扩展检查：并入国外成熟 GEO 工具的评分条款（按可判定性筛选）----------
    try:
        import engine_extra
        engine_extra.extra_checks(html, hd, lds, txt, origin, fetch, url, checks)
    except Exception as e:  # 扩展失败不影响主审计
        checks.append(_ck("X-0", "L1", 0, "info", "扩展检查失败：%s" % str(e)[:120], "", "扩展检查（不计分）"))

    # ---------- 汇总 ----------
    total_w = sum(c["weight"] for c in checks if c["weight"] > 0)
    got = sum(c["weight"] * {"ok": 1.0, "warn": 0.5, "fail": 0.0, "info": 0.0}.get(c["status"], 0) for c in checks if c["weight"] > 0)
    score = round(got / total_w * 100) if total_w else 0
    grade = "A" if score >= 85 else "B" if score >= 70 else "C" if score >= 55 else "D" if score >= 40 else "F"
    layers = {}
    for c in checks:
        if c["weight"] <= 0:
            continue
        L = layers.setdefault(c["layer"], {"got": 0.0, "tot": 0, "fail": 0})
        L["tot"] += c["weight"]
        L["got"] += c["weight"] * {"ok": 1.0, "warn": 0.5, "fail": 0.0}.get(c["status"], 0)
        if c["status"] == "fail":
            L["fail"] += 1
    for k, v in layers.items():
        v["score"] = round(v["got"] / v["tot"] * 100) if v["tot"] else 0
    fails = [c for c in checks if c["status"] == "fail"]
    return {
        "url": url, "final_url": final, "scoring_version": SCORING_VERSION,
        "score": score, "grade": grade, "layers": layers,
        "checks": checks, "raw": raw_meta,
        "priority_fixes": [{"id": c["id"], "title": c["title"], "evidence": c["evidence"], "fix": c["fix"]}
                           for c in sorted(fails + [x for x in checks if x["status"] == "warn"],
                                           key=lambda c: -c["weight"])][:10],
        "honesty_notes": HONESTY_NOTES,
        "no_public_token_vendors": NO_PUBLIC_TOKEN,
        "bot_matrix": {"citation": CITATION_BOTS, "training": TRAINING_BOTS},
    }


def audit_text(r):
    """人类可读摘要（MCP 里同时返回结构化与文本）。"""
    L = ["# 中文 AI 可引用性审计：%s" % r["url"],
         "", "**总分 %d/100（%s）** · scoring %s" % (r["score"], r["grade"], r["scoring_version"]), ""]
    LN = {"L1": "可抓取", "L2": "可解析", "L3": "可引用", "L4": "实体一致", "L5": "分发", "L6": "可信可自验"}
    for k in sorted(r["layers"]):
        v = r["layers"][k]
        L.append("- %s %s：**%d%%**（未达标 %d 项）" % (k, LN.get(k, ""), v["score"], v["fail"]))
    if r["priority_fixes"]:
        L += ["", "## 优先修复"]
        for i, f in enumerate(r["priority_fixes"], 1):
            L.append("%d. **[%s] %s** —— %s → %s" % (i, f["id"], f["title"], f["evidence"], f["fix"] or "保持"))
    L += ["", "## 诚实说明"]
    L += ["- " + n for n in r["honesty_notes"]]
    return "\n".join(L)


def compare(url_a, url_b, timeout=TIMEOUT):
    """竞品对比：两份审计的逐层与逐项差异（成熟工具里的标配能力）。"""
    a, b = audit(url_a, timeout), audit(url_b, timeout)
    ids = []
    for c in a["checks"] + b["checks"]:
        if c["id"] not in ids and c["weight"] > 0:
            ids.append(c["id"])
    amap = {c["id"]: c for c in a["checks"]}
    bmap = {c["id"]: c for c in b["checks"]}
    diff = []
    for i in ids:
        ca, cb = amap.get(i), bmap.get(i)
        sa = {"ok": 1.0, "warn": 0.5, "fail": 0.0}.get(ca["status"] if ca else "fail", 0)
        sb = {"ok": 1.0, "warn": 0.5, "fail": 0.0}.get(cb["status"] if cb else "fail", 0)
        if abs(sa - sb) >= 0.5:
            diff.append({"id": i, "title": (ca or cb)["title"], "a": ca["status"] if ca else "missing",
                         "b": cb["status"] if cb else "missing",
                         "winner": "A" if sa > sb else "B"})
    return {"a": {"url": url_a, "score": a["score"], "grade": a["grade"],
                  "layers": {k: v["score"] for k, v in a["layers"].items()}},
            "b": {"url": url_b, "score": b["score"], "grade": b["grade"],
                  "layers": {k: v["score"] for k, v in b["layers"].items()}},
            "winner": "A" if a["score"] >= b["score"] else "B",
            "score_gap": abs(a["score"] - b["score"]),
            "differing_checks": sorted(diff, key=lambda x: x["id"]),
            "scoring_version": SCORING_VERSION}


if __name__ == "__main__":
    import sys
    t0 = time.time()
    target = sys.argv[1] if len(sys.argv) > 1 else "https://savantcat.cn"
    res = audit(target)
    print(audit_text(res))
    print("\n-- 耗时 %.1fs --" % (time.time() - t0))
