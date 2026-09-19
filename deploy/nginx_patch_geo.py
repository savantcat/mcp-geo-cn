# -*- coding: utf-8 -*-
"""在 ECS 的 savantcat.conf 里加 /mcp-geo：限流 zone + location 块（幂等）。
只做加法：新增一行 limit_req_zone、新增一个 location 块，不动任何既有配置。
nginx -t 失败自动还原备份。
"""
import io, os, re, sys, subprocess, datetime

CONF = sys.argv[1] if len(sys.argv) > 1 else "/etc/nginx/conf.d/savantcat.conf"
ZONE = "limit_req_zone $binary_remote_addr zone=mcpgeo:10m rate=60r/m;   # GEO/AEO MCP（/mcp-geo）"
BLOCK = """
    # ===== 中文 AI 可引用性 GEO/AEO MCP（Agent 可调用层，2026-09-19 上线）=====
    # 与 /mcp、/mcp-compliance 同构：只读、公开、带限流；只加这一条 location。
    location = /mcp-geo {
        access_log /var/log/nginx/mcp_methods.log mcpbody;
        limit_req zone=mcpgeo burst=30 nodelay;
        limit_req_status 429;

        include /etc/nginx/snippets/sec-headers.conf;

        add_header Access-Control-Allow-Origin  "*" always;
        add_header Access-Control-Allow-Methods "GET, POST, DELETE, OPTIONS" always;
        add_header Access-Control-Allow-Headers "Content-Type, Accept, Mcp-Session-Id, MCP-Protocol-Version, Last-Event-ID, Authorization" always;
        add_header Access-Control-Expose-Headers "Mcp-Session-Id" always;
        if ($request_method = OPTIONS) { return 204; }

        proxy_pass http://127.0.0.1:8767/mcp;
        proxy_http_version 1.1;
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Connection        "";

        proxy_buffering off;
        proxy_cache off;
        proxy_read_timeout 300s;
        proxy_send_timeout 300s;
        client_max_body_size 1m;
    error_page 406 =405 /mcp-get-hint.json;
    add_header Allow "POST, DELETE, OPTIONS" always;
    proxy_intercept_errors on;
    }
"""

t = io.open(CONF, encoding="utf-8").read()
def nginx_check(conf_path):
    """python3.6 兼容（ECS 上是 3.6，不能用 capture_output）"""
    p = subprocess.Popen(["nginx", "-t"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    out = p.communicate()[0].decode("utf-8", "replace")
    return p.returncode, out.strip()

if "zone=mcpgeo" in t and "location = /mcp-geo" in t:
    rc, out = nginx_check(CONF)
    print("[跳过] /mcp-geo 已存在；nginx -t:", out[:300])
    sys.exit(0 if rc == 0 else 1)

bak = CONF + ".bak-mcpgeo-" + datetime.datetime.now().strftime("%Y%m%d%H%M%S")
io.open(bak, "w", encoding="utf-8", newline="").write(t)
print("[备份]", bak)

if "zone=mcpgeo" not in t:
    m = re.search(r"(?m)^limit_req_zone .*zone=mcpcomp.*$", t)
    a = m.end() if m else re.search(r"(?m)^limit_req_zone .*$", t).end()
    t = t[:a] + "\n" + ZONE + t[a:]
    print("[加入] 限流 zone mcpgeo")

if "location = /mcp-geo" not in t:
    anchor = None
    for cand in ("    # ── 文档整理服务（轻量前台", "    location ^~ /tools/doc/ {"):
        if cand in t:
            anchor = cand
            break
    if anchor is None:
        print("[错误] 找不到插入锚点，未改动")
        sys.exit(1)
    i = t.index(anchor)
    t = t[:i] + BLOCK.strip("\n") + "\n\n" + t[i:]
    print("[加入] location = /mcp-geo")

io.open(CONF, "w", encoding="utf-8", newline="").write(t)
rc, out = nginx_check(CONF)
print("[nginx -t]", out[:400])
if rc != 0:
    io.open(CONF, "w", encoding="utf-8", newline="").write(io.open(bak, encoding="utf-8").read())
    print("[回滚] 已还原备份")
    sys.exit(1)
print("[OK] /mcp-geo 配置就绪")
