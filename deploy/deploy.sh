#!/usr/bin/env bash
# 部署「中文 AI 可引用性 GEO/AEO MCP」到 ECS（幂等，可反复跑）
# 回滚：systemctl stop/disable mcp-geo + 还原 /etc/nginx/conf.d/savantcat.conf.bak-mcpgeo-*
set -euo pipefail
KEY="$HOME/.ssh/hermes-mqtt.pem"
HOST="root@47.109.58.210"
LOCAL="/d/Hermeswork/mcp-geo"
TAR="/tmp/mcp-geo.tgz"
SSH="ssh -i $KEY -o StrictHostKeyChecking=no $HOST"

cd "$LOCAL"
echo "· 打包本地文件…"
tar czf "$TAR" server.py engine.py engine_extra.py data deploy NOTICE LICENSE LICENSE-DATA README.md
echo "· 上传…"
scp -q -i "$KEY" -o StrictHostKeyChecking=no "$TAR" "$HOST:/tmp/mcp-geo.tgz"

echo "· 远端安装…"
$SSH 'set -e
mkdir -p /opt/mcp-geo
tar xzf /tmp/mcp-geo.tgz -C /opt/mcp-geo
install -m 644 /opt/mcp-geo/deploy/mcp-geo.service /etc/systemd/system/mcp-geo.service
python3 /opt/mcp-geo/deploy/nginx_patch_geo.py /etc/nginx/conf.d/savantcat.conf
systemctl daemon-reload
systemctl enable --now mcp-geo >/dev/null 2>&1
systemctl restart mcp-geo
sleep 4
echo "· 服务状态: $(systemctl is-active mcp-geo)"
systemctl reload nginx
echo "--- selftest ---"
/usr/bin/python3.11 /opt/mcp-geo/server.py --selftest 2>&1 | tail -12
' 2>&1 | grep -v "post-quantum\|store now\|may need to be upgraded"

echo "· 公网回读（本地 curl，走 MCP 协议三步）…"
B="https://savantcat.cn/mcp-geo"
curl -s -o /tmp/geo_init.json -w "initialize HTTP %{http_code}\n" -X POST "$B" \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"deploy-check","version":"1.0"}}}'
head -c 300 /tmp/geo_init.json; echo
curl -s -o /tmp/geo_tools.json -w "tools/list HTTP %{http_code}\n" -X POST "$B" \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'
python3 -c "
import json,re,io
t=io.open('/tmp/geo_tools.json',encoding='utf-8',errors='replace').read()
t=re.sub(r'^data: ','',t.strip(),flags=re.M)
try:
    d=json.loads(t.splitlines()[0] if not t.startswith('{') else t)
    ts=d.get('result',{}).get('tools',[])
    print('工具数:', len(ts), '|', ', '.join(x['name'] for x in ts))
except Exception as e:
    print('解析:', str(e)[:80]); print(t[:300])
"
echo "· 完成"
