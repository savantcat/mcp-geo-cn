# -*- coding: utf-8 -*-
"""抗覆盖保险：断言本服务的**每一个** MCP 工具都带溯源水印。

这条测试的意义不在当下的功能，而在**将来**：
  以后谁新增了一个工具、或者重写 server 时漏掉了 @MARK.seal，
  这条测试立刻变红 —— 水印不会静默消失，没有「哪天发现没了」这种事。

跑法: python -m pytest tests/test_watermark.py -q
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

SERVER_FILE = os.path.join(ROOT, "server.py")
BRAND = "合尘猫 SavantCat"


# ---------------------------------------------------------------- 静态：源码层
def test_source_has_mark_module():
    src = open(SERVER_FILE, encoding="utf-8").read()
    assert "import savantcat_mark as MARK" in src, "server 没有引水源印模块"


def test_every_mcp_tool_is_sealed():
    """每个 @mcp.tool 都必须跟着一个 @MARK.seal —— 数量必须相等。"""
    src = open(SERVER_FILE, encoding="utf-8").read()
    n_tool = src.count("@mcp.tool(")
    n_seal = src.count("@MARK.seal(")
    assert n_tool > 0, "一个工具都没找到，路径写错了？"
    assert n_tool == n_seal, (
        "有 " + str(n_tool) + " 个 @mcp.tool，但只有 " + str(n_seal) + " 个 @MARK.seal"
        " —— 新增工具时漏了盖水印。")


def test_mark_module_is_vendored_and_in_sync():
    """vendor 副本必须与唯一真源逐字节一致。"""
    import hashlib
    src = os.path.join(ROOT, "savantcat_mark.py")
    assert os.path.exists(src), "缺少 vendor 的 savantcat_mark.py"
    canon = os.path.join(os.path.dirname(ROOT), "savantcat-watermark", "savantcat_mark.py")
    if not os.path.exists(canon):
        return   # CI 里没有真源目录，跳过
    def h(f):
        # 换行归一：git 检出可能把 LF 变 CRLF，字节不同但内容等价
        return hashlib.sha256(open(f, "rb").read().replace(b"\r\n", b"\n")).hexdigest()
    assert h(src) == h(canon), "vendor 副本与真源不一致，跑 tools/sync_mark.py 同步"


# ---------------------------------------------------------------- 功能：运行时
def test_seal_is_actually_applied():
    """装饰器必须真的挂在函数上（不只是写了字符串）。"""
    import savantcat_mark as MARK
    sealed = MARK.seal("t", "p", "1.0.0")

    @sealed
    def fake_tool():
        return json.dumps({"ok": True}, ensure_ascii=False)

    assert getattr(fake_tool, "_savantcat_sealed", False) is True
    out = json.loads(fake_tool())
    assert out["attribution"]["brand"] == BRAND


def test_seal_skips_non_dict_and_bad_json():
    import savantcat_mark as MARK

    @MARK.seal("t", "p", "1.0.0")
    def returns_plain():
        return "这不是 JSON"

    assert returns_plain() == "这不是 JSON"


def test_watermark_is_invisible_and_removable():
    import savantcat_mark as MARK
    code = MARK.fingerprint("t", 1)
    plain = "一行业务文本"
    dirty = MARK.zw(plain, code)
    assert MARK.extract_code(dirty) == code
    assert MARK.strip_zw(dirty) == plain


def test_live_tool_output_is_watermarked():
    """真调一个零参工具，确认输出里既有溯源块又有零宽指纹。"""
    mod = __import__("server")
    called = 0
    for n in ["plan_fixes"]:
        fn = getattr(mod, n, None)
        if fn is None:
            continue
        try:
            raw = fn()
        except TypeError:
            continue                      # 需要入参，交给别的用例
        obj = json.loads(raw)
        a = obj.get("attribution") or obj.get("_provenance")
        assert a and a.get("brand") == BRAND, n + " 输出缺少溯源块"
        assert "\u2060" in json.dumps(obj, ensure_ascii=False), n + " 输出缺少零宽指纹"
        called += 1
    assert called > 0, "一个零参工具都没调成"


if __name__ == "__main__":
    fns = [(k, v) for k, v in sorted(globals().items()) if k.startswith("test_")]
    bad = 0
    for name, fn in fns:
        try:
            fn()
            print("  ok   " + name)
        except Exception as e:
            bad += 1
            print("  FAIL " + name + " -> " + type(e).__name__ + ": " + str(e))
    print("")
    print(str(len(fns) - bad) + "/" + str(len(fns)) + " 通过")
    sys.exit(1 if bad else 0)
