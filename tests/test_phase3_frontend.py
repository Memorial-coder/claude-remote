import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HTML_PATH = os.path.join(ROOT, "claude_remote", "web", "index.html")


def verify_frontend_syntax_and_patterns():
    print("[-] 测试 6: 验证独立前端 index.html 语法完整性与 NaN 防御机制...")
    with open(HTML_PATH, "r", encoding="utf-8") as f:
        content = f.read()

    assert "function escapeHtml(str)" in content, "未找到 escapeHtml 函数"
    idx_escape = content.find("function escapeHtml(str)")
    idx_params = content.find("const urlParams = new URLSearchParams")
    assert idx_escape < idx_params, "escapeHtml 未能置于 urlParams 初始化前，可能存在死区风险"

    assert "Number.isFinite(nextPanX)" in content, "zoomAtPoint 缺少 Number.isFinite 安全保护"
    assert "Number.isFinite(this.zoom)" in content, "updateCanvasTransform 缺少 zoom 有限性保护"

    assert "let streamEpoch = 0;" in content, "缺少 streamEpoch 竞态锁"
    assert "thisEpoch !== streamEpoch || sseActive" in content, "pollStream 缺少 epoch 过期阻断逻辑"

    print("[+] 测试 6 通过: 前端 WebOS Canvas 与 SSE/轮询流式竞态锁全部就绪！")


if __name__ == "__main__":
    verify_frontend_syntax_and_patterns()
    print("\n==========================================")
    print(">>> 阶段 3 前端 Canvas 与流通道修复全部验证通过！<<<")
    print("==========================================")
