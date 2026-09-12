import os
import sys
import gzip

HTML_FILE_PATH = os.path.join(os.path.dirname(__file__), "index.html")

def get_html_page():
    if os.path.exists(HTML_FILE_PATH):
        with open(HTML_FILE_PATH, "r", encoding="utf-8") as f:
            return f.read()
    # 如果处于打包环境，通过 sys._MEIPASS 获取
    meipass = getattr(sys, "_MEIPASS", "")
    if meipass:
        alt = os.path.join(meipass, "claude_remote", "web", "index.html")
        if os.path.exists(alt):
            with open(alt, "r", encoding="utf-8") as f:
                return f.read()
    raise FileNotFoundError(f"找不到前端 index.html 资源: {HTML_FILE_PATH}")
