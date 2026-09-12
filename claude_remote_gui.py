import os
import sys
import json
import time
import socket
import secrets
import threading
import subprocess
import string
import base64
import hmac
import hashlib
import struct
import re
import gzip
import ipaddress
import configparser
from collections import deque
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs, unquote, quote
import tkinter as tk
from tkinter import messagebox, ttk
import ctypes

try:
    import winpty
    HAS_WINPTY = True
except ImportError:
    HAS_WINPTY = False

try:
    import qrcode
    from PIL import Image, ImageTk
    HAS_QRCODE = True
except ImportError:
    HAS_QRCODE = False

# 开启 Windows 高分屏 (DPI) 渲染
try:
    ctypes.windll.shcore.SetProcessDpiAwareness(1)
except Exception:
    try:
        ctypes.windll.user32.SetProcessDPIAware()
    except Exception:
        pass

def _app_dir():
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))

def get_frpc_executable():
    d = _app_dir()
    cands = [
        os.path.join(d, "frpc.exe"),
        os.path.join(d, "_internal", "frpc.exe"),
        os.path.join(getattr(sys, "_MEIPASS", d), "frpc.exe"),
        os.path.join(os.getcwd(), "frpc.exe"),
        os.path.abspath(os.path.join(d, "..", "frpc.exe")),
    ]
    for c in cands:
        if c and os.path.isfile(c):
            return os.path.abspath(c)
    return os.path.join(d, "frpc.exe")

def load_frp_config():
    """FRP 鉴权从 server_config.ini 读取，支持环境变量覆盖。"""
    cfg = {
        "server_addr": os.environ.get("FRP_SERVER_HOST", "127.0.0.1"),
        "server_port": int(os.environ.get("FRP_SERVER_PORT", "17000")),
        "auth_token": os.environ.get("FRP_SERVER_TOKEN", ""),
        "public_https_host": os.environ.get("PUBLIC_HTTPS_HOST", "remote.example.com"),
    }
    search = [
        os.path.join(_app_dir(), "server_config.ini"),
        os.path.join(os.path.dirname(_app_dir()), "server_config.ini"),
        os.path.join(os.getcwd(), "server_config.ini"),
    ]
    for path in search:
        if not path or not os.path.isfile(path):
            continue
        try:
            parser = configparser.ConfigParser()
            parser.read(path, encoding="utf-8")
            if "frp_server" not in parser:
                continue
            s = parser["frp_server"]
            cfg["server_addr"] = s.get("server_addr", cfg["server_addr"]).strip() or cfg["server_addr"]
            cfg["server_port"] = s.getint("server_port", cfg["server_port"])
            cfg["auth_token"] = s.get("auth_token", cfg["auth_token"]).strip()
            cfg["public_https_host"] = s.get("public_https_host", cfg["public_https_host"]).strip() or cfg["public_https_host"]
            break
        except Exception:
            continue
    return cfg

_FRP_CFG = load_frp_config()
FRP_SERVER_HOST = _FRP_CFG["server_addr"]
FRP_SERVER_PORT = int(_FRP_CFG["server_port"] or 17000)
FRP_SERVER_TOKEN = _FRP_CFG["auth_token"]
PUBLIC_HTTPS_HOST = _FRP_CFG["public_https_host"] or "remote.example.com"

def get_device_fingerprint():
    host = socket.gethostname() or "pc"
    guid = ""
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography")
        guid, _ = winreg.QueryValueEx(key, "MachineGuid")
        winreg.CloseKey(key)
    except Exception:
        guid = ""
    digest = hashlib.sha256((guid or host).encode("utf-8", "ignore")).hexdigest()[:12]
    return "fp" + digest
# =======================================================


AUTH_TOKEN = ""
PUBLIC_COOKIE_PATH = "/"  # 公网反代下为 /p/{port}/，避免 Cookie 泄漏到同域名其他端口
frpc_process = None
httpd_server = None
gui_app_instance = None


class AccessSessionStore:
    """扫码一次性主 Token 换成短期会话票。Cookie 里不放 AUTH_TOKEN，被偷也换不回原始链接。"""
    TTL = 86400

    def __init__(self):
        self.lock = threading.Lock()
        self.sessions = {}

    def reset(self):
        with self.lock:
            self.sessions.clear()

    def issue(self, ip=""):
        sid = secrets.token_hex(32)
        csrf = secrets.token_hex(32)
        now = time.time()
        with self.lock:
            self.sessions[sid] = {"created": now, "last_seen": now, "ip": ip or "", "csrf": csrf}
        return sid

    def valid(self, sid, ip=""):
        if not sid:
            return False
        now = time.time()
        with self.lock:
            rec = self.sessions.get(sid)
            if not rec:
                return False
            if now - rec.get("last_seen", 0) > self.TTL:
                self.sessions.pop(sid, None)
                return False
            rec["last_seen"] = now
            if ip and ip not in ("127.0.0.1", "::1", "unknown"):
                rec["ip"] = ip
            if not rec.get("csrf"):
                rec["csrf"] = secrets.token_hex(32)
            return True

    def csrf_for(self, sid):
        if not sid:
            return ""
        with self.lock:
            rec = self.sessions.get(sid)
            if not rec:
                return ""
            if not rec.get("csrf"):
                rec["csrf"] = secrets.token_hex(32)
            return rec.get("csrf") or ""


access_sessions = AccessSessionStore()

def log_to_gui(msg):
    timestamp = time.strftime("%H:%M:%S")
    formatted = f"[{timestamp}] {msg}"
    print(formatted)
    if gui_app_instance:
        gui_app_instance.append_log(formatted)

def find_claude_cmd():
    """按 PATH / npm 全局目录动态探测 Claude CLI，不再写死开发机路径。"""
    extra = []
    npm_prefix = os.environ.get("npm_config_prefix") or os.environ.get("NPM_CONFIG_PREFIX")
    if npm_prefix:
        extra.extend([
            os.path.join(npm_prefix, "claude.cmd"),
            os.path.join(npm_prefix, "claude.exe"),
            os.path.join(npm_prefix, "claude"),
        ])
    candidates = extra + [
        os.path.expandvars(r"%APPDATA%\npm\claude.cmd"),
        os.path.expandvars(r"%APPDATA%\npm\claude.exe"),
        os.path.expandvars(r"%LOCALAPPDATA%\npm\claude.cmd"),
        shutil_which("claude"),
        "claude",
    ]
    for c in candidates:
        if c and os.path.exists(c):
            return c
    return "claude"


def shutil_which(name):
    try:
        import shutil
        return shutil.which(name) or ""
    except Exception:
        return ""

def get_windows_drives():
    drives = []
    bitmask = ctypes.windll.kernel32.GetLogicalDrives()
    for letter in string.ascii_uppercase:
        if bitmask & 1:
            drive_path = f"{letter}:\\"
            if os.path.exists(drive_path):
                drives.append(drive_path)
        bitmask >>= 1
    return drives


OPTION_SPLIT_RE = re.compile(
    r'(?:^|[\s>❯\*])(\d{1,2})[\.\、\)](?:\s+|(?=[一-鿿A-Za-z「【]))',
    re.MULTILINE
)

# 完成行只认 Claude Code 的耗时统计（Worked/Baked/... for Ns），排除 Thought/Thinking。
COOK_DONE_RE = re.compile(
    r'(?:[✻✶✦●•*]+\s*)?(Saut[eé]ed|Churned|Baked|Cogitated|Cooked|Simmered|Brewed|Whisked|'
    r'Stewed|Roasted|Grilled|Toasted|Crunched|Worked|Harvested|Distilled|'
    r'Blanched|Poached|Marinated|Seasoned|Kneaded|Fermented|Accomplished|'
    r'Spiraled|Germinated|Molted)\s+for\s+(?:\d+\s*m\s*)?\d+\s*s',
    re.IGNORECASE
)
BUSY_HINT_RE = re.compile(r'esc to interrupt|ctrl\+b to run in background', re.IGNORECASE)
THINKING_HINT_RE = re.compile(r'\b(Thought|Thinking|Think)\s+for\s+(?:\d+\s*m\s*)?\d+\s*s', re.IGNORECASE)


def strip_ansi(text):
    text = (text or '').replace('\r', '\n')
    text = re.sub(r'\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)', '', text)
    text = re.sub(r'\x1b\[[0-9;?]*[a-zA-Z]', '', text)
    text = re.sub(r'\x1b\([A-Z0-9]', '', text)
    text = re.sub(r'\x1b[>=]', '', text)
    return text


def latest_run_status(text):
    """Return ('done', summary) / ('busy', None) / (None, None) based on whichever marker is later."""
    last_busy = -1
    for m in BUSY_HINT_RE.finditer(text):
        last_busy = m.start()
    last_done = None
    for m in COOK_DONE_RE.finditer(text):
        last_done = m
    last_done_pos = last_done.start() if last_done else -1
    if THINKING_HINT_RE.search(text or '') and last_done_pos < 0:
        return 'busy', None, last_busy if last_busy >= 0 else 0
    if last_done_pos > last_busy:
        return 'done', last_done.group(0).strip(), last_done_pos
    if last_busy > last_done_pos:
        return 'busy', None, last_busy
    return None, None, -1


def parse_question_options(block_text):
    """把折行后的选择题拆开。屏幕上常有两套 1.2.3.（工作流步骤 + 真正选项），只取最靠近页脚的那一组。"""
    if not block_text:
        return '', []
    matches = []
    for m in OPTION_SPLIT_RE.finditer(block_text):
        try:
            n = int(m.group(1))
        except Exception:
            continue
        matches.append((n, m))
    if not matches:
        return '', []

    runs = []
    current = []
    expected = 1
    for n, m in matches:
        if n == expected:
            current.append(m)
            expected += 1
        elif n == 1:
            if len(current) >= 2:
                runs.append(current)
            current = [m]
            expected = 2
    if len(current) >= 2:
        runs.append(current)
    if not runs:
        return '', []
    seq = runs[-1]

    prelude = block_text[:seq[0].start()].strip()
    prelude_lines = [l.strip() for l in prelude.splitlines() if l.strip()]
    q_title = ''
    q_header = ''
    for line in reversed(prelude_lines[-6:]):
        cleaned = re.sub(r'^[>❯\s\*\?？●•]+', '', line).strip()
        if any(k in cleaned for k in ['?', '？', '【', 'Which', 'Select', 'What', 'Where', 'How', '请问', '选择', '希望', '先做', 'Run a', 'Want', 'Should']):
            q_title = cleaned
            break
    if not q_title and prelude_lines:
        q_title = re.sub(r'^[>❯\s\*\?？●•]+', '', prelude_lines[-1]).strip()
    if prelude_lines:
        chip = re.sub(r'^[>❯\s\*\?？●•]+', '', prelude_lines[0]).strip()
        if chip and chip != q_title and len(chip) <= 24:
            q_header = chip

    opts = []
    for i, m in enumerate(seq):
        start = m.end()
        end = seq[i + 1].start() if i + 1 < len(seq) else len(block_text)
        raw_opt = block_text[start:end]
        raw_opt = re.sub(r'(?:>\s*)?(Type something|Something else|Other).*$', '', raw_opt, flags=re.I)
        raw_opt = re.sub(r'(Enter to select|Esc to cancel|Enter to submit|to navigate|space to toggle).*$', '', raw_opt, flags=re.I)
        opt_lines = [re.sub(r'^[>❯\s\*●•]+', '', l).strip() for l in raw_opt.splitlines()]
        opt_lines = [l for l in opt_lines if l and l != 'Submit']
        if not opt_lines:
            continue
        title = re.sub(r'\s+', ' ', opt_lines[0]).strip()
        detail = re.sub(r'\s+', ' ', ' '.join(opt_lines[1:])).strip() if len(opt_lines) > 1 else ''
        is_rec = ('(Recommended)' in title) or ('★ 推荐' in title) or ('(Recommended)' in detail)
        title = re.sub(r'\(Recommended\)', '', title, flags=re.I).strip()
        title = re.sub(r'★\s*推荐', '', title).strip()
        if not detail and len(title) > 48:
            cut = title.find(' ', 18)
            if cut == -1 or cut > 56:
                cut = 40
            detail = title[cut:].strip()
            title = title[:cut].strip()
        if not title:
            continue
        opts.append({
            'num': m.group(1),
            'title': title[:80],
            'detail': detail[:280],
            'is_rec': is_rec,
            'is_custom': False
        })
    if re.search(r'Type something|Something else|\bOther\b|自定义', block_text, re.I):
        opts.append({
            'num': '',
            'title': '自定义输入',
            'detail': '输入你自己的选项',
            'is_rec': False,
            'is_custom': True
        })
    return q_title, opts, q_header


def looks_like_permission_prompt(title, opts):
    """Yes / don't ask again / No 这类是权限批准，不是普通选择题。"""
    titles = ' '.join((o.get('title') or '') for o in (opts or [])).lower()
    title_l = (title or '').lower()
    yesish = any(k in titles for k in ('yes', 'allow', 'approve', 'run it', 'proceed'))
    noish = any(k in titles for k in ('no', 'deny', 'reject', 'cancel'))
    autoish = any(k in titles for k in ('auto', "don't ask", 'dont ask', 'always', 'this session'))
    return (yesish and noish) or ('permission' in title_l) or (yesish and autoish)


def classify_permission_kind(text):
    """对照官方 PermissionRequest 分流：Bash / 写文件 / 读文件 / 网络 / 沙箱 / Plan / 通用。"""
    t = (text or '').lower()
    if any(k in t for k in ('exit plan mode', 'ready to code', 'plan mode', 'enter plan mode', 'implementation plan')):
        return 'plan'
    if any(k in t for k in ('fetch', 'web fetch', 'http://', 'https://', 'domain:')):
        return 'webfetch'
    if any(k in t for k in ('write file', 'edit file', 'overwrite', 'file write', 'apply edit', 'notebook')):
        return 'file'
    if any(k in t for k in ('read file', 'read this file', 'filesystem')):
        return 'file'
    if any(k in t for k in ('sandbox', 'without sandbox', 'escape sandbox')):
        return 'sandbox'
    if any(k in t for k in ('run this command', 'bash', 'powershell', 'shell command', '$ ')):
        return 'bash'
    if any(k in t for k in ('skill', 'mcp')):
        return 'skill'
    return 'command'


def extract_permission_command(text):
    """从审批块里抽出要执行的命令 / 文件路径 / URL。"""
    if not text:
        return ''
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    skip = (
        'do you want', 'proceed', 'allow', 'approve', 'yes', 'no', "don't ask",
        'enter to', 'esc to', 'to navigate', 'run this command', 'bash',
        'permission', 'always allow'
    )
    candidates = []
    for line in reversed(lines[-18:]):
        low = line.lower()
        if any(k in low for k in skip) and len(line) < 48:
            continue
        if re.match(r'^[\d]+[\.、\)]', line):
            continue
        if line.startswith('$') or line.startswith('>') or line.startswith('❯'):
            return line.lstrip('$>❯ ').strip()[:400]
        if re.search(r'https?://|\.[A-Za-z0-9]{1,6}\b|[\\/][\w.\-]+', line):
            candidates.append(line)
        elif re.search(r'\b(npm|pnpm|yarn|git|python|py|node|pip|cargo|go|make|curl|wget)\b', line, re.I):
            candidates.append(line)
    return (candidates[-1] if candidates else '')[:400]


# ==================== 状态持久化与 Claude 历史会话管理 ====================
STATE_DIR = os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")), "ClaudeRemote")
STATE_FILE = os.path.join(STATE_DIR, "state.json")
SECURITY_FILE = os.path.join(STATE_DIR, "security.json")

# ==================== RFC 6238 TOTP 2FA 认证与在线设备会话管理 ====================
class SecurityManager:
    """负责 Authenticator 2FA 密钥管理、TOTP 校验、防重放、已授权设备 Session 及踢下线控制"""
    def __init__(self):
        self.lock = threading.RLock()
        self.enabled = False
        self.secret = ""
        self.sessions = {}  # session_token -> {id, ip, user_agent, device_name, created_at, last_active}
        self._failed_attempts = {}  # ip -> {"count": int, "lock_until": float, "last_t": float}
        self._used_totp_codes = {}  # otp_code -> timestamp (防 90s 时间窗口内重复重放)
        self.load()

    def load(self):
        try:
            os.makedirs(STATE_DIR, exist_ok=True)
            if os.path.exists(SECURITY_FILE):
                with open(SECURITY_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.enabled = bool(data.get("enabled", False))
                    self.secret = data.get("secret", "")
                    loaded_sessions = data.get("sessions", {})
                    if isinstance(loaded_sessions, dict):
                        self.sessions = loaded_sessions
        except Exception as e:
            log_to_gui(f"读取安全配置异常: {e}")

    def save(self):
        try:
            os.makedirs(STATE_DIR, exist_ok=True)
            with open(SECURITY_FILE, "w", encoding="utf-8") as f:
                json.dump({
                    "enabled": self.enabled,
                    "secret": self.secret,
                    "sessions": self.sessions
                }, f, indent=2, ensure_ascii=False)
        except Exception as e:
            log_to_gui(f"保存安全配置异常: {e}")

    def generate_secret(self):
        with self.lock:
            # 标准 160-bit 高熵 Base32 密钥
            self.secret = base64.b32encode(secrets.token_bytes(20)).decode('utf-8').replace('=', '')
            self.save()
            return self.secret

    def get_totp_uri(self, account_name="ClaudeRemote"):
        sec = self.secret
        if not sec:
            sec = self.generate_secret()
        safe_host = quote(socket.gethostname() or "pc", safe="")
        safe_issuer = quote(account_name, safe="")
        return f"otpauth://totp/{safe_issuer}:{safe_host}?secret={sec}&issuer={safe_issuer}&algorithm=SHA1&digits=6&period=30"

    def verify_code(self, code):
        """校验客户端输入的 6 位动态验证码，允许 +/- 1 个步长（30 秒时钟容错），并强制防重放"""
        if not self.enabled or not self.secret:
            return True
        code_str = str(code).strip()
        if len(code_str) != 6 or not code_str.isdigit():
            return False
        now = time.time()
        with self.lock:
            # 清理 180 秒之前的已使用 TOTP 缓存，防止内存增长
            stale_codes = [c for c, exp_t in self._used_totp_codes.items() if now - exp_t > 180]
            for c in stale_codes:
                self._used_totp_codes.pop(c, None)

            # 防重放检查：已在当前时钟窗口内成功消费的代码禁止二次使用
            if code_str in self._used_totp_codes:
                log_to_gui(f"TOTP 防重放拦截：动态验证码 {code_str} 已在有效窗口内被使用过")
                return False

            try:
                padded = self.secret + '=' * ((8 - len(self.secret) % 8) % 8)
                key = base64.b32decode(padded.upper(), casefold=True)
                current_time = int(now // 30)
                for step_offset in (-1, 0, 1):
                    t = current_time + step_offset
                    msg = struct.pack('>Q', t)
                    h = hmac.new(key, msg, hashlib.sha1).digest()
                    offset = h[-1] & 0x0F
                    binary = struct.unpack('>I', h[offset:offset+4])[0] & 0x7fffffff
                    otp = str(binary % 1000000).zfill(6)
                    if hmac.compare_digest(otp, code_str):
                        # 标记当前验证码已消费
                        self._used_totp_codes[code_str] = now
                        return True
            except Exception as e:
                log_to_gui(f"TOTP 校验过程异常: {e}")
            return False

    def create_device_session(self, ip, user_agent=""):
        with self.lock:
            device_token = secrets.token_hex(24)
            # 简易解析设备信息（iPhone, Android, Windows, Mac 等）
            ua_lower = (user_agent or "").lower()
            if "iphone" in ua_lower:
                dev = "Apple iPhone"
            elif "ipad" in ua_lower:
                dev = "Apple iPad"
            elif "android" in ua_lower:
                dev = "Android 手机"
            elif "windows" in ua_lower:
                dev = "Windows 浏览器"
            elif "macintosh" in ua_lower or "mac os" in ua_lower:
                dev = "Mac 电脑"
            else:
                dev = "未知浏览器设备"

            now_str = time.strftime("%H:%M:%S")
            self.sessions[device_token] = {
                "id": device_token[:8],
                "token": device_token,
                "ip": ip,
                "user_agent": user_agent[:120],
                "device_name": dev,
                "created_at": now_str,
                "last_active": now_str,
                "last_active_t": time.time()
            }
            self.save()
            if gui_app_instance:
                gui_app_instance.root.after(0, gui_app_instance.refresh_device_list)
            return device_token

    def touch_session(self, device_token, ip=""):
        with self.lock:
            s = self.sessions.get(device_token)
            if s:
                now_t = time.time()
                # 至少间隔 60 秒写盘一次，避免高频请求频繁写磁盘
                should_save = (now_t - s.get("last_active_t", 0) > 60)
                s["last_active"] = time.strftime("%H:%M:%S")
                s["last_active_t"] = now_t
                if ip and ip not in ("127.0.0.1", "::1", "unknown"):
                    s["ip"] = ip
                if should_save:
                    self.save()
                return True
            return False

    def is_session_valid(self, device_token):
        if not self.enabled:
            return True
        if not device_token:
            return False
        with self.lock:
            return device_token in self.sessions

    def revoke_session(self, device_token):
        with self.lock:
            removed = self.sessions.pop(device_token, None)
            if removed:
                self.save()
            if gui_app_instance:
                gui_app_instance.root.after(0, gui_app_instance.refresh_device_list)
            return bool(removed)

    def list_active_devices(self):
        with self.lock:
            # 清理 7 天以上无活动的僵尸会话
            now = time.time()
            stale = [k for k, v in self.sessions.items() if now - v.get("last_active_t", now) > 86400 * 7]
            for k in stale:
                self.sessions.pop(k, None)
            return list(self.sessions.values())

    def record_failed_attempt(self, client_ip):
        """针对 2FA 动态验证码输入防爆破：带 TTL 与容量上限防内存泄漏，连续输错 5 次冻结 15 分钟"""
        now = time.time()
        with self.lock:
            # 自动淘汰过期或过量记录 (LRU/TTL 机制)
            if len(self._failed_attempts) > 1000:
                expired = [k for k, v in self._failed_attempts.items() if now > v.get("lock_until", 0) and now - v.get("last_t", 0) > 3600]
                for k in expired:
                    self._failed_attempts.pop(k, None)
                if len(self._failed_attempts) > 1500:
                    self._failed_attempts.clear()

            record = self._failed_attempts.setdefault(client_ip, {"count": 0, "lock_until": 0, "last_t": now})
            record["count"] += 1
            record["last_t"] = now
            if record["count"] >= 5:
                record["lock_until"] = now + 900  # 锁定 15 分钟
            return record["count"], record["lock_until"]

    def record_success_attempt(self, client_ip):
        with self.lock:
            self._failed_attempts.pop(client_ip, None)

    def check_rate_limit(self, client_ip):
        now = time.time()
        with self.lock:
            record = self._failed_attempts.get(client_ip)
            if record and now < record.get("lock_until", 0):
                return False, int(record["lock_until"] - now)
            return True, 0

security_mgr = SecurityManager()

# 常驻项目工作区：从环境变量 CLAUDE_REMOTE_PINNED_WORKSPACES 读取
# 格式：path1|label1;path2|label2   例：D:\proj\foo|foo;C:\work\bar|bar
# 未配置则不硬编码任何开发机路径。
def _load_pinned_workspaces():
    raw = (os.environ.get("CLAUDE_REMOTE_PINNED_WORKSPACES") or "").strip()
    items = []
    if not raw:
        return items
    for part in raw.split(";"):
        part = part.strip()
        if not part:
            continue
        if "|" in part:
            path, label = part.split("|", 1)
        else:
            path, label = part, os.path.basename(part.rstrip("\\/")) or part
        path = path.strip()
        label = label.strip() or os.path.basename(path.rstrip("\\/"))
        if path and os.path.isdir(path):
            items.append((os.path.abspath(path), label))
    return items


PINNED_PROJECT_WORKSPACES = _load_pinned_workspaces()

def _norm_dir(path):
    if not path:
        return ""
    try:
        return os.path.normcase(os.path.abspath(path))
    except Exception:
        return str(path).replace("/", "\\").rstrip("\\").lower()

def rebind_known_project_dir(name, project_dir):
    """按项目名纠正被写错的工作目录，避免 taoyuan 历史混进 frp 全局。"""
    name_key = re.sub(r"^项目:\s*", "", (name or "")).strip().lower()
    for path, label in PINNED_PROJECT_WORKSPACES:
        if name_key == label.lower() and os.path.isdir(path):
            return os.path.abspath(path)
    return project_dir

# 全局历史记录内存缓存，按 (target_norm, limit, offset) 缓存已解析出的标题元数据
_PROJECT_HISTORY_CACHE = {}
_PROJECT_HISTORY_CACHE_LOCK = threading.Lock()

def discover_latest_claude_session_id(project_dir, min_mtime=0):
    """自动探测指定工作目录下最新生成的 Claude Code 对话 ID (.jsonl)"""
    if not project_dir or not os.path.exists(project_dir):
        return None
    claude_projects_root = os.path.join(os.path.expanduser("~"), ".claude", "projects")
    if not os.path.isdir(claude_projects_root):
        return None
    target_norm = os.path.normcase(os.path.abspath(project_dir))
    clean_proj = re.sub(r'[^a-zA-Z0-9]+', '-', target_norm).strip('-').lower()

    matched_dir = None
    for d in os.listdir(claude_projects_root):
        norm = re.sub(r'[^a-zA-Z0-9]+', '-', d).strip('-').lower()
        if norm == clean_proj:
            matched_dir = os.path.join(claude_projects_root, d)
            break
    if not matched_dir or not os.path.isdir(matched_dir):
        return None

    jsonls = []
    for f in os.listdir(matched_dir):
        if f.endswith(".jsonl") and len(f) >= 16:
            fp = os.path.join(matched_dir, f)
            try:
                mtime = os.path.getmtime(fp)
                if mtime >= (min_mtime - 5):
                    jsonls.append((f[:-6], mtime))
            except Exception:
                pass
    jsonls.sort(key=lambda x: x[1], reverse=True)
    if jsonls:
        return jsonls[0][0]
    return None


def get_claude_project_history(project_dir, limit=10, offset=0):
    """读取 ~/.claude/projects/ 下的历史记录（严格按需分页加载，仅解析前 limit 个文件的首行标题）"""
    if not project_dir:
        return {"total": 0, "items": []}

    claude_projects_root = os.path.join(os.path.expanduser("~"), ".claude", "projects")
    if not os.path.isdir(claude_projects_root):
        return {"total": 0, "items": []}

    target_norm = os.path.normcase(os.path.abspath(project_dir))
    limit = max(1, min(int(limit or 10), 50))
    offset = max(0, int(offset or 0))
    now = time.time()
    cache_key = f"{target_norm}:{limit}:{offset}"

    # 1. 查内存热缓存 (120 秒有效期)
    with _PROJECT_HISTORY_CACHE_LOCK:
        cached = _PROJECT_HISTORY_CACHE.get(cache_key)
        if cached and (now - cached["timestamp"] < 120):
            return cached["data"]

    history = []
    total_count = 0

    try:
        subdirs = [os.path.join(claude_projects_root, d) for d in os.listdir(claude_projects_root)]
        matched_dir = None

        for sdir in subdirs:
            if not os.path.isdir(sdir):
                continue
            idx_file = os.path.join(sdir, "sessions-index.json")
            if os.path.isfile(idx_file):
                try:
                    with open(idx_file, "r", encoding="utf-8", errors="ignore") as f:
                        data = json.load(f)
                    orig_path = data.get("originalPath", "")
                    if orig_path and os.path.normcase(os.path.abspath(orig_path)) == target_norm:
                        matched_dir = sdir
                        all_entries = data.get("entries", [])
                        total_count = len(all_entries)
                        # 内存中直接做切片
                        paged_entries = all_entries[offset:offset+limit]
                        for entry in paged_entries:
                            sid = entry.get("sessionId")
                            if not sid:
                                continue
                            first_prompt = entry.get("firstPrompt", "").strip()
                            if first_prompt.startswith("<ide_opened_file>"):
                                m_file = re.search(r"<ide_opened_file>.*?(?:in the IDE|\.[\w]+)", first_prompt)
                                first_prompt = f"[打开文件] {m_file.group(0)}" if m_file else "[IDE 上下文]"
                            elif len(first_prompt) > 80:
                                first_prompt = first_prompt[:77] + "..."

                            msg_count = entry.get("messageCount", 0)
                            modified_raw = entry.get("modified") or entry.get("created")
                            friendly_time = ""
                            sort_time = 0
                            if modified_raw:
                                try:
                                    t_clean = re.sub(r'\.\d+Z$', '', modified_raw).replace('T', ' ')
                                    friendly_time = t_clean
                                    struct_t = time.strptime(t_clean[:19], "%Y-%m-%d %H:%M:%S")
                                    sort_time = time.mktime(struct_t)
                                except Exception:
                                    friendly_time = str(modified_raw)[:19]

                            history.append({
                                "session_id": sid,
                                "title": first_prompt or "无初始标题",
                                "message_count": msg_count,
                                "modified": friendly_time,
                                "sort_time": sort_time,
                                "git_branch": entry.get("gitBranch", ""),
                                "project_path": orig_path
                            })
                        break
                except Exception:
                    pass

        # 方案二：如果未找到 sessions-index.json，通过目录 slug 匹配，严格【按需分页】仅打开目标区间的 jsonl
        if not history and not total_count:
            clean_proj = re.sub(r'[^a-zA-Z0-9]+', '-', target_norm).strip('-').lower()
            best_match = None
            best_len = -1
            for sdir in subdirs:
                if not os.path.isdir(sdir):
                    continue
                sdir_name = os.path.basename(sdir)
                norm_sdir_name = re.sub(r'[^a-zA-Z0-9]+', '-', sdir_name).strip('-').lower()
                if norm_sdir_name == clean_proj and len(norm_sdir_name) > best_len:
                    best_match = sdir
                    best_len = len(norm_sdir_name)
            matched_dir = best_match

            if matched_dir and os.path.isdir(matched_dir):
                # 仅获取文件名及修改时间（只做非常轻量的目录元数据读取，绝不读内容）
                raw_files = []
                for fname in os.listdir(matched_dir):
                    if fname.endswith(".jsonl") and len(fname) >= 16:
                        fpath = os.path.join(matched_dir, fname)
                        try:
                            raw_files.append((fname, fpath, os.path.getmtime(fpath)))
                        except Exception:
                            pass
                raw_files.sort(key=lambda x: x[2], reverse=True)
                total_count = len(raw_files)
                # 核心：严格只切片当前 offset 到 offset+limit 的几个文件！
                paged_files = raw_files[offset:offset+limit]

                for fname, fpath, mtime in paged_files:
                    sid = fname[:-6]
                    try:
                        friendly_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(mtime))
                        first_prompt = ""
                        git_branch = ""
                        msg_count = 0

                        with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                            for idx, line in enumerate(f):
                                if idx > 25 or first_prompt:
                                    break
                                msg_count += 1
                                line_str = line.strip()
                                if not line_str:
                                    continue
                                try:
                                    obj = json.loads(line_str)
                                    if not git_branch and obj.get("gitBranch"):
                                        git_branch = obj.get("gitBranch")
                                    if first_prompt or obj.get("type") != "user" or obj.get("isMeta"):
                                        continue
                                    msg = obj.get("message", {})
                                    content = msg.get("content", "")
                                    texts = []
                                    if isinstance(content, str):
                                        texts.append(content.strip())
                                    elif isinstance(content, list):
                                        for part in content:
                                            if isinstance(part, dict) and part.get("text"):
                                                texts.append(part["text"].strip())
                                            elif isinstance(part, str):
                                                texts.append(part.strip())
                                    for c_clean in texts:
                                        if not c_clean:
                                            continue
                                        if c_clean.startswith("<command-name>") or c_clean.startswith("<local-command") or c_clean.startswith("<command-"):
                                            continue
                                        if c_clean.startswith("<ide_opened_file>"):
                                            m_file = re.search(r"<ide_opened_file>.*?(?:in the IDE|\.[\w]+)", c_clean)
                                            first_prompt = f"[打开文件] {m_file.group(0)}" if m_file else "[IDE 上下文]"
                                            break
                                        first_prompt = c_clean[:77] + "..." if len(c_clean) > 80 else c_clean
                                        break
                                except Exception:
                                    pass

                        try:
                            fsize = os.path.getsize(fpath)
                            est_count = max(msg_count, max(1, fsize // 2500))
                        except Exception:
                            est_count = max(1, msg_count)

                        history.append({
                            "session_id": sid,
                            "title": first_prompt or f"会话 {sid[:8]}",
                            "message_count": est_count,
                            "modified": friendly_time,
                            "sort_time": mtime,
                            "git_branch": git_branch,
                            "project_path": project_dir
                        })
                    except Exception:
                        pass

        # 同时输出 camelCase 别名，方便前端直接读取
        for item in history:
            item["sessionId"] = item.get("session_id")
            item["firstPrompt"] = item.get("title")
            item["messageCount"] = item.get("message_count")
            item["gitBranch"] = item.get("git_branch")

        result = {
            "total": total_count,
            "items": history,
            "limit": limit,
            "offset": offset,
            "has_more": (offset + len(history)) < total_count
        }

        # 写入全局缓存
        with _PROJECT_HISTORY_CACHE_LOCK:
            _PROJECT_HISTORY_CACHE[cache_key] = {
                "timestamp": now,
                "data": result
            }
        return result
    except Exception as e:
        log_to_gui(f"读取 Claude 历史会话异常: {e}")

    return {"total": 0, "items": []}


# ==================== 结构化协议事件（JSONL > PTY 刮屏） ====================
# 官方 Claude 把 AskUserQuestion / tool_use 写进 ~/.claude/projects/<slug>/<session>.jsonl。
# PTY 继续给 xterm 画画；问题面板优先读 JSONL。锁屏 SSE 挂起后靠 seq_num 回放补洞。
SSE_EVENT_LIMIT = 5000
ASK_USER_QUESTION_TOOL = "AskUserQuestion"
PERMISSION_MODE_ALIASES = {
    "default": "default",
    "acceptedits": "acceptEdits",
    "accept_edits": "acceptEdits",
    "bypasspermissions": "bypassPermissions",
    "bypass_permissions": "bypassPermissions",
    "dontask": "dontAsk",
    "dont_ask": "dontAsk",
    "plan": "plan",
    "auto": "auto",
}
TOOL_KIND_BY_NAME = {
    "Bash": "bash",
    "PowerShell": "bash",
    "Write": "file",
    "Edit": "file",
    "NotebookEdit": "file",
    "Read": "file",
    "WebFetch": "webfetch",
    "WebSearch": "webfetch",
    "Skill": "skill",
    ASK_USER_QUESTION_TOOL: "questions",
}


def redact_secret(text, token=""):
    """日志里绝不放主 Token / 会话票明文。"""
    s = "" if text is None else str(text)
    if token and len(token) >= 8:
        s = s.replace(token, token[:4] + "…" + token[-4:])
    s = re.sub(r"([?&]token=)[0-9a-fA-F]{16,}", r"\1***", s)
    return s


def normalize_permission_mode(raw):
    key = re.sub(r"[^a-z_]", "", (raw or "").lower())
    return PERMISSION_MODE_ALIASES.get(key, "default")


def resolve_claude_project_dir(project_dir):
    """把工作目录映射到 ~/.claude/projects/<slug>。"""
    if not project_dir:
        return None
    root = os.path.join(os.path.expanduser("~"), ".claude", "projects")
    if not os.path.isdir(root):
        return None
    try:
        target_norm = os.path.normcase(os.path.abspath(project_dir))
    except Exception:
        return None
    clean_proj = re.sub(r"[^a-zA-Z0-9]+", "-", target_norm).strip("-").lower()
    best, best_len = None, -1
    try:
        names = os.listdir(root)
    except Exception:
        return None
    for d in names:
        sdir = os.path.join(root, d)
        if not os.path.isdir(sdir):
            continue
        idx_file = os.path.join(sdir, "sessions-index.json")
        if os.path.isfile(idx_file):
            try:
                with open(idx_file, "r", encoding="utf-8", errors="ignore") as f:
                    data = json.load(f)
                orig = data.get("originalPath", "")
                if orig and os.path.normcase(os.path.abspath(orig)) == target_norm:
                    return sdir
            except Exception:
                pass
        norm = re.sub(r"[^a-zA-Z0-9]+", "-", d).strip("-").lower()
        if norm == clean_proj and len(norm) > best_len:
            best, best_len = sdir, len(norm)
    return best


def jsonl_path_for_claude_session(project_dir, claude_session_id):
    if not claude_session_id:
        return None
    sdir = resolve_claude_project_dir(project_dir)
    if not sdir:
        return None
    path = os.path.join(sdir, str(claude_session_id) + ".jsonl")
    return path if os.path.isfile(path) else None


def _iter_jsonl_records(text):
    for line in (text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except Exception:
            continue
        if isinstance(obj, dict):
            yield obj


def _content_blocks(obj):
    msg = obj.get("message") if isinstance(obj.get("message"), dict) else obj
    content = (msg or {}).get("content")
    if isinstance(content, list):
        return [b for b in content if isinstance(b, dict)]
    return []


def _option_from_protocol(opt, idx):
    label = (opt or {}).get("label") or (opt or {}).get("title") or ""
    detail = (opt or {}).get("description") or (opt or {}).get("detail") or ""
    rec = (
        "recommended" in label.lower()
        or "recommended" in detail.lower()
        or "★" in label
        or bool((opt or {}).get("is_rec"))
    )
    label = re.sub(r"\s*\(Recommended\)\s*", " ", label, flags=re.I).strip()
    label = re.sub(r"★\s*推荐", "", label).strip()
    return {
        "num": str(idx + 1),
        "title": label[:80],
        "detail": detail[:280],
        "preview": ((opt or {}).get("preview") or "")[:2000],
        "is_rec": rec,
        "is_custom": False,
    }


def protocol_questions_to_approval(questions, tool_use_id=""):
    """AskUserQuestion input.questions → 手机面板 payload。Other 由前端自动补。"""
    qs = []
    for q in questions or []:
        if not isinstance(q, dict):
            continue
        raw_opts = q.get("options") or []
        opts = [_option_from_protocol(o, i) for i, o in enumerate(raw_opts) if isinstance(o, dict)]
        if len(opts) < 2:
            continue
        header = (q.get("header") or "")[:12]
        qs.append({
            "question": q.get("question") or "",
            "header": header,
            "multiSelect": bool(q.get("multiSelect")),
            "options": opts,
        })
    if not qs:
        return {"type": "none"}
    first = qs[0]
    return {
        "type": "questions",
        "source": "jsonl",
        "tool_use_id": tool_use_id,
        "title": first["question"] or "请选择以下操作选项",
        "header": first["header"],
        "options": first["options"],
        "is_multi": first["multiSelect"],
        "questions": qs,
    }


def protocol_tool_to_command(name, tool_input, tool_use_id=""):
    kind = TOOL_KIND_BY_NAME.get(name, "command")
    cmd = ""
    if isinstance(tool_input, dict):
        cmd = (
            tool_input.get("command")
            or tool_input.get("file_path")
            or tool_input.get("path")
            or tool_input.get("url")
            or ""
        )
        if not cmd:
            try:
                cmd = json.dumps(tool_input, ensure_ascii=False)[:400]
            except Exception:
                cmd = str(tool_input)[:400]
    elif tool_input:
        cmd = str(tool_input)[:400]
    titles = {
        "bash": "Run this command?",
        "file": "Allow file change?",
        "webfetch": "Allow network fetch?",
        "sandbox": "Allow sandbox escape?",
        "plan": "Ready to code?",
        "skill": "Allow this skill?",
        "command": "Allow this action?",
    }
    return {
        "type": "command",
        "source": "jsonl",
        "kind": kind,
        "tool_name": name,
        "tool_use_id": tool_use_id,
        "prompt": titles.get(kind, "Allow this action?"),
        "command": str(cmd)[:400],
        "cwd": "",
        "options": [],
    }


def scan_jsonl_protocol(text):
    """从 jsonl 文本抽出：未完成的 AskUserQuestion / 工具授权、最后一次权限模式。

    规则：assistant 的 tool_use 进入 pending；之后同 id 的 tool_result 把它关掉。
    选择题和授权是两类产品，绝不混成一套编号。
    """
    pending = {}  # tool_use_id -> record
    permission_mode = "default"
    order = []
    for obj in _iter_jsonl_records(text):
        rec_type = obj.get("type")
        if rec_type == "permission-mode":
            permission_mode = normalize_permission_mode(obj.get("permissionMode") or obj.get("mode"))
            continue
        if rec_type == "mode" and obj.get("mode") in PERMISSION_MODE_ALIASES.values():
            permission_mode = normalize_permission_mode(obj.get("mode"))
        for block in _content_blocks(obj):
            btype = block.get("type")
            if btype == "tool_use":
                uid = block.get("id") or ""
                name = block.get("name") or ""
                if not uid or not name:
                    continue
                pending[uid] = {
                    "id": uid,
                    "name": name,
                    "input": block.get("input") if isinstance(block.get("input"), dict) else {},
                }
                if uid in order:
                    order.remove(uid)
                order.append(uid)
            elif btype == "tool_result":
                uid = block.get("tool_use_id") or ""
                if uid:
                    pending.pop(uid, None)
                    if uid in order:
                        order.remove(uid)
    questions = None
    command = None
    for uid in reversed(order):
        rec = pending.get(uid)
        if not rec:
            continue
        if rec["name"] == ASK_USER_QUESTION_TOOL:
            q_input = rec["input"].get("questions") or []
            ap = protocol_questions_to_approval(q_input, rec["id"])
            if ap.get("type") == "questions":
                questions = ap
                break
        elif command is None:
            command = protocol_tool_to_command(rec["name"], rec["input"], rec["id"])
    approval = questions or command or {"type": "none"}
    return {
        "approval": approval,
        "permission_mode": permission_mode,
        "pending_count": len(pending),
    }


class SessionEventBus:
    """CCB EventBus 的精简移植：每条事件有 seq_num，上限 5000，重连 get_events_since 补洞。"""

    def __init__(self):
        self.lock = threading.Lock()
        self.seq_num = 0
        self.events = []

    def publish(self, event_type, payload=None):
        with self.lock:
            self.seq_num += 1
            ev = {
                "id": "ev_%d" % self.seq_num,
                "type": event_type,
                "payload": payload if payload is not None else {},
                "seq_num": self.seq_num,
                "created_at": time.time(),
            }
            self.events.append(ev)
            if len(self.events) > SSE_EVENT_LIMIT:
                self.events = self.events[-(SSE_EVENT_LIMIT // 2):]
            return ev

    def get_events_since(self, seq_num):
        try:
            seq_num = int(seq_num or 0)
        except Exception:
            seq_num = 0
        with self.lock:
            return [e for e in self.events if e["seq_num"] > seq_num]

    def last_seq(self):
        with self.lock:
            return self.seq_num


# ==================== 单会话实体 (ClaudeSession) ====================
class ClaudeSession:
    """单个 Claude Code 终端会话实例 (支持置顶、状态监测、对话续接与生命周期管理)"""
    def __init__(self, session_id, name, project_dir=None, cols=120, rows=36, resume_mode="continue", claude_session_id=None):
        self.id = session_id
        self.name = name
        self.project_dir = os.path.abspath(project_dir) if project_dir and os.path.exists(project_dir) else os.environ.get("USERPROFILE", "C:\\")
        self.cols = max(30, cols)
        self.rows = max(10, rows)
        self.resume_mode = resume_mode or "continue"  # "continue" (续接最近), "resume" (指定id), "new" (全新)
        self.claude_session_id = claude_session_id
        self.pty = None
        self.lock = threading.RLock()
        self.output_event = threading.Event()
        self.buffer = bytearray()
        self.is_running = False
        self.started_at = None
        self.created_at = time.strftime("%Y-%m-%d %H:%M:%S")
        self.pinned = False
        self.last_output_time = time.time()
        self.last_notified_event_id = None
        self.has_active_work = False
        self.saw_busy = False
        self.buf_mark_at_send = 0
        self.completed_until = 0
        self.completed_payload = None
        self.last_completed_pos = -1
        self._cached_approval = {"type": "none"}
        self._cached_buf_len = -1
        self._last_inspect_t = 0
        self._pending_inspect = False
        self.pty_pid = None
        self.known_claude_pids = set()
        self._settings_file = None
        self.event_bus = SessionEventBus()
        self.permission_mode = "default"
        self._jsonl_offset = 0
        self._jsonl_mtime = 0
        self._jsonl_path = None
        self._last_protocol_fp = ""
        self._pty_crash_count = 0
        self._last_crash_at = 0
        self._user_stopped = False
        self._jsonl_buf = ""
        self.conn_state = "idle"  # idle | connecting | connected | error
        self._buf_generation = 0  # 缓冲区截断世代号，客户端用来判断 offset 是否失效
        self._choice_lock = threading.Lock()  # 选项下发串行化，禁止并发方向键交错
        self._choice_busy = False

    def _ensure_theme_settings_file(self, theme_name):
        """生成临时 settings JSON 文件传给 Claude CLI，避免 Windows 命令行转义破坏 JSON 字符串"""
        if theme_name not in ("light", "dark"):
            return None
        try:
            settings_dir = os.path.join(os.environ.get("TEMP", os.getcwd()), "claude_remote_settings")
            os.makedirs(settings_dir, exist_ok=True)
            settings_path = os.path.join(settings_dir, f"settings_{self.id}_{theme_name}.json")
            with open(settings_path, "w", encoding="utf-8") as f:
                json.dump({"theme": "light" if theme_name == "light" else "dark"}, f)
            self._settings_file = settings_path
            return settings_path
        except Exception as e:
            log_to_gui(f"[{self.name}] 创建临时设置文件失败: {e}")
            return None

    def start(self, theme=None):
        with self.lock:
            if self.is_running:
                return True, "会话已在运行中"

            claude_path = find_claude_cmd()

            # 根据 resume_mode 组装启动参数
            cmd_parts = [claude_path]
            mode_desc = "新会话"
            if self.resume_mode == "continue":
                cmd_parts.append("-c")
                mode_desc = "续接最近对话 (-c)"
            elif self.resume_mode == "resume" and self.claude_session_id:
                cmd_parts.extend(["-r", self.claude_session_id])
                mode_desc = f"恢复指定对话 (-r {self.claude_session_id[:8]}...)"

            # 如果指定了浅色/深色主题，注入 Claude CLI 官方主题配置（通过文件路径传入，避免转义错误）
            theme_name = theme or getattr(self, "theme", None)
            if theme_name:
                self.theme = theme_name
            if theme_name in ("light", "dark"):
                settings_file = self._ensure_theme_settings_file(theme_name)
                if settings_file:
                    cmd_parts.extend(["--settings", settings_file])

            cmd_line = subprocess.list2cmdline(cmd_parts)
            log_to_gui(f"[{self.name}] 拉起 Claude CLI ({cmd_line}) 模式: {mode_desc} | 主题: {theme_name or '默认'} | 视口: {self.cols}x{self.rows} | 目录: {self.project_dir}")

            try:
                if HAS_WINPTY:
                    self._user_stopped = False
                    self.conn_state = "connecting"
                    self.event_bus.publish("conn", {"state": "connecting"})
                    pty_env = os.environ.copy()
                    pty_env["TERM"] = "xterm-256color"
                    pty_env["COLUMNS"] = str(max(20, int(self.cols)))
                    pty_env["LINES"] = str(max(8, int(self.rows)))
                    self.pty = winpty.PtyProcess.spawn(
                        cmd_line,
                        cwd=self.project_dir,
                        env=pty_env,
                        dimensions=(self.rows, self.cols),
                    )
                    self.is_running = True
                    self.started_at = time.strftime("%Y-%m-%d %H:%M:%S")
                    self.pty_pid = getattr(self.pty, "pid", None)
                    self.known_claude_pids.clear()
                    if self.pty_pid:
                        self.known_claude_pids.add(self.pty_pid)
                    self.conn_state = "connected"
                    self.event_bus.publish("conn", {"state": "connected", "pid": self.pty_pid})
                    self._append_output(
                        f"\x1b[38;2;245;158;11m[Session: {self.name}] Claude Code PTY 终端就绪 (模式: {mode_desc})\x1b[0m\r\n\r\n"
                    )
                    log_to_gui(f"[{self.name}] Claude PTY 终端启动成功 (PID: {self.pty_pid})")
                    threading.Thread(target=self._read_pty_loop, daemon=True).start()
                    return True, "Claude 会话启动成功"
                else:
                    self.conn_state = "error"
                    self.event_bus.publish("conn", {"state": "error", "reason": "no_winpty"})
                    return False, "系统未安装 winpty 依赖"
            except Exception as e:
                self.is_running = False
                self.conn_state = "error"
                self.event_bus.publish("conn", {"state": "error", "reason": str(e)[:200]})
                log_to_gui(f"[{self.name}] 拉起 Claude 失败: {str(e)}")
                return False, str(e)

    def _append_output(self, text):
        if not text:
            return 0
        raw = text.encode("utf-8", "replace") if isinstance(text, str) else text
        self.buffer.extend(raw)
        blen = len(self.buffer)
        if blen > 300000:
            drop = blen - 150000
            del self.buffer[:drop]
            self.last_completed_pos = max(-1, self.last_completed_pos - drop)
            self.buf_mark_at_send = max(0, self.buf_mark_at_send - drop)
            self._buf_generation += 1
            blen = len(self.buffer)
        return blen

    def _decode_slice(self, start=0, end=None):
        chunk = self.buffer[start:] if end is None else self.buffer[start:end]
        if not chunk:
            return ""
        return chunk.decode("utf-8", "replace")

    def set_size(self, cols, rows):
        with self.lock:
            cols = max(20, int(cols))
            rows = max(8, int(rows))
            self.cols = cols
            self.rows = rows
            if self.pty and self.is_running:
                try:
                    # pywinpty 真实 API 是 setwinsize(rows, cols)，不是 set_winsize
                    if hasattr(self.pty, "setwinsize"):
                        self.pty.setwinsize(rows, cols)
                    elif hasattr(self.pty, "set_size"):
                        self.pty.set_size(cols, rows)
                    elif hasattr(self.pty, "pty") and hasattr(self.pty.pty, "set_size"):
                        self.pty.pty.set_size(cols, rows)
                    else:
                        raise AttributeError("winpty has no setwinsize/set_size")
                    log_to_gui(f"[{self.name}] PTY 视口已更新: {cols}x{rows}")
                except Exception as e:
                    log_to_gui(f"[{self.name}] PTY setwinsize 失败 ({cols}x{rows}): {e}")

    def _read_pty_loop(self):
        while self.is_running and self.pty:
            try:
                if not self.pty.isalive():
                    break
                data = self.pty.read(4096)
                if data:
                    with self.lock:
                        self._append_output(data)
                        self.last_output_time = time.time()
                        self.has_active_work = True
                    if self._tail_looks_interactive(data):
                        self._pending_inspect = True
                    self.output_event.set()
                else:
                    time.sleep(0.01)
            except Exception:
                break
        was_running = self.is_running
        self.is_running = False
        old_pty = None
        with self.lock:
            old_pty = self.pty
            self.pty = None
            self._append_output(f"\r\n\x1b[31m[{self.name}] 会话已结束。\x1b[0m\r\n")
        if old_pty:
            try:
                old_pty.close()
            except Exception:
                pass
        self.output_event.set()
        log_to_gui(f"[{self.name}] Claude 终端会话已退出")
        if was_running:
            self._maybe_auto_restart_pty()

    def _maybe_auto_restart_pty(self):
        """PTY 非用户主动退出时有限重试，避免手机端画面停了只能猜。"""
        if getattr(self, "_user_stopped", False):
            self.conn_state = "idle"
            self.event_bus.publish("conn", {"state": "idle"})
            return
        now = time.time()
        if now - self._last_crash_at > 90:
            self._pty_crash_count = 0
        self._pty_crash_count += 1
        self._last_crash_at = now
        self.conn_state = "error"
        self.event_bus.publish("conn", {
            "state": "error",
            "reason": "pty_exit",
            "retry": self._pty_crash_count,
        })
        if self._pty_crash_count > 3:
            log_to_gui(f"[{self.name}] PTY 连续退出 {self._pty_crash_count} 次，停止自动重启")
            return
        delay = min(8.0, 1.5 * self._pty_crash_count)

        def _retry():
            time.sleep(delay)
            if getattr(self, "_user_stopped", False) or self.is_running:
                return
            with self.lock:
                leftover = self.pty
                self.pty = None
            if leftover:
                try:
                    leftover.close()
                except Exception:
                    pass
            ok, msg = self.start()
            log_to_gui(f"[{self.name}] PTY 自动重启 ({self._pty_crash_count}/3): {msg}")

        threading.Thread(target=_retry, daemon=True, name="pty-retry").start()

    def _publish_approval_if_changed(self, approval):
        try:
            fp = json.dumps(approval or {}, sort_keys=True, ensure_ascii=False)[:800]
        except Exception:
            fp = str((approval or {}).get("type"))
        if fp == self._last_protocol_fp:
            return
        self._last_protocol_fp = fp
        self.event_bus.publish("approval", approval or {"type": "none"})

    def _poll_jsonl_protocol(self):
        """增量读官方 jsonl：AskUserQuestion / 未完成 tool_use 作为选择题与授权数据源。"""
        path = jsonl_path_for_claude_session(self.project_dir, self.claude_session_id)
        if not path:
            return None
        try:
            mtime = os.path.getmtime(path)
            size = os.path.getsize(path)
        except Exception:
            return None
        if path != self._jsonl_path:
            self._jsonl_path = path
            self._jsonl_offset = 0
            self._jsonl_buf = ""
        if size < self._jsonl_offset:
            self._jsonl_offset = 0
            self._jsonl_buf = ""
        if size == self._jsonl_offset and mtime == self._jsonl_mtime:
            return None
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                if self._jsonl_offset:
                    f.seek(self._jsonl_offset)
                chunk = f.read()
                self._jsonl_offset = f.tell()
        except Exception:
            return None
        self._jsonl_mtime = mtime
        if chunk:
            self._jsonl_buf += chunk
            if len(self._jsonl_buf) > 8_000_000:
                self._jsonl_buf = self._jsonl_buf[-5_000_000:]
        parsed = scan_jsonl_protocol(self._jsonl_buf)
        mode = parsed.get("permission_mode") or "default"
        if mode != self.permission_mode:
            self.permission_mode = mode
            self.event_bus.publish("permission_mode", {"mode": mode})
        ap = parsed.get("approval") or {"type": "none"}
        if ap.get("type") in ("questions", "command"):
            ap = dict(ap)
            ap["cwd"] = ap.get("cwd") or self.project_dir
            self._cached_approval = ap
            self._publish_approval_if_changed(ap)
            return parsed
        if (self._cached_approval or {}).get("source") == "jsonl":
            # jsonl 里这题已经有 tool_result，清掉协议卡片，交给 PTY 扫完成态
            self._cached_approval = {"type": "none"}
            self._publish_approval_if_changed(self._cached_approval)
        return parsed

    def _tail_looks_interactive(self, raw_tail):
        """快速指纹：只有尾部出现审批/完成线索时才跑完整正则，普通打字直接跳过"""
        if not raw_tail:
            return False
        if isinstance(raw_tail, (bytes, bytearray)):
            raw_tail = raw_tail.decode("utf-8", "replace")
        probe = raw_tail[-1600:] if len(raw_tail) > 1600 else raw_tail
        low = probe.lower()
        return any(token in low for token in (
            "enter to select", "esc to cancel", "enter to submit", "enter to confirm",
            "to navigate", "space to select", "space to toggle", "toggle all",
            "use arrow keys", "type number", "to choose", "select an option",
            "(y/n)", "do you want to proceed", "allow ", "approve ",
            "worked for", "baked for", "sautéed for", "sauteed for",
            "churned for", "cogitated for", "cooked for", "simmered for",
            "brewed for", "whisked for", "crunched for", "harvested for",
            "distilled for", "blanched for", "poached for", "marinated for",
            "seasoned for", "kneaded for", "fermented for", "accomplished for",
            "spiraled for", "germinated for", "molted for", "stewed for",
            "roasted for", "grilled for", "toasted for", "thought for",
            "thinking for"
        )) or ("?" in probe and any(ch.isdigit() for ch in probe[-400:]))

    def inspect_approval_state(self, force=False):
        """优先 JSONL 协议事件，PTY 刮屏只作降级。"""
        now_t = time.time()
        protocol = None
        try:
            protocol = self._poll_jsonl_protocol()
        except Exception:
            protocol = None
        proto_ap = (protocol or {}).get("approval") if protocol else None
        if proto_ap and proto_ap.get("type") in ("questions", "command"):
            self._last_inspect_t = now_t
            return self._cached_approval
        cached = self._cached_approval or {}
        if cached.get("source") == "jsonl" and cached.get("type") in ("questions", "command"):
            # jsonl 题还活着：PTY 刮屏不能把它盖成 none 或另一套编号
            self._last_inspect_t = now_t
            return cached

        # 300ms 轻量短路缓存，消除高频并发轮询时对 PTY 的锁争用
        if (not force) and (now_t - self._last_inspect_t) < 0.35 and len(self.buffer) == self._cached_buf_len:
            return self._cached_approval

        try:
            with self.lock:
                buf_len = len(self.buffer)
                # 关键优化：绝不全量 strip 上万字节，只截取尾部 8000 字节做检测，性能提升数十倍
                raw_tail = self._decode_slice(-8000 if buf_len > 8000 else 0)
                is_running = self.is_running
                pending_inspect = self._pending_inspect
                self._pending_inspect = False

            if (not force) and (not pending_inspect) and (not self._tail_looks_interactive(raw_tail)):
                self._cached_buf_len = buf_len
                self._last_inspect_t = now_t
                return self._cached_approval

            if not is_running or not raw_tail:
                res = {"type": "none"}
                self._cached_approval = res
                self._cached_buf_len = buf_len
                self._last_inspect_t = now_t
                return res

            clean = strip_ansi(raw_tail)
            lines = [l.strip() for l in clean.splitlines() if l.strip()]
            tail = lines[-40:] if len(lines) >= 40 else lines
            if not tail:
                res = {"type": "none"}
                self._cached_approval = res
                self._cached_buf_len = buf_len
                self._last_inspect_t = now_t
                return res

            # 1. 匹配选择题 (检查末尾 14 行是否有选择提示)
            footer_idx = -1
            footer_keywords = [
                'enter to select', 'esc to cancel', 'enter to submit', 'enter to confirm',
                'to navigate', 'space to select', 'space to toggle', 'toggle all',
                'use arrow keys', 'type number', 'to choose', 'select an option'
            ]
            for i in range(len(tail) - 1, max(-1, len(tail) - 14), -1):
                line_lower = tail[i].lower()
                if any(kw in line_lower for kw in footer_keywords):
                    footer_idx = i
                    break

            if footer_idx != -1:
                q_lines = tail[max(0, footer_idx - 18):footer_idx]
                footer_text = tail[footer_idx].lower()
                is_multi = any(kw in footer_text for kw in ['<space>', 'toggle all', 'multi', 'comma', '多选', '可多选', 'space to toggle'])
                parsed = parse_question_options('\n'.join(q_lines))
                q_title, opts = parsed[0], parsed[1]
                q_header = parsed[2] if len(parsed) > 2 else ''
                if len(opts) < 2:
                    parsed = parse_question_options(' '.join(q_lines))
                    q_title, opts = parsed[0], parsed[1]
                    q_header = parsed[2] if len(parsed) > 2 else q_header

                if len(opts) >= 2:
                    if looks_like_permission_prompt(q_title, opts):
                        block = '\n'.join(q_lines)
                        kind = classify_permission_kind(q_title + '\n' + block)
                        cmd = extract_permission_command(block) or q_title
                        titles = {
                            'bash': 'Run this command?',
                            'file': 'Allow file change?',
                            'webfetch': 'Allow network fetch?',
                            'sandbox': 'Allow sandbox escape?',
                            'plan': 'Ready to code?',
                            'skill': 'Allow this skill?',
                            'command': 'Allow this action?',
                        }
                        res = {
                            "type": "command",
                            "kind": kind,
                            "prompt": titles.get(kind, 'Allow this action?'),
                            "command": cmd,
                            "cwd": self.project_dir,
                            "options": opts
                        }
                    else:
                        res = {
                            "type": "questions",
                            "title": q_title or "请选择以下操作选项",
                            "header": q_header,
                            "options": opts,
                            "is_multi": is_multi
                        }
                    self._cached_approval = res
                    self._cached_buf_len = buf_len
                    self._last_inspect_t = now_t
                    return res

            # 2. 匹配命令执行授权 (y/n)
            recent_text = '\n'.join(tail[-15:])
            recent_lower = recent_text.lower()
            has_prompt = any(kw in recent_lower for kw in [
                '(y/n)', '[y/n]', 'proceed?', 'allow ', 'approve ',
                'run this command?', 'do you want to', 'always allow'
            ])
            is_history = any(kw in recent_text for kw in ['User approved', 'User declined', '已批准', '已拒绝'])

            if has_prompt and not is_history:
                kind = classify_permission_kind(recent_text)
                cmd = extract_permission_command(recent_text)
                titles = {
                    'bash': 'Run this command?',
                    'file': 'Allow file change?',
                    'webfetch': 'Allow network fetch?',
                    'sandbox': 'Allow sandbox escape?',
                    'plan': 'Ready to code?',
                    'skill': 'Allow this skill?',
                    'command': 'Claude 正在等待执行授权 (y/n)',
                }
                res = {
                    "type": "command",
                    "kind": kind,
                    "prompt": titles.get(kind, "Claude 正在等待执行授权 (y/n)"),
                    "command": cmd or titles.get(kind, ''),
                    "cwd": self.project_dir
                }
                self._cached_approval = res
                self._cached_buf_len = buf_len
                self._last_inspect_t = now_t
                return res

            # 3. 任务完成检测与状态保持
            if self.completed_payload and (now_t < self.completed_until or self.has_active_work is False):
                res = self.completed_payload
                self._cached_approval = res
                self._cached_buf_len = buf_len
                self._last_inspect_t = now_t
                return res

            status, summary, pos = latest_run_status(clean)
            if status == 'busy':
                self.saw_busy = True
                self.has_active_work = True
                self.completed_payload = None
                self.completed_until = 0
                res = {"type": "none"}
                self._cached_approval = res
                self._cached_buf_len = buf_len
                self._last_inspect_t = now_t
                return res

            idle_s = now_t - self.last_output_time
            last_line = tail[-1] if tail else ''
            looks_idle_prompt = bool(re.search(r'[❯➜]\s*$', last_line) or last_line in ('>', '❯', '➜'))

            should_complete = False
            event_src = ''
            if status == 'done' and pos > self.last_completed_pos:
                should_complete = True
                event_src = f'{pos}:{summary}'
            elif self.saw_busy and idle_s >= 1.6 and looks_idle_prompt:
                should_complete = True
                summary = '输出已停止，等待下一条指令'
                event_src = 'idle:' + last_line
                pos = len(clean)

            if should_complete:
                event_id = hashlib.md5(event_src.encode('utf-8', 'ignore')).hexdigest()[:8]
                if event_id != self.last_notified_event_id:
                    self.last_notified_event_id = event_id
                    self.last_completed_pos = max(self.last_completed_pos, pos)
                    self.has_active_work = False
                    self.saw_busy = False
                    payload = {
                        "type": "completed",
                        "title": "Claude 任务已完成",
                        "summary": f"已结束 ({summary})",
                        "event_id": event_id
                    }
                    self.completed_payload = payload
                    self.completed_until = now_t + 180  # 延长到 3 分钟，锁屏再亮屏绝不漏接
                    log_to_gui(f"[{self.name}] 检测到任务完成: {summary}")
                    res = payload
                    self._cached_approval = res
                    self._cached_buf_len = buf_len
                    self._last_inspect_t = now_t
                    return res
        except Exception as e:
            log_to_gui(f"[{self.name}] 终端状态解析异常: {e}")

        res = {"type": "none"}
        self._cached_approval = res
        self._cached_buf_len = buf_len
        self._last_inspect_t = now_t
        return res

    def get_incremental(self, offset, check_approval=True, max_bytes=0, generation=None):
        truncated = False
        with self.lock:
            total_len = len(self.buffer)
            gen = getattr(self, "_buf_generation", 0)
            stale_gen = (generation is not None and int(generation) != gen)
            if stale_gen or offset < 0 or offset > total_len:
                start = 0
                reset = True
            else:
                start = offset
                # offset=0 表示客户端还没有任何内容，整段快照必须清屏重画，避免重连叠两份横幅
                reset = (start == 0)
            if max_bytes and (total_len - start) > max_bytes:
                start = total_len - max_bytes
                truncated = True
                reset = True
            chunk = self._decode_slice(start)

        approval = self.inspect_approval_state(force=truncated) if check_approval else self._cached_approval
        if approval and approval.get("type") not in ("none", None):
            self._publish_approval_if_changed(approval)
        return {
            "data": chunk,
            "offset": total_len,
            "generation": getattr(self, "_buf_generation", 0),
            "running": self.is_running,
            "reset": reset,
            "truncated": truncated,
            "approval": approval,
            "seq_num": self.event_bus.last_seq(),
            "permission_mode": self.permission_mode,
            "conn_state": self.conn_state,
        }

    def send_input(self, text):
        with self.lock:
            if not self.is_running or not self.pty:
                return False, "会话未运行"
            try:
                self.pty.write(text + "\r\n")
                self.buf_mark_at_send = len(self.buffer)
                self.has_active_work = True
                self.saw_busy = False
                self.completed_payload = None
                self.completed_until = 0
                self._cached_buf_len = -1
                log_to_gui(f"[{self.name}] 手机下发指令: {text}")
                return True, "已发送"
            except Exception as e:
                return False, str(e)

    def send_raw_data(self, data):
        with self.lock:
            if not self.is_running or not self.pty:
                return False, "会话未运行"
            try:
                self.pty.write(data)
                if data and not data.startswith('\x1b') and data not in ('\t', '\x03'):
                    self.buf_mark_at_send = len(self.buffer)
                    self.has_active_work = True
                    self.saw_busy = False
                    self.completed_payload = None
                    self.completed_until = 0
                    self._cached_buf_len = -1
                return True, "已直通"
            except Exception as e:
                return False, str(e)

    def send_raw_key(self, key_type):
        with self.lock:
            if not self.is_running or not self.pty:
                return False, "会话未运行"
            try:
                payload = ""
                if key_type == "enter":
                    payload = "\r\n"
                elif key_type == "yes":
                    payload = "y\r\n"
                elif key_type == "no":
                    payload = "n\r\n"
                elif key_type == "ctrl_c":
                    payload = "\x03"
                elif key_type == "escape":
                    payload = "\x1b"
                elif key_type == "up":
                    payload = "\x1b[A"
                elif key_type == "down":
                    payload = "\x1b[B"
                elif key_type == "right":
                    payload = "\x1b[C"
                elif key_type == "left":
                    payload = "\x1b[D"
                elif key_type == "tab":
                    payload = "\t"
                elif key_type == "space":
                    payload = " "
                elif key_type == "shift_tab":
                    payload = "\x1b[Z"
                    log_to_gui(f"[{self.name}] 快捷切换模式: Shift+Tab")
                elif key_type == "compact":
                    payload = "/compact\r\n"
                elif key_type == "clear":
                    payload = "/clear\r\n"

                if payload and self.pty.isalive():
                    self.pty.write(payload)
                return True, "按键已触发"
            except Exception as e:
                return False, str(e)

    def apply_choice(self, mode, index=0, indices=None, text=""):
        """在本地按序写入 PTY。同一会话同时只允许一条选择序列在跑，防止方向键交错。"""
        with self.lock:
            if not self.is_running or not self.pty:
                return False, "会话未运行"
            self.has_active_work = True
            self.saw_busy = False
            self.completed_payload = None
            self.completed_until = 0
            self._cached_buf_len = -1

        def _write(data):
            with self.lock:
                if self.is_running and self.pty and self.pty.isalive():
                    self.pty.write(data)
                    return True
            return False

        def _exec():
            acquired = self._choice_lock.acquire(timeout=8)
            if not acquired:
                log_to_gui(f"[{self.name}] 选项下发被丢弃：上一次选择尚未完成")
                return
            try:
                if mode == "single":
                    # 单选下发：先按方向键移动到对应项，再单次回车确认。
                    # 严禁追加多余回车：Claude Code 连续提问时，下一题会在几十毫秒内出现，
                    # 多余的第二次回车会直接吃掉第二题的默认选项！
                    idx = max(0, int(index or 0))
                    for _ in range(idx):
                        if not _write("\x1b[B"):
                            return
                        time.sleep(0.06)
                    if not _write("\r"):
                        return
                elif mode == "multi":
                    target_indices = sorted({int(i) for i in (indices or []) if int(i) >= 0})
                    cursor = 0
                    for ti in target_indices:
                        while cursor < ti:
                            if not _write("\x1b[B"):
                                return
                            time.sleep(0.06)
                            cursor += 1
                        if not _write(" "):
                            return
                        time.sleep(0.06)
                    if not _write("\r"):
                        return
                elif mode == "custom":
                    custom = (text or "").replace("\r", " ").replace("\n", " ").strip()
                    if not custom:
                        return
                    if not _write(custom + "\r"):
                        return
                log_to_gui(f"[{self.name}] 原子化选择下发成功: mode={mode}, idx={index}, targets={indices}")
            except Exception as e:
                log_to_gui(f"[{self.name}] 选项下发异常: {e}")
            finally:
                self._choice_lock.release()

        threading.Thread(target=_exec, daemon=True, name=f"choice-{self.id}").start()
        return True, "正在执行选择"

    def _collect_session_processes(self):
        """精准提取且仅提取属于当前会话的底层进程树 (cmd.exe -> claude.exe 等)"""
        targets = []
        if not self.pty_pid:
            return targets
        try:
            import psutil
            try:
                root = psutil.Process(self.pty_pid)
                for child in root.children(recursive=True):
                    targets.append(child)
                targets.append(root)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

            target_pids = {p.pid for p in targets}
            for k_pid in list(self.known_claude_pids):
                if k_pid not in target_pids:
                    try:
                        kp = psutil.Process(k_pid)
                        # 严格回溯祖先链，避免误杀无关进程
                        curr = kp
                        is_our_child = False
                        for _ in range(5):
                            pp = curr.ppid()
                            if pp == self.pty_pid:
                                is_our_child = True
                                break
                            if pp <= 4:
                                break
                            curr = psutil.Process(pp)
                        if is_our_child:
                            targets.append(kp)
                    except Exception:
                        pass
        except Exception:
            pass
        return targets

    def stop(self):
        """强行中止会话，彻底杀灭底层所有子进程 (包括 claude.exe、node 及命令行)"""
        with self.lock:
            self._user_stopped = True
            self.is_running = False
            self.conn_state = "idle"
            killed_names = []

            # 1. 递归扫描并强杀属于当前会话的子进程树 (优先终止子孙节点)
            try:
                import psutil
                procs = self._collect_session_processes()
                for p in reversed(procs):
                    try:
                        p_name = p.name()
                        p_pid = p.pid
                        p.kill()
                        killed_names.append(f"{p_name}({p_pid})")
                    except Exception:
                        pass
                if procs:
                    try:
                        psutil.wait_procs(procs, timeout=1.5)
                    except Exception:
                        pass
            except Exception as e:
                log_to_gui(f"[{self.name}] 杀进程异常: {e}")

            # 2. 关闭 winpty 终端通道
            if self.pty:
                try:
                    self.pty.close()
                except Exception:
                    pass
                self.pty = None

            self.pty_pid = None
            self.known_claude_pids.clear()
            self.completed_payload = None
            self.has_active_work = False
            self.saw_busy = False

            stop_desc = f"已中止 Claude 进程: {', '.join(killed_names)}" if killed_names else "会话已停止"
            self._append_output(f"\r\n\x1b[33m[{self.name}] 会话已由用户中止，底层 Claude 进程已停止。\x1b[0m\r\n")
            log_to_gui(f"[{self.name}] {stop_desc}")
            return True, stop_desc

    def restart_with_dir(self, new_dir):
        with self.lock:
            self.stop()
            time.sleep(0.3)
            if new_dir and os.path.exists(new_dir):
                self.project_dir = os.path.abspath(new_dir)
            return self.start()

    def restart_with_resume(self, resume_mode="continue", claude_session_id=None):
        with self.lock:
            self.stop()
            time.sleep(0.3)
            self.resume_mode = resume_mode
            self.claude_session_id = claude_session_id
            return self.start()

    def to_dict(self):
        with self.lock:
            dir_name = os.path.basename(self.project_dir) or self.project_dir
            is_run = self.is_running
            approval_info = dict(self._cached_approval or {"type": "none"})
            pinned = self.pinned
            resume_mode = self.resume_mode
            claude_session_id = self.claude_session_id
            started_at = self.started_at
            created_at = self.created_at
            name = self.name
            project_dir = self.project_dir
            sid = self.id

        app_type = approval_info.get("type", "none")
        if app_type in ("questions", "command"):
            sess_status = "waiting"
        elif is_run:
            sess_status = "running"
        else:
            sess_status = "stopped"

        # 列表接口只下发通知所需的轻量审批字段，选项全文仍走 SSE
        light_ap = {"type": app_type}
        if app_type == "completed":
            light_ap["event_id"] = approval_info.get("event_id")
            light_ap["summary"] = approval_info.get("summary") or ""
        elif app_type == "command":
            light_ap["prompt"] = (approval_info.get("prompt") or "")[:240]
        elif app_type == "questions":
            title = approval_info.get("title") or ""
            light_ap["title"] = title[:240]
            light_ap["prompt"] = title[:240]

        return {
            "id": sid,
            "name": name,
            "dir_name": dir_name,
            "project_dir": project_dir,
            "running": is_run,
            "status": sess_status,  # "waiting" | "running" | "stopped"
            "approval_type": app_type,
            "approval": light_ap,
            "pinned": pinned,
            "resume_mode": resume_mode,
            "claude_session_id": claude_session_id,
            "started_at": started_at,
            "created_at": created_at,
            "permission_mode": getattr(self, "permission_mode", "default"),
            "conn_state": getattr(self, "conn_state", "idle"),
            "seq_num": self.event_bus.last_seq() if getattr(self, "event_bus", None) else 0,
        }


# ==================== 多会话管理中心 (ClaudeMultiSessionManager) ====================
class ClaudeMultiSessionManager:
    """管理多个独立的 Claude 会话实例，支持增删改查、热切换、工作区预设与本地状态持久化"""
    def __init__(self):
        self.sessions = {}
        self.active_session_id = None
        self.lock = threading.RLock()
        self.counter = 1
        self.auto_continue = True
        self._watchdog_stop = threading.Event()
        threading.Thread(
            target=self._approval_watchdog_loop,
            daemon=True,
            name="approval-watchdog"
        ).start()

    def _approval_watchdog_loop(self):
        """锁屏后 SSE 会被浏览器挂起，后台会话也没人拉流。
        独立巡检所有运行中的会话，把 waiting/completed 写进缓存，列表轮询才能推通知。
        同时自动探测并绑定全新会话生成的 Claude session_id，让历史记录与侧栏标题实时同步。"""
        while not self._watchdog_stop.wait(1.2):
            try:
                with self.lock:
                    sessions = list(self.sessions.values())
            except Exception:
                sessions = []
            for s in sessions:
                if not getattr(s, "is_running", False):
                    continue
                try:
                    # 动态探测未绑定的 claude_session_id
                    if not getattr(s, "claude_session_id", None):
                        found_cid = discover_latest_claude_session_id(s.project_dir)
                        if found_cid:
                            s.claude_session_id = found_cid
                            try:
                                self.save_state()
                            except Exception:
                                pass
                    force = bool(getattr(s, "saw_busy", False) or getattr(s, "_pending_inspect", False))
                    try:
                        s._poll_jsonl_protocol()
                    except Exception:
                        pass
                    s.inspect_approval_state(force=force)
                except Exception:
                    pass

    def save_state(self, current_work_dir=None):
        """将当前会话列表和状态持久化存储至磁盘"""
        try:
            os.makedirs(STATE_DIR, exist_ok=True)
            with self.lock:
                sess_list = []
                for s in self.sessions.values():
                    sess_list.append({
                        "id": s.id,
                        "name": s.name,
                        "project_dir": s.project_dir,
                        "pinned": s.pinned,
                        "resume_mode": getattr(s, "resume_mode", "continue"),
                        "claude_session_id": getattr(s, "claude_session_id", None),
                        "created_at": getattr(s, "created_at", "")
                    })

                # last_work_dir 只记录桌面 GUI 当前选择，绝不拿活跃会话目录去覆盖各会话自己的 project_dir
                saved_work_dir = current_work_dir
                if not saved_work_dir:
                    try:
                        with open(STATE_FILE, "r", encoding="utf-8", errors="ignore") as f:
                            prev = json.load(f)
                        saved_work_dir = prev.get("last_work_dir")
                    except Exception:
                        saved_work_dir = None
                if not saved_work_dir:
                    saved_work_dir = os.getcwd()

                data = {
                    "version": 1,
                    "last_work_dir": saved_work_dir,
                    "auto_continue": self.auto_continue,
                    "active_session_id": self.active_session_id,
                    "counter": self.counter,
                    "sessions": sess_list
                }
            with open(STATE_FILE, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            log_to_gui(f"保存会话状态异常: {e}")

    def load_state(self):
        """从磁盘读取历史状态配置（仅载入元数据，不立即创建 PTY 进程）"""
        if not os.path.exists(STATE_FILE):
            return None
        try:
            with open(STATE_FILE, "r", encoding="utf-8", errors="ignore") as f:
                data = json.load(f)
            self.counter = data.get("counter", 1)
            self.auto_continue = data.get("auto_continue", True)
            raw_sessions = data.get("sessions", [])
            saved_active = data.get("active_session_id")

            with self.lock:
                self.sessions.clear()
                for s_item in raw_sessions:
                    sid = s_item.get("id")
                    name = s_item.get("name")
                    pdir = rebind_known_project_dir(name, s_item.get("project_dir"))
                    if not sid or not pdir or not os.path.exists(pdir):
                        continue
                    sess = ClaudeSession(
                        sid,
                        name,
                        pdir,
                        resume_mode=s_item.get("resume_mode", "continue"),
                        claude_session_id=s_item.get("claude_session_id")
                    )
                    sess.pinned = s_item.get("pinned", False)
                    if s_item.get("created_at"):
                        sess.created_at = s_item.get("created_at")
                    self.sessions[sid] = sess

                if saved_active and saved_active in self.sessions:
                    self.active_session_id = saved_active
                elif self.sessions:
                    self.active_session_id = next(iter(self.sessions))
                else:
                    self.active_session_id = None

                self._collapse_duplicate_dirs()
                self._ensure_pinned_workspaces()

            log_to_gui(f"已恢复本地配置：共 {len(self.sessions)} 个工作区会话 (激活: {self.active_session_id})")
            try:
                self.save_state()
            except Exception:
                pass
            return data
        except Exception as e:
            log_to_gui(f"载入本地会话状态失败: {e}")
            return None

    def _collapse_duplicate_dirs(self):
        """只合并「同一目录 + 同一 Claude 对话 ID」的重复绑定；同目录允许多个并发会话。"""
        by_key = {}
        for sess in list(self.sessions.values()):
            cid = getattr(sess, "claude_session_id", None) or ""
            if not cid:
                continue
            key = (_norm_dir(sess.project_dir), cid)
            prev = by_key.get(key)
            if not prev:
                by_key[key] = sess
                continue
            keep, drop = prev, sess
            if sess.is_running and not prev.is_running:
                keep, drop = sess, prev
            elif sess.id == self.active_session_id and prev.id != self.active_session_id:
                keep, drop = sess, prev
            by_key[key] = keep
            if drop is not keep:
                try:
                    drop.stop()
                except Exception:
                    pass
                self.sessions.pop(drop.id, None)
                if self.active_session_id == drop.id:
                    self.active_session_id = keep.id

    def _ensure_pinned_workspaces(self):
        """确保环境变量里配置的常驻项目作为独立工作区出现。"""
        for path, label in PINNED_PROJECT_WORKSPACES:
            if not path or not os.path.isdir(path):
                continue
            existing = None
            target = _norm_dir(path)
            for s in self.sessions.values():
                if _norm_dir(s.project_dir) == target:
                    existing = s
                    break
            if existing:
                auto_names = {
                    "默认会话",
                    label,
                    f"项目: {label}",
                    f"项目: {os.path.basename(path)}",
                }
                stripped = re.sub(r"^项目:\s*", "", existing.name or "").strip()
                if existing.name in auto_names or stripped.lower() == label.lower():
                    existing.name = label
                continue
            sid = f"sess_{int(time.time())}_{secrets.token_hex(3)}"
            sess = ClaudeSession(sid, label, path, resume_mode="new")
            self.sessions[sid] = sess
            log_to_gui(f"已加入常驻项目工作区 [{label}] ({path})")
            if not self.active_session_id:
                self.active_session_id = sid

    def get_active_session(self):
        with self.lock:
            if self.active_session_id and self.active_session_id in self.sessions:
                return self.sessions[self.active_session_id]
            if self.sessions:
                first_id = next(iter(self.sessions))
                self.active_session_id = first_id
                return self.sessions[first_id]
            return None

    def get_session(self, session_id=None):
        with self.lock:
            if session_id and session_id in self.sessions:
                return self.sessions[session_id]
            return self.get_active_session()

    def find_session_by_dir(self, project_dir):
        if not project_dir:
            return None
        try:
            target_norm = os.path.normcase(os.path.abspath(project_dir))
        except Exception:
            return None
        with self.lock:
            for s in self.sessions.values():
                try:
                    if os.path.normcase(os.path.abspath(s.project_dir)) == target_norm:
                        return s
                except Exception:
                    continue
        return None

    def find_session_by_claude_id(self, claude_session_id):
        if not claude_session_id:
            return None
        with self.lock:
            for s in self.sessions.values():
                if getattr(s, "claude_session_id", None) == claude_session_id:
                    return s
        return None

    def create_session(self, name=None, project_dir=None, cols=120, rows=36, resume_mode="new", claude_session_id=None, autostart=True, force_new=False, theme=None):
        with self.lock:
            if name:
                project_dir = rebind_known_project_dir(name, project_dir)
            target_dir = os.path.abspath(project_dir) if project_dir and os.path.exists(project_dir) else os.environ.get("USERPROFILE", "C:\\")

            # 同一段 Claude 对话已有活会话：只热切，绝不重启、绝不杀掉别的会话
            if claude_session_id:
                existing_cid = self.find_session_by_claude_id(claude_session_id)
                if existing_cid:
                    self.active_session_id = existing_cid.id
                    if autostart and not existing_cid.is_running:
                        ok, msg = existing_cid.start(theme=theme)
                    else:
                        ok, msg = True, "已切换到该对话（未中断）"
                    self.save_state()
                    log_to_gui(f"复用已有对话会话 [{existing_cid.name}] id={existing_cid.id}")
                    return existing_cid, ok, msg

            # 添加项目工作区：同目录已有会话则进入该项目，不额外开进程
            if not force_new and not claude_session_id:
                existing = self.find_session_by_dir(target_dir)
                if existing:
                    self.active_session_id = existing.id
                    if name and name.strip() and name.strip() != existing.name:
                        existing.name = name.strip()
                    if autostart and not existing.is_running:
                        ok, msg = existing.start(theme=theme)
                    else:
                        ok, msg = True, "已复用该工作区现有会话"
                    self.save_state()
                    log_to_gui(f"工作区已存在，复用会话 [{existing.name}] ({existing.project_dir})")
                    return existing, ok, msg

            sid = f"sess_{int(time.time())}_{secrets.token_hex(3)}"
            dir_base = os.path.basename(target_dir) or target_dir
            if not name or not name.strip():
                name = f"项目: {dir_base}"
                self.counter += 1
            else:
                name = name.strip()

            session = ClaudeSession(sid, name, target_dir, cols=cols, rows=rows, resume_mode=resume_mode, claude_session_id=claude_session_id)
            if theme:
                session.theme = theme
            self.sessions[sid] = session
            self.active_session_id = sid
            ok, msg = (True, "就绪")
            if autostart:
                ok, msg = session.start(theme=theme)
                log_to_gui(f"新建并发会话 [{name}] (工作区: {target_dir} | 模式: {resume_mode} | 主题: {theme or '默认'}) -> {msg}")

            self.save_state()
            return session, ok, msg

    def switch_active(self, session_id):
        with self.lock:
            if session_id in self.sessions:
                self.active_session_id = session_id
                sess = self.sessions[session_id]
                # 首次切入才拉起 PTY；已在跑的会话只切画面，绝不重启 Claude
                if not sess.is_running:
                    sess.start()
                    log_to_gui(f"切换并首次启动会话: [{sess.name}] ({sess.project_dir})")
                else:
                    log_to_gui(f"热切换至已运行会话: [{sess.name}] ({sess.project_dir})")
                self.save_state()
                return True, sess
            return False, None

    def rename_session(self, session_id, new_name):
        with self.lock:
            if session_id in self.sessions:
                self.sessions[session_id].name = new_name.strip()
                log_to_gui(f"会话 [{session_id}] 重命名为: {new_name}")
                self.save_state()
                return True
            return False

    def toggle_pin_session(self, session_id):
        with self.lock:
            if session_id in self.sessions:
                self.sessions[session_id].pinned = not self.sessions[session_id].pinned
                log_to_gui(f"会话 [{self.sessions[session_id].name}] 置顶状态: {self.sessions[session_id].pinned}")
                self.save_state()
                return True, self.sessions[session_id].pinned
            return False, False

    def stop_session(self, session_id):
        """仅中止指定会话的底层 Claude 进程，保留会话工作区记录以供再次启动"""
        with self.lock:
            if session_id in self.sessions:
                sess = self.sessions[session_id]
                ok, msg = sess.stop()
                self.save_state()
                return ok, msg
            return False, "会话不存在"

    def stop_project_sessions(self, project_dir):
        """中止某个项目目录下的所有正在运行的会话进程"""
        with self.lock:
            target_norm = _norm_dir(project_dir)
            stopped = []
            for s in list(self.sessions.values()):
                if _norm_dir(s.project_dir) == target_norm and s.is_running:
                    ok, msg = s.stop()
                    stopped.append(s.name)
            self.save_state()
            return True, f"已中止项目下 {len(stopped)} 个会话进程" if stopped else "没有正在运行的会话"

    def delete_session(self, session_id):
        with self.lock:
            if session_id in self.sessions:
                sess = self.sessions.pop(session_id)
                sess.stop()
                log_to_gui(f"已关闭并销毁会话: [{sess.name}]")
                if self.active_session_id == session_id:
                    self.active_session_id = next(iter(self.sessions)) if self.sessions else None
                self.save_state()
                return True
            return False

    def stop_all(self, keep_config=True):
        """停止所有会话的底层进程。若 keep_config 为 True，则保留会话清单供下次启动复用"""
        with self.lock:
            for s in self.sessions.values():
                s.stop()
            if not keep_config:
                self.sessions.clear()
                self.active_session_id = None
                log_to_gui("所有 Claude 会话已安全销毁并终止")
            else:
                log_to_gui(f"已暂停后台 {len(self.sessions)} 个 Claude 终端进程 (配置已安全保留)")

    def list_sessions(self):
        with self.lock:
            sorted_sessions = sorted(
                self.sessions.values(),
                key=lambda x: (not x.pinned, x.created_at)
            )
            return {
                "active_id": self.active_session_id,
                "stream_mode": getattr(gui_app_instance, "stream_mode_var", None).get() if gui_app_instance else "sse",
                "sessions": [s.to_dict() for s in sorted_sessions]
            }


class HostSystemMonitor:
    """实时监控宿主机硬件指标 (CPU利用率、内存占用、磁盘繁忙百分比与I/O速率)
    磁盘繁忙率优先读 PDH % Idle Time（中英计数器名都试），再回退到 psutil busy_time。
    绝不用 read_time+write_time 相加：SSD 并行 IO 会把这个值堆到 80%~100%，看起来像磁盘打满。
    """
    def __init__(self):
        self.cpu = 0.0
        self.mem_pct = 0.0
        self.mem_used_gb = 0.0
        self.mem_total_gb = 0.0
        self.disk_active_pct = 0.0
        self.disk_read_speed = 0.0
        self.disk_write_speed = 0.0
        self._last_io = None
        self._last_t = time.time()
        self._query = None
        self._counter = None
        self._idle_counter = True
        self._init_pdh()
        self._running = True
        threading.Thread(target=self._loop, daemon=True).start()

    def _init_pdh(self):
        try:
            import win32pdh
            self._query = win32pdh.OpenQuery()
            # 优先 % Idle Time：100 - idle 才是真实繁忙率；中文系统计数器名不同，逐个试
            for path in (
                r'\PhysicalDisk(_Total)\% Idle Time',
                r'\PhysicalDisk(_Total)\空闲时间百分比',
                r'\LogicalDisk(_Total)\% Idle Time',
            ):
                try:
                    self._counter = win32pdh.AddCounter(self._query, path)
                    self._idle_counter = True
                    win32pdh.CollectQueryData(self._query)
                    return
                except Exception:
                    self._counter = None
            for path in (
                r'\PhysicalDisk(_Total)\% Disk Time',
                r'\PhysicalDisk(_Total)\磁盘时间百分比',
            ):
                try:
                    self._counter = win32pdh.AddCounter(self._query, path)
                    self._idle_counter = False
                    win32pdh.CollectQueryData(self._query)
                    return
                except Exception:
                    self._counter = None
            self._query = None
        except Exception:
            self._query = None
            self._counter = None

    def _loop(self):
        import psutil
        while self._running:
            try:
                self.cpu = round(psutil.cpu_percent(interval=None), 1)
                vm = psutil.virtual_memory()
                self.mem_pct = round(vm.percent, 1)
                self.mem_used_gb = round(vm.used / (1024**3), 1)
                self.mem_total_gb = round(vm.total / (1024**3), 1)

                active_pct = None
                if self._query and self._counter:
                    try:
                        import win32pdh
                        win32pdh.CollectQueryData(self._query)
                        _, val = win32pdh.GetFormattedCounterValue(self._counter, win32pdh.PDH_FMT_DOUBLE)
                        if self._idle_counter:
                            active_pct = min(100.0, max(0.0, 100.0 - val))
                        else:
                            active_pct = min(100.0, max(0.0, val))
                    except Exception:
                        pass

                now = time.time()
                dt = max(0.001, now - self._last_t)
                cur_io = psutil.disk_io_counters()
                if self._last_io and cur_io:
                    r_bytes = max(0, cur_io.read_bytes - self._last_io.read_bytes)
                    w_bytes = max(0, cur_io.write_bytes - self._last_io.write_bytes)
                    self.disk_read_speed = round((r_bytes / (1024**2)) / dt, 1)
                    self.disk_write_speed = round((w_bytes / (1024**2)) / dt, 1)
                    if active_pct is None:
                        busy_now = getattr(cur_io, "busy_time", None)
                        busy_prev = getattr(self._last_io, "busy_time", None)
                        if busy_now is not None and busy_prev is not None:
                            busy_ms = max(0, busy_now - busy_prev)
                            active_pct = min(100.0, max(0.0, (busy_ms / (dt * 1000.0)) * 100.0))
                        else:
                            # 最后兜底：按读写速率估算，避免 read_time+write_time 在 SSD 上虚高
                            throughput = self.disk_read_speed + self.disk_write_speed
                            active_pct = min(100.0, throughput / 2.0)
                self._last_io = cur_io
                self._last_t = now

                if active_pct is not None:
                    self.disk_active_pct = round(active_pct, 1)
            except Exception:
                pass
            time.sleep(2.0)

    def get_stats(self):
        return {
            "cpu": self.cpu,
            "mem_pct": self.mem_pct,
            "mem_used_gb": self.mem_used_gb,
            "mem_total_gb": self.mem_total_gb,
            "disk_active_pct": self.disk_active_pct,
            "disk_read_speed": self.disk_read_speed,
            "disk_write_speed": self.disk_write_speed
        }

host_monitor = HostSystemMonitor()

def get_host_system_stats():
    return host_monitor.get_stats()


claude_mgr = ClaudeMultiSessionManager()

# ==================== 原生终端高精度渲染 Web UI (纯矢量无Emoji设计 + ApprovalCard + FileNav) ====================
def _load_html_page_source():
    """从独立 web/index.html 资源文件加载，前后端彻底解耦"""
    html_path = os.path.join(_app_dir(), "claude_remote", "web", "index.html")
    if not os.path.exists(html_path):
        html_path = os.path.join(os.path.dirname(_app_dir()), "claude_remote", "web", "index.html")
    if not os.path.exists(html_path):
        meipass = getattr(sys, "_MEIPASS", "")
        if meipass:
            html_path = os.path.join(meipass, "claude_remote", "web", "index.html")
    if os.path.exists(html_path):
        with open(html_path, "r", encoding="utf-8") as f:
            return f.read()
    # 兼容回退：如果位于当前目录下的 claude_remote/web/index.html
    local_path = os.path.join(os.getcwd(), "claude_remote", "web", "index.html")
    if os.path.exists(local_path):
        with open(local_path, "r", encoding="utf-8") as f:
            return f.read()
    raise FileNotFoundError(f"找不到前端静态文件 index.html: {html_path}")

HTML_PAGE = _load_html_page_source()
HTML_PAGE_BYTES = HTML_PAGE.encode("utf-8")
HTML_PAGE_GZIP = gzip.compress(HTML_PAGE_BYTES, compresslevel=6)

# ==================== HTTP 请求处理 ====================
# 防暴力破解策略：连续认证失败 IP 锁定 (带 TTL 与容量上限防内存泄漏)
AUTH_FAILURES = {}  # ip -> {"count": int, "lock_until": float, "last_t": float}
AUTH_LOCK = threading.Lock()
MAX_AUTH_FAILURES_SIZE = 2000
MAX_JSON_BODY = 1 * 1024 * 1024
MAX_POST_BODY = 12 * 1024 * 1024
MAX_UPLOAD_BYTES = 8 * 1024 * 1024
ALLOWED_IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".heic", ".heif"}


class ClaudeHttpHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def end_headers(self):
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'SAMEORIGIN')
        # same-origin：同源 POST 必须带 Referer，供 _origin_allowed 校验 /p/{port}/
        # 切勿改回 no-referrer，否则会话 create/resume 会被当成跨站 403
        self.send_header('Referrer-Policy', 'same-origin')
        self.send_header('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), screen-wake-lock=*')
        super().end_headers()

    def _forbid(self, msg="403 Forbidden"):
        body = msg.encode('utf-8')
        self.send_response(403)
        self.send_header('Content-Type', 'text/plain; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Connection', 'close')
        self.end_headers()
        try:
            self.wfile.write(body)
        except Exception:
            pass
        self.close_connection = True

    def _not_found(self):
        body = b'404 Not Found'
        self.send_response(404)
        self.send_header('Content-Type', 'text/plain; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Connection', 'keep-alive')
        self.end_headers()
        try:
            self.wfile.write(body)
        except Exception:
            pass

    def _read_json_body(self, max_bytes):
        try:
            length = int(self.headers.get('Content-Length', 0) or 0)
        except (TypeError, ValueError):
            length = 0
        if length < 0:
            length = 0
        if length > max_bytes:
            self._send_json(413, {"success": False, "error": "请求体过大"}, extra_headers={"Connection": "close"})
            self.close_connection = True
            return None
        raw = self.rfile.read(length) if length > 0 else b"{}"
        try:
            data = json.loads(raw.decode('utf-8'))
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    def _check_rate_limit(self, client_ip):
        now = time.time()
        with AUTH_LOCK:
            record = AUTH_FAILURES.get(client_ip)
            if record and now < record.get("lock_until", 0):
                return False, int(record["lock_until"] - now)
            return True, 0

    def _record_auth_result(self, client_ip, success):
        now = time.time()
        with AUTH_LOCK:
            # 自动淘汰过期或过量记录 (LRU/TTL 机制)
            if len(AUTH_FAILURES) > MAX_AUTH_FAILURES_SIZE:
                expired = [k for k, v in AUTH_FAILURES.items() if now > v.get("lock_until", 0) and now - v.get("last_t", 0) > 3600]
                for k in expired:
                    AUTH_FAILURES.pop(k, None)
                if len(AUTH_FAILURES) > (MAX_AUTH_FAILURES_SIZE + 500):
                    AUTH_FAILURES.clear()

            if success:
                AUTH_FAILURES.pop(client_ip, None)
            else:
                record = AUTH_FAILURES.setdefault(client_ip, {"count": 0, "lock_until": 0, "last_t": now})
                record["count"] += 1
                record["last_t"] = now
                # 连续失败 5 次，锁定 5 分钟；失败 10 次，锁定 30 分钟
                if record["count"] >= 10:
                    record["lock_until"] = now + 1800
                elif record["count"] >= 5:
                    record["lock_until"] = now + 300

    def _get_client_ip(self):
        """安全且准确地获取真实客户端 IP：
        如果直连地址是本地回环 (127.0.0.1/::1)，说明经过了本地 FRP 穿透或 Nginx 反代。
        此时优先检查 X-Forwarded-For 与 X-Real-IP：
        1. 针对 X-Forwarded-For 列表，取可信上游反代追加的最右侧可信客户端 IP（防御左侧攻击者伪造注入）。
        2. 经过 ipaddress 标准库做合法格式校验，杜绝任何非法字符注入。
        """
        raw_ip = self.client_address[0] if self.client_address else "unknown"
        if raw_ip in ("127.0.0.1", "::1", "localhost"):
            candidate = ""
            xff = self.headers.get("X-Forwarded-For")
            if xff:
                parts = [p.strip() for p in xff.split(",") if p.strip()]
                for p in reversed(parts):
                    try:
                        ip_obj = ipaddress.ip_address(p)
                        if not ip_obj.is_loopback:
                            candidate = str(ip_obj)
                            break
                    except ValueError:
                        continue
            if not candidate:
                x_real = self.headers.get("X-Real-IP", "").strip()
                if x_real:
                    try:
                        ip_obj = ipaddress.ip_address(x_real)
                        candidate = str(ip_obj)
                    except ValueError:
                        pass
            if candidate:
                return candidate
        return raw_ip

    def _parse_cookies(self):
        cookies = {}
        header = self.headers.get("Cookie", "") or ""
        for part in header.split(";"):
            if "=" not in part:
                continue
            k, v = part.split("=", 1)
            cookies[k.strip()] = unquote(v.strip())
        return cookies

    def _cookie_path(self):
        return PUBLIC_COOKIE_PATH or "/"

    def _is_https_request(self):
        host = (self.headers.get("Host") or "").split(":")[0].lower()
        return host == PUBLIC_HTTPS_HOST.lower()

    def _session_cookie_header(self, session_id, max_age=86400):
        # 会话票 ≠ 主 Token。HttpOnly + SameSite=Lax，JS 读不到；Path 绑在本端口。
        parts = [
            f"claude_sess={quote(session_id, safe='')}",
            f"Path={self._cookie_path()}",
            f"Max-Age={int(max_age)}",
            "HttpOnly",
            "SameSite=Lax",
        ]
        if self._is_https_request():
            parts.append("Secure")
        return "; ".join(parts)

    def _csrf_cookie_header(self, csrf, max_age=86400):
        # 双提交 CSRF：可读 Cookie + 请求头，Path 绑本端口，其它 /p/{port}/ 读不到。
        parts = [
            f"claude_csrf={quote(csrf, safe='')}",
            f"Path={self._cookie_path()}",
            f"Max-Age={int(max_age)}",
            "SameSite=Lax",
        ]
        if self._is_https_request():
            parts.append("Secure")
        return "; ".join(parts)

    def _csrf_ok(self):
        expected = access_sessions.csrf_for(self._extract_session_id())
        got = (self.headers.get("X-CSRF-Token") or "").strip()
        if not expected or not got:
            return False
        try:
            return hmac.compare_digest(got, expected)
        except Exception:
            return False

    def _token_matches(self, token):
        if not AUTH_TOKEN or not token:
            return False
        try:
            return hmac.compare_digest(token, AUTH_TOKEN)
        except Exception:
            return False

    def _extract_master_token(self):
        auth_header = self.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:].strip()
            if token:
                return token
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        return (qs.get("token", [""])[0] or "").strip()

    def _extract_session_id(self):
        return (self._parse_cookies().get("claude_sess") or "").strip()

    def _origin_host_allowed(self, origin):
        if not origin:
            return False
        try:
            parsed = urlparse(origin)
        except Exception:
            return False
        host = (parsed.hostname or "").lower()
        if host == PUBLIC_HTTPS_HOST.lower():
            return parsed.scheme in ("https", "http")
        if host in ("127.0.0.1", "localhost"):
            return parsed.scheme in ("http", "https")
        return False

    def _origin_allowed(self):
        """POST 必须来自本实例页面，严格绑定域名与 /p/{port}/ 路径，彻底杜绝同域跨端口骑劫。"""
        origin = self.headers.get("Origin", "").strip()
        referer = self.headers.get("Referer", "").strip()

        # 校验主机源
        if origin and not self._origin_host_allowed(origin):
            return False

        if not referer:
            # 旧页曾发 no-referrer：刷新后主 Token 已从 URL 剥离。
            # Origin 不含路径，不能单独防 /p/其它端口/ 同域骑劫；改走双提交 CSRF。
            return self._csrf_ok()

        try:
            ref = urlparse(referer)
            fake_origin = f"{ref.scheme}://{ref.netloc}"
            if not self._origin_host_allowed(fake_origin):
                return False
            # 关键防御：公网反代路径 /p/PORT/ 时 Referer 必须命中本端口，禁止被同域名其它租户骑劫
            my_path = self._cookie_path()
            if my_path and my_path != "/":
                ref_path = ref.path or "/"
                prefix = my_path if my_path.endswith("/") else my_path + "/"
                if not (ref_path.startswith(prefix) or ref_path.rstrip("/") == prefix.rstrip("/")):
                    return self._csrf_ok()
            return True
        except Exception:
            return self._csrf_ok()

    def _get_cors_origin(self):
        """精确匹配 Origin，禁止 evil.com 等域名绕过。"""
        req_origin = self.headers.get("Origin", "").strip()
        if self._origin_host_allowed(req_origin):
            return req_origin
        return None

    def _auth(self, require_device=True, record_failure=True):
        client_ip = self._get_client_ip()
        allowed, remaining = self._check_rate_limit(client_ip)
        if not allowed:
            return False

        # 主 Token：Bearer / ?token=（仅扫码首次）。Cookie 只认短期会话票，不放主密钥。
        master = self._extract_master_token()
        is_valid = self._token_matches(master)
        if not is_valid:
            is_valid = access_sessions.valid(self._extract_session_id(), client_ip)
        # 只有在非本地未伪造情况下才针对具体外部 IP 计数；若获取不到外部真实 IP，不滥锁 127.0.0.1
        if record_failure and client_ip not in ("127.0.0.1", "::1", "unknown"):
            self._record_auth_result(client_ip, is_valid)
        if not is_valid:
            return False

        # 如果开启了 2FA，并且接口要求校验设备授权：
        if require_device and security_mgr.enabled:
            dev_token = self.headers.get("X-Device-Token", "").strip()
            if not dev_token:
                parsed = urlparse(self.path)
                qs = parse_qs(parsed.query)
                dev_token = qs.get('device_token', [''])[0].strip()
            if not dev_token:
                cookies = self._parse_cookies()
                dev_token = (cookies.get("claude_device_token") or "").strip()
            if not security_mgr.is_session_valid(dev_token):
                return False
            security_mgr.touch_session(dev_token, client_ip)
        return True

    def _send_json(self, code, data, extra_headers=None):
        body = json.dumps(data, ensure_ascii=False).encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        cors = self._get_cors_origin()
        if cors:
            self.send_header('Access-Control-Allow-Origin', cors)
            self.send_header('Vary', 'Origin')
            self.send_header('Access-Control-Allow-Credentials', 'true')
        extra_headers = extra_headers or {}
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Connection', extra_headers.get('Connection', 'keep-alive'))
        for k, v in extra_headers.items():
            if k.lower() == 'connection':
                continue
            self.send_header(k, v)
        self.end_headers()
        try:
            self.wfile.write(body)
        except Exception:
            pass

    def do_GET(self):
        parsed = urlparse(self.path)
        p = parsed.path
        qs = parse_qs(parsed.query)

        if p == "/":
            # 首页加载只校验主访问 Token，无需要求 device_token（否则新设备无法加载出 2FA 界面）
            if not self._auth(require_device=False):
                self._forbid("403 Forbidden - Invalid Token")
                return

            # 扫码首次进入：主 Token 只用来换一张短期会话票，再 302 掉地址栏密钥。
            qs_token = (qs.get("token", [""])[0] or "").strip()
            set_cookie = None
            if self._token_matches(qs_token):
                sess_id = access_sessions.issue(self._get_client_ip())
                set_cookie = self._session_cookie_header(sess_id)
                csrf_cookie = self._csrf_cookie_header(access_sessions.csrf_for(sess_id))
                clean_qs = []
                for k, vals in qs.items():
                    if k == "token":
                        continue
                    for v in vals:
                        clean_qs.append(f"{quote(k, safe='')}={quote(v, safe='')}")
                location = "./"
                if clean_qs:
                    location = "./?" + "&".join(clean_qs)
                self.send_response(302)
                self.send_header("Location", location)
                self.send_header("Set-Cookie", set_cookie)
                if csrf_cookie:
                    self.send_header("Set-Cookie", csrf_cookie)
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", "0")
                self.send_header("Connection", "keep-alive")
                self.end_headers()
                return

            accept_enc = self.headers.get('Accept-Encoding', '')
            use_gzip = 'gzip' in accept_enc.lower()
            body = HTML_PAGE_GZIP if use_gzip else HTML_PAGE_BYTES

            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            csrf_val = access_sessions.csrf_for(self._extract_session_id())
            if csrf_val:
                self.send_header('Set-Cookie', self._csrf_cookie_header(csrf_val))
            cors = self._get_cors_origin()
            if cors:
                self.send_header('Access-Control-Allow-Origin', cors)
                self.send_header('Vary', 'Origin, Accept-Encoding')
                self.send_header('Access-Control-Allow-Credentials', 'true')
            else:
                self.send_header('Vary', 'Accept-Encoding')
            self.send_header('Connection', 'keep-alive')
            if use_gzip:
                self.send_header('Content-Encoding', 'gzip')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            try:
                self.wfile.write(body)
            except Exception:
                pass
        elif p in ("/manifest.webmanifest", "/manifest.json", "/site.webmanifest"):
            manifest = {
                "name": "Claude Code Remote",
                "short_name": "Claude遥控",
                "start_url": "./",
                "display": "standalone",
                "background_color": "#1c1c1c",
                "theme_color": "#1c1c1c",
                "lang": "zh-CN",
            }
            body = json.dumps(manifest, ensure_ascii=False).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/manifest+json; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            try:
                self.wfile.write(body)
            except Exception:
                pass
        elif p == "/sw.js":
            # 未登录也返回空脚本：避免浏览器把 403 缓存成“整站 SW 失败/旧恶意脚本残留”
            authorized = self._auth(require_device=False, record_failure=False)
            sw_scope = PUBLIC_COOKIE_PATH or "./"
            if authorized:
                sw_code = """self.addEventListener('install', (e) => self.skipWaiting());
self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()));
self.addEventListener('notificationclick', (e) => {
  e.notification.close();
  const data = e.notification.data || {};
  e.waitUntil(
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then((clientList) => {
      for (const client of clientList) {
        if ('focus' in client) {
          try { client.postMessage({ type: 'NOTIF_CLICK', data: data }); } catch(err) {}
          return client.focus();
        }
      }
      if (self.clients.openWindow) return self.clients.openWindow('./');
    })
  );
});"""
            else:
                sw_code = "self.addEventListener('install', (e) => self.skipWaiting());\n"
            body = sw_code.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript; charset=utf-8")
            self.send_header("Service-Worker-Allowed", sw_scope)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            try:
                self.wfile.write(body)
            except Exception:
                pass
        elif p == "/favicon.ico":
            self.send_response(204)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "keep-alive")
            self.end_headers()
        elif p == "/api/auth/2fa_status":
            # 状态检查只验证主 Token，返回 2FA 开关状态及当前 device_token 是否已授信
            if not self._auth(require_device=False):
                self._forbid(); return
            dev_token = self.headers.get("X-Device-Token", "").strip() or qs.get('device_token', [''])[0].strip()
            is_valid = security_mgr.is_session_valid(dev_token)
            self._send_json(200, {
                "enabled": security_mgr.enabled,
                "authenticated": is_valid
            })
        elif p == "/api/sessions":
            if not self._auth():
                self._forbid(); return
            sess_data = claude_mgr.list_sessions()
            # 会话列表轻量哈希 ETag 304 优化
            summary_str = json.dumps([
                sess_data.get("active_id"),
                [(
                    s.get("id"), s.get("status"), s.get("running"), s.get("pinned"), s.get("name"),
                    s.get("approval_type"),
                    (s.get("approval") or {}).get("event_id"),
                    ((s.get("approval") or {}).get("prompt") or (s.get("approval") or {}).get("title") or "")[:80]
                ) for s in sess_data.get("sessions", [])]
            ], sort_keys=True)
            etag = f'"{hashlib.md5(summary_str.encode("utf-8")).hexdigest()[:16]}"'
            if_none_match = self.headers.get("If-None-Match", "").strip()
            if if_none_match == etag:
                self.send_response(304)
                cors = self._get_cors_origin()
                if cors:
                    self.send_header('Access-Control-Allow-Origin', cors)
                    self.send_header('Vary', 'Origin')
                    self.send_header('Access-Control-Allow-Credentials', 'true')
                self.send_header("ETag", etag)
                self.send_header("Connection", "keep-alive")
                self.end_headers()
                return
            self._send_json(200, sess_data, extra_headers={"ETag": etag})
        elif p == "/api/stream_sse":
            # ==================== 原生 Server-Sent Events (SSE) 终端推流通道 ====================
            if not self._auth():
                self._forbid(); return
            sid = qs.get('session_id', [''])[0]
            sess = claude_mgr.get_session(sid)
            if not sess:
                self._not_found(); return
            # Last-Event-ID = 事件序号（锁屏重连补洞）；query offset 仍是 PTY 字节位移
            req_last_id = self.headers.get("Last-Event-ID", "").strip()
            since_seq = 0
            if req_last_id and req_last_id.isdigit():
                since_seq = int(req_last_id)
            else:
                try:
                    since_seq = int(qs.get('since', [0])[0] or 0)
                except Exception:
                    since_seq = 0
            try:
                offset = int(qs.get('offset', [-1])[0])
            except Exception:
                offset = -1
            gen_param = qs.get('gen', [None])[0]

            self.send_response(200)
            self.send_header('Content-Type', 'text/event-stream; charset=utf-8')
            self.send_header('Cache-Control', 'no-cache, no-transform')
            self.send_header('Connection', 'keep-alive')
            self.send_header('X-Accel-Buffering', 'no')
            cors = self._get_cors_origin()
            if cors:
                self.send_header('Access-Control-Allow-Origin', cors)
                self.send_header('Vary', 'Origin')
                self.send_header('Access-Control-Allow-Credentials', 'true')
            self.end_headers()

            try:
                self.connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except Exception:
                pass

            def _sse_send(seq_id, obj):
                p_str = json.dumps(obj, ensure_ascii=False)
                self.wfile.write(("id: %s\ndata: %s\n\n" % (seq_id, p_str)).encode("utf-8"))
                self.wfile.flush()

            try:
                # 空闲保活：防反代掐连接（CCB 同款 `: keepalive`）
                self.wfile.write(b": keepalive\n\n")
                self.wfile.flush()
                missed = sess.event_bus.get_events_since(since_seq)
                for ev in missed:
                    _sse_send(ev["seq_num"], {
                        "event": ev["type"],
                        "seq_num": ev["seq_num"],
                        "payload": ev.get("payload") or {},
                        "data": "",
                        "offset": -1,
                        "generation": getattr(sess, "_buf_generation", 0),
                        "running": sess.is_running,
                        "reset": False,
                        "approval": ev["payload"] if ev["type"] == "approval" else None,
                        "permission_mode": sess.permission_mode,
                        "conn_state": sess.conn_state,
                    })
            except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError, OSError, Exception):
                return

            SNAPSHOT_BYTES = 48000
            initial_res = sess.get_incremental(offset, max_bytes=SNAPSHOT_BYTES, generation=gen_param)
            last_offset = initial_res.get("offset", 0)
            last_seq = initial_res.get("seq_num") or sess.event_bus.last_seq()
            try:
                _sse_send(last_seq, initial_res)
            except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError, OSError, Exception):
                return

            last_ping_t = time.time()
            last_approval_check_t = 0
            last_replay_seq = last_seq
            sse_closed = False

            while not sse_closed:
                now_t = time.time()
                with sess.lock:
                    total_len = len(sess.buffer)
                has_data = (total_len > last_offset)
                bus_seq = sess.event_bus.last_seq()
                has_events = bus_seq > last_replay_seq

                if has_data:
                    if (total_len - last_offset) < 64:
                        sess.output_event.wait(timeout=0.004)
                        sess.output_event.clear()
                    should_check_ap = (now_t - last_approval_check_t >= 0.35)
                    inc = sess.get_incremental(last_offset, check_approval=should_check_ap)
                    if should_check_ap:
                        last_approval_check_t = now_t
                    last_offset = inc.get("offset", total_len)
                    last_seq = inc.get("seq_num") or last_seq
                    last_replay_seq = max(last_replay_seq, last_seq)
                    try:
                        _sse_send(last_seq, inc)
                    except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError, OSError, Exception):
                        break
                elif has_events:
                    missed = sess.event_bus.get_events_since(last_replay_seq)
                    sent_ok = True
                    for ev in missed:
                        try:
                            _sse_send(ev["seq_num"], {
                                "event": ev["type"],
                                "seq_num": ev["seq_num"],
                                "payload": ev.get("payload") or {},
                                "data": "",
                                "offset": last_offset,
                                "running": sess.is_running,
                                "reset": False,
                                "approval": ev["payload"] if ev["type"] == "approval" else None,
                                "permission_mode": sess.permission_mode,
                                "conn_state": sess.conn_state,
                            })
                            last_replay_seq = ev["seq_num"]
                        except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError, OSError, Exception):
                            sent_ok = False
                            break
                    if not sent_ok:
                        break
                    sess.output_event.wait(timeout=0.05)
                    sess.output_event.clear()
                elif now_t - last_ping_t >= 3.0:
                    last_ping_t = now_t
                    try:
                        self.wfile.write(b": keepalive\n\n")
                        self.wfile.flush()
                    except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError, OSError, Exception):
                        break
                    sess.output_event.wait(timeout=0.05)
                    sess.output_event.clear()
                else:
                    sess.output_event.wait(timeout=0.05)
                    sess.output_event.clear()
            return
        elif p == "/api/stream":
            if not self._auth():
                self._forbid(); return
            sid = qs.get('session_id', [''])[0]
            sess = claude_mgr.get_session(sid)
            if not sess:
                self._send_json(200, {"data": "", "offset": 0, "running": False, "reset": True, "approval": {"type": "none"}})
                return
            try:
                offset = int(qs.get('offset', [-1])[0])
            except:
                offset = -1
            gen_param = qs.get('gen', [None])[0]

            # 立即返回增量数据与状态；首屏同样截取尾部快照避免长会话卡死
            res = sess.get_incremental(offset, max_bytes=48000, generation=gen_param)
            self._send_json(200, res)
        elif p == "/api/host":
            if not self._auth():
                self._forbid(); return
            self._send_json(200, {"host_system": get_host_system_stats()})
        elif p == "/api/status":
            if not self._auth():
                self._forbid(); return
            sid = qs.get('session_id', [''])[0]
            sess = claude_mgr.get_session(sid)
            status_data = sess.to_dict() if sess else {}
            self._send_json(200, {"status": status_data})
        elif p == "/api/fs/list":
            if not self._auth():
                self._forbid(); return
            target_path = qs.get('path', [''])[0]
            if not target_path or not os.path.exists(target_path):
                target_path = "C:\\"

            try:
                # 规范化真实路径，彻底消除软链接与跨盘异常
                norm = os.path.realpath(os.path.abspath(target_path))
                parent = os.path.dirname(norm)
                if parent == norm:
                    parent = None
                folders = []
                with os.scandir(norm) as it:
                    for entry in it:
                        try:
                            if entry.is_dir() and not entry.name.startswith('$') and not entry.name.startswith('.'):
                                folders.append({"name": entry.name, "path": os.path.realpath(entry.path)})
                        except Exception:
                            pass
                folders.sort(key=lambda x: x['name'].lower())
                resp_data = {
                    "current_path": norm,
                    "parent_path": parent,
                    "drives": get_windows_drives(),
                    "items": folders
                }
            except Exception as e:
                resp_data = {"error": str(e), "current_path": target_path, "drives": get_windows_drives(), "items": []}

            self._send_json(200, resp_data)
        elif p == "/api/claude/history":
            if not self._auth():
                self._forbid(); return
            target_dir = qs.get('dir', [''])[0]
            sid = qs.get('session_id', [''])[0]
            limit = int(qs.get('limit', [10])[0]) if qs.get('limit') else 10
            offset = int(qs.get('offset', [0])[0]) if qs.get('offset') else 0
            if not target_dir and sid:
                sess_obj = claude_mgr.get_session(sid)
                if sess_obj:
                    target_dir = sess_obj.project_dir
            # 绝不回退到「当前活跃会话 / cwd」——那会把全局历史混进别的工作区
            if not target_dir:
                self._send_json(200, {"success": True, "project_dir": "", "history": [], "sessions": [], "total": 0, "has_more": False})
            else:
                paged_res = get_claude_project_history(target_dir, limit=limit, offset=offset)
                history_list = paged_res.get("items", [])
                self._send_json(200, {
                    "success": True,
                    "project_dir": target_dir,
                    "history": history_list,
                    "sessions": history_list,
                    "total": paged_res.get("total", len(history_list)),
                    "limit": limit,
                    "offset": offset,
                    "has_more": paged_res.get("has_more", False)
                })
        elif p == "/api/fs/workspace_tree":
            if not self._auth():
                self._forbid(); return
            sid = qs.get('session_id', [''])[0]
            sess = claude_mgr.get_session(sid)
            root_dir = sess.project_dir if sess else os.getcwd()
            root_dir = os.path.realpath(os.path.abspath(root_dir))

            req_path = qs.get('path', [''])[0]
            target_path = os.path.realpath(os.path.abspath(req_path)) if req_path and os.path.exists(req_path) else root_dir

            # 目录穿越与真实路径防护：确保访问目标严格在工作区内部
            try:
                common = os.path.realpath(os.path.commonpath([target_path, root_dir]))
                if os.path.normcase(common) != os.path.normcase(root_dir):
                    target_path = root_dir
            except Exception:
                target_path = root_dir

            try:
                parent = os.path.dirname(target_path)
                if parent == target_path:
                    parent = None
                else:
                    try:
                        p_common = os.path.realpath(os.path.commonpath([parent, root_dir]))
                        if os.path.normcase(p_common) != os.path.normcase(root_dir):
                            parent = None
                    except Exception:
                        parent = None

                items = []
                with os.scandir(target_path) as it:
                    for entry in it:
                        try:
                            if entry.name.startswith('$') or entry.name in ['.git', 'node_modules', '__pycache__']:
                                continue
                            is_d = entry.is_dir()
                            st = entry.stat()
                            ext = os.path.splitext(entry.name)[1] if not is_d else ""
                            items.append({
                                "name": entry.name,
                                "path": os.path.realpath(entry.path),
                                "is_dir": is_d,
                                "size": st.st_size if not is_d else 0,
                                "ext": ext,
                                "mtime": int(st.st_mtime)
                            })
                        except Exception:
                            pass

                # 文件夹排前面，文件排后面，按字母排序
                items.sort(key=lambda x: (not x['is_dir'], x['name'].lower()))

                resp_data = {
                    "current_path": target_path,
                    "parent_path": parent,
                    "items": items
                }
            except Exception as e:
                resp_data = {"error": str(e), "current_path": target_path, "items": []}

            self._send_json(200, resp_data)
        elif p == "/api/fs/read_file":
            if not self._auth():
                self._forbid(); return
            file_path = qs.get('path', [''])[0]
            if not file_path or not os.path.exists(file_path) or not os.path.isfile(file_path):
                self._send_json(200, {"success": False, "error": "文件不存在"})
                return

            sid = qs.get('session_id', [''])[0]
            sess = claude_mgr.get_session(sid)
            root_dir = os.path.realpath(os.path.abspath(sess.project_dir)) if sess else os.path.realpath(os.path.abspath(os.getcwd()))
            abs_file = os.path.realpath(os.path.abspath(file_path))

            # 目录穿越与真实软链接防护：禁止读取工作区外系统或私钥文件
            try:
                common = os.path.realpath(os.path.commonpath([abs_file, root_dir]))
                if os.path.normcase(common) != os.path.normcase(root_dir):
                    self._send_json(200, {"success": False, "error": "越权访问：仅允许查看当前工作区内的文件"})
                    return
            except Exception:
                self._send_json(200, {"success": False, "error": "无效的文件路径或跨盘符越权"})
                return

            try:
                # 限制最大读取 1MB 文本
                if os.path.getsize(abs_file) > 1024 * 1024:
                    with open(abs_file, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read(1024 * 1024) + "\n\n... (文件过大，仅截取前1MB内容) ..."
                else:
                    with open(abs_file, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()

                self._send_json(200, {
                    "success": True,
                    "content": content,
                    "name": os.path.basename(abs_file),
                    "path": abs_file
                })
            except Exception as e:
                self._send_json(200, {"success": False, "error": str(e)})
        else:
            self._not_found()

    def do_POST(self):
        parsed = urlparse(self.path)
        p = parsed.path
        qs = parse_qs(parsed.query)

        # 针对 2FA 验证接口特殊放行（只校验基础 AUTH_TOKEN，无需预先拥有 device_token）
        if p == "/api/auth/verify_2fa":
            if not self._auth(require_device=False):
                self._forbid(); return
            if not self._origin_allowed() and not self._token_matches(self._extract_master_token()):
                self._forbid("403 Forbidden - Cross-site request blocked"); return
            client_ip = self._get_client_ip()

            # 检查 2FA 专属防爆破频率限制：连续输错 5 次直接冻结 15 分钟
            allowed, remaining = security_mgr.check_rate_limit(client_ip)
            if not allowed:
                self._send_json(429, {"success": False, "error": f"连续验证失败次数过多，为保障安全已临时锁定，请 {remaining} 秒后再试"})
                return

            payload = self._read_json_body(MAX_JSON_BODY)
            if payload is None:
                return
            code = payload.get("code", "").strip()
            if not security_mgr.enabled:
                dev_tok = security_mgr.create_device_session(client_ip, self.headers.get("User-Agent", ""))
                security_mgr.record_success_attempt(client_ip)
                self._send_json(200, {"success": True, "device_token": dev_tok})
                return
            if security_mgr.verify_code(code):
                security_mgr.record_success_attempt(client_ip)
                dev_tok = security_mgr.create_device_session(client_ip, self.headers.get("User-Agent", ""))
                log_to_gui(f"设备 2FA 验证成功: {client_ip} ({dev_tok[:8]})")
                self._send_json(200, {"success": True, "device_token": dev_tok})
            else:
                fail_count, lock_time = security_mgr.record_failed_attempt(client_ip)
                log_to_gui(f"设备 2FA 验证失败: {client_ip} 输入代码错误 (累计第 {fail_count} 次)")
                if fail_count >= 5:
                    self._send_json(429, {"success": False, "error": "连续 5 次输错 2FA 动态码，安全锁定 15 分钟"})
                else:
                    remaining_chances = 5 - fail_count
                    self._send_json(200, {"success": False, "error": f"动态验证码错误或已过期 (还剩 {remaining_chances} 次尝试机会)"})
            return

        if not self._auth():
            self._forbid(); return
        if not self._origin_allowed() and not self._token_matches(self._extract_master_token()):
            self._forbid("403 Forbidden - Cross-site request blocked"); return

        max_body = MAX_POST_BODY if p == "/api/upload_image" else MAX_JSON_BODY
        payload = self._read_json_body(max_body)
        if payload is None:
            return

        sid = qs.get('session_id', [''])[0] or payload.get("session_id") or payload.get("id")
        sess = claude_mgr.get_session(sid)

        if p == "/api/sessions/create":
            name = payload.get("name")
            project_dir = payload.get("dir")
            resume_mode = payload.get("resume_mode") or "new"
            claude_session_id = payload.get("claude_session_id")
            force_new = bool(payload.get("force_new"))
            theme = payload.get("theme")
            new_sess, ok, msg = claude_mgr.create_session(
                name=name,
                project_dir=project_dir,
                resume_mode=resume_mode,
                claude_session_id=claude_session_id,
                force_new=force_new,
                theme=theme
            )
            self._send_json(200, {"success": ok, "error": msg if not ok else None, "session": new_sess.to_dict() if new_sess else None})
        elif p == "/api/sessions/resume_history":
            target_id = payload.get("session_id") or payload.get("id") or sid
            mode = payload.get("resume_mode") or payload.get("mode") or "resume"
            target_claude_sid = payload.get("claude_session_id")
            theme = payload.get("theme")
            s = claude_mgr.get_session(target_id)
            if not s:
                self._send_json(200, {"success": False, "error": "会话不存在"})
            else:
                # 切历史 / 新开对话：同目录再拉一条并发会话，绝不停掉正在跑的那条
                if target_claude_sid:
                    existing_cid = claude_mgr.find_session_by_claude_id(target_claude_sid)
                    if existing_cid:
                        claude_mgr.switch_active(existing_cid.id)
                        self._send_json(200, {"success": True, "session": existing_cid.to_dict()})
                    else:
                        new_sess, ok, msg = claude_mgr.create_session(
                            name=s.name,
                            project_dir=s.project_dir,
                            resume_mode="resume",
                            claude_session_id=target_claude_sid,
                            force_new=True,
                            theme=theme
                        )
                        self._send_json(200, {"success": ok, "error": None if ok else msg, "session": new_sess.to_dict() if new_sess else None})
                else:
                    new_sess, ok, msg = claude_mgr.create_session(
                        name=s.name,
                        project_dir=s.project_dir,
                        resume_mode=mode or "new",
                        force_new=True,
                        theme=theme
                    )
                    self._send_json(200, {"success": ok, "error": None if ok else msg, "session": new_sess.to_dict() if new_sess else None})
        elif p == "/api/sessions/switch":
            target_id = payload.get("id")
            ok, target_sess = claude_mgr.switch_active(target_id)
            self._send_json(200, {"success": ok, "active_id": target_id})
        elif p == "/api/sessions/pin":
            target_id = payload.get("id")
            ok, is_pinned = claude_mgr.toggle_pin_session(target_id)
            self._send_json(200, {"success": ok, "pinned": is_pinned})
        elif p == "/api/sessions/rename":
            target_id = payload.get("id")
            new_name = payload.get("name", "")
            ok = claude_mgr.rename_session(target_id, new_name)
            self._send_json(200, {"success": ok})
        elif p == "/api/sessions/delete":
            target_id = payload.get("id")
            ok = claude_mgr.delete_session(target_id)
            self._send_json(200, {"success": ok})
        elif p == "/api/sessions/stop":
            target_id = payload.get("id") or sid
            ok, msg = claude_mgr.stop_session(target_id)
            self._send_json(200, {"success": ok, "message": msg})
        elif p == "/api/sessions/stop_project":
            pdir = payload.get("project_dir") or payload.get("dir")
            ok, msg = claude_mgr.stop_project_sessions(pdir)
            self._send_json(200, {"success": ok, "message": msg})
        elif p == "/api/sessions/restart":
            target_id = payload.get("id")
            s = claude_mgr.get_session(target_id)
            ok = False
            if s:
                ok, _ = s.start() if not s.is_running else s.restart_with_dir(s.project_dir)
            self._send_json(200, {"success": ok})
        elif p == "/api/send":
            prompt = payload.get("prompt", "")
            ok, msg = sess.send_input(prompt) if sess else (False, "会话不存在")
            self._send_json(200, {"success": ok, "error": msg if not ok else None})
        elif p == "/api/raw_input":
            raw_data = payload.get("data", "")
            ok, msg = sess.send_raw_data(raw_data) if sess else (False, "会话不存在")
            self._send_json(200, {"success": ok})
        elif p == "/api/upload_image":
            raw_filename = payload.get("filename", "upload.png")
            # 安全清洗：彻底剥离任何前置相对/绝对路径 (如 ../ 或 C:\)，只保留真实文件名
            clean_filename = os.path.basename(raw_filename).strip() or "upload.png"
            # 移除非法字符，避免跨平台路径注入
            clean_filename = re.sub(r'[\\/:*?"<>|]', '_', clean_filename)
            ext = os.path.splitext(clean_filename)[1].lower()
            if ext not in ALLOWED_IMAGE_EXTS:
                self._send_json(200, {"success": False, "error": "仅允许上传常见图片格式"})
                return
            b64data = payload.get("data", "")
            if not isinstance(b64data, str) or not b64data:
                self._send_json(200, {"success": False, "error": "图片数据为空"})
                return
            # base64 膨胀约 4/3，先按字符长度拦掉明显过大的 payload，避免解码撑爆内存
            if len(b64data) > (MAX_UPLOAD_BYTES * 4 // 3) + 64:
                self._send_json(413, {"success": False, "error": "图片过大，最大 8MB"})
                return
            target_dir = sess.project_dir if sess else os.getcwd()
            try:
                raw_bytes = base64.b64decode(b64data, validate=False)
                if len(raw_bytes) > MAX_UPLOAD_BYTES:
                    self._send_json(413, {"success": False, "error": "图片过大，最大 8MB"})
                    return
                upload_dir = os.path.join(target_dir, ".claude_remote_uploads")
                os.makedirs(upload_dir, exist_ok=True)
                safe_name = f"{int(time.time())}_{secrets.token_hex(4)}_{clean_filename}"
                saved_path = os.path.join(upload_dir, safe_name)
                with open(saved_path, "wb") as f:
                    f.write(raw_bytes)
                log_to_gui(f"手机图片上传成功: {saved_path}")
                self._send_json(200, {"success": True, "saved_path": saved_path})
            except Exception as e:
                self._send_json(200, {"success": False, "error": str(e)})
        elif p == "/api/key":
            key_type = payload.get("key", "")
            ok, msg = sess.send_raw_key(key_type) if sess else (False, "会话不存在")
            self._send_json(200, {"success": ok})
        elif p == "/api/choose":
            mode = payload.get("mode", "single")
            index = int(payload.get("index", 0))
            indices = payload.get("indices", [])
            text = payload.get("text") or payload.get("custom") or ""
            ok, msg = sess.apply_choice(mode, index=index, indices=indices, text=text) if sess else (False, "会话不存在")
            self._send_json(200, {"success": ok, "error": msg if not ok else None})
        elif p == "/api/resize":
            cols = int(payload.get("cols", 52))
            rows = int(payload.get("rows", 28))
            if sess:
                sess.set_size(cols, rows)
            self._send_json(200, {"success": True})
        elif p == "/api/restart_with_dir":
            new_dir = payload.get("dir", "")
            ok, msg = sess.restart_with_dir(new_dir) if sess else (False, "会话不存在")
            if ok:
                claude_mgr.save_state()
            self._send_json(200, {"success": ok, "error": msg if not ok else None})
        else:
            self._not_found()

    def log_message(self, format, *args):
        pass

def get_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]

def run_local_http(port, token, cookie_path="/"):
    global httpd_server, AUTH_TOKEN, PUBLIC_COOKIE_PATH
    AUTH_TOKEN = token
    PUBLIC_COOKIE_PATH = cookie_path or "/"
    access_sessions.reset()
    try:
        class ReusableThreadingServer(ThreadingHTTPServer):
            allow_reuse_address = True
            daemon_threads = True  # 关键：工作线程全部标记为 daemon，避免客户端断开或关闭软件时主进程残留假死
        httpd_server = ReusableThreadingServer(('127.0.0.1', port), ClaudeHttpHandler)
        log_to_gui(f"本地多线程 Web 控制服务已就绪 (127.0.0.1:{port})")
        httpd_server.serve_forever()
    except Exception as e:
        log_to_gui(f"本地 Web 服务结束: {e}")

def get_frpc_executable():
    cands = []
    if getattr(sys, "frozen", False):
        exe_dir = os.path.dirname(sys.executable)
        cands.append(os.path.join(exe_dir, "frpc.exe"))
        cands.append(os.path.join(exe_dir, "_internal", "frpc.exe"))
        meipass = getattr(sys, "_MEIPASS", "")
        if meipass:
            cands.append(os.path.join(meipass, "frpc.exe"))
    else:
        base_dir = os.path.dirname(os.path.abspath(__file__))
        cands.append(os.path.join(base_dir, "frpc.exe"))
        cands.append(os.path.join(os.path.dirname(base_dir), "frpc.exe"))
    for c in cands:
        if c and os.path.exists(c):
            return c
    return "frpc.exe"

# ==================== GUI 客户端主界面 (极简黑白灰 WebUI 风格) ====================
GUI_BG_MAIN = "#121212"
GUI_BG_HEADER = "#181818"
GUI_BG_CARD = "#1c1c1c"
GUI_BG_ENTRY = "#242424"
GUI_BG_BTN = "#2b2b2b"
GUI_BG_BTN_HOVER = "#383838"
GUI_BORDER = "#333333"
GUI_FG_MAIN = "#f4f4f4"
GUI_FG_MUTED = "#b8b8b8"
GUI_FG_DIM = "#737373"
GUI_ACCENT_GREEN = "#22c55e"
GUI_ACCENT_RED = "#ef4444"


class ClaudeRemoteGUI:
    def __init__(self, root):
        global gui_app_instance
        self.root = root
        gui_app_instance = self
        self.root.title("Claude Code Remote")

        # 优化窗口尺寸（1027x1092，更加开阔大气，并自适应屏幕居中）
        win_w, win_h = 1027, 1092
        scr_w = self.root.winfo_screenwidth()
        scr_h = self.root.winfo_screenheight()
        pos_x = max(0, (scr_w - win_w) // 2)
        pos_y = max(0, (scr_h - win_h) // 2 - 20)
        self.root.geometry(f"{win_w}x{win_h}+{pos_x}+{pos_y}")
        self.root.minsize(860, 800)
        self.root.resizable(True, True)
        self.root.configure(bg=GUI_BG_MAIN)

        self.is_running = False
        self.token = ""
        self.remote_port = 0
        self.qr_image_tk = None
        self.totp_qr_image_tk = None

        # 载入本地持久化状态
        self.saved_state = claude_mgr.load_state() or {}
        default_dir = self.saved_state.get("last_work_dir")
        if not default_dir or not os.path.exists(default_dir):
            default_dir = os.getcwd()

        self.dir_var = tk.StringVar(value=default_dir)
        self.auto_continue_var = tk.BooleanVar(value=claude_mgr.auto_continue)
        self.stream_mode_var = tk.StringVar(value=self.saved_state.get("stream_mode", "sse"))

        self.setup_ui()
        self.refresh_device_list()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        log_to_gui("服务已初始化就绪，历史工作区已安全载入")

    def choose_dir(self):
        from tkinter import filedialog
        chosen = filedialog.askdirectory(initialdir=self.dir_var.get() or os.getcwd(), title="选择工作区目录")
        if chosen:
            self.dir_var.set(os.path.abspath(chosen))
            claude_mgr.save_state(self.dir_var.get())

    def on_auto_continue_change(self):
        claude_mgr.auto_continue = self.auto_continue_var.get()
        claude_mgr.save_state()

    def on_stream_mode_change(self):
        mode = self.stream_mode_var.get()
        self.saved_state["stream_mode"] = mode
        claude_mgr.save_state()
        log_to_gui(f"已切换传输架构为: {'SSE 流式直推通道' if mode == 'sse' else '经典智能长轮询通道'}")

    def setup_ui(self):
        header_frame = tk.Frame(self.root, bg=GUI_BG_HEADER, height=54)
        header_frame.pack(fill="x")

        title_lbl = tk.Label(
            header_frame,
            text="Claude Code Remote",
            font=("Microsoft YaHei UI", 13, "bold"),
            fg=GUI_FG_MAIN,
            bg=GUI_BG_HEADER
        )
        title_lbl.pack(pady=(8, 1))

        sub_lbl = tk.Label(
            header_frame,
            text="在手机端远程管理与交互本地 Claude 会话 · 支持会话记忆与对话续接",
            font=("Microsoft YaHei UI", 8),
            fg=GUI_FG_MUTED,
            bg=GUI_BG_HEADER
        )
        sub_lbl.pack(pady=(0, 8))

        content_frame = tk.Frame(self.root, bg=GUI_BG_MAIN, padx=16, pady=10)
        content_frame.pack(fill="both", expand=True)

        status_box = tk.Frame(content_frame, bg=GUI_BG_CARD, bd=1, relief="solid")
        status_box.pack(fill="x", pady=(0, 6))

        self.status_indicator = tk.Label(
            status_box,
            text="○ 服务未启动",
            font=("Microsoft YaHei UI", 9, "bold"),
            fg=GUI_FG_MUTED,
            bg=GUI_BG_CARD,
            pady=5,
            wraplength=680
        )
        self.status_indicator.pack()

        dir_frame = tk.Frame(content_frame, bg=GUI_BG_MAIN)
        dir_frame.pack(fill="x", pady=(0, 4))

        tk.Label(dir_frame, text="工作目录:", font=("Microsoft YaHei UI", 9, "bold"), fg=GUI_FG_MAIN, bg=GUI_BG_MAIN).pack(side="left")
        self.dir_entry = tk.Entry(dir_frame, textvariable=self.dir_var, font=("Consolas", 9), bg=GUI_BG_ENTRY, fg=GUI_FG_MAIN, insertbackground=GUI_FG_MAIN, relief="flat")
        self.dir_entry.pack(side="left", fill="x", expand=True, padx=(8, 6), ipady=2)

        self.btn_browse = tk.Button(
            dir_frame,
            text="浏览...",
            font=("Microsoft YaHei UI", 8),
            bg=GUI_BG_BTN,
            fg=GUI_FG_MAIN,
            activebackground=GUI_BG_BTN_HOVER,
            activeforeground="#ffffff",
            relief="flat",
            cursor="hand2",
            command=self.choose_dir,
            padx=8,
            pady=1
        )
        self.btn_browse.pack(side="right")

        # 选项栏：自动续接对话与传输架构模式切换
        opt_frame = tk.Frame(content_frame, bg=GUI_BG_MAIN)
        opt_frame.pack(fill="x", pady=(0, 6))

        self.chk_continue = tk.Checkbutton(
            opt_frame,
            text="智能续接上次对话 (--continue / -c)，启动时自动承接历史上下文",
            variable=self.auto_continue_var,
            font=("Microsoft YaHei UI", 8),
            fg=GUI_FG_MAIN,
            bg=GUI_BG_MAIN,
            selectcolor=GUI_BG_CARD,
            activebackground=GUI_BG_MAIN,
            activeforeground=GUI_FG_MAIN,
            command=self.on_auto_continue_change
        )
        self.chk_continue.pack(anchor="w")

        # 传输架构自由切换开关 (SSE 流式直推 vs 经典长轮询)
        mode_box = tk.Frame(opt_frame, bg=GUI_BG_MAIN)
        mode_box.pack(fill="x", pady=(2, 0))

        tk.Label(mode_box, text="传输通道架构:", font=("Microsoft YaHei UI", 8, "bold"), fg=GUI_FG_MUTED, bg=GUI_BG_MAIN).pack(side="left")

        self.rb_sse = tk.Radiobutton(
            mode_box,
            text="⚡ SSE 流式直推 (Server-Sent Events 毫秒级推流)",
            variable=self.stream_mode_var,
            value="sse",
            font=("Microsoft YaHei UI", 8),
            fg=GUI_ACCENT_GREEN,
            bg=GUI_BG_MAIN,
            selectcolor=GUI_BG_CARD,
            activebackground=GUI_BG_MAIN,
            activeforeground=GUI_ACCENT_GREEN,
            command=self.on_stream_mode_change
        )
        self.rb_sse.pack(side="left", padx=(8, 12))

        self.rb_poll = tk.Radiobutton(
            mode_box,
            text="🔄 经典长轮询 (HTTP Fast Long-Polling 80ms)",
            variable=self.stream_mode_var,
            value="polling",
            font=("Microsoft YaHei UI", 8),
            fg=GUI_FG_MUTED,
            bg=GUI_BG_MAIN,
            selectcolor=GUI_BG_CARD,
            activebackground=GUI_BG_MAIN,
            activeforeground=GUI_FG_MAIN,
            command=self.on_stream_mode_change
        )
        self.rb_poll.pack(side="left")

        mid_frame = tk.Frame(content_frame, bg=GUI_BG_MAIN)
        mid_frame.pack(fill="x", pady=(0, 8))

        # 二维码展示卡片容器（加大尺寸并给予充足的留白 padding 与纯白背景，确保手机极易对焦扫描）
        self.qr_frame = tk.Frame(mid_frame, bg=GUI_BG_CARD, width=155, height=155, bd=1, relief="solid")
        self.qr_frame.pack_propagate(False)
        self.qr_frame.pack(side="left", padx=(0, 12))

        self.qr_label = tk.Label(self.qr_frame, text="启动服务后\n显示二维码", bg=GUI_BG_CARD, fg=GUI_FG_DIM, font=("Microsoft YaHei UI", 9))
        self.qr_label.pack(expand=True)

        right_frame = tk.Frame(mid_frame, bg=GUI_BG_MAIN)
        right_frame.pack(side="left", fill="both", expand=True)

        tk.Label(right_frame, text="远程访问地址:", font=("Microsoft YaHei UI", 9, "bold"), fg=GUI_FG_MAIN, bg=GUI_BG_MAIN).pack(anchor="w")

        self.link_var = tk.StringVar(value="等待启动服务...")
        link_entry = tk.Entry(
            right_frame,
            textvariable=self.link_var,
            font=("Consolas", 9),
            bg=GUI_BG_ENTRY,
            fg=GUI_FG_MAIN,
            readonlybackground=GUI_BG_ENTRY,
            state="readonly",
            relief="flat"
        )
        link_entry.pack(fill="x", pady=(4, 5), ipady=2)

        self.copy_btn = tk.Button(
            right_frame,
            text="复制访问链接",
            font=("Microsoft YaHei UI", 8),
            bg=GUI_BG_BTN,
            fg=GUI_FG_MAIN,
            activebackground=GUI_BG_BTN_HOVER,
            activeforeground="#ffffff",
            relief="flat",
            cursor="hand2",
            state="disabled",
            command=self.copy_link,
            pady=3
        )
        self.copy_btn.pack(fill="x", pady=(0, 4))

        self.toggle_btn = tk.Button(
            content_frame,
            text="启动服务",
            font=("Microsoft YaHei UI", 11, "bold"),
            bg="#f4f4f4",
            fg="#121212",
            activebackground="#e0e0e0",
            activeforeground="#000000",
            relief="flat",
            cursor="hand2",
            pady=6,
            command=self.toggle_service
        )
        self.toggle_btn.pack(fill="x", pady=(0, 8))

        # ==================== 2FA 与已授权设备管理卡片 ====================
        sec_box = tk.LabelFrame(
            content_frame,
            text=" [2FA] 双重身份验证与在线设备管理 ",
            font=("Microsoft YaHei UI", 8, "bold"),
            fg=GUI_FG_MAIN,
            bg=GUI_BG_CARD,
            bd=1,
            relief="solid",
            padx=8,
            pady=6
        )
        sec_box.pack(fill="x", pady=(0, 8))

        sec_top = tk.Frame(sec_box, bg=GUI_BG_CARD)
        sec_top.pack(fill="x", pady=(0, 4))

        self.two_fa_status_lbl = tk.Label(
            sec_top,
            text="2FA 状态: " + ("已启用 (RFC 6238 TOTP)" if security_mgr.enabled else "未启用 (仅 Token 验证)"),
            font=("Microsoft YaHei UI", 8),
            fg=GUI_ACCENT_GREEN if security_mgr.enabled else GUI_FG_MUTED,
            bg=GUI_BG_CARD
        )
        self.two_fa_status_lbl.pack(side="left")

        self.two_fa_config_btn = tk.Button(
            sec_top,
            text="设置 / 绑定 Authenticator" if not security_mgr.enabled else "查看绑定二维码 / 重置",
            font=("Microsoft YaHei UI", 8),
            bg=GUI_BG_BTN,
            fg=GUI_FG_MAIN,
            activebackground=GUI_BG_BTN_HOVER,
            activeforeground="#ffffff",
            relief="flat",
            cursor="hand2",
            command=self.open_2fa_config_dialog,
            padx=6,
            pady=1
        )
        self.two_fa_config_btn.pack(side="right", padx=(6, 0))

        self.two_fa_toggle_btn = tk.Button(
            sec_top,
            text="禁用 2FA" if security_mgr.enabled else "启用 2FA",
            font=("Microsoft YaHei UI", 8, "bold"),
            bg=GUI_ACCENT_RED if security_mgr.enabled else "#27272a",
            fg="#ffffff" if security_mgr.enabled else GUI_FG_MAIN,
            activebackground="#dc2626" if security_mgr.enabled else "#3f3f46",
            activeforeground="#ffffff",
            relief="flat",
            cursor="hand2",
            command=self.toggle_2fa_state,
            padx=6,
            pady=1
        )
        self.two_fa_toggle_btn.pack(side="right")

        # 设备列表树
        tree_frame = tk.Frame(sec_box, bg=GUI_BG_CARD)
        tree_frame.pack(fill="x", pady=(2, 4))

        # 定制 ttk.Treeview 样式以融合黑白灰极简主题
        style = ttk.Style()
        style.theme_use("clam")
        style.configure(
            "Device.Treeview",
            background=GUI_BG_ENTRY,
            foreground=GUI_FG_MAIN,
            fieldbackground=GUI_BG_ENTRY,
            font=("Microsoft YaHei UI", 8),
            rowheight=20
        )
        style.configure(
            "Device.Treeview.Heading",
            background=GUI_BG_HEADER,
            foreground=GUI_FG_MUTED,
            font=("Microsoft YaHei UI", 8, "bold"),
            relief="flat"
        )
        style.map("Device.Treeview", background=[("selected", "#383838")], foreground=[("selected", "#ffffff")])

        cols = ("dev_id", "name", "ip", "last_active")
        self.dev_tree = ttk.Treeview(
            tree_frame,
            columns=cols,
            show="headings",
            height=8,
            style="Device.Treeview"
        )
        self.dev_tree.heading("dev_id", text="会话标识")
        self.dev_tree.heading("name", text="设备类型 / 平台")
        self.dev_tree.heading("ip", text="IP 地址")
        self.dev_tree.heading("last_active", text="最近活跃时间")

        self.dev_tree.column("dev_id", width=80, anchor="center")
        self.dev_tree.column("name", width=180, anchor="w")
        self.dev_tree.column("ip", width=120, anchor="center")
        self.dev_tree.column("last_active", width=110, anchor="center")
        self.dev_tree.pack(side="left", fill="x", expand=True)

        dev_scroll = ttk.Scrollbar(tree_frame, orient="vertical", command=self.dev_tree.yview)
        self.dev_tree.configure(yscrollcommand=dev_scroll.set)
        dev_scroll.pack(side="right", fill="y")

        # 操作行：断开选中设备与一键踢下线全部
        dev_action_frame = tk.Frame(sec_box, bg=GUI_BG_CARD)
        dev_action_frame.pack(fill="x")

        self.dev_count_lbl = tk.Label(
            dev_action_frame,
            text="当前已授权在线设备: 0 台",
            font=("Microsoft YaHei UI", 8),
            fg=GUI_FG_DIM,
            bg=GUI_BG_CARD
        )
        self.dev_count_lbl.pack(side="left")

        self.kick_all_btn = tk.Button(
            dev_action_frame,
            text="全部踢下线",
            font=("Microsoft YaHei UI", 8),
            bg="#7f1d1d",
            fg="#fecaca",
            activebackground="#991b1b",
            activeforeground="#ffffff",
            relief="flat",
            cursor="hand2",
            command=self.kick_all_devices,
            padx=8,
            pady=1
        )
        self.kick_all_btn.pack(side="right", padx=(6, 0))

        self.kick_selected_btn = tk.Button(
            dev_action_frame,
            text="踢出选中设备",
            font=("Microsoft YaHei UI", 8),
            bg=GUI_BG_BTN,
            fg=GUI_FG_MAIN,
            activebackground=GUI_BG_BTN_HOVER,
            activeforeground="#ffffff",
            relief="flat",
            cursor="hand2",
            command=self.kick_selected_device,
            padx=8,
            pady=1
        )
        self.kick_selected_btn.pack(side="right")
        # =================================================================

        log_header = tk.Frame(content_frame, bg=GUI_BG_MAIN)
        log_header.pack(fill="x")
        tk.Label(log_header, text="运行日志:", font=("Microsoft YaHei UI", 8, "bold"), fg=GUI_FG_MUTED, bg=GUI_BG_MAIN).pack(side="left")

        self.log_text = tk.Text(
            content_frame,
            height=5,
            bg="#0d0d0d",
            fg="#e5e5e5",
            insertbackground="#ffffff",
            font=("Consolas", 9),
            relief="solid",
            bd=1
        )
        self.log_text.pack(fill="both", expand=True, pady=(4, 0))

    def append_log(self, text):
        def _insert():
            try:
                self.log_text.insert(tk.END, text + "\n")
                self.log_text.see(tk.END)
            except Exception:
                pass
        self.root.after(0, _insert)

    def toggle_service(self):
        if not self.is_running:
            self.toggle_btn.config(state="disabled", text="正在启动服务...")
            threading.Thread(target=self._async_start, daemon=True).start()
        else:
            self.toggle_btn.config(state="disabled", text="正在停止服务...")
            threading.Thread(target=self._async_stop, daemon=True).start()

    def _async_start(self):
        global frpc_process, httpd_server
        try:
            log_to_gui("正在生成强加密 Token (256-bit) 与映射端口...")
            if not FRP_SERVER_TOKEN:
                raise Exception("未找到 FRP 服务端 Token。请把 server_config.ini 放在程序同目录后再启动。")
            # 升级为 256 位 (32 字节 / 64 个十六进制字符) 高熵安全 Token
            self.token = secrets.token_hex(32)
            self.remote_port = secrets.randbelow(400) + 17600
            local_agent_port = get_free_port()
            log_to_gui(f"本地端口: {local_agent_port} | 远端映射端口: {self.remote_port}")

            # 1. 启动本地多线程并发 HTTP 控制服务
            log_to_gui("启动本地 Web 控制服务...")
            t = threading.Thread(
                target=run_local_http,
                args=(local_agent_port, self.token, f"/p/{self.remote_port}/"),
                daemon=True
            )
            t.start()
            time.sleep(0.2)

            # 2. 启动或恢复 Claude 会话。每个会话使用自己记住的工作区，桌面「工作目录」只用于没有会话时新建默认会话。
            target_dir = self.dir_var.get().strip()
            resume_flag = "continue" if claude_mgr.auto_continue else "new"

            active_sess = claude_mgr.get_active_session()
            if not active_sess:
                sess, ok, msg = claude_mgr.create_session("默认会话", target_dir, cols=120, rows=36, resume_mode=resume_flag)
                if not ok:
                    raise Exception(msg)
            else:
                # 只拉起当前活跃项目；其余工作区保持配置，点进去才启动，切回去不重启
                if not active_sess.is_running:
                    ok, msg = active_sess.start()
                    if not ok:
                        raise Exception(msg)
                log_to_gui(f"已恢复 {len(claude_mgr.sessions)} 个项目工作区，当前: [{active_sess.name}] ({active_sess.project_dir})")

            claude_mgr.save_state()

            # 3. 启动 FRP 客户端
            frpc_exe = get_frpc_executable()
            if not os.path.exists(frpc_exe):
                raise Exception(f"未找到核心穿透程序：{frpc_exe}")

            temp_toml = os.path.join(os.environ.get("TEMP", "."), f"frpc_claude_{self.remote_port}.toml")
            device_fp = get_device_fingerprint()
            toml_content = f"""serverAddr = "{FRP_SERVER_HOST}"
serverPort = {FRP_SERVER_PORT}
auth.method = "token"
auth.token = "{FRP_SERVER_TOKEN}"
user = "{device_fp}"
transport.tls.enable = true

[[proxies]]
name = "{device_fp}.claude_remote_{self.remote_port}"
type = "tcp"
localIP = "127.0.0.1"
localPort = {local_agent_port}
remotePort = {self.remote_port}
"""
            with open(temp_toml, "w", encoding="utf-8") as f:
                f.write(toml_content)

            log_to_gui(f"正在建立 FRP 连接 ({FRP_SERVER_HOST}:{self.remote_port})...")
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = subprocess.SW_HIDE

            frpc_process = subprocess.Popen(
                [frpc_exe, "-c", temp_toml],
                startupinfo=startupinfo,
                creationflags=subprocess.CREATE_NO_WINDOW,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace"
            )

            time.sleep(1.5)
            if frpc_process.poll() is not None:
                err_out = ""
                try:
                    err_out = (frpc_process.stdout.read() or "").strip()
                except Exception:
                    pass
                raise Exception(err_out or "FRP 穿透建立失败，请检查网络或服务器")

            access_url = f"https://{PUBLIC_HTTPS_HOST}/p/{self.remote_port}/?token={self.token}"
            log_to_gui("连接建立成功! 访问地址: " + redact_secret(access_url, self.token))
            self.root.after(0, self._on_start_success, access_url)

        except Exception as e:
            log_to_gui(f"启动失败: {str(e)}")
            self.root.after(0, self._on_start_failed, str(e))

    def _on_start_success(self, access_url):
        self.is_running = True
        self.status_indicator.config(text=f"● 服务运行中 (端口: {self.remote_port})", fg=GUI_ACCENT_GREEN)
        self.link_var.set(access_url)
        self.toggle_btn.config(state="normal", text="停止服务", bg=GUI_ACCENT_RED, fg="#ffffff", activebackground="#dc2626")
        self.copy_btn.config(state="normal")
        self.dir_entry.config(state="disabled")

        if HAS_QRCODE:
            try:
                # 标准 4 单元留白 (quiet zone) 与清晰缩放，避免黑色点阵紧贴容器边界
                qr = qrcode.QRCode(box_size=10, border=4)
                qr.add_data(access_url)
                qr.make(fit=True)
                img = qr.make_image(fill_color="#000000", back_color="#ffffff").convert("RGB")
                # 缩放到 165x165，居中嵌入 175x175 的容器，四周留出纯净白边，扫码极速识别
                img = img.resize((165, 165), Image.Resampling.NEAREST)
                self.qr_image_tk = ImageTk.PhotoImage(img, master=self.root)
                self.qr_label.config(image=self.qr_image_tk, text="", bg="#ffffff")
                log_to_gui("二维码就绪，手机可扫码访问")
            except Exception as e:
                log_to_gui(f"二维码生成异常: {e}")
                self.qr_label.config(text="手机打开链接\n直接访问", bg=GUI_BG_CARD, fg=GUI_FG_DIM)
        else:
            self.qr_label.config(text="手机打开链接\n直接访问", bg=GUI_BG_CARD, fg=GUI_FG_DIM)

    def _on_start_failed(self, err_msg):
        self._cleanup_resources()
        messagebox.showerror("启动失败", err_msg)
        self.toggle_btn.config(state="normal", text="启动服务", bg="#f4f4f4", fg="#121212", activebackground="#e0e0e0")
        self.dir_entry.config(state="normal")

    def copy_link(self):
        url = self.link_var.get()
        if url and not url.startswith("等待"):
            self.root.clipboard_clear()
            self.root.clipboard_append(url)
            messagebox.showinfo("提示", "访问链接已复制到剪贴板。")

    def _cleanup_resources(self, exit_app=False):
        global frpc_process, httpd_server
        if frpc_process:
            try:
                frpc_process.terminate()
                frpc_process.kill()
            except:
                pass
            frpc_process = None

        if httpd_server:
            try:
                httpd_server.server_close()
            except:
                pass
            httpd_server = None

        # 停止所有进程，但保留会话元数据配置，供下次启动复用
        claude_mgr.stop_all(keep_config=True)
        try:
            cur_d = self.dir_var.get().strip() if hasattr(self, 'dir_var') else None
            claude_mgr.save_state(cur_d)
        except Exception:
            pass

    def _async_stop(self):
        log_to_gui("正在断开连接与后台会话...")
        self._cleanup_resources(exit_app=False)
        self.root.after(0, self._on_stop_finished)

    def _on_stop_finished(self):
        self.is_running = False
        self.link_var.set("等待启动服务...")
        self.status_indicator.config(text="○ 服务未启动 (会话已记忆)", fg=GUI_FG_MUTED)
        self.toggle_btn.config(state="normal", text="启动服务", bg="#f4f4f4", fg="#121212", activebackground="#e0e0e0")
        self.copy_btn.config(state="disabled")
        self.dir_entry.config(state="normal")
        self.qr_label.config(image='', text="启动服务后\n显示二维码", bg=GUI_BG_CARD, fg=GUI_FG_DIM)
        log_to_gui("服务已停止，会话与工作区列表已安全持久化")

    def toggle_2fa_state(self):
        """开启或关闭 2FA 身份验证"""
        if not security_mgr.enabled:
            # 开启 2FA，如果尚未生成密钥则先生成
            if not security_mgr.secret:
                security_mgr.generate_secret()
            security_mgr.enabled = True
            security_mgr.save()
            log_to_gui("2FA 双重身份验证已启用")
            # 弹出 Authenticator 配置二维码向导，引导用户绑定
            self.open_2fa_config_dialog()
        else:
            if messagebox.askyesno("确认操作", "确定要禁用 2FA 验证吗？\n禁用后仅凭访问链接 Token 即可控制终端。"):
                security_mgr.enabled = False
                security_mgr.save()
                log_to_gui("2FA 双重身份验证已禁用")
        self._update_2fa_ui()

    def _update_2fa_ui(self):
        is_en = security_mgr.enabled
        self.two_fa_status_lbl.config(
            text="2FA 状态: " + ("已启用 (RFC 6238 TOTP)" if is_en else "未启用 (仅 Token 验证)"),
            fg=GUI_ACCENT_GREEN if is_en else GUI_FG_MUTED
        )
        self.two_fa_toggle_btn.config(
            text="禁用 2FA" if is_en else "启用 2FA",
            bg=GUI_ACCENT_RED if is_en else "#27272a",
            fg="#ffffff" if is_en else GUI_FG_MAIN,
            activebackground="#dc2626" if is_en else "#3f3f46"
        )
        self.two_fa_config_btn.config(
            text="查看绑定二维码 / 重置" if is_en else "设置 / 绑定 Authenticator"
        )

    def open_2fa_config_dialog(self):
        """弹窗展示 Authenticator 绑定二维码及明文密钥"""
        if not security_mgr.secret:
            security_mgr.generate_secret()

        dlg = tk.Toplevel(self.root)
        dlg.title("Authenticator 2FA 身份验证绑定")
        dlg.geometry("500x600")
        dlg.resizable(False, False)
        dlg.configure(bg=GUI_BG_HEADER)
        dlg.transient(self.root)
        dlg.grab_set()

        # 居中显示
        scr_w = dlg.winfo_screenwidth()
        scr_h = dlg.winfo_screenheight()
        pos_x = max(0, (scr_w - 500) // 2)
        pos_y = max(0, (scr_h - 600) // 2)
        dlg.geometry(f"500x600+{pos_x}+{pos_y}")

        header = tk.Frame(dlg, bg=GUI_BG_CARD, pady=12)
        header.pack(fill="x")
        tk.Label(
            header,
            text="绑定 Authenticator 动态验证器",
            font=("Microsoft YaHei UI", 12, "bold"),
            fg=GUI_FG_MAIN,
            bg=GUI_BG_CARD
        ).pack()
        tk.Label(
            header,
            text="兼容 Google Authenticator, Microsoft Authenticator, 1Password 等",
            font=("Microsoft YaHei UI", 8),
            fg=GUI_FG_MUTED,
            bg=GUI_BG_CARD
        ).pack(pady=(2, 0))

        body = tk.Frame(dlg, bg=GUI_BG_HEADER, padx=24, pady=16)
        body.pack(fill="both", expand=True)

        totp_uri = security_mgr.get_totp_uri("ClaudeRemote")

        # 生成二维码容器（加大尺寸 240x240 并预留纯白留白）
        qr_box = tk.Frame(body, bg="#ffffff", width=240, height=240, bd=1, relief="solid")
        qr_box.pack_propagate(False)
        qr_box.pack(pady=(0, 14))

        qr_lbl = tk.Label(qr_box, bg="#ffffff")
        qr_lbl.pack(expand=True, fill="both")

        if HAS_QRCODE:
            try:
                # 使用标准 4 单元静区留白 (Quiet Zone)，生成高对比度清晰二维码
                qr = qrcode.QRCode(box_size=10, border=4)
                qr.add_data(totp_uri)
                qr.make(fit=True)
                img = qr.make_image(fill_color="#000000", back_color="#ffffff").convert("RGB")
                # 缩放到 225x225，在 240x240 的纯白容器内呈现完美的静区边距，极速识别
                img = img.resize((225, 225), Image.Resampling.NEAREST)
                self.totp_qr_image_tk = ImageTk.PhotoImage(img, master=dlg)
                qr_lbl.config(image=self.totp_qr_image_tk)
            except Exception as e:
                qr_lbl.config(text=f"二维码渲染失败: {e}", bg=GUI_BG_CARD, fg=GUI_ACCENT_RED)
        else:
            qr_lbl.config(text="请在手机 App 中手动输入密钥", bg=GUI_BG_CARD, fg=GUI_FG_MUTED)

        tk.Label(
            body,
            text="使用身份验证器扫描上方二维码，或手动输入下方密钥：",
            font=("Microsoft YaHei UI", 8),
            fg=GUI_FG_MUTED,
            bg=GUI_BG_HEADER
        ).pack()

        # 密钥展示及复制
        sec_key_frame = tk.Frame(body, bg=GUI_BG_HEADER)
        sec_key_frame.pack(fill="x", pady=(6, 12))

        key_var = tk.StringVar(value=security_mgr.secret)
        key_entry = tk.Entry(
            sec_key_frame,
            textvariable=key_var,
            font=("Consolas", 11, "bold"),
            bg=GUI_BG_ENTRY,
            fg=GUI_FG_MAIN,
            readonlybackground=GUI_BG_ENTRY,
            state="readonly",
            relief="flat",
            justify="center"
        )
        key_entry.pack(side="left", fill="x", expand=True, ipady=3)

        def _copy_secret():
            dlg.clipboard_clear()
            dlg.clipboard_append(security_mgr.secret)
            messagebox.showinfo("提示", "2FA 密钥已复制到剪贴板！", parent=dlg)

        cp_btn = tk.Button(
            sec_key_frame,
            text="复制密钥",
            font=("Microsoft YaHei UI", 8),
            bg=GUI_BG_BTN,
            fg=GUI_FG_MAIN,
            activebackground=GUI_BG_BTN_HOVER,
            activeforeground="#ffffff",
            relief="flat",
            cursor="hand2",
            command=_copy_secret,
            padx=8,
            pady=2
        )
        cp_btn.pack(side="right", padx=(6, 0))

        # 验证码测试区域
        verify_frame = tk.Frame(body, bg=GUI_BG_HEADER)
        verify_frame.pack(fill="x", pady=(4, 12))

        tk.Label(
            verify_frame,
            text="输入 6 位验证码测试:",
            font=("Microsoft YaHei UI", 8),
            fg=GUI_FG_MUTED,
            bg=GUI_BG_HEADER
        ).pack(side="left")

        test_code_entry = tk.Entry(
            verify_frame,
            font=("Consolas", 11, "bold"),
            bg=GUI_BG_ENTRY,
            fg=GUI_FG_MAIN,
            insertbackground=GUI_FG_MAIN,
            relief="flat",
            width=8,
            justify="center"
        )
        test_code_entry.pack(side="left", padx=(8, 8), ipady=2)

        def _test_verify():
            c = test_code_entry.get().strip()
            if security_mgr.verify_code(c):
                messagebox.showinfo("测试通过", "验证成功！Authenticator 已与本系统正确同步。", parent=dlg)
            else:
                messagebox.showerror("验证失败", "验证码错误或时钟偏差，请检查手机系统时间是否准确。", parent=dlg)

        test_btn = tk.Button(
            verify_frame,
            text="立即验证测试",
            font=("Microsoft YaHei UI", 8),
            bg=GUI_BG_BTN,
            fg=GUI_FG_MAIN,
            activebackground=GUI_BG_BTN_HOVER,
            activeforeground="#ffffff",
            relief="flat",
            cursor="hand2",
            command=_test_verify,
            padx=8,
            pady=2
        )
        test_btn.pack(side="left")

        # 底部重置密钥按钮与关闭按钮
        btn_box = tk.Frame(body, bg=GUI_BG_HEADER)
        btn_box.pack(fill="x", pady=(10, 0))

        def _reset_secret():
            if messagebox.askyesno("重置密钥", "确定要重新生成 2FA 密钥吗？\n重置后所有已绑定的手机验证器与已登录设备都会失效！", parent=dlg):
                security_mgr.generate_secret()
                security_mgr.sessions.clear()
                self.refresh_device_list()
                dlg.destroy()
                self.open_2fa_config_dialog()

        reset_btn = tk.Button(
            btn_box,
            text="重新生成密钥",
            font=("Microsoft YaHei UI", 8),
            bg="#7f1d1d",
            fg="#fecaca",
            activebackground="#991b1b",
            activeforeground="#ffffff",
            relief="flat",
            cursor="hand2",
            command=_reset_secret,
            padx=10,
            pady=3
        )
        reset_btn.pack(side="left")

        close_btn = tk.Button(
            btn_box,
            text="完成",
            font=("Microsoft YaHei UI", 9, "bold"),
            bg="#f4f4f4",
            fg="#121212",
            activebackground="#e0e0e0",
            activeforeground="#000000",
            relief="flat",
            cursor="hand2",
            command=dlg.destroy,
            padx=16,
            pady=3
        )
        close_btn.pack(side="right")

    def refresh_device_list(self):
        """刷新当前已授权在线设备列表"""
        try:
            for item in self.dev_tree.get_children():
                self.dev_tree.delete(item)

            devices = security_mgr.list_active_devices()
            self.dev_count_lbl.config(text=f"当前已授权在线设备: {len(devices)} 台")

            for dev in devices:
                self.dev_tree.insert(
                    "",
                    "end",
                    iid=dev["token"],
                    values=(
                        dev.get("id", ""),
                        dev.get("device_name", "未知设备"),
                        dev.get("ip", "未知"),
                        dev.get("last_active", "")
                    )
                )
        except Exception as e:
            pass

    def kick_selected_device(self):
        """踢出选中的单台设备"""
        sel = self.dev_tree.selection()
        if not sel:
            messagebox.showinfo("提示", "请先在上方列表中选中需要踢出下线的设备。")
            return
        dev_token = sel[0]
        dev_info = security_mgr.sessions.get(dev_token, {})
        dev_name = dev_info.get("device_name", "该设备")
        if messagebox.askyesno("踢出设备", f"确定要断开并注销 [{dev_name}] 的授权吗？\n注销后该设备必须重新输入 2FA 动态码才能访问。"):
            security_mgr.revoke_session(dev_token)
            access_sessions.reset()
            log_to_gui(f"已踢出设备: {dev_name} ({dev_token[:8]})，会话票据已同步吊销")
            self.refresh_device_list()

    def kick_all_devices(self):
        """一键踢下线全部已授权设备"""
        devices = security_mgr.list_active_devices()
        if not devices:
            messagebox.showinfo("提示", "当前没有已授权在线的设备。")
            return
        if messagebox.askyesno("全部踢下线", f"确定要踢下线当前全部 {len(devices)} 台在线设备吗？\n所有手机端将立即被锁屏，需重新验证 2FA。"):
            with security_mgr.lock:
                security_mgr.sessions.clear()
            access_sessions.reset()
            log_to_gui(f"已强制注销并踢下线所有已连接设备 ({len(devices)} 台)，全部会话票据已注销")
            self.refresh_device_list()

    def on_close(self):
        try:
            self._cleanup_resources(exit_app=True)
        except:
            pass
        self.root.destroy()
        os._exit(0)

if __name__ == "__main__":
    root = tk.Tk()
    app = ClaudeRemoteGUI(root)
    root.mainloop()
