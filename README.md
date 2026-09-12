# Claude Remote

Windows 上已经能跑 [Claude Code](https://docs.anthropic.com/en/docs/claude-code) 的话，开这个助手，手机扫码就能看终端、打字、选选项、批权限。

它不替你装 Claude，也不直接调 API。就是用 winpty 把本机 `claude` 接到浏览器里。谁拿到链接，权限就和坐在这台电脑前差不多。

- 演示页面：[https://remote.ymzcc.com/demo](https://remote.ymzcc.com/demo)（静态展示，不连真实会话）

```
手机浏览器
  → https://你的域名:443
  → Nginx 转到 127.0.0.1:176xx
  → 服务器 frps :17000
  → 家里电脑 frpc
  → 本机只绑回环的 HTTP
  → Claude 终端
```

17600–17999 不要对公网开放，只给本机 Nginx。手机一律走 443。没有域名可以先用 `http://IP:端口` 试通，通了再上证书。

---

# 功能

## 电脑这一侧

| | |
| :--- | :--- |
| 工作目录 | 浏览或手改，下次还在 |
| 智能续接 | 勾了启动带 `-c`，接着上次对话 |
| 通道 | SSE（默认）或长轮询（SSE 被运营商掐时换） |
| 开关 | 启动 / 停止。停了只杀进程，名单还在 |
| 入口 | 二维码 + 链接，可复制 |
| 2FA | 开/关、扫 Authenticator、看密钥 |
| 设备 | 类型、IP、最近活跃；踢一台或全踢 |
| 日志 | 窗口最底下 |

关掉窗口 = 停隧道和所有 Claude 进程。名单在 `%APPDATA%\ClaudeRemote\state.json`，2FA 在同目录 `security.json`。

## 手机这一侧

扫码进去是遥控台，不是一个黑框。可深色 / 浅色，能加到主屏幕。

**终端**

xterm 画 Claude 的 TUI。底下输入框等于打字回车。还有 Enter、Esc、Ctrl+C、Tab、方向键、空格、Shift+Tab（切权限模式）、`/compact`、`/clear`。图片可传到工作区 `.claude_remote_uploads/` 再把路径丢给 Claude（常见格式，大约 8MB 以内）。

**选择题和授权**

Claude 卡住问你时出卡片，不用在终端里盲按数字。普通题支持单选、多选、自己填；权限题会区分跑命令、改文件、联网、出沙箱、Plan。优先读官方 jsonl，PTY 刮屏是备用。锁屏后后台仍会巡检，亮屏能看到「在等你」或「做完了」，开了通知还能弹一下。连点选项不会把两次按键搅在一起。

**多会话**

侧边栏按项目文件夹分组。新开、改名、置顶、停、删。同一目录可以开多条。能从该目录的 Claude 历史里 resume 某一条，或新开。切走再切回来，已经在跑的不会重启。

**文件**

看当前工作区目录树，打开文本（大约 1MB 截断）。换工作目录会把那条会话重开到新路径。读文件锁在当前项目里，软链接指到外面的进不去。

**多窗口（WebOS）**

宽屏或打开桌面模式后，终端和文件可以分窗口拖、缩放、最小化。画布能平移、捏合、一键看全貌。位置记在浏览器里。顶栏有这台电脑 CPU / 内存 / 磁盘大概忙不忙。

息屏时推流会降频，回来自动接上。主题会尽量带给 Claude CLI。

## 不会做的

不替你安装或登录 Claude，不替你付 API。不是远程桌面，看不到 VS Code，只能看到 Claude 那个终端。也不是给别人电脑用的「免装 Claude」包。

---

# 从零搭服务器

Ubuntu 22/24、root、装在 `/opt/frp`。域名和路径自己换。

## 你要准备

- 有公网 IP 的 Linux
- 一个域名指到这台机器（强烈建议）
- 服务端 `frps` 和本目录 `frpc.exe` 同一大版本（配置是 FRP 0.52 以后的 TOML）

| 端口 | 干什么 |
| :--- | :--- |
| 22 | SSH |
| 80 / 443 | 证书和网页 |
| 17000 | frpc 连进来 |
| 17600–17999 | 网页助手，公网应拒绝，只许 127.0.0.1 |

每次点启动，客户端在 17600–17999 里随机挑一个。

## 防火墙

```bash
apt update && apt install -y curl wget tar ufw nginx
ufw allow OpenSSH
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 17000/tcp
ufw deny 17600:17999/tcp
ufw enable
```

云安全组同样：放行 22、80、443、17000，别放行 17600–17999。

## frps

[FRP Releases](https://github.com/fatedier/frp/releases) 下 linux_amd64（ARM 就 arm64），版本尽量和 `frpc.exe` 一致。

```bash
mkdir -p /opt/frp
cd /tmp
wget https://github.com/fatedier/frp/releases/download/vX.Y.Z/frp_X.Y.Z_linux_amd64.tar.gz
tar -xzf frp_X.Y.Z_linux_amd64.tar.gz
cp frp_X.Y.Z_linux_amd64/frps /opt/frp/
chmod +x /opt/frp/frps
```

token 自己生成，Windows 里要填同一个：

```bash
python3 -c "import secrets; print(secrets.token_hex(16))"
```

`/opt/frp/frps.toml`：

```toml
bindPort = 17000
kcpBindPort = 17000
transport.tls.force = false

auth.method = "token"
auth.token = "这里填刚生成的"

allowPorts = [
  { start = 17600, end = 17999 }
]

log.to = "/opt/frp/frps.log"
log.level = "info"
log.maxDays = 3
```

`/etc/systemd/system/frps.service`：

```ini
[Unit]
Description=frps
After=network.target

[Service]
Type=simple
ExecStart=/opt/frp/frps -c /opt/frp/frps.toml
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload
systemctl enable --now frps
ss -tulpn | grep 17000
```

有进程在听 17000 就对了。日志：`tail -f /opt/frp/frps.log`。

## 域名和证书

DNS：`remote.example.com` A 记录 → 服务器 IP。等解析生效。

```bash
apt install -y certbot python3-certbot-nginx
certbot --nginx -d remote.example.com
```

证书一般在 `/etc/letsencrypt/live/remote.example.com/`。

## Nginx

手机打开的是：

```
https://remote.example.com/p/17683/?token=...
```

要从路径里取出端口，转到 `127.0.0.1:17683`。SSE 不能开 buffering。

坑：`location ^~ /p/` 会盖掉正则，页面直接 403，正文大概是 `Forbidden: Port out of range`。兜底必须写成普通的 `location /p/`。

`/etc/nginx/sites-available/remote.example.com`：

```nginx
map $http_upgrade $connection_upgrade {
    default upgrade;
    ''      close;
}

server {
    listen 80;
    server_name remote.example.com;
    location /.well-known/acme-challenge/ { root /var/www/html; }
    location / { return 301 https://$host$request_uri; }
}

server {
    listen 443 ssl http2;
    server_name remote.example.com;

    ssl_certificate     /etc/letsencrypt/live/remote.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/remote.example.com/privkey.pem;

    client_max_body_size 32m;
    proxy_read_timeout 600s;
    proxy_send_timeout 600s;
    proxy_buffering off;
    proxy_request_buffering off;
    gzip off;

    location ~ ^/p/(17[6-9][0-9]{2})(/.*)?$ {
        set $backend_port $1;
        set $rest $2;
        if ($rest = "") { set $rest /; }

        proxy_pass http://127.0.0.1:$backend_port$rest$is_args$args;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        proxy_redirect off;
    }

    location /p/ {
        return 403 "Forbidden: Port out of range";
    }
}
```

```bash
ln -sf /etc/nginx/sites-available/remote.example.com /etc/nginx/sites-enabled/
nginx -t && systemctl reload nginx
```

助手没开时，本机 `curl -I https://remote.example.com/p/17600/` 应该是 **502**（反代通了，后面没人）。公网如果能直接打开 17600 的 HTTP，防火墙没拦住。

---

# Windows 这边

## Claude Code

按官方文档装好，PowerShell 里 `claude --version` 有输出，并且能对话。

助手会找 `%APPDATA%\npm\claude.cmd`、`%LOCALAPPDATA%\npm\claude.cmd`、PATH 里的 `claude`。npm 全局目录不在默认位置时，把那个目录加进 PATH，或设 `npm_config_prefix`。

## Python

建议 3.12。

```powershell
cd 本仓库目录
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## 配置

```powershell
copy server_config.ini.example server_config.ini
```

```ini
[frp_server]
server_addr = 服务器IP或域名
server_port = 17000
auth_token = 和 frps.toml 里完全一样
public_https_host = remote.example.com
```

`server_addr` 是 frpc 去连谁；`public_https_host` 是二维码上的主机名，填 Nginx 那个 HTTPS 域名，别填 127.0.0.1。这个 ini 不要提交到 git。

`frpc.exe` 没有的话，从 FRP Release 下 windows_amd64 放到本目录，版本和服务器一致。

## 开起来

```powershell
python claude_remote_gui.py
```

选工作目录 → 启动服务 → 手机扫码。链接类似：

```
https://remote.example.com/p/17683/?token=一长串
```

关掉窗口，隧道和 Claude 一起停。第一次打开会把 URL 里的 token 换成 Cookie。桌面里可以开 2FA。

先不通 HTTPS 时：临时别封 17600–17999，用 `http://IP:端口` 试。试完立刻封回去。

---

# 不对的时候

| 你看到的 | 多半是 |
| :--- | :--- |
| 日志写穿透失败 | token、17000、防火墙；看服务器 `frps.log` |
| 手机 502 | Nginx 没问题，这个口上还没有 frpc |
| 403 且写着 Port out of range | Nginx 用了 `^~ /p/` |
| 403 Invalid Token | 链接过期、复制缺字、或用了上一轮的 |
| 页面有、终端没字 | `claude` 不在 PATH，或没装上 pywinpty |
| 扫出来不是 https | `public_https_host` 填错了 |

---

# 测试和打包

```powershell
python tests/test_security_phase1.py
python tests/test_phase2_pty.py
python tests/test_phase3_frontend.py
```

```powershell
pyinstaller --noconfirm Claude手机遥控助手.spec
```

输出在 `dist/Claude手机遥控助手/`，里面要有 exe、`frpc.exe` 和 `_internal`。zip 发给别人时别把填好 token 的 ini 打进去；对方电脑也得自己有 Claude。

链接当密码：别发群、别截图带完整 URL。用完关窗口。

仓库结构：

```
claude-remote/
├── claude_remote_gui.py
├── claude_remote/web/index.html
├── frpc.exe
├── server_config.ini.example
├── requirements.txt
├── tests/
├── LICENSE
└── README.md
```

---

## 协议

本项目基于 [PolyForm Noncommercial 1.0.0](LICENSE)。

- 个人自用、学习与研究随意。
- 商业使用 / 二次包装售卖请先提 [Issue](https://github.com/Memorial-coder/claude-remote/issues) 沟通。
- `frpc.exe` 版权归 [fatedier/frp](https://github.com/fatedier/frp) 所有。
