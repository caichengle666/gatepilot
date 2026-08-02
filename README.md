# GatePilot

GatePilot 是一个用 Go 实现的 VPNGate OpenVPN 网关。它从 VPNGate 官方 CSV API 获取公开节点，使用系统中的 OpenVPN 建立隧道，并提供 HTTP/SOCKS5 双协议代理和 Web 管理界面。

VPNGate 本身不是一种新的 VPN 协议。VPNGate 是公共 VPN 中继节点目录和志愿者网络；本项目使用其中节点提供的 OpenVPN 配置进行连接。

## 核心流程

```text
VPNGate API
    ↓ 获取并解析 OpenVPN 配置
节点筛选 / OpenVPN 握手检测 / 自动维护
    ↓
OpenVPN 进程 → Linux tun0 / Windows Wintun 或 TAP
    ↓
127.0.0.1:7928 HTTP/SOCKS5 代理
    ↓
调用代理的本机程序
```

## 功能

- 从 `https://www.vpngate.net/api/iphone/` 获取 OpenVPN 节点。
- 解析国家、IP、端口、协议、分数、速度和会话数。
- 在节点列表显示握手测速延迟，并支持手动重新检测单个节点。
- 通过当前 VPN 代理下载测试数据，显示实际宽带速度（Mbps）。
- 支持自动、固定国家、固定节点和收藏优先筛选。
- 支持在 Web 页面配置 HTTP/SOCKS5 前置代理，用于拉取 VPNGate API 节点列表，以及帮助 TCP OpenVPN 节点建立隧道；应用流量连接成功后只走 VPN 隧道，不会经过前置代理。UDP 节点直连，不使用前置代理。
- 支持自定义宽带测速网址，通过当前 VPN 代理下载最多 20 MB 数据并计算真实网速。
  默认测速地址为 `https://speed.cloudflare.com/__down?bytes=10000000`。
- 启动并监控外部 OpenVPN 进程。
- 清理远端配置中的脚本、插件和管理接口等危险指令。
- 在 Linux 上绑定 `tun0`，在 Windows 上自动识别 OpenVPN 网卡并绑定代理出站，避免流量绕过 VPN。
- 同一端口提供 HTTP、HTTPS CONNECT 和 SOCKS5 代理。
- 支持在 Web 页面配置 HTTP/SOCKS5 代理认证；代理监听非本机地址时强制要求启用认证。
- 支持可选的 HTTP Basic / SOCKS5 用户名密码认证。
- 提供登录保护的 Web 页面和 JSON API。
- 保存节点、运行状态和管理凭据，重启后继续使用。

## 系统要求

- Linux 需要 root 权限和可用的 TUN/TAP 设备；Windows 需要以管理员身份运行。
- Go 1.18 或更高版本。
- OpenVPN；Linux 还需要 `iproute2` 和 CA 证书。

Windows 原生模式支持 OpenVPN 2.4 及以上版本。GatePilot 会按以下顺序查找 OpenVPN：

1. `OPENVPN_CMD` 指定的命令或完整路径；
2. GatePilot 可执行文件旁的 `openvpn\openvpn.exe` 便携核心目录；
3. GatePilot 可执行文件旁的 `openvpn.exe`；
4. `C:\Program Files\OpenVPN\bin\openvpn.exe`；
5. `PATH` 中的 `openvpn.exe`。

OpenVPN 2.6 及以上在 Windows 上默认使用 Wintun 驱动，并把本地 HTTP/SOCKS5 代理的 TCP 和 DNS 出站绑定到该虚拟网卡。

## Windows 运行

1. 从 GitHub Releases 下载 `gatepilot-<版本>-windows-amd64-portable.zip`。
2. 解压后目录内已包含 `gatepilot.exe` 和 `openvpn\` 便携核心文件。仓库 `openvpn/` 目录也提供同一套 Windows OpenVPN 核心文件。
3. 右键选择“以管理员身份运行”。Wintun 虚拟网卡需要管理员/SYSTEM 权限；非管理员运行时 OpenVPN 会报 `Wintun requires SYSTEM privileges`。
4. 从终端输出打开管理地址，并在页面连接节点。
5. 将需要走 VPN 的应用代理设置为 `127.0.0.1:7928`，协议使用 HTTP 或 SOCKS5。

Windows 默认只允许一个 GatePilot 实例运行。重复启动会在创建 OpenVPN 进程前退出；如果 Web 管理端口或本地代理端口已被其他程序占用，也会直接提示端口冲突，不会额外创建 Wintun 网卡。

如果节点维护或连接任务异常卡住超过 2 分钟，Web 手动连接会自动恢复该锁，避免页面一直提示“当前已有连接或节点维护任务正在运行”。

如果 OpenVPN 安装在其他目录，使用 PowerShell 指定：

```powershell
$env:OPENVPN_CMD='"D:\Tools\OpenVPN\bin\openvpn.exe"'
.\gatepilot.exe
```

GatePilot 不会修改 Windows 全局默认路由；只有使用 GatePilot 本地代理的应用流量会进入 OpenVPN，避免管理页面和 OpenVPN 控制连接被隧道自身截断。

## 一键安装

```bash
bash <(curl -Ls https://raw.githubusercontent.com/caichengle666/gatepilot/main/install.sh)
```

安装目录为 `/opt/gatepilot`，systemd/OpenRC 服务名为 `gatepilot`。安装后可使用：

```bash
ml info
ml status
ml logs
ml restart
ml update
ml web
ml port
ml password
ml routing
```

直接执行 `ml` 会打开交互式管理菜单，可启动、停止、重启、查看日志、更新程序，以及修改网页绑定、安全路径、端口、账号密码和节点路由策略。管理脚本为 Bash，不再依赖 Python。

## Docker Compose

Docker 主机必须提供 `/dev/net/tun`，容器需要 `NET_ADMIN` 权限：

```bash
git clone https://github.com/caichengle666/gatepilot.git
cd gatepilot
docker compose up -d
docker compose logs -f gatepilot
```

默认发布 Web 端口 `8787`，代理端口仅绑定宿主机 `127.0.0.1:7928`。持久化数据保存在当前目录的 `data/`。首次启动的管理地址、用户名和密码可通过日志查看，也保存在 `data/ui_auth.json`。

Docker 镜像只包含 Linux 共享代码和 Linux OpenVPN，不包含 Windows OpenVPN 二进制。

GitHub Actions 会自动执行测试，生成 Linux amd64/arm64、Windows amd64、macOS amd64/arm64 构建产物。推送 `v*` tag 时会创建 GitHub Release，并优先使用仓库内 `openvpn/` 核心文件打包 Windows 便携版 zip；仓库缺少核心文件时才会从 OpenVPN 官方下载：

```text
gatepilot-<版本>-windows-amd64-portable.zip
```

Linux amd64/arm64 Docker 镜像发布到：

```text
ghcr.io/caichengle666/gatepilot:latest
```

也可以直接使用镜像：

```bash
docker pull ghcr.io/caichengle666/gatepilot:latest
```

## 源码运行

```bash
go test ./...
go build -o gatepilot .
sudo ./gatepilot
```

首次启动会在终端输出管理地址、随机用户名和随机密码。凭据保存在 `vpngate_data/ui_auth.json`。

默认地址：

- Web 管理端口：`8787`
- 本地 HTTP/SOCKS5 代理：`127.0.0.1:7928`
- OpenVPN 虚拟网卡：Linux 为 `tun0`；Windows 自动识别 Wintun/TAP

## 代理使用

HTTP/HTTPS：

```bash
export http_proxy=http://127.0.0.1:7928
export https_proxy=http://127.0.0.1:7928
curl https://api.ipify.org
```

SOCKS5：

```bash
curl --proxy socks5h://127.0.0.1:7928 https://api.ipify.org
```

代理默认只绑定回环地址。确需开放给其他设备时，应同时配置认证和防火墙：

也可以在 Web “代理设置”中启用代理认证并设置用户名/密码。环境变量凭据优先于 Web 配置。若代理监听地址不是本机地址，但未启用任何代理认证，GatePilot 会拒绝启动或拒绝保存设置。

```bash
export LOCAL_PROXY_HOST=0.0.0.0
export LOCAL_PROXY_USER=your-user
export LOCAL_PROXY_PASS=your-strong-password
```

## 常用环境变量

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `VPNGATE_DATA_DIR` | 可执行文件旁的 `vpngate_data` | 数据目录 |
| `VPNGATE_API_URL` | VPNGate 官方 API | 节点数据地址 |
| `OPENVPN_CMD` | Linux 为 `openvpn`；Windows 优先查找程序旁 `openvpn\openvpn.exe` | OpenVPN 命令或完整路径 |
| `LOCAL_PROXY_HOST` | `127.0.0.1` | 代理监听地址 |
| `LOCAL_PROXY_PORT` | `7928` | 代理端口 |
| `LOCAL_PROXY_MAX_CONNECTIONS` | `256` | 最大并发连接数 |
| `LOCAL_PROXY_BIND_TUN` | `true` | 强制把代理出站绑定到 Linux `tun0` 或 Windows OpenVPN 网卡 |
| `LOCAL_PROXY_USER` | 空 | 代理认证用户名；优先于 Web 配置 |
| `LOCAL_PROXY_PASS` | 空 | 代理认证密码；优先于 Web 配置 |
| `UI_HOST` | `127.0.0.1` | Web 监听地址；开放到局域网时应使用反向代理提供 HTTPS |
| `UI_PORT` | `8787` | Web 端口 |
| `UPSTREAM_PROXY` | 空 | 前置代理初始值；可在 Web 页面修改，用于拉取节点列表和帮助 TCP 节点建立隧道 |
| `SPEED_TEST_URL` | Cloudflare 10 MB 下载接口 | 宽带测速地址；可在 Web 页面修改，单次最多读取 20 MB |
| `RECONNECT_INTERVAL_SECONDS` | `15` | 断线检查和自动重连周期 |
| `TARGET_VALID_NODES` | `3` | 每轮探测节点数 |
| `DISABLE_BACKGROUND_FETCH` | `false` | 禁用后台拉取，适合开发测试 |

## 数据文件

```text
vpngate_data/
├── configs/            # 连接时生成的已清洗 OpenVPN 配置
├── nodes.json          # 节点缓存
├── state.json          # 当前连接状态
├── ui_auth.json        # Web 配置和登录凭据
├── blacklist.json      # 暂时失效的节点记录
├── ip_cache.json       # IP 归属和类型缓存
├── logs/               # Web 控制台结构化日志
└── vpngate_auth.txt    # VPNGate 默认认证信息
```

## English

GatePilot is a Go-based gateway for the public VPNGate relay network. It fetches VPNGate's OpenVPN profiles, launches the system OpenVPN client, and exposes a local HTTP/SOCKS5 proxy whose outbound sockets are bound to Linux `tun0` or the detected Windows OpenVPN adapter.

VPNGate is a relay directory and volunteer network, not a separate VPN protocol. This project uses OpenVPN as its tunnel protocol.

Build and run:

```bash
go test ./...
go build -o gatepilot .
sudo ./gatepilot
```

See the Chinese sections above for installation, environment variables, and proxy examples.

## License

See `LICENSE`.
