#!/usr/bin/env bash
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;36m'
PLAIN='\033[0m'

if [ "$(id -u)" != "0" ]; then
    echo -e "${RED}错误: 请使用 root 权限运行。${PLAIN}"
    exit 1
fi

OS_TYPE=""
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS_TYPE="${ID:-}"
fi

echo -e "${BLUE}GatePilot Go 一键部署${PLAIN}"
case "$OS_TYPE" in
    ubuntu|debian)
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -q || true
        apt-get install -y openvpn curl git jq ca-certificates iptables iproute2 psmisc golang-go
        ;;
    alpine)
        apk update || true
        apk add openvpn curl git jq ca-certificates iptables iproute2 psmisc bash go
        ;;
    centos|rhel|rocky|almalinux|fedora|ol|amzn)
        if command -v dnf >/dev/null 2>&1; then
            PKG_MGR=dnf
        else
            PKG_MGR=yum
        fi
        if [ "$OS_TYPE" != "fedora" ] && [ "$OS_TYPE" != "amzn" ]; then
            "$PKG_MGR" install -y epel-release || true
        fi
        "$PKG_MGR" install -y openvpn curl git jq ca-certificates iptables iproute psmisc golang || \
        "$PKG_MGR" install -y openvpn curl git jq ca-certificates iptables iproute2 psmisc golang
        ;;
    *)
        echo -e "${RED}不支持的系统: ${OS_TYPE}${PLAIN}"
        exit 1
        ;;
esac

INSTALL_DIR="${GATEPILOT_INSTALL_DIR:-/opt/gatepilot}"
GITHUB_USER="${1:-caichengle666}"
GITHUB_REPO="${2:-gatepilot}"
DEPLOY_BRANCH="${DEPLOY_BRANCH:-main}"
GITHUB_URL="https://github.com/${GITHUB_USER}/${GITHUB_REPO}.git"
AUTH_FILE="${INSTALL_DIR}/vpngate_data/ui_auth.json"
FIRST_INSTALL=0
if [ ! -f "$AUTH_FILE" ]; then
    FIRST_INSTALL=1
fi

valid_port() {
    [[ "$1" =~ ^[0-9]+$ ]] && [ "$1" -ge 1 ] && [ "$1" -le 65535 ]
}

wait_for_auth_file() {
    local attempt
    for attempt in $(seq 1 30); do
        [ -f "$AUTH_FILE" ] && return 0
        sleep 1
    done
    return 1
}

restart_gatepilot() {
    if command -v systemctl >/dev/null 2>&1; then
        systemctl restart gatepilot.service
    elif command -v rc-service >/dev/null 2>&1; then
        rc-service gatepilot restart
    fi
}

configure_initial_settings() {
    local current_username current_port current_proxy_port current_suffix
    local username password confirm bind_choice host web_port proxy_port suffix
    local proxy_auth_choice proxy_auth_enabled proxy_username proxy_password upstream_proxy temporary

    [ -f "$AUTH_FILE" ] || return 0
    current_username=$(jq -r '.username // empty' "$AUTH_FILE")
    current_port=$(jq -r '.port // 8787' "$AUTH_FILE")
    current_proxy_port=$(jq -r '.proxy_port // 7928' "$AUTH_FILE")
    current_suffix=$(jq -r '.secret_path // empty' "$AUTH_FILE")

    echo -e "${BLUE}首次安装配置向导${PLAIN}"
    read -r -p "管理用户名 [${current_username}]: " username
    username=${username:-$current_username}

    while true; do
        read -r -s -p "管理密码 [回车保留随机密码]: " password
        echo
        [ -z "$password" ] && break
        read -r -s -p "再次输入管理密码: " confirm
        echo
        [ "$password" = "$confirm" ] && break
        echo -e "${RED}两次密码不一致，请重新输入。${PLAIN}"
    done

    echo "1) 仅本机访问 (127.0.0.1)"
    echo "2) 公网 IPv4 (0.0.0.0)"
    echo "3) 公网 IPv4/IPv6 (::)"
    read -r -p "Web 绑定方式 [1-3，默认2]: " bind_choice
    case "${bind_choice:-2}" in
        1) host="127.0.0.1" ;;
        3) host="::" ;;
        *) host="0.0.0.0" ;;
    esac

    read -r -p "Web 管理端口 [${current_port}]: " web_port
    web_port=${web_port:-$current_port}
    while ! valid_port "$web_port"; do
        read -r -p "端口无效，请重新输入 Web 管理端口: " web_port
    done

    read -r -p "本地 HTTP/SOCKS5 代理端口 [${current_proxy_port}]: " proxy_port
    proxy_port=${proxy_port:-$current_proxy_port}
    while ! valid_port "$proxy_port" || [ "$proxy_port" = "$web_port" ]; do
        read -r -p "端口无效或与 Web 端口冲突，请重新输入代理端口: " proxy_port
    done

    read -r -p "Web 安全路径 [${current_suffix}，输入 random 重新生成]: " suffix
    suffix=${suffix:-$current_suffix}
    if [ "$suffix" = "random" ]; then
        suffix=$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 12 || true)
    fi
    while [[ ! "$suffix" =~ ^[A-Za-z0-9]+$ ]]; do
        read -r -p "安全路径只能包含字母和数字，请重新输入: " suffix
    done

    read -r -p "启用本地代理用户名密码认证？[y/N]: " proxy_auth_choice
    proxy_auth_enabled=false
    proxy_username=""
    proxy_password=""
    if [[ "$proxy_auth_choice" =~ ^[Yy]$ ]]; then
        proxy_auth_enabled=true
        while [ -z "$proxy_username" ]; do
            read -r -p "代理用户名: " proxy_username
        done
        while [ -z "$proxy_password" ]; do
            read -r -s -p "代理密码: " proxy_password
            echo
        done
    fi

    read -r -p "前置代理 [可留空，例如 socks5://127.0.0.1:1080]: " upstream_proxy
    while [ -n "$upstream_proxy" ] && [[ ! "$upstream_proxy" =~ ^(http|https|socks|socks5):// ]]; do
        read -r -p "前置代理协议无效，请重新输入或留空: " upstream_proxy
    done

    temporary=$(mktemp)
    jq \
        --arg username "$username" \
        --arg password "$password" \
        --arg host "$host" \
        --arg suffix "$suffix" \
        --arg upstream_proxy "$upstream_proxy" \
        --arg proxy_username "$proxy_username" \
        --arg proxy_password "$proxy_password" \
        --argjson port "$web_port" \
        --argjson proxy_port "$proxy_port" \
        --argjson proxy_auth_enabled "$proxy_auth_enabled" '
            .username = $username |
            .password = (if $password == "" then .password else $password end) |
            .host = $host |
            .port = $port |
            .proxy_port = $proxy_port |
            .secret_path = $suffix |
            .upstream_proxy = $upstream_proxy |
            .proxy_auth_enabled = $proxy_auth_enabled |
            .proxy_username = $proxy_username |
            .proxy_password = (if $proxy_auth_enabled then $proxy_password else "" end)
        ' "$AUTH_FILE" > "$temporary"
    install -m 600 "$temporary" "$AUTH_FILE"
    rm -f "$temporary"
    restart_gatepilot
    echo -e "${GREEN}首次安装配置已保存。${PLAIN}"
}

if [ -d "${INSTALL_DIR}/.git" ]; then
    if [ ! -f "${INSTALL_DIR}/.local_dev" ]; then
        git -C "$INSTALL_DIR" fetch origin "$DEPLOY_BRANCH"
        git -C "$INSTALL_DIR" checkout "$DEPLOY_BRANCH"
        git -C "$INSTALL_DIR" pull --ff-only origin "$DEPLOY_BRANCH"
    fi
else
    git clone --branch "$DEPLOY_BRANCH" "$GITHUB_URL" "$INSTALL_DIR"
fi

echo -e "${YELLOW}正在编译 Go 服务...${PLAIN}"
cd "$INSTALL_DIR"
go build -trimpath -ldflags="-s -w" -o gatepilot .
chmod 755 gatepilot

if command -v systemctl >/dev/null 2>&1; then
    cat > /etc/systemd/system/gatepilot.service <<EOF
[Unit]
Description=GatePilot VPNGate OpenVPN Gateway
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=${INSTALL_DIR}
ExecStart=${INSTALL_DIR}/gatepilot
Restart=always
RestartSec=5
EnvironmentFile=-/etc/default/gatepilot

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable --now gatepilot.service
elif command -v rc-service >/dev/null 2>&1; then
    cat > /etc/init.d/gatepilot <<EOF
#!/sbin/openrc-run
description="GatePilot VPNGate OpenVPN Gateway"
command="${INSTALL_DIR}/gatepilot"
command_background="yes"
directory="${INSTALL_DIR}"
pidfile="/run/gatepilot.pid"
output_log="${INSTALL_DIR}/vpngate_data/service.log"
error_log="${INSTALL_DIR}/vpngate_data/service.log"
depend() { need net; }
EOF
    chmod +x /etc/init.d/gatepilot
    rc-update add gatepilot default
    rc-service gatepilot restart
else
    echo -e "${YELLOW}未检测到 systemd/OpenRC，请手动运行 ${INSTALL_DIR}/gatepilot。${PLAIN}"
fi

install -m 755 "$INSTALL_DIR/scripts/ml.sh" /usr/local/bin/ml

if ! wait_for_auth_file; then
    echo -e "${YELLOW}服务已启动，但配置文件尚未生成，请稍后运行 ml 检查状态。${PLAIN}"
fi
if [ "$FIRST_INSTALL" = "1" ] && [ -t 0 ] && [ "${GATEPILOT_SKIP_WIZARD:-0}" != "1" ]; then
    configure_initial_settings
fi

json_value() {
    jq -r --arg key "$1" '.[$key] // empty' "$AUTH_FILE" 2>/dev/null
}
PUBLIC_IP=$(curl -4 -s --max-time 3 https://api.ipify.org || echo "服务器IP")
echo -e "${GREEN}安装完成。${PLAIN}"
echo -e "管理地址: ${BLUE}http://${PUBLIC_IP}:$(json_value port)/$(json_value secret_path)/${PLAIN}"
echo -e "用户名: ${YELLOW}$(json_value username)${PLAIN}"
echo -e "密码: ${YELLOW}$(json_value password)${PLAIN}"
echo -e "本地 HTTP/SOCKS5 代理: ${BLUE}127.0.0.1:$(json_value proxy_port)${PLAIN}"
echo "管理命令: ml（交互菜单）或 ml info | status | logs | restart | update | web | port | password | routing"
