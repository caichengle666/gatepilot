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

sleep 2
AUTH_FILE="${INSTALL_DIR}/vpngate_data/ui_auth.json"
json_value() {
    sed -n "s/.*\"$1\":[[:space:]]*\"\{0,1\}\([^\",]*\)\"\{0,1\}.*/\1/p" "$AUTH_FILE" 2>/dev/null | head -n1
}
PUBLIC_IP=$(curl -4 -s --max-time 3 https://api.ipify.org || echo "服务器IP")
echo -e "${GREEN}安装完成。${PLAIN}"
echo -e "管理地址: ${BLUE}http://${PUBLIC_IP}:$(json_value port)/$(json_value secret_path)/${PLAIN}"
echo -e "用户名: ${YELLOW}$(json_value username)${PLAIN}"
echo -e "密码: ${YELLOW}$(json_value password)${PLAIN}"
echo -e "本地 HTTP/SOCKS5 代理: ${BLUE}127.0.0.1:$(json_value proxy_port)${PLAIN}"
echo "管理命令: ml（交互菜单）或 ml info | status | logs | restart | update | web | port | password | routing"
