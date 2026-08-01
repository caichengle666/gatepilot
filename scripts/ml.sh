#!/usr/bin/env bash
set -u

INSTALL_DIR="${GATEPILOT_INSTALL_DIR:-${AIMILIVPN_INSTALL_DIR:-/opt/gatepilot}}"
AUTH_FILE="$INSTALL_DIR/vpngate_data/ui_auth.json"
STATE_FILE="$INSTALL_DIR/vpngate_data/state.json"
SERVICE_NAME="gatepilot"

if [ "$(id -u)" != "0" ]; then
    echo "错误: 必须使用 root 权限运行 ml。"
    exit 1
fi

service_action() {
    if command -v systemctl >/dev/null 2>&1; then
        systemctl "$1" "$SERVICE_NAME.service"
    elif command -v rc-service >/dev/null 2>&1; then
        rc-service "$SERVICE_NAME" "$1"
    else
        echo "未检测到 systemd 或 OpenRC。"
        return 1
    fi
}

service_active() {
    if command -v systemctl >/dev/null 2>&1; then
        systemctl is-active --quiet "$SERVICE_NAME.service"
    else
        rc-service "$SERVICE_NAME" status >/dev/null 2>&1
    fi
}

service_pid() {
    if command -v systemctl >/dev/null 2>&1; then
        systemctl show -p MainPID --value "$SERVICE_NAME.service" 2>/dev/null
    else
        cat "/run/$SERVICE_NAME.pid" 2>/dev/null || true
    fi
}

require_config() {
    if [ ! -f "$AUTH_FILE" ]; then
        echo "配置文件尚未生成，请先启动服务: ml start"
        exit 1
    fi
}

json_value() {
    require_config
    jq -r --arg key "$1" '.[$key] // empty' "$AUTH_FILE"
}

state_value() {
    if [ -f "$STATE_FILE" ]; then
        jq -r --arg key "$1" '.[$key] // empty' "$STATE_FILE" 2>/dev/null
    fi
}

set_json_string() {
    local key="$1" value="$2" temporary
    require_config
    temporary=$(mktemp)
    jq --arg key "$key" --arg value "$value" '.[$key] = $value' "$AUTH_FILE" > "$temporary"
    install -m 600 "$temporary" "$AUTH_FILE"
    rm -f "$temporary"
}

set_json_number() {
    local key="$1" value="$2" temporary
    require_config
    temporary=$(mktemp)
    jq --arg key "$key" --argjson value "$value" '.[$key] = $value' "$AUTH_FILE" > "$temporary"
    install -m 600 "$temporary" "$AUTH_FILE"
    rm -f "$temporary"
}

public_ip() {
    curl -4 -fsS --max-time 3 https://api.ipify.org 2>/dev/null || echo "服务器IP"
}

show_info() {
    local host port secret proxy_port username password display_host
    host=$(json_value host)
    port=$(json_value port)
    secret=$(json_value secret_path)
    proxy_port=$(json_value proxy_port)
    username=$(json_value username)
    password=$(json_value password)
    case "$host" in
        "::"|"0.0.0.0"|"") display_host=$(public_ip) ;;
        "::1") display_host="[::1]" ;;
        *)
            if [[ "$host" == *:* ]]; then display_host="[$host]"; else display_host="$host"; fi
            ;;
    esac
    echo "======================================================="
    echo "GatePilot 管理信息"
    echo "======================================================="
    echo "网页登录地址: http://${display_host}:${port}/${secret}/"
    echo "登录用户名:   ${username}"
    echo "登录密码:     ${password}"
    echo "本地代理:     127.0.0.1:${proxy_port} (HTTP/SOCKS5)"
}

show_status() {
    local service_status proxy_status vpn_status pid active latency message proxy_port
    proxy_port=$(json_value proxy_port)
    if service_active; then service_status="已启动"; else service_status="未启动"; fi
    if ss -ltnH 2>/dev/null | awk '{print $4}' | grep -Eq "(^|:)$proxy_port$"; then proxy_status="已监听"; else proxy_status="未监听"; fi
    if pgrep -f '[o]penvpn.*tun0' >/dev/null 2>&1; then vpn_status="已连接"; else vpn_status="未连接"; fi
    pid=$(service_pid)
    active=$(state_value active_openvpn_node_id)
    latency=$(state_value active_node_latency)
    message=$(state_value last_check_message)
    echo "======================================================="
    echo "GatePilot 服务状态"
    echo "======================================================="
    echo "Go 管理服务: ${service_status} (PID: ${pid:-0})"
    echo "代理网关:    ${proxy_status} (Port ${proxy_port})"
    echo "OpenVPN:     ${vpn_status}"
    echo "活动节点:    ${active:--}"
    echo "节点延迟:    ${latency:--}"
    echo "最近状态:    ${message:--}"
}

show_logs() {
    if command -v journalctl >/dev/null 2>&1; then
        journalctl -u "$SERVICE_NAME.service" -f --no-pager
    else
        tail -n 100 -f "$INSTALL_DIR/vpngate_data/service.log"
    fi
}

configure_credentials() {
    local username password confirm
    require_config
    read -r -p "新用户名 [$(json_value username)]: " username
    read -r -s -p "新密码（留空表示不修改）: " password
    echo
    if [ -n "$username" ]; then set_json_string username "$username"; fi
    if [ -n "$password" ]; then
        read -r -s -p "再次输入新密码: " confirm
        echo
        if [ "$password" != "$confirm" ]; then
            echo "两次密码不一致。"
            return 1
        fi
        set_json_string password "$password"
    fi
    service_action restart
    echo "账号密码已保存并重启服务。"
}

valid_port() {
    [[ "$1" =~ ^[0-9]+$ ]] && [ "$1" -ge 1 ] && [ "$1" -le 65535 ]
}

configure_ports() {
    local web_port proxy_port
    require_config
    read -r -p "网页管理端口 [$(json_value port)]: " web_port
    read -r -p "代理出站端口 [$(json_value proxy_port)]: " proxy_port
    web_port=${web_port:-$(json_value port)}
    proxy_port=${proxy_port:-$(json_value proxy_port)}
    if ! valid_port "$web_port" || ! valid_port "$proxy_port" || [ "$proxy_port" -lt 1024 ]; then
        echo "端口无效；代理端口范围必须是 1024-65535。"
        return 1
    fi
    if [ "$web_port" = "$proxy_port" ]; then
        echo "网页端口不能与代理端口相同。"
        return 1
    fi
    set_json_number port "$web_port"
    set_json_number proxy_port "$proxy_port"
    service_action restart
    echo "端口已保存并重启服务。"
}

random_suffix() {
    LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 12
}

configure_web() {
    local choice host suffix
    require_config
    echo "1) 仅本机 IPv4 (127.0.0.1)"
    echo "2) IPv4 公网 (0.0.0.0)"
    echo "3) IPv4/IPv6 双栈公网 (::)"
    echo "4) 仅本机 IPv6 (::1)"
    read -r -p "绑定地址 [1-4，默认3]: " choice
    case "${choice:-3}" in
        1) host="127.0.0.1" ;;
        2) host="0.0.0.0" ;;
        4) host="::1" ;;
        *) host="::" ;;
    esac
    read -r -p "安全路径 [回车保留，输入 random 随机生成]: " suffix
    if [ "$suffix" = "random" ]; then suffix=$(random_suffix); fi
    if [ -n "$suffix" ] && [[ ! "$suffix" =~ ^[A-Za-z0-9]+$ ]]; then
        echo "安全路径只能包含英文字母和数字。"
        return 1
    fi
    set_json_string host "$host"
    if [ -n "$suffix" ]; then set_json_string secret_path "$suffix"; fi
    service_action restart
    show_info
}

configure_routing() {
    local choice mode country ip_choice ip_type fixed_id temporary
    require_config
    echo "1) 自动选择"
    echo "2) 固定地区"
    echo "3) 固定当前 IP"
    echo "4) 仅用收藏"
    read -r -p "路由模式 [1-4]: " choice
    case "$choice" in
        1) mode="auto" ;;
        2) mode="fixed_region"; read -r -p "国家名称或国家代码: " country; [ -n "$country" ] || return 1 ;;
        3)
            mode="fixed_ip"
            fixed_id=$(state_value active_openvpn_node_id)
            if [ -z "$fixed_id" ]; then echo "当前没有活动节点，不能固定 IP。"; return 1; fi
            ;;
        4) mode="favorites" ;;
        *) echo "无效选择。"; return 1 ;;
    esac
    echo "1) 全部 IP  2) 住宅/移动  3) 机房"
    read -r -p "IP 类型 [默认1]: " ip_choice
    case "${ip_choice:-1}" in 2) ip_type="residential" ;; 3) ip_type="hosting" ;; *) ip_type="all" ;; esac
    temporary=$(mktemp)
    jq --arg mode "$mode" --arg country "${country:-}" --arg ip_type "$ip_type" --arg fixed_id "${fixed_id:-}" '
        .routing_mode = $mode |
        .force_country = $country |
        .routing_ip_type = $ip_type |
        .fixed_node_id = (if $mode == "fixed_ip" then $fixed_id else .fixed_node_id end) |
        .fav_fail_fallback = false
    ' "$AUTH_FILE" > "$temporary"
    install -m 600 "$temporary" "$AUTH_FILE"
    rm -f "$temporary"
    service_action restart
    echo "路由配置已保存并重启服务。"
}

update_service() {
    git -C "$INSTALL_DIR" pull --ff-only
    (cd "$INSTALL_DIR" && go build -trimpath -ldflags="-s -w" -o gatepilot.new .)
    install -m 755 "$INSTALL_DIR/gatepilot.new" "$INSTALL_DIR/gatepilot"
    rm -f "$INSTALL_DIR/gatepilot.new"
    install -m 755 "$INSTALL_DIR/scripts/ml.sh" /usr/local/bin/ml
    service_action restart
    echo "更新完成。"
}

uninstall_service() {
    local confirm
    read -r -p "输入 DELETE 确认完全卸载 GatePilot: " confirm
    [ "$confirm" = "DELETE" ] || { echo "已取消。"; return; }
    service_action stop || true
    if command -v systemctl >/dev/null 2>&1; then
        systemctl disable "$SERVICE_NAME.service" || true
        rm -f "/etc/systemd/system/$SERVICE_NAME.service" "/lib/systemd/system/$SERVICE_NAME.service"
        systemctl daemon-reload
    else
        rc-update del "$SERVICE_NAME" default || true
        rm -f "/etc/init.d/$SERVICE_NAME"
    fi
    rm -f /usr/local/bin/ml /usr/bin/ml
    rm -rf "$INSTALL_DIR"
    echo "GatePilot 已卸载。"
}

interactive_menu() {
    while true; do
        clear
        show_status
        echo ""
        echo "1) 启动服务       2) 停止服务"
        echo "3) 重启服务       4) 查看日志"
        echo "5) 网页配置       6) 端口配置"
        echo "7) 账号密码       8) 路由配置"
        echo "9) 一键更新      10) 完全卸载"
        echo "0) 退出"
        read -r -p "请选择: " choice
        case "$choice" in
            1) service_action start ;; 2) service_action stop ;; 3) service_action restart ;;
            4) show_logs ;; 5) configure_web ;; 6) configure_ports ;;
            7) configure_credentials ;; 8) configure_routing ;; 9) update_service ;;
            10) uninstall_service; return ;; 0) return ;; *) echo "无效选择。" ;;
        esac
        read -r -p "按回车键继续..." _
    done
}

case "${1:-menu}" in
    menu) interactive_menu ;;
    info) show_info ;;
    status) show_status ;;
    logs) show_logs ;;
    start|stop|restart) service_action "$1" ;;
    update) update_service ;;
    web) configure_web ;;
    port) configure_ports ;;
    password) configure_credentials ;;
    routing) configure_routing ;;
    uninstall) uninstall_service ;;
    *) echo "用法: ml {info|status|logs|start|stop|restart|update|web|port|password|routing|uninstall}"; exit 1 ;;
esac
