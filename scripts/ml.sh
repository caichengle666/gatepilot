#!/usr/bin/env bash
set -u

ML_SOURCED=0
if [ "${BASH_SOURCE[0]}" != "$0" ]; then
    ML_SOURCED=1
fi

INSTALL_DIR="${GATEPILOT_INSTALL_DIR:-${AIMILIVPN_INSTALL_DIR:-/opt/gatepilot}}"
SERVICE_NAME="gatepilot"
DOCKER_MODE=0
if [ -f "$INSTALL_DIR/.docker_install" ]; then
    DOCKER_MODE=1
    AUTH_FILE="$INSTALL_DIR/data/ui_auth.json"
    STATE_FILE="$INSTALL_DIR/data/state.json"
else
    AUTH_FILE="$INSTALL_DIR/vpngate_data/ui_auth.json"
    STATE_FILE="$INSTALL_DIR/vpngate_data/state.json"
fi

if [ "$ML_SOURCED" != "1" ] && [ "$(id -u)" != "0" ]; then
    echo "错误: 必须使用 root 权限运行 ml。"
    exit 1
fi

compose() {
    if docker compose version >/dev/null 2>&1; then
        docker compose "$@"
    elif command -v docker-compose >/dev/null 2>&1; then
        docker-compose "$@"
    else
        echo "未检测到 Docker Compose。"
        return 127
    fi
}

compose_env_value() {
    local key="$1" fallback="$2" value=""
    if [ -f "$INSTALL_DIR/.env" ]; then
        value=$(sed -n "s/^${key}=//p" "$INSTALL_DIR/.env" | tail -n 1)
    fi
    echo "${value:-$fallback}"
}

set_compose_env_value() {
    local key="$1" value="$2" temporary
    temporary=$(mktemp)
    if [ -f "$INSTALL_DIR/.env" ]; then
        grep -v "^${key}=" "$INSTALL_DIR/.env" > "$temporary" || true
    fi
    printf '%s=%s\n' "$key" "$value" >> "$temporary"
    install -m 600 "$temporary" "$INSTALL_DIR/.env"
    rm -f "$temporary"
}

persist_firewall_rules() {
    if command -v netfilter-persistent >/dev/null 2>&1; then
        netfilter-persistent save >/dev/null 2>&1 || true
    elif [ -d /etc/iptables ] && command -v iptables-save >/dev/null 2>&1; then
        iptables-save > /etc/iptables/rules.v4
    fi
}

remove_gatepilot_firewall() {
    command -v iptables >/dev/null 2>&1 || return 0
    while iptables -C FORWARD -j GATEPILOT >/dev/null 2>&1; do
        iptables -D FORWARD -j GATEPILOT
    done
    if iptables -nL GATEPILOT >/dev/null 2>&1; then
        iptables -F GATEPILOT
        iptables -X GATEPILOT
    fi
}

configure_docker_firewall() {
    local web_bind web_port proxy_bind proxy_port tunnel_proxy_port_start tunnel_proxy_port_end reject_line migration_marker
    local -a public_ports=()
    command -v iptables >/dev/null 2>&1 || return 0
    web_bind=$(compose_env_value GATEPILOT_UI_BIND 0.0.0.0)
    web_port=$(compose_env_value GATEPILOT_UI_PORT 8787)
    proxy_bind=$(compose_env_value GATEPILOT_PROXY_BIND 127.0.0.1)
    proxy_port=$(compose_env_value GATEPILOT_PROXY_PORT 7928)
    tunnel_proxy_port_start=$(compose_env_value GATEPILOT_TUNNEL_PROXY_PORT_START 7929)
    tunnel_proxy_port_end=$(compose_env_value GATEPILOT_TUNNEL_PROXY_PORT_END 7936)
    migration_marker="$INSTALL_DIR/data/.firewall_chain_migrated"
    if [ ! -f "$migration_marker" ]; then
        while iptables -C FORWARD -p tcp --dport "$web_port" -j ACCEPT >/dev/null 2>&1; do
            iptables -D FORWARD -p tcp --dport "$web_port" -j ACCEPT
        done
        while iptables -C FORWARD -p tcp --dport "$proxy_port" -j ACCEPT >/dev/null 2>&1; do
            iptables -D FORWARD -p tcp --dport "$proxy_port" -j ACCEPT
        done
        mkdir -p "$(dirname "$migration_marker")"
        : > "$migration_marker"
    fi
    [ "$web_bind" = "127.0.0.1" ] || public_ports+=("$web_port")
    if [ "$proxy_bind" != "127.0.0.1" ]; then
        public_ports+=("$proxy_port" "${tunnel_proxy_port_start}:${tunnel_proxy_port_end}")
    fi
    remove_gatepilot_firewall
    if [ "${#public_ports[@]}" -eq 0 ]; then
        persist_firewall_rules
        return 0
    fi
    reject_line=$(iptables -L FORWARD -n --line-numbers 2>/dev/null | awk '$2 == "REJECT" { print $1; exit }')
    if [ -z "$reject_line" ]; then
        persist_firewall_rules
        return 0
    fi
    iptables -N GATEPILOT
    for port in "${public_ports[@]}"; do
        iptables -A GATEPILOT -p tcp --dport "$port" -j ACCEPT
    done
    iptables -I FORWARD "$reject_line" -j GATEPILOT
    persist_firewall_rules
}

service_action() {
    if [ "$DOCKER_MODE" = "1" ]; then
        case "$1" in
            start) (cd "$INSTALL_DIR" && compose up -d); configure_docker_firewall ;;
            stop) (cd "$INSTALL_DIR" && compose stop) ;;
            restart) (cd "$INSTALL_DIR" && compose up -d --force-recreate); configure_docker_firewall ;;
        esac
        return
    fi
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
    if [ "$DOCKER_MODE" = "1" ]; then
        [ "$(docker inspect -f '{{.State.Running}}' "$SERVICE_NAME" 2>/dev/null)" = "true" ]
        return
    fi
    if command -v systemctl >/dev/null 2>&1; then
        systemctl is-active --quiet "$SERVICE_NAME.service"
    else
        rc-service "$SERVICE_NAME" status >/dev/null 2>&1
    fi
}

service_pid() {
    if [ "$DOCKER_MODE" = "1" ]; then
        docker inspect -f '{{.State.Pid}}' "$SERVICE_NAME" 2>/dev/null
        return
    fi
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
    local host port secret proxy_bind proxy_port username password display_host proxy_display_host
    if [ "$DOCKER_MODE" = "1" ]; then
        host=$(compose_env_value GATEPILOT_UI_BIND 0.0.0.0)
        port=$(compose_env_value GATEPILOT_UI_PORT 8787)
        proxy_bind=$(compose_env_value GATEPILOT_PROXY_BIND 127.0.0.1)
        proxy_port=$(compose_env_value GATEPILOT_PROXY_PORT 7928)
    else
        host=$(json_value host)
        port=$(json_value port)
        proxy_bind="127.0.0.1"
        proxy_port=$(json_value proxy_port)
    fi
    secret=$(json_value secret_path)
    username=$(json_value username)
    password=$(json_value password)
    case "$host" in
        "::"|"0.0.0.0"|"") display_host=$(public_ip) ;;
        "::1") display_host="[::1]" ;;
        *)
            if [[ "$host" == *:* ]]; then display_host="[$host]"; else display_host="$host"; fi
            ;;
    esac
    case "$proxy_bind" in
        "::"|"0.0.0.0"|"") proxy_display_host=$(public_ip) ;;
        "::1") proxy_display_host="[::1]" ;;
        *) proxy_display_host="$proxy_bind" ;;
    esac
    echo "======================================================="
    echo "GatePilot 管理信息"
    echo "======================================================="
    echo "网页登录地址: http://${display_host}:${port}/${secret}/"
    echo "登录用户名:   ${username}"
    echo "登录密码:     ${password}"
    echo "HTTP/SOCKS5:  ${proxy_display_host}:${proxy_port}"
}

show_status() {
    local service_status proxy_status vpn_status pid active latency message proxy_port
    if [ "$DOCKER_MODE" = "1" ]; then
        proxy_port=$(compose_env_value GATEPILOT_PROXY_PORT 7928)
    else
        proxy_port=$(json_value proxy_port)
    fi
    if service_active; then service_status="已启动"; else service_status="未启动"; fi
    if ss -ltnH 2>/dev/null | awk '{print $4}' | grep -Eq "(^|:)$proxy_port$"; then proxy_status="已监听"; else proxy_status="未监听"; fi
    if [ "$DOCKER_MODE" = "1" ]; then
        if docker exec "$SERVICE_NAME" pgrep -f '[o]penvpn.*tun0' >/dev/null 2>&1; then vpn_status="已连接"; else vpn_status="未连接"; fi
    elif pgrep -f '[o]penvpn.*tun0' >/dev/null 2>&1; then
        vpn_status="已连接"
    else
        vpn_status="未连接"
    fi
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
    if [ "$DOCKER_MODE" = "1" ]; then
        (cd "$INSTALL_DIR" && compose logs -f --tail=100 "$SERVICE_NAME")
        return
    fi
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
    local current_web_port current_proxy_port web_port proxy_port
    require_config
    if [ "$DOCKER_MODE" = "1" ]; then
        current_web_port=$(compose_env_value GATEPILOT_UI_PORT 8787)
        current_proxy_port=$(compose_env_value GATEPILOT_PROXY_PORT 7928)
    else
        current_web_port=$(json_value port)
        current_proxy_port=$(json_value proxy_port)
    fi
    read -r -p "网页管理端口 [${current_web_port}]: " web_port
    read -r -p "代理出站端口 [${current_proxy_port}]: " proxy_port
    web_port=${web_port:-$current_web_port}
    proxy_port=${proxy_port:-$current_proxy_port}
    if ! valid_port "$web_port" || ! valid_port "$proxy_port" || [ "$proxy_port" -lt 1024 ]; then
        echo "端口无效；代理端口范围必须是 1024-65535。"
        return 1
    fi
    if [ "$web_port" = "$proxy_port" ]; then
        echo "网页端口不能与代理端口相同。"
        return 1
    fi
    if [ "$DOCKER_MODE" = "1" ]; then
        set_compose_env_value GATEPILOT_UI_PORT "$web_port"
        set_compose_env_value GATEPILOT_PROXY_PORT "$proxy_port"
        set_compose_env_value GATEPILOT_TUNNEL_PROXY_PORT_START "$((proxy_port + 1))"
        set_compose_env_value GATEPILOT_TUNNEL_PROXY_PORT_END "$((proxy_port + 8))"
    else
        set_json_number port "$web_port"
        set_json_number proxy_port "$proxy_port"
    fi
    service_action restart
    echo "端口已保存并重启服务。"
}

random_suffix() {
    LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 12
}

configure_web() {
    local choice host suffix
    require_config
    if [ "$DOCKER_MODE" = "1" ]; then
        echo "1) 仅本机访问 (127.0.0.1)"
        echo "2) 公网 IPv4 (0.0.0.0)"
        read -r -p "Web 发布范围 [1-2，默认2]: " choice
        case "${choice:-2}" in 1) host="127.0.0.1" ;; *) host="0.0.0.0" ;; esac
    else
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
    fi
    read -r -p "安全路径 [回车保留，输入 random 随机生成]: " suffix
    if [ "$suffix" = "random" ]; then suffix=$(random_suffix); fi
    if [ -n "$suffix" ] && [[ ! "$suffix" =~ ^[A-Za-z0-9]+$ ]]; then
        echo "安全路径只能包含英文字母和数字。"
        return 1
    fi
    if [ "$DOCKER_MODE" = "1" ]; then
        set_compose_env_value GATEPILOT_UI_BIND "$host"
        set_json_string host "0.0.0.0"
    else
        set_json_string host "$host"
    fi
    if [ -n "$suffix" ]; then set_json_string secret_path "$suffix"; fi
    service_action restart
    show_info
}

configure_proxy() {
    local choice bind enabled username password new_username new_password confirm temporary
    require_config
    if [ "$DOCKER_MODE" != "1" ]; then
        echo "原生模式请在 Web 网络设置中配置代理监听和认证。"
        return 1
    fi
    echo "1) 仅本机使用 (127.0.0.1)"
    echo "2) 公网使用 (0.0.0.0，强制启用认证)"
    read -r -p "代理发布范围 [1-2，默认1]: " choice
    case "${choice:-1}" in
        2) bind="0.0.0.0"; enabled=true ;;
        *) bind="127.0.0.1"; enabled=false ;;
    esac
    username=$(json_value proxy_username)
    password=$(json_value proxy_password)
    if [ "$enabled" = "true" ]; then
        read -r -p "代理用户名 [${username}]: " new_username
        username=${new_username:-$username}
        [ -n "$username" ] || { echo "公网代理用户名不能为空。"; return 1; }
        read -r -s -p "代理密码 [回车保留当前密码]: " new_password
        echo
        if [ -n "$new_password" ]; then
            read -r -s -p "再次输入代理密码: " confirm
            echo
            [ "$new_password" = "$confirm" ] || { echo "两次密码不一致。"; return 1; }
            password="$new_password"
        fi
        [ -n "$password" ] || { echo "公网代理密码不能为空。"; return 1; }
    fi
    temporary=$(mktemp)
    jq --arg username "$username" --arg password "$password" --argjson enabled "$enabled" '
        .proxy_auth_enabled = $enabled |
        .proxy_username = $username |
        .proxy_password = $password
    ' "$AUTH_FILE" > "$temporary"
    install -m 600 "$temporary" "$AUTH_FILE"
    rm -f "$temporary"
    set_compose_env_value GATEPILOT_PROXY_BIND "$bind"
    service_action restart
    echo "代理发布和认证配置已保存并重建容器。"
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

update_scripts() {
    git -C "$INSTALL_DIR" pull --ff-only
    install -m 755 "$INSTALL_DIR/scripts/ml.sh" /usr/local/bin/ml
    echo "管理脚本已从 GitHub 更新。"
}

persist_container_geo_files() {
    local kind target
    for kind in geoip geosite; do
        target="$INSTALL_DIR/data/${kind}.dat"
        if [ ! -s "$target" ]; then
            docker cp "$SERVICE_NAME:/usr/local/bin/${kind}.dat" "$target" >/dev/null 2>&1 || true
        fi
    done
}

wait_for_container_health() {
    local attempt health status
    for ((attempt = 1; attempt <= ${GATEPILOT_HEALTH_ATTEMPTS:-24}; attempt++)); do
        health=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$SERVICE_NAME" 2>/dev/null || true)
        status=$(docker inspect -f '{{.State.Status}}' "$SERVICE_NAME" 2>/dev/null || true)
        [ "$health" = "healthy" ] && return 0
        case "$status" in
            exited|dead|restarting) return 1 ;;
        esac
        sleep "${GATEPILOT_HEALTH_INTERVAL:-5}"
    done
    return 1
}

restore_previous_image() {
    local rollback_image="$1"
    (cd "$INSTALL_DIR" && GATEPILOT_IMAGE="$rollback_image" compose up -d --remove-orphans --force-recreate gatepilot) || return 1
    sleep "${GATEPILOT_ROLLBACK_DELAY:-5}"
    [ "$(docker inspect -f '{{.State.Running}}' "$SERVICE_NAME" 2>/dev/null)" = "true" ]
}

update_image() {
    local old_image rollback_image="gatepilot-rollback:local"
    if [ "$DOCKER_MODE" != "1" ]; then
        echo "镜像更新仅适用于 Docker 安装模式。"
        return 1
    fi
    old_image=$(docker inspect -f '{{.Image}}' "$SERVICE_NAME" 2>/dev/null || true)
    if [ -n "$old_image" ]; then
        docker image rm "$rollback_image" >/dev/null 2>&1 || true
        docker tag "$old_image" "$rollback_image"
    fi
    persist_container_geo_files
    if ! (cd "$INSTALL_DIR" && compose pull gatepilot && compose up -d --remove-orphans --force-recreate gatepilot); then
        echo "镜像拉取或容器重建失败，正在恢复更新前镜像。"
        if [ -n "$old_image" ] && restore_previous_image "$rollback_image"; then
            echo "已恢复更新前镜像。"
        fi
        docker image rm "$rollback_image" >/dev/null 2>&1 || true
        return 1
    fi
    configure_docker_firewall
    if ! wait_for_container_health; then
        echo "新镜像健康检查失败，正在恢复更新前镜像。"
        docker logs --tail 80 "$SERVICE_NAME" 2>&1 || true
        if [ -n "$old_image" ]; then
            if restore_previous_image "$rollback_image"; then
                echo "已恢复更新前镜像。"
            else
                echo "旧镜像恢复失败，请运行 docker logs gatepilot 检查。"
            fi
        fi
        docker image rm "$rollback_image" >/dev/null 2>&1 || true
        return 1
    fi
    docker image rm "$rollback_image" >/dev/null 2>&1 || true
    echo "Docker 镜像已拉取并重建容器。"
}

update_service() {
    update_scripts
    if [ "$DOCKER_MODE" = "1" ]; then
        update_image
    else
        (cd "$INSTALL_DIR" && go build -trimpath -ldflags="-s -w" -o gatepilot.new .)
        install -m 755 "$INSTALL_DIR/gatepilot.new" "$INSTALL_DIR/gatepilot"
        rm -f "$INSTALL_DIR/gatepilot.new"
        service_action restart
    fi
    echo "更新完成。"
}

uninstall_service() {
    local confirm
    read -r -p "输入 DELETE 确认完全卸载 GatePilot: " confirm
    [ "$confirm" = "DELETE" ] || { echo "已取消。"; return; }
    case "$INSTALL_DIR" in
        ""|/|/opt|/usr|/var|/home) echo "拒绝删除危险安装目录: $INSTALL_DIR"; return 1 ;;
    esac
    service_action stop || true
    if [ "$DOCKER_MODE" = "1" ]; then
        (cd "$INSTALL_DIR" && compose down --remove-orphans) || true
        remove_gatepilot_firewall
        persist_firewall_rules
    elif command -v systemctl >/dev/null 2>&1; then
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
        echo "9) 代理发布      10) 更新管理脚本"
        echo "11) 更新 Docker 镜像"
        echo "12) 完整更新     13) 完全卸载"
        echo "0) 退出"
        read -r -p "请选择: " choice
        case "$choice" in
            1) service_action start ;; 2) service_action stop ;; 3) service_action restart ;;
            4) show_logs ;; 5) configure_web ;; 6) configure_ports ;;
            7) configure_credentials ;; 8) configure_routing ;; 9) configure_proxy ;;
            10) update_scripts ;; 11) update_image ;; 12) update_service ;;
            13) uninstall_service; return ;;
            0) return ;; *) echo "无效选择。" ;;
        esac
        read -r -p "按回车键继续..." _
    done
}

if [ "$ML_SOURCED" = "1" ]; then
    return 0
fi

case "${1:-menu}" in
    menu) interactive_menu ;;
    info) show_info ;;
    status) show_status ;;
    logs) show_logs ;;
    start|stop|restart) service_action "$1" ;;
    update) update_service ;;
    update-script) update_scripts ;;
    update-image) update_image ;;
    web) configure_web ;;
    port) configure_ports ;;
    password) configure_credentials ;;
    routing) configure_routing ;;
    proxy) configure_proxy ;;
    uninstall) uninstall_service ;;
    *) echo "用法: ml {info|status|logs|start|stop|restart|update|update-script|update-image|web|port|password|routing|proxy|uninstall}"; exit 1 ;;
esac
