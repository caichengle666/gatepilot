#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TEST_DIR=$(mktemp -d)
trap 'rm -rf "$TEST_DIR"' EXIT

export GATEPILOT_INSTALL_DIR="$TEST_DIR"
mkdir -p "$TEST_DIR/data"
touch "$TEST_DIR/.docker_install"

source "$ROOT_DIR/scripts/ml.sh"

IPTABLES_LOG="$TEST_DIR/iptables.log"
jump_exists=0
chain_exists=0
legacy_web_rule=1
legacy_proxy_rule=1

iptables() {
    printf '%s\n' "$*" >> "$IPTABLES_LOG"
    case "$*" in
        "-C FORWARD -j GATEPILOT") [ "$jump_exists" = "1" ] ;;
        "-D FORWARD -j GATEPILOT") jump_exists=0 ;;
        "-nL GATEPILOT") [ "$chain_exists" = "1" ] ;;
        "-F GATEPILOT") ;;
        "-X GATEPILOT") chain_exists=0 ;;
        "-C FORWARD -p tcp --dport 8787 -j ACCEPT") [ "$legacy_web_rule" = "1" ] ;;
        "-D FORWARD -p tcp --dport 8787 -j ACCEPT") legacy_web_rule=0 ;;
        "-C FORWARD -p tcp --dport 17928 -j ACCEPT") [ "$legacy_proxy_rule" = "1" ] ;;
        "-D FORWARD -p tcp --dport 17928 -j ACCEPT") legacy_proxy_rule=0 ;;
        "-L FORWARD -n --line-numbers") printf '8 REJECT all -- 0.0.0.0/0 0.0.0.0/0\n' ;;
        "-N GATEPILOT") chain_exists=1 ;;
        "-I FORWARD 8 -j GATEPILOT") jump_exists=1 ;;
    esac
}

netfilter-persistent() {
    printf 'persist %s\n' "$*" >> "$IPTABLES_LOG"
}

assert_logged() {
    grep -F -- "$1" "$IPTABLES_LOG" >/dev/null || {
        echo "缺少 iptables 调用: $1"
        return 1
    }
}

cat > "$TEST_DIR/.env" <<'EOF'
GATEPILOT_UI_BIND=0.0.0.0
GATEPILOT_UI_PORT=8787
GATEPILOT_PROXY_BIND=0.0.0.0
GATEPILOT_PROXY_PORT=17928
GATEPILOT_TUNNEL_PROXY_PORT_START=17929
GATEPILOT_TUNNEL_PROXY_PORT_END=17936
EOF
configure_docker_firewall
assert_logged "-D FORWARD -p tcp --dport 8787 -j ACCEPT"
assert_logged "-D FORWARD -p tcp --dport 17928 -j ACCEPT"
assert_logged "-A GATEPILOT -p tcp --dport 8787 -j ACCEPT"
assert_logged "-A GATEPILOT -p tcp --dport 17928 -j ACCEPT"
assert_logged "-A GATEPILOT -p tcp --dport 17929:17936 -j ACCEPT"
[ -f "$TEST_DIR/data/.firewall_chain_migrated" ]

: > "$IPTABLES_LOG"
cat > "$TEST_DIR/.env" <<'EOF'
GATEPILOT_UI_BIND=0.0.0.0
GATEPILOT_UI_PORT=9999
GATEPILOT_PROXY_BIND=127.0.0.1
GATEPILOT_PROXY_PORT=7928
EOF
configure_docker_firewall
assert_logged "-F GATEPILOT"
assert_logged "-X GATEPILOT"
assert_logged "-A GATEPILOT -p tcp --dport 9999 -j ACCEPT"
if grep -F -- "-A GATEPILOT -p tcp --dport 8787 -j ACCEPT" "$IPTABLES_LOG" >/dev/null; then
    echo "端口更新后仍添加旧 Web 端口"
    exit 1
fi
if grep -F -- "-A GATEPILOT -p tcp --dport 7929:7936 -j ACCEPT" "$IPTABLES_LOG" >/dev/null; then
    echo "仅本机发布代理时不应放行附加隧道端口"
    exit 1
fi

: > "$IPTABLES_LOG"
cat > "$TEST_DIR/.env" <<'EOF'
GATEPILOT_UI_BIND=127.0.0.1
GATEPILOT_UI_PORT=9999
GATEPILOT_PROXY_BIND=127.0.0.1
GATEPILOT_PROXY_PORT=7928
EOF
configure_docker_firewall
assert_logged "-D FORWARD -j GATEPILOT"
assert_logged "-X GATEPILOT"
if grep -F -- "-A GATEPILOT" "$IPTABLES_LOG" >/dev/null; then
    echo "仅本机发布时不应添加放行规则"
    exit 1
fi

for function_name in persist_firewall_rules remove_gatepilot_firewall configure_docker_firewall; do
    diff \
        <(sed -n "/^${function_name}()/,/^}/p" "$ROOT_DIR/install.sh") \
        <(sed -n "/^${function_name}()/,/^}/p" "$ROOT_DIR/scripts/ml.sh")
done

if grep -E '^[[:space:]]+read ' "$ROOT_DIR/install.sh" | grep -Fv 'read "$@" <&"$PROMPT_FD"' >/dev/null; then
    echo "install.sh 仍有绕过 read_prompt 的交互输入"
    exit 1
fi
grep -F 'exec 3</dev/tty' "$ROOT_DIR/install.sh" >/dev/null
grep -F 'read "$@" <&"$PROMPT_FD"' "$ROOT_DIR/install.sh" >/dev/null
grep -F 'ensure_docker_tun()' "$ROOT_DIR/install.sh" >/dev/null
grep -F 'compose config -q' "$ROOT_DIR/install.sh" >/dev/null
grep -F 'wait_for_container_health' "$ROOT_DIR/install.sh" >/dev/null
grep -F 'valid_tunnel_proxy_port' "$ROOT_DIR/install.sh" >/dev/null
eval "$(sed -n '/^read_prompt()/,/^}/p' "$ROOT_DIR/install.sh")"
eval "$(sed -n '/^valid_port()/,/^}/p' "$ROOT_DIR/install.sh")"
eval "$(sed -n '/^valid_tunnel_proxy_port()/,/^}/p' "$ROOT_DIR/install.sh")"
exec 3<<<"docker"
PROMPT_FD=3
read_prompt -r prompt_value
[ "$prompt_value" = "docker" ]
valid_tunnel_proxy_port 65527
if valid_tunnel_proxy_port 65528; then
    echo "附加隧道代理端口上限校验失效"
    exit 1
fi

UPDATE_LOG="$TEST_DIR/update.log"
git() {
    printf 'git %s\n' "$*" >> "$UPDATE_LOG"
}
install() {
    printf 'install %s\n' "$*" >> "$UPDATE_LOG"
}
compose() {
    printf 'compose image=%s %s\n' "${GATEPILOT_IMAGE:-default}" "$*" >> "$UPDATE_LOG"
    if [ "${MOCK_COMPOSE_FAIL:-0}" = "1" ] && [ "${GATEPILOT_IMAGE:-default}" = "default" ] && [ "$1" = "up" ]; then
        return 1
    fi
}
configure_docker_firewall() {
    printf 'firewall sync\n' >> "$UPDATE_LOG"
}
MOCK_HEALTH="healthy"
docker() {
    printf 'docker %s\n' "$*" >> "$UPDATE_LOG"
    case "$*" in
        "inspect -f {{.Image}} gatepilot") printf 'sha256:old\n' ;;
        "inspect -f {{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}} gatepilot") printf '%s\n' "$MOCK_HEALTH" ;;
        "inspect -f {{.State.Status}} gatepilot") printf 'running\n' ;;
        "inspect -f {{.State.Running}} gatepilot") printf 'true\n' ;;
        "cp gatepilot:"*) printf 'geo-data\n' > "${*: -1}" ;;
    esac
}

eval "$(sed -n '/^wait_for_container_health()/,/^}/p' "$ROOT_DIR/install.sh")"
export GATEPILOT_HEALTH_ATTEMPTS=1
export GATEPILOT_HEALTH_INTERVAL=0
wait_for_container_health
MOCK_HEALTH="unhealthy"
if wait_for_container_health; then
    echo "不健康容器不应通过安装阶段健康检查"
    exit 1
fi
MOCK_HEALTH="healthy"

update_scripts
grep -F "git -C $TEST_DIR pull --ff-only" "$UPDATE_LOG" >/dev/null
grep -F "install -m 755 $TEST_DIR/scripts/ml.sh /usr/local/bin/ml" "$UPDATE_LOG" >/dev/null
if grep -F 'compose ' "$UPDATE_LOG" >/dev/null; then
    echo "单独更新管理脚本时不应操作容器"
    exit 1
fi

: > "$UPDATE_LOG"
DOCKER_MODE=1
export GATEPILOT_HEALTH_ATTEMPTS=1
export GATEPILOT_HEALTH_INTERVAL=0
export GATEPILOT_ROLLBACK_DELAY=0
update_image
grep -F 'compose image=default pull gatepilot' "$UPDATE_LOG" >/dev/null
grep -F 'compose image=default up -d --remove-orphans --force-recreate gatepilot' "$UPDATE_LOG" >/dev/null
grep -F 'firewall sync' "$UPDATE_LOG" >/dev/null
[ -s "$TEST_DIR/data/geoip.dat" ]
[ -s "$TEST_DIR/data/geosite.dat" ]

: > "$UPDATE_LOG"
MOCK_HEALTH="unhealthy"
if update_image; then
    echo "不健康的新镜像不应报告更新成功"
    exit 1
fi
grep -F 'compose image=gatepilot-rollback:local up -d --remove-orphans --force-recreate gatepilot' "$UPDATE_LOG" >/dev/null
grep -F 'docker image rm gatepilot-rollback:local' "$UPDATE_LOG" >/dev/null

: > "$UPDATE_LOG"
MOCK_HEALTH="healthy"
export MOCK_COMPOSE_FAIL=1
if update_image; then
    echo "容器重建失败时不应报告更新成功"
    exit 1
fi
grep -F 'compose image=gatepilot-rollback:local up -d --remove-orphans --force-recreate gatepilot' "$UPDATE_LOG" >/dev/null
unset MOCK_COMPOSE_FAIL

bash -n "$ROOT_DIR/install.sh"
bash -n "$ROOT_DIR/scripts/ml.sh"
echo "Shell tests passed"
