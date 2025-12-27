#!/usr/bin/env bash
set -euo pipefail

# ==========================================
# 变量初始化
# ==========================================
SBOX_ARCH=""
OS_TYPE=""
OS_DISPLAY=""
SBOX_OPTIMIZE_LEVEL="未检测"
INSTALL_MODE=1
ARGO_TOKEN=""
ARGO_DOMAIN=""
ARGO_PORT=8001
TLS_DOMAIN="www.microsoft.com"

# 彩色输出
info() { echo -e "\033[1;34m[INFO]\033[0m $*"; }
warn() { echo -e "\033[1;33m[WARN]\033[0m $*"; }
err()  { echo -e "\033[1;31m[ERR]\033[0m $*" >&2; }
succ() { echo -e "\033[1;32m[OK]\033[0m $*"; }

# ==========================================
# 1. 环境检测与依赖
# ==========================================
install_deps() {
    if [ -f /etc/os-release ]; then
        set +u
        . /etc/os-release
        set -u
        local _id="${ID:-}"
        local _id_like="${ID_LIKE:-}"
        OS_DISPLAY="${PRETTY_NAME:-$_id}"
        [[ "$_id" =~ "alpine" ]] || [[ "$_id_like" =~ "alpine" ]] && OS_TYPE="alpine" || OS_TYPE="debian"
    else
        OS_DISPLAY="Generic Linux"
        OS_TYPE="debian"
    fi

    info "系统检测: $OS_DISPLAY"
    if [ "$OS_TYPE" = "alpine" ]; then
        apk update && apk add --no-cache bash curl jq openssl openrc iproute2 iputils
    else
        [ -f /usr/bin/apt-get ] && (apt-get update && apt-get install -y curl jq openssl iproute2)
        [ -f /usr/bin/yum ] && yum install -y curl jq openssl iproute2
    fi

    case "$(uname -m)" in
        x86_64) SBOX_ARCH="amd64" ;;
        aarch64) SBOX_ARCH="arm64" ;;
        *) err "不支持的架构: $(uname -m)"; exit 1 ;;
    esac
}

# ==========================================
# 2. LXC 内存优化策略
# ==========================================
optimize_system() {
    info "正在执行虚化环境优化..."
    local mem_total=$(free -m | awk '/Mem:/ {print $2}')
    [ -z "$mem_total" ] && mem_total=128

    local go_limit="45MiB"; local gogc="50"
    if [ "$mem_total" -lt 150 ]; then
        go_limit="40MiB"; gogc="40"; SBOX_OPTIMIZE_LEVEL="LXC 极限版"
    else
        go_limit="90MiB"; gogc="65"; SBOX_OPTIMIZE_LEVEL="LXC 均衡版"
    fi

    export SBOX_GOLIMIT="$go_limit"; export SBOX_GOGC="$gogc"

    # Swap 尝试
    if ! free | grep -i "swap" | grep -qv "0" 2>/dev/null; then
        (dd if=/dev/zero of=/swapfile bs=1M count=256 2>/dev/null && \
         chmod 600 /swapfile && mkswap /swapfile && \
         swapon /swapfile 2>/dev/null) && info "Swap 激活" || warn "虚化环境禁止 Swap"
    fi

    # 内核参数 (静默)
    { echo "net.core.default_qdisc = fq"; echo "net.ipv4.tcp_congestion_control = bbr"; } > /tmp/sysctl_sbox.conf
    sysctl -p /tmp/sysctl_sbox.conf >/dev/null 2>&1 || true
}

# ==========================================
# 3. 安装与配置生成 (双协议支持)
# ==========================================
install_singbox() {
    local LATEST_TAG=$(curl -s https://api.github.com/repos/SagerNet/sing-box/releases/latest | jq -r .tag_name)
    local URL="https://github.com/SagerNet/sing-box/releases/download/${LATEST_TAG}/sing-box-${LATEST_TAG#v}-linux-${SBOX_ARCH}.tar.gz"
    local TMP_D=$(mktemp -d)
    curl -fL "$URL" -o "$TMP_D/sb.tar.gz" && tar -xf "$TMP_D/sb.tar.gz" -C "$TMP_D"
    install -m 755 "$TMP_D"/sing-box-*/sing-box /usr/bin/sing-box
    rm -rf "$TMP_D"
}

create_config() {
    local PORT_HY2="${1:-$((RANDOM % 50000 + 10000))}"
    local PSK_HY2=$(openssl rand -hex 12)
    local UUID_VLESS=$(cat /proc/sys/kernel/random/uuid 2>/dev/null || openssl rand -hex 16)
    
    mkdir -p /etc/sing-box/certs
    
    local hy2_in='{"type":"hysteria2","tag":"hy2-in","listen":"::","listen_port":'$PORT_HY2',"users":[{"password":"'$PSK_HY2'"}],"tls":{"enabled":true,"alpn":["h3"],"certificate_path":"/etc/sing-box/certs/fullchain.pem","key_path":"/etc/sing-box/certs/privkey.pem"}}'
    local vless_in='{"type":"vless","tag":"vless-in","listen":"127.0.0.1","listen_port":'$ARGO_PORT',"users":[{"uuid":"'$UUID_VLESS'"}],"transport":{"type":"grpc","service_name":"grpc-query"}}'

    local inbounds=""
    case $INSTALL_MODE in
        1) inbounds="$hy2_in" ;;
        2) inbounds="$vless_in" ;;
        3) inbounds="$hy2_in, $vless_in" ;;
    esac

    cat > /etc/sing-box/config.json <<EOF
{"log":{"level":"warn"},"inbounds":[$inbounds],"outbounds":[{"type":"direct"}]}
EOF
    openssl ecparam -genkey -name prime256v1 -out /etc/sing-box/certs/privkey.pem
    openssl req -new -x509 -days 3650 -key /etc/sing-box/certs/privkey.pem -out /etc/sing-box/certs/fullchain.pem -subj "/CN=$TLS_DOMAIN"
}

setup_service() {
    if [ "$OS_TYPE" = "alpine" ]; then
        cat > /etc/init.d/sing-box <<EOF
#!/sbin/openrc-run
description="Sing-box"
export GOGC=$SBOX_GOGC
export GOMEMLIMIT=$SBOX_GOLIMIT
export GODEBUG=madvdontneed=1
command="/usr/bin/sing-box"
command_args="run -c /etc/sing-box/config.json"
command_background="yes"
pidfile="/run/\${RC_SVCNAME}.pid"
depend() { after firewall; }
EOF
        chmod +x /etc/init.d/sing-box
        rc-update add sing-box default && rc-service sing-box restart
    else
        cat > /etc/systemd/system/sing-box.service <<EOF
[Unit]
Description=Sing-box
[Service]
Environment=GOGC=$SBOX_GOGC
Environment=GOMEMLIMIT=$SBOX_GOLIMIT
Environment=GODEBUG=madvdontneed=1
ExecStart=/usr/bin/sing-box run -c /etc/sing-box/config.json
Restart=on-failure
[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload && systemctl enable sing-box --now
    fi
}

# ==========================================
# 4. 管理工具 sb (支持双协议显示)
# ==========================================
create_sb_tool() {
    cat > /usr/local/bin/sb <<EOF
#!/usr/bin/env bash
service_op() { if command -v rc-service >/dev/null; then rc-service sing-box \$1; else systemctl \$1 sing-box; fi; }
show_info() {
    local IP=\$(curl -s --max-time 5 https://api.ipify.org || echo "YOUR_IP")
    local CONF="/etc/sing-box/config.json"
    echo -e "\n\033[1;34m================ 看板信息 ================\033[0m"
    echo -e "优化等级: $SBOX_OPTIMIZE_LEVEL"
    if [ -f "\$CONF" ]; then
        # Hy2 提取
        if jq -e '.inbounds[] | select(.type=="hysteria2")' "\$CONF" >/dev/null 2>&1; then
            local HP=\$(jq -r '.inbounds[] | select(.type=="hysteria2") | .listen_port' "\$CONF")
            local HK=\$(jq -r '.inbounds[] | select(.type=="hysteria2") | .users[0].password' "\$CONF")
            echo -e "Hy2 链接: \033[1;32mhy2://\$HK@\$IP:\$HP/?sni=$TLS_DOMAIN&alpn=h3&insecure=1#$OS_TYPE_Hy2\033[0m"
        fi
        # VLESS 提取
        if jq -e '.inbounds[] | select(.type=="vless")' "\$CONF" >/dev/null 2>&1; then
            local VU=\$(jq -r '.inbounds[] | select(.type=="vless") | .users[0].uuid' "\$CONF")
            echo -e "Argo 域名: \033[1;33m$ARGO_DOMAIN\033[0m"
            echo -e "VLESS 链接: \033[1;32mvless://\$VU@$ARGO_DOMAIN:443?encryption=none&security=tls&sni=$ARGO_DOMAIN&type=grpc&serviceName=grpc-query#$OS_TYPE_Argo\033[0m"
        fi
    fi
    echo -e "\033[1;34m==========================================\033[0m"
}

if [[ "\${1:-}" == "--info" ]]; then show_info; exit 0; fi
while true; do
    echo -e "\n1) 查看链接  2) 重启服务  3) 卸载节点  0) 退出"
    read -p "选择: " opt
    case "\$opt" in
        1) show_info ;;
        2) service_op restart && echo "已重启" ;;
        3) service_op stop; rm -rf /etc/sing-box /usr/bin/sing-box /usr/local/bin/sb; echo "已卸载"; exit 0 ;;
        0) exit 0 ;;
    esac
done
EOF
    chmod +x /usr/local/bin/sb
}

# ==========================================
# 5. 主流程
# ==========================================
[ "$(id -u)" != "0" ] && err "需 root 权限" && exit 1
install_deps

echo -e "1) 仅 Hysteria2\n2) 仅 VLESS + Argo\n3) 双协议共存"
read -p "选择模式: " INSTALL_MODE
if [[ "$INSTALL_MODE" =~ [23] ]]; then
    read -p "Argo Token: " ARGO_TOKEN
    read -p "Argo 域名: " ARGO_DOMAIN
fi
read -p "Hy2 端口 (回车随机): " USER_PORT

optimize_system
install_singbox
create_config "${USER_PORT:-}"
setup_service
create_sb_tool
succ "全量安装完成！"
/usr/local/bin/sb --info
