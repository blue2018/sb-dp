#!/usr/bin/env bash
set -euo pipefail

# ==========================================
# 变量声明与环境准备
# ==========================================
SBOX_ARCH=""
OS_DISPLAY=""
SBOX_CORE="/etc/sing-box/core_script.sh"
SBOX_GOLIMIT="52MiB"
SBOX_MEM_MAX="55M"
SBOX_OPTIMIZE_LEVEL="未检测"
INSTALL_MODE=1
ARGO_TOKEN=""
ARGO_DOMAIN=""
ARGO_PORT=8001

# TLS 域名随机池
TLS_DOMAIN_POOL=("www.bing.com" "www.microsoft.com" "download.windowsupdate.com" "www.icloud.com" "gateway.icloud.com" "cdn.staticfile.org")
pick_tls_domain() { echo "${TLS_DOMAIN_POOL[$RANDOM % ${#TLS_DOMAIN_POOL[@]}]}"; }
TLS_DOMAIN="$(pick_tls_domain)"

# 彩色输出
info() { echo -e "\033[1;34m[INFO]\033[0m $*"; }
warn() { echo -e "\033[1;33m[WARN]\033[0m $*"; }
err()  { echo -e "\033[1;31m[ERR]\033[0m $*" >&2; }
succ() { echo -e "\033[1;32m[OK]\033[0m $*"; }

# ==========================================
# 系统检测与深度阶梯优化 (含 Alpine 专项)
# ==========================================
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_DISPLAY="${PRETTY_NAME:-$ID}"
        ID="${ID:-}"
        ID_LIKE="${ID_LIKE:-}"
    else
        OS_DISPLAY="Unknown Linux"
        ID="unknown"
    fi
    [[ "$ID $ID_LIKE" =~ "alpine" ]] && OS="alpine" || [[ "$ID $ID_LIKE" =~ "debian|ubuntu" ]] && OS="debian" || [[ "$ID $ID_LIKE" =~ "centos|rhel|fedora" ]] && OS="redhat" || OS="unknown"
    
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64) SBOX_ARCH="amd64" ;;
        aarch64) SBOX_ARCH="arm64" ;;
        *) err "不支持的架构: $ARCH"; exit 1 ;;
    esac
}

optimize_system() {
    # 1. 基础环境与内核模块准备
    info "正在进行系统深度优化适配..."
    if [ "$OS" = "alpine" ]; then
        # Alpine 手动加载必要内核模块
        modprobe tcp_bbr 2>/dev/null || true
        modprobe tun 2>/dev/null || true
    fi

    # 2. 内存探测与阶梯变量设置
    local mem_total=64
    local mem_free=$(free -m | awk '/Mem:/ {print $2}')
    # 兼容 Cgroup 限制（如容器环境）
    if [ -f /sys/fs/cgroup/memory.max ]; then
        local m_max=$(cat /sys/fs/cgroup/memory.max)
        [[ "$m_max" =~ ^[0-9]+$ ]] && mem_total=$((m_max / 1024 / 1024)) || mem_total=$mem_free
    else
        mem_total=$mem_free
    fi
    [ "$mem_total" -le 0 ] && mem_total=64

    # 根据内存总量设定优化阶梯
    local go_limit gogc udp_buffer mem_level
    if [ "$mem_total" -ge 450 ]; then
        go_limit="420MiB"; gogc="110"; udp_buffer="134217728"; mem_level="512M (爆发版)"
    elif [ "$mem_total" -ge 200 ]; then
        go_limit="210MiB"; gogc="100"; udp_buffer="67108864"; mem_level="256M (瞬时版)"
    elif [ "$mem_total" -ge 100 ]; then
        go_limit="100MiB"; gogc="80"; udp_buffer="33554432"; mem_level="128M (激进版)"
    else
        go_limit="52MiB"; gogc="70"; udp_buffer="16777216"; mem_level="64M (极限版)"
    fi

    SBOX_GOLIMIT="$go_limit"
    SBOX_GOGC="$gogc"
    SBOX_MEM_MAX="$((mem_total * 92 / 100))M"
    SBOX_OPTIMIZE_LEVEL="$mem_level"

    # 3. Swap (虚拟内存) 深度优化
    # 针对内存小于 512M 的小鸡，如果没有 Swap 则创建一个
    if [ "$mem_total" -lt 512 ] && [ "$(swapon --show)" == "" ]; then
        if [ ! -f /swapfile ]; then
            warn "内存较低且无 Swap，正在创建 256M 虚拟内存以防 OOM..."
            if command -v fallocate >/dev/null; then
                fallocate -l 256M /swapfile
            else
                dd if=/dev/zero of=/swapfile bs=1M count=256 2>/dev/null
            fi
            chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile
        fi
    fi

    # 4. 内核参数与网络栈调优
    cat > /etc/sysctl.conf <<SYSCTL
# TCP 拥塞控制与队列
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_fastopen = 3

# UDP 与缓存优化 (针对 Hysteria2)
net.core.rmem_max = $udp_buffer
net.core.wmem_max = $udp_buffer
net.ipv4.udp_mem = 131072 262144 524288

# 虚拟内存策略优化
# Alpine 用户磁盘通常 IO 较差，进一步调低 swappiness 以减少 IO 等待
vm.swappiness = $([ "$OS" = "alpine" ] && echo "5" || echo "10")
vm.vfs_cache_pressure = 50

# 增加系统最大文件句柄
fs.file-max = 1000000
SYSCTL

    sysctl -p >/dev/null 2>&1 || true

    # 5. BDP (带宽时延乘积) 初始窗口优化
    if command -v ip >/dev/null; then
        local dr=$(ip route show default | head -n1)
        if [[ $dr == *"via"* ]]; then
            # 增大初始拥塞窗口到 15，显著提升网页首屏加载速度
            ip route change $dr initcwnd 15 initrwnd 15 2>/dev/null || true
        fi
    fi
    
    succ "系统优化配置完成 (级别: $SBOX_OPTIMIZE_LEVEL)"
}

# ==========================================
# 安装与配置模块
# ==========================================
install_singbox() {
    local LATEST_TAG=$(curl -s https://api.github.com/repos/SagerNet/sing-box/releases/latest | jq -r .tag_name)
    local REMOTE_VER="${LATEST_TAG#v}"
    local URL="https://github.com/SagerNet/sing-box/releases/download/${LATEST_TAG}/sing-box-${REMOTE_VER}-linux-${SBOX_ARCH}.tar.gz"
    local TMP_D=$(mktemp -d)
    curl -fL "$URL" -o "$TMP_D/sb.tar.gz" && tar -xf "$TMP_D/sb.tar.gz" -C "$TMP_D"
    install -m 755 "$TMP_D"/sing-box-*/sing-box /usr/bin/sing-box
    rm -rf "$TMP_D"
}

install_cloudflared() {
    local cf_arch="amd64"; [[ "$SBOX_ARCH" == "arm64" ]] && cf_arch="arm64"
    curl -L "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-$cf_arch" -o /usr/bin/cloudflared
    chmod +x /usr/bin/cloudflared
}

create_config() {
    local PORT_HY2="${1:-$((RANDOM % 50000 + 10000))}"
    local PSK=$(cat /proc/sys/kernel/random/uuid 2>/dev/null || openssl rand -hex 16)
    local UUID=$(cat /proc/sys/kernel/random/uuid 2>/dev/null || openssl rand -hex 16)
    
    [ -f /etc/sing-box/config.json ] && {
        PSK=$(jq -r '.inbounds[] | select(.type=="hysteria2") | .users[0].password' /etc/sing-box/config.json 2>/dev/null || echo "$PSK")
        UUID=$(jq -r '.inbounds[] | select(.type=="vless") | .users[0].uuid' /etc/sing-box/config.json 2>/dev/null || echo "$UUID")
    }

    local hy2_in='{"type":"hysteria2","tag":"hy2-in","listen":"::","listen_port":'$PORT_HY2',"users":[{"password":"'$PSK'"}],"ignore_client_bandwidth":true,"tls":{"enabled":true,"alpn":["h3"],"certificate_path":"/etc/sing-box/certs/fullchain.pem","key_path":"/etc/sing-box/certs/privkey.pem"}}'
    local vless_in='{"type":"vless","tag":"vless-in","listen":"127.0.0.1","listen_port":'$ARGO_PORT',"users":[{"uuid":"'$UUID'"}],"transport":{"type":"grpc","service_name":"grpc-query"}}'

    local inbounds=""
    [ "$INSTALL_MODE" -eq 1 ] && inbounds="$hy2_in"
    [ "$INSTALL_MODE" -eq 2 ] && inbounds="$vless_in"
    [ "$INSTALL_MODE" -eq 3 ] && inbounds="$hy2_in, $vless_in"

    mkdir -p /etc/sing-box
    cat > /etc/sing-box/config.json <<EOF
{"log":{"level":"warn","timestamp":true},"inbounds":[$inbounds],"outbounds":[{"type":"direct","tag":"direct-out"}]}
EOF
}

# ==========================================
# 服务管理 (Systemd & OpenRC 双适配)
# ==========================================
setup_service() {
    if [ "$OS" = "alpine" ]; then
        # Sing-box OpenRC
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
depend() { need net; }
EOF
        chmod +x /etc/init.d/sing-box
        rc-update add sing-box default && rc-service sing-box restart
        
        # Cloudflared OpenRC
        if [[ "$INSTALL_MODE" =~ [23] ]]; then
            cat > /etc/init.d/cloudflared <<EOF
#!/sbin/openrc-run
description="Argo Tunnel"
export GOMEMLIMIT=32MiB
command="/usr/bin/cloudflared"
command_args="tunnel --no-autoupdate run --token $ARGO_TOKEN"
command_background="yes"
pidfile="/run/\${RC_SVCNAME}.pid"
EOF
            chmod +x /etc/init.d/cloudflared
            rc-update add cloudflared default && rc-service cloudflared restart
        fi
    else
        # Sing-box Systemd
        cat > /etc/systemd/system/sing-box.service <<EOF
[Unit]
Description=Sing-box Service
After=network.target
[Service]
Environment=GOGC=$SBOX_GOGC
Environment=GOMEMLIMIT=$SBOX_GOLIMIT
Environment=GODEBUG=madvdontneed=1
ExecStart=/usr/bin/sing-box run -c /etc/sing-box/config.json
Restart=on-failure
MemoryMax=$SBOX_MEM_MAX
[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload && systemctl enable sing-box --now
        
        # Cloudflared Systemd
        if [[ "$INSTALL_MODE" =~ [23] ]]; then
            cat > /etc/systemd/system/cloudflared.service <<EOF
[Unit]
Description=Argo Tunnel
After=network.target
[Service]
Environment=GOMEMLIMIT=32MiB
Environment=GODEBUG=madvdontneed=1
ExecStart=/usr/bin/cloudflared tunnel --no-autoupdate run --token $ARGO_TOKEN
Restart=on-failure
MemoryMax=60M
[Install]
WantedBy=multi-user.target
EOF
            systemctl daemon-reload && systemctl enable cloudflared --now
        fi
    fi
}

# ==========================================
# 信息展示模块 (完整保留你要求的格式)
# ==========================================
show_info() {
    local IP=$(curl -s --max-time 5 https://api.ipify.org || echo "YOUR_IP")
    local VER_INFO=$(/usr/bin/sing-box version | head -n1)
    local CONF="/etc/sing-box/config.json"
    [ ! -f "$CONF" ] && { err "配置不存在"; return; }

    echo -e "\n\033[1;34m==========================================\033[0m"
    echo -e "\033[1;37m        Sing-box 节点详细信息\033[0m"
    echo -e "\033[1;34m==========================================\033[0m"
    echo -e "系统版本: \033[1;33m$OS_DISPLAY\033[0m"
    echo -e "内核信息: \033[1;33m$VER_INFO\033[0m"
    echo -e "优化级别: \033[1;32m${SBOX_OPTIMIZE_LEVEL:-未检测}\033[0m"
    echo -e "公网地址: \033[1;33m$IP\033[0m"
    
    if jq -e '.inbounds[] | select(.type=="hysteria2")' "$CONF" >/dev/null 2>&1; then
        local P=$(jq -r '.inbounds[] | select(.type=="hysteria2") | .listen_port' "$CONF")
        local K=$(jq -r '.inbounds[] | select(.type=="hysteria2") | .users[0].password' "$CONF")
        local SNI=$(openssl x509 -in /etc/sing-box/certs/fullchain.pem -noout -subject -nameopt RFC2253 | sed 's/.*CN=\([^,]*\).*/\1/' 2>/dev/null || echo "$TLS_DOMAIN")
        local HY2_LINK="hy2://$K@$IP:$P/?sni=$SNI&alpn=h3&insecure=1#Hy2_$(hostname)"
        echo -e "运行端口: \033[1;33m$P\033[0m (Hy2)"
        echo -e "\033[1;34m------------------------------------------\033[0m"
        echo -e "\033[1;32m$HY2_LINK\033[0m"
        echo -ne "\033]52;c;$(echo -n "$HY2_LINK" | base64 | tr -d '\r\n')\a"
    fi

    if jq -e '.inbounds[] | select(.type=="vless")' "$CONF" >/dev/null 2>&1; then
        local U=$(jq -r '.inbounds[] | select(.type=="vless") | .users[0].uuid' "$CONF")
        echo -e "\n\033[1;33m[VLESS Argo gRPC 节点]\033[0m"
        echo -e "UUID: \033[1;33m$U\033[0m"
        echo -e "传输: grpc | ServiceName: grpc-query | TLS: 443"
    fi
    echo -e "\033[1;34m==========================================\033[0m\n"
}

# ==========================================
# 管理菜单 (sb)
# ==========================================
create_sb_tool() {
    local SB_PATH="/usr/local/bin/sb"
    cat > "$SB_PATH" <<'EOF'
#!/usr/bin/env bash
info() { echo -e "\033[1;34m[INFO]\033[0m $*"; }
service_ctrl() {
    if command -v systemctl >/dev/null; then systemctl $1 $2; else rc-service $2 $1; fi
}
while true; do
    echo -e "\n1) 查看链接  2) 重启服务  3) 重置端口  4) 卸载程序  0) 退出"
    read -p "选择: " opt
    case "$opt" in
        1) /etc/sing-box/core_script.sh --show-only ;;
        2) service_ctrl restart sing-box; service_ctrl restart cloudflared 2>/dev/null; info "已重启" ;;
        3) read -p "新Hy2端口: " np; /etc/sing-box/core_script.sh --reset-port "$np" ;;
        4) service_ctrl stop sing-box; service_ctrl stop cloudflared 2>/dev/null; rm -rf /etc/sing-box /usr/bin/sing-box /usr/bin/cloudflared /usr/local/bin/sb; exit 0 ;;
        0) exit 0 ;;
    esac
done
EOF
    chmod +x "$SB_PATH"
    cp "$0" /etc/sing-box/core_script.sh
    chmod +x /etc/sing-box/core_script.sh
}

# ==========================================
# 主逻辑入口
# ==========================================
detect_os

if [[ "${1:-}" == "--show-only" ]]; then
    show_info
elif [[ "${1:-}" == "--reset-port" ]]; then
    create_config "$2" && setup_service && show_info
else
    [ "$(id -u)" != "0" ] && err "请使用 root 运行" && exit 1
    echo -e "1) 仅 Hysteria2\n2) 仅 VLESS + Argo\n3) 双协议共存 (Hy2 / VLESS + Argo)"
    read -p "选择模式: " INSTALL_MODE
    [[ "$INSTALL_MODE" =~ [23] ]] && { read -p "Argo Token: " ARGO_TOKEN; read -p "Argo 域名: " ARGO_DOMAIN; }
    read -p "Hy2 端口 (回车随机): " USER_PORT
    
    [ "$OS" = "alpine" ] && apk add --no-cache bash curl jq openssl openrc iproute2 || { apt-get update && apt-get install -y curl jq openssl iproute2; }

    optimize_system
    install_singbox
    mkdir -p /etc/sing-box/certs
    openssl ecparam -genkey -name prime256v1 -out /etc/sing-box/certs/privkey.pem
    openssl req -new -x509 -days 3650 -key /etc/sing-box/certs/privkey.pem -out /etc/sing-box/certs/fullchain.pem -subj "/CN=$TLS_DOMAIN"
    
    [[ "$INSTALL_MODE" =~ [23] ]] && install_cloudflared
    create_config "${USER_PORT:-}"
    setup_service
    create_sb_tool
    show_info
    succ "安装完毕。输入 'sb' 管理。"
fi
