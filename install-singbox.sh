#!/usr/bin/env bash
set -euo pipefail

# 变量声明与环境准备
SBOX_ARCH=""
OS_DISPLAY=""
SBOX_CORE="/etc/sing-box/core_script.sh"
# 优化变量容器 (将在 optimize_system 中填充)
VAR_GOLIMIT=""
VAR_GOGC=""
VAR_UDP_RMEM=""
VAR_UDP_WMEM=""
VAR_UDP_MEM_LIMIT=""
VAR_SYSTEMD_NICE=""
VAR_SYSTEMD_IOSCHED=""
VAR_OPTIMIZE_DESC=""

# TLS 域名随机池
TLS_DOMAIN_POOL=(
  "www.bing.com"
  "www.microsoft.com"
  "download.windowsupdate.com"
  "www.icloud.com"
  "gateway.icloud.com"
  "cdn.staticfile.org"
)
pick_tls_domain() { echo "${TLS_DOMAIN_POOL[$RANDOM % ${#TLS_DOMAIN_POOL[@]}]}"; }
TLS_DOMAIN="$(pick_tls_domain)"

# 彩色输出与工具函数
info() { echo -e "\033[1;34m[INFO]\033[0m $*"; }
warn() { echo -e "\033[1;33m[WARN]\033[0m $*"; }
err()  { echo -e "\033[1;31m[ERR]\033[0m $*" >&2; }
succ() { echo -e "\033[1;32m[OK]\033[0m $*"; }

copy_to_clipboard() {
    local content="$1"
    if [ -n "${SSH_TTY:-}" ] || [ -n "${DISPLAY:-}" ]; then
        local b64_content=$(printf "%b" "$content" | base64 | tr -d '\r\n')
        echo -ne "\033]52;c;${b64_content}\a"
        echo -e "\033[1;32m[复制]\033[0m 节点链接已自动推送到本地剪贴板"
    fi
}

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
    if echo "$ID $ID_LIKE" | grep -qi "alpine"; then OS="alpine";
    elif echo "$ID $ID_LIKE" | grep -Ei "debian|ubuntu" >/dev/null; then OS="debian";
    elif echo "$ID $ID_LIKE" | grep -Ei "centos|rhel|fedora" >/dev/null; then OS="redhat";
    else OS="unknown"; fi

    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64)    SBOX_ARCH="amd64" ;;
        aarch64)   SBOX_ARCH="arm64" ;;
        armv7l)    SBOX_ARCH="armv7" ;;
        i386|i686) SBOX_ARCH="386" ;;
        *) err "不支持的架构: $ARCH"; exit 1 ;;
    esac
}

# --- 核心优化逻辑 (整合了你的5点建议) ---
optimize_system() {
    # 1. 精准内存探测
    local mem_total=64
    local mem_cgroup=0
    local mem_free=$(free -m | awk '/Mem:/ {print $2}')
    
    if [ -f /sys/fs/cgroup/memory/memory.limit_in_bytes ]; then
        mem_cgroup=$(($(cat /sys/fs/cgroup/memory/memory.limit_in_bytes) / 1024 / 1024))
    elif [ -f /sys/fs/cgroup/memory.max ]; then
        local m_max=$(cat /sys/fs/cgroup/memory.max)
        [[ "$m_max" =~ ^[0-9]+$ ]] && mem_cgroup=$((m_max / 1024 / 1024))
    fi
    if [ "$mem_cgroup" -gt 0 ] && [ "$mem_cgroup" -le "$mem_free" ]; then mem_total=$mem_cgroup; else mem_total=$mem_free; fi
    if [ "$mem_total" -le 0 ] || [ "$mem_total" -gt 64000 ]; then mem_total=64; fi
    
    info "检测到可用内存: ${mem_total} MB"

    # 2. 差异化参数计算 (针对 64M/128M/256M/512M)
    # 这里的 buffer 计算采用 page 为单位 (1 page = 4096 bytes)，用于 sysctl 的 udp_mem
    
    if [ "$mem_total" -ge 450 ]; then
        # === 512M 档位 (爆发响应激进版) ===
        VAR_OPTIMIZE_DESC="512M (旗舰版)"
        VAR_GOLIMIT="400MiB"
        VAR_GOGC="120"          # 减少 GC 频率，牺牲内存换 CPU 性能
        VAR_UDP_RMEM="33554432" # 32MB 单连接最大接收缓冲
        VAR_UDP_WMEM="33554432" # 32MB 单连接最大发送缓冲
        # udp_mem: min pressure max (单位 pages)
        # 262144 pages * 4KB ≈ 1GB (允许系统分配巨大的 UDP 总池)
        VAR_UDP_MEM_LIMIT="81920 163840 262144" 
        VAR_SYSTEMD_NICE="-15"  # 极高优先级
        VAR_SYSTEMD_IOSCHED="realtime" # IO 实时调度

    elif [ "$mem_total" -ge 200 ]; then
        # === 256M 档位 (均衡性能版) ===
        VAR_OPTIMIZE_DESC="256M (性能版)"
        VAR_GOLIMIT="200MiB"
        VAR_GOGC="100"
        VAR_UDP_RMEM="16777216" # 16MB
        VAR_UDP_WMEM="16777216"
        VAR_UDP_MEM_LIMIT="40960 81920 163840"
        VAR_SYSTEMD_NICE="-10"
        VAR_SYSTEMD_IOSCHED="best-effort"

    elif [ "$mem_total" -ge 100 ]; then
        # === 128M 档位 (紧凑版) ===
        VAR_OPTIMIZE_DESC="128M (紧凑版)"
        VAR_GOLIMIT="96MiB"
        VAR_GOGC="70"           # 稍频繁 GC 防止 OOM
        VAR_UDP_RMEM="8388608"  # 8MB
        VAR_UDP_WMEM="8388608"
        VAR_UDP_MEM_LIMIT="20480 40960 81920"
        VAR_SYSTEMD_NICE="-5"
        VAR_SYSTEMD_IOSCHED="best-effort"

    else
        # === 64M 档位 (生存版) ===
        VAR_OPTIMIZE_DESC="64M (生存版)"
        VAR_GOLIMIT="48MiB"
        VAR_GOGC="50"           # 极其激进的 GC，内存优先
        VAR_UDP_RMEM="4194304"  # 4MB (对 300Mbps 勉强够用)
        VAR_UDP_WMEM="4194304"
        VAR_UDP_MEM_LIMIT="4096 8192 16384" # 限制 UDP 总占用防止系统崩溃
        VAR_SYSTEMD_NICE="-2"   # 稍高优先级，避免被彻底饿死
        VAR_SYSTEMD_IOSCHED="best-effort"
    fi

    info "应用优化: $VAR_OPTIMIZE_DESC | 缓冲上限: $((VAR_UDP_RMEM/1024/1024))MB | GoGC: $VAR_GOGC"

    # 3. Swap 智能处理
    if [ "$OS" != "alpine" ]; then
        local swap_total=$(free -m | awk '/Swap:/ {print $2}')
        if [ "$mem_total" -lt 150 ] && [ "$swap_total" -lt 10 ]; then
            warn "低内存环境，正在创建 128MB Swap 以防止 OOM..."
            fallocate -l 128M /swapfile 2>/dev/null || dd if=/dev/zero of=/swapfile bs=1M count=128 2>/dev/null
            chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile
            echo "/swapfile none swap sw 0 0" >> /etc/fstab
        fi
    fi

    # 4. 内核 Sysctl 深度调优 (包含你提到的 PMTUD 和 UDP 极限参数)
    modprobe tcp_bbr >/dev/null 2>&1 || true
    cat > /etc/sysctl.conf <<SYSCTL
# === 1. 拥塞控制与 BBR 优化 ===
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
# 避免 BBR 在低流量时过于保守
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_notsent_lowat = 16384

# === 2. 你的核心需求：防止 UDP 队列卡死 ===
# 允许巨大的网络设备积压队列，防止网卡收包过快导致丢包
net.core.netdev_max_backlog = 65536
net.core.somaxconn = 32768
# 允许更多的挂起连接
net.ipv4.tcp_max_syn_backlog = 32768

# === 3. 你的核心需求：UDP 极限内存参数 (基于内存等级) ===
# 所有的 UDP 缓冲区调优，让 sing-box 有足够的空间处理 burst 流量
net.core.rmem_max = $VAR_UDP_RMEM
net.core.wmem_max = $VAR_UDP_WMEM
net.core.rmem_default = 1048576
net.core.wmem_default = 1048576
# 自动调整 UDP 内存池 (min pressure max)
net.ipv4.udp_mem = $VAR_UDP_MEM_LIMIT
# 放宽 UDP 最小缓冲限制
net.ipv4.udp_rmem_min = 16384
net.ipv4.udp_wmem_min = 16384

# === 4. 你的核心需求：MTU 自动学习 (PMTUD) ===
# 开启 PMTU 发现，解决中间链路 MTU 较小导致的丢包
net.ipv4.ip_no_pmtu_disc = 0
# 可选：如果网络极差，可尝试设置为 1 (部分国内 NAT 环境可能需要)，但标准优化应为 0

# === 5. 通用优化 ===
net.ipv4.ip_forward = 1
net.ipv4.conf.all.route_localnet = 1
vm.swappiness = 10
SYSCTL
    sysctl -p >/dev/null 2>&1 || true

    # InitCWND 优化 (保持 15)
    if command -v ip >/dev/null; then
        local default_route=$(ip route show default | head -n1)
        if [[ $default_route == *"via"* ]]; then
            ip route change $default_route initcwnd 15 initrwnd 15 2>/dev/null || true
        fi
    fi
}

install_singbox() {
    local MODE="${1:-install}"
    local LOCAL_VER="未安装"
    [ -f /usr/bin/sing-box ] && LOCAL_VER=$(/usr/bin/sing-box version | head -n1 | awk '{print $3}')
    
    # 简化版：直接尝试下载最新
    local RELEASE_JSON=$(curl -sL --max-time 10 https://api.github.com/repos/SagerNet/sing-box/releases/latest 2>/dev/null)
    local LATEST_TAG=$(echo "$RELEASE_JSON" | jq -r .tag_name 2>/dev/null)
    [ -z "$LATEST_TAG" ] || [ "$LATEST_TAG" = "null" ] && LATEST_TAG=$(curl -sL https://sing-box.org/ | grep -oE 'v1\.[0-9]+\.[0-9]+' | head -n1)
    
    if [ -z "$LATEST_TAG" ]; then
        if [ "$LOCAL_VER" != "未安装" ]; then return 0; else err "获取版本失败"; exit 1; fi
    fi
    local REMOTE_VER="${LATEST_TAG#v}"

    if [[ "$MODE" == "update" && "$LOCAL_VER" == "$REMOTE_VER" ]]; then succ "已是最新版"; return 1; fi
    
    info "下载内核: $LATEST_TAG ($SBOX_ARCH)..."
    local URL="https://github.com/SagerNet/sing-box/releases/download/${LATEST_TAG}/sing-box-${REMOTE_VER}-linux-${SBOX_ARCH}.tar.gz"
    local TMP_D=$(mktemp -d)
    
    if ! curl -fL --max-time 30 "$URL" -o "$TMP_D/sb.tar.gz"; then
        URL="https://mirror.ghproxy.com/${URL}"
        curl -fL --max-time 30 "$URL" -o "$TMP_D/sb.tar.gz" || { rm -rf "$TMP_D"; err "下载失败"; exit 1; }
    fi

    tar -xf "$TMP_D/sb.tar.gz" -C "$TMP_D"
    pgrep sing-box >/dev/null && (systemctl stop sing-box 2>/dev/null || rc-service sing-box stop 2>/dev/null || true)
    install -m 755 "$TMP_D"/sing-box-*/sing-box /usr/bin/sing-box
    rm -rf "$TMP_D"
    succ "内核安装完毕"
}

is_valid_port() {
    [[ "$1" =~ ^[0-9]+$ ]] && [ "$1" -ge 1025 ] && [ "$1" -le 65535 ]
}
prompt_for_port() {
    local input_port
    while true; do
        read -p "请输入端口 [1025-65535] (回车随机): " input_port
        if [[ -z "$input_port" ]]; then
            echo $(shuf -i 10000-60000 -n 1); return 0
        elif is_valid_port "$input_port"; then
            echo "$input_port"; return 0
        else
            echo -e "\033[1;31m端口无效\033[0m" >&2
        fi
    done
}

generate_cert() {
    mkdir -p /etc/sing-box/certs
    if [ ! -f /etc/sing-box/certs/fullchain.pem ]; then
        info "生成自签名证书 (SNI: $TLS_DOMAIN)..."
        openssl ecparam -genkey -name prime256v1 -out /etc/sing-box/certs/privkey.pem
        openssl req -new -x509 -days 3650 -key /etc/sing-box/certs/privkey.pem \
          -out /etc/sing-box/certs/fullchain.pem -subj "/CN=$TLS_DOMAIN"
    fi
}

create_config() {
    local PORT_HY2="${1:-}"
    mkdir -p /etc/sing-box
    if [ -z "$PORT_HY2" ]; then
        if [ -f /etc/sing-box/config.json ]; then
            PORT_HY2=$(jq -r '.inbounds[0].listen_port' /etc/sing-box/config.json)
        else
            PORT_HY2=$(shuf -i 10000-60000 -n 1)
        fi
    fi
    local PSK
    if [ -f /etc/sing-box/config.json ]; then
        PSK=$(jq -r '.inbounds[0].users[0].password' /etc/sing-box/config.json)
    else
        PSK=$(cat /proc/sys/kernel/random/uuid 2>/dev/null || openssl rand -hex 16)
    fi
    
    # 注：Sing-box Hy2 inbound 目前不直接支持 max_early_data 等字段写入 inbound 层
    # 它们主要依赖内核层面的优化 (Sysctl) 和客户端的协商。
    # 这里我们保持配置文件的简洁与标准，避免不识别的字段导致 panic。
    cat > "/etc/sing-box/config.json" <<EOF
{
  "log": { "level": "warn", "timestamp": true },
  "inbounds": [{
    "type": "hysteria2",
    "tag": "hy2-in",
    "listen": "::",
    "listen_port": $PORT_HY2,
    "users": [ { "password": "$PSK" } ],
    "ignore_client_bandwidth": true,
    "tls": {
      "enabled": true,
      "alpn": ["h3"],
      "certificate_path": "/etc/sing-box/certs/fullchain.pem",
      "key_path": "/etc/sing-box/certs/privkey.pem"
    }
  }],
  "outbounds": [{ "type": "direct", "tag": "direct-out" }]
}
EOF
    chmod 600 "/etc/sing-box/config.json"
}

# --- 服务配置优化 (整合了你的进程调度建议) ---
setup_service() {
    info "配置服务 (Limit: $VAR_GOLIMIT, Nice: $VAR_SYSTEMD_NICE)..."
    
    if [ "$OS" = "alpine" ]; then
        # Alpine OpenRC 也可以设置 nice，但在脚本里较复杂，这里主要应用内存限制
        cat > /etc/init.d/sing-box <<EOF
#!/sbin/openrc-run
name="sing-box"
export GOGC=${VAR_GOGC}
export GOMEMLIMIT=$VAR_GOLIMIT
export GODEBUG=madvdontneed=1
command="/usr/bin/sing-box"
command_args="run -c /etc/sing-box/config.json"
command_background="yes"
pidfile="/run/\${RC_SVCNAME}.pid"
EOF
        chmod +x /etc/init.d/sing-box
        rc-update add sing-box default && rc-service sing-box restart
    else
        # Systemd 深度优化：CPUScheduling 和 IO 优先级
        cat > /etc/systemd/system/sing-box.service <<EOF
[Unit]
Description=Sing-box Optimized Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/etc/sing-box
# 1. 内存控制
Environment=GOGC=${VAR_GOGC}
Environment=GOMEMLIMIT=${VAR_GOLIMIT}
Environment=GODEBUG=madvdontneed=1
# 2. 进程优先级优化 (关键)
# 负数 Nice 值给予更高的 CPU 优先级 (-20 ~ 19)
Nice=${VAR_SYSTEMD_NICE}
# 3. IO 调度优化 (关键)
# best-effort (2) 或 realtime (1)。Realtime 风险较高，best-effort 配合高优先级通常足够
IOSchedulingClass=${VAR_SYSTEMD_IOSCHED}
IOSchedulingPriority=0
# 4. 其它保护
ExecStart=/usr/bin/sing-box run -c /etc/sing-box/config.json
Restart=on-failure
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload && systemctl enable sing-box --now
    fi
}

get_env_data() {
    local CONFIG_FILE="/etc/sing-box/config.json"
    [ ! -f "$CONFIG_FILE" ] && return 1
    RAW_PSK=$(jq -r '.inbounds[0].users[0].password' "$CONFIG_FILE" | xargs)
    RAW_PORT=$(jq -r '.inbounds[0].listen_port' "$CONFIG_FILE" | xargs)
    local CERT_PATH=$(jq -r '.inbounds[0].tls.certificate_path' "$CONFIG_FILE" | xargs)
    RAW_SNI=$(openssl x509 -in "$CERT_PATH" -noout -subject -nameopt RFC2253 | sed 's/.*CN=\([^,]*\).*/\1/' | xargs || echo "unknown")
}

display_links() {
    local LINK_V4="" LINK_V6=""
    if [ -n "${RAW_IP4:-}" ]; then
        LINK_V4="hy2://$RAW_PSK@$RAW_IP4:$RAW_PORT/?sni=$RAW_SNI&alpn=h3&insecure=1#$(hostname)_v4"
        echo -e "\n\033[1;35m[IPv4]\033[0m $LINK_V4"
    fi
    if [ -n "${RAW_IP6:-}" ]; then
        LINK_V6="hy2://$RAW_PSK@[$RAW_IP6]:$RAW_PORT/?sni=$RAW_SNI&alpn=h3&insecure=1#$(hostname)_v6"
        echo -e "\n\033[1;36m[IPv6]\033[0m $LINK_V6"
    fi
    [ -n "$LINK_V4" ] && copy_to_clipboard "$LINK_V4"
}

display_system_status() {
    local VER_INFO=$(/usr/bin/sing-box version 2>/dev/null | head -n1 | awk '{print $3}')
    echo -e "优化方案: \033[1;32m$VAR_OPTIMIZE_DESC\033[0m"
    echo -e "内核版本: v$VER_INFO"
    echo -e "UDP缓冲: RMEM=$((VAR_UDP_RMEM/1024/1024))MB | WMEM=$((VAR_UDP_WMEM/1024/1024))MB"
}

create_sb_tool() {
    mkdir -p /etc/sing-box
    # 固化变量到 core script
    cat > "$SBOX_CORE" <<EOF
#!/usr/bin/env bash
set -euo pipefail
SBOX_CORE='$SBOX_CORE'
TLS_DOMAIN_POOL=(${TLS_DOMAIN_POOL[@]})
RAW_IP4='$RAW_IP4'
RAW_IP6='$RAW_IP6'
# 固化优化参数，方便重置时调用
VAR_GOLIMIT='$VAR_GOLIMIT'
VAR_GOGC='$VAR_GOGC'
VAR_UDP_RMEM='$VAR_UDP_RMEM'
VAR_UDP_WMEM='$VAR_UDP_WMEM'
VAR_UDP_MEM_LIMIT='$VAR_UDP_MEM_LIMIT'
VAR_SYSTEMD_NICE='$VAR_SYSTEMD_NICE'
VAR_SYSTEMD_IOSCHED='$VAR_SYSTEMD_IOSCHED'
VAR_OPTIMIZE_DESC='$VAR_OPTIMIZE_DESC'
EOF
    declare -f is_valid_port prompt_for_port get_env_data display_links display_system_status detect_os copy_to_clipboard create_config setup_service install_singbox info err warn succ >> "$SBOX_CORE"
    
    cat >> "$SBOX_CORE" <<'EOF'
# 复用 logic，确保 setup_service 能读到变量
optimize_system_fake() { return 0; } # 既然变量已固化，无需再次计算
if [[ "${1:-}" == "--show-only" ]]; then
    detect_os; get_env_data; display_system_status; display_links
elif [[ "${1:-}" == "--reset-port" ]]; then
    detect_os; create_config "$2"; setup_service; sleep 1; get_env_data; display_links
elif [[ "${1:-}" == "--update-kernel" ]]; then
    detect_os; install_singbox "update" && setup_service && succ "完成"
fi
EOF
    chmod 700 "$SBOX_CORE"
    
    # 生成 sb 快捷指令
    cat > "/usr/local/bin/sb" <<'EOF'
#!/usr/bin/env bash
CORE="/etc/sing-box/core_script.sh"
[ ! -f "$CORE" ] && exit 1
source "$CORE" --fake-load
while true; do
    echo -e "\n=== Sing-box HY2 管理 ==="
    echo "1. 查看状态   2. 修改配置"
    echo "3. 重置端口   4. 更新内核"
    echo "5. 重启服务   6. 卸载脚本"
    echo "0. 退出"
    read -p "选择: " opt
    case "$opt" in
        1) source "$CORE" --show-only ;;
        2) vi /etc/sing-box/config.json && systemctl restart sing-box && echo "已重启" ;;
        3) P=$(prompt_for_port); source "$CORE" --reset-port "$P" ;;
        4) source "$CORE" --update-kernel ;;
        5) systemctl restart sing-box && echo "服务已重启" ;;
        6) systemctl stop sing-box; rm -rf /usr/bin/sing-box /etc/sing-box /usr/local/bin/sb /etc/systemd/system/sing-box.service; echo "已卸载"; exit 0 ;;
        0) exit 0 ;;
        *) continue ;;
    esac
done
EOF
    chmod +x /usr/local/bin/sb
}

# --- Main ---
detect_os
[ "$(id -u)" != "0" ] && err "Need root" && exit 1

case "$OS" in
    alpine) apk add --no-cache bash curl jq openssl openrc iproute2 coreutils ;;
    *) apt-get update -y && apt-get install -y curl jq openssl || yum install -y curl jq openssl ;;
esac

info "获取 IP..."
RAW_IP4=$(curl -s4 --max-time 5 https://api.ipify.org || echo "")
RAW_IP6=$(curl -s6 --max-time 5 https://api6.ipify.org || echo "")

USER_PORT=$(prompt_for_port)

optimize_system   # 计算所有差异化变量
install_singbox "install"
generate_cert
create_config "$USER_PORT"
setup_service     # 应用变量到 Systemd
create_sb_tool

get_env_data
display_system_status
display_links
